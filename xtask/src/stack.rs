//! The controller's stack, measured from the image the gate built (F-094).
//!
//! The stack grows down from the mailbox toward the statics, and nothing on
//! a Cortex-M0+ stops it at their edge: #217 was the stack running 1.2 KB
//! into `.bss` and leaving a small number where the HAL keeps SPI1's clock,
//! so the NOR's bus refused its frequency on every boot. Host tests cannot
//! see a frame, so this reads them off the release ELF: every function's
//! frame from its prologue, the deepest chain of direct calls under each
//! task and interrupt, and the sum of what can be on the stack at once,
//! held under the room the linker left with a margin.
//!
//! What can be on the stack at once follows from who preempts whom: one
//! thread-mode task, one task of the control executor above it, one of the
//! supervisor's above that, and the hardware's handlers above everything.
//! `main`'s poll is the exception: `control::start` holds the control
//! executor until `control::release` runs after `main` has returned, so
//! nothing of the control executor nests on `main`'s frame, and the check
//! counts the boot and the running image apart on that promise.
//!
//! What the call graph cannot see is a call through a pointer: a waker, a
//! `dyn` visitor, the executor polling a task. The tasks are named here as
//! roots for the last; the rest are counted as calling nothing, which is
//! what the margin is for.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use crate::repo::llvm_tool;

/// What the check insists on under the room the linker left, for the calls
/// through a pointer the call graph counts as calling nothing.
const MARGIN: u64 = 2 * 1024;

/// What an exception pushes: eight words, and one more when the stack it
/// lands on is not 8-byte aligned.
const EXCEPTION_FRAME: u64 = 36;

/// The interrupt the control executor runs from (`control.rs`).
const CONTROL_IRQ: &str = "USB_UCPD1_2";
/// The interrupt the supervisor's executor runs from (`supervisor.rs`).
const SUPERVISOR_IRQ: &str = "CEC";
/// The runtime's entry, which runs the thread-mode executor.
const THREAD_ENTRY: &str = "main";

/// Where a task is polled from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Runs {
    /// Thread mode, as `main`: the control executor is held while it runs.
    Boot,
    /// Thread mode, once `main` has returned.
    Thread,
    /// The control executor.
    Control,
    /// The supervisor's executor.
    Supervisor,
}

/// Every task of the image, by the path its pool's poll is named with, and
/// where it runs. A task the image has and this does not name fails the
/// check: where it runs is what decides what it can nest on.
const TASKS: &[(&str, Runs)] = &[
    ("o89_controller::____embassy_main_task::", Runs::Boot),
    ("o89_controller::agreement::__run_task::", Runs::Thread),
    (
        "o89_controller::control::held::__release_task::",
        Runs::Thread,
    ),
    ("o89_controller::link::__run_task::", Runs::Control),
    ("o89_controller::recorder::__run_task::", Runs::Control),
    ("o89_controller::rail::__run_task::", Runs::Control),
    ("o89_controller::control::__run_task::", Runs::Control),
    ("o89_controller::supervisor::__run_task::", Runs::Supervisor),
];

/// Recursion the data bounds, by a name every function on the cycle
/// carries, and why. Such a cycle is counted twice around; any other fails
/// the check, since recursion is forbidden (`.claude/rules/code-style.md`).
const BOUNDED_RECURSION: &[(&str, &str)] = &[
    (
        "km43::cbor::CborReader",
        "a repeated-key search reads its map's earlier keys with a reader whose checks are off, and that reader never searches: two deep",
    ),
    (
        "core::panicking::",
        "the panic handler's record of its site can only re-enter it through a panic of its own, and the handler resets",
    ),
    (
        "rust_begin_unwind",
        "the panic handler, on the same cycle as the line above",
    ),
    (
        "o89_controller::last_words::write",
        "the panic handler's record, on the same cycle as the lines above",
    ),
];

/// One function of the image.
#[derive(Debug)]
struct Function {
    name: String,
    /// Bytes its prologue takes: every push, every `sub sp`, every
    /// `add sp` of a negative constant, summed.
    frame: u64,
    /// The functions it calls directly, by start address.
    calls: BTreeSet<u64>,
}

/// The image's functions, by start address.
#[derive(Debug, Default)]
struct Program {
    functions: BTreeMap<u64, Function>,
}

impl Program {
    /// Read `llvm-objdump -d --no-show-raw-insn --demangle` output.
    fn parse(disassembly: &str) -> Result<Self> {
        let words = literal_words(disassembly);
        let mut functions = BTreeMap::new();
        let mut current: Option<(u64, Function, BTreeMap<String, u64>)> = None;
        // Branch targets are resolved once every function's start is known.
        let mut branches: Vec<(u64, u64, bool)> = Vec::new();
        for line in disassembly.lines() {
            if let Some((start, name)) = function_header(line) {
                if let Some((at, function, _)) = current.take() {
                    functions.insert(at, function);
                }
                current = Some((
                    start,
                    Function {
                        name: name.to_owned(),
                        frame: 0,
                        calls: BTreeSet::new(),
                    },
                    BTreeMap::new(),
                ));
                continue;
            }
            let Some((at, function, loaded)) = current.as_mut() else {
                continue;
            };
            let Some((mnemonic, operands)) = instruction(line) else {
                continue;
            };
            match mnemonic {
                "push" => {
                    let registers = u64::try_from(operands.split(',').count()).unwrap_or(u64::MAX);
                    function.frame = function
                        .frame
                        .saturating_add(4_u64.saturating_mul(registers));
                }
                "sub" => {
                    if let Some(bytes) = operands
                        .strip_prefix("sp, #")
                        .and_then(|imm| parse_number(imm.split_whitespace().next()?))
                    {
                        function.frame = function.frame.saturating_add(bytes);
                    } else if operands.starts_with("sp,") {
                        bail!(
                            "{}: `sub {operands}` is a frame the check cannot size",
                            function.name
                        );
                    }
                }
                "ldr" => {
                    // `ldr rN, [pc, #imm] @ 0xADDR <...>`: the literal at ADDR.
                    if let Some((register, rest)) = operands.split_once(", [pc")
                        && let Some(address) = rest
                            .split_once("@ 0x")
                            .and_then(|(_, tail)| tail.split_whitespace().next())
                            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                        && let Some(&word) = words.get(&address)
                    {
                        loaded.insert(register.trim().to_owned(), word);
                    }
                }
                "add" => {
                    if let Some(register) = operands.strip_prefix("sp, ")
                        && !register.starts_with('#')
                    {
                        let register = register.split_whitespace().next().unwrap_or(register);
                        let Some(&word) = loaded.get(register) else {
                            bail!(
                                "{}: `add sp, {register}` with no constant loaded is a frame the check cannot size",
                                function.name
                            );
                        };
                        // A negative 32-bit constant grows the frame; a
                        // positive one is an epilogue giving it back.
                        if word >= 0x8000_0000 {
                            let bytes = 0x1_0000_0000_u64.saturating_sub(word);
                            function.frame = function.frame.saturating_add(bytes);
                        }
                    }
                }
                "bl" | "b" | "b.w" => {
                    if let Some(target) = branch_target(operands) {
                        branches.push((*at, target, mnemonic == "bl"));
                    }
                }
                _ => {}
            }
        }
        if let Some((at, function, _)) = current.take() {
            functions.insert(at, function);
        }
        let mut program = Self { functions };
        for (from, target, linked) in branches {
            // A branch into the middle of a function, its own included, is
            // not a call: thumbv6m reaches a far label of its own with `bl`.
            if target != from && program.functions.contains_key(&target) {
                if let Some(function) = program.functions.get_mut(&from) {
                    function.calls.insert(target);
                }
            } else if target == from
                && linked
                && let Some(function) = program.functions.get_mut(&from)
            {
                // A call to its own start is recursion; a plain branch there
                // is a loop whose head is the entry.
                function.calls.insert(target);
            }
        }
        Ok(program)
    }

    /// The function whose name contains `pattern`, exactly one.
    fn find(&self, pattern: &str, suffix: &str) -> Result<u64> {
        let found: Vec<u64> = self
            .functions
            .iter()
            .filter(|(_, function)| {
                function.name.contains(pattern) && function.name.ends_with(suffix)
            })
            .map(|(&at, _)| at)
            .collect();
        match found.as_slice() {
            [one] => Ok(*one),
            [] => bail!("the image has no function `{pattern}…{suffix}`"),
            _ => bail!(
                "the image has {} functions `{pattern}…{suffix}`",
                found.len()
            ),
        }
    }

    /// The function named exactly `name`.
    fn named(&self, name: &str) -> Result<u64> {
        self.functions
            .iter()
            .find(|(_, function)| function.name == name)
            .map(|(&at, _)| at)
            .with_context(|| format!("the image has no function `{name}`"))
    }

    /// The deepest chain of direct calls from every function, in bytes.
    fn depths(&self) -> Result<BTreeMap<u64, u64>> {
        let components = strongly_connected(self);
        let mut component_of = BTreeMap::new();
        for (index, members) in components.iter().enumerate() {
            for &member in members {
                component_of.insert(member, index);
            }
        }
        // Tarjan's order is reverse topological: a component's callees come
        // before it, so one pass in order sees every callee's depth first.
        let mut depth_of_component: Vec<u64> = Vec::with_capacity(components.len());
        for (index, members) in components.iter().enumerate() {
            let recursive = members.len() > 1
                || members.iter().any(|at| {
                    self.functions
                        .get(at)
                        .is_some_and(|function| function.calls.contains(at))
                });
            let frames: u64 = members
                .iter()
                .filter_map(|at| self.functions.get(at))
                .map(|function| function.frame)
                .sum();
            let weight = if recursive {
                let names: Vec<&str> = members
                    .iter()
                    .filter_map(|at| self.functions.get(at))
                    .map(|function| function.name.as_str())
                    .collect();
                let bounded = names.iter().all(|name| {
                    BOUNDED_RECURSION
                        .iter()
                        .any(|(pattern, _)| name.contains(pattern))
                });
                ensure!(
                    bounded,
                    "recursion the check cannot bound: {}",
                    names.join(" -> ")
                );
                frames.saturating_mul(2)
            } else {
                frames
            };
            let mut deepest_callee = 0_u64;
            for at in members {
                let Some(function) = self.functions.get(at) else {
                    continue;
                };
                for callee in &function.calls {
                    let Some(&other) = component_of.get(callee) else {
                        continue;
                    };
                    if other == index {
                        continue;
                    }
                    let depth = depth_of_component
                        .get(other)
                        .copied()
                        .context("a callee's component was not sized before its caller's")?;
                    deepest_callee = deepest_callee.max(depth);
                }
            }
            depth_of_component.push(weight.saturating_add(deepest_callee));
        }
        let mut depths = BTreeMap::new();
        for (at, index) in component_of {
            let depth = depth_of_component
                .get(index)
                .copied()
                .context("a component was not sized")?;
            depths.insert(at, depth);
        }
        Ok(depths)
    }
}

/// Tarjan's strongly connected components, iteratively, in reverse
/// topological order.
fn strongly_connected(program: &Program) -> Vec<Vec<u64>> {
    #[derive(Clone, Copy)]
    struct Mark {
        index: usize,
        low: usize,
        on_stack: bool,
    }
    let mut marks: BTreeMap<u64, Mark> = BTreeMap::new();
    let mut stack: Vec<u64> = Vec::new();
    let mut components = Vec::new();
    let mut next = 0_usize;
    for &root in program.functions.keys() {
        if marks.contains_key(&root) {
            continue;
        }
        // Each frame: the node and the callees still to visit.
        let mut work: Vec<(u64, Vec<u64>)> = Vec::new();
        let callees = |at: u64| -> Vec<u64> {
            program
                .functions
                .get(&at)
                .map(|function| function.calls.iter().copied().collect())
                .unwrap_or_default()
        };
        marks.insert(
            root,
            Mark {
                index: next,
                low: next,
                on_stack: true,
            },
        );
        next = next.saturating_add(1);
        stack.push(root);
        work.push((root, callees(root)));
        while let Some((node, pending)) = work.last_mut() {
            let node = *node;
            if let Some(callee) = pending.pop() {
                match marks.get(&callee).copied() {
                    None => {
                        marks.insert(
                            callee,
                            Mark {
                                index: next,
                                low: next,
                                on_stack: true,
                            },
                        );
                        next = next.saturating_add(1);
                        stack.push(callee);
                        work.push((callee, callees(callee)));
                    }
                    Some(mark) if mark.on_stack => {
                        if let Some(own) = marks.get_mut(&node) {
                            own.low = own.low.min(mark.index);
                        }
                    }
                    Some(_) => {}
                }
                continue;
            }
            work.pop();
            let Some(own) = marks.get(&node).copied() else {
                continue;
            };
            if let Some((parent, _)) = work.last()
                && let Some(parent) = marks.get_mut(parent)
            {
                parent.low = parent.low.min(own.low);
            }
            if own.low == own.index {
                let mut members = Vec::new();
                while let Some(member) = stack.pop() {
                    if let Some(mark) = marks.get_mut(&member) {
                        mark.on_stack = false;
                    }
                    members.push(member);
                    if member == node {
                        break;
                    }
                }
                components.push(members);
            }
        }
    }
    components
}

/// Every `.word` in the disassembly, by address: the literal pools.
fn literal_words(disassembly: &str) -> BTreeMap<u64, u64> {
    disassembly
        .lines()
        .filter_map(|line| {
            let (address, rest) = line.trim_start().split_once(':')?;
            let address = u64::from_str_radix(address, 16).ok()?;
            let (_, word) = rest.split_once(".word")?;
            let word = word.trim().strip_prefix("0x")?;
            Some((address, u64::from_str_radix(word, 16).ok()?))
        })
        .collect()
}

/// `08025a5c <name>:`.
fn function_header(line: &str) -> Option<(u64, &str)> {
    let (address, rest) = line.split_once(" <")?;
    if address.len() != 8 || !address.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let name = rest.strip_suffix(">:")?;
    Some((u64::from_str_radix(address, 16).ok()?, name))
}

/// ` 8025a5c:      \tpush\t{r4, r5, r6, r7, lr}` as `("push", "{r4, …}")`.
fn instruction(line: &str) -> Option<(&str, &str)> {
    let (address, rest) = line.trim_start().split_once(':')?;
    if address.is_empty() || !address.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let rest = rest.trim_start();
    let (mnemonic, operands) = rest.split_once('\t').unwrap_or((rest, ""));
    Some((mnemonic.trim(), operands.trim()))
}

/// `0x803af54 <name> @ imm = #…` as the address.
fn branch_target(operands: &str) -> Option<u64> {
    let hex = operands.strip_prefix("0x")?.split_whitespace().next()?;
    u64::from_str_radix(hex, 16).ok()
}

fn parse_number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// What can be on the stack at once, measured.
#[derive(Debug)]
struct Measured {
    /// The room between the statics and the stack's top.
    room: u64,
    /// The boot: `main` and what nests on it.
    boot: u64,
    /// The running image: a thread task, a control task and what nests on
    /// them.
    running: u64,
    /// Each part, for the report.
    parts: Vec<(String, u64)>,
}

impl Measured {
    fn worst(&self) -> u64 {
        self.boot.max(self.running)
    }
}

/// Measure `program`, whose vector table points at `vectors`, against
/// `room` bytes of stack.
fn measure(program: &Program, vectors: &[u64], room: u64) -> Result<Measured> {
    let depths = program.depths()?;
    let depth = |at: u64| depths.get(&at).copied().unwrap_or(0);

    for function in program.functions.values() {
        if function
            .name
            .starts_with("<embassy_executor::raw::TaskStorage<")
            && function.name.ends_with(">>::poll")
            && !TASKS.iter().any(|(path, _)| function.name.contains(path))
        {
            bail!(
                "the task polled by `{}` is not placed: name where it runs in xtask/src/stack.rs",
                function.name
            );
        }
    }
    let mut parts = Vec::new();
    let mut deepest = BTreeMap::<&str, u64>::new();
    for &(path, runs) in TASKS {
        let at = program.find(&format!("TaskStorage<{path}"), ">>::poll")?;
        let key = match runs {
            Runs::Boot => "boot",
            Runs::Thread => "thread",
            Runs::Control => "control",
            Runs::Supervisor => "supervisor",
        };
        let entry = deepest.entry(key).or_insert(0);
        *entry = (*entry).max(depth(at));
        parts.push((format!("task {path}"), depth(at)));
    }
    let of = |key: &str| deepest.get(key).copied().unwrap_or(0);

    let thread_entry = program.named(THREAD_ENTRY)?;
    let control_irq = program.named(CONTROL_IRQ)?;
    let supervisor_irq = program.named(SUPERVISOR_IRQ)?;
    // The table's first handler is the reset vector, which runs once and
    // is under everything, as the thread entry it calls is counted.
    let reset = vectors
        .first()
        .copied()
        .context("the vector table has no reset")?;
    let thread = depth(thread_entry);
    let supervisor = EXCEPTION_FRAME
        .saturating_add(depth(supervisor_irq))
        .saturating_add(of("supervisor"));
    let control = EXCEPTION_FRAME
        .saturating_add(depth(control_irq))
        .saturating_add(of("control"));
    // Every other handler the vector table names, each counted as nesting
    // on all the others: more than their priorities allow, and small.
    let handlers: BTreeSet<u64> = vectors
        .iter()
        .copied()
        .filter(|&at| at != reset && at != control_irq && at != supervisor_irq)
        .collect();
    let mut hardware = 0_u64;
    for at in &handlers {
        let function = program
            .functions
            .get(at)
            .with_context(|| format!("the vector table names {at:#x}, which starts no function"))?;
        hardware = hardware
            .saturating_add(EXCEPTION_FRAME)
            .saturating_add(depth(*at));
        parts.push((format!("handler {}", function.name), depth(*at)));
    }
    parts.push((format!("thread entry `{THREAD_ENTRY}`"), thread));
    parts.push((
        format!("control interrupt `{CONTROL_IRQ}` with its deepest task"),
        control,
    ));
    parts.push((
        format!("supervisor interrupt `{SUPERVISOR_IRQ}` with its task"),
        supervisor,
    ));

    let above = supervisor.saturating_add(hardware);
    let boot = thread.saturating_add(of("boot")).saturating_add(above);
    let running = thread
        .saturating_add(of("thread"))
        .saturating_add(control)
        .saturating_add(above);
    Ok(Measured {
        room,
        boot,
        running,
        parts,
    })
}

/// Refuse a stack deeper than the room less the margin.
fn enforce(measured: &Measured) -> Result<()> {
    let limit = measured.room.saturating_sub(MARGIN);
    ensure!(
        measured.worst() <= limit,
        "the controller's stack can reach {} bytes (boot {}, running {}), over the {limit}-byte line ({} of room less a {MARGIN} margin): the stack would run into the statics below it (#217)",
        measured.worst(),
        measured.boot,
        measured.running,
        measured.room
    );
    Ok(())
}

fn tool(name: &str, args: &[&str], elf: &Path) -> Result<String> {
    let path = llvm_tool(name)?;
    let output = Command::new(&path)
        .args(args)
        .arg(elf)
        .output()
        .with_context(|| format!("running {name}"))?;
    ensure!(
        output.status.success(),
        "{name} {} failed: {}",
        elf.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).with_context(|| format!("{name} wrote something not UTF-8"))
}

/// `_stack_start - _stack_end` from `llvm-nm`: the room cortex-m-rt left.
fn room(symbols: &str) -> Result<u64> {
    let find = |name: &str| -> Result<u64> {
        symbols
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let address = fields.next()?;
                let _kind = fields.next()?;
                (fields.next()? == name).then(|| u64::from_str_radix(address, 16).ok())?
            })
            .with_context(|| format!("the image has no `{name}`"))
    };
    let start = find("_stack_start")?;
    let end = find("_stack_end")?;
    start
        .checked_sub(end)
        .with_context(|| format!("the stack's top {start:#x} is under its floor {end:#x}"))
}

/// The handlers the vector table names, past the initial stack pointer and
/// the reset vector first, from `llvm-objdump -s -j .vector_table`, with
/// the Thumb bit cleared.
fn vectors(dump: &str) -> Result<Vec<u64>> {
    let mut words = Vec::new();
    for line in dump.lines() {
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next() else {
            continue;
        };
        if u64::from_str_radix(address, 16).is_err() {
            continue;
        }
        for field in fields.take(4) {
            if field.len() != 8 || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
                break;
            }
            let bytes = u32::from_str_radix(field, 16)?.to_be_bytes();
            words.push(u64::from(u32::from_le_bytes(bytes)));
        }
    }
    ensure!(words.len() > 2, "the vector table is empty");
    Ok(words
        .into_iter()
        .skip(1)
        .filter(|&word| word != 0)
        .map(|word| word & !1)
        .collect())
}

/// Measure the controller's release ELF and refuse a stack that does not
/// fit (F-094).
pub fn check(elf: &Path) -> Result<()> {
    let disassembly = tool(
        "llvm-objdump",
        &["-d", "--no-show-raw-insn", "--demangle"],
        elf,
    )?;
    let dump = tool("llvm-objdump", &["-s", "-j", ".vector_table"], elf)?;
    let symbols = tool("llvm-nm", &[], elf)?;
    let program = Program::parse(&disassembly)?;
    let measured = measure(&program, &vectors(&dump)?, room(&symbols)?)?;
    let mut report = String::new();
    for (part, bytes) in &measured.parts {
        let _ = writeln!(report, "  {bytes:>6}  {part}");
    }
    print!("{report}");
    println!(
        "o89-controller stack: boot {} and running {} bytes of {} (margin {MARGIN})",
        measured.boot, measured.running, measured.room
    );
    enforce(&measured)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disassembly in `llvm-objdump`'s shape: `Reset` calls `main`, the
    /// handlers and one task of each kind, with the frames each test sets.
    fn image(link_frame: u64, extra: &str) -> String {
        let mut text = String::new();
        let mut at = 0x0800_1000_u64;
        let mut function = |name: &str, body: &str| {
            let _ = writeln!(text, "{at:08x} <{name}>:");
            for line in body.lines() {
                at = at.saturating_add(2);
                let _ = writeln!(text, " {at:x}:      \t{}", line.trim());
            }
            at = (at | 0xff).saturating_add(1);
            let _ = writeln!(text);
        };
        function("Reset", "push\t{r7, lr}");
        function("main", "push\t{r7, lr}\nsub\tsp, #0x8");
        function(CONTROL_IRQ, "push\t{r7, lr}");
        function(SUPERVISOR_IRQ, "push\t{r7, lr}");
        function("TIM2", "push\t{r4, r7, lr}");
        for &(path, runs) in TASKS {
            let frame = match runs {
                Runs::Control if path.contains("link") => link_frame,
                Runs::Boot => 1000,
                Runs::Thread => 100,
                Runs::Control | Runs::Supervisor => 50,
            };
            function(
                &format!("<embassy_executor::raw::TaskStorage<{path}inner>>::poll"),
                &format!("sub\tsp, #{frame:#x}"),
            );
        }
        text.push_str(extra);
        text
    }

    /// The addresses of `Reset`, the two executors' interrupts and `TIM2`.
    fn table(program: &Program) -> Vec<u64> {
        ["Reset", CONTROL_IRQ, SUPERVISOR_IRQ, "TIM2"]
            .iter()
            .map(|name| program.named(name).expect("in the fixture"))
            .collect()
    }

    fn measured(link_frame: u64, extra: &str, room: u64) -> Result<Measured> {
        let program = Program::parse(&image(link_frame, extra))?;
        measure(&program, &table(&program), room)
    }

    #[test]
    fn f_094_frames_are_summed_from_push_sub_and_a_negative_constant() {
        let text = "\
08000100 <big>:
 8000100:      \tpush\t{r4, r5, r6, r7, lr}
 8000102:      \tsub\tsp, #0x1fc
 8000104:      \tldr\tr6, [pc, #0x4]        @ 0x800010c <big+0xc>
 8000106:      \tadd\tsp, r6
 8000108:      \tldr\tr5, [pc, #0x4]        @ 0x8000110 <big+0x10>
 800010a:      \tadd\tsp, r5
 800010c: 00 f0 ff ff  \t.word\t0xfffff000
 8000110: 00 10 00 00  \t.word\t0x00001000
";
        let program = Program::parse(text).expect("parses");
        let big = program.named("big").expect("found");
        // 20 pushed, 508 subtracted, 4096 by the negative constant; the
        // positive one is an epilogue and gives nothing back to the count.
        assert_eq!(program.functions[&big].frame, 20 + 0x1fc + 0x1000);
    }

    #[test]
    fn f_094_a_chain_is_the_sum_of_its_frames_and_a_far_label_is_not_a_call() {
        let text = "\
08000100 <outer>:
 8000100:      \tsub\tsp, #0x100
 8000102:      \tbl\t0x8000200 <inner> @ imm = #0xfc
 8000106:      \tbl\t0x8000104 <outer+0x4> @ imm = #0x0

08000200 <inner>:
 8000200:      \tsub\tsp, #0x40
";
        let program = Program::parse(text).expect("parses");
        let depths = program.depths().expect("no recursion");
        assert_eq!(depths[&program.named("outer").unwrap()], 0x140);
        assert_eq!(depths[&program.named("inner").unwrap()], 0x40);
    }

    #[test]
    fn f_094_a_branch_to_its_own_start_is_a_loop_not_recursion() {
        let text = "\
08000100 <o89_controller::idle>:
 8000100:      \tsub\tsp, #0x10
 8000102:      \tb\t0x8000100 <o89_controller::idle> @ imm = #-0x6
";
        let program = Program::parse(text).expect("parses");
        let depths = program.depths().expect("a loop is not recursion");
        assert_eq!(depths[&0x0800_0100], 0x10);
    }

    #[test]
    fn f_094_a_frame_from_an_unknown_register_is_refused() {
        let text = "\
08000100 <opaque>:
 8000100:      \tadd\tsp, r6
";
        let error = Program::parse(text).expect_err("unsized");
        assert!(error.to_string().contains("cannot size"), "{error}");
    }

    #[test]
    fn f_094_recursion_is_refused_unless_the_data_bounds_it() {
        let recursive = "\
08000100 <o89_controller::walk>:
 8000100:      \tsub\tsp, #0x10
 8000102:      \tbl\t0x8000100 <o89_controller::walk> @ imm = #-0x6
";
        let program = Program::parse(recursive).expect("parses");
        let error = program.depths().expect_err("unbounded");
        assert!(
            error.to_string().contains("o89_controller::walk"),
            "{error}"
        );

        let bounded = "\
08000100 <<km43::cbor::CborReader>::head>:
 8000100:      \tsub\tsp, #0x10
 8000102:      \tbl\t0x8000200 <<km43::cbor::CborReader>::search> @ imm = #0xfa

08000200 <<km43::cbor::CborReader>::search>:
 8000200:      \tsub\tsp, #0x20
 8000202:      \tbl\t0x8000100 <<km43::cbor::CborReader>::head> @ imm = #-0x106
";
        let program = Program::parse(bounded).expect("parses");
        let depths = program.depths().expect("bounded");
        // Twice around the cycle.
        assert_eq!(depths[&0x0800_0100], 2 * (0x10 + 0x20));
    }

    #[test]
    fn f_094_the_running_image_sums_a_thread_task_a_control_task_and_what_is_above() {
        let m = measured(0x200, "", 64 * 1024).expect("measures");
        // main 8+8, the deepest thread task 100 (release and agreement), the
        // control interrupt 8 + 36 + the link's 0x200, the supervisor 8 + 36
        // + 50, TIM2 12 + 36.
        assert_eq!(
            m.running,
            16 + 100 + (8 + 36 + 0x200) + (8 + 36 + 50) + (12 + 36)
        );
        // main's own 1000 with no control task on it.
        assert_eq!(m.boot, 16 + 1000 + (8 + 36 + 50) + (12 + 36));
    }

    #[test]
    fn f_094_a_stack_that_reaches_the_margin_is_refused_and_one_under_it_passes() {
        // The link's frame over main's, so the running image is the worst.
        let fits = measured(0x800, "", 64 * 1024).expect("measures");
        assert!(fits.running > fits.boot);
        let exact = fits.worst() + MARGIN;
        let at_the_line = measured(0x800, "", exact).expect("measures");
        assert!(enforce(&at_the_line).is_ok(), "exactly at the line fits");
        let over = measured(0x800 + 4, "", exact).expect("measures");
        let error = enforce(&over).expect_err("four bytes over");
        assert!(error.to_string().contains("#217"), "{error}");
    }

    #[test]
    fn f_094_a_task_the_check_does_not_place_is_refused() {
        let stray = "\
08100000 <<embassy_executor::raw::TaskStorage<o89_controller::stray::__run_task::inner>>::poll>:
 8100000:      \tsub\tsp, #0x10
";
        let error = measured(0x200, stray, 64 * 1024).expect_err("unplaced");
        assert!(error.to_string().contains("stray"), "{error}");
    }

    #[test]
    fn f_094_room_is_read_from_the_runtime_symbols() {
        let symbols = "20012154 B _stack_end\n20022000 A _stack_start\n20000000 D __sdata\n";
        assert_eq!(room(symbols).expect("both"), 0x2_2000 - 0x1_2154);
        assert!(room("20022000 A _stack_start\n").is_err(), "no floor");
        assert!(
            room("20000000 B _stack_end\n1fff0000 A _stack_start\n").is_err(),
            "inverted"
        );
    }

    #[test]
    fn f_094_the_vector_table_is_read_past_the_stack_pointer_without_thumb_bits() {
        let dump = "\
o89-controller:\tfile format elf32-littlearm
Contents of section .vector_table:
 8008000 00200220 01810008 00000000 99cd0408  . . ............
";
        assert_eq!(
            vectors(dump).expect("reads"),
            vec![0x0800_8100, 0x0804_cd98]
        );
        assert!(vectors("Contents of section .vector_table:\n").is_err());
    }
}
