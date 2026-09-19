//! Flashing the module through the controller, with no wire on it (F-038).
//!
//! Board A has no USB or programming header on the module; the controller
//! sits on its UART0 and holds its `EN`. So the firmware is asked, through
//! the mailbox, to reset the module and knock inside its download window
//! (KM43 L-190 to L-192), and then to hold the UART at the ROM's rate with
//! its bytes on the mailbox's two rings. This end serves those rings on a
//! local socket and runs `esptool` against it, which speaks the ROM's
//! protocol; when it is done the firmware is asked to reset the module
//! normally, and the next thing on the controller's log is the module's
//! `LinkUp`. Nothing here speaks the ROM's protocol itself: `esptool` is
//! the reference implementation, and a second one would be a second
//! opinion about a flash layout.
//!
//! What is written, and in what order, is [`Plan`]. By default it is an
//! application into an OTA slot with the factory image left alone (F-084),
//! because that image carries the download window and is the way back into
//! a module with no wire on it (F-036, #1).

use o89_core::mailbox::DownloadEntry;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::layout::{
    ImageState, OTADATA_LEN, Role, TABLE_AT, TABLE_LEN, Table, otadata_no_slot, otadata_selecting,
};
use crate::link::Link;

/// `download_reason` as the registry numbers `bench`.
const REASON_BENCH: u8 = 1;
/// Bytes from the socket held for the module before the socket stops
/// being read.
const PENDING_MAX: usize = 64 * 1024;
/// A pass that moved nothing rests this long before the next.
const IDLE: Duration = Duration::from_millis(2);
/// How long `esptool` may take for the whole image: a 176 KB merged image
/// at 115 200 baud with the stub is well under a minute.
const ESPTOOL_DEADLINE: Duration = Duration::from_mins(10);
/// How long after `esptool` exits the bytes still on the rings are moved
/// before the bridge is closed.
const DRAIN: Duration = Duration::from_millis(500);

/// The OTA slot the bench writes, counted from zero, and how many the
/// table declares. Slot zero always: which slot the bench uses is not
/// what these runs are about, and a fixed one is a number the operator can
/// read off `dev-nor`-style dumps without asking what ran last.
const BENCH_SLOT: u8 = 0;
const OTA_SLOTS: u32 = 2;

/// What the flash writes, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    /// The address in the module's flash.
    pub at: u32,
    /// How many bytes land there.
    pub len: u32,
    /// The file holding them.
    pub file: PathBuf,
}

/// The writes, in passes. Each pass is one `esptool` run, and `esptool`
/// writes a pass's entries in the order they are given. The split into
/// passes is what makes the order survive a run that dies: everything a
/// later pass does is known not to have happened when an earlier one is
/// still going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// What the operator is told before the module is touched.
    pub says: String,
    /// The passes, in order.
    pub passes: Vec<Vec<Write>>,
}

/// Where the generated files live for the length of one flash, removed
/// when this drops however the flash ended.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// A directory of this flash's own: two benches on two probes must
    /// not hand `esptool` each other's image, and neither must two flashes
    /// of one process.
    ///
    /// Named from the operating system's generator and created exclusively,
    /// so the directory is one nobody else could have made first. The
    /// temporary directory is shared, the files in here are the bytes that
    /// go onto the module, and this is what `Drop` later removes whole: a
    /// path somebody else could hold is an image somebody else could
    /// choose, and a directory somebody else could own is one this must
    /// not delete.
    pub fn new() -> Result<Self> {
        let mut name = [0u8; 16];
        getrandom::fill(&mut name)
            .map_err(|error| anyhow!("the operating system's generator: {error}"))?;
        let dir = std::env::temp_dir().join(format!("o89-dev-{}", hex::encode(name)));
        std::fs::create_dir(&dir).with_context(|| format!("making {}", dir.display()))?;
        Ok(Self(dir))
    }

    /// A file inside it, by name.
    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nobody to report to in a drop, and a directory that outlives one
        // run is picked up by the next.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The application alone, into an OTA slot, with the bootloader, the
/// partition table and the factory image left where they are (F-084).
///
/// Three writes in two passes, and the order is the point:
///
/// 1. the `otadata` blanked, so the bootloader runs the factory image;
/// 2. the application into the slot;
/// 3. the `otadata` naming the slot, once the application has landed.
///
/// Between 1 and 3 the module boots the factory image, which honours the
/// window, so a transfer that dies anywhere in there leaves a module the
/// controller can knock at again with no wire on it.
pub fn plan_slot(table: &Table, app: &Path, scratch: &Scratch) -> Result<Plan> {
    let otadata = table.find(Role::OTA_DATA)?;
    if otadata.size != OTADATA_LEN {
        bail!("{otadata} is not the {OTADATA_LEN:#x} bytes the bootloader reads");
    }
    let role = Role::ota(BENCH_SLOT);
    let slot = table.find(role)?;
    let app_len = u32::try_from(
        std::fs::metadata(app)
            .with_context(|| format!("measuring {}", app.display()))?
            .len(),
    )
    .context("an application that fits a u32")?;
    if app_len > slot.size {
        bail!("the application is {app_len} bytes and {slot} holds it not");
    }
    let blank = scratch.file("otadata-blank.bin");
    std::fs::write(&blank, otadata_no_slot())
        .with_context(|| format!("writing {}", blank.display()))?;
    let selecting = scratch.file("otadata-slot.bin");
    std::fs::write(
        &selecting,
        otadata_selecting(u32::from(BENCH_SLOT), OTA_SLOTS, ImageState::New)?,
    )
    .with_context(|| format!("writing {}", selecting.display()))?;
    let plan = Plan {
        says: format!(
            "writing the application into {} ({role}) at {:#x}; the bootloader, the partition table and the factory image stay",
            slot.name, slot.offset
        ),
        passes: vec![
            vec![
                Write {
                    at: otadata.offset,
                    len: OTADATA_LEN,
                    file: blank,
                },
                Write {
                    at: slot.offset,
                    len: app_len,
                    file: app.to_path_buf(),
                },
            ],
            vec![Write {
                at: otadata.offset,
                len: OTADATA_LEN,
                file: selecting,
            }],
        ],
    };
    keeps_the_recovery_image(&plan, table)?;
    Ok(plan)
}

/// The flash below the first partition: the second-stage bootloader from
/// address zero, and the partition table in the sector at `0x8000`. No
/// route but the whole one may touch either, and a table that is gone is
/// as bad as a factory image that is gone — the bootloader cannot find
/// the one without the other. The table declares nothing below its own
/// offset, so this is the one boundary the table cannot state.
const PARTITION_TABLE_END: u32 = 0x9000;

/// Every write in `plan` stays clear of the factory image, of the
/// partition table that points at it, and of the bootloader that reads
/// them (F-036, F-084): what lets a module with no wire on it be reached
/// again is all three, and losing any one of them loses the window.
///
/// Asserted on the plan rather than trusted from the code that built it,
/// because it is the property the operator is relying on and a slot
/// offset read out of the wrong row would not otherwise show.
pub fn keeps_the_recovery_image(plan: &Plan, table: &Table) -> Result<()> {
    let factory = table.find(Role::FACTORY)?;
    let factory_end = factory.end()?;
    for write in plan.passes.iter().flatten() {
        let end = write
            .at
            .checked_add(write.len)
            .with_context(|| format!("a write at {:#x} that runs past the flash", write.at))?;
        if write.at < PARTITION_TABLE_END {
            bail!(
                "a write of {} bytes at {:#x} reaches the bootloader or the partition table",
                write.len,
                write.at
            );
        }
        if write.at < factory_end && end > factory.offset {
            bail!(
                "a write of {} bytes at {:#x} reaches {factory}, which carries the download window",
                write.len,
                write.at
            );
        }
    }
    Ok(())
}

/// The whole flash from address zero: the bootloader, the partition table
/// and the factory image with it.
///
/// This is how a module is brought up the first time and how one whose
/// recovery image is gone is restored, and it is the only route that
/// replaces that image. It has no safe point: from the first erase until
/// the write completes the module boots nothing, and a module that boots
/// nothing is reached by the strap with a wire on revision A, or not at
/// all (F-038, #1).
pub fn plan_whole(merged: &Path) -> Result<Plan> {
    let len = u32::try_from(
        std::fs::metadata(merged)
            .with_context(|| format!("measuring {}", merged.display()))?
            .len(),
    )
    .context("an image that fits a u32")?;
    Ok(Plan {
        says: "writing the whole flash from 0x0: the bootloader, the partition table and the \
               factory image are replaced, and until it finishes the module boots nothing"
            .to_owned(),
        passes: vec![vec![Write {
            at: 0,
            len,
            file: merged.to_path_buf(),
        }]],
    })
}

/// The merged image `plan_whole` writes: the bootloader and the partition
/// table with the application at its factory offset, without the padding
/// to the flash's end.
pub fn merge(elf: &Path, partitions: &Path, out: &Path) -> Result<()> {
    espflash(
        &["--merge", "--skip-padding", "--partition-table"],
        Some(partitions),
        elf,
        out,
    )
}

/// The application image alone, as the bootloader loads it from a slot.
pub fn app_image(elf: &Path, out: &Path) -> Result<()> {
    espflash(&[], None, elf, out)
}

fn espflash(extra: &[&str], partitions: Option<&Path>, elf: &Path, out: &Path) -> Result<()> {
    let mut command = Command::new("espflash");
    command
        .args(["save-image", "--chip", "esp32c6", "--flash-size", "8mb"])
        .args(extra);
    if let Some(partitions) = partitions {
        command.arg(partitions);
    }
    let status =
        command.arg(elf).arg(out).status().context(
            "running espflash save-image (install with `cargo install espflash --locked`)",
        )?;
    if !status.success() {
        bail!("espflash save-image failed: {status}");
    }
    Ok(())
}

/// What a flash is asked to do. The slot route's plan cannot be made
/// before the bridge is up, because it is made from the table the module
/// holds and not from the one in the repository (F-085).
pub enum Request<'a> {
    /// The application into an OTA slot, the recovery image kept.
    Slot {
        /// The application image, as the bootloader loads it from a slot.
        app: &'a Path,
        /// Where the `otadata` this writes is built.
        scratch: &'a Scratch,
        /// The table the image was built against, compared against the
        /// module's so that a repository that has moved on says so.
        declared: Option<&'a Table>,
    },
    /// The whole flash from zero, the recovery image with it.
    Whole {
        /// The merged image: bootloader, partition table and factory app.
        merged: &'a Path,
    },
}

/// Carry out `request` on the module through the controller. With `knock`
/// the firmware asks the module's own window; with the strap it holds IO9
/// low across a reset, for a module that runs nothing that answers.
pub fn flash(link: &mut Link, request: &Request, entry: DownloadEntry) -> Result<()> {
    link.download(REASON_BENCH, entry)?;
    println!("module in download mode; the bridge is up");
    let outcome = carry_out(link, request);
    // The module goes back whatever esptool did: a half-written image is
    // the bootloader's to refuse, and a module left in the ROM is a
    // module nobody can reach.
    let back = link.normal();
    both(outcome, back)?;
    println!("module reset normally");
    Ok(())
}

/// The plan made and run with the bridge up, so that whatever happens the
/// caller still gives the module back.
fn carry_out(link: &mut Link, request: &Request) -> Result<()> {
    let plan = match request {
        Request::Slot {
            app,
            scratch,
            declared,
        } => {
            let installed = installed_table(link, scratch)?;
            if let Some(declared) = declared {
                differences(&installed, declared);
            }
            plan_slot(&installed, app, scratch)?
        }
        Request::Whole { merged } => plan_whole(merged)?,
    };
    println!("{}", plan.says);
    let mut outcome = Ok(());
    for (number, pass) in plan.passes.iter().enumerate() {
        let number = number.saturating_add(1);
        let mut args = vec!["write-flash".to_owned()];
        // In the order given, which is the order they land: what a pass
        // writes first is what a pass that dies has already done.
        for write in pass {
            println!(
                "  {} bytes at {:#x} from {}",
                write.len,
                write.at,
                write.file.display()
            );
            args.push(format!("{:#x}", write.at));
            args.push(write.file.to_string_lossy().into_owned());
        }
        outcome = run_esptool(link, &args)
            .with_context(|| format!("pass {number} of {}", plan.passes.len()));
        if outcome.is_err() {
            break;
        }
    }
    outcome
}

/// The partition table the module holds, read out of the sector the
/// bootloader reads it from (F-085).
fn installed_table(link: &mut Link, scratch: &Scratch) -> Result<Table> {
    let out = scratch.file("installed-table.bin");
    run_esptool(
        link,
        &[
            "read-flash".to_owned(),
            format!("{TABLE_AT:#x}"),
            format!("{TABLE_LEN:#x}"),
            out.to_string_lossy().into_owned(),
        ],
    )
    .context("reading the module's partition table")?;
    let bytes = std::fs::read(&out).with_context(|| format!("reading back {}", out.display()))?;
    Table::parse_installed(&bytes).context("the module's partition table")
}

/// Say where the module's table and the one in the repository disagree
/// about the partitions this writes.
///
/// Not a refusal: the module's table is the one that decides, and it is
/// the one this plans from. But a repository whose table has moved on is
/// a whole flash somebody has not run yet, and the operator should hear
/// it from the tool rather than from a module that boots the wrong thing.
fn differences(installed: &Table, declared: &Table) {
    for role in [Role::OTA_DATA, Role::FACTORY, Role::ota(BENCH_SLOT)] {
        match (installed.find(role), declared.find(role)) {
            (Ok(on_part), Ok(in_repo))
                if on_part.offset != in_repo.offset || on_part.size != in_repo.size =>
            {
                println!(
                    "note: the module has {role} at {:#x} for {} bytes; the table in the \
                     repository says {:#x} for {}. The module's is used",
                    on_part.offset, on_part.size, in_repo.offset, in_repo.size
                );
            }
            (Err(_), Ok(_)) => println!("note: the module's table has no {role}"),
            (Ok(_), Err(_)) => println!("note: the table in the repository has no {role}"),
            (Ok(_), Ok(_)) | (Err(_), Err(_)) => {}
        }
    }
}

/// An operation's outcome and the module's return to normal after it,
/// neither hidden by the other: a return that failed leaves the module in
/// its ROM, which is the one thing the operator must hear about.
fn both(outcome: Result<()>, back: Result<()>) -> Result<()> {
    match (outcome, back) {
        (Err(outcome), Err(back)) => Err(outcome.context(format!(
            "returning the module to normal also failed: {back:#}"
        ))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The module reset and its UART0 read for `seconds`, printed as text with
/// the bytes that are not text in hex, then the module reset normally, or,
/// with `leave_open`, the bridge left open as a host that died would leave
/// it: the next download reclaims it, or the firmware closes it once
/// nothing has moved on it for a minute.
pub fn listen(link: &mut Link, seconds: u64, entry: DownloadEntry, leave_open: bool) -> Result<()> {
    link.download(REASON_BENCH, entry)?;
    println!("the bridge is up; listening for {seconds} s");
    let until = Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .context("the deadline fits the clock")?;
    let mut buf = Vec::new();
    let mut total: usize = 0;
    let mut text = String::new();
    while Instant::now() < until {
        buf.clear();
        let outcome = link.bridge_read(&mut buf);
        match outcome {
            Ok(0) => std::thread::sleep(IDLE),
            Ok(count) => {
                total = total.saturating_add(count);
                for byte in &buf {
                    match byte {
                        b'\n' => {
                            println!("  {text}");
                            text.clear();
                        }
                        b'\r' => {}
                        0x20..=0x7e => text.push(char::from(*byte)),
                        other => {
                            use std::fmt::Write as _;
                            let _ = write!(text, "<{other:02x}>");
                        }
                    }
                }
            }
            Err(error) => return both(Err(error), link.normal()),
        }
    }
    if !text.is_empty() {
        println!("  {text}");
    }
    println!("{total} bytes in {seconds} s");
    if leave_open {
        println!("the bridge is left open, as a host that died would leave it");
        return Ok(());
    }
    link.normal()?;
    println!("module reset normally");
    Ok(())
}

fn run_esptool(link: &mut Link, args: &[String]) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("opening the relay socket")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let (mut esptool, from_esptool) = spawn_esptool(port, args)?;
    let mut relay = Relay {
        listener,
        client: None,
        pending: Vec::new(),
        outbound: Vec::new(),
        buf: vec![0u8; 8192],
    };
    let started = Instant::now();
    let mut exited = None;
    // Bounded by esptool's deadline; every pass moves bytes or rests.
    loop {
        for line in from_esptool.try_iter() {
            // esptool asks the port for a USB identity a socket does not
            // have, on every open; the line says nothing about the flash.
            if !line.contains("Failed to get VID/PID") && !line.trim().is_empty() {
                println!("esptool: {line}");
            }
        }
        if exited.is_none()
            && let Some(status) = esptool.0.try_wait().context("waiting for esptool")?
        {
            exited = Some((status, Instant::now()));
        }
        let busy = relay.pass(link)?;
        if let Some((status, at)) = exited
            && relay.pending.is_empty()
            && at.elapsed() >= DRAIN
        {
            if !status.success() {
                bail!("esptool failed: {status}");
            }
            return Ok(());
        }
        if started.elapsed() > ESPTOOL_DEADLINE {
            // Killed and reaped as the guard drops.
            bail!("esptool did not finish within {ESPTOOL_DEADLINE:?}");
        }
        if !busy {
            thread::sleep(IDLE);
        }
    }
}

/// The esptool lines that may wait for the relay's next pass.
const ESPTOOL_LINES: usize = 256;

/// A running esptool, killed and reaped when this drops, on every way out
/// of the flash: a relay that failed, a deadline passed, or the flash done.
/// The module is given back only after, so nothing is still writing to it
/// while the controller resets it, and the readers of its pipes end at the
/// pipes' close.
struct Esptool(Child);

impl Drop for Esptool {
    fn drop(&mut self) {
        // Either may fail on a process that has already gone; both are
        // tried, and a drop has nobody to report to.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `esptool` against the socket, its output lines on a channel.
fn spawn_esptool(port: u16, args: &[String]) -> Result<(Esptool, mpsc::Receiver<String>)> {
    let esptool = std::env::var("O89_ESPTOOL").unwrap_or_else(|_| "uvx esptool".to_owned());
    let mut words = esptool.split_whitespace();
    let program = words.next().context("an esptool command")?;
    let mut command = Command::new(program);
    command
        .args(words)
        .args(["--chip", "esp32c6", "--port"])
        .arg(format!("socket://127.0.0.1:{port}"))
        .args([
            "--baud", "115200", "--before", "no-reset", "--after", "no-reset",
        ])
        // The ROM's own loader: the stub would be one more image to move over
        // the bridge, and the 176 KB take under a minute without it.
        .arg("--no-stub")
        .args(args);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {esptool}"))?;
    // Bounded: a reader thread that gets ahead of the relay blocks on the
    // pipe, which holds esptool back, rather than growing the queue.
    let (lines, from_esptool) = mpsc::sync_channel::<String>(ESPTOOL_LINES);
    for pipe in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let lines = lines.clone();
        thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
    }
    Ok((Esptool(child), from_esptool))
}

/// The socket esptool talks to and the bytes in flight either way.
struct Relay {
    listener: TcpListener,
    client: Option<TcpStream>,
    /// From esptool, waiting for room on the ring.
    pending: Vec<u8>,
    /// From the module, waiting for esptool to take it.
    outbound: Vec<u8>,
    buf: Vec<u8>,
}

impl Relay {
    /// One pass: accept, move what the module said to the socket, take
    /// what esptool sent, and put what fits on the ring. Whether anything
    /// moved.
    fn pass(&mut self, link: &mut Link) -> Result<bool> {
        let mut busy = false;
        if self.client.is_none() {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    stream.set_nodelay(true)?;
                    self.client = Some(stream);
                    busy = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e).context("accepting esptool"),
            }
        }
        if link.bridge_read(&mut self.outbound)? > 0 {
            busy = true;
        }
        if !self.outbound.is_empty()
            && let Some(stream) = self.client.as_mut()
        {
            // Non-blocking: what the socket takes now goes, the rest waits
            // for the next pass; a socket that errors is a client gone.
            match stream.write(&self.outbound) {
                Ok(0) => {}
                Ok(n) => {
                    self.outbound.drain(..n.min(self.outbound.len()));
                    busy = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => self.client = None,
            }
        }
        if let Some(stream) = self.client.as_mut() {
            let room = PENDING_MAX
                .saturating_sub(self.pending.len())
                .min(self.buf.len());
            if room > 0 {
                match stream.read(self.buf.get_mut(..room).unwrap_or(&mut [])) {
                    Ok(0) => self.client = None,
                    Ok(n) => {
                        self.pending
                            .extend_from_slice(self.buf.get(..n).unwrap_or(&[]));
                        busy = true;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => self.client = None,
                }
            }
        }
        if !self.pending.is_empty() {
            let written = link.bridge_write(&self.pending)?;
            if written > 0 {
                self.pending.drain(..written.min(self.pending.len()));
                busy = true;
            }
        }
        Ok(busy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a process with this id is still there, a zombie included.
    fn exists(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .expect("kill runs")
            .success()
    }

    #[test]
    fn an_esptool_left_running_is_killed_and_reaped_when_its_guard_drops() {
        let child = Command::new("sleep").arg("30").spawn().expect("sleep runs");
        let pid = child.id();
        assert!(exists(pid));
        drop(Esptool(child));
        assert!(!exists(pid), "still there after the guard dropped");
    }

    #[test]
    fn an_esptool_that_already_exited_is_reaped_without_complaint() {
        let child = Command::new("true").spawn().expect("true runs");
        let pid = child.id();
        // Exited, not yet waited on: a zombie until someone reaps it.
        thread::sleep(Duration::from_millis(200));
        assert!(exists(pid), "a zombie until reaped");
        drop(Esptool(child));
        assert!(!exists(pid), "reaped as the guard dropped");
    }
}

#[cfg(test)]
mod plans {
    use super::*;
    use crate::layout::Table;

    /// The table the comms image is built against.
    const BOARD_A: &str = "\
otadata, data, ota,     0x9000,   0x2000,
factory, app,  factory, 0x10000,  0x200000,
ota_0,   app,  ota_0,   0x210000, 0x200000,
ota_1,   app,  ota_1,   0x410000, 0x200000,
";

    /// A file of `len` bytes standing in for a built application.
    fn application(scratch: &Scratch, len: usize) -> PathBuf {
        let path = scratch.file("app.bin");
        std::fs::write(&path, vec![0u8; len]).expect("the scratch takes a file");
        path
    }

    fn board_a() -> Table {
        Table::parse(BOARD_A).expect("the table parses")
    }

    #[test]
    fn f_084_the_otadata_is_blanked_before_the_slot_is_erased_and_named_after_it_lands() {
        let scratch = Scratch::new().expect("a scratch");
        let table = board_a();
        let plan = plan_slot(&table, &application(&scratch, 176_272), &scratch).expect("a plan");
        let first = plan.passes.first().expect("a first pass");
        let second = plan.passes.get(1).expect("a second pass");
        assert_eq!(
            plan.passes.len(),
            2,
            "the otadata is named in a pass of its own"
        );
        // The blank goes out before the slot is touched.
        assert_eq!(first.first().expect("a blank").at, 0x9000);
        assert_eq!(first.get(1).expect("the application").at, 0x0021_0000);
        // And the slot is named only once the application has landed.
        assert_eq!(second.first().expect("the otadata").at, 0x9000);
        let blank = std::fs::read(&first.first().expect("a blank").file).expect("it is there");
        assert!(blank.iter().all(|byte| *byte == 0xff), "no slot chosen");
        let naming =
            std::fs::read(&second.first().expect("the otadata").file).expect("it is there");
        assert_ne!(naming.first(), Some(&0xff), "a slot chosen");
    }

    #[test]
    fn f_085_the_plan_comes_from_the_table_the_module_holds() {
        // The repository's table has moved on: what it now calls ota_0 is
        // where the module still keeps its factory image. A plan made from
        // the repository's table would erase the recovery image and report
        // that it stays, because the guard would be checking the wrong
        // factory range.
        let moved_on = Table::parse(
            "otadata, data, ota,     0x9000,   0x2000,\n\
             ota_0,   app,  ota_0,   0x10000,  0x200000,\n\
             factory, app,  factory, 0x210000, 0x200000,\n",
        )
        .expect("the table parses");
        let scratch = Scratch::new().expect("a scratch");
        let app = application(&scratch, 112_832);
        // Planned from the module's table, the application goes where the
        // module keeps ota_0, and the module's factory image is what the
        // guard protects.
        let installed = board_a();
        let plan = plan_slot(&installed, &app, &scratch).expect("a plan");
        let landing = plan
            .passes
            .iter()
            .flatten()
            .find(|write| write.file == app)
            .expect("the application is written");
        assert_eq!(
            landing.at, 0x0021_0000,
            "the module's ota_0, not the repository's"
        );
        keeps_the_recovery_image(&plan, &installed).expect("the module's factory image stays");
        // And the same plan judged against the table that moved on would
        // have been called safe while erasing the image it protects.
        assert!(
            keeps_the_recovery_image(&plan, &moved_on).is_err(),
            "the repository's table calls this plan safe, which is the bug"
        );
    }

    #[test]
    fn f_036_the_slot_route_writes_neither_the_factory_image_nor_the_bootloader() {
        let scratch = Scratch::new().expect("a scratch");
        let table = board_a();
        let plan = plan_slot(&table, &application(&scratch, 176_272), &scratch).expect("a plan");
        keeps_the_recovery_image(&plan, &table).expect("the recovery image is untouched");
        for write in plan.passes.iter().flatten() {
            assert!(
                write.at >= 0x9000,
                "{:#x} is in the bootloader or the partition table",
                write.at
            );
            let end = write.at + write.len;
            assert!(
                write.at >= 0x0021_0000 || end <= 0x0001_0000,
                "{:#x}..{end:#x} overlaps the factory image",
                write.at
            );
        }
    }

    #[test]
    fn f_036_a_plan_that_reaches_the_factory_image_is_refused() {
        let plan = Plan {
            says: String::new(),
            passes: vec![vec![Write {
                at: 0x000f_f000,
                len: 0x2000,
                file: PathBuf::from("app.bin"),
            }]],
        };
        let error = format!(
            "{:#}",
            keeps_the_recovery_image(&plan, &board_a()).expect_err("refused")
        );
        assert!(error.contains("download window"), "{error}");
    }

    #[test]
    fn f_036_a_plan_that_reaches_the_partition_table_is_refused() {
        // A table that placed a slot over the partition table would take
        // the factory image out of the bootloader's reach without ever
        // writing a byte of it.
        let plan = Plan {
            says: String::new(),
            passes: vec![vec![Write {
                at: 0x8000,
                len: 0x1000,
                file: PathBuf::from("otadata.bin"),
            }]],
        };
        let error = format!(
            "{:#}",
            keeps_the_recovery_image(&plan, &board_a()).expect_err("refused")
        );
        assert!(error.contains("partition table"), "{error}");
    }

    #[test]
    fn the_whole_route_is_the_one_that_replaces_the_image_the_slot_route_keeps() {
        let scratch = Scratch::new().expect("a scratch");
        let merged = application(&scratch, 176_272);
        let plan = plan_whole(&merged).expect("a plan");
        assert_eq!(plan.passes.len(), 1, "no safe point to split on");
        let error = format!(
            "{:#}",
            keeps_the_recovery_image(&plan, &board_a()).expect_err("refused")
        );
        assert!(error.contains("bootloader"), "{error}");
    }

    #[test]
    fn an_application_too_large_for_its_slot_is_refused_before_the_module_is_touched() {
        let scratch = Scratch::new().expect("a scratch");
        let table = board_a();
        let app = application(&scratch, 0x0020_0001);
        let error = format!(
            "{:#}",
            plan_slot(&table, &app, &scratch).expect_err("refused")
        );
        assert!(error.contains("ota_0"), "{error}");
    }

    #[test]
    fn a_table_with_no_otadata_of_the_size_the_bootloader_reads_is_refused() {
        let scratch = Scratch::new().expect("a scratch");
        let table = Table::parse(
            "otadata, data, ota, 0x9000, 0x1000,\nfactory, app, factory, 0x10000, 0x200000,\nota_0, app, ota_0, 0x210000, 0x200000,\n",
        )
        .expect("the table parses");
        let app = application(&scratch, 1024);
        assert!(plan_slot(&table, &app, &scratch).is_err());
    }

    #[test]
    fn two_scratches_never_share_a_directory() {
        let one = Scratch::new().expect("a scratch");
        let two = Scratch::new().expect("another");
        assert_ne!(one.file("app.bin"), two.file("app.bin"));
    }

    #[test]
    fn a_scratch_takes_its_files_with_it() {
        let path = {
            let scratch = Scratch::new().expect("a scratch");
            let file = application(&scratch, 16);
            assert!(file.exists());
            file
        };
        assert!(!path.exists(), "the scratch was removed with its files");
    }
}
