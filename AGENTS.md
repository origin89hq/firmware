# Working in this repository

For hosted PR reviews, follow `Code Review Rules` below without running the local
skills refresh. For other tasks, run `just skills-sync` from the repository root.
Read `skills/origin89-working/SKILL.md` and the relevant domain skills under the
immutable `path` printed by that command. Keep that snapshot for the task; do not
refresh it halfway through work. Before branch, commit, push, or PR operations,
read `skills/origin89-commits/SKILL.md` from that snapshot. Read local instructions
and preserve stronger project constraints and project-specific skills.

If refresh reports cached content, continue with that verified cache and mention
that the script could not check for updates. If no cache is available or
validation fails, report the error; do not claim the shared rules loaded. Local
instructions and the user's request still apply. Do not overwrite local skill
files to fix a conflict without reconciling them.

[Origin89 engineering](https://github.com/origin89hq/engineering) owns the shared
rules. Keep only repository-specific architecture, commands, target constraints,
and exceptions below. Internal RFCs and research belong in
[internal-research](https://github.com/origin89hq/internal-research). Add documentation
only when its value and upkeep are clear; remove AI filler from every message.

Confirmed problems left outside the current fix need an issue in the owning
repository: search with `gh`, reuse a matching issue or create one with evidence,
and return its URL. Follow the shared working skill's unfinished-work rule.
Respect posting restrictions; if filing is blocked, provide the draft and say why.
Finish authorized fixes instead of replacing them with backlog issues.

## What this repository is

The two firmwares of the Origin89 controller, written for the boards in
[origin89hq/hardware](https://github.com/origin89hq/hardware): the controller
on the STM32G0B1RE, which decides, and the comms processor on the ESP32-C6,
which transports. Read [README.md](README.md) for where the work stands. The
design is [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), maintained here and
cited by section; the protocol is [km43](https://github.com/origin89hq/km43),
and the plan with its milestones is
[issue #3](https://github.com/origin89hq/firmware/issues/3).

## Rules that are not preferences

- The STM32 owns every decision, all persistence, all timing and all actuation,
  and runs a full week with the ESP32 unplugged. The ESP32 forwards bytes and
  never inspects them; it holds no key, caches no state, and must never depend
  on the crate that decides.
- Decisions are host-testable. A behaviour returns a typed decision and never
  touches an output; nothing in a domain crate names a peripheral. If logic
  needs a board to test, the seam is in the wrong place.
- Missing, stale or implausible measurements carry their quality. Never a
  default that could be mistaken for a reading.
- No allocator on the STM32, in domain crates or their tests, or in our ESP32
  application and transport code. The sole exception is a fixed-budget heap
  for the ESP32 vendor radio stack, initialized after the recovery download
  window. Its scope and qualification are defined in
  [the comms architecture](docs/ARCHITECTURE.md#the-comms-processor) and F-037.
  Every collection has a named capacity and a documented behaviour when full;
  refuse rather than evict.
- No `unwrap`, `expect`, `panic!`, `[]` indexing or unchecked arithmetic
  outside `#[cfg(test)]`. Match our own enums exhaustively, without `_` arms.
  Never `#[allow]`; an exceptional `#[expect(..., reason = "...")]` says what
  makes it safe.
- Safety timing lives in hardware. The executor is cooperative and cannot be
  the only thing between a maintained contact and a generator running the
  tank dry. Feed the watchdog only when every state machine reports progress.
- The download path into the ESP32 is recovery-critical on revision A
  (#1): it must run before anything that can crash and must
  never be triggered by bytes in the relayed client stream.
- Pins come from the board's netlist and the hardware repository's decisions,
  never from a devkit or a guess. The controller link is the module's UART0
  (origin89hq/hardware#13). One file per firmware names every pin it touches.
- `defmt` on the target; host tools use `tracing`. Do not introduce `log`.
- Build and check commands stay separate from flashing, erasing and
  actuation. Before a hardware operation, confirm the exact target, its
  expected effect and the recovery path.

## Target constraints

- STM32G0B1RE: Cortex-M0+, no FPU, no compare-and-swap, 144 KB RAM.
  Revision A stages updates on the NOR, so the image budget is 480 KB behind
  a 32 KB bootloader, never 512 (#185). Account for monomorphisation; enum
  dispatch for closed sets, traits at target seams. No floating point in
  interrupts or hot paths.
- ESP32-C6: RISC-V, bare-metal `esp-hal`. Wi-Fi and BLE are Espressif blobs
  either way; the security boundary is the STM32.
- Embassy and HAL releases are pinned exactly. Read the release notes before
  moving a pin and revalidate on the board.

## Verification

Run `just check` before committing: formatting, Clippy with the restriction
lints, the host tests, and `cargo xtask check` — cross-compiles for both
targets, the dependency boundaries, the three images built in release and
measured against their slots. Host tests for domain logic, a release build of
the actual target with its linked size measured, then the bench. A build is
not bench evidence and a bench pass is not a winter.

Break a new check on purpose and watch it fail before trusting it. Back up the
file with `cp` first and restore from that copy; `git checkout -- <file>` and
`git restore` discard every uncommitted change in the file, and a hook refuses
them on a dirty path.

## Code Review Rules

Read the shared `origin89-review` skill and relevant domain skills when available.
In hosted review jobs that already provide `.origin89/engineering/skills/`, use
that checkout without running the local refresh. If shared context is missing,
review against the rules below and disclose that limit.

- Flag changes that bypass authorization, lose data or provenance, break a
  supported contract, or turn unknown or stale equipment input into permission
  to act. Check callers and existing guards before reporting a defect.
- Flag a decision reaching the comms firmware, a peripheral reaching a domain
  crate, a client-stream pattern that changes the ESP32's boot, and any output
  whose state at boot, reset or brown-out is not stated.
- Require meaningful success, invalid-input, boundary, and failure coverage for
  changed nontrivial behavior. Hazardous behavior needs its full fault matrix
  and relevant bench evidence; a host build does not establish target linking.
- For Rust domain logic, prefer typed state, errors, units, and identifiers.
  Strings at text boundaries are expected; flag strings that discard useful
  invariants or leave invalid domain states representable.
- Report the trigger, consequence, and precise location. Distinguish checks run
  from missing evidence. Leave formatting to the configured linters, and avoid
  duplicate or speculative findings. A review request does not authorize implementation.
- Keep current PR defects in the review. Track confirmed pre-existing or explicitly
  deferred problems as issues when filing is authorized; comments-only reviewers
  provide a draft and state that it was not filed.
