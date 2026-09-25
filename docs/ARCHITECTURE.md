# Architecture

The design of the two firmwares: what each part owns, why the boundaries sit
where they do, and the rules a change has to keep. A rule with a number lives
where the number is allocated: KM43's `P-`/`L-`, this repository's `F-` in
`REQUIREMENTS.md`, the hardware repository's `A-`/`B-`. This document says why
each rule is what it is, and is cited by section.

It grew out of origin89's `CONTROLLER-V1.md` (2026-08-03), split three ways on
[origin89hq/origin89#16](https://github.com/origin89hq/origin89/issues/16): the
system design came here, the circuit reasoning went to
[origin89hq/hardware#50](https://github.com/origin89hq/hardware/issues/50), and
the plan became [#3](https://github.com/origin89hq/firmware/issues/3) and its
milestones. Where the two documents describe the same boundary, each describes
its own side and cites the other.

## The one rule

> The controller never depends on a client for a control decision.

Its acceptance test: **the site runs a full week with no client connected at
all.** No phone, no cloud, no comms processor. Any feature that cannot survive
that week is a client feature and belongs in the client. The corollary is
where the rule leaks: an advisory input from a client must expire, and its
absence must have a defined behaviour. A forecast hint that decays to
*unknown* is fine if every rule reading it has an answer for unknown. A hint
that holds its last value forever is a dependency wearing a disguise, and it
is discovered in February.

The rule is why control is on a microcontroller and not a Linux board. Three
arguments hold. An MCU with FRAM has none of an SBC's failure categories:
filesystem corruption on brown-out, SD wear, a thirty-second boot that can
hang. An MCU can guarantee a fail-safe actuation path: at reset these pins are
inputs, that contact is open, and a hardware timer drops the run contact
whether or not any code is running. And the box draws from the bank through
the season when the bank is weakest, so it has to be small. Determinism is not
one of the arguments; nothing here needs microsecond response.

## Two processors, and who owns what

| Image | Part | Owns |
|---|---|---|
| `o89-controller` | STM32G0B1RE, Cortex-M0+ | Every decision, all persistence, all timing, all actuation. Runs a full week with the comms processor unplugged |
| `o89-boot` | STM32G0B1RE | The controller's bootloader: the generator lines to their fail state before anything else, the selected bank's manifest verified, trial boots counted and a bad image flipped back. Frozen by the first unit that ships with read-out protection, so it is small and it is first |
| `o89-comms` | ESP32-C6, RISC-V | The comms processor: Wi-Fi, BLE, cloud transport, the credential cache, NTP offers, OTA delivery, and the download window that is the only wire-free recovery path on board A revision A |

Named by role, not by chip. The controller design keeps an STM32H5 as the
upgrade path, and a crate called `o89-stm32` would be wrong the day that
happens.

**The comms processor is a pipe, not a participant.** It frames, forwards and
provisions. It holds no controller secret, caches no control state,
translates no semantics, and never depends on the crate that decides; the one
record it keeps is the network it joins, and the controller holds the master
copy (L-130). The moment it knows what a generator is there are two sources
of truth, and one of them is on the chip that will have a CVE. Its power rail
is switched by the controller, so a wedged radio is recoverable without a
drive and the power argument stays honest.

**The security boundary is the controller.** The comms processor is the
internet-facing part: the one an attacker reaches first and the one being
patched for years. TLS terminates there, and commands are authenticated
end-to-end at the controller as well:

- A controller key made at manufacture and a printed secret, both in the
  controller's FRAM and never exposed to the comms processor. Pairing is a
  Noise handshake under a key the label derives, and the client pins the
  controller key the label's fingerprint vouches for; every session after it
  is a Noise handshake against that key. No private key and no shared secret
  crosses the link.
- Every request after a handshake is sealed under keys only that handshake
  produced, writes included. Authenticating one write and not another is a
  locked door beside an open one.
- Every response and every event is sealed too. A forged command has a
  physical consequence somebody eventually notices; a forged *reading* is
  simply believed, and a comms chip that can answer "bank at 80 %" when it is
  at 30 defeats the product's whole proposition.
- Factory reset and un-pairing are physical acts at the controller and exist
  as no message at all. Not a command that checks a flag: there is no such
  command in the protocol to find.

That is the client–controller authentication: the keys, the handshakes and the
sealed transport are P-226–P-243, with P-044–P-045 and P-085–P-088. It is not the link
between the two chips. While they are on one board that link carries no MAC
and shares no key (L-020): a key the untrusted peer held would authenticate
nothing, and a compromised comms processor is assumed throughout. L-024 is the
day the link leaves the board.

The wire is [KM43](https://github.com/origin89hq/km43): one protocol on every
transport, CBOR bodies with integer keys, request and response with sequence
numbers, an event stream a client can detect gaps in, a version negotiated on
every link-up, and idempotent commands carrying an id so a retry after a lost
acknowledgement cannot start a generator twice. Nothing here re-implements a
byte of it; the `km43` crate is pinned exactly in both workspaces. The link
between the two parts is the module's UART0 with hardware flow control
([origin89hq/hardware#13](https://github.com/origin89hq/hardware/issues/13),
[#2](https://github.com/origin89hq/firmware/issues/2)); its rules are `L-nnn`
in KM43's `LINK.md`.

**The download window is recovery-critical on board A revision A**
([#1](https://github.com/origin89hq/firmware/issues/1)). The module's IO8
strap is unconnected, so the only wire-free way into serial download is
firmware on the comms processor honouring a request from the controller. That
window runs before anything that can crash, and is never triggered by bytes
in the relayed client stream. It is the first requirement, not a feature.
The other route, IO9 held low across a reset the controller performs, is in
the rail sequencer for both revisions and is the bench's on revision A, with
a wire holding IO8 high; on revision B (hardware#48) it works alone, and
whether the firmware may take it by itself is the board's `StrapRoute`
policy. The bench of 2026-09-19 showed why both exist: a flash that died
after esptool's erase left the module with a bootloader and no app, which
reboots forever and never enters the ROM's loader, and only the strap reached
it.

## Repository layout

Two Cargo workspaces: the host workspace never cross-compiles by accident,
and the firmware workspace has its own lockfile and release profile. The
layout below is where things end up; a crate is created in the milestone
that gives it its first code, never ahead of it.

```text
Cargo.toml                 host workspace
crates/
  o89-core/                no_std, no alloc. Decisions, tables, the link-local
                           state machines, the log ring, configuration slots.
                           Names no peripheral. Host-tested.
  o89-comms-core/          no_std, no alloc. The comms processor's decisions:
                           the download window's intake and its link-local
                           state machine. Never reaches o89-core. Host-tested.
  o89-link/                no_std, no alloc. The link's mechanics both cores
                           share and neither decides by: the tick, the
                           requests and beats in flight, the rules every
                           link-local frame meets. Host-tested.
  o89-drivers/             no_std device dialects: Modbus RTU, EPEver, PZEM DC,
                           PZEM-016, VE.Direct text, Pylontech CAN, DS18B20.
                           Tested against committed captures.
  o89-sim/                 The simulated site: seasons, faults, the hostile
                           comms processor on o89-comms-core's own link,
                           crash-at-every-step.
  o89-dev/                 The bench tool: the FRAM, the NOR and the rail's pin
                           over SWD, through the firmware's mailbox.
  xtask/                   The gate.
firmwares/
  Cargo.toml               firmware workspace, excluded from the root
  o89-boot/                STM32 bootloader
  o89-controller/          STM32 application
  o89-comms/               ESP32-C6 application
docs/
  ARCHITECTURE.md          this document
  REQUIREMENTS.md          F-nnn, with sources
  BOARD-A.md               the pin map and the per-revision policy table
  SAFETY.md                the hazard matrix
  sizes.tsv                the size log, a row per image when a change moves it
  bench/YYYY-MM-DD.md      dated sessions
```

`just check` is the gate and runs what CI runs. `cargo xtask check` is the
part of it `cargo test` cannot do because it builds for the laptop: every
`no_std` crate cross-compiled for both targets, the three images built in
release with their `.bin` measured against the slot and a stated margin, the
dependency rules below refused mechanically, the pin table in `BOARD-A.md`
held against the controller's board module, and every numbered rule sorted
into covered, declared untestable or uncovered against `traceability.toml`,
which lists the uncovered rules by name and only shrinks. Flashing, erasing
and actuation are separate recipes that never run from `check`.

## The controller

### Layers, and the rule between them

```text
        ┌────────────────────────────────────────────┐
        │  o89-core   (no_std, no alloc, host-tested)│
        │  behaviours · the store · the log ring     │
        │  configuration · the link-local machines   │
        └───────────────┬────────────────────────────┘
                        │ traits: clock, storage, contacts, ports, buses
        ┌───────────────┴──────────────┬────────────────────────┐
        │  o89-controller (Embassy)    │  o89-sim (host)        │
        │  real peripherals            │  a simulated site      │
        └──────────────────────────────┴────────────────────────┘
```

`o89-core` returns decisions and touches nothing. A behaviour returns a typed
decision and never writes an output; nothing in a domain crate names a
peripheral. `o89-controller` is the adapter: it fills the seams the core
leaves and contains no `if` about a generator, a threshold or a timeout. That
is what makes shadow mode a flag and a simulated winter a unit test, and the
gate enforces it: `cargo xtask check` refuses `o89-comms` depending on
`o89-core`, and any domain crate depending on a HAL crate or reaching for the
allocator. The comms processor's own decisions are `o89-comms-core`'s, and
what the two sides' links share, the tick and the bookkeeping of requests
and beats, is `o89-link`'s, below both cores, so it is written once. If
logic needs a board to test, the seam is in the wrong place.

**Time is a tick, not a clock.** Every duration is measured on a monotonic
millisecond count since boot that a clock write cannot move, because the wall
clock is settable by any enrolled client and movable by the comms processor,
and a duration measured on it is a duration somebody else sets (P-004). A
behaviour that needed the date would be a behaviour that stops working at a
site whose clock nobody has set, which is why autostart needs no calendar and
why exercise runs and quiet hours wait (below).

### Design rules

Everything is swappable, but the mechanism differs by boundary, because the
naive traits-everywhere version costs real resources on this part. Dual-bank
A/B leaves an image budget of 248 KB, not 512; generics monomorphise, so
every instantiation duplicates code; `dyn Trait` in `no_std` means vtables,
no inlining and usually a heap.

| Boundary | Mechanism | Why |
|---|---|---|
| The seams: clock, storage, contacts, ports, buses | Trait, static dispatch | What makes the core host-testable. Monomorphised once per target, so no runtime cost |
| Devices: EPEver, PZEM, shunt, BMS | Enum dispatch | A closed set known at build time. Zero indirection, and the compiler catches a missing variant, which is the same reason there are no wildcard arms anywhere in this repository |
| Transports | Trait for the byte pipe, one protocol above it | Only the framing differs |
| Behaviours: generator, frost, schedule, load-shed | Concrete state machines | Extending means adding one, not swapping one. A trait here buys nothing and costs clarity |
| Randomness | Manufactured, not a seam | The part has no RNG peripheral: a generator whose state the station wrote, so there is nothing behind a trait to vary (below) |

The distinction is open set against closed set. Peripherals and transports
vary by target and by test, so they are traits. Devices and behaviours are
enumerable at build time, so they are enums.

Alongside: no `dyn`; our own enums matched exhaustively; `#[must_use]` on
every decision, verdict and outcome type, because a dropped decision is a
rule nothing performed; fixed capacity everywhere with a written overflow
policy, so what is dropped when a queue is full is decided now rather than
discovered at −30 °C. Telemetry drops. A safety event does not. The full
coding rules are #3 §3, enforced by the manifests and the gate.

### Where randomness comes from

The STM32G0B1 has no RNG peripheral; `RNG` does not appear in the part's
metadata at all. Every challenge and every ephemeral key the controller uses
is a draw from a deterministic generator whose thirty-two bytes of state the
manufacturing station drew from its own CSPRNG and recorded nowhere (P-237).
The controller key is made the same way, at the same time, and only its
private half is stored; `CS` is derived when it is needed (P-235). A key
minted from whatever a Cortex-M0+ scrapes together at power-on is a key
nobody can vouch for, which is why neither is made on the part.

**The successor is on the part before the draw is used.** Each draw replaces
the state with a one-way function of itself; `km43`'s `Drbg` writes the
successor through the store, reads it back off the part, compares, and only
then releases the draw, and the store reads the FRAM rather than the RAM copy
(`drbg.rs`). A reset at the wrong moment therefore loses a draw and never
repeats one: the same challenge twice is a recorded `Hello` accepted twice,
and the same ephemeral twice is a session key given away. A state read out
with a probe yields the draws after it and none before, so a session recorded
before a capture stays sealed.

**It is never re-initialised.** A factory reset does not touch it, a boot that
finds it damaged keeps it damaged, and a record that cannot be read back
refuses every `Pair` and `Hello`, answers `Discover` with error 18 and raises
condition 22 `entropy unavailable`; a bench repairs it by erasing the part, not
by the firmware choosing a state. Bytes from elsewhere may be mixed in through
the same one-way step, never in place of it.

**Manufacture is one transaction.** `o89-dev store write-secret` draws the
printed secret and, on a unit that holds neither, the controller key and the
generator's first state, and stages them through a mailbox operation; the next
boot writes each onto a record never written, marks the transaction applied
with the fingerprint of the key the part holds, and only then returns a store.
The host prints P-049's v2 label, `km43:2:<device_id>:<printed_secret>:<fp>`,
from that applied record, so `--resume` never reads the key back, and it
writes neither the key nor the seed anywhere. A transaction onto a unit that
holds either is refused; `--replace` changes the printed secret alone and
keeps the fingerprint. A cut before the intent lands keeps what the unit held;
a cut after it replays the boot's writes, none of them twice. An intent that
would leave no controller key is discarded whole and the boot goes on.
Pending or unacknowledged transactions refuse new writes, and output and FRAM
acknowledgement cannot be atomic: a crash after output but before
acknowledgement can repeat the same label on resume. The intent keeps the
secret and the fingerprint, never the key or the seed, once applied.
`o89-dev store blank --yes` is the erase a bench repairs a part with: it zeroes
the map, reads it back and reboots onto an unborn unit, which `write-secret`
then gives a new key, generator and label. It is also how a part written under
an earlier map is brought onto this one, since its old bytes read as a damaged
key or generator.

### Embassy, and why the choice is cheap

Embassy, confined to `o89-controller`. The drivers are already async state
machines: a Modbus exchange is send, await a reply, time out, which in a
superloop is a hand-rolled state machine per bus, and that is where the bugs
live. `embassy-stm32` gives a buffered UART fed from its interrupt, which is
what the framing wants; its DMA ring overran on this part (#39). It is
pinned to a revision of Embassy's `main` rather than to 0.6.0, because that
release's handler empties the data register even when its ring is full: the
byte is dropped and `RTS` never asserts, so flow control cannot hold the
module off for a task that is late (F-090, #66). And the
one real concurrency constraint is *do not
block each other*: a slow Modbus timeout on one bus must not stall the frost
tick or the link. Nothing here is fast; a device is polled every two seconds
and behaviours tick once a second.

The core names no peripheral, so the executor lives in the adapter and
nowhere else; if it turns out wrong the adapter is rewritten and the
controller is not. RTIC would make a better safety case if a certification
conversation ever starts, and the adapter is small enough that revisiting is
cheap.

Three rules come with it:

1. **Safety timing stays in hardware.** The run-enable monostable on board B
   does not care which executor is running, which is why it is there. A
   cooperative executor must never be the only thing between a maintained
   contact and a tank running dry.
2. **No task blocks, and every `await` has a deadline** or a documented
   liveness argument. Key agreement is the one computation that cannot
   yield, a quarter of a second per X25519, and it is alone in thread mode
   below every task that times anything (P-243, below). The failure mode of a cooperative executor is one task
   starving the rest, and it looks exactly like a dead controller.
3. **The image is measured every time the gate runs**, the `.bin` against
   the 248 KB slot with a stated margin, and a change that moves it records
   the row in `sizes.tsv`. The number is wanted early, not in November.

Exact pins on every firmware dependency, because Embassy and `esp-hal` move
under a caret and a toolchain that moves in January is a winter lost. Moving
a pin is a commit that names the release note it read and the bench that
revalidated it. `defmt` on the target, so log strings live on the host rather
than in the flash budget; `static_cell` for the statics the executor needs,
so there is still no allocator.

### Boot, in the order the hazards dictate

Each step is a requirement with an issue behind it. Signals are named by
role; `BOARD-A.md` maps them to pins.

1. **Reset vector.** `RUN` and `KICK` driven low, push-pull, before the stack
   is set up if the runtime allows it and as the first statement of `main` if
   not ([origin89hq/hardware#30](https://github.com/origin89hq/hardware/issues/30)).
   The three RS-485 transmit lines driven high so the transceivers stop
   holding their buses low
   ([origin89hq/hardware#28](https://github.com/origin89hq/hardware/issues/28)).
   The four module lines (transmit, RTS, `EN`, `BOOT`) left as inputs, never
   driven high ([origin89hq/hardware#17](https://github.com/origin89hq/hardware/issues/17),
   F-003).
   The generator run reason is read from FRAM *before* the outputs move, so
   a reset inside board B's ride-through window can resume an automatic
   start ([origin89hq/hardware#18](https://github.com/origin89hq/hardware/issues/18)).
   Board B revision B budgets that window at 15 s
   ([origin89hq/hardware#51](https://github.com/origin89hq/hardware/issues/51),
   B-20), of which 3 s is the controller's: when it decides to resume, `RUN`
   is up and the first kick sent within 3 s of the reset, FRAM read included
   (F-016). Revision A has no window; the contact has already opened, and the
   boot record says so.
2. **Reset cause** read and cleared; the previous image's last words from
   `.uninit` RAM, the pattern the self-test proved. Both go into the boot
   record with the RTC backup-domain state (L-143).
3. **Clocks**: HSE to 64 MHz; LSE to the RTC, asserted rather than assumed.
   An RTC on LSI looks alive and does not survive the backup domain.
4. **IWDG armed** at 8 s and never petted from a timer. A supervisor pets it
   only when every task has checked in inside its declared period; a task
   that has not gets its name written to `.uninit` and the part resets.
   Proven on the bench by the self-test's one-shot starvation.
5. **PVD armed** above the FRAM's minimum supply. On the falling edge no new
   FRAM transaction starts, and one in flight completes. Seven brown-outs on
   the bench destroyed both counter slots at once; the write discipline is
   the answer, not a hope about the part. Then the **module rail** back on
   with `EN` held low, before any bus: revision A drops the rail through
   every reset, so this path is all a reset adds to a cut (F-005), and the
   boot waits the rail's settling before the FRAM is touched, so that the
   switch-on of a cold boot never lands inside a write.
6. **FRAM read**: the secret, the controller key, the generator's state,
   the epoch, the eight slots with their generation marks and the dedup
   table, the generator run reason, the panic record, the boot count, the
   byte budget, the
   authorised comms release, the network master copy; the configuration
   sections when M5 adds them. One read into a `Store`, and the rules that
   tie one record to another applied where both are in hand: a fresh unit
   gets its first epoch, an epoch record behind a slot is raised to it and
   the table is repaired as P-239 says (F-026),
   the boot count climbs, the last words are written down with it, and
   every window measured on the tick restarts at zero (P-121).
   The supervisor is not running yet, so this phase bounds itself: every
   FRAM transfer is cut by the driver's timeout, and `Boot` is written to
   the last words as a provisional blame until the store is read, so a
   boot the watchdog cuts short here is named by the boot after.
   **NOR scan**: the log ring's head and the time floor, the newest
   timestamped record (L-140).
7. **Outputs to their declared fail state**, per output, from configuration,
   and shadow unless authority was granted.
8. **Buses up**: three RS-485 USARTs, FDCAN, two LPUARTs, 1-Wire, ADC.
9. **The module rail sequence** (the safety architecture below): the rail
   task, which releases `EN`, then the link task.
10. **Control tick** at 1 Hz. Boot-to-first-kick is measured and logged; the
    hardware repository is waiting on that number
    ([origin89hq/hardware#18](https://github.com/origin89hq/hardware/issues/18)).

### Tasks and the watchdog

Each task owns a peripheral and declares a check-in period: supervisor,
control, link, recorder (the only owner of the NOR bus), one per
RS-485 channel, CAN, one per VE.Direct port, 1-Wire, ADC, selector, lamp.
Bounded channels between them, `static_cell` for what the executor needs, no
allocator. The FRAM is the one part two tasks keep records on: the boot
reads every record, then hands each to the task that writes it, the client
protocol's to the link task and the rest to the recorder, and the part to
both behind one async mutex held for a single blocking transfer. A task
never writes another's record, so the RAM copy each keeps is the part's.
Nothing blocks; a bus that hangs is a task that misses its
check-in, which is a reset, which is the fail state.

**Three executors, by priority.** Thread mode is the lowest priority a
Cortex-M0+ has, so it holds the one job that computes for seconds at a
time, key agreement (a `Hello` measured 2.46 s on board A), and nothing else
(P-243). Every task that times
anything, control, link, rail and recorder, runs on the control executor,
driven by `USB_UCPD1_2` at `P12`, and preempts the worker whenever it has
anything to do; the tasks there share it cooperatively as they always did.
The supervisor runs from `CEC` at `P8`, above both, so a transfer that never
returns and holds the control executor is still a task named in the last
words before the watchdog fires: the watchdog is the floor either way, the
blame is what the next boot reads. The time driver and every bus interrupt
are above all three. The M0+ implements two priority bits and embassy-stm32
names levels for four, so only `P0`, `P4`, `P8` and `P12` are real here; any
other truncates to the highest, where nothing preempts anything, and a
compile-time assertion refuses them. The worker is on the roll with a ten-second window, and
checks in between jobs and every idle second.

**The IWDG is fed only when every state machine reports sane.** A watchdog
fed from a timer interrupt is a watchdog that does not work.

### The store: every reading carries its quality

The site is buses and devices from configuration, and a store of signals
each carrying validity and provenance. Drivers speak to a port trait so a
captured exchange is a host test. RS-485 on this board is auto-direction with
the receiver always on, so every driver hears its own frame and must discard
it: a rule, with a test. Whether an input is a pin on the controller or a
register on a Modbus device is a wiring decision resolved in configuration;
onboard I/O is addressed like a remote module, which is the seam that makes
remote modules a later implementation rather than a later refactor.

**Absence is representable.** A missing probe is not 0.0 °C and an unknown
state of charge is not 0 %. Every slot carries a quality beside its value,
because a controller that renders absence as a number is the same bug as a
room card showing an inverter's heatsink at 0.0 °C while the room is at −0.9.

**Provenance decides what a number may be used for.** The same quantity from
three sources is three different qualities of number. KM43 allocates the
provenances (measured, counted, derived, estimated, reported, commanded) in
an allocation order, not a trust order: a BMS *reporting* its own
charge-current limit is the most authoritative number on the bus, and a
behaviour written from a `≥` would refuse it and act on an inference instead.
So behaviours name the set of provenances they will act on. An estimated
state of charge may drive display and coarse inputs; it may drive generator
autostart only when somebody has explicitly accepted that it is an estimate,
which is a named parameter rather than a flag because that is what it is.

**A hung instrument is not a steady site.** A channel stops being true two
ways, and only one looks like it. The bus goes quiet and nothing is written;
a **maximum age** on the last write catches that. Or the probe stays powered,
the bus keeps answering, and it hands back the same plausible number for a
week with quality *measured*, and the pipe freezes anyway. So a channel also
carries **how long its reading may go unchanged** before the instrument is
presumed hung; past it the slot reports *stale*, which a behaviour that needs
a current reading already refuses. Three things restart that clock, each an
instrument doing something: the value changing, its quality changing, and a
channel that went silent coming back, which starts a new run rather than
continuing the old one. It is per channel and optional, because for a starts
counter, a selector nobody has turned or a tank that is still full an
unchanging number is the truth. What it does not catch is a thermistor gone
open-circuit reading a noisy rail: that is a plausibility check and belongs
to the driver that knows the channel's range, not to a store that must not
derive anything.

**V1 reads state of charge; it does not compute it.** A shunt's counted
figure or a BMS's own, and otherwise bank voltage under load sustained for N
minutes. No estimator, no coulomb counting, no Peukert model. The autostart
decision is hysteretic and coarse, so it needs a defensible number rather
than a precise one; on a lead-acid bank *below the start figure continuously
for fifteen minutes* is crude, honest, drift-free, and labelled for what it
is.

**The capability audit is generated, not written.** Behaviours declare what
they need and at which provenances; the store knows what it has and at what
quality; the gap is the shopping list. A missing capability degrades quality
and never blocks function: autostart still works on voltage-plus-duration,
labelled crude, and a shunt makes it good. The moment an accessory becomes a
paywall the product has become the thing it is positioned against.

### Behaviours: parameters, not an engine

A general rule engine on the MCU means an AST, an encoder, a validator,
versioned storage, an upload protocol, latch and hysteresis semantics, and a
test suite proving it evaluates identically to whatever the client shows. It
buys the ability to express rules nobody has asked for yet. The behaviours
that must survive every client dying are a short list:

```text
generator:  autostart (bank_voltage | state_of_charge) · start_below · stop_above
            provenance (counted_only | estimate_accepted)   — charge source only
            duration · start_window · min_runtime · max_runtime · cooldown
            human_stop_inhibit · stop_grace · unknown_grace · ac_live
            quiet_hours                    — not built: needs a wall clock
            exercise: day · time · duration · skip_if_ran_within
                                           — not built: needs a calendar
frost:      channel · setpoint · hysteresis · output
            on_unknown (energise | de-energise | hold) · unknown_grace
schedule:   output · start_time · duration · days
load_shed:  threshold · outputs[]
```

Each is a verified state machine with parameters and a shadow flag per output
(P-103). No `crank_time` and no `crank_retries`: the start kit owns cranking,
and duplicating its protection here would be two things disagreeing about a
starter motor. The asymmetry decides it: parameters that turn out too rigid
cost a V2; an engine subtly different from the client's costs a generator
that starts when it should not, four hours from a road, with no way to see
why.

**Shadow is per output, and an output arrives in shadow.** Sense, evaluate,
and log what would have been done without touching the output. Authority is
granted one output at a time, so *granted* is the state somebody has to ask
for rather than the one a misread configuration falls into. A month of shadow
compared against what happened finds the wrong threshold and the 3 a.m. start
on a cloudy Tuesday before either can matter.

**Exercise runs and quiet hours are not built**, and the reason is a design
decision rather than a gap. Both need to know what day it is, and a behaviour
that may depend on the wall clock has a fail state nobody has chosen: what a
weekly run does in the window before the clock has ever been set. Skipping
forever is a generator that does not start in an emergency; running on boot
is an engine that starts every time the power blinks. Neither is obviously
right, so it waits for somebody to choose rather than being inferred by
whoever writes it.

### The generator

The generator is started by a kit that owns the engine switch, the fuel
valve, the choke, the crank sequence and the retries; the controller owns
deciding. The interface is **a maintained dry contact: closed is run, open is
stopped**, over a pair to a lockout switch and the kit's 2-wire input. There
is no crank timer, no choke output and no preheat output in this firmware.
The contact itself, two relays in series behind a hardware run-enable
watchdog on board B, is the hardware repository's (`GENERATOR-BOARD.md`, and
the reasoning under origin89hq/hardware#50); what the firmware owes it is the
kick, and the rules below.

**Two facts give the state**: is there AC at the panel, and is our contact
closed. Proof of running is measured, not assumed: 120 V at 60 Hz on the AC
meter at the panel is the evidence the engine caught, and a contact closing
is not an engine catching.

| AC | Our contact | State | Behaviour |
|---|---|---|---|
| no | open | `stopped` | Normal. Autostart may fire |
| no | closed | `starting` | Waiting for AC. Gives up on this attempt after `start_window` |
| yes | closed | `running` | Ours. We can stop it |
| yes | open | `running, not ours` | Do not interfere. Do not command. Not a fault |
| yes, past `stop_grace` | withdrawn | `stop not honoured` | Notify. Never retry |
| any | open, attempts spent | `gave up` | Nothing but a person starts it trying again |

KM43 allocates the six. **Both facts can be missing, and then none of the
states is true.** If the AC meter is not answering, the controller publishes
nothing for the channel rather than the nearest state. *I cannot see the
line* is not *the engine stopped*, and the two have opposite correct actions:
one holds a run that is going fine, the other ends it. A controller that
confused them would withdraw, read *no AC, contact open* on the next poll,
call that `stopped`, and close again into an engine that never stopped.

**Never grab a generator somebody else is running.** The fob and the 2-wire
input are OR'd, so closing our contact on an already-running engine converts
*the fob owns it* into *both own it*, and from that moment the human's stop
button does not work: somebody presses stop, the engine keeps running because
our relay is holding it, and they reach in. So we leave it alone. Everything
that does not touch the contact keeps working while it is theirs: the bank
charges, load-shedding releases, run hours accumulate because the engine does
not care who started it.

**Do not fight the person.** AC disappearing with our contact *open* is
somebody stopping their own engine, and it inhibits autostart for
`human_stop_inhibit`; otherwise they stop it, the bank is still low, it
restarts, and they conclude the system is broken. AC disappearing while we
are commanding run is our run dying: withdraw, log, wait `cooldown`, retry at
most twice, then give up. Out of fuel, an oil-alert shutdown and somebody
killing it at the engine switch are indistinguishable from here, and
hammering a start line into any of them is wrong. Our own contact is the only
thing that tells the two cases apart.

**A sustain is continuous or it is nothing.** *Below the start figure for
fifteen minutes* means fifteen minutes of being below it, not fifteen minutes
since it first dipped. A well pump sags the terminals for three minutes an
hour on a bank resting at 12.4 V, which is not a bank that wants an engine,
and counting from the first dip cranks the generator about six hundred times
a month. A bank genuinely being drained keeps falling until it sits below the
figure without wobbling back over it, so it corrects itself.

**Giving up is a state, not a log line.** Every closure that was not a real
run spends one of a persisted attempt budget: a start window that expired, a
run whose AC died at ninety seconds, a run that hit its ceiling. Only a run
that ended on its own stop condition having served `min_runtime` refills it.
There is no decay: a budget that refilled itself with time would retry once
an hour forever, which is the same destroyed starter arriving in March
instead of February. It comes back when a person says they have looked, and
it outlives a reset, because a brown-out between attempts is the same event
that would clear a counter held in RAM.

**After the contact opens, the engine may keep running for a while.** Most
sets cool down after a stop, so proof of running sees live AC after every
normal stop. `stop_grace`, sized per generator at commissioning, is the
window inside which that is the engine doing what its maker documented; only
AC that outlives it is `stop not honoured`, logged with how long it outlived
it. Too short a window raises the alarm that exists for the fob-latched case
on every ordinary stop, and an alarm that fires on every stop is one nobody
reads.

**A start below −20 °C is a decision, not a default.** The kit's choke
actuator is specified to −20 °C and its maker says not to remote-start below
it. The coldest night is exactly when the generator is most needed and least
able to start. Refusing protects the actuator and lets the pipes freeze;
starting anyway risks the actuator and may still not start. Whichever is
chosen is chosen, logged with the outdoor temperature that justified it, and
visible afterwards. The behaviour reads the outdoor probe it already has, and
a missing probe is not a permission either way.

**Proof of running cannot come over Wi-Fi.** Making the `starting` to
`running` transition depend on a smart plug on the LAN makes it depend on the
comms processor, the association and the network, on the machine where not
knowing the state is most dangerous. The AC meter is on a bus the controller
reads itself.

### The selector, the gestures and the lamp

Inferring intent is good; being told is better. One three-position selector
at the controller, as on every industrial panel:

- **Auto**: as above.
- **Off**: never command the generator, for any reason. A behaviour that
  needs it reports itself *inhibited* rather than silently failing.
- **Manual**: the operator is driving. The controller monitors and logs only.

This is a different thing from the lockout switch at the genset. That one is
a service lockout: nothing can crank while your hands are in there. This one
is an operator override. An operator taking control must not find the
generator still running because the last decision left it there: taking
authority back puts the output at its fail state.

**The selector is also the physical act the protocol needs.** Un-pairing and
factory reset must be acts nobody can perform over the wire. A deliberate
gesture on the selector opens pairing, with the first-enrolment boot exception
below for board A revision A, which carries no pushbutton. There are three
distinct gestures because P-117 forbids one press meaning two things: the
pairing window, the time-floor override and the factory reset (P-066). Every
transition passes
through *Off*, the position in which the controller never commands the
generator, and the person making it is standing at the panel. Revision B's
button ([origin89hq/hardware#11](https://github.com/origin89hq/hardware/issues/11),
A-42) takes over with at least the same three gestures; the selector gestures
stay defined so a unit with either board reads the same.

Until [firmware#60](https://github.com/origin89hq/firmware/issues/60) adds the
button, revision A also opens the same 120-second window at power-on when the
client table read from storage is valid and empty and the boot has a usable
epoch (P-066, F-091; owner decision
2026-09-24). `Revision::first_enrolment_at_power_on` owns the revision policy;
revision B disables it. Absent, corrupt or unreadable storage opens nothing,
even if boot repairs the table. F-026 still repairs a lost table durably:
that repair boot stays closed, but the next boot reads a valid empty table
and opens the window. The cost is explicit: client-table corruption restores
power-on eligibility from the next boot, after recovery has already lost all
enrolled clients; no separate "enrolled once" marker is kept.

The deadline starts at boot, never link-up, and expiry does not reopen it. A power cut at an unattended, unpaired site
opens it with nobody there. This exposure ends at the first enrolment: that
Pair closes the window, and subsequent boots open nothing. Factory reset
restores eligibility on the next boot under the new epoch. The pairing
handshake is unchanged; a message 1 that does not open neither enrols nor
closes the window. The window
uses the same steady lamp and L-193 to L-195 reports, and grants no time-floor
override. The selector gesture still works during and after it.

On revision A, hold **Off for two seconds**, then make three excursions,
returning to Off after each. Hold each outer position for at least 300 ms;
no outer-position or intermediate-Off leg may exceed three seconds:

| Excursions from Off | Final Off hold | Act |
| --- | --- | --- |
| Auto, Auto, Auto | 2 s | Open the 120 s pairing window |
| Manual, Manual, Manual | 2 s | Arm one floor-crossing time write |
| Auto, Manual, Auto | 10 s | Advance the epoch, then free every slot and empty the dedup table |

The controller samples every 10 ms and accepts a position after 50 ms of
unchanged samples. Both contacts low is unknown. Unknown input, a sample
gap greater than 100 ms, or an invalid sequence cancels the gesture. A
completed gesture fires once; leave Off before starting another. The floor
permission ends on consumption, departure from Off (before debounce), lost
sampling, or 120 seconds. Pairing never arms it. The time-operation handler
must check it when processing the request and consume it only on an accepted
floor-crossing write; rate-limit refusal does not consume it.

During the pairing window the status lamp is steady. A watchdog fault
retains priority over that indication. Reset closes the window before
requesting persistence. A failed reset keeps enrolment blocked; after a
successful reset, a new pairing gesture is required in that boot; the next
boot may open F-091's first-enrolment window.

**One lamp, meaning by pattern.** Two LEDs share one light pipe, so what a
person sees is one lamp: a slow heartbeat is a controller that is alive,
linked and on the network; a double heartbeat is alive with no network; a
fast blink is a fault. The controller learns link and radio state over the
protocol and renders it; the board has no lamp of its own for the radio.

### Sessions and writes

Sessions are a state machine in `o89-core`, `Sessions`, driven by the link
task beside the link-local one, and host-tested the same way: frames and
ticks in, answers and closes out. The link admits and frees connection rows
on the comms processor's word through a `Rows` seam and drops every row with
the link; the sessions decide what a row holds: at most one live challenge,
drawn when the row is accepted and again by a `Discover` that finds it spent
or 120 seconds old; at most one pairing handshake (P-229); and at most one
session, bound by a `Hello` that proves the slot's key and replaced by the
next one that does (P-076). The session's id is the row's handle. `Endpoint`
is the one place a frame goes to one state machine or the other, by opcode,
and the adapter and the simulator both drive it.

**Key agreement never runs where a frame arrives** (P-243). What is cheap is
done there, in P-226's order: the body and its suite, the challenge consumed,
then the label's tag on pairing message 1 (an HKDF chain) or the admission
tags of every occupied slot on a `Hello` (eight HMACs, P-238), then the
window and P-240's table check, then the draw. A peer that fails any of them
costs no DH and is answered at once: bare error 10 or 12, counted, or a
refusal tagged under the label's refusal key, uncounted (P-241). What is
left is a `Job`, owned and self-contained, one per row: pairing message 2,
message 3 with the slot's admission key, or a `Hello`'s proof and answer.
The link task hands one to the worker only when none is out, picking the
next row after the last one served, and answers with its `Done` when it
comes back. A result for a handshake abandoned since, by a second one on the
row, the row going, 120 seconds, a failure or a factory reset, is recognised
by its ticket and discarded. The worker holds the controller key and the
label and writes nothing; every FRAM write a handshake needs, the draws and
the slot, is the link task's, before the answer that depends on it.

**At message 3 the slot lands before the answer names it** (P-064): the
window read again, P-240 run again with the client key message 3 proved, the
next challenge drawn, every session on the slot unbound, then the slot
written as P-239 says. A slot that does not land is outcome 7: nothing
enrolled, the window left open, condition 23. The pairing's keys seal the
answer and are dropped with it; a pairing opens no session.

**Every slot holds a role** (P-250), written in its key record with the
key, so no cut separates them (P-239). A pairing through the label is the
owner when no occupied slot holds one and an admin otherwise; the same key
pairing again keeps its role; and the role is decided again at message 3
with the slot, because another pairing may have enrolled an owner in
between. `client_kind` and the link's transport are shown and decide
nothing. At most six slots hold `admin` and one `viewer` (P-258), so P-240
runs with the ceilings in its steps: a free slot is an admin's only below
six, and a reclaim by label takes only an admin's slot, never an owner's
or the viewer's. km43's `Allocation::choose` reads no role, so
`Clients::place` runs P-240 itself (origin89hq/km43#141). The mask is the
role's row of the registry, computed from the record and never stored
(P-105); the network and cloud sections, and the scan list, are read only
with bit 5, and a slot without it is sealed error 20 before the section is
read (P-251).

**Every request after a `Hello` is sealed** (P-231), opened under the
session's keys before anything is read. The opener holds P-022's window: a
`req_id` it accepted already, or below the highest less `MAX_INFLIGHT`, is
dropped unanswered, uncounted, and refreshes nothing. Only a request that
opened refreshes the session (P-077); a tag that fails counts against the
connection, and eight inside a minute close it (P-051). A session answers
only while its slot still holds the enrolment it proved: a re-key or a
reset unbinds it first, and the mask is the role the slot's current record
holds.
A write carries no client of its own and no counter; its session is the only
statement of who sent it (km43 #134). A `Command` goes through `admit` in
P-080's order: the dedup lookup, the in-flight entry landed, then the
execution; a dedup write that fails is error 7 and nothing runs (P-079).
Commands are reserved until an output has been granted authority.
`GetConfig` opens before reading identity, network, or a behaviour's shadow
flag. `SetConfig` checks the mask, then `check_version`, then section
validation, then the inactive slot. Structure errors answer Error 1; invalid
values answer SetConfigAck 3. Network reads use `NetworkRead`, which can
report `psk_set` but cannot hold a passphrase. A write omitting `psk`
retains it only for the byte-identical SSID.

The link task keeps the records the client protocol writes, the epoch, the
generator, the slots and the dedup table, through its own lease on the FRAM;
a draw is two FRAM transfers, so a challenge never waits behind a NOR erase
in the recorder. The selector's factory reset is served there too: every
session ends and every handshake is abandoned before the epoch moves, and
the slots are freed under the new one after it lands.

### The link

USART1, interrupt-fed into the driver's ring, and KM43's frame reader and
writer. The core
holds the link-local state: link-up and `boot_id` invalidation, the heartbeat
and the recovery ladder with the board's revision policy (below), connection
rows and challenges, network configuration push, time offers with the floor,
cap and rate limit, and the comms release flow. After every accepted `LinkUp`, the controller
compares the module's `net_version` with its persisted network section and
pushes `NetConfig` whenever they differ in either direction (L-133). A local
network write also owes a push. One immutable snapshot is tracked in the
bounded request table; retries retain its request id and bytes. A newer write
supersedes that request. A refused or exhausted request raises a probe note;
the next link-up compares again.

Factory reset ends sessions and writes the network clear before advancing the
epoch. The clear increments the network version and retains country and
hostname, so it remains encodable after reboot (L-134, L-135). After the clear
commits, reset scrubs the entire old slot before advancing the epoch, leaving
the current cleared record untouched. A failed clear or scrub stops the reset;
a retry finishes removing the old credentials. A damaged network record is erased across both slots before
the epoch advances; a failed erase also stops the reset. An absent record is
erased too, so a retry finishes removing residue after a partial erase. No
country or hostname is invented, and the section reads absent afterwards. A
never-written section remains unwritten. If that unit meets a module reporting
a nonzero network version, it sends `ClearUnwritten`: version zero with no
credentials, country or hostname (L-133). The module erases its cache durably
before reporting `stored` and version zero, and stops both Wi-Fi modes until a
valid nonzero configuration supplies radio metadata. An erase failure still
clears the RAM configuration and disables Wi-Fi; the acknowledgement and next
`LinkUp` retain the previously persisted version, and the controller retries at
the next link-up (L-137). Unanswered clears use the same bounded retry machinery
as written network changes. A module already reporting zero needs no clear.
A corrupt or malformed master still raises `NetworkWithoutMaster` until it is
replaced or reset; damage is not evidence of an unwritten section.
Equal-version collisions remain tracked in [KM43 #100](https://github.com/origin89hq/km43/issues/100).
The phone-to-Wi-Fi bench exit, including unwritten-clear radio shutdown and
reconfiguration, remains open and depends on #90's comms side.

The adapter owns the bytes
and the rail pin. The ROM's boot text arrives on the link at 115200 after
every module reset while the link runs at 921600; the framer resynchronises
through it and counts it, and a count far from the bench's baseline of about
1 140 refusals per module boot, the ESP-IDF bootloader's log included, means
the link is wrong (#2). The state machine takes decoded frames and
ticks and answers typed actions, so the whole rulebook runs on the host
against a hostile peer, the comms processor's own link with a named
capability set on top: linked once the
controller's own `LinkUp` is answered and not before, a changed `boot_id`
dropping every connection, a heartbeat every two seconds answered at once,
the ladder measured from the peer's last answer to a request of the
controller's and never from what it says of its own accord, so a comms
processor that talks but cannot hear is cut at sixty seconds, the ladder
suspended while a release installs, and the request counter with its four
outstanding and three attempts. The
controller's `boot_id` is a hash of the part's unique id and the boot
count (F-039): the G0 has no RNG, and what L-040 needs is a number that
is new at every boot and never read back from RAM, which a boot count kept
on the FRAM and advanced at every boot is; two boots
share a value with the chance two random draws would, one in 2^32.
Every controller `LinkUp` carries the device secret's `device_id` as key 8
(KM43 L-035), the one fact about the controller the comms processor keeps:
it names the controller in the mDNS advertisement and nothing reads it
otherwise. A boot without a secret has nothing to state, so its link stays
down on purpose: no `LinkUp` goes out, the module's is left unanswered, and
the ladder does not cut (F-039). A boot whose L-195 revisions are spent is
down on purpose too, and differs in one thing: it still answers the
module's `LinkUp`, because it has a statement to answer with.
A connection the comms processor announces is refused as not yet linked
before the `LinkUp` exchange and otherwise goes to the session layer's rows
(above). A frame from the comms processor that is not four elements is
refused with `Error 1` at `0, 0` before any element is read (P-025, P-028);
it names no connection, so it stays on the link. Each answer to a heartbeat of the controller's carries the comms
processor's count of connections; three in a row that disagree with the
rows close every connection with one `CloseConnection` naming handle 0, and
its answer frees every row (L-102), so a release lost on the wire leaks a
row for six seconds rather than until the next reboot. Under a major
mismatch the peer would refuse that close (L-050), so nothing is counted
and a close already owed waits for an agreed version. The comms firmware
counts the rows of its own table (below), and its answer to the close
reports how many transports it closed (L-090). Time offers go through a bounded
queue to the recorder, which owns the RTC and reads the newest timestamp from
`Ring::floor` when the calendar is unknown. Each value retains its receipt tick
and advances by the monotonic queue and scan delay before admission. A failed scan never becomes the build-time fallback. The first
set must lie within ten Julian years of the floor; later offers may correct
at most five seconds in either direction. The fifteen-minute acceptance limit
uses the monotonic tick and survives comms resets. Each accepted change writes
KM43's `time set` body with the old value, new value and `ntp-via-comms` source.
Records acquire timestamps once the calendar is known; earlier records stay
untouched.

The RTC adapter admits reads and writes only with a ready LSE source, for
2000–2099. Its five TAMP backup words hold a format marker, the fractional
millisecond offset (the HAL sets whole seconds), and an unfinished change's old
and new values. The marker is invalidated before a calendar write and committed
after it; interruption before commit leaves the calendar unknown. An applied
change waits for its audit append, retried at most once a second. No later offer
is applied until that audit lands. The pending audit survives link loss and
controller reset. A reset between append and journal acknowledgement may repeat
the original audit record, without applying the change again. Acceptance is
returned only after both writes succeed and remains replayable for the protocol's
three 500 ms attempts, keyed by request ID and original value. Link loss or
expiry clears that bounded reply cache so IDs can be reused.

Boot validity requires the backup-domain flag, ready LSE and a readable marked
calendar. Signed client Time and its floor override remain dependent on #85,
#86 and km43#73; the reset and backup-cell tests in #87 still require board
evidence.

On the controller the link task owns USART1's pins for the life of the
part and builds the UART only for as long as the module is powered: the
rail task says the rail settled, the UART is built and the statement goes
out (F-006); the state machine asks for a cut, the UART is dropped, its
pins back to inputs, and only then is the rail task asked (F-003). What
the sequencer answered and every settling come back to the link as words
on a bounded channel. The UART's interrupt fills the driver's ring of
two frames. A DMA ring on `DMA1` channels with interrupt lines of their
own was tried first and overran from the first byte on board A, as the
recorder's DMA had (#39), and the bench decided. Every await in the task has a deadline: a read
waits one tick, a write two hundred milliseconds, so a module holding
`CTS` costs a frame and never a check-in; the frame's bytes are stuck in
the transmitter's ring, which the driver cannot clear, so the UART is
dropped and built again and the ladder decides from the silence. A
boot without a written boot count, which is a FRAM that did not answer
or a new count that did not land on it, has no `boot_id` to state
(F-039): the link task keeps its place on the roll and the link never
comes up, the module powered as on every boot because a rail switched on
at a later boot is what F-005 forbids, and the probe's log says why; KM43's
boot body has no field for it, so nothing on the ring does. Records the
link raises go to the recorder through a queue as deep as the protocol's
event queue, which refuses when full.

## Persistence

| | Part | Holds | Layout |
|---|---|---|---|
| FRAM | FM24W256, 32 KB, I2C | Everything control-critical: configuration sections in A/B slots (P-102), the eight client slots, each a key record in two copies with a generation mark beside it (P-239), the dedup table under its epoch (P-080, P-121), the epoch (P-085), the generator's state (P-237), the device secret and the controller key (P-235), the generator run reason (origin89hq/hardware#18), the panic record, the boot counter, the rolling write-volume counter, the authorised comms release (L-170), the network master copy (L-130), the manufacturing transaction (appended after the configuration reservations) | A `const` map with a budget assertion; two slots per record, each `[magic \| seq \| body \| crc32]`, the magic cleared first and written last, the higher valid sequence current |
| NOR | W25Q128, 16 MB, SPI | The event log ring and the 15-minute aggregates; later the last authorised comms image | The ring below, written against `embedded-storage-async`'s `NorFlash` |

Different failure consequences, so different chips. FRAM must survive a
power cut mid-write. A corrupted log must never be able to stop the site or
imply a relay is open when the hardware says closed.

**The state store is authoritative; the log is the durable change and audit
record.** Those are different claims, and conflating them is how a damaged
log entry comes to imply a relay is open. The log is how a client catches up
and how a failure is explained afterwards; it is not where the truth lives.
Every event gets a monotonic sequence number and lands in NOR, and clients
read by sequence number and ask for what they missed. That one decision means
a phone away for six weeks resyncs by asking for everything after *n*; the
outbound queue to the comms processor can be small and lossy, because
dropping from a queue is not dropping from the log; and cloud, phone and
browser use the identical mechanism, so the cloud is optional rather than
merely described that way. Reliable delivery belongs in the log, not in the
link.

**A/B answers multi-word atomicity; the part answers power loss.** FRAM has
no erase cycle and no write latency, so a single word survives a cut by
itself; what it cannot do is make six words land together. Configuration and
every client slot live in A/B slots with a sequence number and a CRC; a write
goes to the slot that is not current, clears its magic first, lands the
sequence, the body and the CRC, and writes the magic last, and the slot
whose magic and CRC hold with the higher sequence is the record. The magic
landing is the switch, as it is on the NOR, so there is no pointer word to
tear, and a slot being reused is no record at all while the new bytes land
over the old ones, which the CRC alone could not promise: the old CRC stays
in the slot until the new one lands, and a thirty-two bit CRC has an image
that collides with it. It is the same machinery the bootloader needs, so it
is built once. The PVD discipline above is the other
half: no
transaction starts on a falling supply. Every FRAM write path runs crashing
at every step on the host, and the invariant after recovery is asserted.

Identity and behaviour configuration use schema-sized prefixes of the existing
`SITE_CONFIG`, `GENR`, `FRST`, `SCHD` and `SHED` reservations. The second slot
keeps its reserved address; the CRC follows the encoded prefix. Identity needs
41 bytes (4 version + 1 length + 36 CBOR), each behaviour 8 (4 + 1 + 3).
No existing record moves. The network body uses 138 of its reserved 160 bytes:
4 version + 1 metadata marker + 2 country + 33 hostname + 1 join marker +
33 SSID + 64 passphrase. A clear retains country and hostname and advances the
version. Configuration is canonicalized after validation; unknown CBOR keys
are not persisted. Never-written or unreadable records answer version zero with
no body (P-108),
so a client can discover the version needed to repair a damaged section. Reads
leave damaged bytes on the part, and a damaged network is not pushed to the
comms processor. The network read shape never includes the passphrase (P-106).
An authenticated replacement of a damaged section requires expected version
zero because its
version is unknowable; the validated replacement starts at version one. A
local network replacement owes a push even when the module reports version one.

**One record is one transaction, and that decides what shares a record.**
Each client slot is a record of its own, because P-239 re-keys one slot at a
time and a torn write must never reach another's. The dedup table is a record
of its own, because a command's in-flight entry is the one thing P-080 lands
before it executes, and nothing else has to land with it. The typed layer
keeps the RAM copy of every record with the record's position on the part,
and changes it only once the part has the change: a refused write leaves the
controller knowing exactly what it accepted, which is P-079 as a structure
rather than a discipline. Where a rule says *read back*, the epoch, a slot, a
generation mark, the generator, the write is read back off the part and the
handle holds what the read found.

**A slot is re-keyed by writing it free first** (P-239). The mark is raised
and read back, the slot is written free under that generation and read back,
the slot's dedup entries are forgotten, and only then is the new record
written and read back. FRAM commits byte by byte, so a record rewritten in
place and cut between the label and the key would leave the old install's key
under the new label; this way a cut at any byte leaves the old enrolment or a
free slot. A generation is never issued twice under an epoch, so
`(epoch, client_id, generation)` names one enrolment: a mark that cannot be
read back makes the table corrupt, and the boot repairs it to empty under a
new epoch, as a reset would.

**A factory reset commits with one write** (P-085). A slot is occupied only
if it reads, says occupied and was written under the current epoch, so the
epoch landing is the reset: every slot is free from that moment, and freeing
them one by one afterwards is housekeeping a cut cannot undo. The permission
to clear is a type only the read-back of a new epoch produces. The other
direction is never a clearing: a slot under a later epoch than the record
means the record regressed, which this firmware does not do by its own hand,
and the boot raises the record to it, because a slot's epoch is a second copy
of a counter that only climbs (F-026). The dedup table carries its epoch too,
and a boot clears it under any other.

History at full resolution is a client's job. The controller keeps enough to
survive a long disconnection, which is a different requirement from keeping
a year.

**The bench reaches the parts through the firmware, never around it.** The
last 8 KB of RAM is a mailbox the recorder task polls, with the two rings of
the module's bridge and the host's lease on it at its end: the host lands a
request over SWD, read these bytes, write these, erase this block outside
the ring or drop the ring's oldest, reboot, and its sequence last; the recorder serves it through the same seams the
store and the ring use, and lands the same sequence as its answer. So a
write from the bench meets the voltage detector's refusal as the firmware's
own would, and the bytes it writes are framed by this crate's own records
on the host: the epoch and the secret a unit leaves the bench with are
records the boot reads exactly as it reads its own. Manufacture is the
exception: the mailbox stages the transaction in the controller, then the tool
requests a reset and reads back the applied record before it prints a label.
Other raw record writes retain their host-side encoding in `o89-core`. One request reads records rather than bytes: the ring's
newest events are walked by the ring's own reader and handed back a page at
a time, because the ring is the one thing that knows where it starts and
ends, and a host finding the head a mailbox request at a time would probe
thousands of empty blocks at a tenth of a second each. The host decodes
each event, a boot's reason and last words included, with KM43's codecs. The
ring's own blocks are erased only from the old end, as the firmware erases
them: a block erased anywhere else leaves a hole the head search reads as
the end of the log, and the next record would reuse a sequence (#78).
The region is one the runtime never loads or zeroes and the
stack never reaches, at the address both sides share from one constant.

### The event log ring

Append-only records over a ring of erase blocks. Nothing here is a
filesystem.

```text
[ magic: u16 | len: u16 | seq: u64 | class: u8 | payload | crc32 ]
  ^ programmed LAST
```

- **The magic is programmed last.** NOR programs 1→0 over an erased block,
  so a record is written payload-first and becomes findable only when its
  magic lands. A torn write leaves a record with no magic, which the boot
  scan treats as the tail. No half-record is ever readable. Writing the body
  and then the magic is two program cycles over one word, which is
  `MultiwriteNorFlash` rather than plain `NorFlash`, a line the datasheet has
  to answer before the ring is written.
- **A damaged record is not stepped over by its own length.** The length is
  inside the CRC, so it can only be checked after it has been trusted, and a
  scan that resynchronised by it would turn one flipped bit into the loss of
  every record after it in the block. The scan hunts forward for the next
  magic and verifies each candidate. This cost the old firmware a defect.
- **CRC32 per record.** A failing record is skipped and logged as a
  diagnostic; one bad sector costs its own records and nothing else.
- **A torn write closes its block.** The residue cannot be written over,
  since NOR only clears bits, and cannot be skipped past, since the scan
  stops at it. So the block is finished, its records stay readable, and the
  log continues in the next one. A power cut costs the rest of one block.
- **A torn write is not damage.** A block that is neither erased nor holding
  records is a first record cut short, which on a new part is an ordinary
  first boot. A block holding records that failed their CRC is a chip
  somebody has to look at. The two want opposite answers, carry on and refuse
  to guess, and a controller that conflated them either bricks itself on its
  first power cut or writes over the evidence of a failing part.
- **Sequential ring, the oldest block erased one ahead of the write head**,
  so an append never blocks on an erase. **No wear-levelling layer**: a pass
  takes the better part of six months, so each block is erased about twice a
  year against an endurance of 100,000 cycles.

**Nothing is held per block, and the boot reads one block.** The part is
megabytes and the controller has 144 KB, so the boot finds the head by
binary search over the first record of each block, a probe that reads one
record's reach at the block's start and no further, so a part full of
somebody else's bytes costs a bounded read per block rather than the whole
of it: blocks before the head carry newer sequences than the first block
holding records, blocks after it carry older ones or nothing, and a block
closed by a torn write is stepped over to its neighbour. The head block
alone is scanned to its tail, the block ahead of it alone is read whole to
be sure it is erased, every walk over blocks yields between them, and every
read streams through one record's worth of scratch. The first boot on
this bench board, whose NOR held the self-test's bytes, is what taught it:
a scan that read every block whole took longer than the watchdog's eight
seconds and the part never got to open its ring. The time floor a clock offer is checked against
(L-140) is found the first time it is asked for rather than at boot,
because the walk back to the newest timestamped record is instant on a unit
whose clock was ever set and the whole ring on one whose clock never was.

`sequential-storage` was read before this was designed and is not adopted,
for shape rather than quality: its queue is a FIFO, and this log is read by
sequence number from arbitrary positions by several clients months apart, and
nothing ever pops. Its length-CRC idea was weighed and declined: a length
check alone cannot tell a corrupt record from the end of the log, so it would
be needed as well as the magic, two bytes on every record forever against a
scan that costs a few thousand comparisons once, at boot, on a damaged block.
What is taken is the trait.

### Two classes of record, and the byte budget

| Class | Examples | Under pressure |
|---|---|---|
| A, durable | State changes, commands and their outcomes, alarms, configuration changes, boot records, faults | Never dropped |
| B, droppable | Periodic aggregates, diagnostics, telemetry | Dropped first, with a marker recording how many |

Sampled telemetry is never logged as individual events: a temperature read
every two seconds is 43,200 records a day per channel. Channels emit a
state-change event only through the deadband, minimum-interval and
maximum-silence trio, and history is carried by 15-minute aggregates.

**Never dropped is a rule about the way in.** A class A record is always
appended; the per-session queues to the comms processor shed a session rather
than a record (P-098). The ring itself overwrites its oldest block as it
wraps — that is what a retention of 176 days means — and a client that asks
for a `seq` older than the ring holds is told so rather than left believing
the stream complete (P-099). An append never blocks on a full ring: the block
ahead was erased one step earlier, and a controller that stalled control to
keep an audit record would have inverted which of the two is authoritative.

**A per-channel rate cap does not bound the ring.** One event a minute per
channel, excess coalesced, stops one flapping input from filling the log. It
does not stop forty-eight of them: 48 channels at that cap is 3.9 MiB a day,
which empties the ring in under four days. What protects the ring is a
**global byte budget**: a rolling 24-hour write-volume counter in FRAM,
compared on every append against a configured target of 85 KiB/day. Exceed it
and class B is dropped first, with a marker. Exceed it on class A alone and a
diagnostic is raised, because a site producing that many state changes has
something wrong with it.

**The capacity, calculated.** Capacity is a function of rate, not of chip
size. Every record pays the 17 bytes of framing above, so a class A event of
about 40 bytes of CBOR is 57 framed, and a packed seven-field aggregate of 25
bytes is 42. Twenty channels at 96 windows a day plus about a hundred class A
records is about 2,020 records and 84 KiB a day, and a 14.5 MiB usable ring
holds **176 days** of it. That does not reach the winter this ring exists
for: first frost to the first person who connects after the thaw is around
200 days at this latitude, and the first thing a full ring overwrites is the
beginning of the winter, which is the part somebody drove out to read. So the
constraint KM43's aggregate record has to satisfy (its `DEFERRED.md` entry 3)
is a packed payload under 20 bytes at 20 channels and 15-minute windows, or
the window or the channel count moves: twelve channels gives 281 days,
30-minute windows give 330. Each costs something a person will notice, and
which one is not decidable before a month of real sampling. Every figure is
reproducible from the 17, the 14.5 MiB, 100 class A records a day and 96
windows per channel.

## Safety architecture

**Every output declares its fail state**: what it is at reset, through a
brown-out, while the processor is unresponsive, and before firmware runs. The
answer is not the same for a run contact and a heater, and it is also where a
behaviour that declines puts its output, where an output goes when authority
is taken back, and what an output that has never been granted authority
shows. An output without a declared fail state is not configured.

| Output | Fail state | Held by | Notes |
|---|---|---|---|
| `RUN`, `KICK`: the generator contact, through board B | Open | Board B's run-enable monostable drops the contact when the kick stops; the firmware drives both lines low at the reset vector before anything else, and the bootloader does the same | ST's system bootloader on an empty flash can drive `RUN` high and pulse `KICK` (origin89hq/hardware#30), so there is never an empty-flash window: dual-bank swap, and `o89-boot` written at manufacture into both banks. Revision B pulls both down at the MCU (A-34). Any reset opens the contact on revision A; revision B's ride-through is 15 s (B-20), and a resumed automatic start re-raises `RUN` within 3 s (F-016) |
| The three RS-485 transmit lines | High, idle | Firmware, from the reset vector | Through reset the drivers float and hold the buses low (origin89hq/hardware#28). Every image configures all three USARTs |
| The module lines: transmit, RTS, `EN`, `BOOT` | Inputs, or driven low; never high | Firmware | Input or low from before the rail drops until after it is up, so nothing back-powers an unpowered module (origin89hq/hardware#17, F-003). `EN` is driven low on purpose across every rail cycle and released after the rail settles (origin89hq/hardware#14) |
| The comms processor's UART0 transmit and RTS, GPIO16 and GPIO5 | Not driven: high-impedance through the module's reset, a brown-out that resets it, and with the rail off | The ESP32-C6's pads (datasheet v1.5, table 2-1); neither net has a pull on board A | Released from reset, GPIO16 is the ROM's UART0 transmit, enabled with a weak pull-up and idle high, and GPIO5 an input with no pull, until the firmware's second statement makes them UART0's TX and RTS. So the controller's `PB7` and `PB4` float while the module is held in reset or unpowered, when USART1 is down (F-003, F-006), and `PB4` floats from the module's reset until the firmware takes its RTS: a controller write there may be held by a CTS reading high, and every write has a deadline and every request a retry (L-015, L-192). Measured on board A: bench 2026-09-19 §7 |
| The module rail, `V3V3_ESP` | **On** (L-114) | The board, per revision (A-23); the controller once booted | Below |
| The VE.Direct receive pull-ups | Off | Firmware | 3.3 V products only, by configuration (origin89hq/hardware#27) |
| The lamp | Whatever the board leaves it through reset (`BOARD-A.md`) | The supervisor drives the pattern | A lamp showing nothing is a controller that has not reached its supervisor. No hazard |
| Any other output | Declared in its configuration section | | Arrives in shadow; commands against it are reserved until authority is granted |

**The module rail.** KM43 declares its fail state on (L-114): a controller
that reaches a state it did not plan for comes up with the radio powered,
because a controller that comes up with its radio off is one nobody can reach
to ask why. The reasons that hold are that a controller reset must never
power-cycle the radio, that cold boot then has no separate inrush event, and
that a rail cut is always a logged decision
([origin89hq/km43#35](https://github.com/origin89hq/km43/issues/35) rewrites
the rule's rationale onto those). Board A revision B builds that in: the
switch is slew-limited, defaults on with the controller's pin high-impedance,
and the pin drives low to cut it (A-23). The controller takes ownership once
it has booted and applies its policy from there:

- The recovery ladder's cuts (L-111, L-112), never while the link is down
  on purpose (no device secret, or L-195's revisions spent; F-039,
  [origin89hq/km43#127](https://github.com/origin89hq/km43/issues/127)),
  each recorded with the count
  L-111 names, and the third rung with the branch it took: `comms
  unrecoverable` says whether the rail was left on or off (KM43 P-215). The cuts of the last hour
  are on the FRAM before the rail goes off, and a cut whose count does not
  land is not made and the ladder asks again. The rail task never waits on
  the part for it: a module reset asked while the count goes out, or in the
  turn it lands, is served first, and the cut planned before it is not
  made. That order is `o89-core`'s `Rail`, which the simulator's bench runs
  too. A boot carries the cuts as made at its own start, so a controller
  that resets between rungs still reaches the third (F-017).
- A bank-voltage threshold below which the radio stays off, so the weakest
  bank in February is not also carrying a radio nobody is using. The
  threshold and its hysteresis are configuration values that have not been
  chosen; the threshold sits above the front end's own stop threshold, or the
  policy never runs. Hysteresis alone chatters, because the radio's own load
  moves the number it is judged by: radio on, the bank sags under the
  threshold, radio off, the bank recovers over it. So the policy also carries
  a minimum dwell in each state; the ladder already has the shape, a cut of
  at least 5 s and three an hour, and on revision B every re-enable is a
  switch-on event of the kind board A's open item 9 measures. A bank voltage
  that is absent or stale is not a reason to cut: unknown is not low, and
  the rail follows its fail state, on.
- Every cut is a decision by running firmware, logged as such, and never a
  reset's side effect. Two consequences to carry: a blank or crash-looping
  controller leaves the radio powered until firmware runs, so the ladder's
  cuts exist only in running firmware; and a brown-out recovery on a weak
  bank, where the module's first Wi-Fi burst comes before the policy runs,
  is bounded to under a second at about 1.3 W and is measured on the
  hardware repository's bench (board A's open item 9) rather than argued.

Revision A is the opposite by accident, and the firmware lives with it. The
rail defaults **off** through every controller reset, so each reset reboots
the module, costs a Wi-Fi association and is a switch-on event; a crash loop
at the 8 s watchdog is 450 rail cycles an hour against the ladder's three
deliberate ones. Those resets are counted as the ladder's cuts, so three of
them inside an hour are its third rung (F-018), even when a reset comes
before the boot's own record lands: the record names the boot count it was
written at, and the next boot counts every boot in between. Switching the rail on after minutes off corrupted the
controller within milliseconds, 22 of 22 times on the bench, while short
cycles pass hundreds of times
([origin89hq/hardware#5](https://github.com/origin89hq/hardware/issues/5)).
So on revision A a rail cycle is at most 5 s off, and a controller reset
inside one adds only the boot's path to the rail, which runs before any bus
(boot step 5); the ladder's third rung,
15 minutes off, is not executed
([origin89hq/km43#36](https://github.com/origin89hq/km43/issues/36) says how a
conformance claim states that): the controller stops cycling, leaves the rail
on, raises comms unrecoverable and logs which policy it applied (F-005). The
bank-voltage policy does not run on revision A for the same reason: a rail
left off while the bank is low and switched on when it recovers is a
switch-on after minutes off, the pattern origin89hq/hardware#5 forbids, so on
revision A the radio stays on down to the front end's own stop threshold.
USART1 is configured only after the rail has settled, and a cold boot is
treated as the same condition. The boot record says the radio was cycled.
`BOARD-A.md` carries the whole revision policy table; the firmware carries a
`Revision` the policies read, chosen at build time.

**The rest of the floor:**

- **Boot reason recorded and acted on.** Power-on, watchdog and brown-out
  are three different situations, and a generator that was running through
  one of them is a fourth; the run reason in FRAM is what tells the boot
  which.
- **Run-enable watchdog in hardware** on the generator contact: survives a
  fast reset, drops the contact if firmware dies. The monostable's design
  figure is 4.5 s and the bench measured 4.23–4.46 s, drifting; the contract
  is 3.0–6.5 s, and the firmware measures what it sees
  ([origin89hq/hardware#22](https://github.com/origin89hq/hardware/issues/22)).
- **Two relays in series**, so a single weld cannot run the tank dry, plus
  `max_runtime` as a backstop on automatic and manual runs alike, and the
  `stop not honoured` alarm when AC persists past `stop_grace`.
- **The IWDG is fed only when every state machine reports sane.**
- **No panic path in production.** The panic handler writes the reason to
  FRAM, enters the fail state, and resets. A controller that panics silently
  and reboots into an unexplained state is the one failure that cannot be
  debugged from four hours away.
- **Auto/off/manual at the controller; the lockout switch at the genset.**
- **Advisory inputs expire**, and a missing, stale or implausible measurement
  carries its quality. Never a default that could be mistaken for a reading,
  and never a permission to act.
- **A named safe state per subsystem**, and a written answer to *what may a
  single fault cause*. Borrowed from IEC 61508 thinking without claiming
  certification. `SAFETY.md` is the hazard matrix, one row per hazard the
  hardware or this document names: hazard, invariant, mechanism, test,
  evidence, reviewer. A row whose evidence says "compiles" is not done.
- **Fault injection is routine.** A deterministic step counter behind the
  storage, clock and I/O seams; every persistence and command path run
  crashing at every step; a hostile comms processor with a named capability
  set driving the adversarial corpus; a simulated winter on every commit. The
  bench then cuts power a thousand times overnight and pulls a bus
  mid-transaction, and a bench session is dated and names the board
  revision, the firmware hash, the fixture and the instrument. Nothing is
  called safe because it compiled.

Not now: formal verification, redundant or lockstep MCUs, ECC, a
certification process. Those answer failure rates for which there is no
evidence yet.

## The bootloader and A/B

The part's flash is two 256 KB banks it swaps in hardware by an option bit,
so the application always links at one address and an update is: erase the
inactive bank, program it, verify the manifest, flip the bit, reset. No copy
and no half-copied window; an interrupted copy is exactly the empty-flash
window origin89hq/hardware#30 describes, which is why `embassy-boot`'s
copy-based scheme is not used. The HAL erases and programs either bank but
never writes option bytes on this part; the bootloader does that through the
PAC in one audited function, one of the five `unsafe` sites in the firmware,
with the bootloader's jump into the application, the controller's hard-fault
handler, and the polls of the supervisor's and the control executor from
their interrupts.

The invariants that make A/B what it claims:

- **At no instant are there zero bootable images.** The selected bank is
  never erased, and the flip is the last step after the whole inactive bank
  has been written and verified, so at the instant of the flip both banks
  hold a bootloader and a verified image: whichever bank the part selects
  afterwards — the old, the new, or whatever it loads after an option-byte
  write it could not verify — boots. No bank is ever empty after
  manufacture, so the empty check that starts the system bootloader
  (origin89hq/hardware#30) cannot fire. What the reference manual settles in
  M7, before this is relied on, is what the part does with an option word
  whose complement does not match — which values it loads, and whether
  read-out protection is among them — and the bench test is an option-byte
  write interrupted at every step.
- **The bootloader is written at manufacture into both banks and never by an
  update.** The updater refuses a manifest that covers the first 8 KB, and
  the bootloader checks its twin at boot. Without that rule a bad release
  puts a broken bootloader in the new bank and nothing ever flips back.
- **Trial boots are counted and the flip-back is performed by the
  bootloader**, not the application; an image that never confirms healthy is
  rolled back without its cooperation.
- **The manifest carries a monotonic anti-rollback index**, and a downgrade
  below it is refused without the gesture.

The bootloader does four things: drives `RUN` and `KICK` low, verifies the
selected bank's manifest signature, counts trial boots and flips back, and
jumps. It is frozen by the first unit that ships with read-out protection.
The signature algorithm, where the public key sits, and where the
highest-confirmed-healthy index is stored so the running image cannot lower
it are decided in M7 against the reference manual and recorded in KM43's
manifest specification
([origin89hq/km43#34](https://github.com/origin89hq/km43/issues/34)).

**Two firmwares, two roles in an update.** The comms processor *delivers* the
controller's image; the controller's bootloader *validates* it. Letting the
untrusted chip be the gatekeeper undoes the security boundary. Each side
rolls back independently, and the two are never offline at once.

## The comms processor

**Boot, in the order #1 dictates:**

1. The HAL's init, which in the pinned release disables every watchdog, then
   the RWDT re-armed as the first statement after it. A hang is a reset and a
   reset re-opens the window.
2. UART0 opened at the link baud with RTS/CTS, before the radio, before the
   scheduler.
3. **The download window.** For 1.5 s from its own start the firmware
   listens for a link-local `EnterDownload` frame from the controller
   (KM43 L-190 to L-192, from
   [origin89hq/km43#30](https://github.com/origin89hq/km43/issues/30)) and
   for nothing else. On one it acknowledges `entering`, disarms the RTC
   watchdog, which outlives the software reset and which the ROM's loader
   does not feed, sets the ROM's force-download flag (`LP_AON.SYS_CFG` bit
   30, a field write the register crate makes safe) and resets into the
   ROM. It never scans the relayed
   client stream for anything, and after the window a request is answered
   `refused_outside_window` and never acted on. The window runs before any
   code that can crash for a reason of ours, and its having run is what
   confirms an OTA slot in pending verification (F-036): the proof an image
   is safe to keep is that it honours the window, and the confirmation takes
   the value only the window's run produces (F-089), so an image without a
   window cannot confirm itself.
4. The scheduler (`esp-rtos`, with the embassy executor the link runs on,
   entered from the HAL's bare entry only now, so nothing of either runs
   before the window),
   the heap for the radio blobs, the Wi-Fi station on the cached network,
   the TRNG seeded from the ADC source so `boot_id` is random before the RF
   subsystem is up (L-040).
5. `LinkUp`, then the heartbeat, then transports.

**Nothing on this side prints.** The module's only wire on board A is the
link, and a console on it would put a person's text into a CRC (#2). What
the comms processor does is read on the controller's log, its `LinkUp`
carrying its firmware and `boot_id`; a panic is an immediate reset, a fault
a hang the watchdog ends the same way, and either shows on the controller
as a new `boot_id` and the ROM's text counted once. A console on UART1's
unconnected pins is a bench addition when the radio work needs one.

**A heap only for the radio (F-037).** The ESP32 vendor Wi-Fi/BLE stack may
allocate from a fixed-budget heap backed by statically reserved RAM. Initialize
it only after the recovery download window has completed. This exception does
not extend to the STM32, domain crates or their tests, or our ESP32 application
and transport code. Connection tables, fragment assemblies and queues retain
named static capacities and refuse at capacity without eviction. `o89-comms`
never depends on `o89-core`, which the gate refuses.

The pinned radio stack's required allocator and scheduler integration must be
identified during qualification; the exception is not permission for a BLE host
or an unrelated dependency to allocate. Disabling `esp-alloc` alone does not
remove allocation: [Espressif's radio documentation][radio-allocation] requires
replacement allocation functions. Heap initialization and the stack's allocator
adapter are the only allocation plumbing our firmware may supply.

[#89](https://github.com/origin89hq/firmware/issues/89) owns the shared radio
initialization; [#96](https://github.com/origin89hq/firmware/issues/96) qualifies
BLE and coexistence against that same memory budget. Before accepting a stack,
record its exact pins, allocating components, reserved heap bytes, static RAM,
task stacks, transport buffers and linked release size, with remaining margins.
Choose the heap size from measured Wi-Fi/BLE operation; no heap size or stack
is qualified by this exception alone.

Qualification must measure peak heap use and fragmentation through repeated
connect/disconnect cycles, full connections and queues, and BLE traffic while
Wi-Fi associates, reconnects or fails. Exercise allocation failure during both
initialization and operation. Where the stack returns an error, refuse the
affected work and clean up its resources; where it cannot recover, reset the
ESP32 through the existing reset/watchdog path. Verify that the controller keeps
operating, stale client sessions cannot be reused, and no failure grants KM43
permission. Revalidate the early download window with the radio stack present,
including recovery after exhaustion. These are board acceptance obligations,
not claims established by a host test or a fixed heap size.

Wi-Fi scan results add a temporary vendor allocation: pinned esp-radio's
`scan_async` collects its `ScanResults` into a `Vec<AccessPointInfo>`. Each
AP occupies **47 bytes** on this ESP32-C6 build, plus the Vec's spare capacity
and allocator overhead; the blob's own scan list also occupies the radio heap.
The public API reports a `u16` AP count. No smaller AP-count limit was found
in the pinned radio configuration or blob API; APs in range and the remaining
128 KiB heap bound it in practice, not a qualified density limit. Allocation
failure reaches the existing reset panic handler and the next recovery window.
This remains part of F-037 exhaustion/coexistence qualification and the vendor
allocation concern tracked in [#134](https://github.com/origin89hq/firmware/issues/134).

The adapter passes no `max` option: truncating before SSID deduplication would
lose choices and the exact omitted count. It sorts the vendor-owned slice in
place without allocation, then the core consumes it in one bounded pass into
16 fixed rows and a saturating unlisted count. The Vec is dropped before the
next await. Hidden and invalid UTF-8 names are omitted; invalid UTF-8 is detected
by comparing the vendor's text-prefix length with its original SSID length.
Duplicates of listed SSIDs do not add to unlisted. No application container
allocates, and no reference into the vendor result survives the reduction.

The radio-only allocation inventory includes the vendor Wi-Fi and BLE blobs,
`esp-rtos` task/queue integration, `esp-alloc`, and esp-radio's HCI/NPL adapter.
On the C6 the latter boxes incoming packets and queues them in a growable
`VecDeque` with **no independent length cap**. Two BLE connections, controller
buffer counts and HCI/ACL flow control constrain traffic, but do not establish
a byte bound for that queue; its absolute bound is the shared 128 KiB heap.
The C6 controller defaults request a 4096-byte task stack, 30 high and eight
low HCI event buffers of size 70, and 24 ACL buffers of size 255, plus
controller and allocator overhead. These are runtime heap consumers, not
additional application statics. Wi-Fi/BLE `coex` is enabled for the C6.
The heap was 72 KiB until board A ran out of it, a panic in the allocation
error handler, each time Wi-Fi scanned or associated beside a BLE connection
(#170). With room to spare the peaks were 73 KiB for a scan beside BLE and
78 KiB for a join with a WebSocket client, repeated three times at 128 KiB
without a failure (bench 2026-09-25). The driver's buffers grow with free
heap, so a peak measured under one budget is not a requirement under
another; 128 KiB is still provisional for combined operation.

Allocation failure is not a sleep loop: `esp-alloc` returns null, Rust's
infallible allocation handler panics, and this firmware's panic handler resets
immediately. The vendor C allocator also returns null; the pinned NPL adapter
and controller initialization assert several failure results. A host error,
a failed two-second disconnect, or a missed two-second HCI health command
resets the ESP32. A successful HCI command reports watchdog progress every
second; the link cannot keep feeding on behalf of a stalled BLE host. BLE owns
its progress cell, separately from Wi-Fi's network, station and NTP reports.
Restarting or idling Wi-Fi resets only those three reports. Each report expires
at 6,000 ms; `o89-comms-core` tests this rollcall with caller-supplied time (F-032). If a
vendor fault prevents the executor or interrupts from running, the already
armed hardware watchdog ends the hang. Every reset enters the recovery window
before allocating or starting radios again. Null-return behavior inside the
closed blob and exhaustion during reconnect/coexistence still require fault
injection on the board; source inspection is not that evidence.

[radio-allocation]: https://docs.espressif.com/projects/rust/esp-radio/0.18.0/esp32c6/esp_radio/index.html#feature-flags

**Partitions and recovery.** `otadata`, two OTA slots, a **factory** slot
that OTA never writes and that always carries the window, a single-network
credential record, and a web-assets partition (`firmwares/o89-comms/partitions.csv`);
three 2 MB slots and the assets fit an 8 MB module. The factory slot is the frozen first release, not
a minimal image: a recovery path has to be proven and immutable, and a
shipped release is both. An OTA image that boots and never confirms healthy
is rolled back by the ESP-IDF bootloader to the image that was running, which
honours the window (L-173). That bootloader is the one this repository builds
with rollback enabled (`firmwares/o89-comms/bootloader/`, F-088), because the
one `espflash` ships is built without it and would run the bad image for
good; the slot route refuses a module that does not hold it. If both OTA
slots are bad it falls to the factory image, which honours the window. The only way to lose the window is to flash
a bad image into the factory slot through the download mode itself, a bench
act with a probe attached and a wire available. So the bench tool does not
do it by default: `dev-flash-comms` writes the application into `ota_0`,
blanking the `otadata` before it erases the slot and naming the slot after
the application lands, which leaves the factory image booting at every point
in between (F-084). Replacing the factory image is its own recipe, and it
says so. That is #1's acceptance test, run before any revision A unit leaves
the bench. ESP-IDF's eFuse
anti-rollback would refuse the factory image the first time its counter
advanced, so the eFuse counter stays untouched and no-downgrade is enforced
at the controller's authorisation (L-169). Kept open, not in V1: the
controller has 16 MB of NOR and the authorised comms image is under 2 MB, so
a controller that keeps the last authorised image can reflash a dead module
through the ROM with no client and no drive.

**Transports in V1**: BLE GATT is required for initial pairing from the
native phone app, before site Wi-Fi is configured and without internet.
The person scans the controller's QR code, opens the 120-second window at
the panel, and the app performs `Discover`, `Pair`, then `Hello` over BLE.
An authenticated session can then write the network configuration. BLE
advertises whenever the station holds no address, including when cached
credentials name an unavailable network, and while the pairing window is
open. Once the station holds an address with the window closed, a phone
reaches the controller over the site network and finds it over mDNS, so
advertising stops; a phone already connected over BLE keeps its connection
and hands over (F-044). The ESP32 carries bytes; the STM32 verifies proofs,
owns enrolment and holds every key.
Bluetooth connection or bonding alone grants no KM43 permission.

Local Wi-Fi uses one WebSocket connection per client (P-034), on TCP port
80 of the station's network, served by eight workers, one per row, inside
the Wi-Fi session, so a changed network closes every connection and releases
its row. Each worker owns fixed buffers for its socket, a client's envelope,
its stamped copy and one frame for the client; each has a two-frame mailbox
the link task fills from the UART, and a client whose mailbox is full when a
frame arrives is closed rather than a frame dropped or evicted. Clients'
stamped frames reach the UART through a two-envelope queue the link task
drains one a turn after reading the UART; a frame that cannot enter it
within a second is lost and its client retries. The opening handshake is
RFC 6455's within 1 024 bytes and five seconds, on port `WS_PORT` (80) at
`WS_PATH` (`/km43`); any other
request-target is answered 404 without an upgrade (P-223). No origin or
subprotocol is decided on. A text frame, a fragmented message, an unmasked
frame or one over one envelope closes the connection (1003, 1002, 1009).
Every close carries a code and a reason a client can show (L-061). A ninth
client finds no listening socket. The link, with the table, is shared with
the workers through an async mutex no task holds across an await. The comms
processor raises no access point of its own (F-042 is retired): run beside
the station while the pairing window was open, it reset the module every
seven seconds on board A, which took BLE down for the window a phone pairs
in. First pairing is BLE's, and later access is the site network's. The
controller reports its window over the link with KM43's `PairingWindow`
after every link-up, on the opening and on every closure, an enrolment's
`Pair` answer ahead of the closed report (L-195); the comms processor acts
on it only from the controller UART once its own link is up (L-194) and
keeps the lifetime on its own clock from receipt. The radio's plan
(`o89_comms_core::Plan`) reads the network record alone: a `set` record
runs the station, a `clear` that kept a country brings the station
interface up without joining once a client's scan is accepted, and keeps
Wi-Fi off before that so a phone can connect over BLE (#166), and a change of
record restarts the Wi-Fi session.
Advertising is transport availability, not permission to pair; the
controller checks its window when it processes `Pair`. Cloud stays out of V1.

**BLE setup transport (#96).** The GATT server uses the UUIDs in pinned
KM43 0.6.0: RX is Write Without Response and TX is Notify with a CCCD.
Advertising includes the service UUID only after valid `LinkUp`; controller
loss requests advertising cancellation within 100 ms and closes existing
clients. The same 100 ms poll requests cancellation when the station holds
an address and the window is closed, leaving connected clients alone; the
host's disable command completes after that request, unmeasured.
The gate reads the station's latest observation, taken once a second, not
its report: the report keeps `joined` through a rejoin (L-204), while a lost
lease or association restores advertising at the next observation (F-044).
Neither connection nor subscription nor bonding grants KM43 permission. The
controller still owns the physical window and proof checks.

`BLE_CONNECTIONS = 2` bounds concurrent setup phones, the vendor controller,
TrouBLE's connection resources and the KM43 codec pairs. Two is enough for
setup without reserving eight radio connections and eight pairs of 1024-byte
payload buffers. Raising it requires F-037 heap measurements first. Each phone
also takes a row in the shared eight-row table; there is no second allowance.
At the BLE cap no worker advertises; a shared-table refusal disconnects the
new phone, never an existing client.

The host is `trouble-host =0.7.0`, defaults disabled, with only `peripheral`,
`gatt` and `default-packet-pool`. Its `bt-hci =0.9.0` matches the pinned
`esp-radio =1.0.0-beta.1` connector; TrouBLE 0.8 uses the newer HCI API.
Existing HAL, RTOS and Embassy pins remain unchanged. The host allocates no
heap and uses 16 static 251-byte packets (4036 bytes including bookkeeping),
eight-entry receive/transmit queues, two-entry connection-event queues, two
channel records, four HCI command slots and 16 attribute records. Const
assertions tie these upstream configuration values to the BLE cap and KM43
limits. ATT MTU starts at 23 and negotiates up to 247; characteristic values
are at most 244 bytes. No Bluetooth security/bond storage or central role is enabled.

Each connection owns one `km43::BleReceiver` and `BleSender`. No fragment
format or assembly algorithm is implemented here. A transmit slot refuses a
second message, and the two-entry delivery mailbox closes an overrun client.
TrouBLE's full receive queue or exhausted static packet pool rejects the new
ACL PDU; its runner discards that PDU rather than evicting an older one or
reporting a fatal runner error. KM43 sequence checking/expiry discards an
incomplete message, and the client's request timeout drives retry. Saturation
and recovery still need the board tests below.
The shared two-entry upstream queue waits at most one second; a BLE timeout
closes that connection. Queued upstream frames retain their connection handle
and are canceled before UART transmission if the row is no longer open.
Malformed fragments close the connection; incomplete assemblies expire after
KM43's five seconds even without traffic. Disconnect, controller restart and
subscription loss clear both codec directions. Notification admission advances
the sender only with an enabled CCCD: TrouBLE's successful no-op for an
unsubscribed peer must not consume a fragment. Every write has a one-second
deadline, announcements three seconds and disconnect confirmation two seconds.

The host tests consume all 2758 shared BLE trace steps from KM43's
`docs/protocol/vectors/v1.json`, including selected value limits, maximum
payloads, errors, expiry, disconnect, backpressure and message-ID wrap.
`crates/o89-sim/tests/ble_vectors.rs` reads `km43::VECTORS_JSON` from the
exactly pinned crate and runs the firmware's `o89_comms_core::BlePipe`
adapter. JSON parsing allocates only in the host harness; the dependency gate
keeps the parser and vector feature out of the domain crates and firmware
images. The test asserts the step count and each verdict and output. These
are host checks, not BLE conformance.
Native-app onboarding on each supported phone OS, coexistence, recovery and
heap-exhaustion tests on board A remain open in
[#96](https://github.com/origin89hq/firmware/issues/96) and
[KM43 #81](https://github.com/origin89hq/km43/issues/81).

BLE and WebSocket share the bounded connection table, with eight rows and
handles from a counter never 0 and never reused before the controller acknowledges the disconnect (L-060, L-080);
every inbound client frame has its handle stamped into `session_id` (P-021);
a link-local type on a client transport is dropped and answered (L-002). The
table lives in `o89-comms-core`'s link. A transport gets a row only while
linked, and a ninth is refused with nothing evicted; a row still waiting on
the answer to its release holds its place. Announcements and releases share
L-014's four requests with the time offer, three at a time, and wait for a
slot when all three are out. A refused `ClientConnected` drops the row and
closes the transport with its reason (L-061); one unanswered three times
closes the transport and is released, since the controller may hold the
row; an unanswered release goes again under a new id until answered or the
link falls. `conns` counts rows whose transport exists, announced or open
(L-101). A `CloseConnection` closes the transports it names and reports how
many (L-090); after a resync every transport is closed, and each client that
reconnects is announced under a new handle, which is the re-announcement
L-102 asks of a side that keeps no connection without its transport. A frame
that is not an envelope is answered `Error 1` at `0, 0` on its own connection
(P-025, P-028), since only this side knows where it came from. The
controller's frames go to the open row their `session_id` names, and a
refusal carrying one of the six link codes no client may see goes nowhere
(L-180). A
controller that goes quiet closes every client, stops advertising and retries
`LinkUp` every two seconds (L-120); it never answers a `Discover` from memory
(L-121).

**Storage**: one network, a value not a table (L-136), in its own partition;
a failed write is reported and the RAM copy keeps the site on the air
(L-137). The comms cache uses a fixed, checksummed record in `creds`, not
ESP-IDF's key/value NVS format. Replacement erases that partition, writes the
record, commits its marker last, and verifies it before answering `stored`.
An interrupted replacement may lose the cache; the controller restores it at
link-up. A clear erases the previous passphrase and retains only the version,
country and hostname. Duplicate successful requests do not erase again.

The Wi-Fi station starts after the recovery window and OTA confirmation,
using that cache, once the controller has said whether its pairing window
is open (L-195); without a controller there is no client to serve. Association, the network
runner and NTP run concurrently within one Wi-Fi session, so a failed
association does not hold up the UART or BLE tasks. Each reports
progress before the link feeds the watchdog. An unwritten clear keeps
Wi-Fi off; a written clear retains the country, and the radio scans under
it without joining once a client asks for a scan, until no client is left
connected and the result is settled (#166). While the pairing window is open Wi-Fi stays off
altogether (F-043).

On esp-radio 1.0.0-beta.1, BLE shares the radio with a joined station but
not with every station. With the station joined, a phone found the
advertisement and never completed a connection, twelve attempts of twelve
(bench 2026-09-24); that was the 72 KiB heap, since at 128 KiB three of
three connected, held and answered, with the station joined at boot or
after BLE (esp-rs/esp-hal#6397, bench 2026-09-25). What the heap does not
explain, on board A at 128 KiB: a station brought up for scans alone,
without connecting, left BLE advertising nothing; a BLE connection open
when a station starts ends in a supervision timeout; and disconnecting the
station, stopping it, or dropping the last `WifiController` each left BLE
advertising nothing until the module rebooted (bench 2026-09-24 and
2026-09-25). The vendor's BLE-side coexistence callbacks are empty stubs.
So Wi-Fi is off while a phone pairs, starting a station
is the only transition the radio makes in place, and any session that ends,
a changed record, a changed plan or a stuck scan, reboots the module
through its recovery window into the new plan, after the station's mDNS
goodbye. A window opened while the station runs costs that reboot; the
window at boot does not, because Wi-Fi waits for its report. With no network
cached, a scan starts the station only once its client is connected over
BLE, and that client loses its link: on board A a supervision timeout
ended it within a second of the station starting to scan and about two
seconds into a join, with no reset (bench 2026-09-25). The scan still
completes and its list reaches the controller, which keeps it; once the
client has gone and the result is acknowledged, the module reboots into
Wi-Fi off, and the phone reconnects and reads the kept list without a
refresh. A join goes on after the link has gone, and the phone finds the
controller over mDNS.
The radio and its RTOS use a fixed 128 KiB heap; credential storage and application networking buffers do not allocate. The IP stack's
socket set is fixed, and smoltcp panics, resetting the module, when a
socket arrives at a full one, so the budget is a sum of named slots in
`o89_comms_core::sockets`, one per socket anything opens. The station's
stack, the only one, has twelve: embassy-net's own DNS and DHCP client,
NTP, the mDNS responder, and one TCP socket per WebSocket worker. A host
test builds it with the firmware's embassy-net release and features and holds every socket open at once, and `cargo xtask
check` refuses the two feature lists differing. The time-offer channel
holds one sample, refusing a new sample while full.

**Discovery on the site network (KM43 P-224).** While the station holds an
address, the comms processor answers mDNS for `<hostname>.local` and
advertises one `_km43._tcp` instance named after the hostname: SRV on
`WS_PORT`, TXT `id` carrying the controller's `device_id` from its latest
`LinkUp` (L-035). Until a controller has stated one it advertises nothing,
and a client falls back to the address `WifiStatus` reported. The responder
is `o89_comms_core::mdns`, sans I/O and host-tested: three probes 250 ms
apart before claiming either name, RFC 6762 §8.2's comparison against a
simultaneous probe, `-2` and ` (2)` on a conflict up to 32 names, two
announcements a second apart and again when the address or the `device_id`
changes, known-answer suppression, a record multicast at most once a
second, unicast to a question that asks for it or to a resolver on another
port. The firmware runs it on one UDP socket in the station session, with
its 2.5 KB of buffers static, and `station()` asks it for a goodbye, every
record at TTL 0, before it returns, waiting at most 500 ms. Losing the
address stops the answers; there is nobody to send a goodbye from. Not
done: the 20 to 120 ms delay before a shared answer, negative answers for
types it lacks, and IPv6. mDNS says where to try, never who answers:
`Discover` and `Hello` decide (P-225).

Wi-Fi diagnostics on KM43 0.6.3 live in `o89-core::Wifi`. Both wrapped
reads are answered before capability bit 8 is advertised. A refresh checks
mask bit 1, written network metadata, the link, and the 10-second interval;
a refresh during a running scan joins it. A link up under a major mismatch
counts as down: the refresh is answered `link_down` and no order is sent,
since the peer refuses one with 261 (L-050). One numbered scan waits for its
acknowledgement and then at most 15 seconds for a result. Refusal, request
retry exhaustion, timeout, link loss or a changed comms boot fails it while
retaining the last completed list. Late results are acknowledged and discarded.
One current-boot radio report is held separately from the controller's network
version and is discarded with the link. Neither report can trigger a network
push or grant authority (P-221, L-207).

The core schedules `0x0806` through the recorder's existing bounded class A
queue: never for joining, immediately for a new reported version, otherwise
at the 10-minute boundary with the state then held. Address-only changes do
not generate records. A full recorder queue leaves the diagnostic due for the next turn and does
not spend its interval; no diagnostic changes persistence outside the recorder.

The comms core holds one accepted scan until its single result is acknowledged
or given up. A duplicate request retains the started verdict; another scan is
busy. Scan results, radio reports and NTP share one reserved link request slot,
leaving three for connection lifecycle requests. Retries carry their original
body; only the newest radio state waits behind an outstanding report. RAM
credential versions are reported even after persistence fails, and observations
from a superseded radio session are discarded. The first DHCP outcome waits at
most four seconds after association; missing IPv4 is `no_ip`, and a dropped
association is `lost`. The DHCP client resends DISCOVER after two seconds
rather than smoltcp's ten, so a single lost DISCOVER is resent inside that
bound instead of reading as `no_ip`. Once an installation has an outcome, retries never report joining. L-204 is
read as the current credential installation: any change of installed RAM
version, including a lower L-133 push, starts with no outcome. Old numeric
versions are not a history; an earlier configuration says nothing about the
credentials now installed under that number.

For a written country-only configuration, Wi-Fi stays off until a scan is
accepted, so a phone can open its BLE connection (#166); the station
interface then comes up without joining: no SSID and no call to connect.
It stays up while any client is connected or the result waits for its
acknowledgement, and the module then reboots into Wi-Fi off, since
stopping a started station in place leaves BLE silent. This permits an explicitly
requested scan before there is a network to join. Each scan has a four-second deadline; timeout produces a failed
result and ends the session so driver teardown stops an uncertain scan before
another join or scan. An unwritten configuration never starts either active or
passive scans. The recovery download window remains ahead of radio initialization.

NTP replies must match the request nonce and server endpoint and declare a
synchronized server clock. Samples older than one second before their first send are discarded.
Queries retry after thirty seconds unless the link attempts a fresh offer;
only that attempt defers the next query by fifteen minutes.
New `TimeOffer` requests are separated by at least fifteen monotonic minutes,
including failed sends and controller refusals. An unanswered request retries
the same sample and request ID at 500 ms, up to three attempts (L-015). The ESP32 never sets a clock
from the response. Board-A association, reboot recovery, time delivery and
recovery-window qualification with the radio remain the bench exit for
[#89](https://github.com/origin89hq/firmware/issues/89); BLE coexistence is
[#96](https://github.com/origin89hq/firmware/issues/96).

## Because it will become a product

Four things cannot be retrofitted to fielded hardware, so they are in from
unit #1 regardless of scope: **the bootloader with A/B and rollback**,
**per-device keys**, **protocol versioning**, and **serial numbers**.
Everything else waits for evidence. The standard being aimed at is not exotic
engineering; it is field data folded back into defaults, from three sites
through a winter, then thirty. The discipline above is what makes that data
trustworthy when it arrives.

## What lives elsewhere

- The circuit reasoning: the generator's electrical design, the
  transceivers, the isolated bus, the bus map, the serial-port budget, the
  buck values and the pin answers. origin89hq/hardware, per
  [origin89hq/hardware#50](https://github.com/origin89hq/hardware/issues/50);
  the rules are `A-nn` in board A's `LAYOUT-REQUIREMENTS.md` and `B-nn` in
  `GENERATOR-BOARD.md`.
- The wire: [KM43](https://github.com/origin89hq/km43), `P-nnn` and `L-nnn`.
- The requirements this repository adds: `REQUIREMENTS.md`, `F-nnn`, each
  with its source, and `traceability.toml`.
- The pins and the per-revision policy: `BOARD-A.md`, from the netlist.
- The hazards: `SAFETY.md`.
- The plan, the milestones and what is out of V1:
  [#3](https://github.com/origin89hq/firmware/issues/3) and its sub-issues.
