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

- A device-unique secret in the controller's FRAM, never exposed to the comms
  processor. No key crosses the link; both sides derive one, and what crosses
  is a proof of knowledge.
- Every write is signed, with a per-client monotonic counter. Authenticating
  one write and not another is a locked door beside an open one.
- Every response and every event carries a MAC too. A forged command has a
  physical consequence somebody eventually notices; a forged *reading* is
  simply believed, and a comms chip that can answer "bank at 80 %" when it is
  at 30 defeats the product's whole proposition.
- Factory reset and un-pairing are physical acts at the controller and exist
  as no message at all. Not a command that checks a flag: there is no such
  command in the protocol to find.

That is the client–controller authentication: the keys, their derivation and
the MACs are P-040–P-045, P-050–P-053 and P-085–P-088. It is not the link
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
  o89-drivers/             no_std device dialects: Modbus RTU, EPEver, PZEM DC,
                           PZEM-016, VE.Direct text, Pylontech CAN, DS18B20.
                           Tested against committed captures.
  o89-sim/                 The simulated site: seasons, faults, the hostile
                           comms processor, crash-at-every-step.
  o89-dev/                 The bench tool: flashes both chips, streams defmt,
                           reads the FRAM and the NOR ring over SWD.
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
allocator. If logic needs a board to test, the seam is in the wrong place.

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
| Challenges | Derived, not a seam | The part has no RNG peripheral, so there is nothing behind a trait to vary (below) |

The distinction is open set against closed set. Peripherals and transports
vary by target and by test, so they are traits. Devices and behaviours are
enumerable at build time, so they are enums.

Alongside: no `dyn`; our own enums matched exhaustively; `#[must_use]` on
every decision, verdict and outcome type, because a dropped decision is a
rule nothing performed; fixed capacity everywhere with a written overflow
policy, so what is dropped when a queue is full is decided now rather than
discovered at −30 °C. Telemetry drops. A safety event does not. The full
coding rules are #3 §3, enforced by the manifests and the gate.

### Where challenges come from

The STM32G0B1 has no RNG peripheral; `RNG` does not appear in the part's
metadata at all. P-063's *a challenge MUST come from a CSPRNG* is answered by
derivation: a challenge is `HKDF(device_secret, "km43/v1/challenge" | counter)`
truncated to sixteen bytes, a PRF in counter mode, unpredictable to anybody
who does not hold the printed secret, which is everybody the threat model
cares about. The comms processor is hostile and does not hold it; somebody
who does can pair anyway, so predicting a challenge buys them nothing. It has
its own derivation label because a challenge is published in every
`Discover`, and sharing a derivation with the pairing key would hand out the
key the device rests on.

**The counter is the whole of the security, and it must outlive a reset.** A
counter that repeats re-mints a challenge that a recorded proof verifies
against a second time. So it is written to FRAM before the challenge it names
goes out, never after. That makes the CSPRNG depend on storage rather than on
a peripheral, which is why it is not a seam. Physical entropy is not needed
and not ruled out: the ADC's low bits are noisy, and stirring them in raises
the cost of a stolen label without changing the argument.

### Embassy, and why the choice is cheap

Embassy, confined to `o89-controller`. The drivers are already async state
machines: a Modbus exchange is send, await a reply, time out, which in a
superloop is a hand-rolled state machine per bus, and that is where the bugs
live. `embassy-stm32` gives DMA receive with idle-line detection, which is
what the framing wants. And the one real concurrency constraint is *do not
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
   liveness argument. The failure mode of a cooperative executor is one task
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
   the answer, not a hope about the part.
6. **FRAM read**: identity, epoch, configuration pointers, the client table,
   counters, the dedup table, the generator run reason, the panic record.
   **NOR scan**: the log ring's head and the time floor, the newest
   timestamped record (L-140).
7. **Outputs to their declared fail state**, per output, from configuration,
   and shadow unless authority was granted.
8. **Buses up**: three RS-485 USARTs, FDCAN, two LPUARTs, 1-Wire, ADC.
9. **The module rail sequence** (the safety architecture below), then the
   link task.
10. **Control tick** at 1 Hz. Boot-to-first-kick is measured and logged; the
    hardware repository is waiting on that number
    ([origin89hq/hardware#18](https://github.com/origin89hq/hardware/issues/18)).

### Tasks and the watchdog

Each task owns a peripheral and declares a check-in period: supervisor,
control, link, recorder (the only owner of the FRAM and NOR buses), one per
RS-485 channel, CAN, one per VE.Direct port, 1-Wire, ADC, selector, lamp.
Bounded channels between them, `static_cell` for what the executor needs, no
allocator. Nothing blocks; a bus that hangs is a task that misses its
check-in, which is a reset, which is the fail state.

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

**The selector is also the physical act the protocol needs.** Opening a
pairing window, un-pairing and factory reset must be acts nobody can perform
over the wire, and board A revision A carries no pushbutton. So a deliberate
gesture on the selector is the act, and there are three distinct gestures
because P-117 forbids one press meaning two things: the pairing window, the
time-floor override and the factory reset (P-066). Every transition passes
through *Off*, the position in which the controller never commands the
generator, and the person making it is standing at the panel. Revision B's
button ([origin89hq/hardware#11](https://github.com/origin89hq/hardware/issues/11),
A-42) takes over with at least the same three gestures; the selector gestures
stay defined so a unit with either board reads the same.

**One lamp, meaning by pattern.** Two LEDs share one light pipe, so what a
person sees is one lamp: a slow heartbeat is a controller that is alive,
linked and on the network; a double heartbeat is alive with no network; a
fast blink is a fault. The controller learns link and radio state over the
protocol and renders it; the board has no lamp of its own for the radio.

### Sessions and writes

Enrolment is gated by the gesture. Challenges are derived as above, with the
counter written before the challenge leaves. A signed request is verified in
P-080's order; the counter and the dedup entry are written in one FRAM
transaction, and a write that fails fails closed (P-079). Commands are
reserved until an output has been granted authority.

### The link

USART1 with a DMA ring buffer and KM43's frame reader and writer. The core
holds the link-local state: link-up and `boot_id` invalidation, the heartbeat
and the recovery ladder with the board's revision policy (below), connection
rows and challenges, network configuration push, time offers with the floor,
cap and rate limit, and the comms release flow. The adapter owns the bytes
and the rail pin. The ROM's boot text arrives on the link at 115200 after
every module reset while the link runs at 921600; the framer resynchronises
through it and counts it, and a count that is not near one per module boot
means the link is wrong (#2).

## Persistence

| | Part | Holds | Layout |
|---|---|---|---|
| FRAM | FM24W256, 32 KB, I2C | Everything control-critical: configuration sections in A/B slots (P-102), the client table with masks and counters (P-081, P-105), the dedup table (P-121), the epoch (P-085), the challenge counter, the device secret, the generator run reason (origin89hq/hardware#18), the panic record, the boot counter, the rolling write-volume counter, the authorised comms release (L-170), the network master copy (L-130) | A `const` map with a budget assertion; each slot `[magic \| seq \| body \| crc32]`, pointer flip last |
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
the client table live in A/B slots with a sequence number and a CRC, switched
by an atomic pointer flip, and it is the same machinery the bootloader needs,
so it is built once. The PVD discipline above is the other half: no
transaction starts on a falling supply. Every FRAM write path runs crashing
at every step on the host, and the invariant after recovery is asserted.

History at full resolution is a client's job. The controller keeps enough to
survive a long disconnection, which is a different requirement from keeping
a year.

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

- The recovery ladder's cuts (L-111, L-112), each logged with its count.
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
deliberate ones. Switching the rail on after minutes off corrupted the
controller within milliseconds, 22 of 22 times on the bench, while short
cycles pass hundreds of times
([origin89hq/hardware#5](https://github.com/origin89hq/hardware/issues/5)).
So on revision A a rail cycle is at most 5 s off; the ladder's third rung,
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
PAC in one audited function, one of the three `unsafe` sites in the firmware,
with the bootloader's jump into the application and the comms processor's
download-register write.

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
3. **The download window.** For a fixed period the firmware listens for a
   link-local `EnterDownload` frame from the controller
   ([origin89hq/km43#30](https://github.com/origin89hq/km43/issues/30)) and
   for nothing else. On one it acknowledges, sets the ROM's force-download
   flag (`LP_AON.SYS_CFG` bit 30, the crate's one `unsafe`) and resets into
   the ROM. It never scans the relayed client stream for anything. The window
   runs before any code that can crash for a reason of ours.
4. The scheduler, the heap for the radio blobs, the Wi-Fi station on the
   cached network, the TRNG seeded from the ADC source so `boot_id` is random
   before the RF subsystem is up (L-040).
5. `LinkUp`, then the heartbeat, then transports.

**A heap only for the radio.** The radio blobs cannot run without one; our
own code there is written as if it had none, and `o89-comms` never depends
on `o89-core`, which the gate refuses.

**Partitions and recovery.** `otadata`, two OTA slots, a **factory** slot
that OTA never writes and that always carries the window, a single-network
credential record, and a web-assets partition; three 2 MB slots and the
assets fit an 8 MB module. The factory slot is the frozen first release, not
a minimal image: a recovery path has to be proven and immutable, and a
shipped release is both. An OTA image that boots and never confirms healthy
is rolled back by the ESP-IDF bootloader to the image that was running, which
honours the window (L-173). If both OTA slots are bad it falls to the factory
image, which honours the window. The only way to lose the window is to flash
a bad image into the factory slot through the download mode itself, a bench
act with a probe attached and a wire available. That is #1's acceptance
test, run before any revision A unit leaves the bench. ESP-IDF's eFuse
anti-rollback would refuse the factory image the first time its counter
advanced, so the eFuse counter stays untouched and no-downgrade is enforced
at the controller's authorisation (L-169). Kept open, not in V1: the
controller has 16 MB of NOR and the authorised comms image is under 2 MB, so
a controller that keeps the last authorised image can reflash a dead module
through the ROM with no client and no drive.

**Transports in V1**: local Wi-Fi with one WebSocket connection per client
(P-034), and the comms processor's own access point for provisioning, raised
only while no network is cached or the pairing window is open, so a phone's
browser can pair and write the network section before the house Wi-Fi
exists. It carries nothing a client could act on without a session. Cloud
and BLE are specified in KM43 as unimplemented and stay that way in V1. The
connection table has eight rows, handles from a counter never 0 and never
reused before the controller acknowledges the disconnect (L-060, L-080);
every inbound client frame has its handle stamped into `session_id` (P-021);
a link-local type on a client transport is dropped and answered (L-002). A
controller that goes quiet closes every client, stops advertising and retries
`LinkUp` every two seconds (L-120); it never answers a `Discover` from memory
(L-121).

**Storage**: one network, a value not a table (L-136), in its own partition;
a failed write is reported and the RAM copy keeps the site on the air
(L-137).

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
