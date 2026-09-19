# Safety

The hazard matrix: every way this firmware can hurt the equipment or the
site, the invariant that prevents it, the mechanism that holds the
invariant, the test that proves the mechanism, the evidence that the test
was run, and who reviewed it. A row whose evidence column says *compiles* is
a row that is not done; a row whose test column is empty is a hazard nobody
has argued against yet. The shape is the engineering repository's
[change record](https://github.com/origin89hq/engineering/blob/main/templates/safety/change-record.md);
a change that alters a row files one.

Safe is not always de-energised. The generator contact's safe state is open;
a frost heater's is a decision the configuration makes per output (F-011). The
comms processor's rail is on (F-014). What every row shares is that the state
is *declared*, before the output exists.

## Hazards

| # | Hazard | Invariant | Mechanism | Test | Evidence | Reviewer |
| --- | --- | --- | --- | --- | --- | --- |
| H1 | The generator's start contact closes with no firmware running: an empty flash boots the ST system bootloader, which pulls `RUN` up and can pulse `KICK` (hardware#30) | There is never an empty-flash window, and no image reaches its second instruction with `RUN` undriven | Dual-bank swap with the selected bank never erased (F-070); `RUN`/`KICK` low at the reset vector (F-001); revision B moves the lines and adds pull-downs (`A-34`) | M1: with board B on CN9 and nothing on its CN10, a mass erase, a watchdog reset, a panic and a supply cut, the contact scoped and never closing; M7: an update interrupted at every step | host: `f_001_*` reads the declared fail state in `o89-core`, 2026-09-18; bench 2026-09-18: the production image boots through the bootloader on board A revision A, the lines not yet scoped (`docs/bench/2026-09-18.md`) | — |
| H2 | A reset stops a running generator: on revision A any controller reset opens the contact within milliseconds (hardware#18) | A generator that was running under automatic control resumes when its condition still holds; a manual start does not | The run reason in FRAM before the output moves (F-022): the output driver moves on a `Declared` that only a landed write produces; the resume policy (F-061); board B's ride-through window on revision B | M8 on the bench with the analyser on CN9; boot-to-first-kick posted (F-015) | host: `f_022_*` in `o89-core`, 2026-09-18; bench: none yet | — |
| H3 | The comms rail switched on after minutes off corrupts the STM32's control flow (hardware#5), which on this board holds the generator lines | The rail is never switched on after a long off on revision A | F-005, F-006; the default-on switch on revision B (F-014) | M1: the ladder's rungs exercised with the rail scoped; the 22-of-22 case never produced | bench 2026-09-14 and 2026-09-16 record the hazard, not yet the mitigation; host: `f_004_*` and `f_005_*` in `o89-core` run the rail sequencer through a boot, a cut and the third rung on both revisions, 2026-09-18 | — |
| H4 | A brown-out mid-write destroys the counters that stop a replay, or the configuration that runs the site: seven brown-outs on 2026-09-16 wiped both counter slots | A write cut at any byte leaves the previous record in effect, and no counter ever regresses | A/B slots with the CRC landed last (F-020); no transaction after the PVD edge (F-021); crash-at-every-step on the host (F-025); the counter and the dedup entry in one record, the RAM copy moved only once the part has it (P-079, P-080); the epoch stamp that finishes a cut reset (F-026) | M2: a thousand supply cuts mid-write overnight | host: `f_025_*`, `p_080_*`, `p_085_*` and `f_026_*` in `o89-core` and `o89-sim`, 2026-09-18; bench: the boot count landed through every reset of 2026-09-18 §3 | — |
| H5 | A hung task leaves an output where it was while the watchdog is fed by a timer | The watchdog is fed only when every task has checked in inside its period | The rollcall supervisor (F-007), on its own interrupt above the thread executor so a task that blocks the executor is still named; the blame that survives the reset (F-008) | M1: deliberate starvation, the reset, the next boot naming the task | host: `f_007_*` and `f_008_*` in `o89-core` run the rollcall and the last words on a laptop; bench 2026-09-18 §1: a task that stopped checking in was named and the reset followed; bench 2026-09-18 §3: a recorder blocked in a DMA transfer's await was named 101 ms past its window and the watchdog reset the part with the outputs in their fail state, which proves the cooperative case only; bench 2026-09-19: with the control task spinning the thread executor, the supervisor still ran from its interrupt, named Control 99 ms past its window, and the boot after the watchdog read the blame | — |
| H6 | A decision reaches an output without authority: a behaviour writes a pin, or an output arrives granted | No behaviour touches an output; every output arrives in shadow | `Decision` is `#[must_use]` and inert (F-060); per-output shadow (F-011) | M6: a test per behaviour that fails when its fail-safe is deleted; a month of shadow compared against what happened | none yet | — |
| H7 | The comms processor makes a decision, or a client makes one through it | The untrusted half cannot reach the crate that decides; every write is authenticated at the controller | `o89-comms` never depends on `o89-core` (F-081); KM43's MACs and counters at the controller (P-080) | The gate, watched refuse the dependency; M4's adversarial corpus | gate: 2026-09-18, refused `o89-core` under `o89-comms` | — |
| H8 | The module can no longer be reprogrammed on revision A: a bad image takes the only wire-free download path with it (#1) | The download window runs before any code that can crash, and is never triggered from the client stream | F-032, F-033, F-034; OTA rollback to the image that honoured it; the factory slot (F-036, F-074) | M3: a crashing OTA image recovered through the STM32 with no wire, then one with the handler omitted | none yet | — |
| H9 | A clock moved by a client or the comms processor ages out a dedup entry, a session or a challenge, and a retried command starts the generator twice | No duration is measured on the wall clock | The monotonic tick (P-004); every bound in `o89-core` on it | `p_004_*` in `o89-core`; M4: the clock moved eleven minutes under a running session and nothing on the tick moves | `o89-core` tests, 2026-09-18 | — |
| H10 | A hung instrument reads as a steady site: a bus keeps answering the same plausible number for a week | A channel that has not changed inside its declared run reports `stale` | The store's maximum unchanged run per channel; `initialising`, `sensor_fault`, `absent` as distinct validities | M5: a frozen fixture crosses its run and the reading turns stale; a reconnected probe starts a new run | none yet | — |
| H11 | An estimate is acted on as a measurement: an EPEver's computed state of charge starts the generator under a `counted_only` rule | Provenance is declared per cell and never defaults to measured | F-052 | M5: a cell declared `estimated` refused by `counted_only` (#5) | none yet | — |
| H12 | An image that fits the part and not the slot ships and fails its first update in a cabin | Every image is measured as the `.bin` against its slot with a margin, on every commit | F-080 | The gate, watched refuse a lowered budget | gate: 2026-09-18 | — |
| H13 | A start attempt below −20 °C damages the choke actuator, and the failure is silent until the engine will not catch in January | The decision is made deliberately, from a temperature the controller holds, and logged | F-062; the outdoor probe's validity in the decision's inputs | M6: the decision and its record under both policies, with the probe absent, stale and present | none yet | — |
| H14 | A probe transient on an unclamped input reads as a real state change: the selector flips to manual, a temperature jumps (hardware#31) | An out-of-range or CRC-failed reading is no reading | Selector debounce; F-053 | M5: eleven CRC failures in a row produce no value and one concern | bench 2026-09-16 records the hazard | — |
| H15 | A firmware change locks the probe out of a revision A board for good (hardware#29) | No stop mode, no SWD pin reuse on revision A | F-012 | Review, and the board revision as a build-time type that makes the stop-mode path unreachable on revision A | host: `f_012_*` reads the policy in `o89-core`, 2026-09-18; the type lands with the first low-power path | — |

## Fault matrix

The engineering standard's rows, and where each is answered. A row here is a
promise about coverage; the tests are named in the milestones.

| Failure | Where it is answered |
| --- | --- |
| Sensor missing, stale, implausible or conflicting | H10, H11, H14; the store's validity and provenance (M5); every behaviour's answer for *unknown* (M6) |
| Boot, reset, brownout, watchdog or power loss | H1, H2, H3, H4, H5; the boot order (M1); persistence (M2) |
| Disconnect, malformed frame, duplicate or delayed command | H7, H9; the resynchroniser and CRC (M3); the dedup table and counters (M4) |
| Stuck actuator, or command and feedback disagreeing | `FEEDBACK` against the commanded state; *stop not honoured* and *running, not ours* as states (M8) |
| Timer wrap, full queue, exhausted retries, memory pressure | The 64-bit tick (H9); every table with a named capacity that refuses (M4, M5); no allocator (F-081) |
| Interrupted update or corrupt persisted state | H1, H4, H8; the bootloader's trial and flip-back (M7); the ring's torn-write rule (M2) |
