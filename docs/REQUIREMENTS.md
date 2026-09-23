# Requirements

The rules this firmware is held to that KM43 does not number. KM43's `P-nnn`
and `L-nnn` bind the wire and the controller's protocol obligations; the
hardware repository's `A-nn` and `B-nn` bind the boards. Everything here is
an `F-nnn`: a rule about what the firmware does on this board, each with the
source that argued for it and the milestone in [#3][plan] that closes it.

`cargo xtask check` reads every `**F-nnn**` below and refuses a rule that has
neither a `#[test]` named after it that invokes an assertion
(`fn f_012_...`), nor an entry in [`traceability.toml`](traceability.toml)
saying why no test can reach it, nor a place on that file's list of uncovered
rules. The list is by name and somebody defends it at each audit: a rule
leaves it when its test lands and joins it only when the rule is added, so a
test that goes missing is a failure and not a number that stayed the same. The
KM43 rules this repository's tests cite are counted the same way and reported,
against the rules the pinned `km43` ships as `km43::REQUIREMENTS`
([km43#31][k31]), so a citation is checked against the version the firmware
builds with.

A rule states one obligation. Where it seems to state two, it is two rules.
The reasoning behind a rule is in [`ARCHITECTURE.md`](ARCHITECTURE.md) or the
issue it cites; this file is the list.

[plan]: https://github.com/origin89hq/firmware/issues/3
[k31]: https://github.com/origin89hq/km43/issues/31

## The safety floor

**F-001** — `RUN` and `KICK` are driven low, push-pull, before any other
statement of the bootloader or the application executes after reset. On an
empty flash the ST system bootloader pulls `RUN` to 2.1–2.6 V and can pulse
`KICK`, which can close the generator's start contact with no firmware
running. Source: [hardware#30][h30], `A-34`. M1.

**F-002** — The three RS-485 transmit lines idle high from the reset vector
until their USARTs own them. A floating `DI` makes the transceiver drive its
bus low and blocks every other device on it. Source: [hardware#28][h28],
`A-41`. M1.

**F-003** — `PB6`, `PB3`, `PC2` and `PC3` are inputs, or driven low, and never
driven high, from before `V3V3_ESP` drops until after it is up. A pin driven
high into an unpowered module back-powers it through its input protection;
`EN` is driven low on purpose across a cycle (F-004). Source:
[hardware#17][h17], `A-39`. M1.

**F-004** — `EN` is held low by `PC2` across every rail cycle and released
only after the rail has settled. The RC alone does not reset a module whose
rail was cut briefly. Source: [hardware#14][h14]. M1.

**F-005** — On revision A no cut leaves the rail off for more than 5
seconds, and a controller reset, which drops the rail on this board, has it
back on before any bus is up, so a reset inside a cut adds only that path.
Switching it on after minutes off corrupts the STM32's control flow within
milliseconds, 22 times of 22; switch-ons after up to 33 s off passed. Where L-112 asks for a fifteen-minute cut, the
controller stops cycling, leaves the rail on, raises `0x0803` and logs which
policy it applied. Source: [hardware#5][h5], [km43#36][k36]. M1, M3.

**F-006** — USART1 is configured only after the rail has settled, never while
the unpowered module holds its transmit line low. Source: [hardware#5][h5]
(the framing error every cycle logged on the bench). M3.

**F-007** — The independent watchdog is armed at boot and is petted only by a
supervisor that has seen every task check in inside the period that task
declares. A watchdog fed from a timer is a watchdog that does not work.
Source: [`ARCHITECTURE.md`](ARCHITECTURE.md), the safety architecture. M1.

**F-008** — A task that misses its check-in has its name written to RAM that
survives the reset, and the next boot's record carries it. A reset nobody can
explain from the log is the one failure that cannot be debugged from four
hours away. Source: the self-test's last-words pattern, proven on the bench
2026-09-14. M1.

**F-009** — The reset cause is read from `RCC.CSR` before the HAL initialises
and cleared; it enters the boot record with the RTC backup-domain state.
Source: KM43 L-143, [km43#32][k32]. M1.

**F-010** — The LSE is asserted as the RTC's clock at boot; an RTC on the LSI
is reported as a fault, never taken as a fallback. It keeps time to a few
percent, looks alive, and does not survive the backup domain. Source: the
self-test's clock check. M1.

**F-011** — Every output declares its state at reset and reaches it before any
bus is up; an output arrives in shadow, and *granted* is a state somebody has
to ask for. Source: [`ARCHITECTURE.md`](ARCHITECTURE.md), per-channel fail
state. M1, M6.

**F-012** — On revision A no code enters a stop mode or reconfigures `PA13`
or `PA14`. The debug header carries no `NRST`, so a part that does either is
locked away from the probe for good. Source: [hardware#29][h29]. M1.

**F-013** — `FEEDBACK` is read through the pin's internal pull-up, and low
means both relays are closed. No pull-up exists on either board. Source:
`B-09b`. M1 reads it under the contract and logs it; M8 decides on it.

**F-014** — On revision B the rail is on with `PC5` high-impedance, the
controller takes ownership of it once booted, and every cut it makes is a
logged decision under L-111 or L-112 or the bank-voltage policy. On revision
A the rail is off through every reset, which nobody chose, and the boot
record says so. Source: [hardware#48][h48] `A-23`, [km43#35][k35]. M1.

**F-015** — Boot-to-first-kick is measured on the bench per reset kind —
watchdog, supply cut, panic — with a logic analyser on `CN9` pins 3 and 4,
and posted on [hardware#18][h18] with the watchdog timeout the firmware
settled on. M1; re-measured in M7 when the bootloader verifies a signature.

**F-016** — When the boot decides to resume an automatic start, `RUN` is up
and the first `KICK` is sent within 3 seconds of the reset, the FRAM read and
the bootloader's signature verification included. Board B revision B's
ride-through window is 15 s, budgeted as the 8.8 s worst-case watchdog plus
this allowance (`B-20`, [hardware#51][h51]). M1; held through M7.

**F-017** — The recovery ladder's cuts of the last hour outlive a controller
reset: they are written to the FRAM before the rail goes off, and a cut
whose count does not land is not made; a cut counts for the hour from when
its lines move. A boot carries each of them as made at its own start
(P-121), and a record that does not read counts as the three cuts L-112
stops at. A reset therefore never lowers the count; it can keep a cut in
the count for up to an hour longer than it was. Source: [#49][i49], KM43
L-112. M3.

**F-018** — On revision A the reset that began a boot is one of the ladder's
cuts, because the rail is off through every controller reset: three resets
inside an hour are the third rung. The ladder's record names the boot count
it was written at; a boot whose count landed and whose own record did not
is a cut the next boot counts, from the gap in the count. A reset before
the boot count itself lands is counted by no later boot: the count never
advanced, so no gap names the boot that was.
Source: [#49][i49], [hardware#48][h48]. M3.

## Persistence

**F-020** — Every FRAM record is an A/B pair of slots `[magic | seq | body |
crc32]`; a write goes to the slot that is not current, clears its magic
first and lands its magic last, in a transaction of its own, and the reader
takes the slot whose magic and CRC hold with the higher sequence, so a
write cut at any byte leaves the previous record in effect and no
intermediate image is a record, whatever its CRC. Source: KM43 P-102, the
seven brown-outs of 2026-09-16 that destroyed both counter slots. M2.

**F-021** — No FRAM transaction starts after the PVD's falling edge; one in
flight completes. Source: the same brown-outs. M2.

**F-022** — The reason the generator is running is written to FRAM on every
start and every stop, before the output moves. Source: [hardware#18][h18].
M2, M6.

**F-023** — The event log is a ring of variable-length records with 17 bytes
of framing, the magic programmed last, recovery by hunting forward for the
next magic rather than trusting a length, a torn write closing its block, and
class A never dropped. Source: [`ARCHITECTURE.md`](ARCHITECTURE.md), event
log storage. M2.

**F-024** — A rolling 24-hour write-volume counter lives in FRAM and is
compared on every append; class B is dropped first and counted, class A
over budget raises a concern. Source: the capacity budget in
[`ARCHITECTURE.md`](ARCHITECTURE.md). M2.

**F-025** — Every FRAM and NOR write path is run on the host crashing at
every step, with the recovery invariant asserted after each. Source: KM43
VERIFICATION §6. M2.

**F-026** — The client table carries the epoch its rows were enrolled under.
A boot that reads a table under an earlier epoch than the epoch record
holds clears it: a factory reset cut between moving the epoch and clearing
the table is finished at the next boot rather than leaving eight rows whose
keys no longer derive counting towards `table_full`. A table under a later
epoch than the record is never cleared under the earlier one: the record
regressed, and the higher of the two copies is the epoch. Source: KM43
P-085's order, F-025 on the reset path. M2.

## The link and the comms processor

**F-030** — The link is USART1 at 921600 8N1 with hardware flow control on
`PB6` (TX), `PB7` (RX), `PB3` (RTS) and `PB4` (CTS), to the module's UART0.
Source: [hardware#13][h13], [#2][i2]. M3.

**F-031** — The boot text arriving on the link at the ROM's baud after every
module reset, the ROM's and the second-stage bootloader's, is resynchronised
through and counted in bytes, and each boot attempt the controller starts
is recorded as `comms boot noise` (`0x0805`), zero included (KM43 P-215).
The bench measured about 1 140 refused runs per boot with the ESP-IDF
bootloader's log (2026-09-19 §4 and §5), which is a count of runs; the
baseline in bytes is to be measured. A count far from the baseline, in
either direction, is a link fault. The count is of the boots the link task hears at its own
rate; a boot into the ROM's loader for the bench is bridged at the ROM's rate,
byte for byte, and never counted. Source: [#2][i2]. M3.

**F-032** — The comms firmware re-arms the RTC watchdog as the first statement
after `esp_hal::init`, which disables every watchdog. A hang becomes a reset
and a reset re-opens the download window. Source: [#1][i1]. M3.

**F-033** — Before it forwards any client frame, the comms firmware listens
for a bounded period for `EnterDownload` on the controller UART and for
nothing else. Source: [#1][i1], [km43#30][k30]. M3.

**F-034** — `EnterDownload` is honoured by disarming the RTC watchdog, setting
`FORCE_DOWNLOAD_BOOT` and resetting, in that order: the watchdog lives in the
LP domain and outlives the software reset, and the ROM's loader does not feed
it, so one left armed resets the chip out of the loader eight seconds in. It
is never acted on outside the window, and never from a client transport. A
pattern in the relayed stream that reboots the module is a way for any client
to take the product off the air. Source: [#1][i1], bench 2026-09-19. M3.

**F-035** — `boot_id` is drawn from the hardware RNG with the ADC entropy
source enabled, before the RF subsystem is up; the bare RNG is pseudo-random
until then. Source: KM43 L-040, `esp-hal`'s RNG documentation. M3.

**F-036** — The partition table holds `otadata`, two OTA slots, a factory
slot that OTA never writes and that always carries the window, the credential
record and the assets. Source: [#3][plan] §4.4, §9 item 5. M3.

**F-037** — The comms firmware's heap serves the radio's blobs only; no code
of ours allocates, and the gate refuses `alloc` in our modules. Source:
[#3][plan] §3. M3.

**F-038** — The bench flashing path through the STM32 speaks the ROM's baud on
USART1 and switches back to the link's afterwards. It enters the ROM by one
of two routes the controller performs: the window the comms firmware opens
(L-190 to L-192), or IO9 held low across a reset, which on revision A needs
IO8 held high by a wire and on revision B works alone. The ROM never waits
in its loader by itself: a module with no bootable app reboots through its
second-stage bootloader forever, so a module that runs nothing that honours
the window is reached by the strap or not at all. Source: [#4][i4],
[hardware#6][h6], [#1][i1]. M3.

**F-039** — The controller's `boot_id` is SHA-256 over the part's unique id
and the boot count, truncated to the field's width. The boot count is kept
on the FRAM and advanced from the stored value when the boot record is
written, saturating at `u32::MAX`, so before saturation it is a new input at
every boot; with no RNG and no secret in it, a unit without a provisioned
secret still states itself. Two boots share a
value with the chance two random draws would, one in 2^32, which is the
bound the field's width gives any scheme; what L-040 forbids is a value
that rests on RAM and comes back the same by construction, not one that
repeats by chance. Its secrecy is nothing (L-020). A boot without a
written count, which is a FRAM that did not answer or a new count that
did not land on it, has no `boot_id`: the link stays down, because an id over the unique id
alone would come back the same after the reboot L-040 exists to make
visible. The module is powered as on every boot: on revision A a rail kept
off and switched on at a later boot is what F-005 forbids.
Source: KM43 L-040, [#3][plan] §4.2. M3.

## Sessions and provisioning

**F-040** — Three distinct gestures — open the pairing window, arm the floor
override, factory reset — are defined on the selector for revision A and the
button for revision B, and no gesture means two things. Source: KM43 P-066,
P-117, `A-42`. M4.

**F-041** — A challenge is derived from the device secret and a counter in
FRAM that is written before the challenge leaves; a write that fails mints
nothing. The part has no RNG, and a counter that repeats re-mints a challenge
a recorded proof verifies against twice. Source:
[`ARCHITECTURE.md`](ARCHITECTURE.md), where challenges come from. M4.

**F-042** — The comms processor's own access point is up only while no
network is cached or the pairing window is open, and goes away when either
ends. Source: [#3][plan] §9 item 3. M4.

## The site

**F-050** — A Modbus driver on this board discards the frame it just sent
before reading the reply; the transceivers are auto-direction with the
receiver always on, so every speaker hears itself. Source: the self-test's
RS-485 check, `A-13b`. M5.

**F-051** — On revision A the VE.Direct receive pins carry no pull-up unless
the port is configured for a 3.3 V product; Victron's MPPTs drive 5 V and the
pins sustain it only with the pull-up off. Source: [hardware#27][h27]. M5.

**F-052** — A map cell declares the provenance the vendor can justify, and
the driver writes that provenance; nothing publishes as `measured` by
default. An estimated state of charge published as measured is one a
`counted_only` rule would act on. Source: [#5][i5]. M5.

**F-053** — A DS18B20 read that fails its CRC produces no value; a hot-swapped
probe produced eleven on the bench. Source: [hardware#31][h31], bench
2026-09-16. M5.

**F-054** — The generator board's dropout after the last kick is measured on
every observed dropout against the 3.0–6.5 s contract, and the design figure
of 4.5 s is never assumed. Source: [hardware#22][h22]. M8.

## Behaviours

**F-060** — A `Decision` is `#[must_use]` and touches no output; the runtime
applies it or writes down what it would have done, and the behaviour cannot
tell which. Source: [`ARCHITECTURE.md`](ARCHITECTURE.md), shadow mode. M6.

**F-061** — After a reset inside the generator board's ride-through window, an
automatic start whose condition still holds resumes, a manual start is
stopped deliberately by kicking with `RUN` low, and a maximum run time
backstops both. Source: [hardware#18][h18]. M8.

**F-062** — A start attempt below −20 °C is a decision made deliberately and
logged with the temperature that justified it, never the result of not
knowing. Source: the GenStart manual's choke-actuator range,
[`ARCHITECTURE.md`](ARCHITECTURE.md). M6.

## The bootloader and release

**F-070** — At no instant are there zero bootable images: the selected bank
is never erased, and the bank flip is the last step after the whole inactive
bank has been written and verified. Source: [#3][plan] §9 item 2. M7.

**F-071** — The bootloader is written at manufacture into both banks and
never by an update: the updater refuses a manifest that covers the first 8 KB
of a bank, and the bootloader checks its twin at boot. Source: [#3][plan] §9
item 2. M7.

**F-072** — Trial boots of a new image are counted, and the flip back to the
previous bank is performed by the bootloader, not the application. Source:
[#3][plan] §4.2. M7.

**F-073** — The ESP32-C6's eFuse anti-rollback counter is left untouched;
no-downgrade for the comms image is enforced at the controller's
authorisation. A counter that advanced would refuse the factory image.
Source: [#3][plan] §9 item 5, KM43 L-169, [km43#34][k34]. M7.

**F-074** — The factory slot holds the first release, frozen; recovery from
two dead OTA slots is that release. Source: [#3][plan] §9 item 5. M7.

## The gate

**F-080** — Every image is measured as the bytes that reach the part, never
the ELF, against its slot with a stated margin, on every commit. Source:
[#3][plan] §6. M0.

**F-081** — `o89-comms` never depends on `o89-core`, and no domain crate
depends on a crate that names a peripheral or on the allocator. Source:
[#3][plan] §4.2, §4.4. M0.

**F-082** — Every `F-nnn` has a `#[test]` named after it that invokes an
assertion, or an entry in `traceability.toml` with a kind and a reason, or is
listed there as uncovered by name; a rule leaves that list when its test
lands, joins it only in the commit that adds the rule, and a rule whose test
goes missing fails the gate whatever the count. Source: KM43 VERIFICATION §1.
M0.

**F-083** — Every pin the controller's board module takes has a row in
`BOARD-A.md`, and every row there is taken by the module or named by it as
left alone; a pin lives in exactly two places that cannot disagree. Source:
[#3][plan] §6. M1.

**F-084** — The bench flashing path writes the application into an OTA slot
and names that slot in `otadata` only once the application has landed; before
it erases the slot it blanks the `otadata`, so from the first erase until the
last write the module boots the factory image. The bootloader, the partition
table and the factory image are replaced only by a route named for replacing
them. The state written is `New`, which the bootloader, having rollback
(F-088), holds against the image until it confirms itself, which `o89-comms`
does after its window and not before (F-089). A transfer that dies leaves a
module the controller can knock at with no wire on it, which is what the
erase at address zero did not. Source: [#1][i1], F-036, bench 2026-09-19 §5
for the loss this prevents and §10 for the sequence run on the board. M3.

**F-085** — The slot route plans from the partition table the module holds,
read back from the sector the bootloader reads it from, and never from the
table in the repository, which says only what the next whole flash would
install. The two are compared and any disagreement about the partitions
being written is reported, because a repository whose table has moved on is
a whole flash somebody has not run. A table this tool cannot read whole is
refused rather than partly believed: its checksum is recomputed the way the
bootloader recomputes it and a table that fails it is refused, since offsets
from a table the bootloader would reject are offsets to write nothing at,
and every partition is bounded by the flash the module has. A table with no
checksum entry is still read, because ESP-IDF makes it optional and the
bootloader accepts one without. Without this the guard of F-084 checks
the factory range the repository claims while the bytes land on the
module's, so a table change alone could erase the recovery image and report
that it stayed. Source: [#1][i1], F-084, review of [#58][p58]. M3.

**F-086** — A link reader that loses its footing finds it again at the next
delimiter, and the loss is bounded to one frame. A pair pulled mid-frame
leaves a fragment that runs into whatever arrives next, so the frame whose
delimiter closes that run is read as one frame with the fragment and
refused; the frame after it is read whole. A break the line then goes quiet
after costs only the part-frame, which the reader abandons once it is told
how long the line has been silent. No input panics, and nothing on this path
allocates. Source: KM43 P-030, [#3][plan] §M3 exit. M3.

**F-087** — The link carries ten thousand worst-case frames at 921600 with
no CRC failure and no overrun, and the same run with the flow control lifted
does not. A worst-case frame is the longest payload KM43 allows with no
delimiter byte in it, so COBS adds its most and the wire carries its most
per frame; the module sends them in batches between turns of its link loop,
so the controller's requests are still answered and the ladder never cuts
the rail mid-run. The controller counts frames whose CRC held, frames
refused between delimiters, part-frames abandoned and the UART's own
overruns, apart, because a counter that added them would hide whichever was
rarer. Source: KM43 VERIFICATION §8, [#3][plan] §M3 exit. M3.

**F-088** — The module's second-stage bootloader is ESP-IDF's, built by this
repository from a pinned release with app rollback enabled, committed with
the configuration that built it and its hash, and the only bootloader the
whole route writes: the bench tool takes no other file, and refuses the
committed one when its bytes and its hash disagree. The gate holds the
binary to that hash, the configuration to the rollback option and the
binary to the release the build script names, because a binary is invisible
in a review and those three lines are not. The one `espflash` ships is
built without rollback: its manifest sets
only the flash size, and ESP-IDF's default for the option is off, so under it
the `New` state of F-084 is ignored and a bad image keeps its slot for good,
which is the loss #1 names. The slot route reads the module's flash below
the partition table back and refuses, before it writes anything, a module
that does not hold byte for byte what the whole route would write there; the
way forward is the whole route once, by the knock. Source: [#1][i1], F-084,
`espflash`'s bootloader manifest, ESP-IDF's `Kconfig.app_rollback`. M3.

**F-090** — When the controller's receive ring is full, the driver leaves
the byte in the hardware and masks its receive interrupt until the task has
made room, so `RTS` deasserts and the module is held off rather than the
byte being dropped. A late task therefore costs throughput and never a
frame. This is why the firmware workspace pins Embassy to a revision of its
`main` and not to 0.6.0, whose handler empties the data register on every
interrupt and drops what does not fit, which makes the flow control on the
wire decorative. The hardware's own receive faults are still not reported
by the driver, so F-087's no-overrun condition stays unmeasured ([#66][i66]).
Source: [#66][i66], embassy-rs/embassy 844c4e7b. M3.

**F-089** — `o89-comms` confirms the slot it runs from against the proof
that its download window ran, a value only the window makes and only once it
has passed, and against nothing else. An image whose window is omitted has
nothing to confirm with, so it runs unconfirmed until its next reset, at
which the bootloader puts the previous image back (F-088); an image that
crashes before its window never reaches the confirmation at all. Together
these are #1's acceptance test: a crashing image and a windowless image,
each delivered as an update, each rolled back to an image that honours the
window, and the module reached again through the controller with no wire.
Source: [#1][i1], F-036, F-088. M3.

[h5]: https://github.com/origin89hq/hardware/issues/5
[h6]: https://github.com/origin89hq/hardware/issues/6
[h13]: https://github.com/origin89hq/hardware/issues/13
[h14]: https://github.com/origin89hq/hardware/issues/14
[h17]: https://github.com/origin89hq/hardware/issues/17
[h18]: https://github.com/origin89hq/hardware/issues/18
[h22]: https://github.com/origin89hq/hardware/issues/22
[h27]: https://github.com/origin89hq/hardware/issues/27
[h28]: https://github.com/origin89hq/hardware/issues/28
[h29]: https://github.com/origin89hq/hardware/issues/29
[h30]: https://github.com/origin89hq/hardware/issues/30
[h31]: https://github.com/origin89hq/hardware/issues/31
[h48]: https://github.com/origin89hq/hardware/pull/48
[h51]: https://github.com/origin89hq/hardware/pull/51
[i1]: https://github.com/origin89hq/firmware/issues/1
[i2]: https://github.com/origin89hq/firmware/issues/2
[i4]: https://github.com/origin89hq/firmware/issues/4
[i5]: https://github.com/origin89hq/firmware/issues/5
[i49]: https://github.com/origin89hq/firmware/issues/49
[i66]: https://github.com/origin89hq/firmware/issues/66
[k30]: https://github.com/origin89hq/km43/issues/30
[k32]: https://github.com/origin89hq/km43/issues/32
[k34]: https://github.com/origin89hq/km43/issues/34
[k35]: https://github.com/origin89hq/km43/issues/35
[k36]: https://github.com/origin89hq/km43/issues/36
[p58]: https://github.com/origin89hq/firmware/pull/58
