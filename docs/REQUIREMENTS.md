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
against the pinned copy in [`km43/requirements.tsv`](km43/requirements.tsv),
until km43 ships the index itself ([km43#31][k31]).

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

**F-005** — On revision A the rail is never off for more than 5 seconds.
Switching it on after minutes off corrupts the STM32's control flow within
milliseconds, 22 times of 22. Where L-112 asks for a fifteen-minute cut, the
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
`B-09b`. M8.

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

## Persistence

**F-020** — Every FRAM record is an A/B slot `[magic | seq | body | crc32]`
and takes effect by a pointer flipped last; a write cut at any byte leaves
the previous record in effect. Source: KM43 P-102, the seven brown-outs of
2026-09-16 that destroyed both counter slots. M2.

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

## The link and the comms processor

**F-030** — The link is USART1 at 921600 8N1 with hardware flow control on
`PB6` (TX), `PB7` (RX), `PB3` (RTS) and `PB4` (CTS), to the module's UART0.
Source: [hardware#13][h13], [#2][i2]. M3.

**F-031** — The ROM's boot text, arriving on the link at its own baud after
every module reset, is resynchronised through and counted, and the count per
boot is logged; a count far from one is a link fault. Source: [#2][i2]. M3.

**F-032** — The comms firmware re-arms the RTC watchdog as the first statement
after `esp_hal::init`, which disables every watchdog. A hang becomes a reset
and a reset re-opens the download window. Source: [#1][i1]. M3.

**F-033** — Before it forwards any client frame, the comms firmware listens
for a bounded period for `EnterDownload` on the controller UART and for
nothing else. Source: [#1][i1], [km43#30][k30]. M3.

**F-034** — `EnterDownload` is honoured by setting `FORCE_DOWNLOAD_BOOT` and
resetting; it is never acted on outside the window, and never from a client
transport. A pattern in the relayed stream that reboots the module is a way
for any client to take the product off the air. Source: [#1][i1]. M3.

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
USART1 and switches back to the link's afterwards. Source: [#4][i4],
[hardware#6][h6]. M3.

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
[k30]: https://github.com/origin89hq/km43/issues/30
[k32]: https://github.com/origin89hq/km43/issues/32
[k34]: https://github.com/origin89hq/km43/issues/34
[k35]: https://github.com/origin89hq/km43/issues/35
[k36]: https://github.com/origin89hq/km43/issues/36
