//! The DS18B20 temperature probe, over the [`OneWire`] line seam.
//!
//! One conversion on every probe at once ([`convert_all`]), a wait of
//! [`CONVERSION`] that is the caller's, then one scratchpad read per probe
//! ([`Probe::read`]), which writes what it found into the store.
//!
//! A probe keeps its last conversion in its scratchpad, CRC and all, so a
//! read with no conversion behind it would publish an old temperature as a
//! new one. A read therefore takes the [`Conversion`] that `convert_all`
//! returns only once the line has shown a probe converting, is refused
//! before the conversion can have finished or after [`READ_WINDOW`], and
//! writes at the tick the conversion finished, however late or often it is
//! read. What that does not prove: the busy slot is one line for every
//! probe, so it shows that some probe converted, not that each did, and a
//! token says nothing about which line it came from. A probe that missed
//! the command while another converted returns its previous scratchpad; the
//! caller binds each token to its own line and gives each probe's signal a
//! maximum unchanged run, which is what catches that (#196).
//!
//! What a read writes, and what it never does (F-053):
//!
//! - A scratchpad whose CRC fails writes nothing: the slot keeps its last
//!   write and ages out through the store's maximum age. After
//!   [`CRC_FAILURES`] in a row the read returns [`ProbeRead::Failing`], a
//!   condition naming the probe, on every read until one succeeds; turning
//!   it into a concern is the caller's.
//! - A probe that does not answer, unplugged or never fitted, writes
//!   `absent` and no value, never 0 °C.
//! - The power-on value, 85 °C, is a probe that has not converted since it
//!   was powered, and writes `initialising`. A true 85 °C reads the same and
//!   is refused with it, by requirement rather than by any assumption about
//!   the temperatures on a site.
//! - A temperature outside the datasheet's −55 to +125 °C writes
//!   `out_of_range`, and a scratchpad whose fixed bits are wrong, which a
//!   line held low produces with a valid CRC, writes `sensor_fault`.
//!
//! Anything else is `measured`, in tenths of a degree, KM43's scale for
//! [`Kind::Temperature`].
//!
//! Taken from the self-test (`origin89hq/origin89`,
//! `firmwares/o89-selftest/src/onewire.rs` and `checks/onewire.rs`):
//! the commands, the conversion wait, the power-on value and the range.
//! Values in the tests are the datasheet's (Maxim DS18B20, 19-7487 Rev 6,
//! table 1) or built by hand, and none is a bench capture.
//!
//! cites: F-053

use km43::{Id, Provenance, QualityError, SignalDomain, Validity};
use o89_core::{Millis, Observation, SignalError, Signals, Tick};

use crate::dialect::{Kind, Plausible};
use crate::onewire::{self, Rom};
use crate::port::{OneWire, Presence};

/// How long after a conversion finishes its reads are accepted.
///
/// A named policy, not a measured one: eight probes read in well under
/// 100 ms of slots, and the rest is the executor's scheduling, which the
/// bench has not qualified. Past it, a read is refused rather than stamped
/// with a conversion that may no longer describe the probe.
pub const READ_WINDOW: Millis = Millis::from_millis(1_000);

/// The DS18B20's family code, the first byte of its ROM.
pub const FAMILY: u8 = 0x28;

/// The longest a 12-bit conversion takes, from the datasheet's `tCONV`. The
/// caller waits at least this long between [`convert_all`] and the reads;
/// nothing here waits, and no host test establishes the wait on the board.
pub const CONVERSION: Millis = Millis::from_millis(750);

/// CRC failures in a row before a read returns [`ProbeRead::Failing`].
///
/// A named software policy, not a bench-proven diagnosis: a single failure
/// says nothing about its cause, and three in a row at the poll period is
/// treated as a probe that is not reading. The bench saw eleven from one
/// probe hot-swapped on 2026-09-16; that session did not measure where a
/// threshold belongs.
pub const CRC_FAILURES: u8 = 3;

/// What a probe publishes as.
pub const KIND: Kind = Kind::Temperature;

/// The datasheet's measuring range, −55 to +125 °C, in tenths.
pub const RANGE: Plausible = Plausible {
    low: -550,
    high: 1250,
};

/// What a probe's reading is: the part reads the temperature at its tip.
const PROVENANCE: Provenance = Provenance::Measured;

// A reading is the kind's to carry, in tenths.
const _: () = assert!(KIND.accepts(SignalDomain::Live).contains(PROVENANCE));
const _: () = assert!(KIND.scale() == -1);

/// The scratchpad's temperature register at power-on: 85 °C in sixteenths.
const POWER_ON: i16 = 0x0550;

const MATCH_ROM: u8 = 0x55;
const SKIP_ROM: u8 = 0xCC;
const CONVERT_T: u8 = 0x44;
const READ_SCRATCHPAD: u8 = 0xBE;

/// The configuration register's fixed bits: bit 7 is zero and bits 0 to 4
/// are one, whatever the resolution.
const CONFIG_FIXED_MASK: u8 = 0x9F;
const CONFIG_FIXED: u8 = 0x1F;

/// A conversion the line showed under way, and when its reads are accepted.
///
/// Built only by [`convert_all`].
///
/// ```compile_fail
/// use o89_core::Tick;
/// use o89_drivers::ds18b20::Conversion;
///
/// let forged = Conversion { ready: Tick::ZERO, until: Tick::ZERO };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a conversion nobody reads is a line polled for nothing"]
pub struct Conversion {
    ready: Tick,
    until: Tick,
}

impl Conversion {
    /// When the conversion has finished: the first tick a read is accepted,
    /// and the tick every read of it is written at.
    #[must_use]
    pub const fn ready(&self) -> Tick {
        self.ready
    }

    /// The last tick a read of it is accepted.
    #[must_use]
    pub const fn until(&self) -> Tick {
        self.until
    }
}

/// Why no conversion was started, or none can be vouched for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed conversion is probes whose readings will not refresh"]
pub enum ConvertError<E> {
    /// The line reported a fault.
    Line(E),
    /// Nothing answered the reset, and nothing was sent. Every probe on the
    /// line is unplugged; [`Probe::absent`] records that.
    Absent,
    /// The line read high straight after the command: no probe held it low
    /// to say it was converting. A probe powered from the line itself cannot
    /// say so either, and is refused the same way; board A's probes are
    /// powered from `OW_VCC`.
    NotConverting,
    /// The tick is too close to its end to bound the reads.
    Tick,
}

/// Start a conversion on every probe on the line at once, at `now`.
///
/// After the command, one read slot: a probe powered from `OW_VCC` holds it
/// low while it converts, so a slot read high is refused as
/// [`ConvertError::NotConverting`].
pub async fn convert_all<W: OneWire>(
    line: &mut W,
    now: Tick,
) -> Result<Conversion, ConvertError<W::Error>> {
    let ready = now.after(CONVERSION).ok_or(ConvertError::Tick)?;
    let until = ready.after(READ_WINDOW).ok_or(ConvertError::Tick)?;
    match line.reset().await.map_err(ConvertError::Line)? {
        Presence::Absent => return Err(ConvertError::Absent),
        Presence::Present => {}
    }
    onewire::write_byte(line, SKIP_ROM)
        .await
        .map_err(ConvertError::Line)?;
    onewire::write_byte(line, CONVERT_T)
        .await
        .map_err(ConvertError::Line)?;
    if line.read_bit().await.map_err(ConvertError::Line)? {
        return Err(ConvertError::NotConverting);
    }
    Ok(Conversion { ready, until })
}

/// What nine scratchpad bytes say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a decoded scratchpad is a reading or the reason there is none"]
pub enum Pad {
    /// A temperature inside the range, in tenths of a degree.
    Tenths(i32),
    /// Every bit read one: nothing drove the line.
    NoAnswer,
    /// The CRC over the nine bytes fails.
    Crc,
    /// The CRC holds and the configuration register's fixed bits do not.
    Malformed,
    /// The power-on value: no conversion since the probe was powered.
    PowerOn,
    /// A temperature outside [`RANGE`].
    OutOfRange,
}

impl Pad {
    /// Decode `pad`, bytes in the order the probe sends them.
    pub fn decode(pad: &[u8; 9]) -> Self {
        if pad.iter().all(|byte| *byte == 0xFF) {
            return Self::NoAnswer;
        }
        if onewire::crc8(pad) != 0 {
            return Self::Crc;
        }
        let [low, high, _, _, config, ..] = *pad;
        if config & CONFIG_FIXED_MASK != CONFIG_FIXED {
            return Self::Malformed;
        }
        let raw = i16::from_le_bytes([low, high]);
        if raw == POWER_ON {
            return Self::PowerOn;
        }
        // Below twelve bits the lowest bits are undefined: nine bits leaves
        // three of them, and each step of resolution one fewer.
        let defined: i16 = match (config >> 5) & 0b11 {
            0b00 => !0b111,
            0b01 => !0b11,
            0b10 => !0b1,
            _ => !0,
        };
        let raw = raw & defined;
        let tenths = sixteenths_to_tenths(raw);
        if RANGE.holds(tenths) {
            Self::Tenths(tenths)
        } else {
            Self::OutOfRange
        }
    }

    /// What it writes into the store: nothing for a CRC failure, otherwise a
    /// value or the reason there is none.
    pub fn observation(self) -> Result<Option<Observation>, QualityError> {
        let missing = |validity| Observation::missing(validity).map(Some);
        match self {
            Self::Tenths(tenths) => Observation::value(tenths, PROVENANCE).map(Some),
            Self::Crc => Ok(None),
            Self::NoAnswer => missing(Validity::Absent),
            Self::Malformed => missing(Validity::SensorFault),
            Self::PowerOn => missing(Validity::Initialising),
            Self::OutOfRange => missing(Validity::OutOfRange),
        }
    }
}

/// Sixteenths of a degree in tenths, rounding half away from zero.
fn sixteenths_to_tenths(raw: i16) -> i32 {
    let scaled = i32::from(raw).saturating_mul(10);
    let nudge = if scaled < 0 { -8 } else { 8 };
    scaled.saturating_add(nudge) / 16
}

/// A DS18B20 on the line and the signal it publishes as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Probe {
    rom: Rom,
    signal: Id,
    crc_failures: u8,
}

/// Why a probe read stopped before writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed probe read is a temperature that was not refreshed"]
pub enum ProbeError<E> {
    /// The line reported a fault; nothing was written.
    Line(E),
    /// The read came before the conversion had finished, or before it was
    /// started; nothing was sent or written.
    Early,
    /// The read came after the conversion's [`READ_WINDOW`]; nothing was
    /// sent or written.
    Expired,
    /// The store refused the write.
    Store(SignalError),
    /// KM43 refused the observation: a defect surfaced rather than hidden.
    Quality(QualityError),
}

/// What one read of one probe came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a probe read is a reading written or a probe failing"]
pub enum ProbeRead {
    /// This was written into the store.
    Wrote(Observation),
    /// The scratchpad failed its CRC and nothing was written; fewer than
    /// [`CRC_FAILURES`] in a row so far.
    Crc {
        /// CRC failures in a row, this one included.
        consecutive: u8,
    },
    /// The scratchpad failed its CRC, [`CRC_FAILURES`] or more times in a
    /// row, and nothing was written.
    Failing(RepeatedCrc),
}

/// A probe whose scratchpad keeps failing its CRC: the condition a concern
/// is raised from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failing probe is a concern nobody raised"]
pub struct RepeatedCrc {
    /// The probe.
    pub rom: Rom,
    /// The signal it publishes as, which has had nothing written since the
    /// failures began.
    pub signal: Id,
    /// CRC failures in a row, saturating at 255.
    pub consecutive: u8,
}

impl Probe {
    /// The DS18B20 `rom`, publishing as `signal`, or `None` when `rom` is
    /// another family's.
    #[must_use]
    pub fn new(rom: Rom, signal: Id) -> Option<Self> {
        (rom.family() == FAMILY).then_some(Self {
            rom,
            signal,
            crc_failures: 0,
        })
    }

    /// Its ROM code.
    #[must_use]
    pub const fn rom(&self) -> Rom {
        self.rom
    }

    /// The signal it publishes as.
    #[must_use]
    pub const fn signal(&self) -> Id {
        self.signal
    }

    /// CRC failures in a row since its last good read.
    #[must_use]
    pub const fn crc_failures(&self) -> u8 {
        self.crc_failures
    }

    /// Read `conversion` at `now` and write it into `store` at the tick the
    /// conversion finished.
    ///
    /// Refused, with nothing sent or written, before the conversion is
    /// ready or after its window. Nothing answering the reset or the match
    /// writes `absent`. A CRC failure writes nothing and counts toward
    /// [`ProbeRead::Failing`]; any other outcome ends the run. A line fault
    /// writes nothing and leaves the count as it was. Reading the same
    /// conversion again writes at the same tick, so it never makes a
    /// reading younger than it is.
    pub async fn read<W: OneWire, const N: usize>(
        &mut self,
        line: &mut W,
        conversion: &Conversion,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<ProbeRead, ProbeError<W::Error>> {
        if now < conversion.ready {
            return Err(ProbeError::Early);
        }
        if now > conversion.until {
            return Err(ProbeError::Expired);
        }
        let pad = self.scratchpad(line).await.map_err(ProbeError::Line)?;
        let decoded = pad.map_or(Pad::NoAnswer, |bytes| Pad::decode(&bytes));
        let Some(seen) = decoded.observation().map_err(ProbeError::Quality)? else {
            self.crc_failures = self.crc_failures.saturating_add(1);
            if self.crc_failures < CRC_FAILURES {
                return Ok(ProbeRead::Crc {
                    consecutive: self.crc_failures,
                });
            }
            return Ok(ProbeRead::Failing(RepeatedCrc {
                rom: self.rom,
                signal: self.signal,
                consecutive: self.crc_failures,
            }));
        };
        self.crc_failures = 0;
        store
            .write(self.signal, conversion.ready, seen)
            .map_err(ProbeError::Store)?;
        Ok(ProbeRead::Wrote(seen))
    }

    /// Record at `now` that nothing answered on the probe's line, after
    /// [`ConvertError::Absent`]: `absent` and no value, never 0 °C.
    pub fn absent<const N: usize>(
        &mut self,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Observation, SignalError> {
        let seen = Observation::missing(Validity::Absent).map_err(SignalError::Quality)?;
        self.crc_failures = 0;
        store.write(self.signal, now, seen)?;
        Ok(seen)
    }

    /// The nine scratchpad bytes, or `None` when nothing answered the reset.
    async fn scratchpad<W: OneWire>(&self, line: &mut W) -> Result<Option<[u8; 9]>, W::Error> {
        match line.reset().await? {
            Presence::Absent => return Ok(None),
            Presence::Present => {}
        }
        onewire::write_byte(line, MATCH_ROM).await?;
        for byte in self.rom.bytes() {
            onewire::write_byte(line, byte).await?;
        }
        onewire::write_byte(line, READ_SCRATCHPAD).await?;
        let mut pad = [0u8; 9];
        for byte in &mut pad {
            *byte = onewire::read_byte(line).await?;
        }
        Ok(Some(pad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onewire::tests::{Device, HeldLow, Line, device, rom};
    use embassy_futures::block_on;
    use km43::Sample;
    use o89_core::Limits;

    /// A 12-bit scratchpad around `raw`, with the datasheet's power-on
    /// alarm and reserved bytes and its CRC. Built by hand.
    fn pad(raw: u16) -> [u8; 9] {
        let [low, high] = raw.to_le_bytes();
        let mut pad = [low, high, 0x4B, 0x46, 0x7F, 0xFF, 0x0C, 0x10, 0];
        pad[8] = onewire::crc8(&pad[..8]);
        pad
    }

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    /// When a conversion started at zero is ready.
    const READY: u64 = 750;

    fn store() -> Signals<2> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
        store.register(id(40), limits).unwrap();
        store.register(id(41), limits).unwrap();
        store
    }

    fn probe_rom() -> [u8; 8] {
        rom(FAMILY, [0x5C, 0x1A, 0x03, 0x00, 0x00, 0x80])
    }

    fn probe() -> Probe {
        Probe::new(Rom::new(probe_rom()).unwrap(), id(40)).unwrap()
    }

    fn on_line(pad: [u8; 9]) -> [Device; 1] {
        [Device {
            pad,
            ..device(probe_rom())
        }]
    }

    /// A conversion started at `start` on a line whose probe converts.
    fn converted(start: u64) -> Conversion {
        let devices = on_line(pad(0));
        block_on(convert_all(&mut Line::new(&devices), at(start))).unwrap()
    }

    /// One read of `pad` through a conversion started at `start`, at its
    /// ready tick.
    fn read_once(
        probe: &mut Probe,
        pad: [u8; 9],
        start: u64,
        store: &mut Signals<2>,
    ) -> Result<ProbeRead, ProbeError<HeldLow>> {
        let devices = on_line(pad);
        let conversion = converted(start);
        block_on(probe.read(
            &mut Line::new(&devices),
            &conversion,
            conversion.ready(),
            store,
        ))
    }

    fn sample(store: &Signals<2>, when: u64) -> Sample {
        store.sample(id(40), at(when)).unwrap()
    }

    #[test]
    fn f_053_a_valid_scratchpad_decodes_every_datasheet_row_including_negatives() {
        // DS18B20 datasheet, table 1: the register and the temperature.
        for (raw, tenths) in [
            (0x07D0, 1250),
            (0x0191, 251),
            (0x00A2, 101),
            (0x0008, 5),
            (0x0000, 0),
            (0xFFF8, -5),
            (0xFF5E, -101),
            (0xFE6F, -251),
            (0xFC90, -550),
        ] {
            assert_eq!(Pad::decode(&pad(raw)), Pad::Tenths(tenths), "{raw:#06x}");
        }
    }

    #[test]
    fn f_053_a_valid_negative_scratchpad_is_written_as_measured() {
        let mut store = store();
        let mut probe = probe();
        let read = read_once(&mut probe, pad(0xFF5E), 0, &mut store).unwrap();
        assert!(matches!(read, ProbeRead::Wrote(_)));
        let seen = sample(&store, READY);
        assert_eq!(
            (seen.value(), seen.q.validity_of(), seen.q.provenance_of()),
            (Some(-101), Validity::Ok, Provenance::Measured)
        );
    }

    #[test]
    fn f_053_a_crc_failure_writes_no_value_and_keeps_the_last_one() {
        let mut store = store();
        let mut probe = probe();
        let _ = read_once(&mut probe, pad(0x0191), 0, &mut store).unwrap();

        let mut bad = pad(0x0191);
        bad[1] ^= 0x04;
        assert_eq!(
            read_once(&mut probe, bad, 10_000, &mut store),
            Ok(ProbeRead::Crc { consecutive: 1 })
        );
        // The slot still holds the good reading, from its own write.
        let seen = sample(&store, 10_750);
        assert_eq!(
            (seen.value(), seen.q.validity_of(), seen.q.provenance_of()),
            (Some(251), Validity::Ok, Provenance::Measured)
        );
        // The failed read refreshed nothing: the reading ages out a minute
        // after its own write at 750 ms, not after the failure.
        assert_eq!(sample(&store, 60_750).q.validity_of(), Validity::Ok);
        let seen = sample(&store, 60_751);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (Some(251), Validity::Stale)
        );
    }

    #[test]
    fn f_053_every_single_bit_flip_of_a_scratchpad_is_no_value() {
        let good = pad(0x0191);
        for bit in 0..72 {
            let mut flipped = good;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(Pad::decode(&flipped), Pad::Crc, "bit {bit}");
            assert_eq!(Pad::decode(&flipped).observation(), Ok(None), "bit {bit}");
        }
    }

    #[test]
    fn f_053_eleven_crc_failures_in_a_row_raise_the_condition_and_write_nothing() {
        let mut bad = pad(0x0191);
        bad[8] ^= 0xFF;
        let mut store = store();
        let mut probe = probe();
        let mut raised = 0u8;
        for n in 1..=11u8 {
            let start = u64::from(n) * 10_000;
            let read = read_once(&mut probe, bad, start, &mut store).unwrap();
            if n < CRC_FAILURES {
                assert_eq!(read, ProbeRead::Crc { consecutive: n });
            } else {
                assert_eq!(
                    read,
                    ProbeRead::Failing(RepeatedCrc {
                        rom: probe.rom(),
                        signal: id(40),
                        consecutive: n
                    })
                );
                raised = raised.checked_add(1).unwrap();
            }
        }
        assert_eq!(raised, 9);
        // Nothing was ever written: the slot has never had a value.
        let seen = sample(&store, 120_000);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::Initialising)
        );
    }

    #[test]
    fn f_053_a_good_read_ends_the_run_of_crc_failures() {
        let mut bad = pad(0x0191);
        bad[0] ^= 1;
        let mut store = store();
        let mut probe = probe();
        for _ in 0..CRC_FAILURES {
            let _ = read_once(&mut probe, bad, 0, &mut store);
        }
        assert_eq!(probe.crc_failures(), CRC_FAILURES);
        let read = read_once(&mut probe, pad(0x0191), 0, &mut store);
        assert!(matches!(read, Ok(ProbeRead::Wrote(_))));
        assert_eq!(probe.crc_failures(), 0);
        assert_eq!(
            read_once(&mut probe, bad, 0, &mut store),
            Ok(ProbeRead::Crc { consecutive: 1 })
        );
    }

    #[test]
    fn f_053_an_unplugged_probe_is_absent_never_zero() {
        // Nothing on the line at all: no conversion, and the caller records
        // the probe absent.
        let mut store = store();
        let mut probe = probe();
        assert_eq!(
            block_on(convert_all(&mut Line::new(&[]), at(0))),
            Err(ConvertError::Absent)
        );
        let seen = probe.absent(at(0), &mut store).unwrap();
        assert_eq!(seen.reading(), None);
        let seen = sample(&store, 0);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::Absent)
        );

        // Another probe converts, and nothing answers this one's match.
        let other = [Device {
            pad: pad(0x0191),
            ..device(rom(FAMILY, [9, 9, 9, 9, 9, 9]))
        }];
        let mut line = Line::new(&other);
        let conversion = block_on(convert_all(&mut line, at(10_000))).unwrap();
        let _ = block_on(probe.read(&mut line, &conversion, at(10_750), &mut store)).unwrap();
        let seen = sample(&store, 10_750);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::Absent)
        );

        // Unplugged between the conversion and the read.
        let gone = [Device {
            leaves_after: Some(1),
            ..on_line(pad(0x0191))[0]
        }];
        let mut line = Line::new(&gone);
        let conversion = block_on(convert_all(&mut line, at(20_000))).unwrap();
        let _ = block_on(probe.read(&mut line, &conversion, at(20_750), &mut store)).unwrap();
        assert_eq!(sample(&store, 20_750).q.validity_of(), Validity::Absent);
    }

    #[test]
    fn a_conversion_is_vouched_for_only_when_the_line_shows_a_probe_converting() {
        // Every probe ignored the command: the busy slot reads high.
        let deaf = [Device {
            ignores_convert: true,
            ..on_line(pad(0x0191))[0]
        }];
        let mut line = Line::new(&deaf);
        assert_eq!(
            block_on(convert_all(&mut line, at(0))),
            Err(ConvertError::NotConverting)
        );
        assert_eq!(line.converts, 1);
        // A line fault is its own error, and no token either way.
        let devices = on_line(pad(0x0191));
        let mut line = Line::new(&devices);
        line.fault = true;
        assert_eq!(
            block_on(convert_all(&mut line, at(0))),
            Err(ConvertError::Line(HeldLow))
        );
        // A tick too close to its end cannot bound the reads.
        let mut line = Line::new(&devices);
        assert_eq!(
            block_on(convert_all(&mut line, Tick::from_millis(u64::MAX - 1_000))),
            Err(ConvertError::Tick)
        );
        assert_eq!(line.resets, 0);
        // A probe converting: ready after the datasheet's wait, open for
        // the read window.
        let conversion = converted(5_000);
        assert_eq!(
            (conversion.ready(), conversion.until()),
            (at(5_750), at(6_750))
        );
    }

    #[test]
    fn a_read_is_refused_before_its_conversion_is_ready_and_after_its_window() {
        let devices = on_line(pad(0x0191));
        let conversion = converted(0);
        let mut store = store();
        let mut probe = probe();
        let mut read = |when: u64, store: &mut Signals<2>| {
            block_on(probe.read(&mut Line::new(&devices), &conversion, at(when), store))
        };
        assert_eq!(read(749, &mut store), Err(ProbeError::Early));
        assert_eq!(read(1_751, &mut store), Err(ProbeError::Expired));
        assert_eq!(sample(&store, 749).q.validity_of(), Validity::Initialising);
        // Both ends of the window are inside.
        assert!(matches!(read(750, &mut store), Ok(ProbeRead::Wrote(_))));
        assert!(matches!(read(1_750, &mut store), Ok(ProbeRead::Wrote(_))));
    }

    #[test]
    fn a_read_on_a_tick_before_the_conversion_started_is_refused() {
        let devices = on_line(pad(0x0191));
        let conversion = converted(10_000);
        let mut store = store();
        let mut probe = probe();
        assert_eq!(
            block_on(probe.read(&mut Line::new(&devices), &conversion, at(9_000), &mut store)),
            Err(ProbeError::Early)
        );
        assert_eq!(
            sample(&store, 9_000).q.validity_of(),
            Validity::Initialising
        );
    }

    #[test]
    fn reading_one_conversion_again_never_makes_the_reading_younger() {
        let devices = on_line(pad(0x0191));
        let conversion = converted(0);
        let mut store = store();
        let mut probe = probe();
        for when in [750, 1_200, 1_750] {
            let read =
                block_on(probe.read(&mut Line::new(&devices), &conversion, at(when), &mut store));
            assert!(matches!(read, Ok(ProbeRead::Wrote(_))), "{when}");
        }
        // Every write was at 750 ms: stale a minute after that, not after
        // the last read.
        assert_eq!(sample(&store, 60_750).q.validity_of(), Validity::Ok);
        assert_eq!(sample(&store, 60_751).q.validity_of(), Validity::Stale);
    }

    #[test]
    fn a_line_held_low_is_a_sensor_fault_not_zero_degrees() {
        // All zeros: the CRC holds, the configuration's fixed bits do not.
        assert_eq!(Pad::decode(&[0; 9]), Pad::Malformed);
        assert_eq!(
            Pad::Malformed
                .observation()
                .unwrap()
                .map(Observation::reading),
            Some(None)
        );
        let conversion = converted(0);
        let mut line = Line::new(&[]);
        line.fault = true;
        let mut store = store();
        let mut probe = probe();
        assert_eq!(
            block_on(probe.read(&mut line, &conversion, at(READY), &mut store)),
            Err(ProbeError::Line(HeldLow))
        );
        assert_eq!(
            sample(&store, READY).q.validity_of(),
            Validity::Initialising
        );
    }

    #[test]
    fn the_power_on_value_is_no_reading() {
        assert_eq!(Pad::decode(&pad(0x0550)), Pad::PowerOn);
        let mut store = store();
        let mut probe = probe();
        let _ = read_once(&mut probe, pad(0x0550), 0, &mut store).unwrap();
        let seen = sample(&store, READY);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::Initialising)
        );
        // One sixteenth either side is a reading.
        assert_eq!(Pad::decode(&pad(0x0551)), Pad::Tenths(851));
        assert_eq!(Pad::decode(&pad(0x054F)), Pad::Tenths(849));
    }

    #[test]
    fn a_temperature_past_the_datasheet_range_is_out_of_range() {
        assert_eq!(Pad::decode(&pad(0x07D1)), Pad::OutOfRange);
        assert_eq!(Pad::decode(&pad(0xFC8F)), Pad::OutOfRange);
        assert_eq!(Pad::decode(&pad(0x7FFF)), Pad::OutOfRange);
        assert_eq!(Pad::decode(&pad(0x8000)), Pad::OutOfRange);
        assert_eq!(
            Pad::OutOfRange
                .observation()
                .unwrap()
                .map(|seen| seen.quality().validity_of()),
            Some(Validity::OutOfRange)
        );
    }

    #[test]
    fn a_lower_resolution_drops_its_undefined_bits() {
        // 9 bits, configuration 0x1F: the three lowest bits are undefined.
        let mut nine = pad(0x0197);
        nine[4] = 0x1F;
        nine[8] = onewire::crc8(&nine[..8]);
        assert_eq!(Pad::decode(&nine), Pad::Tenths(250));
        // 11 bits, configuration 0x5F: only the lowest.
        let mut eleven = pad(0x0193);
        eleven[4] = 0x5F;
        eleven[8] = onewire::crc8(&eleven[..8]);
        assert_eq!(Pad::decode(&eleven), Pad::Tenths(251));
    }

    #[test]
    fn a_probe_is_only_a_ds18b20() {
        let ds18s20 = Rom::new(rom(0x10, [1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(Probe::new(ds18s20, id(40)), None);
        let probe = probe();
        assert_eq!((probe.rom().bytes(), probe.signal()), (probe_rom(), id(40)));
    }

    #[test]
    fn a_write_to_a_signal_the_store_does_not_hold_is_refused() {
        let devices = on_line(pad(0x0191));
        let conversion = converted(0);
        let mut store = Signals::<1>::new();
        let mut probe = probe();
        assert_eq!(
            block_on(probe.read(&mut Line::new(&devices), &conversion, at(READY), &mut store)),
            Err(ProbeError::Store(SignalError::Unknown(id(40))))
        );
        assert_eq!(
            probe.absent(at(0), &mut store),
            Err(SignalError::Unknown(id(40)))
        );
    }
}
