//! The PZEM-014 and PZEM-016 AC meters, the generator's proof of running:
//! 9600 8N1, ten input registers from `0x0000` read with function `0x04`.
//!
//! Source: Peacefair, *PZEM-014/016 AC communication module*, §1 for the
//! ranges and §2.3 for the registers. No PZEM-016 has been read on the
//! bench yet; this is the manual's table, rewritten to the port seam.
//!
//! KM43 allocates no dialect for this meter (origin89hq/km43#154), so its
//! cells form a checked [`BLOCK`] and not a [`RegisterMap`], and it is not
//! in [`REGISTER_MAPS`]: the build reads it, and does not yet say it
//! supports it. Power factor has no KM43 kind and the alarm no alarm kind;
//! both come back as [`Words`] from the same reply and are never stored.
//! The meter is powered from the voltage it measures, so with no AC it does
//! not answer at all, and the manual defines no *not available* word: a
//! stopped generator leaves the signals without a value and ages them out.
//!
//! [`RegisterMap`]: crate::dialect::RegisterMap
//! [`REGISTER_MAPS`]: crate::dialect::REGISTER_MAPS
//!
//! cites: F-050, F-052

use km43::{Id, Provenance, SignalDomain, Unit};
use o89_core::{Signals, Tick};

use crate::PollError;
use crate::dialect::{Block, Cell, Kind, Plausible, Sign, Span};
use crate::modbus::{self, Address, Function, RECEIVE_BYTES, Registers, Timing};
use crate::port::Rs485;
use crate::vendor::{self, Alarm, ConditionError, Report, VendorError};

/// The measurement registers, §2.3, with the PZEM-016's ranges from §1.
const CELLS: [Cell; 5] = [
    // 0x0000, 0.1 V. §1.1.1 measures 80 to 260 V.
    Cell {
        register: 0x0000,
        kind: Kind::AcVoltage,
        domain: SignalDomain::Live,
        span: Span::One,
        sign: Sign::Unsigned,
        unit: Unit::Volt,
        decade: -1,
        absent: None,
        plausible: Some(Plausible {
            low: 800,
            high: 2600,
        }),
        provenance: Provenance::Measured,
    },
    // 0x0001 and 0x0002, low word first, 0.001 A. §1.2.1 measures 0 to
    // 100 A on the PZEM-016.
    Cell {
        register: 0x0001,
        kind: Kind::AcCurrent,
        domain: SignalDomain::Live,
        span: Span::TwoLowFirst,
        sign: Sign::Unsigned,
        unit: Unit::Ampere,
        decade: -3,
        absent: None,
        plausible: Some(Plausible {
            low: 0,
            high: 100_000,
        }),
        provenance: Provenance::Measured,
    },
    // 0x0003 and 0x0004, low word first, 0.1 W. §1.3.1 measures 0 to 23 kW
    // on the PZEM-016.
    Cell {
        register: 0x0003,
        kind: Kind::AcPower,
        domain: SignalDomain::Live,
        span: Span::TwoLowFirst,
        sign: Sign::Unsigned,
        unit: Unit::Watt,
        decade: -1,
        absent: None,
        plausible: Some(Plausible {
            low: 0,
            high: 230_000,
        }),
        provenance: Provenance::Measured,
    },
    // 0x0005 and 0x0006, low word first, 1 Wh, a count since the last
    // reset (§1.6.5, §2.5). §1.6.1 counts 0 to 9999.99 kWh.
    Cell {
        register: 0x0005,
        kind: Kind::AcEnergy,
        domain: SignalDomain::SinceReset,
        span: Span::TwoLowFirst,
        sign: Sign::Unsigned,
        unit: Unit::WattHour,
        decade: 0,
        absent: None,
        plausible: Some(Plausible {
            low: 0,
            high: 9_999_990,
        }),
        provenance: Provenance::Counted,
    },
    // 0x0007, 0.1 Hz. §1.5.1 measures 45 to 65 Hz.
    Cell {
        register: 0x0007,
        kind: Kind::AcFrequency,
        domain: SignalDomain::Live,
        span: Span::One,
        sign: Sign::Unsigned,
        unit: Unit::Hertz,
        decade: -1,
        absent: None,
        plausible: Some(Plausible {
            low: 4500,
            high: 6500,
        }),
        provenance: Provenance::Measured,
    },
];

/// The whole measurement table in one read, §2.3's own example request.
pub const BLOCK: Block = crate::block!(Function::ReadInput, 0x0000, 10, &CELLS);

/// The registers §2.3 defines that no KM43 kind carries, from the same
/// reply as the cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Words {
    /// `0x0008`, 0.01, which §1.4.1 bounds to 0.00 to 1.00.
    pub power_factor_hundredths: u16,
    /// `0x0009`: the active power is above the threshold in holding
    /// register `0x0001`.
    pub over_power: Alarm,
}

/// The largest power factor §1.4.1 measures, in hundredths.
const POWER_FACTOR_MAX: u16 = 100;

impl Words {
    /// The words in `registers`, which must be [`BLOCK`]'s read.
    ///
    /// A power factor above 1.00, or an alarm word other than `0x0000` or
    /// `0xFFFF`, is refused: the manual defines neither.
    pub fn from_registers(registers: &Registers<'_>) -> Result<Self, ConditionError> {
        let power_factor = vendor::word(registers, 0x0008)?;
        if power_factor > POWER_FACTOR_MAX {
            return Err(ConditionError::Undefined {
                register: 0x0008,
                raw: power_factor,
            });
        }
        Ok(Self {
            power_factor_hundredths: power_factor,
            over_power: Alarm::at(registers, 0x0009)?,
        })
    }
}

/// The number of cells, and so of signals, a meter publishes.
const SIGNALS: usize = BLOCK.cells().len();

/// A PZEM-014 or PZEM-016 on an RS-485 port at 9600 8N1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Meter {
    address: Address,
    first: Id,
}

impl Meter {
    /// The meter at `address`, whose cells publish as consecutive signals
    /// from `first` in [`BLOCK`]'s order: voltage, current, power, energy,
    /// frequency.
    ///
    /// `None` when the signals would run past `0xFFFF`.
    #[must_use]
    pub fn new(address: Address, first: Id) -> Option<Self> {
        let last = u16::try_from(SIGNALS.checked_sub(1)?).ok()?;
        first.get().checked_add(last)?;
        Some(Self { address, first })
    }

    /// The meter's address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The signal the `index`th cell publishes as, or `None` past the last.
    #[must_use]
    pub fn signal(&self, index: usize) -> Option<Id> {
        if index >= SIGNALS {
            return None;
        }
        let offset = u16::try_from(index).ok()?;
        Id::new(self.first.get().checked_add(offset)?).ok()
    }

    /// Read the meter once and write its cells into `store` at `now`.
    ///
    /// One exchange, bounded by `timing`. A reply holding a word the manual
    /// does not define writes nothing.
    pub async fn poll<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Report<Words>, VendorError<P::Error>> {
        let mut buf = [0u8; RECEIVE_BYTES];
        let registers = modbus::read(port, BLOCK.read(self.address), timing, &mut buf)
            .await
            .map_err(|error| VendorError::Poll(PollError::Modbus { block: 0, error }))?;
        let conditions = Words::from_registers(&registers).map_err(VendorError::Condition)?;
        let polled = vendor::publish(&BLOCK, &registers, |cell| self.signal(cell), now, store)
            .map_err(VendorError::Poll)?;
        Ok(Report { polled, conditions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modbus::tests::{Scripted, TIMING, register_reply};
    use crate::modbus::{ModbusError, ReplyError};
    use embassy_futures::block_on;
    use km43::Validity;
    use o89_core::{Limits, Millis, ProvenanceSet};

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn meter() -> Meter {
        Meter::new(Address::new(1).unwrap(), id(50)).unwrap()
    }

    fn store() -> Signals<5> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        for n in 50..55 {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    /// The manual's §2.3 example reply, with its CRC computed, since the
    /// manual prints `0xHH 0xLL` in its place: 220.0 V, 1.000 A, 220.0 W,
    /// 0 Wh, 50.0 Hz, power factor 1.00, no alarm. From the vendor's
    /// document, not a bench capture.
    const MANUAL: [u16; 10] = [
        0x0898, 0x03E8, 0x0000, 0x0898, 0x0000, 0x0000, 0x0000, 0x01F4, 0x0064, 0x0000,
    ];

    fn poll(words: &[u16], store: &mut Signals<5>) -> Result<Report<Words>, VendorError<u8>> {
        let echo = BLOCK.read(Address::new(1).unwrap()).encode();
        let (reply, len) = register_reply(1, 0x04, words);
        let bursts: [&[u8]; 2] = [&echo, &reply[..len]];
        let mut port = Scripted::new(&bursts);
        let report = block_on(meter().poll(&mut port, TIMING, Tick::ZERO, store));
        assert_eq!(port.sent, echo);
        report
    }

    fn published(store: &Signals<5>) -> [(Option<i32>, Provenance); 5] {
        [50, 51, 52, 53, 54].map(|n| {
            let seen = store.sample(id(n), Tick::ZERO).unwrap();
            (seen.value(), seen.q.provenance_of())
        })
    }

    #[test]
    fn the_request_is_the_manual_s_example() {
        // §2.3: 01 04 00 00 00 0A and its CRC, low byte first. 0x0D70 is
        // CRC-16/MODBUS over the six bytes.
        assert_eq!(
            BLOCK.read(Address::new(1).unwrap()).encode(),
            [0x01, 0x04, 0x00, 0x00, 0x00, 0x0A, 0x70, 0x0D]
        );
    }

    #[test]
    fn f_052_the_manual_s_example_publishes_each_cell_with_its_declared_provenance() {
        let mut store = store();
        let report = poll(&MANUAL, &mut store).unwrap();
        assert_eq!(report.polled.written, 5);
        assert_eq!(
            report.conditions,
            Words {
                power_factor_hundredths: 100,
                over_power: Alarm::Clear,
            }
        );
        assert_eq!(
            published(&store),
            [
                (Some(2200), Provenance::Measured),
                (Some(1000), Provenance::Measured),
                (Some(2200), Provenance::Measured),
                (Some(0), Provenance::Counted),
                (Some(5000), Provenance::Measured),
            ]
        );
    }

    #[test]
    fn the_thirty_two_bit_values_are_read_low_word_first() {
        let mut store = store();
        // Built by hand: 99.999 A, 22 999.9 W and 9 999 990 Wh, each with
        // a non-zero high word, and the alarm raised.
        let mut words = MANUAL;
        words[1..7].copy_from_slice(&[0x869F, 0x0001, 0x826F, 0x0003, 0x9676, 0x0098]);
        words[9] = 0xFFFF;
        let report = poll(&words, &mut store).unwrap();
        assert_eq!(report.conditions.over_power, Alarm::Raised);
        let [_, current, power, energy, _] = published(&store);
        assert_eq!(current.0, Some(99_999));
        assert_eq!(power.0, Some(229_999));
        assert_eq!(energy.0, Some(9_999_990));
    }

    #[test]
    fn p_185_a_value_outside_the_manual_s_range_is_out_of_range_and_the_edges_are_not() {
        // (register, raw word, the cell's index, what it publishes)
        let cases: [(usize, u16, usize, Option<i32>); 8] = [
            (0, 800, 0, Some(800)),
            (0, 2600, 0, Some(2600)),
            (0, 799, 0, None),
            (0, 2601, 0, None),
            (7, 450, 4, Some(4500)),
            (7, 650, 4, Some(6500)),
            (7, 449, 4, None),
            (7, 651, 4, None),
        ];
        for (register, raw, cell, expected) in cases {
            let mut store = store();
            let mut words = MANUAL;
            words[register] = raw;
            let _ = poll(&words, &mut store).unwrap();
            let signal = id(50u16.checked_add(u16::try_from(cell).unwrap()).unwrap());
            let seen = store.sample(signal, Tick::ZERO).unwrap();
            assert_eq!(seen.value(), expected, "{register:#06x} {raw}");
            if expected.is_none() {
                assert_eq!(seen.q.validity_of(), Validity::OutOfRange);
            }
        }
        // 100.001 A, above the PZEM-016's 100 A.
        let mut store = store();
        let mut words = MANUAL;
        words[1..3].copy_from_slice(&[0x86A1, 0x0001]);
        let _ = poll(&words, &mut store).unwrap();
        assert_eq!(published(&store)[1].0, None);
    }

    #[test]
    fn an_undefined_power_factor_or_alarm_word_refuses_the_reply_and_writes_nothing() {
        for (register, raw) in [(8usize, 101u16), (9, 0x0001)] {
            let mut store = store();
            let mut words = MANUAL;
            words[register] = raw;
            assert_eq!(
                poll(&words, &mut store),
                Err(VendorError::Condition(ConditionError::Undefined {
                    register: u16::try_from(register).unwrap(),
                    raw
                }))
            );
            assert!(published(&store).iter().all(|(value, _)| value.is_none()));
        }
    }

    #[test]
    fn f_050_a_malformed_reply_is_refused_and_writes_nothing() {
        let echo = BLOCK.read(Address::new(1).unwrap()).encode();
        let (reply, len) = register_reply(2, 0x04, &MANUAL);
        let bursts: [&[u8]; 2] = [&echo, &reply[..len]];
        let mut port = Scripted::new(&bursts);
        let mut store = store();
        assert_eq!(
            block_on(meter().poll(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(VendorError::Poll(PollError::Modbus {
                block: 0,
                error: ModbusError::Reply(ReplyError::WrongAddress(2))
            }))
        );
        assert!(published(&store).iter().all(|(value, _)| value.is_none()));
    }

    #[test]
    fn a_stopped_generator_s_meter_is_silent_and_its_readings_go_stale_never_zero() {
        let mut store = store();
        let _ = poll(&MANUAL, &mut store).unwrap();
        let echo = BLOCK.read(Address::new(1).unwrap()).encode();
        let bursts: [&[u8]; 1] = [&echo];
        let mut port = Scripted::new(&bursts);
        let later = Tick::from_millis(10_001);
        assert_eq!(
            block_on(meter().poll(&mut port, TIMING, later, &mut store)),
            Err(VendorError::Poll(PollError::Modbus {
                block: 0,
                error: ModbusError::Timeout
            }))
        );
        let hertz = store.sample(id(54), later).unwrap();
        assert_eq!(hertz.q.validity_of(), Validity::Stale);
        assert!(
            store
                .current(id(54), later, ProvenanceSet::of(&[Provenance::Measured]))
                .is_err()
        );
    }

    #[test]
    fn a_meter_s_signals_are_consecutive_and_refused_past_the_top_of_the_range() {
        let meter = meter();
        assert_eq!(
            [0, 4, 5].map(|at| meter.signal(at)),
            [Some(id(50)), Some(id(54)), None]
        );
        assert!(Meter::new(Address::new(1).unwrap(), id(0xFFFB)).is_some());
        assert_eq!(Meter::new(Address::new(1).unwrap(), id(0xFFFC)), None);
    }
}
