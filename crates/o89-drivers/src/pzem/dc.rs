//! The PZEM-003 and PZEM-017 DC meters: 9600 8N2, eight input registers
//! from `0x0000` read with function `0x04`.
//!
//! Source: Peacefair, *PZEM-003/017 DC communication module*, §1 for the
//! ranges and §2.3 for the registers; read against the self-test's `pzem`
//! check in origin89hq/origin89 and board A's bench log of 2026-09-14, where
//! a PZEM-017 answered 119 of 120 polls of exactly this read with the CRC
//! low byte first, as Modbus sends it and not as the manual writes it.
//!
//! Only the voltage is a signal. The manual gives current and power as
//! unsigned magnitudes, and KM43's DC current and power are signed, so a
//! meter that cannot tell charge from discharge does not fill them; KM43
//! has no DC energy kind (origin89hq/km43#2) and no alarm kind. Those
//! registers come back as [`Words`] from the same reply, typed and never
//! stored. The manual defines no *not available* word for any register: a
//! meter with no voltage on its terminals and no USB supply does not answer
//! at all, which leaves its signal without a value and ages it out.
//!
//! cites: F-050, F-052

use km43::{Dialect, Id, Provenance, SignalDomain, Unit};
use o89_core::{Signals, Tick};

use crate::dialect::{Block, Cell, Kind, Plausible, RegisterMap, Sign, Span};
use crate::modbus::{self, Address, Function, RECEIVE_BYTES, Registers, Timing};
use crate::port::Rs485;
use crate::vendor::{self, Alarm, ConditionError, Report, VendorError};
use crate::{ModbusDevice, PollError};

/// The measurement registers, §2.3.
const CELLS: [Cell; 1] = [
    // 0x0000, 0.01 V. §1.1 measures 0.05 to 300 V.
    Cell {
        register: 0x0000,
        kind: Kind::DcVoltage,
        domain: SignalDomain::Live,
        span: Span::One,
        sign: Sign::Unsigned,
        unit: Unit::Volt,
        decade: -2,
        absent: None,
        plausible: Some(Plausible {
            low: 50,
            high: 300_000,
        }),
        provenance: Provenance::Measured,
    },
];

const BLOCKS: [Block; 1] = [crate::block!(Function::ReadInput, 0x0000, 8, &CELLS)];

/// The PZEM-003/017 register map: one read of the whole measurement table,
/// the request the bench proved.
pub const MAP: RegisterMap = RegisterMap {
    dialect: Dialect::PZEM_DC,
    blocks: &BLOCKS,
};

/// The registers §2.3 defines that no KM43 kind carries, from the same
/// reply as the voltage and at the manual's own resolutions. Unsigned
/// magnitudes: none of them says which way the current flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Words {
    /// `0x0001`, 0.01 A.
    pub current_centiamps: u16,
    /// `0x0002` and `0x0003`, low word first, 0.1 W.
    pub power_deciwatts: u32,
    /// `0x0004` and `0x0005`, low word first, 1 Wh, since the meter's
    /// energy was last reset (§2.5).
    pub energy_watt_hours: u32,
    /// `0x0006`: the voltage is above the high threshold.
    pub high_voltage: Alarm,
    /// `0x0007`: the voltage is below the low threshold.
    pub low_voltage: Alarm,
}

impl Words {
    /// The words in `registers`, which must be [`MAP`]'s read.
    ///
    /// An alarm word other than `0x0000` or `0xFFFF` is refused: the manual
    /// defines only those two.
    pub fn from_registers(registers: &Registers<'_>) -> Result<Self, ConditionError> {
        Ok(Self {
            current_centiamps: vendor::word(registers, 0x0001)?,
            power_deciwatts: vendor::low_first(registers, 0x0002)?,
            energy_watt_hours: vendor::low_first(registers, 0x0004)?,
            high_voltage: Alarm::at(registers, 0x0006)?,
            low_voltage: Alarm::at(registers, 0x0007)?,
        })
    }
}

/// A PZEM-003 or PZEM-017 on an RS-485 port at 9600 8N2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Meter(ModbusDevice);

impl Meter {
    /// The meter at `address`, whose voltage publishes as `signal`.
    ///
    /// `None` only where [`ModbusDevice::new`] refuses.
    #[must_use]
    pub fn new(address: Address, signal: Id) -> Option<Self> {
        ModbusDevice::new(address, &MAP, signal).map(Self)
    }

    /// The device and its signals.
    #[must_use]
    pub const fn device(&self) -> &ModbusDevice {
        &self.0
    }

    /// Read the meter once and write its voltage into `store` at `now`.
    ///
    /// One exchange, bounded by `timing`. A reply whose alarm words the
    /// manual does not define writes nothing.
    pub async fn poll<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Report<Words>, VendorError<P::Error>> {
        let [block] = &BLOCKS;
        let mut buf = [0u8; RECEIVE_BYTES];
        let registers = modbus::read(port, block.read(self.0.address()), timing, &mut buf)
            .await
            .map_err(|error| VendorError::Poll(PollError::Modbus { block: 0, error }))?;
        let conditions = Words::from_registers(&registers).map_err(VendorError::Condition)?;
        let polled = vendor::publish(block, &registers, |cell| self.0.signal(cell), now, store)
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

    fn id() -> Id {
        Id::new(40).unwrap()
    }

    fn meter() -> Meter {
        Meter::new(Address::new(1).unwrap(), id()).unwrap()
    }

    fn store() -> Signals<1> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        store.register(id(), limits).unwrap();
        store
    }

    /// The manual's §2.3 example reply, with its CRC computed, since the
    /// manual prints `0xHH 0xLL` in its place: 100.00 V, 1.00 A, 100.0 W,
    /// 0 Wh, neither alarm. From the vendor's document, not a bench capture.
    const MANUAL: [u16; 8] = [0x2710, 0x0064, 0x03E8, 0x0000, 0, 0, 0, 0];

    fn poll(words: &[u16], store: &mut Signals<1>) -> Result<Report<Words>, VendorError<u8>> {
        let echo = BLOCKS[0].read(Address::new(1).unwrap()).encode();
        let (reply, len) = register_reply(1, 0x04, words);
        let bursts: [&[u8]; 2] = [&echo, &reply[..len]];
        let mut port = Scripted::new(&bursts);
        let report = block_on(meter().poll(&mut port, TIMING, Tick::ZERO, store));
        assert_eq!(port.sent, echo);
        report
    }

    #[test]
    fn the_request_is_the_one_the_bench_proved() {
        // Board A's bench log, 2026-09-14: 01 04 00 00 00 08 and its CRC,
        // CRC low byte first. 0xF1CC is CRC-16/MODBUS over the six bytes.
        assert_eq!(
            BLOCKS[0].read(Address::new(1).unwrap()).encode(),
            [0x01, 0x04, 0x00, 0x00, 0x00, 0x08, 0xF1, 0xCC]
        );
    }

    #[test]
    fn f_052_the_manual_s_example_publishes_a_measured_voltage_and_its_words() {
        let mut store = store();
        let report = poll(&MANUAL, &mut store).unwrap();
        assert_eq!(report.polled.written, 1);
        assert_eq!(
            report.conditions,
            Words {
                current_centiamps: 100,
                power_deciwatts: 1000,
                energy_watt_hours: 0,
                high_voltage: Alarm::Clear,
                low_voltage: Alarm::Clear,
            }
        );
        let volts = store.sample(id(), Tick::ZERO).unwrap();
        assert_eq!(volts.value(), Some(100_000));
        assert_eq!(volts.q.provenance_of(), Provenance::Measured);
    }

    #[test]
    fn raised_alarms_and_high_words_are_read_in_the_manual_s_word_order() {
        let mut store = store();
        // Built by hand: 12.34 V, 655.35 A, 0x0001_0002 dW, 0x0003_0004 Wh,
        // both alarms raised.
        let words = [1234, 0xFFFF, 0x0002, 0x0001, 0x0004, 0x0003, 0xFFFF, 0xFFFF];
        let report = poll(&words, &mut store).unwrap();
        assert_eq!(
            report.conditions,
            Words {
                current_centiamps: 0xFFFF,
                power_deciwatts: 0x0001_0002,
                energy_watt_hours: 0x0003_0004,
                high_voltage: Alarm::Raised,
                low_voltage: Alarm::Raised,
            }
        );
        assert_eq!(
            store.sample(id(), Tick::ZERO).unwrap().value(),
            Some(12_340)
        );
    }

    #[test]
    fn p_185_a_voltage_outside_the_manual_s_range_is_out_of_range_and_its_edges_are_not() {
        for (raw, expected) in [
            (5u16, Some(50)),
            (30_000, Some(300_000)),
            (4, None),
            (0, None),
            (30_001, None),
        ] {
            let mut store = store();
            let mut words = MANUAL;
            words[0] = raw;
            let report = poll(&words, &mut store).unwrap();
            assert_eq!(report.polled.written, 1, "{raw}");
            let volts = store.sample(id(), Tick::ZERO).unwrap();
            assert_eq!(volts.value(), expected, "{raw}");
            if expected.is_none() {
                assert_eq!(volts.q.validity_of(), Validity::OutOfRange, "{raw}");
            }
        }
    }

    #[test]
    fn an_alarm_word_the_manual_does_not_define_refuses_the_reply_and_writes_nothing() {
        let mut store = store();
        let mut words = MANUAL;
        words[7] = 0x0001;
        assert_eq!(
            poll(&words, &mut store),
            Err(VendorError::Condition(ConditionError::Undefined {
                register: 0x0007,
                raw: 0x0001
            }))
        );
        let volts = store.sample(id(), Tick::ZERO).unwrap();
        assert_eq!(volts.value(), None);
        assert_eq!(volts.q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn f_050_a_malformed_reply_is_refused_and_writes_nothing() {
        let echo = BLOCKS[0].read(Address::new(1).unwrap()).encode();
        // Seven registers where eight were asked, CRC intact; then a reply
        // with one bit flipped.
        let (short, short_len) = register_reply(1, 0x04, &MANUAL[..7]);
        let (mut flipped, flipped_len) = register_reply(1, 0x04, &MANUAL);
        flipped[5] ^= 0x01;
        let replies: [(&[u8], ReplyError); 2] = [
            (&short[..short_len], ReplyError::ByteCount(14)),
            (&flipped[..flipped_len], ReplyError::Crc),
        ];
        for (reply, error) in replies {
            let bursts: [&[u8]; 2] = [&echo, reply];
            let mut port = Scripted::new(&bursts);
            let mut store = store();
            assert_eq!(
                block_on(meter().poll(&mut port, TIMING, Tick::ZERO, &mut store)),
                Err(VendorError::Poll(PollError::Modbus {
                    block: 0,
                    error: ModbusError::Reply(error)
                }))
            );
            assert_eq!(store.sample(id(), Tick::ZERO).unwrap().value(), None);
        }
    }

    #[test]
    fn a_meter_that_stops_answering_is_absent_and_never_zero() {
        let mut store = store();
        let _ = poll(&MANUAL, &mut store).unwrap();
        // Below 7 V with no USB supply the meter does not answer (§5.2):
        // only the request's own echo comes back.
        let echo = BLOCKS[0].read(Address::new(1).unwrap()).encode();
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
        let volts = store.sample(id(), later).unwrap();
        assert_eq!(volts.q.validity_of(), Validity::Stale);
        assert!(
            store
                .current(id(), later, ProvenanceSet::of(&[Provenance::Measured]))
                .is_err()
        );
    }
}
