//! EPEVER B-series charge controllers (Tracer-A and -B, LS-B, VS-B and their
//! kin): 115200 8N1, input registers read with function `0x04`.
//!
//! Sources: EPEVER, *LS-B, VS-B, Tracer-B, Tracer-A, iTracer, eTracer
//! Series Controller Communication Instruction* V2.5 (the real-time and
//! statistics tables, and its worked example at `0x331A`), and *B-Series
//! MODBUS Specification* V2.3. No EPEVER has been read on the bench yet.
//!
//! Each block reads only registers the V2.5 table lists, so a model that
//! lays out its gaps differently has nothing to refuse; that costs four
//! exchanges where one would reach across the gaps. The state of charge at
//! `0x311A` is the controller's own estimate and publishes `estimated`,
//! which a `counted_only` rule refuses (F-052). V2.5 gives it in whole
//! percent where V2.3 says hundredths; V2.5 is followed, and the kind's own
//! 0 to 100 % refuses a value read at the wrong scale.
//!
//! The charge stage at `0x3201` has no KM43 member to publish as
//! (origin89hq/km43#3), so it comes back typed in [`Status`] and is never
//! stored. The generated-energy counters have no DC energy kind
//! (origin89hq/km43#2) and are not read. Neither document defines a
//! *not available* word for any register read here, and none is declared.
//!
//! Neither says whether the battery current is signed or which way is
//! positive, so it is not in [`MAP`]: it publishes `unsupported` unless the
//! caller declares a [`BatteryCurrent`] for the unit, and its raw words come
//! back in [`Words`] either way. [`ROLES`] names the component each of the
//! map's cells describes.
//!
//! cites: F-050, F-052

use km43::{ComponentRole, Dialect, Id, Provenance, SignalDomain, Unit, Validity};
use o89_core::{Observation, Signals, Tick};

use crate::dialect::{Block, Cell, DecodeError, Kind, RegisterMap, Sign, Span};
use crate::modbus::{self, Address, Function, RECEIVE_BYTES, Read, Registers, Timing};
use crate::port::Rs485;
use crate::vendor::{self, ConditionError, Report, VendorError};
use crate::{ModbusDevice, PollError, Polled};

/// A cell in hundredths, which is how V2.5 scales every voltage, current
/// and power read here.
const fn centi(register: u16, kind: Kind, span: Span, sign: Sign) -> Cell {
    Cell {
        register,
        kind,
        domain: SignalDomain::Live,
        span,
        sign,
        unit: kind.unit(),
        decade: -2,
        absent: None,
        plausible: None,
        provenance: Provenance::Measured,
    }
}

/// `0x3100` to `0x3103`: the PV array's voltage, current into the
/// controller, and power, low word first.
const PV: [Cell; 3] = [
    centi(0x3100, Kind::DcVoltage, Span::One, Sign::Unsigned),
    centi(0x3101, Kind::DcCurrent, Span::One, Sign::Unsigned),
    centi(0x3102, Kind::DcPower, Span::TwoLowFirst, Sign::Unsigned),
];

/// `0x310C` to `0x310F`: the load output's voltage, current out to the
/// load, and power, low word first.
const LOAD: [Cell; 3] = [
    centi(0x310C, Kind::DcVoltage, Span::One, Sign::Unsigned),
    centi(0x310D, Kind::DcCurrent, Span::One, Sign::Unsigned),
    centi(0x310E, Kind::DcPower, Span::TwoLowFirst, Sign::Unsigned),
];

/// `0x311A`: the battery's remaining capacity in whole percent, the
/// controller's estimate.
const SOC: [Cell; 1] = [Cell {
    register: 0x311A,
    kind: Kind::StateOfCharge,
    domain: SignalDomain::Live,
    span: Span::One,
    sign: Sign::Unsigned,
    unit: Unit::Percent,
    decade: 0,
    absent: None,
    plausible: None,
    provenance: Provenance::Estimated,
}];

/// `0x331A`: the battery's voltage.
const BATTERY: [Cell; 1] = [centi(0x331A, Kind::DcVoltage, Span::One, Sign::Unsigned)];

/// The battery block reads on to `0x331C` for the battery current beside
/// the voltage; see [`BatteryCurrent`].
const BLOCKS: [Block; 4] = [
    crate::block!(Function::ReadInput, 0x3100, 4, &PV),
    crate::block!(Function::ReadInput, 0x310C, 4, &LOAD),
    crate::block!(Function::ReadInput, 0x311A, 1, &SOC),
    crate::block!(Function::ReadInput, 0x331A, 3, &BATTERY),
];

/// The EPEVER B-series register map. Its cells publish in this order: PV
/// voltage, current and power; load voltage, current and power; state of
/// charge; battery voltage.
pub const MAP: RegisterMap = RegisterMap {
    dialect: Dialect::EPEVER_B,
    blocks: &BLOCKS,
};

/// The component each of [`MAP`]'s cells describes, by register, in the
/// map's order. The PV cells are the tracker's input, where the current
/// flows in, rather than the array's output, where it flows out; KM43's DC
/// current is positive into its component.
pub const ROLES: [(u16, ComponentRole); 8] = [
    (0x3100, ComponentRole::MPPT_TRACKER),
    (0x3101, ComponentRole::MPPT_TRACKER),
    (0x3102, ComponentRole::MPPT_TRACKER),
    (0x310C, ComponentRole::LOAD_OUTPUT),
    (0x310D, ComponentRole::LOAD_OUTPUT),
    (0x310E, ComponentRole::LOAD_OUTPUT),
    (0x311A, ComponentRole::BATTERY_BANK),
    (0x331A, ComponentRole::BATTERY_BANK),
];

/// The battery current's registers, `0x331B` low and `0x331C` high.
const BATTERY_CURRENT: u16 = 0x331B;

/// The battery current read as two's complement, positive into the bank.
const SIGNED_CURRENT: [Cell; 1] = [centi(
    BATTERY_CURRENT,
    Kind::DcCurrent,
    Span::TwoLowFirst,
    Sign::Signed,
)];

/// The battery block's read, decoding only the battery current.
const SIGNED_CURRENT_BLOCK: Block = crate::block!(Function::ReadInput, 0x331A, 3, &SIGNED_CURRENT);

/// What the caller has established about the battery current at `0x331B`
/// and `0x331C`, one 32-bit value in hundredths of an ampere, low word
/// first.
///
/// Neither vendor document says whether it is signed or which way is
/// positive, and KM43's DC current needs both: a magnitude would read a
/// discharging bank as a charging one. So there is no default reading. The
/// signal publishes `unsupported` until the caller declares what this
/// unit sends, and the raw words come back in [`Words`] either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BatteryCurrent {
    /// Not established: the signal publishes `unsupported` and no value.
    Unsupported,
    /// Established for this unit, on the bench or from its documentation:
    /// two's complement, positive while the bank charges.
    SignedPositiveCharging,
}

/// The charging equipment status register.
const CHARGING_STATUS: u16 = 0x3201;

/// What the controller is doing with the charge, bits D3 and D2 of
/// `0x3201`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChargeStage {
    /// `00`: not charging.
    NotCharging,
    /// `01`: float.
    Float,
    /// `10`: boost, which is absorption by another name.
    Boost,
    /// `11`: equalization.
    Equalization,
}

/// The charging equipment status, `0x3201`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Status {
    /// Bits D3 and D2.
    pub stage: ChargeStage,
    /// Bit D1: the charging equipment reports a fault.
    pub fault: bool,
}

impl Status {
    /// The read that fetches it from the controller at `address`.
    #[must_use]
    pub const fn read(address: Address) -> Read {
        // One register, far from the top of the range: what `Read::new`
        // requires holds.
        Read::checked(address, Function::ReadInput, CHARGING_STATUS, 1)
    }

    /// The status in `registers`, which must hold `0x3201`.
    pub fn from_registers(registers: &Registers<'_>) -> Result<Self, ConditionError> {
        let word = vendor::word(registers, CHARGING_STATUS)?;
        let stage = match (word & 0b1000 != 0, word & 0b0100 != 0) {
            (false, false) => ChargeStage::NotCharging,
            (false, true) => ChargeStage::Float,
            (true, false) => ChargeStage::Boost,
            (true, true) => ChargeStage::Equalization,
        };
        Ok(Self {
            stage,
            fault: word & 0b10 != 0,
        })
    }
}

/// What a poll read that no KM43 kind carries, or that only the caller can
/// say how to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Words {
    /// The charging equipment status.
    pub status: Status,
    /// `0x331B` and `0x331C` as sent, low word first, whatever
    /// [`BatteryCurrent`] the charger was given.
    pub battery_current_raw: u32,
}

/// The signals a charger publishes: [`MAP`]'s cells, then the battery
/// current.
const SIGNALS: usize = 9;

/// An EPEVER B-series controller on an RS-485 port at 115200 8N1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Charger {
    device: ModbusDevice,
    current: Id,
    battery_current: BatteryCurrent,
}

impl Charger {
    /// The controller at `address`, whose cells publish as consecutive
    /// signals from `first` in [`MAP`]'s order, followed by the battery
    /// current read as `battery_current` says.
    ///
    /// `None` when the signals would run past `0xFFFF`.
    #[must_use]
    pub fn new(address: Address, first: Id, battery_current: BatteryCurrent) -> Option<Self> {
        let device = ModbusDevice::new(address, &MAP, first)?;
        let offset = u16::try_from(SIGNALS.checked_sub(1)?).ok()?;
        let current = Id::new(first.get().checked_add(offset)?).ok()?;
        Some(Self {
            device,
            current,
            battery_current,
        })
    }

    /// The device and the signals of its map's cells.
    #[must_use]
    pub const fn device(&self) -> &ModbusDevice {
        &self.device
    }

    /// The signal the battery current publishes as.
    #[must_use]
    pub const fn battery_current_signal(&self) -> Id {
        self.current
    }

    /// Read every block of [`MAP`] and the battery current into `store` at
    /// `now`, then the charging status.
    ///
    /// Five exchanges, each bounded by `timing`. The poll stops at the first
    /// failure, and what it wrote before stands; a failed status read leaves
    /// every signal written and the words unknown.
    pub async fn poll<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Report<Words>, VendorError<P::Error>> {
        let address = self.device.address();
        let signal = |cell| self.device.signal(cell);
        let mut buf = [0u8; RECEIVE_BYTES];
        let [pv, load, soc, battery] = &BLOCKS;
        let mut written = 0usize;
        for (at, block) in [pv, load, soc].into_iter().enumerate() {
            let registers = modbus::read(port, block.read(address), timing, &mut buf)
                .await
                .map_err(|error| VendorError::Poll(PollError::Modbus { block: at, error }))?;
            let cells = vendor::publish(block, &registers, written, signal, now, store)
                .map_err(VendorError::Poll)?;
            written = written.saturating_add(cells);
        }
        let registers = modbus::read(port, battery.read(address), timing, &mut buf)
            .await
            .map_err(|error| VendorError::Poll(PollError::Modbus { block: 3, error }))?;
        let battery_current_raw =
            vendor::low_first(&registers, BATTERY_CURRENT).map_err(VendorError::Condition)?;
        let cells = vendor::publish(battery, &registers, written, signal, now, store)
            .map_err(VendorError::Poll)?;
        written = written.saturating_add(cells);
        let cells = self.publish_current(&registers, written, now, store)?;
        written = written.saturating_add(cells);

        let mut buf = [0u8; RECEIVE_BYTES];
        let registers = modbus::read(port, Status::read(address), timing, &mut buf)
            .await
            .map_err(VendorError::Conditions)?;
        let status = Status::from_registers(&registers).map_err(VendorError::Condition)?;
        Ok(Report {
            polled: Polled { written },
            conditions: Words {
                status,
                battery_current_raw,
            },
        })
    }

    /// Write the battery current as the charger's [`BatteryCurrent`] says,
    /// `unsupported` or decoded as the caller declared it, and say how many
    /// signals were written.
    fn publish_current<E, const N: usize>(
        &self,
        registers: &Registers<'_>,
        cell: usize,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<usize, VendorError<E>> {
        match self.battery_current {
            BatteryCurrent::Unsupported => {
                let seen = Observation::missing(Validity::Unsupported).map_err(|error| {
                    VendorError::Poll(PollError::Decode {
                        cell,
                        error: DecodeError::Quality(error),
                    })
                })?;
                store
                    .write(self.current, now, seen)
                    .map_err(|error| VendorError::Poll(PollError::Store(error)))?;
                Ok(1)
            }
            BatteryCurrent::SignedPositiveCharging => vendor::publish(
                &SIGNED_CURRENT_BLOCK,
                registers,
                cell,
                |_| Some(self.current),
                now,
                store,
            )
            .map_err(VendorError::Poll),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PollError;
    use crate::modbus::tests::{Scripted, TIMING, register_reply};
    use crate::modbus::{Exception, FRAME_BYTES, ModbusError, ReplyError, parse};
    use embassy_futures::block_on;
    use km43::Validity;
    use o89_core::{ChargeSource, Ineligible, Limits, Millis};

    const FIRST: u16 = 60;

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn address() -> Address {
        Address::new(1).unwrap()
    }

    fn charger(battery_current: BatteryCurrent) -> Charger {
        Charger::new(address(), id(FIRST), battery_current).unwrap()
    }

    fn store() -> Signals<9> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        for n in FIRST..FIRST + 9 {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    /// Hand-built replies to the four blocks and the status read, in poll
    /// order: 48.00 V, 5.00 A and 240.00 W from the array; 12.80 V, 1.50 A
    /// and 19.20 W to the load; 64 %; 12.30 V and −3.25 A at the battery;
    /// boost with no fault. Not a bench capture.
    const WORDS: [&[u16]; 5] = [
        &[4800, 500, 24_000, 0],
        &[1280, 150, 1920, 0],
        &[64],
        &[1230, 0xFEBB, 0xFFFF],
        &[0b1000],
    ];

    fn frames(words: &[&[u16]; 5]) -> [([u8; FRAME_BYTES], usize); 5] {
        words.map(|words| register_reply(1, 0x04, words))
    }

    fn echoes() -> [[u8; 8]; 5] {
        let [a, b, c, d] = BLOCKS.map(|block| block.read(address()).encode());
        [a, b, c, d, Status::read(address()).encode()]
    }

    /// Each read's echo followed by its reply, in poll order.
    fn interleaved<'a>(
        echoes: &'a [[u8; 8]; 5],
        replies: &'a [([u8; FRAME_BYTES], usize); 5],
    ) -> [&'a [u8]; 10] {
        let mut bursts: [&[u8]; 10] = [&[]; 10];
        let pairs = echoes.iter().zip(replies);
        for (slot, (echo, (reply, len))) in bursts.as_chunks_mut::<2>().0.iter_mut().zip(pairs) {
            *slot = [echo, &reply[..*len]];
        }
        bursts
    }

    fn poll_as(
        battery_current: BatteryCurrent,
        words: &[&[u16]; 5],
        store: &mut Signals<9>,
    ) -> Result<Report<Words>, VendorError<u8>> {
        let (echoes, replies) = (echoes(), frames(words));
        let bursts = interleaved(&echoes, &replies);
        let mut port = Scripted::new(&bursts);
        block_on(charger(battery_current).poll(&mut port, TIMING, Tick::ZERO, store))
    }

    fn poll_with(
        words: &[&[u16]; 5],
        store: &mut Signals<9>,
    ) -> Result<Report<Words>, VendorError<u8>> {
        poll_as(BatteryCurrent::Unsupported, words, store)
    }

    fn published(store: &Signals<9>) -> [(Option<i32>, Provenance); 9] {
        core::array::from_fn(|at| {
            let n = FIRST.checked_add(u16::try_from(at).unwrap()).unwrap();
            let seen = store.sample(id(n), Tick::ZERO).unwrap();
            (seen.value(), seen.q.provenance_of())
        })
    }

    #[test]
    fn the_v2_5_worked_example_decodes_to_the_battery_voltage_it_names() {
        // V2.5, "Read real-time battery voltage": 01 04 33 1A 00 01 1F 49,
        // answered 01 04 02 04 CE 3A 64, which is 12.30 V. Both frames are
        // the vendor's, CRC included; neither is a bench capture.
        static VOLTS: [Cell; 1] = [BATTERY[0]];
        const ONE: Block = crate::block!(Function::ReadInput, 0x331A, 1, &VOLTS);
        let read = ONE.read(address());
        assert_eq!(
            read.encode(),
            [0x01, 0x04, 0x33, 0x1A, 0x00, 0x01, 0x1F, 0x49]
        );
        let registers = parse(read, &[0x01, 0x04, 0x02, 0x04, 0xCE, 0x3A, 0x64]).unwrap();
        let seen = ONE.decode(&registers).next().unwrap().unwrap();
        assert_eq!(seen.reading(), Some(12_300));
        assert_eq!(seen.quality().provenance_of(), Provenance::Measured);
    }

    #[test]
    fn f_052_a_poll_publishes_every_cell_with_its_declared_provenance() {
        let mut store = store();
        let report = poll_as(BatteryCurrent::SignedPositiveCharging, &WORDS, &mut store).unwrap();
        assert_eq!(report.polled.written, 9);
        assert_eq!(
            report.conditions,
            Words {
                status: Status {
                    stage: ChargeStage::Boost,
                    fault: false
                },
                battery_current_raw: 0xFFFF_FEBB,
            }
        );
        let measured = Provenance::Measured;
        assert_eq!(
            published(&store),
            [
                (Some(48_000), measured),
                (Some(5_000), measured),
                (Some(2_400), measured),
                (Some(12_800), measured),
                (Some(1_500), measured),
                (Some(192), measured),
                (Some(640), Provenance::Estimated),
                (Some(12_300), measured),
                (Some(-3_250), measured),
            ]
        );
    }

    #[test]
    fn f_052_the_state_of_charge_is_an_estimate_counted_only_refuses() {
        let mut store = store();
        let _ = poll_with(&WORDS, &mut store).unwrap();
        let soc = id(FIRST + 6);
        assert_eq!(
            store.current(soc, Tick::ZERO, ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Provenance(Provenance::Estimated))
        );
        let eligible = store
            .current(soc, Tick::ZERO, ChargeSource::EstimateAccepted.accepts())
            .unwrap();
        assert_eq!(
            (eligible.value(), eligible.provenance()),
            (640, Provenance::Estimated)
        );
    }

    #[test]
    fn p_185_a_state_of_charge_past_full_is_out_of_range_and_full_is_not() {
        for (raw, expected) in [
            (100u16, Some(1000)),
            (0, Some(0)),
            (101, None),
            (6400, None),
        ] {
            let mut store = store();
            let mut words = WORDS;
            let soc = [raw];
            words[2] = &soc;
            let _ = poll_with(&words, &mut store).unwrap();
            let seen = store.sample(id(FIRST + 6), Tick::ZERO).unwrap();
            assert_eq!(seen.value(), expected, "{raw}");
            if expected.is_none() {
                // What V2.3's hundredths would have read as 64 %.
                assert_eq!(seen.q.validity_of(), Validity::OutOfRange, "{raw}");
            }
        }
    }

    #[test]
    fn every_charge_stage_and_the_fault_bit_are_read_from_their_own_bits() {
        for (word, stage, fault) in [
            (0x0000u16, ChargeStage::NotCharging, false),
            (0x0004, ChargeStage::Float, false),
            (0x0008, ChargeStage::Boost, false),
            (0x000C, ChargeStage::Equalization, false),
            // Every other bit set, the stage bits clear, the fault raised.
            (0xFFF3, ChargeStage::NotCharging, true),
        ] {
            let mut store = store();
            let mut words = WORDS;
            let status = [word];
            words[4] = &status;
            let report = poll_with(&words, &mut store).unwrap();
            assert_eq!(
                report.conditions.status,
                Status { stage, fault },
                "{word:#06x}"
            );
        }
    }

    #[test]
    fn f_050_a_malformed_block_stops_the_poll_and_keeps_what_came_before() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let mut bursts = interleaved(&echoes, &replies);
        // The third block's reply carries two registers where one was asked.
        let (wrong, wrong_len) = register_reply(1, 0x04, &[64, 0]);
        bursts[5] = &wrong[..wrong_len];
        let mut port = Scripted::new(&bursts[..6]);
        assert_eq!(
            block_on(charger(BatteryCurrent::Unsupported).poll(
                &mut port,
                TIMING,
                Tick::ZERO,
                &mut store
            )),
            Err(VendorError::Poll(PollError::Modbus {
                block: 2,
                error: ModbusError::Reply(ReplyError::ByteCount(4))
            }))
        );
        let seen = published(&store);
        assert_eq!(seen[5].0, Some(192));
        // The state of charge was never read: it has no value, not zero.
        assert_eq!(seen[6].0, None);
        assert_eq!(
            store
                .sample(id(FIRST + 6), Tick::ZERO)
                .unwrap()
                .q
                .validity_of(),
            Validity::Initialising
        );
    }

    #[test]
    fn a_model_without_a_register_answers_with_an_exception_and_its_cells_stay_absent() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let mut bursts = interleaved(&echoes, &replies);
        // Built by hand: 0x331A refused with illegal data address.
        let refusal = [0x01, 0x84, 0x02, 0xC2, 0xC1];
        bursts[7] = &refusal;
        let mut port = Scripted::new(&bursts[..8]);
        assert_eq!(
            block_on(charger(BatteryCurrent::SignedPositiveCharging).poll(
                &mut port,
                TIMING,
                Tick::ZERO,
                &mut store
            )),
            Err(VendorError::Poll(PollError::Modbus {
                block: 3,
                error: ModbusError::Reply(ReplyError::Exception(Exception::IllegalDataAddress))
            }))
        );
        let seen = published(&store);
        assert_eq!(seen[6].0, Some(640));
        assert_eq!((seen[7].0, seen[8].0), (None, None));
    }

    #[test]
    fn a_failed_status_read_leaves_the_cells_written_and_the_status_unknown() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let bursts = interleaved(&echoes, &replies);
        // The status read's echo, and nothing behind it.
        let mut port = Scripted::new(&bursts[..9]);
        assert_eq!(
            block_on(charger(BatteryCurrent::SignedPositiveCharging).poll(
                &mut port,
                TIMING,
                Tick::ZERO,
                &mut store
            )),
            Err(VendorError::Conditions(ModbusError::Timeout))
        );
        assert_eq!(published(&store)[8].0, Some(-3_250));
    }

    #[test]
    fn a_battery_current_nobody_has_qualified_publishes_unsupported_and_keeps_its_raw_words() {
        let mut store = store();
        let report = poll_with(&WORDS, &mut store).unwrap();
        assert_eq!(report.polled.written, 9);
        assert_eq!(report.conditions.battery_current_raw, 0xFFFF_FEBB);
        let current = store.sample(id(FIRST + 8), Tick::ZERO).unwrap();
        assert_eq!(current.value(), None);
        assert_eq!(current.q.validity_of(), Validity::Unsupported);
        // The cells beside it publish as ever.
        assert_eq!(published(&store)[7].0, Some(12_300));
    }

    #[test]
    fn p_185_a_declared_signed_battery_current_decodes_to_its_edges_and_refuses_past_them() {
        // (low word, high word, what publishes at −3), built by hand.
        let cases: [(u16, u16, Option<i32>); 7] = [
            (0x0000, 0x0000, Some(0)),
            (0xFFFF, 0xFFFF, Some(-10)),
            // ±214 748 364 hundredths is the widest that fits at −3.
            (0xCCCC, 0x0CCC, Some(2_147_483_640)),
            (0x3334, 0xF333, Some(-2_147_483_640)),
            (0xCCCD, 0x0CCC, None),
            (0x3333, 0xF333, None),
            (0x0000, 0x8000, None),
        ];
        for (low, high, expected) in cases {
            let mut store = store();
            let mut words = WORDS;
            let battery = [1230, low, high];
            words[3] = &battery;
            let report =
                poll_as(BatteryCurrent::SignedPositiveCharging, &words, &mut store).unwrap();
            assert_eq!(
                report.conditions.battery_current_raw,
                u32::from(low) | (u32::from(high) << 16)
            );
            let current = store.sample(id(FIRST + 8), Tick::ZERO).unwrap();
            assert_eq!(current.value(), expected, "{high:#06x}{low:04x}");
            match expected {
                Some(_) => assert_eq!(current.q.provenance_of(), Provenance::Measured),
                None => assert_eq!(current.q.validity_of(), Validity::OutOfRange),
            }
        }
    }

    #[test]
    fn a_charger_s_signals_run_past_its_map_by_one_and_are_refused_past_the_top() {
        let charger = charger(BatteryCurrent::Unsupported);
        assert_eq!(charger.device().signal(7), Some(id(FIRST + 7)));
        assert_eq!(charger.device().signal(8), None);
        assert_eq!(charger.battery_current_signal(), id(FIRST + 8));
        assert!(Charger::new(address(), id(0xFFF7), BatteryCurrent::Unsupported).is_some());
        assert_eq!(
            Charger::new(address(), id(0xFFF8), BatteryCurrent::Unsupported),
            None
        );
    }

    #[test]
    fn every_map_cell_has_its_component_role_in_the_map_s_order() {
        let registers: [u16; 8] = ROLES.map(|(register, _)| register);
        assert!(MAP.cells().map(|cell| cell.register).eq(registers));
        assert!(
            ROLES[..3]
                .iter()
                .all(|(_, role)| *role == ComponentRole::MPPT_TRACKER)
        );
        assert!(
            ROLES[6..]
                .iter()
                .all(|(_, role)| *role == ComponentRole::BATTERY_BANK)
        );
    }

    #[test]
    fn a_status_is_refused_from_registers_that_do_not_hold_it() {
        assert_eq!(
            Some(Status::read(address())),
            Read::new(address(), Function::ReadInput, CHARGING_STATUS, 1)
        );
        let read = Read::new(address(), Function::ReadInput, 0x3200, 1).unwrap();
        let (frame, len) = register_reply(1, 0x04, &[0x0008]);
        let registers = parse(read, &frame[..len]).unwrap();
        assert_eq!(
            Status::from_registers(&registers),
            Err(ConditionError::Missing(CHARGING_STATUS))
        );
    }
}
