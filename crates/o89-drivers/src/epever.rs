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
//! cites: F-050, F-052

use km43::{Dialect, Id, Provenance, SignalDomain, Unit};
use o89_core::{Signals, Tick};

use crate::dialect::{Block, Cell, Kind, RegisterMap, Sign, Span};
use crate::modbus::{self, Address, Function, RECEIVE_BYTES, Read, Registers, Timing};
use crate::port::Rs485;
use crate::vendor::{self, ConditionError, Report, VendorError};
use crate::{Device, ModbusDevice};

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

/// `0x331A` to `0x331C`: the battery's voltage and its net current, low
/// word first.
///
/// The tables give the current as one 32-bit value in hundredths of an
/// ampere without saying it is signed. It is read as two's complement,
/// negative while the bank discharges, as the earlier `cabin-epever`
/// driver and the two implementations it cites read it; that is not the
/// vendor's word. A controller that sent a magnitude instead would read
/// the same while charging and wrongly while discharging, which is a bench
/// check before anything decides on it.
const BATTERY: [Cell; 2] = [
    centi(0x331A, Kind::DcVoltage, Span::One, Sign::Unsigned),
    centi(0x331B, Kind::DcCurrent, Span::TwoLowFirst, Sign::Signed),
];

const BLOCKS: [Block; 4] = [
    crate::block!(Function::ReadInput, 0x3100, 4, &PV),
    crate::block!(Function::ReadInput, 0x310C, 4, &LOAD),
    crate::block!(Function::ReadInput, 0x311A, 1, &SOC),
    crate::block!(Function::ReadInput, 0x331A, 3, &BATTERY),
];

/// The EPEVER B-series register map. Its cells publish in this order: PV
/// voltage, current and power; load voltage, current and power; state of
/// charge; battery voltage and current.
pub const MAP: RegisterMap = RegisterMap {
    dialect: Dialect::EPEVER_B,
    blocks: &BLOCKS,
};

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

/// An EPEVER B-series controller on an RS-485 port at 115200 8N1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Charger(ModbusDevice);

impl Charger {
    /// The controller at `address`, whose cells publish as consecutive
    /// signals from `first` in [`MAP`]'s order.
    ///
    /// `None` only where [`ModbusDevice::new`] refuses.
    #[must_use]
    pub fn new(address: Address, first: Id) -> Option<Self> {
        ModbusDevice::new(address, &MAP, first).map(Self)
    }

    /// The device and its signals.
    #[must_use]
    pub const fn device(&self) -> &ModbusDevice {
        &self.0
    }

    /// Read every block of [`MAP`] into `store` at `now`, then the charging
    /// status.
    ///
    /// Five exchanges, each bounded by `timing`. The map's poll stops at its
    /// first failure, as [`Device::poll_rs485`] does; a failed status read
    /// leaves the cells written and the status unknown.
    pub async fn poll<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Report<Status>, VendorError<P::Error>> {
        let polled = Device::Modbus(self.0)
            .poll_rs485(port, timing, now, store)
            .await
            .map_err(VendorError::Poll)?;
        let read = Status::read(self.0.address());
        let mut buf = [0u8; RECEIVE_BYTES];
        let registers = modbus::read(port, read, timing, &mut buf)
            .await
            .map_err(VendorError::Conditions)?;
        let conditions = Status::from_registers(&registers).map_err(VendorError::Condition)?;
        Ok(Report { polled, conditions })
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

    fn charger() -> Charger {
        Charger::new(address(), id(FIRST)).unwrap()
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

    fn poll_with(
        words: &[&[u16]; 5],
        store: &mut Signals<9>,
    ) -> Result<Report<Status>, VendorError<u8>> {
        let (echoes, replies) = (echoes(), frames(words));
        let bursts = interleaved(&echoes, &replies);
        let mut port = Scripted::new(&bursts);
        block_on(charger().poll(&mut port, TIMING, Tick::ZERO, store))
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
        let report = poll_with(&WORDS, &mut store).unwrap();
        assert_eq!(report.polled.written, 9);
        assert_eq!(
            report.conditions,
            Status {
                stage: ChargeStage::Boost,
                fault: false
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
            assert_eq!(report.conditions, Status { stage, fault }, "{word:#06x}");
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
            block_on(charger().poll(&mut port, TIMING, Tick::ZERO, &mut store)),
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
            block_on(charger().poll(&mut port, TIMING, Tick::ZERO, &mut store)),
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
            block_on(charger().poll(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(VendorError::Conditions(ModbusError::Timeout))
        );
        assert_eq!(published(&store)[8].0, Some(-3_250));
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
