//! EPEVER B-series charge controllers (Tracer-A and -B, LS-B, VS-B and their
//! kin): 115200 8N1, input registers read with function `0x04`.
//!
//! Sources: EPEVER, *LS-B, VS-B, Tracer-B, Tracer-A, iTracer, eTracer
//! Series Controller Communication Instruction* V2.5 (the real-time and
//! statistics tables, and its worked example at `0x331A`), and *B-Series
//! MODBUS Specification* V2.3. No EPEVER has been read on the bench yet.
//!
//! Each read covers only registers the V2.5 table lists, so a model that
//! lays out its gaps differently has nothing to refuse; that costs five
//! exchanges where fewer would reach across the gaps. The charge stage at
//! `0x3201` has no KM43 member to publish as (origin89hq/km43#3), so it
//! comes back typed in [`Status`] and is never stored. The generated-energy
//! counters have no DC energy kind (origin89hq/km43#2) and are not read.
//! Neither document defines a *not available* word for any register read
//! here, and none is declared.
//!
//! Two registers are read and published only as the caller declares them,
//! because the documents leave their representation open: the state of
//! charge at `0x311A`, which V2.5 gives in whole percent and V2.3 in
//! hundredths, and the battery current at `0x331B`, whose sign neither
//! states. Read at the wrong scale, a bank at 0.50 % reads 50 %, and no
//! range catches it. Each publishes `unsupported` until the caller names a
//! [`StateOfCharge`] or a [`BatteryCurrent`] for the unit, and its raw words
//! come back in [`Words`] either way. The state of charge is the
//! controller's estimate, so a declared one publishes `estimated`, which a
//! `counted_only` rule refuses (F-052).
//!
//! [`MAP`] is what every EPEVER of this class publishes the same way; a
//! [`Charger`] publishes its cells, then the state of charge, then the
//! battery current. `Device::Modbus` over [`MAP`] alone reads the cells
//! without the declared readings or the status; the `Device` variant that
//! polls a [`Charger`] whole, and the check that no two devices' signals
//! overlap, belong to the configuration of buses and devices (#196).
//!
//! cites: F-050, F-052

use km43::{ComponentRole, Dialect, Id, Provenance, SignalDomain, Unit};
use o89_core::{Signals, Tick};

use crate::dialect::{Block, Cell, Kind, RegisterMap, Sign, Span};
use crate::modbus::{self, Address, Function, RECEIVE_BYTES, Read, Registers, Timing};
use crate::port::Rs485;
use crate::vendor::{self, ConditionError, Report, VendorError};
use crate::{PollError, Polled};

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

/// `0x331A`: the battery's voltage. The read goes on to `0x331C` for the
/// battery current beside it.
const BATTERY: [Cell; 1] = [centi(0x331A, Kind::DcVoltage, Span::One, Sign::Unsigned)];

const BLOCKS: [Block; 3] = [
    crate::block!(Function::ReadInput, 0x3100, 4, &PV),
    crate::block!(Function::ReadInput, 0x310C, 4, &LOAD),
    crate::block!(Function::ReadInput, 0x331A, 3, &BATTERY),
];

/// The EPEVER B-series register map. Its cells publish in this order: PV
/// voltage, current and power; load voltage, current and power; battery
/// voltage.
pub const MAP: RegisterMap = RegisterMap {
    dialect: Dialect::EPEVER_B,
    blocks: &BLOCKS,
};

/// The component each of [`MAP`]'s cells describes, by register, in the
/// map's order. The PV cells are the tracker's input, where the current
/// flows in, rather than the array's output, where it flows out; KM43's DC
/// current is positive into its component. The state of charge and the
/// battery current, outside the map, describe the battery bank.
pub const ROLES: [(u16, ComponentRole); 7] = [
    (0x3100, ComponentRole::MPPT_TRACKER),
    (0x3101, ComponentRole::MPPT_TRACKER),
    (0x3102, ComponentRole::MPPT_TRACKER),
    (0x310C, ComponentRole::LOAD_OUTPUT),
    (0x310D, ComponentRole::LOAD_OUTPUT),
    (0x310E, ComponentRole::LOAD_OUTPUT),
    (0x331A, ComponentRole::BATTERY_BANK),
];

/// The state of charge register.
const SOC_REGISTER: u16 = 0x311A;

/// The state of charge at `decade`, the controller's estimate.
const fn soc(decade: i8) -> [Cell; 1] {
    [Cell {
        register: SOC_REGISTER,
        kind: Kind::StateOfCharge,
        domain: SignalDomain::Live,
        span: Span::One,
        sign: Sign::Unsigned,
        unit: Unit::Percent,
        decade,
        absent: None,
        plausible: None,
        provenance: Provenance::Estimated,
    }]
}

const SOC_WHOLE: [Cell; 1] = soc(0);
const SOC_HUNDREDTHS: [Cell; 1] = soc(-2);
const SOC_WHOLE_BLOCK: Block = crate::block!(Function::ReadInput, SOC_REGISTER, 1, &SOC_WHOLE);
const SOC_HUNDREDTHS_BLOCK: Block =
    crate::block!(Function::ReadInput, SOC_REGISTER, 1, &SOC_HUNDREDTHS);

/// How the caller has established this unit sends its state of charge at
/// `0x311A`.
///
/// V2.5 lists it in whole percent and V2.3 in hundredths, and a raw 1 to
/// 100 is a plausible reading either way, so there is no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StateOfCharge {
    /// Not established: the signal publishes `unsupported` and no value.
    Unsupported,
    /// Whole percent, as V2.5 lists it.
    WholePercent,
    /// Hundredths of a percent, as V2.3 lists it.
    Hundredths,
}

impl StateOfCharge {
    /// The checked block that decodes it, or `None` when undeclared.
    const fn block(self) -> Option<&'static Block> {
        match self {
            Self::Unsupported => None,
            Self::WholePercent => Some(&SOC_WHOLE_BLOCK),
            Self::Hundredths => Some(&SOC_HUNDREDTHS_BLOCK),
        }
    }
}

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

/// How the caller has established this unit sends its battery current at
/// `0x331B` and `0x331C`, one 32-bit value in hundredths of an ampere, low
/// word first.
///
/// Neither vendor document says whether it is signed or which way is
/// positive, and KM43's DC current needs both: a magnitude would read a
/// discharging bank as a charging one. So there is no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BatteryCurrent {
    /// Not established: the signal publishes `unsupported` and no value.
    Unsupported,
    /// Two's complement, positive while the bank charges.
    SignedPositiveCharging,
}

impl BatteryCurrent {
    /// The checked block that decodes it, or `None` when undeclared.
    const fn block(self) -> Option<&'static Block> {
        match self {
            Self::Unsupported => None,
            Self::SignedPositiveCharging => Some(&SIGNED_CURRENT_BLOCK),
        }
    }
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
    /// `0x311A` as sent, whatever [`StateOfCharge`] the charger was given.
    pub state_of_charge_raw: u16,
    /// `0x331B` and `0x331C` as sent, low word first, whatever
    /// [`BatteryCurrent`] the charger was given.
    pub battery_current_raw: u32,
}

/// Where the state of charge falls among a charger's signals: after the
/// map's seven cells.
const SOC_AT: usize = 7;
/// Where the battery current falls: last.
const CURRENT_AT: usize = 8;

/// An EPEVER B-series controller on an RS-485 port at 115200 8N1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Charger {
    address: Address,
    first: Id,
    state_of_charge: StateOfCharge,
    battery_current: BatteryCurrent,
}

impl Charger {
    /// How many signals a charger publishes: [`MAP`]'s cells, the state of
    /// charge and the battery current.
    pub const SIGNALS: usize = 9;

    /// The controller at `address`, whose readings publish as the
    /// consecutive signals from `first`: [`MAP`]'s cells in order, then the
    /// state of charge read as `state_of_charge` says, then the battery
    /// current read as `battery_current` says.
    ///
    /// `None` when the signals would run past `0xFFFF`.
    #[must_use]
    pub fn new(
        address: Address,
        first: Id,
        state_of_charge: StateOfCharge,
        battery_current: BatteryCurrent,
    ) -> Option<Self> {
        vendor::fits(first, Self::SIGNALS).then_some(Self {
            address,
            first,
            state_of_charge,
            battery_current,
        })
    }

    /// The controller's address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The signal the `index`th reading publishes as, of
    /// [`Charger::SIGNALS`] from the first; `None` past the last.
    #[must_use]
    pub fn signal(&self, index: usize) -> Option<Id> {
        vendor::signal(self.first, Self::SIGNALS, index)
    }

    /// Read the controller into `store` at `now`: [`MAP`]'s cells, the state
    /// of charge and the battery current, then the charging status.
    ///
    /// Five exchanges, each bounded by `timing`, in this order: PV, load,
    /// state of charge, battery, status. A failed read of one of the first
    /// four is [`PollError::Modbus`] with its position in that order. The
    /// poll stops at the first failure, and what it wrote before stands; a
    /// failed status read leaves every signal written and the words unknown.
    pub async fn poll<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Report<Words>, VendorError<P::Error>> {
        let signal = |cell| self.signal(cell);
        let mut buf = [0u8; RECEIVE_BYTES];
        let [pv, load, battery] = &BLOCKS;
        // The map's cells written so far, which is where its next cell
        // falls, and the declared readings written after all of them.
        let mut cells = 0usize;
        let mut declared = 0usize;

        for (at, block) in [pv, load].into_iter().enumerate() {
            let registers = modbus::read(port, block.read(self.address), timing, &mut buf)
                .await
                .map_err(|error| VendorError::Poll(PollError::Modbus { block: at, error }))?;
            cells = cells.saturating_add(
                vendor::publish(block, &registers, cells, signal, now, store)
                    .map_err(VendorError::Poll)?,
            );
        }

        let registers = modbus::read(port, SOC_WHOLE_BLOCK.read(self.address), timing, &mut buf)
            .await
            .map_err(|error| VendorError::Poll(PollError::Modbus { block: 2, error }))?;
        let state_of_charge_raw =
            vendor::word(&registers, SOC_REGISTER).map_err(VendorError::Condition)?;
        let soc = self
            .signal(SOC_AT)
            .ok_or(VendorError::Poll(PollError::Signals))?;
        let soc_block = self.state_of_charge.block();
        declared = declared.saturating_add(
            vendor::publish_declared(soc_block, &registers, SOC_AT, soc, now, store)
                .map_err(VendorError::Poll)?,
        );

        let registers = modbus::read(port, battery.read(self.address), timing, &mut buf)
            .await
            .map_err(|error| VendorError::Poll(PollError::Modbus { block: 3, error }))?;
        let battery_current_raw =
            vendor::low_first(&registers, BATTERY_CURRENT).map_err(VendorError::Condition)?;
        cells = cells.saturating_add(
            vendor::publish(battery, &registers, cells, signal, now, store)
                .map_err(VendorError::Poll)?,
        );
        let current = self
            .signal(CURRENT_AT)
            .ok_or(VendorError::Poll(PollError::Signals))?;
        let current_block = self.battery_current.block();
        declared = declared.saturating_add(
            vendor::publish_declared(current_block, &registers, CURRENT_AT, current, now, store)
                .map_err(VendorError::Poll)?,
        );
        let written = cells.saturating_add(declared);

        let registers = modbus::read(port, Status::read(self.address), timing, &mut buf)
            .await
            .map_err(VendorError::Conditions)?;
        let status = Status::from_registers(&registers).map_err(VendorError::Condition)?;
        Ok(Report {
            polled: Polled { written },
            conditions: Words {
                status,
                state_of_charge_raw,
                battery_current_raw,
            },
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modbus::tests::{Scripted, TIMING, register_reply};
    use crate::modbus::{Exception, FRAME_BYTES, ModbusError, ReplyError, parse};
    use embassy_futures::block_on;
    use km43::Validity;
    use o89_core::{ChargeSource, Ineligible, Limits, Millis};

    const FIRST: u16 = 60;
    /// Where each declared reading publishes.
    const SOC: u16 = FIRST + 7;
    const CURRENT: u16 = FIRST + 8;

    /// Both readings declared, as a unit qualified on the bench would be.
    const DECLARED: (StateOfCharge, BatteryCurrent) = (
        StateOfCharge::WholePercent,
        BatteryCurrent::SignedPositiveCharging,
    );
    const UNDECLARED: (StateOfCharge, BatteryCurrent) =
        (StateOfCharge::Unsupported, BatteryCurrent::Unsupported);

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn address() -> Address {
        Address::new(1).unwrap()
    }

    fn charger((soc, current): (StateOfCharge, BatteryCurrent)) -> Charger {
        Charger::new(address(), id(FIRST), soc, current).unwrap()
    }

    fn store() -> Signals<9> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        for n in FIRST..=CURRENT {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    /// Hand-built replies to the five reads, in poll order: 48.00 V, 5.00 A
    /// and 240.00 W from the array; 12.80 V, 1.50 A and 19.20 W to the load;
    /// 64 %; 12.30 V and −3.25 A at the battery; boost with no fault. Not a
    /// bench capture.
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
        let [pv, load, battery] = BLOCKS.map(|block| block.read(address()).encode());
        let soc = SOC_WHOLE_BLOCK.read(address()).encode();
        [pv, load, soc, battery, Status::read(address()).encode()]
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
        declared: (StateOfCharge, BatteryCurrent),
        words: &[&[u16]; 5],
        store: &mut Signals<9>,
    ) -> Result<Report<Words>, VendorError<u8>> {
        let (echoes, replies) = (echoes(), frames(words));
        let bursts = interleaved(&echoes, &replies);
        let mut port = Scripted::new(&bursts);
        let report = block_on(charger(declared).poll(&mut port, TIMING, Tick::ZERO, store));
        assert_eq!(port.next, 10, "every read and its reply were heard");
        report
    }

    fn poll_prefix(
        declared: (StateOfCharge, BatteryCurrent),
        bursts: &[&[u8]],
        store: &mut Signals<9>,
    ) -> Result<Report<Words>, VendorError<u8>> {
        let mut port = Scripted::new(bursts);
        block_on(charger(declared).poll(&mut port, TIMING, Tick::ZERO, store))
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
    fn f_052_a_poll_publishes_every_reading_with_its_declared_provenance() {
        let mut store = store();
        let report = poll_as(DECLARED, &WORDS, &mut store).unwrap();
        assert_eq!(report.polled.written, Charger::SIGNALS);
        assert_eq!(
            report.conditions,
            Words {
                status: Status {
                    stage: ChargeStage::Boost,
                    fault: false
                },
                state_of_charge_raw: 64,
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
                (Some(12_300), measured),
                (Some(640), Provenance::Estimated),
                (Some(-3_250), measured),
            ]
        );
    }

    #[test]
    fn f_052_a_declared_state_of_charge_is_an_estimate_counted_only_refuses() {
        let mut store = store();
        let _ = poll_as(DECLARED, &WORDS, &mut store).unwrap();
        assert_eq!(
            store.current(id(SOC), Tick::ZERO, ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Provenance(Provenance::Estimated))
        );
        let eligible = store
            .current(
                id(SOC),
                Tick::ZERO,
                ChargeSource::EstimateAccepted.accepts(),
            )
            .unwrap();
        assert_eq!(
            (eligible.value(), eligible.provenance()),
            (640, Provenance::Estimated)
        );
    }

    #[test]
    fn readings_nobody_has_declared_publish_unsupported_and_keep_their_raw_words() {
        let mut store = store();
        let report = poll_as(UNDECLARED, &WORDS, &mut store).unwrap();
        assert_eq!(report.polled.written, Charger::SIGNALS);
        assert_eq!(report.conditions.state_of_charge_raw, 64);
        assert_eq!(report.conditions.battery_current_raw, 0xFFFF_FEBB);
        for signal in [SOC, CURRENT] {
            let seen = store.sample(id(signal), Tick::ZERO).unwrap();
            assert_eq!(seen.value(), None, "{signal}");
            assert_eq!(seen.q.validity_of(), Validity::Unsupported, "{signal}");
            assert!(
                store
                    .current(
                        id(signal),
                        Tick::ZERO,
                        ChargeSource::EstimateAccepted.accepts()
                    )
                    .is_err()
            );
        }
        // The map's cells beside them publish as ever.
        assert_eq!(published(&store)[6].0, Some(12_300));
    }

    #[test]
    fn p_185_the_same_state_of_charge_word_reads_as_its_declaration_says_and_past_full_is_refused()
    {
        // A raw 50 is 50 % in whole percent and 0.50 % in hundredths: no
        // range tells the two apart, which is why the unit's is declared.
        let current = BatteryCurrent::Unsupported;
        for (declared, raw, expected) in [
            (StateOfCharge::WholePercent, 50u16, Some(500)),
            (StateOfCharge::Hundredths, 50, Some(5)),
            (StateOfCharge::WholePercent, 0, Some(0)),
            (StateOfCharge::WholePercent, 100, Some(1000)),
            (StateOfCharge::WholePercent, 101, None),
            (StateOfCharge::Hundredths, 10_000, Some(1000)),
            // Hundredths round to the registry's tenths, half away from zero:
            // 100.04 % is 100.0 %, and 100.05 % is past full.
            (StateOfCharge::Hundredths, 10_004, Some(1000)),
            (StateOfCharge::Hundredths, 10_005, None),
        ] {
            let mut store = store();
            let mut words = WORDS;
            let soc = [raw];
            words[2] = &soc;
            let report = poll_as((declared, current), &words, &mut store).unwrap();
            assert_eq!(report.conditions.state_of_charge_raw, raw);
            let seen = store.sample(id(SOC), Tick::ZERO).unwrap();
            assert_eq!(seen.value(), expected, "{declared:?} {raw}");
            match expected {
                Some(_) => assert_eq!(seen.q.provenance_of(), Provenance::Estimated),
                None => assert_eq!(seen.q.validity_of(), Validity::OutOfRange),
            }
        }
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
            let report = poll_as(DECLARED, &words, &mut store).unwrap();
            assert_eq!(
                report.conditions.battery_current_raw,
                u32::from(low) | (u32::from(high) << 16)
            );
            let seen = store.sample(id(CURRENT), Tick::ZERO).unwrap();
            assert_eq!(seen.value(), expected, "{high:#06x}{low:04x}");
            match expected {
                Some(_) => assert_eq!(seen.q.provenance_of(), Provenance::Measured),
                None => assert_eq!(seen.q.validity_of(), Validity::OutOfRange),
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
            let report = poll_as(UNDECLARED, &words, &mut store).unwrap();
            assert_eq!(
                report.conditions.status,
                Status { stage, fault },
                "{word:#06x}"
            );
        }
    }

    #[test]
    fn f_050_a_malformed_reply_stops_the_poll_and_keeps_what_came_before() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let mut bursts = interleaved(&echoes, &replies);
        // The state of charge's reply carries two registers where one was
        // asked.
        let (wrong, wrong_len) = register_reply(1, 0x04, &[64, 0]);
        bursts[5] = &wrong[..wrong_len];
        assert_eq!(
            poll_prefix(DECLARED, &bursts[..6], &mut store),
            Err(VendorError::Poll(PollError::Modbus {
                block: 2,
                error: ModbusError::Reply(ReplyError::ByteCount(4))
            }))
        );
        let seen = published(&store);
        assert_eq!(seen[5].0, Some(192));
        // The state of charge was never read: it has no value, not zero.
        let soc = store.sample(id(SOC), Tick::ZERO).unwrap();
        assert_eq!(soc.value(), None);
        assert_eq!(soc.q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn a_model_without_a_register_answers_with_an_exception_and_its_readings_stay_absent() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let mut bursts = interleaved(&echoes, &replies);
        // Built by hand: 0x331A refused with illegal data address.
        let refusal = [0x01, 0x84, 0x02, 0xC2, 0xC1];
        bursts[7] = &refusal;
        assert_eq!(
            poll_prefix(DECLARED, &bursts[..8], &mut store),
            Err(VendorError::Poll(PollError::Modbus {
                block: 3,
                error: ModbusError::Reply(ReplyError::Exception(Exception::IllegalDataAddress))
            }))
        );
        let seen = published(&store);
        assert_eq!(seen[7].0, Some(640));
        assert_eq!((seen[6].0, seen[8].0), (None, None));
    }

    #[test]
    fn a_failed_status_read_leaves_every_signal_written_and_the_words_unknown() {
        let mut store = store();
        let (echoes, replies) = (echoes(), frames(&WORDS));
        let bursts = interleaved(&echoes, &replies);
        // The status read's echo, and nothing behind it.
        assert_eq!(
            poll_prefix(DECLARED, &bursts[..9], &mut store),
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

    #[test]
    fn a_charger_s_signals_cover_every_reading_and_are_refused_past_the_top() {
        let charger = charger(UNDECLARED);
        assert_eq!(charger.signal(0), Some(id(FIRST)));
        assert_eq!(charger.signal(8), Some(id(CURRENT)));
        assert_eq!(charger.signal(9), None);
        assert_eq!(MAP.cells().count(), SOC_AT);
        let (soc, current) = UNDECLARED;
        assert!(Charger::new(address(), id(0xFFF7), soc, current).is_some());
        assert_eq!(Charger::new(address(), id(0xFFF8), soc, current), None);
    }

    #[test]
    fn every_map_cell_has_its_component_role_in_the_map_s_order() {
        let registers: [u16; 7] = ROLES.map(|(register, _)| register);
        assert!(MAP.cells().map(|cell| cell.register).eq(registers));
        assert!(
            ROLES[..3]
                .iter()
                .all(|(_, role)| *role == ComponentRole::MPPT_TRACKER)
        );
        assert_eq!(ROLES[6].1, ComponentRole::BATTERY_BANK);
    }
}
