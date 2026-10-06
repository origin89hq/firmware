//! VE.Direct text mode, receive only: a Victron product's blocks, checked,
//! and the readings in them.
//!
//! The protocol is Victron's *VE.Direct Protocol*, version 3.34. A product
//! sends a block about once a second, each field as `\r\n`, a label, a tab
//! and a value in ASCII, and each block ends with a `Checksum` field whose
//! one-byte value brings the block's byte sum to zero modulo 256. A product
//! may interleave asynchronous HEX messages, `:` to `\n`, even inside a
//! block; they are skipped and are not part of the sum.
//!
//! The [`Parser`] takes the stream a byte at a time and holds at most one
//! block. The label, value and field limits are the ones the document's
//! implementation guidelines give, and anything past one refuses the
//! block. A block is accepted only when it begins right after a `Checksum`
//! field the parser saw end, so a stream joined mid-block, or a block
//! refused for its shape, is never decoded from the middle: the parser
//! hunts for the next block boundary first. A checksum that does not come
//! to zero refuses the block and keeps the boundary, because the `Checksum`
//! field still ended it. A block with one corruption the sum cannot see
//! (a one-in-256 chance for random damage) is accepted; that is the
//! protocol's limit, not something the parser can recover.
//!
//! A verified [`Frame`] keeps the raw text of each field the controller
//! reads. [`publish`] writes the battery voltage, battery current, panel
//! power, charge state and yields into the store with the provenance their
//! kinds carry. A charge state is a KM43 charge-stage member where one
//! names it, and `unnamed_state` with its raw code raised otherwise
//! (P-164); a yield is a DC energy total in Wh, `reset` when it falls
//! (P-259). The error is never a signal: [`VendorError::raise`] gives the
//! concern it is, its condition, severity and Victron code. Raising it in
//! the concern table is the device's, with the subject the site gives it.
//!
//! Nothing here can transmit: the driver reads through a
//! [`Listener`](crate::port::Listener), which has no send. The self-test's
//! line settings, 19200 8N1, are the controller port's to configure, with
//! the pull-up policy per revision (F-051).

use km43::{
    ChargeStage, Condition, Dialect, Id, Provenance, Severity, SignalDomain, Validity, VendorCode,
    VendorNamespace,
};
use o89_core::{Counter, Millis, Observation, SignalError, Signals, Tick};

use crate::dialect::{Kind, Plausible};
use crate::port::{Burst, Ended, Listener, PortFault};

/// The longest label a field may carry, from the protocol document's
/// implementation guidelines. A longer one refuses the block.
pub const LABEL_BYTES: usize = 9;
/// The longest value a field may carry, from the same guidelines. A longer
/// one refuses the block.
pub const VALUE_BYTES: usize = 33;
/// The most fields in one block before its `Checksum`, from the same
/// guidelines (raised from 18 to 22 in version 3.28). One more refuses the
/// block.
pub const BLOCK_FIELDS: usize = 22;
/// The longest HEX message skipped, in bytes after its `:`. Not a figure
/// from Victron: it bounds how long the parser waits for a HEX message's
/// `\n` before treating the stream as lost and hunting for the next block.
pub const HEX_BYTES: usize = 128;
/// What [`listen`] receives into, per call. A block longer than this spans
/// several receives, which the parser joins.
pub const BURST_BYTES: usize = 64;

/// The KM43 dialect a VE.Direct text port speaks.
pub const DIALECT: Dialect = Dialect::VE_DIRECT_TEXT;

/// The label of the field that ends every block.
const CHECKSUM: &[u8] = b"Checksum";

/// A field the controller reads, by its VE.Direct label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Field {
    /// `V`: main (battery) voltage, mV.
    BatteryVoltage,
    /// `I`: main (battery) current, mA, positive into the battery.
    BatteryCurrent,
    /// `PPV`: panel power, W.
    PanelPower,
    /// `CS`: state of operation.
    ChargeState,
    /// `ERR`: error code.
    Error,
    /// `H19`: yield total, user resettable, 0.01 kWh.
    YieldTotal,
    /// `H20`: yield today, 0.01 kWh.
    YieldToday,
    /// `H22`: yield yesterday, 0.01 kWh.
    YieldYesterday,
}

/// How many [`Field`]s there are.
const FIELDS: usize = 8;

impl Field {
    /// Every field, in declaration order.
    pub const ALL: [Self; FIELDS] = [
        Self::BatteryVoltage,
        Self::BatteryCurrent,
        Self::PanelPower,
        Self::ChargeState,
        Self::Error,
        Self::YieldTotal,
        Self::YieldToday,
        Self::YieldYesterday,
    ];

    /// The label on the wire.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::BatteryVoltage => b"V",
            Self::BatteryCurrent => b"I",
            Self::PanelPower => b"PPV",
            Self::ChargeState => b"CS",
            Self::Error => b"ERR",
            Self::YieldTotal => b"H19",
            Self::YieldToday => b"H20",
            Self::YieldYesterday => b"H22",
        }
    }

    /// The field `label` names, or `None` for one the controller does not
    /// read.
    #[must_use]
    pub fn from_label(label: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.label() == label)
    }

    /// Its position in [`Field::ALL`].
    const fn index(self) -> usize {
        match self {
            Self::BatteryVoltage => 0,
            Self::BatteryCurrent => 1,
            Self::PanelPower => 2,
            Self::ChargeState => 3,
            Self::Error => 4,
            Self::YieldTotal => 5,
            Self::YieldToday => 6,
            Self::YieldYesterday => 7,
        }
    }
}

/// Up to `N` bytes of a field, as they came off the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    const EMPTY: Self = Self {
        bytes: [0; N],
        len: 0,
    };

    /// The bytes held.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    /// Append `byte`, or `Err` when `N` are already held.
    fn push(&mut self, byte: u8) -> Result<(), ()> {
        let slot = self.bytes.get_mut(self.len).ok_or(())?;
        *slot = byte;
        self.len = self.len.checked_add(1).ok_or(())?;
        Ok(())
    }

    const fn clear(&mut self) {
        self.len = 0;
    }
}

/// A field's value text.
pub type Value = Text<VALUE_BYTES>;

/// A value whose text is not the number its field carries. The raw text is
/// still on the [`Frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an unreadable value is a reading that was not taken"]
pub struct Malformed {
    /// The field.
    pub field: Field,
    /// What is wrong with its text.
    pub why: Unreadable,
}

/// Why a field's text is not its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Unreadable {
    /// Not an optionally negative decimal integer, such as `---` or `13.2`.
    NotANumber,
    /// A decimal integer outside what the field's type holds, `i64` at
    /// most.
    OutOfRange,
}

/// The state of operation, as the protocol document's `CS` table lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChargeState {
    /// 0.
    Off,
    /// 1, an inverter's load search.
    LowPower,
    /// 2.
    Fault,
    /// 3.
    Bulk,
    /// 4.
    Absorption,
    /// 5.
    Float,
    /// 6.
    Storage,
    /// 7, manual.
    Equalize,
    /// 9.
    Inverting,
    /// 11.
    PowerSupply,
    /// 245.
    StartingUp,
    /// 246.
    RepeatedAbsorption,
    /// 247, auto equalize or recondition.
    AutoEqualize,
    /// 248.
    BatterySafe,
    /// 252.
    ExternalControl,
    /// A code the table does not list, kept as sent.
    Unlisted(u8),
}

impl ChargeState {
    /// The state `code` names.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Off,
            1 => Self::LowPower,
            2 => Self::Fault,
            3 => Self::Bulk,
            4 => Self::Absorption,
            5 => Self::Float,
            6 => Self::Storage,
            7 => Self::Equalize,
            9 => Self::Inverting,
            11 => Self::PowerSupply,
            245 => Self::StartingUp,
            246 => Self::RepeatedAbsorption,
            247 => Self::AutoEqualize,
            248 => Self::BatterySafe,
            252 => Self::ExternalControl,
            other => Self::Unlisted(other),
        }
    }

    /// The code on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::LowPower => 1,
            Self::Fault => 2,
            Self::Bulk => 3,
            Self::Absorption => 4,
            Self::Float => 5,
            Self::Storage => 6,
            Self::Equalize => 7,
            Self::Inverting => 9,
            Self::PowerSupply => 11,
            Self::StartingUp => 245,
            Self::RepeatedAbsorption => 246,
            Self::AutoEqualize => 247,
            Self::BatterySafe => 248,
            Self::ExternalControl => 252,
            Self::Unlisted(code) => code,
        }
    }

    /// The KM43 charge stage this state is, where one names it without
    /// loss (origin89hq/km43#3). Every other state, a repeated absorption
    /// or an auto equalize included, is `None`, never a nearest guess: it
    /// publishes `unnamed_state` and [`ChargeState::raise`] carries its code.
    #[must_use]
    pub const fn stage(self) -> Option<ChargeStage> {
        match self {
            Self::Off => Some(ChargeStage::Off),
            Self::Fault => Some(ChargeStage::Fault),
            Self::Bulk => Some(ChargeStage::Bulk),
            Self::Absorption => Some(ChargeStage::Absorption),
            Self::Float => Some(ChargeStage::Float),
            Self::Storage => Some(ChargeStage::Storage),
            Self::Equalize => Some(ChargeStage::Equalise),
            Self::LowPower
            | Self::Inverting
            | Self::PowerSupply
            | Self::StartingUp
            | Self::RepeatedAbsorption
            | Self::AutoEqualize
            | Self::BatterySafe
            | Self::ExternalControl
            | Self::Unlisted(_) => None,
        }
    }

    /// The code as KM43 carries it beside a concern: verbatim, in
    /// Victron's namespace.
    #[must_use]
    pub fn vendor_code(self) -> VendorCode {
        VendorCode {
            raw: u32::from(self.code()),
            vns: VendorNamespace::VICTRON,
        }
    }

    /// The concern this state raises: none for a stage KM43 names, and an
    /// `unnamed_state` at `info` carrying the raw code for one it does not
    /// (P-164).
    pub fn raise(self) -> Raise {
        match self.stage() {
            Some(_) => Raise::Nothing,
            None => Raise::Concern(Concern {
                cond: Condition::UNNAMED_STATE,
                sev: Severity::Info,
                code: self.vendor_code(),
            }),
        }
    }
}

/// The error code, as the protocol document's `ERR` table lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VendorError {
    /// 0.
    None,
    /// 2.
    BatteryVoltageTooHigh,
    /// 17.
    ChargerTemperatureTooHigh,
    /// 18.
    ChargerOverCurrent,
    /// 19, which the document says to ignore: it occurs at start-up and
    /// shutdown, and firmware 1.15 on stops reporting it.
    ChargerCurrentReversed,
    /// 20.
    BulkTimeLimitExceeded,
    /// 21, a sensor bias or a broken sensor; the document says it may be
    /// ignored for five minutes around start-up and shutdown.
    CurrentSensorIssue,
    /// 26.
    TerminalsOverheated,
    /// 28, dual converter models only.
    ConverterIssue,
    /// 33, solar panel.
    InputVoltageTooHigh,
    /// 34, solar panel.
    InputCurrentTooHigh,
    /// 38, from excessive battery voltage.
    InputShutdownBatteryVoltage,
    /// 39, from current flowing while off.
    InputShutdownCurrentWhileOff,
    /// 65.
    LostCommunication,
    /// 66.
    SynchronisedChargingConfiguration,
    /// 67.
    BmsConnectionLost,
    /// 68.
    NetworkMisconfigured,
    /// 116.
    FactoryCalibrationLost,
    /// 117.
    InvalidFirmware,
    /// 119.
    UserSettingsInvalid,
    /// A code the table does not list, kept as sent.
    Unlisted(u8),
}

impl VendorError {
    /// The error `code` names.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::None,
            2 => Self::BatteryVoltageTooHigh,
            17 => Self::ChargerTemperatureTooHigh,
            18 => Self::ChargerOverCurrent,
            19 => Self::ChargerCurrentReversed,
            20 => Self::BulkTimeLimitExceeded,
            21 => Self::CurrentSensorIssue,
            26 => Self::TerminalsOverheated,
            28 => Self::ConverterIssue,
            33 => Self::InputVoltageTooHigh,
            34 => Self::InputCurrentTooHigh,
            38 => Self::InputShutdownBatteryVoltage,
            39 => Self::InputShutdownCurrentWhileOff,
            65 => Self::LostCommunication,
            66 => Self::SynchronisedChargingConfiguration,
            67 => Self::BmsConnectionLost,
            68 => Self::NetworkMisconfigured,
            116 => Self::FactoryCalibrationLost,
            117 => Self::InvalidFirmware,
            119 => Self::UserSettingsInvalid,
            other => Self::Unlisted(other),
        }
    }

    /// The code as KM43 carries it beside a concern: verbatim, in
    /// Victron's namespace.
    #[must_use]
    pub fn vendor_code(self) -> VendorCode {
        VendorCode {
            raw: u32::from(self.code()),
            vns: VendorNamespace::VICTRON,
        }
    }

    /// The concern this error is, with its Victron code always beside it.
    ///
    /// The condition is the one the registry names exactly: a battery or
    /// panel voltage too high is over voltage, the charger or its terminals
    /// too hot is over temperature, the charger's over current is charge
    /// over current. Every other fault is `vendor fault`
    /// (origin89hq/km43#156), never a nearest guess.
    ///
    /// The severity is this table's, per code (origin89hq/km43#156):
    /// `protection` where the charger stops to protect itself or the bank,
    /// `fault` where something is broken, an unlisted code included,
    /// `warning` for a limit or a link that degrades charging, and `info`
    /// for code 19, which the document says to ignore.
    pub fn raise(self) -> Raise {
        let (cond, sev) = match self {
            Self::None => return Raise::Nothing,
            Self::BatteryVoltageTooHigh | Self::InputVoltageTooHigh => {
                (Condition::OVER_VOLTAGE, Severity::Protection)
            }
            Self::ChargerTemperatureTooHigh | Self::TerminalsOverheated => {
                (Condition::OVER_TEMPERATURE, Severity::Protection)
            }
            Self::ChargerOverCurrent => (Condition::CHARGE_OVER_CURRENT, Severity::Protection),
            Self::InputCurrentTooHigh
            | Self::InputShutdownBatteryVoltage
            | Self::InputShutdownCurrentWhileOff => (Condition::VENDOR_FAULT, Severity::Protection),
            Self::CurrentSensorIssue
            | Self::ConverterIssue
            | Self::BmsConnectionLost
            | Self::FactoryCalibrationLost
            | Self::InvalidFirmware
            | Self::UserSettingsInvalid
            | Self::Unlisted(_) => (Condition::VENDOR_FAULT, Severity::Fault),
            Self::BulkTimeLimitExceeded
            | Self::LostCommunication
            | Self::SynchronisedChargingConfiguration
            | Self::NetworkMisconfigured => (Condition::VENDOR_FAULT, Severity::Warning),
            Self::ChargerCurrentReversed => (Condition::VENDOR_FAULT, Severity::Info),
        };
        Raise::Concern(Concern {
            cond,
            sev,
            code: self.vendor_code(),
        })
    }

    /// The code on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::BatteryVoltageTooHigh => 2,
            Self::ChargerTemperatureTooHigh => 17,
            Self::ChargerOverCurrent => 18,
            Self::ChargerCurrentReversed => 19,
            Self::BulkTimeLimitExceeded => 20,
            Self::CurrentSensorIssue => 21,
            Self::TerminalsOverheated => 26,
            Self::ConverterIssue => 28,
            Self::InputVoltageTooHigh => 33,
            Self::InputCurrentTooHigh => 34,
            Self::InputShutdownBatteryVoltage => 38,
            Self::InputShutdownCurrentWhileOff => 39,
            Self::LostCommunication => 65,
            Self::SynchronisedChargingConfiguration => 66,
            Self::BmsConnectionLost => 67,
            Self::NetworkMisconfigured => 68,
            Self::FactoryCalibrationLost => 116,
            Self::InvalidFirmware => 117,
            Self::UserSettingsInvalid => 119,
            Self::Unlisted(code) => code,
        }
    }
}

/// What an `ERR` or a `CS` asks the controller to raise, in KM43's concern
/// registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an error the device reports is a concern nobody raised"]
pub enum Raise {
    /// `ERR 0`, or a stage KM43 names: nothing, and a concern the product
    /// had open from the same field clears.
    Nothing,
    /// A concern, which the device raises under the subject the site gives
    /// it.
    Concern(Concern),
}

/// A concern as the product reports it, short of its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Concern {
    /// The normalised condition.
    pub cond: Condition,
    /// Its band, which decides admission (P-169).
    pub sev: Severity,
    /// The product's own code, verbatim.
    pub code: VendorCode,
}

/// An energy the product counted, in its own unit of 0.01 kWh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CentiKilowattHours(pub u32);

impl CentiKilowattHours {
    /// The same energy in Wh, or `None` past `u32`.
    #[must_use]
    pub const fn watt_hours(self) -> Option<u32> {
        self.0.checked_mul(10)
    }
}

/// One block whose checksum came to zero: the raw text of each field the
/// controller reads that the block carried.
///
/// A product may send its fields over several blocks, so a field missing
/// from one block says nothing about the product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame {
    values: [Option<Value>; FIELDS],
}

impl Frame {
    const EMPTY: Self = Self {
        values: [None; FIELDS],
    };

    /// `field`'s text as the product sent it, if the block carried it.
    #[must_use]
    pub fn raw(&self, field: Field) -> Option<&Value> {
        self.values.get(field.index()).and_then(Option::as_ref)
    }

    /// `field`'s value as a decimal integer, if the block carried it.
    #[must_use]
    pub fn integer(&self, field: Field) -> Option<Result<i64, Malformed>> {
        self.raw(field)
            .map(|text| decimal(text.as_bytes()).map_err(|why| Malformed { field, why }))
    }

    /// `field`'s value as a `T`, if the block carried it.
    fn typed<T: TryFrom<i64>>(&self, field: Field) -> Option<Result<T, Malformed>> {
        self.integer(field).map(|value| {
            value.and_then(|value| {
                T::try_from(value).map_err(|_| Malformed {
                    field,
                    why: Unreadable::OutOfRange,
                })
            })
        })
    }

    /// `V`, in mV.
    #[must_use]
    pub fn battery_voltage(&self) -> Option<Result<i32, Malformed>> {
        self.typed(Field::BatteryVoltage)
    }

    /// `I`, in mA, positive into the battery.
    #[must_use]
    pub fn battery_current(&self) -> Option<Result<i32, Malformed>> {
        self.typed(Field::BatteryCurrent)
    }

    /// `PPV`, in W.
    #[must_use]
    pub fn panel_power(&self) -> Option<Result<i32, Malformed>> {
        self.typed(Field::PanelPower)
    }

    /// `CS`.
    #[must_use]
    pub fn charge_state(&self) -> Option<Result<ChargeState, Malformed>> {
        self.typed(Field::ChargeState)
            .map(|code| code.map(ChargeState::from_code))
    }

    /// `ERR`.
    #[must_use]
    pub fn error(&self) -> Option<Result<VendorError, Malformed>> {
        self.typed(Field::Error)
            .map(|code| code.map(VendorError::from_code))
    }

    /// `H19`, `H20` or `H22`; `None` for any other field.
    #[must_use]
    pub fn energy(&self, field: Field) -> Option<Result<CentiKilowattHours, Malformed>> {
        match field {
            Field::YieldTotal | Field::YieldToday | Field::YieldYesterday => {
                self.typed(field).map(|count| count.map(CentiKilowattHours))
            }
            Field::BatteryVoltage
            | Field::BatteryCurrent
            | Field::PanelPower
            | Field::ChargeState
            | Field::Error => None,
        }
    }
}

/// `text` as an optionally negative decimal integer.
fn decimal(text: &[u8]) -> Result<i64, Unreadable> {
    let (negative, digits) = match text {
        [b'-', rest @ ..] => (true, rest),
        rest => (false, rest),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Unreadable::NotANumber);
    }
    digits.iter().try_fold(0i64, |value, &digit| {
        let digit = i64::from(digit.checked_sub(b'0').ok_or(Unreadable::NotANumber)?);
        let step = value.checked_mul(10);
        let next = if negative {
            step.and_then(|step| step.checked_sub(digit))
        } else {
            step.and_then(|step| step.checked_add(digit))
        };
        next.ok_or(Unreadable::OutOfRange)
    })
}

/// Why a block was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused block is a second of readings that was not taken"]
pub enum Refused {
    /// The block's byte sum did not come to zero.
    Checksum,
    /// A label longer than [`LABEL_BYTES`].
    LabelTooLong,
    /// A value longer than [`VALUE_BYTES`].
    ValueTooLong,
    /// More than [`BLOCK_FIELDS`] fields before the `Checksum`.
    TooManyFields,
    /// A HEX message longer than [`HEX_BYTES`], or one carrying a byte that
    /// is not a hex digit.
    Hex,
    /// A field the controller reads, twice in one block.
    Duplicate(Field),
    /// A byte the text format cannot carry where it came: no `\r\n` before
    /// a field, an empty label, a control byte in a label or value.
    Framing,
}

/// Where the parser is in the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not at a known block boundary: reading labels only, to find the end
    /// of a `Checksum` field. `labelling` while a line's label is open.
    Hunt { labelling: bool },
    /// Hunting, and the next byte is a checksum byte, which ends the hunt.
    HuntChecksum,
    /// In a block, at the `\r` that begins a field.
    Cr,
    /// In a block, at the `\n` after it.
    Lf,
    /// In a block, reading a label.
    Label,
    /// In a block, reading a value.
    Value,
    /// In a block, the next byte is its checksum.
    Checksum,
}

/// A VE.Direct text-mode parser for one port.
///
/// Holds the block being read and nothing older: a block is decoded only
/// once its checksum comes to zero, and a refused block leaves nothing
/// behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parser {
    state: State,
    /// Bytes of the HEX message being skipped, while one is.
    hex: Option<usize>,
    /// The block's byte sum so far.
    sum: u8,
    /// Fields completed in the block, `Checksum` aside.
    fields: usize,
    label: Text<LABEL_BYTES>,
    value: Value,
    block: Frame,
    /// `block` was handed out by the last byte, and is cleared at the next.
    handed: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// A parser that has not seen a block boundary yet, and hunts for one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Hunt { labelling: false },
            hex: None,
            sum: 0,
            fields: 0,
            label: Text::EMPTY,
            value: Text::EMPTY,
            block: Frame::EMPTY,
            handed: false,
        }
    }

    /// Forget the block in progress and hunt for the next boundary: for
    /// when the line lost bytes, such as on a framing error.
    pub const fn resynchronise(&mut self) {
        *self = Self::new();
    }

    /// Take one byte. A block ends at its checksum byte: the verified frame,
    /// or why it was refused. Nothing is reported for what the parser skips
    /// while hunting.
    pub fn feed(&mut self, byte: u8) -> Option<Result<&Frame, Refused>> {
        if self.handed {
            self.block = Frame::EMPTY;
            self.handed = false;
        }
        if let Some(len) = self.hex {
            return match byte {
                b'\n' => {
                    self.hex = None;
                    None
                }
                digit if digit.is_ascii_hexdigit() && len < HEX_BYTES => {
                    self.hex = len.checked_add(1);
                    None
                }
                _ => self.lose(Refused::Hex, byte),
            };
        }
        let at_checksum = matches!(self.state, State::Checksum | State::HuntChecksum);
        if byte == b':' && !at_checksum {
            self.hex = Some(0);
            return None;
        }
        match self.state {
            State::Hunt { labelling } => {
                self.hunt(byte, labelling);
                None
            }
            State::HuntChecksum => {
                self.begin_block();
                None
            }
            State::Cr | State::Lf | State::Label | State::Value | State::Checksum => {
                self.sum = self.sum.wrapping_add(byte);
                self.in_block(byte)
            }
        }
    }

    /// A hunting byte: find a line whose label is `Checksum`.
    fn hunt(&mut self, byte: u8, labelling: bool) {
        self.state = match byte {
            b'\n' => {
                self.label.clear();
                State::Hunt { labelling: true }
            }
            b'\t' if labelling && self.label.as_bytes() == CHECKSUM => State::HuntChecksum,
            _ if labelling && self.label.push(byte).is_ok() => State::Hunt { labelling: true },
            _ => State::Hunt { labelling: false },
        };
    }

    /// At a block boundary: the next byte begins a block.
    const fn begin_block(&mut self) {
        self.state = State::Cr;
        self.sum = 0;
        self.fields = 0;
        self.block = Frame::EMPTY;
        self.handed = false;
    }

    /// A byte inside a block, already added to the sum.
    fn in_block(&mut self, byte: u8) -> Option<Result<&Frame, Refused>> {
        match (self.state, byte) {
            (State::Cr, b'\r') => self.state = State::Lf,
            (State::Lf, b'\n') => {
                self.label.clear();
                self.state = State::Label;
            }
            (State::Label, b'\t') => {
                let label = self.label.as_bytes();
                if label.is_empty() {
                    return self.lose(Refused::Framing, byte);
                }
                if label == CHECKSUM {
                    self.state = State::Checksum;
                } else {
                    self.value.clear();
                    self.state = State::Value;
                }
            }
            (State::Label, 0x21..=0x7E) => {
                if self.label.push(byte).is_err() {
                    return self.lose(Refused::LabelTooLong, byte);
                }
            }
            (State::Value, b'\r') => {
                if let Err(refused) = self.close_field() {
                    return self.lose(refused, byte);
                }
                self.state = State::Lf;
            }
            (State::Value, 0x20..=0x7E) => {
                if self.value.push(byte).is_err() {
                    return self.lose(Refused::ValueTooLong, byte);
                }
            }
            (State::Checksum, _) => {
                if self.sum != 0 {
                    self.begin_block();
                    return Some(Err(Refused::Checksum));
                }
                // The frame stays until the next byte, so it can be handed
                // out; `feed` clears it then.
                self.state = State::Cr;
                self.sum = 0;
                self.fields = 0;
                self.handed = true;
                return Some(Ok(&self.block));
            }
            (
                State::Cr
                | State::Lf
                | State::Label
                | State::Value
                | State::Hunt { .. }
                | State::HuntChecksum,
                _,
            ) => return self.lose(Refused::Framing, byte),
        }
        None
    }

    /// Record the field just read.
    fn close_field(&mut self) -> Result<(), Refused> {
        if self.fields >= BLOCK_FIELDS {
            return Err(Refused::TooManyFields);
        }
        self.fields = self.fields.saturating_add(1);
        if let Some(field) = Field::from_label(self.label.as_bytes()) {
            let slot = self
                .block
                .values
                .get_mut(field.index())
                .ok_or(Refused::Framing)?;
            if slot.is_some() {
                return Err(Refused::Duplicate(field));
            }
            *slot = Some(self.value);
        }
        Ok(())
    }

    /// Give up the block in progress for `why`, at `byte`, and hunt.
    /// Reported once: a parser already hunting has nothing to refuse. A
    /// `\n` refused where a `\r` was due still begins a line, so the hunt
    /// reads the label after it: that label may be the refused block's own
    /// `Checksum`.
    fn lose(&mut self, why: Refused, byte: u8) -> Option<Result<&Frame, Refused>> {
        let hunting = matches!(self.state, State::Hunt { .. } | State::HuntChecksum);
        self.resynchronise();
        if byte == b'\n' {
            self.state = State::Hunt { labelling: true };
        }
        if hunting { None } else { Some(Err(why)) }
    }
}

/// The store signals a port's readings publish as, each chosen by the
/// configuration; a field with no signal is not written.
///
/// Every field but `ERR` can have one: an error is a concern
/// ([`VendorError::raise`]), never a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Assignment {
    /// `V`.
    pub battery_voltage: Option<Id>,
    /// `I`.
    pub battery_current: Option<Id>,
    /// `PPV`.
    pub panel_power: Option<Id>,
    /// `CS`.
    pub charge_state: Option<Id>,
    /// `H19`.
    pub yield_total: Option<Id>,
    /// `H20`.
    pub yield_today: Option<Id>,
    /// `H22`.
    pub yield_yesterday: Option<Id>,
}

/// An [`Assignment`] with no two fields on one signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Channels(Assignment);

impl Channels {
    /// The assignment, or `None` when two fields are on the same signal.
    /// Keeping them apart from other devices' signals is the
    /// configuration's to check.
    #[must_use]
    pub fn new(assignment: Assignment) -> Option<Self> {
        let channels = Self(assignment);
        let clash = PUBLISHED.iter().enumerate().any(|(at, a)| {
            PUBLISHED.iter().skip(at.saturating_add(1)).any(|b| {
                let sig = channels.signal(a.field);
                sig.is_some() && sig == channels.signal(b.field)
            })
        });
        (!clash).then_some(channels)
    }

    /// The signal `field` publishes as; `None` when unassigned, and always
    /// for `ERR`.
    #[must_use]
    pub const fn signal(&self, field: Field) -> Option<Id> {
        match field {
            Field::BatteryVoltage => self.0.battery_voltage,
            Field::BatteryCurrent => self.0.battery_current,
            Field::PanelPower => self.0.panel_power,
            Field::ChargeState => self.0.charge_state,
            Field::YieldTotal => self.0.yield_total,
            Field::YieldToday => self.0.yield_today,
            Field::YieldYesterday => self.0.yield_yesterday,
            Field::Error => None,
        }
    }
}

/// What one port publishes: its [`Channels`], and the last total published
/// for each yield since boot, which P-259's judgement needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Publisher {
    channels: Channels,
    /// `H19`, `H20` and `H22`, in that order.
    totals: [Counter; 3],
}

impl Publisher {
    /// A port publishing through `channels`, with no total published yet.
    #[must_use]
    pub const fn new(channels: Channels) -> Self {
        Self {
            channels,
            totals: [Counter::NEW; 3],
        }
    }

    /// The signals it publishes as.
    #[must_use]
    pub const fn channels(&self) -> &Channels {
        &self.channels
    }

    /// The counter behind a yield; `None` for a field that is no total.
    fn total(&mut self, field: Field) -> Option<&mut Counter> {
        let at = match field {
            Field::YieldTotal => 0,
            Field::YieldToday => 1,
            Field::YieldYesterday => 2,
            Field::BatteryVoltage
            | Field::BatteryCurrent
            | Field::PanelPower
            | Field::ChargeState
            | Field::Error => return None,
        };
        self.totals.get_mut(at)
    }
}

/// How a field's text becomes the kind's integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// A present value in the vendor's unit, ten to `decade` of the kind's
    /// unit, within the range the vendor documents.
    Gauge {
        decade: i8,
        plausible: Option<Plausible>,
    },
    /// A running total in the vendor's unit, ten to `decade` of the kind's
    /// unit, judged against the last one published (P-259).
    Total { decade: i8 },
    /// `CS`, as a KM43 charge-stage member (P-164).
    Stage,
}

/// A field written to the store: its kind over its domain, the provenance
/// it carries, and how its text becomes the kind's integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Published {
    field: Field,
    kind: Kind,
    domain: SignalDomain,
    provenance: Provenance,
    encoding: Encoding,
}

/// The fields [`publish`] writes, each with the provenance its kind
/// accepts over its domain (F-052): a row that breaks
/// [`Published::admissible`] fails the build.
///
/// `V`, `I` and `PPV` are what the product's instrument reads, so
/// `measured`. `CS` is the state the charger says it is in, so `reported`.
/// The yields are totals the product keeps, so `counted`; the document
/// gives them in 0.01 kWh, ten times the kind's Wh. `H19` is the total the
/// user can reset, so since reset and not lifetime.
const PUBLISHED: [Published; 7] = [
    Published {
        field: Field::BatteryVoltage,
        kind: Kind::DcVoltage,
        domain: SignalDomain::Live,
        provenance: Provenance::Measured,
        encoding: Encoding::Gauge {
            decade: -3,
            // Unsigned on an MPPT (HEX protocol rev 18, 0xEDD5 `un16`) but
            // signed on a BMV (BMV-7xx HEX protocol, 0xED8D `sn16`): the
            // text field does not say which product sent it, so no bound.
            plausible: None,
        },
    },
    Published {
        field: Field::BatteryCurrent,
        kind: Kind::DcCurrent,
        domain: SignalDomain::Live,
        provenance: Provenance::Measured,
        encoding: Encoding::Gauge {
            decade: -3,
            // Signed: a battery discharges.
            plausible: None,
        },
    },
    Published {
        field: Field::PanelPower,
        kind: Kind::DcPower,
        domain: SignalDomain::Live,
        provenance: Provenance::Measured,
        encoding: Encoding::Gauge {
            decade: 0,
            // Only MPPT chargers send `PPV`, and their panel power is
            // unsigned (HEX protocol rev 18, 0xEDBC `un32`).
            plausible: Some(Plausible {
                low: 0,
                high: i32::MAX,
            }),
        },
    },
    Published {
        field: Field::ChargeState,
        kind: Kind::ChargeStage,
        domain: SignalDomain::Live,
        provenance: Provenance::Reported,
        encoding: Encoding::Stage,
    },
    Published {
        field: Field::YieldTotal,
        kind: Kind::DcEnergy,
        domain: SignalDomain::SinceReset,
        provenance: Provenance::Counted,
        encoding: Encoding::Total { decade: 1 },
    },
    Published {
        field: Field::YieldToday,
        kind: Kind::DcEnergy,
        domain: SignalDomain::Today,
        provenance: Provenance::Counted,
        encoding: Encoding::Total { decade: 1 },
    },
    Published {
        field: Field::YieldYesterday,
        kind: Kind::DcEnergy,
        domain: SignalDomain::Yesterday,
        provenance: Provenance::Counted,
        encoding: Encoding::Total { decade: 1 },
    },
];

// A table typo is a build error, never a reading published as
// `out_of_range` at runtime.
const _: () = {
    let [voltage, current, power, state, total, today, yesterday] = PUBLISHED;
    assert!(voltage.admissible() && current.admissible() && power.admissible());
    assert!(state.admissible());
    assert!(total.admissible() && today.admissible() && yesterday.admissible());
};

impl Published {
    /// Whether the row's kind carries its provenance over its domain, and
    /// its encoding fits the kind: a decade at or above the kind's scale,
    /// within the nine decades a rescale can span, a range that is not
    /// empty, and a stage only for the charge-stage kind.
    const fn admissible(self) -> bool {
        let encoding = match self.encoding {
            Encoding::Gauge { decade, plausible } => {
                let range = match plausible {
                    Some(range) => range.low <= range.high,
                    None => true,
                };
                self.decade_fits(decade) && range
            }
            Encoding::Total { decade } => self.decade_fits(decade),
            Encoding::Stage => matches!(self.kind, Kind::ChargeStage),
        };
        self.kind.accepts(self.domain).contains(self.provenance) && encoding
    }

    /// Whether `decade` is at or above the kind's scale, within the nine
    /// decades a rescale can span.
    const fn decade_fits(self, decade: i8) -> bool {
        let scale = self.kind.scale();
        decade >= scale && decade.abs_diff(scale) <= 9
    }

    /// `value`, in ten to `decade` of the kind's unit, at the kind's scale;
    /// `None` past `i32`.
    fn scaled(self, value: i64, decade: i8) -> Option<i32> {
        let scale = self.kind.scale();
        // `admissible` holds every published decade at or above its kind's
        // scale, at build time.
        let factor = if decade >= scale {
            10i64.checked_pow(u32::from(decade.abs_diff(scale)))
        } else {
            None
        };
        factor
            .and_then(|factor| value.checked_mul(factor))
            .and_then(|scaled| i32::try_from(scaled).ok())
    }

    /// What the frame says about this field, or `None` when it carried no
    /// such field, and the malformed text behind a value it could not read.
    ///
    /// A field present in a verified block always writes, so a value the
    /// product withdrew never leaves the last one current: a number too
    /// large for `i64` or for `i32` at the kind's scale, or outside the
    /// range the vendor documents, is `out_of_range` (P-185), and text that
    /// is no number is `sensor_fault`, the product reporting the reading
    /// bad. Victron documents `---` as a no-value pattern only for fields
    /// this driver does not publish. A total is judged by `total` (P-259);
    /// a charge state with no KM43 member is `unnamed_state` (P-164).
    fn observe(
        self,
        frame: &Frame,
        total: Option<Counter>,
    ) -> Option<(Observation, Option<Malformed>)> {
        let value = match frame.integer(self.field)? {
            Ok(value) => value,
            Err(malformed) => return Some((unreadable(malformed)?, Some(malformed))),
        };
        let seen = match self.encoding {
            Encoding::Gauge { decade, plausible } => match self
                .scaled(value, decade)
                .filter(|&value| plausible.is_none_or(|range| range.holds(value)))
            {
                Some(value) => Observation::value(value, self.provenance),
                None => Observation::missing(Validity::OutOfRange),
            },
            Encoding::Total { decade } => match (self.scaled(value, decade), total) {
                (Some(value), Some(counter)) => counter.judge(value, self.provenance),
                (None, _) | (_, None) => Observation::missing(Validity::OutOfRange),
            },
            Encoding::Stage => match u8::try_from(value).map(ChargeState::from_code) {
                Ok(state) => match state.stage() {
                    Some(member) => Observation::value(i32::from(member as u8), self.provenance),
                    None => Observation::missing(Validity::UnnamedState),
                },
                Err(_) => Observation::missing(Validity::OutOfRange),
            },
        };
        // KM43 refuses only a value without a provenance, which
        // `admissible` rules out, or a missing validity that carries one,
        // which no arm builds.
        Some((seen.ok()?, None))
    }
}

/// What a field whose text is not its number publishes: no value, and why.
fn unreadable(malformed: Malformed) -> Option<Observation> {
    let validity = match malformed.why {
        Unreadable::NotANumber => Validity::SensorFault,
        Unreadable::OutOfRange => Validity::OutOfRange,
    };
    Observation::missing(validity).ok()
}

/// Why a field of a verified frame did not publish a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a field without a reading is a reading that was not recorded"]
pub enum PublishError {
    /// Its text is not its number. Its signal was written with no value,
    /// `sensor_fault` or `out_of_range`, so the last reading is withdrawn.
    Malformed(Malformed),
    /// The store refused the write, and the signal keeps what it held.
    Store(SignalError),
}

/// What [`publish`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "what was published is what the store now says about the product"]
pub struct Written {
    /// Signals the store accepted a write for, with a value or without.
    pub count: usize,
    /// The first field that did not publish a reading, and why.
    pub first: Option<PublishError>,
}

/// Write the frame's `V`, `I`, `PPV`, `CS` and yields into `store` at
/// `now`, each to its signal in `publisher`'s channels, with the provenance
/// its kind carries.
///
/// A field the frame did not carry, or that has no signal, is not written:
/// a product sends its fields over several blocks. A field it carried
/// always writes, a reading or the reason there is none. A yield the store
/// accepts becomes the last total its next reading is judged against. Every
/// field is tried, and every write the store accepts stands. `ERR` is not
/// written; [`Frame::error`] and [`VendorError::raise`] say what it raises.
pub fn publish<const N: usize>(
    frame: &Frame,
    publisher: &mut Publisher,
    now: Tick,
    store: &mut Signals<N>,
) -> Written {
    let mut written = Written {
        count: 0,
        first: None,
    };
    for published in PUBLISHED {
        let Some(sig) = publisher.channels.signal(published.field) else {
            continue;
        };
        let total = publisher.total(published.field).map(|counter| *counter);
        let Some((seen, malformed)) = published.observe(frame, total) else {
            continue;
        };
        match store.write(sig, now, seen) {
            Ok(()) => {
                written.count = written.count.saturating_add(1);
                if let Some(counter) = publisher.total(published.field) {
                    counter.published(seen);
                }
                if let Some(malformed) = malformed {
                    written
                        .first
                        .get_or_insert(PublishError::Malformed(malformed));
                }
            }
            Err(error) => {
                written.first.get_or_insert(PublishError::Store(error));
            }
        }
    }
    written
}

/// What one [`listen`] heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "what a port heard is the product's presence"]
pub struct Heard {
    /// Blocks verified in this burst.
    pub blocks: usize,
    /// Blocks refused in this burst.
    pub refused: usize,
    /// Why the last block refused in this burst was.
    pub last_refusal: Option<Refused>,
    /// Signals the store accepted a write for.
    pub written: usize,
    /// The first field of a verified block that did not publish a reading,
    /// and why.
    pub unwritten: Option<PublishError>,
}

/// Why a listen heard nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a silent port is a product that is not heard"]
pub enum ListenError<E> {
    /// Nothing arrived within the wait. The parser keeps its place, since a
    /// product pauses between blocks; see [`listen`] for a pause inside
    /// one.
    Silent,
    /// The line reported an error; bytes may be lost, so the parser hunts
    /// for the next block.
    Line(E),
    /// The port reported a burst it cannot have received; the parser hunts.
    Adapter,
}

/// Receive one burst from `port`, waiting at most `within` for its first
/// byte, and parse it: each verified block is published into `store` at
/// `now` through `publisher` ([`publish`]), and handed to `on_block`, in
/// order, for its typed fields and what its `ERR` and `CS` raise.
///
/// One receive per call, so the caller's loop sets the pace. A block spread
/// over several bursts is joined by `parser`, which the caller keeps for
/// the port; a burst of [`BURST_BYTES`] can end several blocks, and each
/// reaches `on_block`.
///
/// Silence does not resynchronise the parser, so a block split by a pause
/// still decodes. A product that restarts or is swapped mid-block leaves a
/// partial block that the next block's bytes join; a repeated field or the
/// checksum refuses that join, except for the one-in-256 damage the sum
/// cannot see. A caller that knows the product changed, or that waits past
/// several block intervals with nothing heard, calls
/// [`Parser::resynchronise`].
pub async fn listen<L: Listener, const N: usize>(
    port: &mut L,
    parser: &mut Parser,
    within: Millis,
    publisher: &mut Publisher,
    now: Tick,
    store: &mut Signals<N>,
    mut on_block: impl FnMut(&Frame),
) -> Result<Heard, ListenError<L::Error>> {
    let mut buf = [0u8; BURST_BYTES];
    let len = match port.receive(&mut buf, within).await {
        Ok(Burst { len, ended }) => {
            let consistent = match ended {
                Ended::Gap => len > 0 && len < BURST_BYTES,
                Ended::Full => len == BURST_BYTES,
            };
            if !consistent {
                parser.resynchronise();
                return Err(ListenError::Adapter);
            }
            len
        }
        Err(PortFault::Timeout) => return Err(ListenError::Silent),
        Err(PortFault::Line(error)) => {
            parser.resynchronise();
            return Err(ListenError::Line(error));
        }
    };
    let mut heard = Heard {
        blocks: 0,
        refused: 0,
        last_refusal: None,
        written: 0,
        unwritten: None,
    };
    for &byte in buf.get(..len).unwrap_or(&[]) {
        match parser.feed(byte) {
            None => {}
            Some(Ok(frame)) => {
                heard.blocks = heard.blocks.saturating_add(1);
                let written = publish(frame, publisher, now, store);
                heard.written = heard.written.saturating_add(written.count);
                if let Some(error) = written.first {
                    heard.unwritten.get_or_insert(error);
                }
                on_block(frame);
            }
            Some(Err(why)) => {
                heard.refused = heard.refused.saturating_add(1);
                heard.last_refusal = Some(why);
            }
        }
    }
    Ok(heard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;
    use o89_core::Limits;

    /// A block built by hand in the shape of an MPPT charger's, from the
    /// field table of Victron's VE.Direct Protocol 3.34; not a capture. Its
    /// last byte, `\`, was worked out by hand to bring the sum to zero.
    const MPPT: &[u8] = b"\r\nPID\t0xA053\r\nFW\t159\r\nSER#\tHQ0000TEST\r\nV\t13250\r\nI\t-1500\
        \r\nVPV\t36420\r\nPPV\t48\r\nCS\t3\r\nMPPT\t2\r\nOR\t0x00000000\r\nERR\t0\r\nLOAD\tON\
        \r\nIL\t300\r\nH19\t10345\r\nH20\t12\r\nH21\t110\r\nH22\t34\r\nH23\t98\r\nHSDS\t17\
        \r\nChecksum\t\\";

    /// The end of an earlier block, which is where a parser finds its first
    /// boundary. Built by hand.
    const TAIL: &[u8] = b"\r\nChecksum\t\x42";

    /// An asynchronous HEX message in the protocol's shape, built by hand.
    const HEX: &[u8] = b":A0102000543\n";

    /// A byte buffer for building streams without an allocator.
    struct Bytes {
        buf: [u8; 4096],
        len: usize,
    }

    impl Bytes {
        fn new() -> Self {
            Self {
                buf: [0; 4096],
                len: 0,
            }
        }

        fn push(&mut self, bytes: &[u8]) -> &mut Self {
            let end = self.len.checked_add(bytes.len()).unwrap();
            self.buf[self.len..end].copy_from_slice(bytes);
            self.len = end;
            self
        }

        fn get(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    /// A block of `fields`, each `(label, value)`, with the checksum byte
    /// that brings its sum to zero.
    fn block(fields: &[(&[u8], &[u8])]) -> Bytes {
        let mut out = Bytes::new();
        for (label, value) in fields {
            out.push(b"\r\n").push(label).push(b"\t").push(value);
        }
        out.push(b"\r\nChecksum\t");
        let sum = out.get().iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        out.push(&[0u8.wrapping_sub(sum)]);
        out
    }

    /// A block whose checksum byte is `target`: a padding field whose value
    /// is chosen to make it so.
    fn block_ending_in(target: u8) -> Bytes {
        let head = b"\r\nV\t12000\r\nPAD\t";
        let rest = b"\r\nChecksum\t";
        let sum = head
            .iter()
            .chain(rest)
            .chain(&[target])
            .fold(0u8, |sum, b| sum.wrapping_add(*b));
        // Pad with printable bytes until the sum comes to zero: four
        // bytes from 0x20 to 0x7E cover every residue.
        let mut need = 0u8.wrapping_sub(sum).wrapping_sub(4 * 0x20);
        let mut pad = [0x20u8; 4];
        for byte in &mut pad {
            let add = need.min(0x7E - 0x20);
            *byte = byte.wrapping_add(add);
            need = need.wrapping_sub(add);
        }
        assert_eq!(need, 0, "four bytes cover every residue");
        let mut out = Bytes::new();
        out.push(head).push(&pad).push(rest).push(&[target]);
        assert_eq!(out.get().iter().fold(0u8, |s, b| s.wrapping_add(*b)), 0);
        out
    }

    /// Feed `bytes`, collecting up to eight outcomes.
    fn run(parser: &mut Parser, bytes: &[u8]) -> ([Option<Result<Frame, Refused>>; 8], usize) {
        let mut seen = [None; 8];
        let mut n = 0;
        for &byte in bytes {
            if let Some(outcome) = parser.feed(byte) {
                seen[n] = Some(outcome.copied());
                n = n.checked_add(1).unwrap();
            }
        }
        (seen, n)
    }

    /// The outcomes of feeding `bytes` to a new parser.
    fn outcomes(bytes: &[u8]) -> ([Option<Result<Frame, Refused>>; 8], usize) {
        run(&mut Parser::new(), bytes)
    }

    fn frame(outcome: Option<&Result<Frame, Refused>>) -> Frame {
        *outcome
            .expect("an outcome")
            .as_ref()
            .expect("a verified frame")
    }

    fn text(frame: &Frame, field: Field) -> &[u8] {
        frame.raw(field).expect("the field").as_bytes()
    }

    #[test]
    fn a_valid_block_decodes_every_field_the_controller_reads() {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 1);
        let got = frame(seen[0].as_ref());
        assert_eq!(got.battery_voltage(), Some(Ok(13_250)));
        assert_eq!(got.battery_current(), Some(Ok(-1_500)));
        assert_eq!(got.panel_power(), Some(Ok(48)));
        assert_eq!(got.charge_state(), Some(Ok(ChargeState::Bulk)));
        assert_eq!(got.error(), Some(Ok(VendorError::None)));
        assert_eq!(
            got.energy(Field::YieldTotal),
            Some(Ok(CentiKilowattHours(10_345)))
        );
        assert_eq!(
            got.energy(Field::YieldToday),
            Some(Ok(CentiKilowattHours(12)))
        );
        assert_eq!(
            got.energy(Field::YieldYesterday),
            Some(Ok(CentiKilowattHours(34)))
        );
        assert_eq!(got.energy(Field::PanelPower), None);
        assert_eq!(text(&got, Field::BatteryCurrent), b"-1500");
    }

    #[test]
    fn a_block_joined_mid_stream_is_never_decoded_from_the_middle() {
        // From the `V` field on: the head of the block was never heard.
        let from_v = MPPT.iter().position(|b| *b == b'V').unwrap();
        let mut stream = Bytes::new();
        stream.push(&MPPT[from_v..]).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 1, "{seen:?}");
        assert_eq!(frame(seen[0].as_ref()).battery_voltage(), Some(Ok(13_250)));

        // A stream that starts exactly on a block: the parser cannot know
        // it, so that first block is skipped and the next one decodes.
        let mut stream = Bytes::new();
        stream.push(MPPT).push(MPPT);
        assert_eq!(outcomes(stream.get()).1, 1);
        assert_eq!(outcomes(MPPT).1, 0);
    }

    #[test]
    fn a_bad_checksum_refuses_the_block_and_the_next_block_decodes() {
        let mut bad = Bytes::new();
        bad.push(MPPT);
        // 13250 mV becomes 13251: one bit, and the sum is off by one.
        let at = bad.get().windows(5).position(|w| w == b"13250").unwrap();
        bad.buf[at + 4] = b'1';
        let mut stream = Bytes::new();
        stream.push(TAIL).push(bad.get()).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2);
        assert_eq!(seen[0], Some(Err(Refused::Checksum)));
        assert_eq!(frame(seen[1].as_ref()).battery_voltage(), Some(Ok(13_250)));
    }

    #[test]
    fn a_bad_checksum_writes_nothing_to_the_store() {
        let mut bad = Bytes::new();
        bad.push(MPPT);
        let last = bad.len - 1;
        bad.buf[last] ^= 0x01;
        let mut stream = Bytes::new();
        stream.push(TAIL).push(bad.get());
        let (mut store, mut channels, ids) = site();
        let mut port = Chunked::new(stream.get(), BURST_BYTES);
        let mut parser = Parser::new();
        let mut refused = 0usize;
        while port.left() {
            let heard = block_on(listen(
                &mut port,
                &mut parser,
                WAIT,
                &mut channels,
                Tick::ZERO,
                &mut store,
                |_| {},
            ))
            .unwrap();
            assert_eq!(heard.blocks, 0);
            assert_eq!(heard.written, 0);
            refused = refused.checked_add(heard.refused).unwrap();
        }
        assert_eq!(refused, 1);
        for id in ids {
            let sample = store.sample(id, Tick::ZERO).unwrap();
            assert_eq!(sample.value(), None);
            assert_eq!(sample.q.validity_of(), Validity::Initialising);
        }
    }

    #[test]
    fn a_label_at_its_limit_is_read_and_one_past_it_refuses_the_block() {
        let at = block(&[(b"LABEL6789", b"1"), (b"V", b"12000")]);
        let past = block(&[(b"LABEL67890", b"1"), (b"V", b"12000")]);
        let mut stream = Bytes::new();
        stream.push(TAIL).push(at.get()).push(past.get()).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3, "{seen:?}");
        assert_eq!(frame(seen[0].as_ref()).battery_voltage(), Some(Ok(12_000)));
        assert_eq!(seen[1], Some(Err(Refused::LabelTooLong)));
        // The refused block's own `Checksum` ends the hunt.
        assert_eq!(frame(seen[2].as_ref()).battery_voltage(), Some(Ok(13_250)));
    }

    #[test]
    fn a_value_at_its_limit_is_read_and_one_past_it_refuses_the_block() {
        let long = [b'7'; VALUE_BYTES + 1];
        let at = block(&[(b"SER#", &long[..VALUE_BYTES]), (b"V", b"12000")]);
        let past = block(&[(b"SER#", &long), (b"V", b"12000")]);
        let mut stream = Bytes::new();
        stream.push(TAIL).push(at.get()).push(past.get()).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3, "{seen:?}");
        assert_eq!(frame(seen[0].as_ref()).battery_voltage(), Some(Ok(12_000)));
        assert_eq!(seen[1], Some(Err(Refused::ValueTooLong)));
        assert_eq!(frame(seen[2].as_ref()).battery_voltage(), Some(Ok(13_250)));
    }

    #[test]
    fn a_known_field_s_value_at_its_limit_is_kept_whole() {
        let long = [b'1'; VALUE_BYTES];
        let mut stream = Bytes::new();
        stream.push(TAIL).push(block(&[(b"V", &long)]).get());
        let got = frame(outcomes(stream.get()).0[0].as_ref());
        assert_eq!(text(&got, Field::BatteryVoltage), &long);
        // Thirty-three digits are no i32.
        assert_eq!(
            got.battery_voltage(),
            Some(Err(Malformed {
                field: Field::BatteryVoltage,
                why: Unreadable::OutOfRange,
            }))
        );
    }

    /// `n` distinct unknown fields and a `V`.
    fn fields(n: usize) -> Bytes {
        const LABELS: [&[u8]; 23] = [
            b"A0", b"A1", b"A2", b"A3", b"A4", b"A5", b"A6", b"A7", b"A8", b"A9", b"B0", b"B1",
            b"B2", b"B3", b"B4", b"B5", b"B6", b"B7", b"B8", b"B9", b"C0", b"C1", b"C2",
        ];
        let mut list: [(&[u8], &[u8]); 23] = [(b"", b""); 23];
        for (i, label) in LABELS.iter().take(n.checked_sub(1).unwrap()).enumerate() {
            list[i] = (label, b"1");
        }
        list[n.checked_sub(1).unwrap()] = (b"V", b"12000");
        block(&list[..n])
    }

    #[test]
    fn a_block_of_22_fields_is_read_and_one_of_23_is_refused() {
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(fields(BLOCK_FIELDS).get())
            .push(fields(BLOCK_FIELDS + 1).get())
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3, "{seen:?}");
        assert_eq!(frame(seen[0].as_ref()).battery_voltage(), Some(Ok(12_000)));
        assert_eq!(seen[1], Some(Err(Refused::TooManyFields)));
        assert_eq!(frame(seen[2].as_ref()).battery_voltage(), Some(Ok(13_250)));
    }

    #[test]
    fn an_unknown_field_is_ignored_without_disturbing_the_rest() {
        let with = block(&[
            (b"V", b"12800"),
            (b"FUTURE", b"anything at all, 123"),
            (b"I", b"250"),
        ]);
        let mut stream = Bytes::new();
        stream.push(TAIL).push(with.get());
        let got = frame(outcomes(stream.get()).0[0].as_ref());
        assert_eq!(got.battery_voltage(), Some(Ok(12_800)));
        assert_eq!(got.battery_current(), Some(Ok(250)));
        for field in [Field::PanelPower, Field::ChargeState, Field::Error] {
            assert_eq!(got.raw(field), None, "{field:?}");
        }
    }

    #[test]
    fn a_hex_message_anywhere_in_a_block_is_skipped_and_left_out_of_the_sum() {
        let checksum_byte = MPPT.len().checked_sub(1).unwrap();
        for at in 0..=MPPT.len() {
            if at == checksum_byte {
                // Where the checksum byte is due, `:` is that byte.
                continue;
            }
            let mut stream = Bytes::new();
            stream
                .push(TAIL)
                .push(&MPPT[..at])
                .push(HEX)
                .push(&MPPT[at..]);
            let (seen, n) = outcomes(stream.get());
            assert_eq!(n, 1, "at {at}: {seen:?}");
            assert_eq!(frame(seen[0].as_ref()), mppt());
        }
    }

    #[test]
    fn a_hex_message_while_hunting_does_not_end_the_hunt_or_start_a_block() {
        let mut stream = Bytes::new();
        stream
            .push(HEX)
            .push(b"\r\nCheck")
            .push(HEX)
            .push(b"sum\t\x42")
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 1, "{seen:?}");
        assert_eq!(frame(seen[0].as_ref()).panel_power(), Some(Ok(48)));
    }

    #[test]
    fn a_checksum_byte_that_is_a_colon_or_a_line_ending_is_the_checksum() {
        for target in [b':', b'\n', b'\r', b'\t', 0x00, 0xFF] {
            let mut stream = Bytes::new();
            stream
                .push(TAIL)
                .push(block_ending_in(target).get())
                .push(MPPT);
            let (seen, n) = outcomes(stream.get());
            assert_eq!(n, 2, "{target:#04x}: {seen:?}");
            assert_eq!(frame(seen[0].as_ref()).battery_voltage(), Some(Ok(12_000)));
            assert_eq!(frame(seen[1].as_ref()).battery_voltage(), Some(Ok(13_250)));
        }
        // The same when hunting: a `:` due as a checksum byte ends the hunt.
        let mut stream = Bytes::new();
        stream.push(b"\r\nChecksum\t:").push(MPPT);
        assert_eq!(outcomes(stream.get()).1, 1);
    }

    #[test]
    fn a_hex_message_at_its_limit_is_skipped_and_one_past_it_refuses_the_block() {
        let digits = [b'A'; HEX_BYTES + 1];
        let (head, tail) = MPPT.split_at(20);
        for (len, verified) in [(HEX_BYTES, true), (HEX_BYTES + 1, false)] {
            let mut stream = Bytes::new();
            stream
                .push(TAIL)
                .push(head)
                .push(b":")
                .push(&digits[..len])
                .push(b"\n")
                .push(tail)
                .push(MPPT);
            let (seen, n) = outcomes(stream.get());
            if verified {
                assert_eq!(n, 2, "{seen:?}");
                assert!(matches!(seen[0], Some(Ok(_))));
            } else {
                // The refused block's `Checksum` ends the hunt, and the next
                // block decodes.
                assert_eq!(n, 2, "{seen:?}");
                assert_eq!(seen[0], Some(Err(Refused::Hex)));
            }
            assert_eq!(frame(seen[1].as_ref()).battery_voltage(), Some(Ok(13_250)));
        }
    }

    #[test]
    fn a_hex_message_carrying_a_byte_that_is_no_hex_digit_refuses_the_block() {
        let (head, tail) = MPPT.split_at(20);
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(head)
            .push(b":A01G\n")
            .push(tail)
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2, "{seen:?}");
        assert_eq!(seen[0], Some(Err(Refused::Hex)));
        assert_eq!(frame(seen[1].as_ref()).battery_voltage(), Some(Ok(13_250)));
    }

    #[test]
    fn a_truncated_block_is_refused_and_the_block_after_it_decodes() {
        // Cut before `V`: the rest joins the next block, whose sum fails.
        let before_v = MPPT.windows(3).position(|w| w == b"\nV\t").unwrap();
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(&MPPT[..before_v - 1])
            .push(MPPT)
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2, "{seen:?}");
        assert_eq!(seen[0], Some(Err(Refused::Checksum)));
        assert!(matches!(seen[1], Some(Ok(_))));

        // Cut after `V`: the next block's `V` is a second one.
        let after_v = MPPT.windows(5).position(|w| w == b"13250").unwrap() + 5;
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(&MPPT[..after_v])
            .push(MPPT)
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2, "{seen:?}");
        assert_eq!(
            seen[0],
            Some(Err(Refused::Duplicate(Field::BatteryVoltage)))
        );
        assert!(matches!(seen[1], Some(Ok(_))));
    }

    #[test]
    fn garbage_and_control_bytes_refuse_the_block_and_the_stream_recovers() {
        let mut stream = Bytes::new();
        // Line noise before anything, which the hunt swallows.
        stream.push(&[0x00, 0xFF, 0x80, b'\t', b'\n', 0x7F, 0x13]);
        stream.push(TAIL);
        // A control byte inside a value.
        let mut noisy = Bytes::new();
        noisy.push(MPPT);
        let at = noisy.get().windows(5).position(|w| w == b"13250").unwrap();
        noisy.buf[at + 2] = 0x07;
        stream.push(noisy.get());
        // Noise between blocks: no `\r\n` where a field begins.
        stream.push(MPPT).push(b"x").push(MPPT).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 4, "{seen:?}");
        assert_eq!(seen[0], Some(Err(Refused::Framing)));
        assert!(matches!(seen[1], Some(Ok(_))));
        assert_eq!(seen[2], Some(Err(Refused::Framing)));
        assert!(matches!(seen[3], Some(Ok(_))));
    }

    #[test]
    fn an_empty_label_refuses_the_block() {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(b"\r\n\t1").push(MPPT).push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2, "{seen:?}");
        assert_eq!(seen[0], Some(Err(Refused::Framing)));
    }

    #[test]
    fn a_frame_handed_out_is_gone_before_the_next_block_s_fields() {
        let only_i = block(&[(b"I", b"-20")]);
        let empty = block(&[]);
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(MPPT)
            .push(only_i.get())
            .push(empty.get());
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3);
        let second = frame(seen[1].as_ref());
        assert_eq!(second.battery_current(), Some(Ok(-20)));
        assert_eq!(second.battery_voltage(), None, "nothing of the first block");
        assert_eq!(frame(seen[2].as_ref()), Frame::EMPTY);
    }

    #[test]
    fn a_value_that_is_not_a_decimal_integer_is_malformed_and_its_text_kept() {
        for bad in [&b""[..], b"-", b"12a", b" 12", b"1.5", b"--1", b"0x10"] {
            let mut stream = Bytes::new();
            stream
                .push(TAIL)
                .push(block(&[(b"V", bad), (b"CS", b"999")]).get());
            let got = frame(outcomes(stream.get()).0[0].as_ref());
            assert_eq!(
                got.battery_voltage(),
                Some(Err(Malformed {
                    field: Field::BatteryVoltage,
                    why: Unreadable::NotANumber
                })),
                "{bad:?}"
            );
            assert_eq!(text(&got, Field::BatteryVoltage), bad);
            // 999 is no u8 code.
            assert_eq!(
                got.charge_state(),
                Some(Err(Malformed {
                    field: Field::ChargeState,
                    why: Unreadable::OutOfRange
                }))
            );
        }
    }

    #[test]
    fn decimal_reads_the_edges_of_i64_and_refuses_one_past() {
        assert_eq!(decimal(b"9223372036854775807"), Ok(i64::MAX));
        assert_eq!(decimal(b"-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(decimal(b"9223372036854775808"), Err(Unreadable::OutOfRange));
        assert_eq!(
            decimal(b"-9223372036854775809"),
            Err(Unreadable::OutOfRange)
        );
        assert_eq!(decimal(b"0"), Ok(0));
        assert_eq!(decimal(b"-0"), Ok(0));
        assert_eq!(decimal(b"1-"), Err(Unreadable::NotANumber));
    }

    #[test]
    fn every_charge_state_and_error_code_survives_and_unlisted_ones_are_kept() {
        for code in 0..=u8::MAX {
            assert_eq!(ChargeState::from_code(code).code(), code);
            assert_eq!(VendorError::from_code(code).code(), code);
        }
        assert_eq!(ChargeState::from_code(8), ChargeState::Unlisted(8));
        assert_eq!(ChargeState::from_code(252), ChargeState::ExternalControl);
        assert_eq!(VendorError::from_code(1), VendorError::Unlisted(1));
        assert_eq!(
            VendorError::from_code(119),
            VendorError::UserSettingsInvalid
        );
        // The document lists fifteen states and twenty errors.
        let named = |f: fn(u8) -> bool| (0..=u8::MAX).filter(|c| f(*c)).count();
        assert_eq!(
            named(|c| !matches!(ChargeState::from_code(c), ChargeState::Unlisted(_))),
            15
        );
        assert_eq!(
            named(|c| !matches!(VendorError::from_code(c), VendorError::Unlisted(_))),
            20
        );
    }

    #[test]
    fn every_error_raises_its_exact_condition_or_vendor_fault_at_its_table_s_severity() {
        use Severity::{Fault, Info, Protection, Warning};
        // Victron's VE.Direct Protocol 3.34 `ERR` table, with this driver's
        // severity per code, written out rather than derived.
        let table = [
            (2, Condition::OVER_VOLTAGE, Protection),
            (17, Condition::OVER_TEMPERATURE, Protection),
            (18, Condition::CHARGE_OVER_CURRENT, Protection),
            (19, Condition::VENDOR_FAULT, Info),
            (20, Condition::VENDOR_FAULT, Warning),
            (21, Condition::VENDOR_FAULT, Fault),
            (26, Condition::OVER_TEMPERATURE, Protection),
            (28, Condition::VENDOR_FAULT, Fault),
            (33, Condition::OVER_VOLTAGE, Protection),
            (34, Condition::VENDOR_FAULT, Protection),
            (38, Condition::VENDOR_FAULT, Protection),
            (39, Condition::VENDOR_FAULT, Protection),
            (65, Condition::VENDOR_FAULT, Warning),
            (66, Condition::VENDOR_FAULT, Warning),
            (67, Condition::VENDOR_FAULT, Fault),
            (68, Condition::VENDOR_FAULT, Warning),
            (116, Condition::VENDOR_FAULT, Fault),
            (117, Condition::VENDOR_FAULT, Fault),
            (119, Condition::VENDOR_FAULT, Fault),
        ];
        for code in 0..=u8::MAX {
            let error = VendorError::from_code(code);
            let expected = match table.iter().find(|(c, _, _)| *c == code) {
                Some(&(_, cond, sev)) => Raise::Concern(Concern {
                    cond,
                    sev,
                    code: VendorCode {
                        raw: u32::from(code),
                        vns: VendorNamespace::VICTRON,
                    },
                }),
                None if code == 0 => Raise::Nothing,
                // A code the document does not list is still a fault the
                // product reports, and is admitted in the fault band.
                None => Raise::Concern(Concern {
                    cond: Condition::VENDOR_FAULT,
                    sev: Fault,
                    code: VendorCode {
                        raw: u32::from(code),
                        vns: VendorNamespace::VICTRON,
                    },
                }),
            };
            assert_eq!(error.raise(), expected, "{code}");
        }
    }

    #[test]
    fn p_164_every_state_km43_names_is_its_stage_and_every_other_raises_its_code() {
        let named = [
            (0, ChargeStage::Off),
            (2, ChargeStage::Fault),
            (3, ChargeStage::Bulk),
            (4, ChargeStage::Absorption),
            (5, ChargeStage::Float),
            (6, ChargeStage::Storage),
            (7, ChargeStage::Equalise),
        ];
        for code in 0..=u8::MAX {
            let state = ChargeState::from_code(code);
            if let Some(&(_, stage)) = named.iter().find(|(c, _)| *c == code) {
                assert_eq!(state.stage(), Some(stage), "{code}");
                assert_eq!(state.raise(), Raise::Nothing, "{code}");
            } else {
                // Repeated absorption, auto equalize, external control
                // and unlisted codes alike: never a nearest member.
                assert_eq!(state.stage(), None, "{code}");
                assert_eq!(
                    state.raise(),
                    Raise::Concern(Concern {
                        cond: Condition::UNNAMED_STATE,
                        sev: Severity::Info,
                        code: VendorCode {
                            raw: u32::from(code),
                            vns: VendorNamespace::VICTRON,
                        },
                    }),
                    "{code}"
                );
            }
        }
    }

    #[test]
    fn the_dialect_is_km43_s_ve_direct_text() {
        assert_eq!(DIALECT, Dialect::VE_DIRECT_TEXT);
        assert_eq!(DIALECT, Dialect(0x000b));
    }

    #[test]
    fn a_yield_in_hundredths_of_a_kilowatt_hour_is_ten_watt_hours() {
        assert_eq!(CentiKilowattHours(12).watt_hours(), Some(120));
        assert_eq!(CentiKilowattHours(0).watt_hours(), Some(0));
        assert_eq!(CentiKilowattHours(u32::MAX).watt_hours(), None);
    }

    #[test]
    fn every_field_s_label_finds_it_and_no_other_label_does() {
        for field in Field::ALL {
            assert_eq!(Field::from_label(field.label()), Some(field));
            assert_eq!(Field::ALL[field.index()], field);
        }
        for other in [&b"v"[..], b"VPV", b"H21", b"Checksum", b""] {
            assert_eq!(Field::from_label(other), None, "{other:?}");
        }
    }

    // The store.

    const WAIT: Millis = Millis::from_millis(1_500);

    /// A port publishing `V`, `I` and `PPV` only.
    fn vip(v: Option<Id>, i: Option<Id>, ppv: Option<Id>) -> Publisher {
        Publisher::new(
            Channels::new(Assignment {
                battery_voltage: v,
                battery_current: i,
                panel_power: ppv,
                ..Assignment::default()
            })
            .expect("distinct signals"),
        )
    }

    fn site() -> (Signals<4>, Publisher, [Id; 3]) {
        let ids = [10, 11, 12].map(|n| Id::new(n).unwrap());
        let mut store = Signals::<4>::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        for id in ids {
            store.register(id, limits).unwrap();
        }
        (store, vip(Some(ids[0]), Some(ids[1]), Some(ids[2])), ids)
    }

    fn mppt() -> Frame {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(MPPT);
        frame(outcomes(stream.get()).0[0].as_ref())
    }

    #[test]
    fn f_052_every_published_field_declares_a_provenance_its_kind_accepts() {
        use Encoding::{Gauge, Stage, Total};
        // Each row as the protocol document and KM43 give it, written out.
        let expect = [
            (
                Field::BatteryVoltage,
                SignalDomain::Live,
                Provenance::Measured,
                km43::Unit::Volt,
                Some(-3),
            ),
            (
                Field::BatteryCurrent,
                SignalDomain::Live,
                Provenance::Measured,
                km43::Unit::Ampere,
                Some(-3),
            ),
            (
                Field::PanelPower,
                SignalDomain::Live,
                Provenance::Measured,
                km43::Unit::Watt,
                Some(0),
            ),
            (
                Field::ChargeState,
                SignalDomain::Live,
                Provenance::Reported,
                km43::Unit::None,
                None,
            ),
            (
                Field::YieldTotal,
                SignalDomain::SinceReset,
                Provenance::Counted,
                km43::Unit::WattHour,
                Some(1),
            ),
            (
                Field::YieldToday,
                SignalDomain::Today,
                Provenance::Counted,
                km43::Unit::WattHour,
                Some(1),
            ),
            (
                Field::YieldYesterday,
                SignalDomain::Yesterday,
                Provenance::Counted,
                km43::Unit::WattHour,
                Some(1),
            ),
        ];
        assert_eq!(PUBLISHED.len(), expect.len());
        for (published, (field, domain, provenance, unit, decade)) in
            PUBLISHED.into_iter().zip(expect)
        {
            assert_eq!(published.field, field);
            assert_eq!(published.domain, domain, "{field:?}");
            assert_eq!(published.provenance, provenance, "{field:?}");
            assert_eq!(published.kind.unit(), unit, "{field:?}");
            assert!(
                published.kind.accepts(domain).contains(provenance),
                "{field:?}"
            );
            assert!(published.admissible(), "{field:?}");
            let got = match published.encoding {
                Gauge { decade, .. } | Total { decade } => Some(decade),
                Stage => None,
            };
            assert_eq!(got, decade, "{field:?}");
        }
        // The error is a concern, never a row.
        assert!(PUBLISHED.iter().all(|row| row.field != Field::Error));
    }

    #[test]
    fn f_052_a_row_whose_kind_refuses_its_provenance_or_encoding_is_inadmissible() {
        let [_, _, _, stage, total, ..] = PUBLISHED;
        // A yield claimed as measured, or published live.
        assert!(
            !Published {
                provenance: Provenance::Measured,
                ..total
            }
            .admissible()
        );
        assert!(
            !Published {
                domain: SignalDomain::Live,
                ..total
            }
            .admissible()
        );
        // A total in a unit finer than the kind's Wh.
        assert!(
            !Published {
                encoding: Encoding::Total { decade: -1 },
                ..total
            }
            .admissible()
        );
        // A stage counted, or decoded as a stage into a kind that is none.
        assert!(
            !Published {
                provenance: Provenance::Counted,
                ..stage
            }
            .admissible()
        );
        assert!(
            !Published {
                kind: Kind::DcEnergy,
                domain: SignalDomain::Today,
                provenance: Provenance::Counted,
                ..stage
            }
            .admissible()
        );
        assert!(total.admissible() && stage.admissible());
    }

    #[test]
    fn f_052_a_verified_block_writes_v_i_and_ppv_as_measured_at_their_kinds_scales() {
        let (mut store, mut channels, ids) = site();
        assert_eq!(
            publish(&mppt(), &mut channels, Tick::ZERO, &mut store),
            Written {
                count: 3,
                first: None
            }
        );
        let expect = [13_250, -1_500, 480];
        for (id, value) in ids.into_iter().zip(expect) {
            let sample = store.sample(id, Tick::ZERO).unwrap();
            assert_eq!(sample.value(), Some(value), "{id:?}");
            assert_eq!(sample.q.provenance_of(), Provenance::Measured);
            assert_eq!(sample.q.validity_of(), Validity::Ok);
        }
        // Only the fields with a signal are written.
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn a_field_with_no_signal_or_missing_from_the_block_is_not_written() {
        let (mut store, _, ids) = site();
        let mut only_voltage = vip(Some(ids[0]), None, None);
        assert_eq!(
            publish(&mppt(), &mut only_voltage, Tick::ZERO, &mut store),
            Written {
                count: 1,
                first: None
            }
        );
        let (mut store, mut channels, ids) = site();
        let mut stream = Bytes::new();
        stream.push(TAIL).push(block(&[(b"I", b"700")]).get());
        let only_current = frame(outcomes(stream.get()).0[0].as_ref());
        assert_eq!(
            publish(&only_current, &mut channels, Tick::ZERO, &mut store),
            Written {
                count: 1,
                first: None
            }
        );
        assert_eq!(store.sample(ids[1], Tick::ZERO).unwrap().value(), Some(700));
        for id in [ids[0], ids[2]] {
            let sample = store.sample(id, Tick::ZERO).unwrap();
            assert_eq!(sample.q.validity_of(), Validity::Initialising);
        }
    }

    #[test]
    fn a_panel_power_past_the_kind_s_scale_is_out_of_range_with_no_value() {
        let (mut store, mut channels, ids) = site();
        // 214 748 364 W is 2 147 483 640 at 0.1 W, which fits; one more
        // does not.
        for (watts, expected) in [
            (&b"214748364"[..], Some(2_147_483_640)),
            (b"214748365", None),
        ] {
            let mut stream = Bytes::new();
            stream.push(TAIL).push(block(&[(b"PPV", watts)]).get());
            let got = frame(outcomes(stream.get()).0[0].as_ref());
            let written = publish(&got, &mut channels, Tick::ZERO, &mut store);
            assert_eq!(written.count, 1);
            assert_eq!(written.first, None);
            let sample = store.sample(ids[2], Tick::ZERO).unwrap();
            assert_eq!(sample.value(), expected);
            if expected.is_none() {
                assert_eq!(sample.q.validity_of(), Validity::OutOfRange);
            }
        }
    }

    #[test]
    fn a_negative_panel_power_is_out_of_range_and_a_negative_voltage_is_not() {
        let (mut store, mut channels, ids) = site();
        for (fields, id, expected) in [
            (&[(&b"PPV"[..], &b"-1"[..])][..], ids[2], None),
            (&[(b"PPV", b"0")], ids[2], Some(0)),
            // A BMV's main voltage is signed in its HEX protocol.
            (&[(b"V", b"-1")], ids[0], Some(-1)),
        ] {
            let mut stream = Bytes::new();
            stream.push(TAIL).push(block(fields).get());
            let got = frame(outcomes(stream.get()).0[0].as_ref());
            let written = publish(&got, &mut channels, Tick::ZERO, &mut store);
            assert_eq!((written.count, written.first), (1, None), "{fields:?}");
            let sample = store.sample(id, Tick::ZERO).unwrap();
            assert_eq!(sample.value(), expected, "{fields:?}");
            if expected.is_none() {
                assert_eq!(sample.q.validity_of(), Validity::OutOfRange);
            }
        }
    }

    #[test]
    fn a_malformed_value_is_written_without_a_value_and_the_rest_are_written() {
        let (mut store, mut channels, ids) = site();
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(block(&[(b"V", b"13.2"), (b"I", b"10"), (b"PPV", b"5")]).get());
        let got = frame(outcomes(stream.get()).0[0].as_ref());
        assert_eq!(
            publish(&got, &mut channels, Tick::ZERO, &mut store),
            Written {
                count: 3,
                first: Some(PublishError::Malformed(Malformed {
                    field: Field::BatteryVoltage,
                    why: Unreadable::NotANumber
                }))
            }
        );
        let voltage = store.sample(ids[0], Tick::ZERO).unwrap();
        assert_eq!(voltage.value(), None);
        assert_eq!(voltage.q.validity_of(), Validity::SensorFault);
        assert_eq!(store.sample(ids[1], Tick::ZERO).unwrap().value(), Some(10));
        assert_eq!(store.sample(ids[2], Tick::ZERO).unwrap().value(), Some(50));
    }

    /// A good `V` at tick 0, then a verified block with `V` as `text` at
    /// tick 1: what the signal says at tick 1.
    fn after_good_voltage(text: &[u8]) -> (Option<i32>, Validity) {
        let (mut store, mut channels, ids) = site();
        let good = block(&[(b"V", b"13250")]);
        let then = block(&[(b"V", text)]);
        let mut stream = Bytes::new();
        stream.push(TAIL).push(good.get()).push(then.get());
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 2);
        let first = publish(
            &frame(seen[0].as_ref()),
            &mut channels,
            Tick::ZERO,
            &mut store,
        );
        assert_eq!(first.count, 1);
        let later = Tick::ZERO.after(Millis::from_millis(1_000)).unwrap();
        let _ = publish(&frame(seen[1].as_ref()), &mut channels, later, &mut store);
        let sample = store.sample(ids[0], later).unwrap();
        (sample.value(), sample.q.validity_of())
    }

    #[test]
    fn a_withdrawn_or_unreadable_voltage_invalidates_the_last_reading_at_once() {
        // `---` is not documented for `V`; it is text that is no number.
        assert_eq!(after_good_voltage(b"---"), (None, Validity::SensorFault));
        assert_eq!(after_good_voltage(b"13.2"), (None, Validity::SensorFault));
        // Too large for i32 at the kind's scale, and too large for i64:
        // the same refusal either way.
        assert_eq!(
            after_good_voltage(b"9999999999"),
            (None, Validity::OutOfRange)
        );
        assert_eq!(
            after_good_voltage(b"99999999999999999999"),
            (None, Validity::OutOfRange)
        );
        assert_eq!(after_good_voltage(b"12900"), (Some(12_900), Validity::Ok));
    }

    #[test]
    fn a_block_without_a_field_leaves_its_reading_and_a_bad_checksum_leaves_all() {
        let (mut store, mut channels, ids) = site();
        let with_v = block(&[(b"V", b"13250"), (b"I", b"100")]);
        let without_v = block(&[(b"I", b"200")]);
        let mut bad = block(&[(b"V", b"1"), (b"I", b"1")]);
        let last = bad.len.checked_sub(1).unwrap();
        bad.buf[last] ^= 0x01;
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(with_v.get())
            .push(without_v.get())
            .push(bad.get());
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3);
        assert_eq!(seen[2], Some(Err(Refused::Checksum)));
        for outcome in &seen[..2] {
            let written = publish(
                &frame(outcome.as_ref()),
                &mut channels,
                Tick::ZERO,
                &mut store,
            );
            assert_eq!(written.first, None);
        }
        assert_eq!(
            store.sample(ids[0], Tick::ZERO).unwrap().value(),
            Some(13_250)
        );
        assert_eq!(store.sample(ids[1], Tick::ZERO).unwrap().value(), Some(200));
    }

    #[test]
    fn a_signal_the_store_does_not_hold_is_a_store_error() {
        let (mut store, _, ids) = site();
        let stranger = Id::new(99).unwrap();
        let mut channels = vip(Some(stranger), Some(ids[1]), None);
        assert_eq!(
            publish(&mppt(), &mut channels, Tick::ZERO, &mut store),
            Written {
                count: 1,
                first: Some(PublishError::Store(SignalError::Unknown(stranger)))
            }
        );
        assert_eq!(
            store.sample(ids[1], Tick::ZERO).unwrap().value(),
            Some(-1_500)
        );
    }

    /// A store and a port with every field that can have a signal on one,
    /// in [`SIGNALLED`] order from signal 10.
    fn every_field() -> (Signals<8>, Publisher, [Id; 7]) {
        let ids = [10, 11, 12, 13, 14, 15, 16].map(|n| Id::new(n).unwrap());
        let mut store = Signals::<8>::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        let mut assignment = Assignment::default();
        for (field, id) in SIGNALLED.into_iter().zip(ids) {
            store.register(id, limits).unwrap();
            assignment = on(assignment, field, id);
        }
        let publisher = Publisher::new(Channels::new(assignment).unwrap());
        (store, publisher, ids)
    }

    /// One verified block of `fields`, built by hand.
    fn one(fields: &[(&[u8], &[u8])]) -> Frame {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(block(fields).get());
        frame(outcomes(stream.get()).0[0].as_ref())
    }

    fn reading(store: &Signals<8>, id: Id, now: Tick) -> (Option<i32>, Validity, Provenance) {
        let sample = store.sample(id, now).unwrap();
        (
            sample.value(),
            sample.q.validity_of(),
            sample.q.provenance_of(),
        )
    }

    fn tick(seconds: u64) -> Tick {
        Tick::ZERO
            .after(Millis::from_secs(seconds).unwrap())
            .unwrap()
    }

    #[test]
    fn f_052_a_verified_block_writes_every_field_at_its_kind_s_scale_and_provenance() {
        use Provenance::{Counted, Measured, Reported};
        let (mut store, mut publisher, ids) = every_field();
        assert_eq!(
            publish(&mppt(), &mut publisher, Tick::ZERO, &mut store),
            Written {
                count: 7,
                first: None
            }
        );
        let expect = [
            (Some(13_250), Measured),
            (Some(-1_500), Measured),
            (Some(480), Measured),
            // `CS 3`, bulk, is KM43's member 2.
            (Some(ChargeStage::Bulk as i32), Reported),
            // `H19 10345`, `H20 12`, `H22 34`, in 0.01 kWh, as Wh.
            (Some(103_450), Counted),
            (Some(120), Counted),
            (Some(340), Counted),
        ];
        for (id, (value, provenance)) in ids.into_iter().zip(expect) {
            assert_eq!(
                reading(&store, id, Tick::ZERO),
                (value, Validity::Ok, provenance),
                "{id:?}"
            );
        }
        // `ERR` is never a signal: nothing else was registered or written.
        assert_eq!(store.len(), 7);
    }

    #[test]
    fn p_164_a_charge_state_km43_does_not_name_publishes_unnamed_state_with_no_value() {
        let (mut store, mut publisher, ids) = every_field();
        let cs = ids[3];
        let _ = publish(&one(&[(b"CS", b"5")]), &mut publisher, tick(0), &mut store);
        assert_eq!(
            reading(&store, cs, tick(0)),
            (
                Some(ChargeStage::Float as i32),
                Validity::Ok,
                Provenance::Reported
            )
        );
        // 247, auto equalize, then 8, which the document does not list: the
        // float before it is withdrawn, and no number is left to render.
        for (n, code) in [(1, &b"247"[..]), (2, b"8")] {
            let got = one(&[(b"CS", code)]);
            let written = publish(&got, &mut publisher, tick(n), &mut store);
            assert_eq!((written.count, written.first), (1, None), "{code:?}");
            assert_eq!(
                reading(&store, cs, tick(n)),
                (None, Validity::UnnamedState, Provenance::None),
                "{code:?}"
            );
            // The raw code goes to the concern instead.
            let state = got.charge_state().unwrap().unwrap();
            assert!(matches!(
                state.raise(),
                Raise::Concern(Concern { cond: Condition::UNNAMED_STATE, code: VendorCode { raw, .. }, .. })
                    if raw == u32::from(state.code())
            ));
        }
    }

    #[test]
    fn a_charge_state_that_is_no_code_is_out_of_range_or_a_sensor_fault() {
        let (mut store, mut publisher, ids) = every_field();
        // A number past a code is out of range, as a panel power past its
        // kind is; text that is no number is the product's fault, and says so.
        let malformed = Some(PublishError::Malformed(Malformed {
            field: Field::ChargeState,
            why: Unreadable::NotANumber,
        }));
        for (text, validity, first) in [
            (&b"256"[..], Validity::OutOfRange, None),
            (b"-1", Validity::OutOfRange, None),
            (b"---", Validity::SensorFault, malformed),
            (b"3.0", Validity::SensorFault, malformed),
        ] {
            let _ = publish(&one(&[(b"CS", b"3")]), &mut publisher, tick(0), &mut store);
            let written = publish(&one(&[(b"CS", text)]), &mut publisher, tick(1), &mut store);
            assert_eq!((written.count, written.first), (1, first), "{text:?}");
            assert_eq!(
                reading(&store, ids[3], tick(1)),
                (None, validity, Provenance::None),
                "{text:?}"
            );
        }
        // 255 is a code, unlisted: unnamed, not out of range.
        let _ = publish(
            &one(&[(b"CS", b"255")]),
            &mut publisher,
            tick(2),
            &mut store,
        );
        assert_eq!(reading(&store, ids[3], tick(2)).1, Validity::UnnamedState);
    }

    #[test]
    fn p_259_a_yield_that_falls_publishes_reset_with_its_new_total() {
        let (mut store, mut publisher, ids) = every_field();
        let today = ids[5];
        // Evening, then the first block after midnight.
        let _ = publish(
            &one(&[(b"H20", b"412")]),
            &mut publisher,
            tick(0),
            &mut store,
        );
        assert_eq!(
            reading(&store, today, tick(0)),
            (Some(4_120), Validity::Ok, Provenance::Counted)
        );
        let _ = publish(&one(&[(b"H20", b"0")]), &mut publisher, tick(1), &mut store);
        assert_eq!(
            reading(&store, today, tick(1)),
            (Some(0), Validity::Reset, Provenance::Counted)
        );
        // The new day goes on as `ok`, an unchanged total included.
        for (n, text, wh) in [(2, &b"0"[..], 0), (3, b"1", 10), (4, b"1", 10)] {
            let _ = publish(&one(&[(b"H20", text)]), &mut publisher, tick(n), &mut store);
            assert_eq!(
                reading(&store, today, tick(n)),
                (Some(wh), Validity::Ok, Provenance::Counted)
            );
        }
        // Each yield is judged against its own last total.
        let _ = publish(
            &one(&[(b"H19", b"900"), (b"H22", b"50")]),
            &mut publisher,
            tick(5),
            &mut store,
        );
        let _ = publish(
            &one(&[(b"H19", b"901"), (b"H22", b"40")]),
            &mut publisher,
            tick(6),
            &mut store,
        );
        assert_eq!(reading(&store, ids[4], tick(6)).1, Validity::Ok);
        assert_eq!(
            reading(&store, ids[6], tick(6)),
            (Some(400), Validity::Reset, Provenance::Counted)
        );
    }

    #[test]
    fn a_yield_at_the_kind_s_limit_is_read_and_one_past_it_is_out_of_range() {
        let (mut store, mut publisher, ids) = every_field();
        let total = ids[4];
        // 214 748 364 × 0.01 kWh is 2 147 483 640 Wh, which fits an i32.
        let _ = publish(
            &one(&[(b"H19", b"214748364")]),
            &mut publisher,
            tick(0),
            &mut store,
        );
        assert_eq!(
            reading(&store, total, tick(0)),
            (Some(2_147_483_640), Validity::Ok, Provenance::Counted)
        );
        for (n, text) in [
            (1, &b"214748365"[..]),
            (2, b"99999999999999999999"),
            (3, b"-1"),
        ] {
            let _ = publish(&one(&[(b"H19", text)]), &mut publisher, tick(n), &mut store);
            assert_eq!(
                reading(&store, total, tick(n)),
                (None, Validity::OutOfRange, Provenance::None),
                "{text:?}"
            );
        }
        // None of those became the last total: the next honest one is
        // judged against 2 147 483 640.
        let _ = publish(
            &one(&[(b"H19", b"214748364")]),
            &mut publisher,
            tick(4),
            &mut store,
        );
        assert_eq!(reading(&store, total, tick(4)).1, Validity::Ok);
        let _ = publish(&one(&[(b"H19", b"0")]), &mut publisher, tick(5), &mut store);
        assert_eq!(
            reading(&store, total, tick(5)),
            (Some(0), Validity::Reset, Provenance::Counted)
        );
    }

    #[test]
    fn a_yield_the_store_refuses_is_not_the_last_total() {
        let (mut store, mut publisher, ids) = every_field();
        let today = ids[5];
        let _ = publish(
            &one(&[(b"H20", b"100")]),
            &mut publisher,
            tick(5),
            &mut store,
        );
        // A tick behind the last write: the store refuses and keeps 1 000 Wh.
        let refused = publish(&one(&[(b"H20", b"7")]), &mut publisher, tick(4), &mut store);
        assert_eq!(
            refused,
            Written {
                count: 0,
                first: Some(PublishError::Store(SignalError::TickBehind(today)))
            }
        );
        assert_eq!(
            reading(&store, today, tick(5)),
            (Some(1_000), Validity::Ok, Provenance::Counted)
        );
        // So 50 Wh is still below what was published.
        let _ = publish(&one(&[(b"H20", b"5")]), &mut publisher, tick(6), &mut store);
        assert_eq!(
            reading(&store, today, tick(6)),
            (Some(50), Validity::Reset, Provenance::Counted)
        );
    }

    #[test]
    fn a_yield_that_is_no_number_withdraws_the_last_and_keeps_it_as_the_last_total() {
        let (mut store, mut publisher, ids) = every_field();
        let today = ids[5];
        let _ = publish(
            &one(&[(b"H20", b"100")]),
            &mut publisher,
            tick(0),
            &mut store,
        );
        let written = publish(
            &one(&[(b"H20", b"---")]),
            &mut publisher,
            tick(1),
            &mut store,
        );
        assert_eq!(
            written.first,
            Some(PublishError::Malformed(Malformed {
                field: Field::YieldToday,
                why: Unreadable::NotANumber
            }))
        );
        assert_eq!(
            reading(&store, today, tick(1)),
            (None, Validity::SensorFault, Provenance::None)
        );
        let _ = publish(
            &one(&[(b"H20", b"99")]),
            &mut publisher,
            tick(2),
            &mut store,
        );
        assert_eq!(reading(&store, today, tick(2)).1, Validity::Reset);
    }

    #[test]
    fn an_error_in_a_block_writes_nothing_and_raises_its_concern() {
        let (mut store, mut publisher, ids) = every_field();
        // Built by hand: an MPPT stopped on a panel voltage too high.
        let got = one(&[(b"CS", b"2"), (b"ERR", b"33")]);
        let written = publish(&got, &mut publisher, Tick::ZERO, &mut store);
        assert_eq!(
            written,
            Written {
                count: 1,
                first: None
            }
        );
        assert_eq!(
            reading(&store, ids[3], Tick::ZERO),
            (
                Some(ChargeStage::Fault as i32),
                Validity::Ok,
                Provenance::Reported
            )
        );
        assert_eq!(
            got.error().unwrap().unwrap().raise(),
            Raise::Concern(Concern {
                cond: Condition::OVER_VOLTAGE,
                sev: Severity::Protection,
                code: VendorCode {
                    raw: 33,
                    vns: VendorNamespace::VICTRON
                },
            })
        );
        for id in [ids[0], ids[1], ids[2], ids[4], ids[5], ids[6]] {
            assert_eq!(
                reading(&store, id, Tick::ZERO).1,
                Validity::Initialising,
                "{id:?}"
            );
        }
    }

    /// `assignment` with `field` on `sig`.
    fn on(mut assignment: Assignment, field: Field, sig: Id) -> Assignment {
        let slot = match field {
            Field::BatteryVoltage => &mut assignment.battery_voltage,
            Field::BatteryCurrent => &mut assignment.battery_current,
            Field::PanelPower => &mut assignment.panel_power,
            Field::ChargeState => &mut assignment.charge_state,
            Field::YieldTotal => &mut assignment.yield_total,
            Field::YieldToday => &mut assignment.yield_today,
            Field::YieldYesterday => &mut assignment.yield_yesterday,
            Field::Error => panic!("ERR has no signal"),
        };
        *slot = Some(sig);
        assignment
    }

    const SIGNALLED: [Field; 7] = [
        Field::BatteryVoltage,
        Field::BatteryCurrent,
        Field::PanelPower,
        Field::ChargeState,
        Field::YieldTotal,
        Field::YieldToday,
        Field::YieldYesterday,
    ];

    #[test]
    fn two_fields_on_one_signal_are_refused() {
        let [a, b] = [1, 2].map(|n| Id::new(n).unwrap());
        for (at, first) in SIGNALLED.into_iter().enumerate() {
            for second in SIGNALLED.into_iter().skip(at + 1) {
                let both = on(on(Assignment::default(), first, a), second, a);
                assert_eq!(Channels::new(both), None, "{first:?} {second:?}");
                let apart = on(on(Assignment::default(), first, a), second, b);
                let fine = Channels::new(apart).expect("distinct");
                assert_eq!(fine.signal(first), Some(a));
                assert_eq!(fine.signal(second), Some(b));
            }
        }
        let none = Channels::new(Assignment::default()).expect("nothing assigned");
        for field in Field::ALL {
            assert_eq!(none.signal(field), None, "{field:?}");
        }
    }

    // The port.

    /// A listener that plays `stream` back in bursts of `chunk` bytes, as an
    /// honest adapter would, with a scripted fault or lie before the burst
    /// at `at`.
    struct Chunked<'a> {
        stream: &'a [u8],
        chunk: usize,
        pos: usize,
        at: usize,
        fault: Option<PortFault<u8>>,
        lie: Option<Burst>,
    }

    impl<'a> Chunked<'a> {
        fn new(stream: &'a [u8], chunk: usize) -> Self {
            Self {
                stream,
                chunk,
                pos: 0,
                at: usize::MAX,
                fault: None,
                lie: None,
            }
        }

        fn left(&self) -> bool {
            self.pos < self.stream.len()
        }
    }

    impl Listener for Chunked<'_> {
        type Error = u8;

        fn receive(
            &mut self,
            into: &mut [u8],
            _: Millis,
        ) -> impl Future<Output = Result<Burst, PortFault<u8>>> {
            if self.pos >= self.at {
                self.at = usize::MAX;
                if let Some(fault) = self.fault.take() {
                    return ready(Err(fault));
                }
                if let Some(lie) = self.lie.take() {
                    return ready(Ok(lie));
                }
            }
            let rest = &self.stream[self.pos..];
            if rest.is_empty() {
                return ready(Err(PortFault::Timeout));
            }
            let len = rest.len().min(self.chunk).min(into.len());
            into[..len].copy_from_slice(&rest[..len]);
            self.pos = self.pos.checked_add(len).unwrap();
            let ended = if len == into.len() {
                Ended::Full
            } else {
                Ended::Gap
            };
            ready(Ok(Burst { len, ended }))
        }
    }

    /// Listen until the stream is spent, adding up what was heard.
    fn drain(
        port: &mut Chunked<'_>,
        parser: &mut Parser,
        store: &mut Signals<4>,
        channels: &mut Publisher,
    ) -> (usize, usize, usize) {
        let (mut blocks, mut refused, mut written) = (0usize, 0usize, 0usize);
        for _ in 0..4096 {
            match block_on(listen(
                port,
                parser,
                WAIT,
                channels,
                Tick::ZERO,
                store,
                |_| {},
            )) {
                Ok(heard) => {
                    blocks = blocks.checked_add(heard.blocks).unwrap();
                    refused = refused.checked_add(heard.refused).unwrap();
                    written = written.checked_add(heard.written).unwrap();
                }
                Err(ListenError::Silent) => return (blocks, refused, written),
                Err(other) => panic!("{other:?}"),
            }
        }
        panic!("the stream never ran dry");
    }

    #[test]
    fn a_stream_split_at_any_burst_size_decodes_the_same() {
        let mut bad = Bytes::new();
        bad.push(MPPT);
        bad.buf[30] ^= 0x04;
        let mut stream = Bytes::new();
        stream
            .push(b"\x13noise")
            .push(TAIL)
            .push(MPPT)
            .push(HEX)
            .push(bad.get())
            .push(MPPT);
        for chunk in 1..=BURST_BYTES + 1 {
            let (mut store, mut channels, ids) = site();
            let mut port = Chunked::new(stream.get(), chunk);
            let mut parser = Parser::new();
            assert_eq!(
                drain(&mut port, &mut parser, &mut store, &mut channels),
                (2, 1, 6),
                "bursts of {chunk}"
            );
            assert_eq!(
                store.sample(ids[0], Tick::ZERO).unwrap().value(),
                Some(13_250)
            );
        }
    }

    #[test]
    fn a_block_split_by_silence_still_decodes() {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(MPPT);
        let mut port = Chunked::new(stream.get(), 16);
        port.at = 64;
        port.fault = Some(PortFault::Timeout);
        let (mut store, mut channels, _) = site();
        let mut parser = Parser::new();
        let mut blocks = 0usize;
        let mut silences = 0usize;
        while port.left() {
            match block_on(listen(
                &mut port,
                &mut parser,
                WAIT,
                &mut channels,
                Tick::ZERO,
                &mut store,
                |_| {},
            )) {
                Ok(heard) => blocks = blocks.checked_add(heard.blocks).unwrap(),
                Err(ListenError::Silent) => silences = silences.checked_add(1).unwrap(),
                Err(other) => panic!("{other:?}"),
            }
        }
        assert_eq!((blocks, silences), (1, 1));
    }

    #[test]
    fn a_line_error_mid_block_loses_that_block_and_the_next_decodes() {
        let mut stream = Bytes::new();
        stream.push(TAIL).push(MPPT).push(MPPT);
        let mut port = Chunked::new(stream.get(), 16);
        port.at = 64;
        port.fault = Some(PortFault::Line(7));
        let (mut store, mut channels, _) = site();
        let mut parser = Parser::new();
        let mut blocks = 0usize;
        let mut errors = 0usize;
        while port.left() {
            match block_on(listen(
                &mut port,
                &mut parser,
                WAIT,
                &mut channels,
                Tick::ZERO,
                &mut store,
                |_| {},
            )) {
                Ok(heard) => blocks = blocks.checked_add(heard.blocks).unwrap(),
                Err(ListenError::Line(7)) => errors = errors.checked_add(1).unwrap(),
                Err(other) => panic!("{other:?}"),
            }
        }
        // Without the resynchronisation the first block would decode here,
        // joined across bytes the line lost.
        assert_eq!((blocks, errors), (1, 1));
    }

    #[test]
    fn a_burst_no_adapter_can_have_received_is_refused_and_the_parser_hunts() {
        let lies = [
            Burst {
                len: 0,
                ended: Ended::Gap,
            },
            Burst {
                len: BURST_BYTES,
                ended: Ended::Gap,
            },
            Burst {
                len: 3,
                ended: Ended::Full,
            },
            Burst {
                len: BURST_BYTES + 1,
                ended: Ended::Full,
            },
        ];
        for lie in lies {
            let mut stream = Bytes::new();
            stream.push(TAIL).push(MPPT).push(MPPT);
            let mut port = Chunked::new(stream.get(), 16);
            port.at = 64;
            port.lie = Some(lie);
            let (mut store, mut channels, _) = site();
            let mut parser = Parser::new();
            let mut blocks = 0usize;
            let mut adapter = 0usize;
            while port.left() {
                match block_on(listen(
                    &mut port,
                    &mut parser,
                    WAIT,
                    &mut channels,
                    Tick::ZERO,
                    &mut store,
                    |_| {},
                )) {
                    Ok(heard) => blocks = blocks.checked_add(heard.blocks).unwrap(),
                    Err(ListenError::Adapter) => adapter = adapter.checked_add(1).unwrap(),
                    Err(other) => panic!("{other:?}"),
                }
            }
            assert_eq!((blocks, adapter), (1, 1), "{lie:?}");
        }
    }

    /// Two verified blocks, the first with `ERR 17` and the second with
    /// only `V`, after a tail: 53 bytes, which fit one receive. Built by
    /// hand; the checksum bytes `<` and `D` were worked out by hand.
    const TWO_BLOCKS: &[u8] =
        b"\r\nChecksum\t\x42\r\nERR\t17\r\nChecksum\t<\r\nV\t12000\r\nChecksum\tD";

    #[test]
    fn every_verified_block_in_one_burst_reaches_the_caller_in_order() {
        assert_eq!(TWO_BLOCKS.len(), 53);
        let mut built = Bytes::new();
        built
            .push(TAIL)
            .push(block(&[(b"ERR", b"17")]).get())
            .push(block(&[(b"V", b"12000")]).get());
        assert_eq!(built.get(), TWO_BLOCKS);
        let first_ends = TAIL.len() + block(&[(b"ERR", b"17")]).len;
        // One burst for both blocks, and a burst ending between them.
        for chunk in [BURST_BYTES, first_ends] {
            let mut port = Chunked::new(TWO_BLOCKS, chunk);
            let (mut store, mut channels, ids) = site();
            let mut parser = Parser::new();
            let mut frames = [None; 4];
            let mut n = 0usize;
            let mut blocks = 0usize;
            while port.left() {
                let heard = block_on(listen(
                    &mut port,
                    &mut parser,
                    WAIT,
                    &mut channels,
                    Tick::ZERO,
                    &mut store,
                    |frame| {
                        frames[n] = Some(*frame);
                        n += 1;
                    },
                ))
                .unwrap();
                blocks = blocks.checked_add(heard.blocks).unwrap();
            }
            assert_eq!((n, blocks), (2, 2), "bursts of {chunk}");
            let [Some(first), Some(second), None, None] = frames else {
                panic!("{frames:?}");
            };
            assert_eq!(
                first.error(),
                Some(Ok(VendorError::ChargerTemperatureTooHigh))
            );
            assert_eq!(first.battery_voltage(), None);
            assert_eq!(second.battery_voltage(), Some(Ok(12_000)));
            assert_eq!(second.error(), None);
            assert_eq!(
                store.sample(ids[0], Tick::ZERO).unwrap().value(),
                Some(12_000)
            );
        }
    }

    #[test]
    fn listen_counts_the_writes_of_a_block_with_one_unreadable_field() {
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(block(&[(b"V", b"13.2"), (b"I", b"10"), (b"PPV", b"5")]).get());
        let mut port = Chunked::new(stream.get(), BURST_BYTES);
        let (mut store, mut channels, ids) = site();
        let mut parser = Parser::new();
        let heard = block_on(listen(
            &mut port,
            &mut parser,
            WAIT,
            &mut channels,
            Tick::ZERO,
            &mut store,
            |_| {},
        ))
        .unwrap();
        assert!(!port.left());
        assert_eq!(heard.blocks, 1);
        assert_eq!(heard.written, 3);
        assert_eq!(
            heard.unwritten,
            Some(PublishError::Malformed(Malformed {
                field: Field::BatteryVoltage,
                why: Unreadable::NotANumber
            }))
        );
        assert_eq!(store.sample(ids[1], Tick::ZERO).unwrap().value(), Some(10));
    }

    #[test]
    fn a_line_feed_where_a_carriage_return_was_due_still_finds_the_block_s_end() {
        // The `\r` before `\nChecksum` lost: the refusal comes at that `\n`,
        // and the hunt must still read the `Checksum` label after it.
        let at = MPPT.windows(10).position(|w| w == b"\r\nChecksum").unwrap();
        let mut stream = Bytes::new();
        stream
            .push(TAIL)
            .push(&MPPT[..at])
            .push(&MPPT[at + 1..])
            .push(MPPT)
            .push(MPPT);
        let (seen, n) = outcomes(stream.get());
        assert_eq!(n, 3, "{seen:?}");
        assert_eq!(seen[0], Some(Err(Refused::Framing)));
        assert!(matches!(seen[1], Some(Ok(_))));
        assert!(matches!(seen[2], Some(Ok(_))));
    }
}
