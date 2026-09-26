//! A Pylontech-class BMS on CAN, read through the [`Can`] seam.
//!
//! The frames are those of Pylontech's *CAN-Bus Protocol PYLON Low Voltage*,
//! V1.2 of 2018-04-08 and its V1.3: standard identifiers at 500 kbit/s, each
//! frame broadcast once a second, integers little-endian. The BMS speaks
//! without being asked; the inverter's once-a-second `0x305` is its own
//! frame on the bus and not the BMS's.
//!
//! | Id | Bytes | What |
//! | --- | --- | --- |
//! | `0x351` | 6 (V1.2) or 8 (V1.3) | charge voltage 0.1 V `u16`, charge and discharge current limits 0.1 A `i16`, V1.3's discharge voltage 0.1 V `i16` |
//! | `0x355` | 4 | state of charge and state of health, 1 % `u16` |
//! | `0x356` | 6 | pack voltage 0.01 V, current 0.1 A, average cell temperature 0.1 °C, each `i16` |
//! | `0x359` | 7 | protections, alarms, module count, then `"PN"` |
//! | `0x35C` | 2 | the request flags |
//!
//! The documents lay out each frame's bytes and never state a length. The
//! lengths above are the bytes each table defines, and a frame of any other
//! length is refused ([`FrameError::Length`]), as is an identifier this table
//! does not hold, an extended identifier among them ([`FrameError::Unknown`]).
//! A refused frame writes nothing. A BMS that goes silent writes nothing
//! either, and its signals go stale through the store's maximum age.
//!
//! What the store carries, each with the provenance the protocol can justify
//! (F-052): the BMS's charge and discharge limits are `reported`; its state
//! of charge is its own count, `counted`, as the architecture treats a BMS's
//! own figure beside a shunt's; the pack's voltage, current and temperature
//! are `measured`, the current only once the caller states which way the
//! BMS counts it positive ([`CurrentDirection`]), because the documents do
//! not say. A negative limit publishes `out_of_range`: the documents type the
//! limits as signed and give a negative one no meaning. KM43 has no metric
//! for a state of health, a protection, an alarm or a request, so those
//! decode into [`Charge`], [`Status`] and [`Requests`], which a read hands
//! back with every bit the frame carried, and nothing of them reaches the
//! store.
//!
//! cites: F-052, P-185, P-196

use km43::{Id, Provenance, SignalDomain, Validity};
use o89_core::{Millis, Observation, SignalError, Signals, Tick};

use crate::dialect::Kind;
use crate::port::{Can, CanFrame, CanId, PortFault};

/// The signals a BMS publishes into the store: one per [`Channel`].
pub const CHANNELS: usize = 8;

/// The most signals one frame writes: `0x351`'s four limits.
pub const MOST_PER_FRAME: usize = 4;

/// A value the BMS publishes into the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Channel {
    /// The highest voltage the BMS will be charged to, from `0x351`.
    ChargeVoltageLimit,
    /// The most current the BMS will take, from `0x351`.
    ChargeCurrentLimit,
    /// The most current the BMS will give, from `0x351`, published as the
    /// lowest current into the pack: a limit of 100 A out is −100 A.
    DischargeCurrentLimit,
    /// The lowest voltage the BMS will be discharged to, from V1.3's
    /// `0x351`; `unsupported` from a V1.2 BMS, whose frame has no such field.
    DischargeVoltageLimit,
    /// The BMS's own state of charge, from `0x355`.
    StateOfCharge,
    /// The pack's voltage, from `0x356`.
    PackVoltage,
    /// The pack's current, from `0x356`, published only when the caller
    /// says which way the BMS counts positive ([`CurrentDirection`]).
    PackCurrent,
    /// The average cell temperature, from `0x356`.
    Temperature,
}

impl Channel {
    /// Every channel, in the order their signals are numbered.
    pub const ALL: [Self; CHANNELS] = [
        Self::ChargeVoltageLimit,
        Self::ChargeCurrentLimit,
        Self::DischargeCurrentLimit,
        Self::DischargeVoltageLimit,
        Self::StateOfCharge,
        Self::PackVoltage,
        Self::PackCurrent,
        Self::Temperature,
    ];

    /// What it is.
    #[must_use]
    pub const fn kind(self) -> Kind {
        match self {
            Self::ChargeVoltageLimit | Self::DischargeVoltageLimit | Self::PackVoltage => {
                Kind::DcVoltage
            }
            Self::ChargeCurrentLimit | Self::DischargeCurrentLimit | Self::PackCurrent => {
                Kind::DcCurrent
            }
            Self::StateOfCharge => Kind::StateOfCharge,
            Self::Temperature => Kind::Temperature,
        }
    }

    /// Which window of it.
    #[must_use]
    pub const fn domain(self) -> SignalDomain {
        match self {
            Self::ChargeVoltageLimit | Self::ChargeCurrentLimit => SignalDomain::LimitUpper,
            Self::DischargeCurrentLimit | Self::DischargeVoltageLimit => SignalDomain::LimitLower,
            Self::StateOfCharge | Self::PackVoltage | Self::PackCurrent | Self::Temperature => {
                SignalDomain::Live
            }
        }
    }

    /// Where the number comes from.
    #[must_use]
    pub const fn provenance(self) -> Provenance {
        match self {
            Self::ChargeVoltageLimit
            | Self::ChargeCurrentLimit
            | Self::DischargeCurrentLimit
            | Self::DischargeVoltageLimit => Provenance::Reported,
            Self::StateOfCharge => Provenance::Counted,
            Self::PackVoltage | Self::PackCurrent | Self::Temperature => Provenance::Measured,
        }
    }

    /// The vendor's wire integer times this is the value at the kind's
    /// registry scale.
    const fn factor(self) -> i32 {
        match self {
            // 0.1 V and 0.1 A to mV and mA.
            Self::ChargeVoltageLimit
            | Self::DischargeVoltageLimit
            | Self::ChargeCurrentLimit
            | Self::PackCurrent => 100,
            // A limit on current out is a floor on current in.
            Self::DischargeCurrentLimit => -100,
            // 1 % to 0.1 %, and 0.01 V to mV.
            Self::StateOfCharge | Self::PackVoltage => 10,
            // 0.1 °C is the registry's own scale.
            Self::Temperature => 1,
        }
    }

    /// Whether the vendor states the value as a magnitude: a limit the
    /// tables type as a signed integer without saying what a negative one
    /// means, so a negative one is not a number this driver may interpret.
    const fn magnitude(self) -> bool {
        match self {
            Self::ChargeCurrentLimit
            | Self::DischargeCurrentLimit
            | Self::DischargeVoltageLimit => true,
            Self::ChargeVoltageLimit
            | Self::StateOfCharge
            | Self::PackVoltage
            | Self::PackCurrent
            | Self::Temperature => false,
        }
    }

    /// The channel's observation of `raw`: out of range when it is a
    /// negative magnitude, does not fit an `i32` at the kind's scale or
    /// leaves the kind's own range (P-185), never clamped.
    fn observe(self, raw: i32) -> Result<Observation, SignalError> {
        let value = raw
            .checked_mul(self.factor())
            .filter(|_| !(self.magnitude() && raw < 0))
            .filter(|value| {
                self.kind()
                    .intrinsic()
                    .is_none_or(|range| range.holds(*value))
            });
        match value {
            Some(value) => Observation::value(value, self.provenance()),
            None => Observation::missing(Validity::OutOfRange),
        }
        .map_err(SignalError::Quality)
    }
}

/// Whether every channel's provenance is one its kind can carry over its
/// domain, the rule a register map's cell is held to.
const fn declared() -> bool {
    let mut rest: &[Channel] = &Channel::ALL;
    while let [channel, tail @ ..] = rest {
        if !channel
            .kind()
            .accepts(channel.domain())
            .contains(channel.provenance())
        {
            return false;
        }
        rest = tail;
    }
    true
}

const _: () = assert!(
    declared(),
    "a channel declares a provenance its kind cannot carry"
);

/// Which way a BMS counts its pack current as positive.
///
/// The protocol documents type `0x356`'s current as a signed integer and do
/// not say which direction is positive, so the driver never assumes one: the
/// configuration states it for the BMS in front of it, from its own
/// documentation or a bench reading, and until then says
/// [`CurrentDirection::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CurrentDirection {
    /// Positive while the pack charges: published as the BMS sends it,
    /// since KM43 counts current positive into the component.
    IntoPack,
    /// Positive while the pack discharges: published negated.
    OutOfPack,
    /// Nobody has established it: the pack current publishes
    /// `unsupported` and no value, and the decoded [`Pack`] keeps the raw
    /// word.
    Unknown,
}

/// The frames this table decodes, by standard identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameId {
    /// `0x351`, the charge and discharge limits.
    Limits,
    /// `0x355`, state of charge and state of health.
    Charge,
    /// `0x356`, the pack's voltage, current and temperature.
    Pack,
    /// `0x359`, protections and alarms.
    Status,
    /// `0x35C`, the request flags.
    Requests,
}

impl FrameId {
    /// The frame `id` carries, or `None` for any other identifier and for
    /// every extended one.
    #[must_use]
    pub const fn of(id: CanId) -> Option<Self> {
        if id.is_extended() {
            return None;
        }
        match id.raw() {
            0x351 => Some(Self::Limits),
            0x355 => Some(Self::Charge),
            0x356 => Some(Self::Pack),
            0x359 => Some(Self::Status),
            0x35C => Some(Self::Requests),
            _ => None,
        }
    }
}

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused frame is a reading that was not recorded"]
pub enum FrameError {
    /// Not one of this table's identifiers: another node's frame, such as
    /// the inverter's `0x305`, or the BMS's name in `0x35E`.
    Unknown(CanId),
    /// A known identifier with a length its table does not define.
    Length {
        /// Which frame.
        id: FrameId,
        /// How many bytes it carried.
        len: usize,
    },
    /// A `0x359` whose last two bytes are not `"PN"`.
    Signature,
}

/// `0x351`, in the vendor's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Limits {
    /// Charge voltage, 0.1 V.
    pub charge_voltage: u16,
    /// Charge current limit, 0.1 A.
    pub charge_current: i16,
    /// Discharge current limit, 0.1 A, positive out of the pack.
    pub discharge_current: i16,
    /// Discharge voltage, 0.1 V: V1.3's eight-byte frame, `None` from V1.2's
    /// six.
    pub discharge_voltage: Option<i16>,
}

/// `0x355`, in the vendor's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Charge {
    /// State of charge, 1 %.
    pub soc: u16,
    /// State of health, 1 %. KM43 has no metric for it, so it stays here.
    pub soh: u16,
}

/// `0x356`, in the vendor's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Pack {
    /// Module or average module voltage, 0.01 V.
    pub voltage: i16,
    /// Module or system current, 0.1 A.
    pub current: i16,
    /// Average cell temperature, 0.1 °C.
    pub temperature: i16,
}

/// A protection the BMS has tripped, from `0x359`'s bytes 0 and 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Protection {
    /// Byte 0 bit 1: cell or module over voltage.
    OverVoltage,
    /// Byte 0 bit 2: cell or module under voltage.
    UnderVoltage,
    /// Byte 0 bit 3: cell over temperature.
    OverTemperature,
    /// Byte 0 bit 4: cell under temperature.
    UnderTemperature,
    /// Byte 0 bit 7: discharge over current.
    DischargeOverCurrent,
    /// Byte 1 bit 0: charge over current.
    ChargeOverCurrent,
    /// Byte 1 bit 3: system error.
    SystemError,
}

impl Protection {
    /// Every protection the table names.
    pub const ALL: [Self; 7] = [
        Self::OverVoltage,
        Self::UnderVoltage,
        Self::OverTemperature,
        Self::UnderTemperature,
        Self::DischargeOverCurrent,
        Self::ChargeOverCurrent,
        Self::SystemError,
    ];

    /// Its bit in the two bytes read as one little-endian word.
    const fn mask(self) -> u16 {
        match self {
            Self::OverVoltage => 1 << 1,
            Self::UnderVoltage => 1 << 2,
            Self::OverTemperature => 1 << 3,
            Self::UnderTemperature => 1 << 4,
            Self::DischargeOverCurrent => 1 << 7,
            Self::ChargeOverCurrent => 1 << 8,
            Self::SystemError => 1 << 11,
        }
    }
}

/// An alarm the BMS raises before a protection trips, from `0x359`'s bytes
/// 2 and 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Alarm {
    /// Byte 2 bit 1: cell or module high voltage.
    HighVoltage,
    /// Byte 2 bit 2: cell or module low voltage.
    LowVoltage,
    /// Byte 2 bit 3: cell high temperature.
    HighTemperature,
    /// Byte 2 bit 4: cell low temperature.
    LowTemperature,
    /// Byte 2 bit 7: discharge high current.
    DischargeHighCurrent,
    /// Byte 3 bit 0: charge high current.
    ChargeHighCurrent,
    /// Byte 3 bit 3: internal communication fail.
    InternalCommunication,
}

impl Alarm {
    /// Every alarm the table names.
    pub const ALL: [Self; 7] = [
        Self::HighVoltage,
        Self::LowVoltage,
        Self::HighTemperature,
        Self::LowTemperature,
        Self::DischargeHighCurrent,
        Self::ChargeHighCurrent,
        Self::InternalCommunication,
    ];

    /// Its bit in the two bytes read as one little-endian word.
    const fn mask(self) -> u16 {
        match self {
            Self::HighVoltage => 1 << 1,
            Self::LowVoltage => 1 << 2,
            Self::HighTemperature => 1 << 3,
            Self::LowTemperature => 1 << 4,
            Self::DischargeHighCurrent => 1 << 7,
            Self::ChargeHighCurrent => 1 << 8,
            Self::InternalCommunication => 1 << 11,
        }
    }
}

/// `0x359`: every bit the frame carried, named where the table names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Status {
    protections: u16,
    alarms: u16,
    modules: u8,
}

impl Status {
    /// Whether `protection` has tripped.
    #[must_use]
    pub const fn tripped(self, protection: Protection) -> bool {
        self.protections & protection.mask() != 0
    }

    /// Whether `alarm` is raised.
    #[must_use]
    pub const fn raised(self, alarm: Alarm) -> bool {
        self.alarms & alarm.mask() != 0
    }

    /// Bytes 0 and 1 as one little-endian word, with the bits the table
    /// leaves unnamed.
    #[must_use]
    pub const fn protection_bits(self) -> u16 {
        self.protections
    }

    /// Bytes 2 and 3 as one little-endian word, with the bits the table
    /// leaves unnamed.
    #[must_use]
    pub const fn alarm_bits(self) -> u16 {
        self.alarms
    }

    /// Byte 4, the number of modules.
    #[must_use]
    pub const fn modules(self) -> u8 {
        self.modules
    }
}

/// A request the BMS makes of its charger, from `0x35C`'s byte 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Request {
    /// Bit 7: charging is allowed.
    ChargeEnable,
    /// Bit 6: discharging is allowed.
    DischargeEnable,
    /// Bit 5: force charge I, the BMS may shut down and be woken to charge.
    ForceChargeOne,
    /// Bit 4: force charge II, charge before the BMS shuts down.
    ForceChargeTwo,
    /// Bit 3: a full charge, set after thirty days without reaching 97 %.
    FullCharge,
}

impl Request {
    /// Every request the table names.
    pub const ALL: [Self; 5] = [
        Self::ChargeEnable,
        Self::DischargeEnable,
        Self::ForceChargeOne,
        Self::ForceChargeTwo,
        Self::FullCharge,
    ];

    /// Its bit in the two bytes read as one little-endian word.
    const fn mask(self) -> u16 {
        match self {
            Self::ChargeEnable => 1 << 7,
            Self::DischargeEnable => 1 << 6,
            Self::ForceChargeOne => 1 << 5,
            Self::ForceChargeTwo => 1 << 4,
            Self::FullCharge => 1 << 3,
        }
    }
}

/// `0x35C`: every bit the frame carried, named where the table names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Requests(u16);

impl Requests {
    /// Whether the BMS makes `request`.
    #[must_use]
    pub const fn makes(self, request: Request) -> bool {
        self.0 & request.mask() != 0
    }

    /// Both bytes as one little-endian word, with the bits the table leaves
    /// unnamed.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// One decoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Frame {
    /// `0x351`.
    Limits(Limits),
    /// `0x355`.
    Charge(Charge),
    /// `0x356`.
    Pack(Pack),
    /// `0x359`.
    Status(Status),
    /// `0x35C`.
    Requests(Requests),
}

impl Frame {
    /// The frame `frame` carries, or why it is refused.
    pub fn decode(frame: &CanFrame) -> Result<Self, FrameError> {
        let id = FrameId::of(frame.id()).ok_or(FrameError::Unknown(frame.id()))?;
        let le = |low: u8, high: u8| u16::from_le_bytes([low, high]);
        let signed = |low: u8, high: u8| i16::from_le_bytes([low, high]);
        Ok(match (id, frame.data()) {
            (FrameId::Limits, &[v0, v1, c0, c1, d0, d1]) => Self::Limits(Limits {
                charge_voltage: le(v0, v1),
                charge_current: signed(c0, c1),
                discharge_current: signed(d0, d1),
                discharge_voltage: None,
            }),
            (FrameId::Limits, &[v0, v1, c0, c1, d0, d1, f0, f1]) => Self::Limits(Limits {
                charge_voltage: le(v0, v1),
                charge_current: signed(c0, c1),
                discharge_current: signed(d0, d1),
                discharge_voltage: Some(signed(f0, f1)),
            }),
            (FrameId::Charge, &[c0, c1, h0, h1]) => Self::Charge(Charge {
                soc: le(c0, c1),
                soh: le(h0, h1),
            }),
            (FrameId::Pack, &[v0, v1, c0, c1, t0, t1]) => Self::Pack(Pack {
                voltage: signed(v0, v1),
                current: signed(c0, c1),
                temperature: signed(t0, t1),
            }),
            (FrameId::Status, &[p0, p1, a0, a1, modules, b'P', b'N']) => Self::Status(Status {
                protections: le(p0, p1),
                alarms: le(a0, a1),
                modules,
            }),
            (FrameId::Status, &[_, _, _, _, _, _, _]) => return Err(FrameError::Signature),
            (FrameId::Requests, &[r0, r1]) => Self::Requests(Requests(le(r0, r1))),
            (
                FrameId::Limits
                | FrameId::Charge
                | FrameId::Pack
                | FrameId::Status
                | FrameId::Requests,
                data,
            ) => {
                return Err(FrameError::Length {
                    id,
                    len: data.len(),
                });
            }
        })
    }

    /// What the frame publishes into the store, at most
    /// [`MOST_PER_FRAME`], in channel order.
    fn observations(
        &self,
        direction: CurrentDirection,
    ) -> Result<[Option<(Channel, Observation)>; MOST_PER_FRAME], SignalError> {
        let seen = |channel: Channel, raw: i32| Ok(Some((channel, channel.observe(raw)?)));
        Ok(match *self {
            Self::Limits(limits) => [
                seen(
                    Channel::ChargeVoltageLimit,
                    i32::from(limits.charge_voltage),
                )?,
                seen(
                    Channel::ChargeCurrentLimit,
                    i32::from(limits.charge_current),
                )?,
                seen(
                    Channel::DischargeCurrentLimit,
                    i32::from(limits.discharge_current),
                )?,
                match limits.discharge_voltage {
                    Some(raw) => seen(Channel::DischargeVoltageLimit, i32::from(raw))?,
                    None => Some((
                        Channel::DischargeVoltageLimit,
                        Observation::missing(Validity::Unsupported)
                            .map_err(SignalError::Quality)?,
                    )),
                },
            ],
            Self::Charge(charge) => [
                seen(Channel::StateOfCharge, i32::from(charge.soc))?,
                None,
                None,
                None,
            ],
            Self::Pack(pack) => [
                seen(Channel::PackVoltage, i32::from(pack.voltage))?,
                match (direction, i32::from(pack.current).checked_neg()) {
                    (CurrentDirection::IntoPack, _) => {
                        seen(Channel::PackCurrent, i32::from(pack.current))?
                    }
                    (CurrentDirection::OutOfPack, Some(into)) => seen(Channel::PackCurrent, into)?,
                    // Unreachable: every `i16` negates inside an `i32`.
                    (CurrentDirection::OutOfPack, None) => Some((
                        Channel::PackCurrent,
                        Observation::missing(Validity::OutOfRange).map_err(SignalError::Quality)?,
                    )),
                    (CurrentDirection::Unknown, _) => Some((
                        Channel::PackCurrent,
                        Observation::missing(Validity::Unsupported)
                            .map_err(SignalError::Quality)?,
                    )),
                },
                seen(Channel::Temperature, i32::from(pack.temperature))?,
                None,
            ],
            Self::Status(_) | Self::Requests(_) => [None; MOST_PER_FRAME],
        })
    }
}

/// The store signal of each [`Channel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ChannelIds {
    charge_voltage_limit: Id,
    charge_current_limit: Id,
    discharge_current_limit: Id,
    discharge_voltage_limit: Id,
    state_of_charge: Id,
    pack_voltage: Id,
    pack_current: Id,
    temperature: Id,
}

/// What a read heard, and what it wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a read's frame carries the BMS's alarms and requests, which the store does not"]
pub struct Heard {
    /// The frame, with what the store does not carry.
    pub frame: Frame,
    /// The signals written.
    pub written: usize,
}

/// Why a read wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed read is a BMS whose readings were not refreshed"]
pub enum ReadError<E> {
    /// No frame: nothing arrived in time, or the port reported a fault.
    Port(PortFault<E>),
    /// The frame was refused.
    Frame(FrameError),
    /// The store refused the frame's signals.
    Store(SignalError),
}

/// A Pylontech-class BMS and the store signals it publishes as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Pylontech {
    signals: ChannelIds,
    direction: CurrentDirection,
}

impl Pylontech {
    /// A BMS whose channels publish as consecutive signals from `first`, in
    /// [`Channel::ALL`]'s order, and whose pack current counts positive in
    /// `direction`; `None` when the signals would run past `0xFFFF`.
    /// Keeping devices' ranges apart is the configuration's to check.
    #[must_use]
    pub fn new(first: Id, direction: CurrentDirection) -> Option<Self> {
        let at = |offset: u16| Id::new(first.get().checked_add(offset)?).ok();
        Some(Self {
            signals: ChannelIds {
                charge_voltage_limit: first,
                charge_current_limit: at(1)?,
                discharge_current_limit: at(2)?,
                discharge_voltage_limit: at(3)?,
                state_of_charge: at(4)?,
                pack_voltage: at(5)?,
                pack_current: at(6)?,
                temperature: at(7)?,
            },
            direction,
        })
    }

    /// The signal `channel` publishes as.
    #[must_use]
    pub const fn signal(&self, channel: Channel) -> Id {
        let ids = &self.signals;
        match channel {
            Channel::ChargeVoltageLimit => ids.charge_voltage_limit,
            Channel::ChargeCurrentLimit => ids.charge_current_limit,
            Channel::DischargeCurrentLimit => ids.discharge_current_limit,
            Channel::DischargeVoltageLimit => ids.discharge_voltage_limit,
            Channel::StateOfCharge => ids.state_of_charge,
            Channel::PackVoltage => ids.pack_voltage,
            Channel::PackCurrent => ids.pack_current,
            Channel::Temperature => ids.temperature,
        }
    }

    /// Write what `frame` publishes into `store` at `now`, with each
    /// channel's declared provenance, and say how many signals it wrote.
    ///
    /// All or nothing: every signal is checked against the store before the
    /// first is written, so a store that does not hold one, or holds a write
    /// later than `now`, refuses the whole frame.
    pub fn record<const N: usize>(
        &self,
        frame: &Frame,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<usize, SignalError> {
        let seen = frame.observations(self.direction)?;
        for (channel, _) in seen.iter().flatten() {
            let _ = store.sample(self.signal(*channel), now)?;
        }
        let mut written = 0usize;
        for (channel, observation) in seen.iter().flatten() {
            store.write(self.signal(*channel), now, *observation)?;
            written = written.saturating_add(1);
        }
        Ok(written)
    }

    /// Wait at most `within` for the next frame on `port`, decode it, and
    /// write it into `store` at `now`.
    ///
    /// A timeout, a line fault and a refused frame write nothing. The
    /// writes carry `now`, read before the wait, so a frame that arrives
    /// later reads at most `within` older than it is, never younger.
    pub async fn read<P: Can, const N: usize>(
        &self,
        port: &mut P,
        within: Millis,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Heard, ReadError<P::Error>> {
        let received = port.receive(within).await.map_err(ReadError::Port)?;
        let frame = Frame::decode(&received).map_err(ReadError::Frame)?;
        let written = self.record(&frame, now, store).map_err(ReadError::Store)?;
        Ok(Heard { frame, written })
    }
}

#[cfg(test)]
mod tests {
    //! Every frame here is built by hand from the byte tables of the V1.2
    //! and V1.3 protocol documents; none is a bench capture.

    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;
    use o89_core::{ChargeSource, Ineligible, Limits as SignalLimits};

    const MAX_AGE: u64 = 10_000;

    fn standard(id: u16) -> CanId {
        CanId::standard(id).expect("an 11-bit id")
    }

    fn frame(id: u16, data: &[u8]) -> CanFrame {
        CanFrame::new(standard(id), data).expect("at most eight bytes")
    }

    fn id(n: u16) -> Id {
        Id::new(n).expect("not zero")
    }

    fn bms() -> Pylontech {
        // These fixtures count positive into the pack; the direction test
        // takes each setting in turn.
        Pylontech::new(id(40), CurrentDirection::IntoPack).expect("room for eight signals")
    }

    fn store() -> Signals<CHANNELS> {
        let mut store = Signals::new();
        let limits = SignalLimits::new(Millis::from_millis(MAX_AGE), None).expect("a non-zero age");
        for channel in Channel::ALL {
            store.register(bms().signal(channel), limits).expect("room");
        }
        store
    }

    fn value(
        store: &Signals<CHANNELS>,
        channel: Channel,
        now: Tick,
    ) -> (Option<i32>, Validity, Provenance) {
        let sample = store
            .sample(bms().signal(channel), now)
            .expect("registered");
        (
            sample.value(),
            sample.q.validity_of(),
            sample.q.provenance_of(),
        )
    }

    /// A V1.3 `0x351`: 53.2 V, 25.0 A in, 50.0 A out, 47.0 V floor.
    const LIMITS_V13: [u8; 8] = [0x14, 0x02, 0xFA, 0x00, 0xF4, 0x01, 0xD6, 0x01];
    /// `0x355`: 64 %, 99 %.
    const CHARGE: [u8; 4] = [0x40, 0x00, 0x63, 0x00];
    /// `0x356`: 51.23 V, −12.5 A, −3.5 °C.
    const PACK: [u8; 6] = [0x03, 0x14, 0x83, 0xFF, 0xDD, 0xFF];

    /// A port that hands out a script of receives, then times out.
    struct Script<'a> {
        receives: &'a [Result<CanFrame, PortFault<u8>>],
        at: usize,
        waited: Option<Millis>,
    }

    impl Can for Script<'_> {
        type Error = u8;

        fn send(&mut self, _frame: &CanFrame) -> impl Future<Output = Result<(), u8>> {
            ready(Ok(()))
        }

        fn receive(
            &mut self,
            within: Millis,
        ) -> impl Future<Output = Result<CanFrame, PortFault<u8>>> {
            self.waited = Some(within);
            let next = self
                .receives
                .get(self.at)
                .copied()
                .unwrap_or(Err(PortFault::Timeout));
            self.at = self.at.saturating_add(1);
            ready(next)
        }
    }

    fn read(
        receives: &[Result<CanFrame, PortFault<u8>>],
        now: Tick,
        store: &mut Signals<CHANNELS>,
    ) -> Result<Heard, ReadError<u8>> {
        let mut port = Script {
            receives,
            at: 0,
            waited: None,
        };
        block_on(bms().read(&mut port, Millis::from_millis(1_500), now, store))
    }

    #[test]
    fn f_052_every_channel_declares_a_provenance_its_kind_carries_and_never_measured_for_charge() {
        assert!(declared());
        for channel in Channel::ALL {
            assert!(
                channel
                    .kind()
                    .accepts(channel.domain())
                    .contains(channel.provenance()),
                "{channel:?}"
            );
        }
        assert_eq!(Channel::StateOfCharge.provenance(), Provenance::Counted);
        for limit in [
            Channel::ChargeVoltageLimit,
            Channel::ChargeCurrentLimit,
            Channel::DischargeCurrentLimit,
            Channel::DischargeVoltageLimit,
        ] {
            assert_eq!(limit.provenance(), Provenance::Reported, "{limit:?}");
        }
    }

    #[test]
    fn f_052_reported_limits_publish_as_reported_with_the_discharge_limit_as_a_floor_on_current_in()
    {
        let mut store = store();
        let heard = read(&[Ok(frame(0x351, &LIMITS_V13))], Tick::ZERO, &mut store).unwrap();
        assert_eq!(heard.written, 4);
        assert_eq!(
            heard.frame,
            Frame::Limits(Limits {
                charge_voltage: 532,
                charge_current: 250,
                discharge_current: 500,
                discharge_voltage: Some(470),
            })
        );
        let ok = |v| (Some(v), Validity::Ok, Provenance::Reported);
        assert_eq!(
            value(&store, Channel::ChargeVoltageLimit, Tick::ZERO),
            ok(53_200)
        );
        assert_eq!(
            value(&store, Channel::ChargeCurrentLimit, Tick::ZERO),
            ok(25_000)
        );
        assert_eq!(
            value(&store, Channel::DischargeCurrentLimit, Tick::ZERO),
            ok(-50_000)
        );
        assert_eq!(
            value(&store, Channel::DischargeVoltageLimit, Tick::ZERO),
            ok(47_000)
        );
        // Nothing else was touched.
        assert_eq!(
            value(&store, Channel::PackVoltage, Tick::ZERO),
            (None, Validity::Initialising, Provenance::None)
        );
    }

    #[test]
    fn a_v1_2_limits_frame_publishes_its_discharge_voltage_as_unsupported_and_no_value() {
        let mut store = store();
        let heard = read(
            &[Ok(frame(0x351, &LIMITS_V13[..6]))],
            Tick::ZERO,
            &mut store,
        )
        .unwrap();
        assert_eq!(heard.written, 4);
        let Frame::Limits(limits) = heard.frame else {
            panic!("{:?}", heard.frame);
        };
        assert_eq!(limits.discharge_voltage, None);
        assert_eq!(
            value(&store, Channel::DischargeVoltageLimit, Tick::ZERO),
            (None, Validity::Unsupported, Provenance::None)
        );
        assert_eq!(
            value(&store, Channel::ChargeVoltageLimit, Tick::ZERO).0,
            Some(53_200)
        );
    }

    #[test]
    fn p_185_a_negative_limit_is_out_of_range_and_its_raw_bits_are_kept() {
        // Built by hand: the signed limit fields at zero, one, both extremes
        // and minus one. The tables type them as signed and give no meaning
        // to a negative limit, so a negative one publishes no value.
        for (raw, published) in [
            (0i16, Some(0)),
            (1, Some(100)),
            (i16::MAX, Some(3_276_700)),
            (-1, None),
            (i16::MIN, None),
        ] {
            let [low, high] = raw.to_le_bytes();
            let data = [0xFF, 0xFF, low, high, low, high, low, high];
            let mut store = store();
            let heard = read(&[Ok(frame(0x351, &data))], Tick::ZERO, &mut store).unwrap();
            assert_eq!(heard.written, 4, "{raw}");
            assert_eq!(
                heard.frame,
                Frame::Limits(Limits {
                    charge_voltage: 0xFFFF,
                    charge_current: raw,
                    discharge_current: raw,
                    discharge_voltage: Some(raw),
                }),
                "{raw}"
            );
            let expect = |value: Option<i32>| match value {
                Some(value) => (Some(value), Validity::Ok, Provenance::Reported),
                None => (None, Validity::OutOfRange, Provenance::None),
            };
            assert_eq!(
                value(&store, Channel::ChargeCurrentLimit, Tick::ZERO),
                expect(published),
                "{raw}"
            );
            assert_eq!(
                value(&store, Channel::DischargeCurrentLimit, Tick::ZERO),
                expect(published.map(|v| -v)),
                "{raw}"
            );
            assert_eq!(
                value(&store, Channel::DischargeVoltageLimit, Tick::ZERO),
                expect(published),
                "{raw}"
            );
            // The charge voltage is unsigned: 0xFFFF is 6553.5 V, not −0.1.
            assert_eq!(
                value(&store, Channel::ChargeVoltageLimit, Tick::ZERO).0,
                Some(6_553_500)
            );
        }
    }

    #[test]
    fn f_052_the_bms_s_own_state_of_charge_is_counted_and_counted_only_acts_on_it() {
        let mut store = store();
        let heard = read(&[Ok(frame(0x355, &CHARGE))], Tick::ZERO, &mut store).unwrap();
        assert_eq!(heard.frame, Frame::Charge(Charge { soc: 64, soh: 99 }));
        assert_eq!(heard.written, 1);
        let soc = store
            .current(
                bms().signal(Channel::StateOfCharge),
                Tick::ZERO,
                ChargeSource::CountedOnly.accepts(),
            )
            .unwrap();
        assert_eq!((soc.value(), soc.provenance()), (640, Provenance::Counted));
    }

    #[test]
    fn p_185_a_state_of_charge_past_one_hundred_percent_is_out_of_range_and_not_clamped() {
        for (soc, expected) in [
            (0u16, Some(0)),
            (100, Some(1000)),
            (101, None),
            (u16::MAX, None),
        ] {
            let mut store = store();
            let [low, high] = soc.to_le_bytes();
            let _ = read(
                &[Ok(frame(0x355, &[low, high, 100, 0]))],
                Tick::ZERO,
                &mut store,
            )
            .unwrap();
            let eligible = store.current(
                bms().signal(Channel::StateOfCharge),
                Tick::ZERO,
                ChargeSource::CountedOnly.accepts(),
            );
            match expected {
                Some(v) => assert_eq!(eligible.map(o89_core::Eligible::value), Ok(v), "{soc}"),
                None => assert_eq!(
                    eligible,
                    Err(Ineligible::NoValue(Validity::OutOfRange)),
                    "{soc}"
                ),
            }
        }
    }

    #[test]
    fn the_pack_frame_publishes_signed_voltage_current_and_temperature_as_measured() {
        let mut store = store();
        let heard = read(&[Ok(frame(0x356, &PACK))], Tick::ZERO, &mut store).unwrap();
        assert_eq!(
            heard.frame,
            Frame::Pack(Pack {
                voltage: 5123,
                current: -125,
                temperature: -35,
            })
        );
        assert_eq!(heard.written, 3);
        let ok = |v| (Some(v), Validity::Ok, Provenance::Measured);
        assert_eq!(value(&store, Channel::PackVoltage, Tick::ZERO), ok(51_230));
        assert_eq!(value(&store, Channel::PackCurrent, Tick::ZERO), ok(-12_500));
        assert_eq!(value(&store, Channel::Temperature, Tick::ZERO), ok(-35));
    }

    #[test]
    fn the_pack_current_publishes_only_in_the_direction_the_caller_states() {
        // Built by hand: the current at zero, ±1 and both extremes, the rest
        // of the frame as in `PACK`.
        for (raw, into) in [
            (0i16, 0),
            (1, 100),
            (-1, -100),
            (i16::MAX, 3_276_700),
            (i16::MIN, -3_276_800),
        ] {
            let [low, high] = raw.to_le_bytes();
            let data = [0x03, 0x14, low, high, 0xDD, 0xFF];
            for (direction, expected) in [
                (
                    CurrentDirection::IntoPack,
                    (Some(into), Validity::Ok, Provenance::Measured),
                ),
                (
                    CurrentDirection::OutOfPack,
                    (Some(-into), Validity::Ok, Provenance::Measured),
                ),
                (
                    CurrentDirection::Unknown,
                    (None, Validity::Unsupported, Provenance::None),
                ),
            ] {
                let bms = Pylontech::new(id(40), direction).unwrap();
                let mut store = store();
                let receives = [Ok(frame(0x356, &data))];
                let mut port = Script {
                    receives: &receives,
                    at: 0,
                    waited: None,
                };
                let heard = block_on(bms.read(
                    &mut port,
                    Millis::from_millis(1_500),
                    Tick::ZERO,
                    &mut store,
                ))
                .unwrap();
                let Frame::Pack(pack) = heard.frame else {
                    panic!("{:?}", heard.frame);
                };
                assert_eq!(pack.current, raw, "{direction:?}");
                assert_eq!(
                    value(&store, Channel::PackCurrent, Tick::ZERO),
                    expected,
                    "{raw} {direction:?}"
                );
                // The rest of the frame does not depend on it.
                assert_eq!(
                    value(&store, Channel::PackVoltage, Tick::ZERO).0,
                    Some(51_230)
                );
            }
        }
    }

    #[test]
    fn every_protection_and_alarm_bit_decodes_as_itself_and_nothing_else() {
        let named = [
            (Protection::OverVoltage, Alarm::HighVoltage, 1u16 << 1),
            (Protection::UnderVoltage, Alarm::LowVoltage, 1 << 2),
            (Protection::OverTemperature, Alarm::HighTemperature, 1 << 3),
            (Protection::UnderTemperature, Alarm::LowTemperature, 1 << 4),
            (
                Protection::DischargeOverCurrent,
                Alarm::DischargeHighCurrent,
                1 << 7,
            ),
            (
                Protection::ChargeOverCurrent,
                Alarm::ChargeHighCurrent,
                1 << 8,
            ),
            (
                Protection::SystemError,
                Alarm::InternalCommunication,
                1 << 11,
            ),
        ];
        for (protection, alarm, bit) in named {
            // The protection in bytes 0-1 and nothing in 2-3, then the reverse.
            for (protections, alarms) in [(bit, 0u16), (0, bit)] {
                let [p0, p1] = protections.to_le_bytes();
                let [a0, a1] = alarms.to_le_bytes();
                let data = [p0, p1, a0, a1, 3, b'P', b'N'];
                let mut store = store();
                let heard = read(&[Ok(frame(0x359, &data))], Tick::ZERO, &mut store).unwrap();
                assert_eq!(heard.written, 0);
                let Frame::Status(status) = heard.frame else {
                    panic!("{:?}", heard.frame);
                };
                for other in Protection::ALL {
                    assert_eq!(
                        status.tripped(other),
                        other == protection && protections != 0,
                        "{protection:?} {other:?}"
                    );
                }
                for other in Alarm::ALL {
                    assert_eq!(
                        status.raised(other),
                        other == alarm && alarms != 0,
                        "{alarm:?} {other:?}"
                    );
                }
                assert_eq!(status.modules(), 3);
                // The store holds none of it.
                assert!(
                    store
                        .samples(Tick::ZERO)
                        .all(|s| s.unwrap().value().is_none())
                );
            }
        }
    }

    #[test]
    fn bits_the_tables_leave_unnamed_are_kept_rather_than_dropped() {
        let data = [0x41, 0xF6, 0x41, 0xF6, 1, b'P', b'N'];
        let Ok(Frame::Status(status)) = Frame::decode(&frame(0x359, &data)) else {
            panic!("a status frame");
        };
        assert!(Protection::ALL.iter().all(|p| !status.tripped(*p)));
        assert!(Alarm::ALL.iter().all(|a| !status.raised(*a)));
        assert_eq!(
            (status.protection_bits(), status.alarm_bits()),
            (0xF641, 0xF641)
        );

        let Ok(Frame::Requests(requests)) = Frame::decode(&frame(0x35C, &[0x07, 0xA5])) else {
            panic!("a requests frame");
        };
        assert!(Request::ALL.iter().all(|r| !requests.makes(*r)));
        assert_eq!(requests.bits(), 0xA507);
    }

    #[test]
    fn every_request_flag_decodes_as_itself_and_nothing_else() {
        let named = [
            (Request::ChargeEnable, 0x80u8),
            (Request::DischargeEnable, 0x40),
            (Request::ForceChargeOne, 0x20),
            (Request::ForceChargeTwo, 0x10),
            (Request::FullCharge, 0x08),
        ];
        for (request, bit) in named {
            let mut store = store();
            let heard = read(&[Ok(frame(0x35C, &[bit, 0]))], Tick::ZERO, &mut store).unwrap();
            assert_eq!(heard.written, 0);
            let Frame::Requests(requests) = heard.frame else {
                panic!("{:?}", heard.frame);
            };
            for other in Request::ALL {
                assert_eq!(
                    requests.makes(other),
                    other == request,
                    "{request:?} {other:?}"
                );
            }
        }
        let Ok(Frame::Requests(both)) = Frame::decode(&frame(0x35C, &[0xC0, 0])) else {
            panic!("a requests frame");
        };
        assert!(both.makes(Request::ChargeEnable) && both.makes(Request::DischargeEnable));
    }

    #[test]
    fn a_short_or_long_frame_is_refused_and_writes_nothing() {
        let cases: [(u16, FrameId, &[usize]); 5] = [
            (0x351, FrameId::Limits, &[0, 5, 7]),
            (0x355, FrameId::Charge, &[0, 3, 5, 8]),
            (0x356, FrameId::Pack, &[0, 5, 7, 8]),
            (0x359, FrameId::Status, &[0, 6, 8]),
            (0x35C, FrameId::Requests, &[0, 1, 3, 8]),
        ];
        for (raw, id, lengths) in cases {
            for &len in lengths {
                let mut data = [0u8; 8];
                // A signature where a status frame would carry it, so only
                // the length is wrong.
                data[5] = b'P';
                data[6] = b'N';
                let mut store = store();
                assert_eq!(
                    read(&[Ok(frame(raw, &data[..len]))], Tick::ZERO, &mut store),
                    Err(ReadError::Frame(FrameError::Length { id, len })),
                    "{raw:#x} {len}"
                );
                assert!(
                    store
                        .samples(Tick::ZERO)
                        .all(|s| s.unwrap().q.validity_of() == Validity::Initialising),
                    "{raw:#x} {len}"
                );
            }
        }
    }

    #[test]
    fn an_unknown_or_extended_identifier_is_refused_and_writes_nothing() {
        let extended = CanId::extended(0x351).unwrap();
        for can_id in [
            standard(0x305),
            standard(0x35E),
            standard(0x350),
            standard(0x7FF),
            extended,
        ] {
            let mut store = store();
            let unknown = CanFrame::new(can_id, &LIMITS_V13).unwrap();
            assert_eq!(
                read(&[Ok(unknown)], Tick::ZERO, &mut store),
                Err(ReadError::Frame(FrameError::Unknown(can_id)))
            );
            assert!(
                store
                    .samples(Tick::ZERO)
                    .all(|s| s.unwrap().q.validity_of() == Validity::Initialising)
            );
        }
    }

    #[test]
    fn a_status_frame_without_its_signature_is_refused() {
        for tail in [*b"PX", *b"NP", [0, 0]] {
            let data = [0, 0, 0, 0, 1, tail[0], tail[1]];
            assert_eq!(
                Frame::decode(&frame(0x359, &data)),
                Err(FrameError::Signature)
            );
        }
    }

    #[test]
    fn a_bms_that_goes_silent_reads_stale_after_the_maximum_age() {
        let mut store = store();
        let _ = read(&[Ok(frame(0x356, &PACK))], Tick::ZERO, &mut store).unwrap();
        let _ = read(&[Ok(frame(0x355, &CHARGE))], Tick::ZERO, &mut store).unwrap();

        let at_age = Tick::from_millis(MAX_AGE);
        assert_eq!(
            read(&[], at_age, &mut store),
            Err(ReadError::Port(PortFault::Timeout))
        );
        assert_eq!(value(&store, Channel::PackVoltage, at_age).1, Validity::Ok);

        let past = Tick::from_millis(MAX_AGE + 1);
        assert_eq!(
            read(&[], past, &mut store),
            Err(ReadError::Port(PortFault::Timeout))
        );
        assert_eq!(
            value(&store, Channel::PackVoltage, past),
            (Some(51_230), Validity::Stale, Provenance::Measured)
        );
        assert_eq!(
            store.current(
                bms().signal(Channel::StateOfCharge),
                past,
                ChargeSource::CountedOnly.accepts()
            ),
            Err(Ineligible::Stale(Provenance::Counted))
        );
    }

    #[test]
    fn a_read_waits_on_the_port_for_exactly_the_deadline_it_is_given() {
        let receives = [Ok(frame(0x355, &CHARGE))];
        let mut port = Script {
            receives: &receives,
            at: 0,
            waited: None,
        };
        let mut store = store();
        let within = Millis::from_millis(2_000);
        let heard = block_on(bms().read(&mut port, within, Tick::ZERO, &mut store)).unwrap();
        assert_eq!(heard.written, 1);
        assert_eq!(port.waited, Some(within));
    }

    #[test]
    fn a_line_fault_is_reported_as_itself_and_writes_nothing() {
        let mut store = store();
        assert_eq!(
            read(&[Err(PortFault::Line(7))], Tick::ZERO, &mut store),
            Err(ReadError::Port(PortFault::Line(7)))
        );
        assert!(
            store
                .samples(Tick::ZERO)
                .all(|s| s.unwrap().q.validity_of() == Validity::Initialising)
        );
    }

    #[test]
    fn a_store_missing_one_signal_refuses_the_whole_frame() {
        let mut store = Signals::<CHANNELS>::new();
        let limits = SignalLimits::new(Millis::from_millis(MAX_AGE), None).unwrap();
        // Every limit but the last.
        for channel in [
            Channel::ChargeVoltageLimit,
            Channel::ChargeCurrentLimit,
            Channel::DischargeCurrentLimit,
        ] {
            store.register(bms().signal(channel), limits).unwrap();
        }
        let missing = bms().signal(Channel::DischargeVoltageLimit);
        assert_eq!(
            read(&[Ok(frame(0x351, &LIMITS_V13))], Tick::ZERO, &mut store),
            Err(ReadError::Store(SignalError::Unknown(missing)))
        );
        assert!(
            store
                .samples(Tick::ZERO)
                .all(|s| s.unwrap().q.validity_of() == Validity::Initialising)
        );
    }

    #[test]
    fn a_frame_stamped_behind_the_last_write_is_refused_whole() {
        let mut store = store();
        let later = Tick::from_millis(5_000);
        let _ = read(&[Ok(frame(0x356, &PACK))], later, &mut store).unwrap();
        let earlier = Tick::from_millis(4_000);
        let colder = [0x03, 0x14, 0x83, 0xFF, 0x00, 0x00];
        assert_eq!(
            read(&[Ok(frame(0x356, &colder))], earlier, &mut store),
            Err(ReadError::Store(SignalError::TickBehind(
                bms().signal(Channel::PackVoltage)
            )))
        );
        assert_eq!(value(&store, Channel::Temperature, later).0, Some(-35));
    }

    #[test]
    fn a_bms_s_signals_are_consecutive_and_refused_past_the_top_of_the_range() {
        let bms = bms();
        for (offset, channel) in (0u16..).zip(Channel::ALL) {
            assert_eq!(bms.signal(channel), id(40 + offset), "{channel:?}");
        }
        assert!(Pylontech::new(id(0xFFF8), CurrentDirection::Unknown).is_some());
        assert_eq!(Pylontech::new(id(0xFFF9), CurrentDirection::Unknown), None);
        assert_eq!(Pylontech::new(id(0xFFFF), CurrentDirection::Unknown), None);
    }
}
