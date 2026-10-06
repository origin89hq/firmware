//! The devices a site can have, and the one call that reads each.
//!
//! A closed set, so an enum: a dialect lands as a variant, and every match
//! that has to answer for it stops compiling until it does. A bus task owns
//! its port and calls the entry for its kind of bus: [`Device::poll_rs485`],
//! [`Device::listen_vedirect`], [`Device::read_can`] and
//! [`Device::read_probe`]. Each refuses a device that is not on its kind of
//! bus, which configuration has already kept off it ([`crate::plan::Plan`]); the
//! refusal is there so that a mistake costs one poll and not a reading
//! written under somebody else's signal.

use km43::{ComponentRole, Id, SignalDomain, Validity};
use o89_core::{Heard, Millis, Readings, SignalError, Tick};

use crate::dialect::{DecodeError, Kind, RegisterMap};
use crate::ds18b20::{Conversion, Probe, ProbeError, ProbeRead};
use crate::epever::{self, Charger};
use crate::modbus::{self, Address, ModbusError, RECEIVE_BYTES, Timing};
use crate::port::{Can, Listener, OneWire, Rs485};
use crate::pylontech::FrameError;
use crate::pylontech::{self, Pylontech, ReadError};
use crate::pzem;
use crate::vedirect::{self, Channels, Field, Frame, ListenError, Parser};
use crate::vendor::DeclaredError;
use crate::vendor::{Report, VendorError};

/// The kinds of line a device can be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BusKind {
    /// An RS-485 byte port.
    Rs485,
    /// A VE.Direct port the controller only listens on.
    VeDirect,
    /// A CAN port.
    Can,
    /// A 1-Wire line.
    OneWire,
    /// The ADC.
    Adc,
}

/// A Modbus server and the store signals its register map's cells publish
/// as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ModbusDevice {
    address: Address,
    map: &'static RegisterMap,
    first: Id,
}

impl ModbusDevice {
    /// The server at `address` speaking `map`, whose cells publish as
    /// consecutive signals from `first` in the map's poll order.
    ///
    /// `None` when the map has no cells, which would poll as a silent
    /// device, or when the signals would run past `0xFFFF`. Keeping ranges
    /// of different devices apart is the configuration's to check.
    #[must_use]
    pub fn new(address: Address, map: &'static RegisterMap, first: Id) -> Option<Self> {
        let cells = u16::try_from(map.cells().count()).ok()?;
        first.get().checked_add(cells.checked_sub(1)?)?;
        Some(Self {
            address,
            map,
            first,
        })
    }

    /// The server's address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The register map.
    #[must_use]
    pub const fn map(&self) -> &'static RegisterMap {
        self.map
    }

    /// The signal the map's `index`th cell publishes as, or `None` past the
    /// map's last cell.
    #[must_use]
    pub fn signal(&self, index: usize) -> Option<Id> {
        if index >= self.map.cells().count() {
            return None;
        }
        let offset = u16::try_from(index).ok()?;
        Id::new(self.first.get().checked_add(offset)?).ok()
    }
}

/// A device on the site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Device {
    /// A Modbus RTU server described by a register map alone.
    Modbus(ModbusDevice),
    /// An EPEVER B-series charge controller.
    Epever(Charger),
    /// A PZEM-003 or PZEM-017 DC meter.
    PzemDc(pzem::dc::Meter),
    /// A PZEM-014 or PZEM-016 AC meter.
    PzemAc(pzem::ac::Meter),
    /// A Victron product's VE.Direct text port.
    VeDirect(Channels),
    /// A Pylontech-class BMS on CAN.
    Pylontech(Pylontech),
    /// A DS18B20 probe on the 1-Wire line.
    Ds18b20(Probe),
}

/// Why a poll stopped.
///
/// Whatever was written before the failure stands; the rest of the device's
/// signals keep their last values and age out through the store's maximum
/// age. A failed exchange writes nothing, so a garbled reply never
/// replaces a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed poll is a device whose readings were not refreshed"]
pub enum PollError<E> {
    /// The read of the block at `block` failed.
    Modbus {
        /// The block's position in the map.
        block: usize,
        /// Why.
        error: ModbusError<E>,
    },
    /// The cell at `cell`, counted across the map, could not be decoded.
    Decode {
        /// The cell's position in the map.
        cell: usize,
        /// Why.
        error: DecodeError,
    },
    /// The store refused a write.
    Store(SignalError),
    /// The device's signals run past `0xFFFF`, which [`ModbusDevice::new`]
    /// refuses; reported rather than wrapped onto another device's.
    Signals,
}

/// What a poll wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a poll's outcome is the device's presence"]
pub struct Polled {
    /// The signals written, one per cell.
    pub written: usize,
}

/// What a vendor said beside an RS-485 poll's readings, which no signal
/// carries: a charge stage, an alarm, a raw word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Conditions {
    /// A device whose map is all it reads.
    None,
    /// An EPEVER's status and raw words.
    Epever(epever::Words),
    /// A PZEM DC meter's raw words and alarms.
    PzemDc(pzem::dc::Words),
    /// A PZEM AC meter's power factor and alarm.
    PzemAc(pzem::ac::Words),
}

/// Why a device's entry wrote nothing, or stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed read is a device whose readings were not refreshed"]
pub enum DeviceError<E> {
    /// The device is on this kind of bus, not the one the entry reads.
    WrongBus(BusKind),
    /// A register map's poll failed.
    Poll(PollError<E>),
    /// A vendor dialect's poll failed.
    Vendor(VendorError<E>),
    /// A VE.Direct port was silent or faulted.
    Listen(ListenError<E>),
    /// A CAN read failed.
    Can(ReadError<E>),
    /// A probe read failed.
    Probe(ProbeError<E>),
}

impl<E> DeviceError<E> {
    /// What the failure says of the device: silent when nothing came back
    /// in time, faulty when something did and was refused, and nothing at
    /// all when the failure is the line's, the store's or the adapter's,
    /// or another node's frame on a shared bus.
    #[must_use]
    pub const fn heard(&self) -> Option<Heard> {
        match self {
            Self::WrongBus(_) => None,
            Self::Poll(error) => poll_heard(error),
            Self::Vendor(error) => match error {
                VendorError::Poll(error) => poll_heard(error),
                VendorError::Conditions(error)
                | VendorError::Declared {
                    error: DeclaredError::Read(error),
                    ..
                } => modbus_heard(error),
                VendorError::Declared {
                    error: DeclaredError::Decode(_),
                    ..
                }
                | VendorError::Condition(_) => Some(Heard::Faulty),
                VendorError::Declared {
                    error: DeclaredError::Store(_),
                    ..
                } => None,
            },
            Self::Listen(error) => match error {
                ListenError::Silent => Some(Heard::Silent),
                ListenError::Line(_) => Some(Heard::Faulty),
                ListenError::Adapter => None,
            },
            Self::Can(error) => match error {
                ReadError::Port(crate::port::PortFault::Timeout) => Some(Heard::Silent),
                ReadError::Frame(FrameError::Length { .. } | FrameError::Signature) => {
                    Some(Heard::Faulty)
                }
                ReadError::Port(crate::port::PortFault::Line(_))
                | ReadError::Frame(FrameError::Unknown(_))
                | ReadError::Store(_) => None,
            },
            Self::Probe(error) => match error {
                ProbeError::Line(_)
                | ProbeError::Early
                | ProbeError::Expired
                | ProbeError::Store(_)
                | ProbeError::Quality(_) => None,
            },
        }
    }
}

const fn poll_heard<E>(error: &PollError<E>) -> Option<Heard> {
    match error {
        PollError::Modbus { error, .. } => modbus_heard(error),
        PollError::Decode { .. } => Some(Heard::Faulty),
        PollError::Store(_) | PollError::Signals => None,
    }
}

/// A Modbus exchange's failure, as presence: a reply that never began is
/// silence; one that arrived and was refused is a device answering
/// badly. A missing echo is the bus, not the device.
const fn modbus_heard<E>(error: &ModbusError<E>) -> Option<Heard> {
    match error {
        ModbusError::Timeout => Some(Heard::Silent),
        ModbusError::Reply(_) => Some(Heard::Faulty),
        ModbusError::Echo | ModbusError::Port(_) | ModbusError::Adapter => None,
    }
}

/// How long a bus must stay quiet after an exchange before the next one
/// discards what the port holds: a response bound after one that heard
/// nothing, so a reply later than the bound but inside twice it lands
/// before that discard and is dropped by it, rather than taken for the next
/// exchange's own; nothing after any other outcome.
#[must_use]
pub fn quiet_after<T, E>(result: &Result<T, DeviceError<E>>, timing: Timing) -> Millis {
    match result.as_ref().err().and_then(DeviceError::heard) {
        Some(Heard::Silent) => timing.response,
        Some(Heard::Answered | Heard::Faulty) | None => Millis::ZERO,
    }
}

/// What a probe read says of the probe.
#[must_use]
pub const fn probe_heard(read: &ProbeRead) -> Heard {
    match read {
        ProbeRead::Wrote(seen) => match seen.quality().validity_of() {
            Validity::Absent => Heard::Silent,
            Validity::Ok => Heard::Answered,
            Validity::Stale
            | Validity::OutOfRange
            | Validity::SensorFault
            | Validity::Initialising
            | Validity::Unsupported
            | Validity::Reset
            | Validity::UnnamedState => Heard::Faulty,
        },
        ProbeRead::Crc { .. } | ProbeRead::Failing(_) => Heard::Faulty,
    }
}

/// What a VE.Direct burst says of the product: a verified block is an
/// answer; only refused ones are a product answering badly.
#[must_use]
pub const fn vedirect_heard(heard: &vedirect::Heard) -> Option<Heard> {
    if heard.blocks > 0 {
        Some(Heard::Answered)
    } else if heard.refused > 0 {
        Some(Heard::Faulty)
    } else {
        None
    }
}

impl Device {
    /// The kind of bus it is on.
    #[must_use]
    pub const fn bus(&self) -> BusKind {
        match self {
            Self::Modbus(_) | Self::Epever(_) | Self::PzemDc(_) | Self::PzemAc(_) => BusKind::Rs485,
            Self::VeDirect(_) => BusKind::VeDirect,
            Self::Pylontech(_) => BusKind::Can,
            Self::Ds18b20(_) => BusKind::OneWire,
        }
    }

    /// The signal its `index`th reading publishes as, in the order
    /// [`Device::layout`] describes them; `None` past the last.
    #[must_use]
    pub fn signal(&self, index: usize) -> Option<Id> {
        match self {
            Self::Modbus(device) => device.signal(index),
            Self::Epever(charger) => charger.signal(index),
            Self::PzemDc(meter) => meter.signal(index),
            Self::PzemAc(meter) => meter.signal(index),
            Self::VeDirect(channels) => VEDIRECT_FIELDS
                .get(index)
                .and_then(|field| channels.signal(*field)),
            Self::Pylontech(bms) => pylontech::Channel::ALL
                .get(index)
                .map(|channel| bms.signal(*channel)),
            Self::Ds18b20(probe) => (index == 0).then_some(probe.signal()),
        }
    }

    /// What each of its signals is, in its numbering: kind, window, and
    /// the part of the device it describes. The ids are
    /// [`Device::signal`]'s.
    #[must_use]
    pub fn layout(&self) -> Layout {
        let mut layout = Layout::EMPTY;
        match self {
            Self::Modbus(device) => {
                for cell in device.map.cells() {
                    layout.push(Described::whole(cell.kind, cell.domain));
                }
            }
            Self::Epever(_) => {
                for cell in epever::MAP.cells() {
                    let part = epever::ROLES
                        .iter()
                        .find(|(register, _)| *register == cell.register)
                        .map(|(_, role)| *role);
                    layout.push(Described {
                        kind: cell.kind,
                        domain: cell.domain,
                        part,
                    });
                }
                layout.push(Described::of(
                    Kind::StateOfCharge,
                    SignalDomain::Live,
                    ComponentRole::BATTERY_BANK,
                ));
                layout.push(Described::of(
                    Kind::DcCurrent,
                    SignalDomain::Live,
                    ComponentRole::BATTERY_BANK,
                ));
            }
            Self::PzemDc(_) => {
                for cell in pzem::dc::MAP.cells() {
                    layout.push(Described::whole(cell.kind, cell.domain));
                }
            }
            Self::PzemAc(_) => {
                for cell in pzem::ac::PZEM_016.cells() {
                    layout.push(Described::whole(cell.kind, cell.domain));
                }
            }
            Self::VeDirect(_) => {
                for field in VEDIRECT_FIELDS {
                    let (kind, part) = match field {
                        Field::BatteryVoltage => (Kind::DcVoltage, ComponentRole::BATTERY_BANK),
                        Field::BatteryCurrent => (Kind::DcCurrent, ComponentRole::BATTERY_BANK),
                        Field::PanelPower
                        | Field::ChargeState
                        | Field::Error
                        | Field::YieldTotal
                        | Field::YieldToday
                        | Field::YieldYesterday => (Kind::DcPower, ComponentRole::MPPT_TRACKER),
                    };
                    layout.push(Described::of(kind, SignalDomain::Live, part));
                }
            }
            Self::Pylontech(_) => {
                for channel in pylontech::Channel::ALL {
                    layout.push(Described::whole(channel.kind(), channel.domain()));
                }
            }
            Self::Ds18b20(_) => {
                layout.push(Described::whole(Kind::Temperature, SignalDomain::Live));
            }
        }
        layout
    }

    /// Read the device over an RS-485 port and write what it says into
    /// `store` at `now`, with each reading's declared provenance; the
    /// vendor's words beside them come back in the report.
    ///
    /// Each exchange is bounded by `timing`; the poll stops at the first
    /// failure.
    pub async fn poll_rs485<P: Rs485, R: Readings>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut R,
    ) -> Result<Report<Conditions>, DeviceError<P::Error>> {
        match self {
            Self::Modbus(device) => poll_modbus(device, port, timing, now, store)
                .await
                .map(|polled| Report {
                    polled,
                    conditions: Conditions::None,
                })
                .map_err(DeviceError::Poll),
            Self::Epever(charger) => charger
                .poll(port, timing, now, store)
                .await
                .map(|report| Report {
                    polled: report.polled,
                    conditions: Conditions::Epever(report.conditions),
                })
                .map_err(DeviceError::Vendor),
            Self::PzemDc(meter) => meter
                .poll(port, timing, now, store)
                .await
                .map(|report| Report {
                    polled: report.polled,
                    conditions: Conditions::PzemDc(report.conditions),
                })
                .map_err(DeviceError::Vendor),
            Self::PzemAc(meter) => meter
                .poll(port, timing, now, store)
                .await
                .map(|report| Report {
                    polled: report.polled,
                    conditions: Conditions::PzemAc(report.conditions),
                })
                .map_err(DeviceError::Vendor),
            Self::VeDirect(_) | Self::Pylontech(_) | Self::Ds18b20(_) => {
                Err(DeviceError::WrongBus(self.bus()))
            }
        }
    }

    /// Hear one burst on a VE.Direct port, at most `within` for its first
    /// byte, and write each verified block's readings into `store` at `now`;
    /// every verified block goes to `on_block` for what no signal carries.
    pub async fn listen_vedirect<L: Listener, R: Readings>(
        &self,
        port: &mut L,
        parser: &mut Parser,
        within: Millis,
        now: Tick,
        store: &mut R,
        on_block: impl FnMut(&Frame),
    ) -> Result<vedirect::Heard, DeviceError<L::Error>> {
        match self {
            Self::VeDirect(channels) => {
                vedirect::listen(port, parser, within, channels, now, store, on_block)
                    .await
                    .map_err(DeviceError::Listen)
            }
            Self::Modbus(_)
            | Self::Epever(_)
            | Self::PzemDc(_)
            | Self::PzemAc(_)
            | Self::Pylontech(_)
            | Self::Ds18b20(_) => Err(DeviceError::WrongBus(self.bus())),
        }
    }

    /// Wait at most `within` for a BMS's next frame and write it into
    /// `store` at `now`.
    pub async fn read_can<P: Can, R: Readings>(
        &self,
        port: &mut P,
        within: Millis,
        now: Tick,
        store: &mut R,
    ) -> Result<pylontech::Heard, DeviceError<P::Error>> {
        match self {
            Self::Pylontech(bms) => bms
                .read(port, within, now, store)
                .await
                .map_err(DeviceError::Can),
            Self::Modbus(_)
            | Self::Epever(_)
            | Self::PzemDc(_)
            | Self::PzemAc(_)
            | Self::VeDirect(_)
            | Self::Ds18b20(_) => Err(DeviceError::WrongBus(self.bus())),
        }
    }

    /// Read a probe's share of `conversion` at `now` and write it into
    /// `store` at the tick the conversion finished.
    pub async fn read_probe<W: OneWire, R: Readings>(
        &mut self,
        line: &mut W,
        conversion: &Conversion,
        now: Tick,
        store: &mut R,
    ) -> Result<ProbeRead, DeviceError<W::Error>> {
        let bus = self.bus();
        match self {
            Self::Ds18b20(probe) => probe
                .read(line, conversion, now, store)
                .await
                .map_err(DeviceError::Probe),
            Self::Modbus(_)
            | Self::Epever(_)
            | Self::PzemDc(_)
            | Self::PzemAc(_)
            | Self::VeDirect(_)
            | Self::Pylontech(_) => Err(DeviceError::WrongBus(bus)),
        }
    }
}

/// The VE.Direct fields a port publishes, in the order its signals are
/// numbered.
pub const VEDIRECT_FIELDS: [Field; 3] = [
    Field::BatteryVoltage,
    Field::BatteryCurrent,
    Field::PanelPower,
];

/// The most signals one device publishes: an EPEVER's map, its state of
/// charge and its battery current.
pub const DEVICE_SIGNALS: usize = epever::Charger::SIGNALS;

const _: () = {
    assert!(pylontech::CHANNELS <= DEVICE_SIGNALS);
    assert!(pzem::ac::Meter::SIGNALS <= DEVICE_SIGNALS);
    assert!(VEDIRECT_FIELDS.len() <= DEVICE_SIGNALS);
};

/// What one of a device's signals is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Described {
    /// Its kind.
    pub kind: Kind,
    /// Its window.
    pub domain: SignalDomain,
    /// The part of the device it describes, or `None` for the device as a
    /// whole.
    pub part: Option<ComponentRole>,
}

impl Described {
    const fn whole(kind: Kind, domain: SignalDomain) -> Self {
        Self {
            kind,
            domain,
            part: None,
        }
    }

    const fn of(kind: Kind, domain: SignalDomain, part: ComponentRole) -> Self {
        Self {
            kind,
            domain,
            part: Some(part),
        }
    }
}

/// A device's signals, described, at most [`DEVICE_SIGNALS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Layout {
    signals: [Option<Described>; DEVICE_SIGNALS],
    len: usize,
}

impl Layout {
    const EMPTY: Self = Self {
        signals: [None; DEVICE_SIGNALS],
        len: 0,
    };

    /// Add one. Every device's count is held at or under the capacity at
    /// compile time above, so none is dropped; one that were would be a
    /// device whose layout is short, which the plan's per-device test
    /// catches.
    fn push(&mut self, described: Described) {
        if let Some(slot) = self.signals.get_mut(self.len) {
            *slot = Some(described);
            self.len = self.len.saturating_add(1);
        }
    }

    /// How many signals.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The signals, in the device's numbering.
    pub fn iter(&self) -> impl Iterator<Item = &Described> {
        self.signals.iter().take(self.len).flatten()
    }
}

async fn poll_modbus<P: Rs485, R: Readings>(
    device: &ModbusDevice,
    port: &mut P,
    timing: Timing,
    now: Tick,
    store: &mut R,
) -> Result<Polled, PollError<P::Error>> {
    let mut cell = 0usize;
    let mut buf = [0u8; RECEIVE_BYTES];
    for (block_at, block) in device.map.blocks.iter().enumerate() {
        let read = block.read(device.address);
        let registers = modbus::read(port, read, timing, &mut buf)
            .await
            .map_err(|error| PollError::Modbus {
                block: block_at,
                error,
            })?;
        for seen in block.decode(&registers) {
            let seen = seen.map_err(|error| PollError::Decode { cell, error })?;
            let sig = device.signal(cell).ok_or(PollError::Signals)?;
            store.write(sig, now, seen).map_err(PollError::Store)?;
            cell = cell.saturating_add(1);
        }
    }
    Ok(Polled { written: cell })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::tests::cell;
    use crate::dialect::{Block, Kind};
    use crate::modbus::tests::{Scripted, TIMING};
    use crate::modbus::{Function, ReplyError};
    use embassy_futures::block_on;
    use km43::{Dialect, Provenance, SignalDomain, Validity};
    use o89_core::Signals;
    use o89_core::{ChargeSource, Ineligible, Limits, Millis};

    /// Two blocks built by hand for these tests; not a vendor's map.
    static FIRST: [crate::dialect::Cell; 2] = [
        cell(
            0x10,
            Kind::DcVoltage,
            SignalDomain::Live,
            -2,
            Provenance::Measured,
        ),
        cell(
            0x11,
            Kind::StateOfCharge,
            SignalDomain::Live,
            0,
            Provenance::Estimated,
        ),
    ];
    static SECOND: [crate::dialect::Cell; 1] = [cell(
        0x40,
        Kind::DcCurrent,
        SignalDomain::LimitUpper,
        -2,
        Provenance::Reported,
    )];
    static BLOCKS: [Block; 2] = [
        crate::block!(Function::ReadInput, 0x10, 2, &FIRST),
        crate::block!(Function::ReadHolding, 0x40, 1, &SECOND),
    ];
    static EMPTY: RegisterMap = RegisterMap {
        dialect: Dialect(0xF001),
        blocks: &[],
    };
    static MAP: RegisterMap = RegisterMap {
        dialect: Dialect(0xF000),
        blocks: &BLOCKS,
    };

    /// A counted state of charge in tenths of a percent, signed, built by
    /// hand; not a vendor's row.
    static SOC_CELLS: [crate::dialect::Cell; 1] = [crate::dialect::Cell {
        sign: crate::dialect::Sign::Signed,
        ..cell(
            0x20,
            Kind::StateOfCharge,
            SignalDomain::Live,
            -1,
            Provenance::Counted,
        )
    }];
    static SOC_BLOCKS: [Block; 1] = [crate::block!(Function::ReadInput, 0x20, 1, &SOC_CELLS)];
    static SOC_MAP: RegisterMap = RegisterMap {
        dialect: Dialect(0xF002),
        blocks: &SOC_BLOCKS,
    };

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn device() -> Device {
        Device::Modbus(ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(20)).unwrap())
    }

    fn store() -> Signals<4> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
        for n in 20..=22 {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    fn reply(function: u8, words: &[u16]) -> ([u8; crate::modbus::FRAME_BYTES], usize) {
        crate::modbus::tests::register_reply(7, function, words)
    }

    fn echo(block: usize) -> [u8; 8] {
        BLOCKS[block].read(Address::new(7).unwrap()).encode()
    }

    #[test]
    fn f_052_a_poll_writes_every_cell_with_its_declared_provenance() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (second, second_len) = reply(0x03, &[5000]);
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = store();

        let polled =
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)).unwrap();
        assert_eq!(polled.polled, Polled { written: 3 });
        assert_eq!(polled.conditions, Conditions::None);

        let volts = store.sample(id(20), Tick::ZERO).unwrap();
        assert_eq!(
            (volts.value(), volts.q.provenance_of()),
            (Some(13_250), Provenance::Measured)
        );
        let soc = store.sample(id(21), Tick::ZERO).unwrap();
        assert_eq!(
            (soc.value(), soc.q.provenance_of()),
            (Some(640), Provenance::Estimated)
        );
        let limit = store.sample(id(22), Tick::ZERO).unwrap();
        assert_eq!(
            (limit.value(), limit.q.provenance_of()),
            (Some(50_000), Provenance::Reported)
        );
        assert_eq!(
            store.current(id(21), Tick::ZERO, ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Provenance(Provenance::Estimated))
        );
    }

    #[test]
    fn an_implausible_state_of_charge_is_out_of_range_and_never_eligible() {
        let soc =
            Device::Modbus(ModbusDevice::new(Address::new(7).unwrap(), &SOC_MAP, id(30)).unwrap());
        let read = SOC_BLOCKS[0].read(Address::new(7).unwrap());
        for (raw, expected) in [
            ((-1i16).cast_unsigned(), None),
            (0, Some(0)),
            (1000, Some(1000)),
            (1001, None),
            (0x7FFF, None),
        ] {
            let mut store = Signals::<1>::new();
            let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
            store.register(id(30), limits).unwrap();
            let echo = read.encode();
            let (frame, len) = reply(0x04, &[raw]);
            let bursts: [&[u8]; 2] = [&echo, &frame[..len]];
            let mut port = Scripted::new(&bursts);
            let polled = block_on(soc.poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store));
            assert_eq!(
                polled.map(|report| report.polled),
                Ok(Polled { written: 1 }),
                "{raw}"
            );

            let eligible = store.current(id(30), Tick::ZERO, ChargeSource::CountedOnly.accepts());
            match expected {
                Some(value) => {
                    let eligible = eligible.unwrap();
                    assert_eq!(
                        (eligible.value(), eligible.provenance()),
                        (value, Provenance::Counted)
                    );
                }
                None => assert_eq!(
                    eligible,
                    Err(Ineligible::NoValue(Validity::OutOfRange)),
                    "{raw}"
                ),
            }
        }
    }

    #[test]
    fn a_failed_block_stops_the_poll_writes_nothing_for_it_and_keeps_what_came_before() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (mut second, second_len) = reply(0x03, &[5000]);
        second[4] ^= 1;
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = store();

        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(DeviceError::Poll(PollError::Modbus {
                block: 1,
                error: ModbusError::Reply(ReplyError::Crc)
            }))
        );
        assert_eq!(
            store.sample(id(20), Tick::ZERO).unwrap().value(),
            Some(13_250)
        );
        // The limit was never read, so it has never had a value.
        let limit = store.sample(id(22), Tick::ZERO).unwrap();
        assert_eq!(limit.value(), None);
        assert_eq!(limit.q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn a_device_that_never_answers_writes_nothing_and_ages_out_through_the_store() {
        let mut store = store();
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (second, second_len) = reply(0x03, &[5000]);
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let _ = block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)).unwrap();

        let bursts: [&[u8]; 1] = [&e0];
        let mut port = Scripted::new(&bursts);
        let later = Tick::from_millis(60_001);
        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, later, &mut store)),
            Err(DeviceError::Poll(PollError::Modbus {
                block: 0,
                error: ModbusError::Timeout
            }))
        );
        let volts = store.sample(id(20), later).unwrap();
        assert_eq!(volts.q.validity_of(), Validity::Stale);
        assert_eq!(volts.value(), Some(13_250));
    }

    #[test]
    fn a_write_to_a_signal_the_store_does_not_hold_is_refused() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let e0 = echo(0);
        let bursts: [&[u8]; 2] = [&e0, &first[..first_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = Signals::<4>::new();
        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(DeviceError::Poll(PollError::Store(SignalError::Unknown(
                id(20)
            ))))
        );
    }

    #[test]
    fn a_device_s_signals_are_consecutive_and_refused_past_the_top_of_the_range() {
        let Device::Modbus(device) = device() else {
            panic!("a register-map device");
        };
        assert_eq!(
            device.bus_signals(),
            [Some(id(20)), Some(id(21)), Some(id(22)), None]
        );
        assert_eq!(Device::Modbus(device).bus(), BusKind::Rs485);
        assert!(ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(0xFFFD)).is_some());
        assert_eq!(
            ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(0xFFFE)),
            None
        );
        assert_eq!(
            ModbusDevice::new(Address::new(7).unwrap(), &EMPTY, id(1)),
            None
        );
    }

    impl ModbusDevice {
        fn bus_signals(&self) -> [Option<Id>; 4] {
            [
                self.signal(0),
                self.signal(1),
                self.signal(2),
                self.signal(3),
            ]
        }
    }

    /// One device of every kind, built by hand on signals from 100.
    fn every_kind() -> [Device; 7] {
        let address = Address::new(1).unwrap();
        [
            device(),
            Device::Epever(
                Charger::new(
                    address,
                    id(100),
                    epever::StateOfCharge::Unsupported,
                    epever::BatteryCurrent::Unsupported,
                )
                .unwrap(),
            ),
            Device::PzemDc(pzem::dc::Meter::new(address, id(110))),
            Device::PzemAc(
                pzem::ac::Meter::new(address, id(120), pzem::ac::Model::Pzem016).unwrap(),
            ),
            Device::VeDirect(Channels::new(Some(id(130)), Some(id(131)), Some(id(132))).unwrap()),
            Device::Pylontech(
                Pylontech::new(
                    id(140),
                    pylontech::Version::V13,
                    pylontech::CurrentDirection::Unknown,
                )
                .unwrap(),
            ),
            Device::Ds18b20(Probe::new(valid_rom(), id(150)).unwrap()),
        ]
    }

    /// A DS18B20 ROM code whose CRC holds, computed here.
    fn valid_rom() -> crate::onewire::Rom {
        let mut bytes = [0x28, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0];
        bytes[7] = crate::onewire::crc8(&bytes[..7]);
        crate::onewire::Rom::new(bytes).unwrap()
    }

    /// A line that answers nothing; nothing here should reach it.
    struct Untouched;

    impl Rs485 for Untouched {
        type Error = u8;
        fn discard(&mut self) -> impl core::future::Future<Output = Result<(), u8>> {
            core::future::ready(Err(1))
        }
        fn send(&mut self, _: &[u8]) -> impl core::future::Future<Output = Result<(), u8>> {
            core::future::ready(Err(1))
        }
        fn receive(
            &mut self,
            _: &mut [u8],
            _: Millis,
        ) -> impl core::future::Future<Output = Result<crate::port::Burst, crate::port::PortFault<u8>>>
        {
            core::future::ready(Err(crate::port::PortFault::Line(1)))
        }
    }

    impl Listener for Untouched {
        type Error = u8;
        fn receive(
            &mut self,
            _: &mut [u8],
            _: Millis,
        ) -> impl core::future::Future<Output = Result<crate::port::Burst, crate::port::PortFault<u8>>>
        {
            core::future::ready(Err(crate::port::PortFault::Line(1)))
        }
    }

    impl Can for Untouched {
        type Error = u8;
        fn send(
            &mut self,
            _: &crate::port::CanFrame,
        ) -> impl core::future::Future<Output = Result<(), u8>> {
            core::future::ready(Err(1))
        }
        fn receive(
            &mut self,
            _: Millis,
        ) -> impl core::future::Future<Output = Result<crate::port::CanFrame, crate::port::PortFault<u8>>>
        {
            core::future::ready(Err(crate::port::PortFault::Line(1)))
        }
    }

    impl OneWire for Untouched {
        type Error = u8;
        fn reset(
            &mut self,
        ) -> impl core::future::Future<Output = Result<crate::port::Presence, u8>> {
            core::future::ready(Err(1))
        }
        fn write_bit(&mut self, _: bool) -> impl core::future::Future<Output = Result<(), u8>> {
            core::future::ready(Err(1))
        }
        fn read_bit(&mut self) -> impl core::future::Future<Output = Result<bool, u8>> {
            core::future::ready(Err(1))
        }
    }

    #[test]
    fn every_entry_refuses_a_device_on_another_kind_of_bus_without_touching_its_line() {
        let mut store = Signals::<4>::new();
        let conversion = ready_conversion();
        for mut device in every_kind() {
            let bus = device.bus();
            let refused =
                |error: Option<DeviceError<u8>>| error == Some(DeviceError::WrongBus(bus));
            let rs485 = block_on(device.poll_rs485(&mut Untouched, TIMING, Tick::ZERO, &mut store));
            let mut parser = Parser::new();
            let heard = block_on(device.listen_vedirect(
                &mut Untouched,
                &mut parser,
                Millis::from_millis(1),
                Tick::ZERO,
                &mut store,
                |_| {},
            ));
            let can = block_on(device.read_can(
                &mut Untouched,
                Millis::from_millis(1),
                Tick::ZERO,
                &mut store,
            ));
            let probe =
                block_on(device.read_probe(&mut Untouched, &conversion, Tick::ZERO, &mut store));
            // A device's own entry reaches its line, which fails; every
            // other entry refuses it first.
            assert_eq!(refused(rs485.err()), bus != BusKind::Rs485, "{device:?}");
            assert_eq!(refused(heard.err()), bus != BusKind::VeDirect, "{device:?}");
            assert_eq!(refused(can.err()), bus != BusKind::Can, "{device:?}");
            assert_eq!(refused(probe.err()), bus != BusKind::OneWire, "{device:?}");
        }
    }

    /// A conversion whose window holds `Tick::ZERO`.
    fn ready_conversion() -> Conversion {
        // The only way to make one is a line that showed a conversion.
        struct Converting(u8);
        impl OneWire for Converting {
            type Error = u8;
            fn reset(
                &mut self,
            ) -> impl core::future::Future<Output = Result<crate::port::Presence, u8>> {
                core::future::ready(Ok(crate::port::Presence::Present))
            }
            fn write_bit(&mut self, _: bool) -> impl core::future::Future<Output = Result<(), u8>> {
                core::future::ready(Ok(()))
            }
            fn read_bit(&mut self) -> impl core::future::Future<Output = Result<bool, u8>> {
                self.0 = self.0.saturating_add(1);
                core::future::ready(Ok(false))
            }
        }
        struct Zero;
        impl o89_core::Clock for Zero {
            fn now(&self) -> Tick {
                Tick::ZERO
            }
        }
        block_on(crate::ds18b20::convert_all(&mut Converting(0), &Zero)).unwrap()
    }

    #[test]
    fn a_device_s_layout_describes_exactly_the_signals_it_publishes() {
        let sizes = [3, 9, 1, 5, 3, 8, 1];
        for (device, size) in every_kind().into_iter().zip(sizes) {
            let layout = device.layout();
            assert_eq!(layout.len(), size, "{device:?}");
            assert!(!layout.is_empty());
            for index in 0..size {
                assert!(device.signal(index).is_some(), "{device:?} {index}");
            }
            assert_eq!(device.signal(size), None, "{device:?}");
        }
        // An EPEVER's battery cells describe the bank; its PV ones the
        // tracker.
        let charger = every_kind()[1].layout();
        let parts: [Option<ComponentRole>; 9] =
            core::array::from_fn(|at| charger.iter().nth(at).and_then(|described| described.part));
        assert_eq!(parts[0], Some(ComponentRole::MPPT_TRACKER));
        assert_eq!(parts[6], Some(ComponentRole::BATTERY_BANK));
        assert_eq!(parts[8], Some(ComponentRole::BATTERY_BANK));
    }

    #[test]
    fn f_052_a_pzem_dc_polled_as_a_device_writes_its_voltage_and_hands_back_its_words() {
        let address = Address::new(1).unwrap();
        let meter = Device::PzemDc(pzem::dc::Meter::new(address, id(40)));
        let echo = pzem::dc::MAP.blocks[0].read(address).encode();
        let (reply, len) =
            crate::modbus::tests::register_reply(1, 0x04, &[0x2710, 0x0064, 0x03E8, 0, 0, 0, 0, 0]);
        let bursts: [&[u8]; 2] = [&echo, &reply[..len]];
        let mut port = Scripted::new(&bursts);
        let mut store = Signals::<1>::new();
        let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
        store.register(id(40), limits).unwrap();
        let report = block_on(meter.poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)).unwrap();
        assert_eq!(report.polled, Polled { written: 1 });
        assert!(matches!(report.conditions, Conditions::PzemDc(_)));
        let volts = store.sample(id(40), Tick::ZERO).unwrap();
        assert_eq!(
            (volts.value(), volts.q.provenance_of()),
            (Some(100_000), Provenance::Measured)
        );
    }

    #[test]
    fn f_050_a_bus_stays_quiet_a_response_bound_after_an_exchange_that_heard_nothing() {
        let silent: Result<(), DeviceError<u8>> = Err(DeviceError::Poll(PollError::Modbus {
            block: 0,
            error: ModbusError::Timeout,
        }));
        assert_eq!(quiet_after(&silent, TIMING), TIMING.response);
        let refused = DeviceError::<u8>::Poll(PollError::Modbus {
            block: 0,
            error: ModbusError::Reply(ReplyError::Crc),
        });
        assert_eq!(quiet_after(&Err::<(), _>(refused), TIMING), Millis::ZERO);
        assert_eq!(refused.heard(), Some(Heard::Faulty));
        let echo = DeviceError::<u8>::Poll(PollError::Modbus {
            block: 0,
            error: ModbusError::Echo,
        });
        assert_eq!(echo.heard(), None);

        assert_eq!(
            quiet_after(&Ok::<(), DeviceError<u8>>(()), TIMING),
            Millis::ZERO
        );
    }

    #[test]
    fn a_failure_says_silent_faulty_or_nothing_of_the_device() {
        assert_eq!(
            DeviceError::<u8>::Listen(ListenError::Silent).heard(),
            Some(Heard::Silent)
        );
        assert_eq!(
            DeviceError::<u8>::Listen(ListenError::Line(3)).heard(),
            Some(Heard::Faulty)
        );
        assert_eq!(
            DeviceError::<u8>::Can(ReadError::Port(crate::port::PortFault::Timeout)).heard(),
            Some(Heard::Silent)
        );
        // Another node's frame on the bus says nothing of the BMS.
        let other = crate::port::CanId::standard(0x305).unwrap();
        assert_eq!(
            DeviceError::<u8>::Can(ReadError::Frame(FrameError::Unknown(other))).heard(),
            None
        );
        assert_eq!(DeviceError::<u8>::WrongBus(BusKind::Can).heard(), None);
        assert_eq!(DeviceError::<u8>::Probe(ProbeError::Early).heard(), None);
        let absent = o89_core::Observation::missing(Validity::Absent).unwrap();
        assert_eq!(probe_heard(&ProbeRead::Wrote(absent)), Heard::Silent);
        assert_eq!(
            probe_heard(&ProbeRead::Crc { consecutive: 1 }),
            Heard::Faulty
        );
    }
}
