//! From `0x0003 buses and devices` to the site: which device each entry
//! is, the signals it publishes and their ids, how each bus runs, and the
//! rows the inventory lists.
//!
//! The section names a device by its dialect, its product, its bus and its
//! address; everything else is derived here, from the dialect, and is not
//! configurable (P-263). A device's components and signals take ids from a
//! block of [`STRIDE`] numbered from its `dev`, so an edit that keeps a
//! device keeps its ids, and the history filed under them (P-262). The
//! controller's own inputs are `dev 0`'s, on `bus 0`.
//!
//! [`Plan::new`] is the whole check the firmware adds to km43's: it runs on
//! every write before it is stored ([`BUSES_CHECK`]), and again on the
//! section the boot reads, so a section the controller accepted is one it
//! can build, and the boot never builds one it would refuse. What it
//! refuses, beside what km43 does: a bus carrying more devices than its
//! task holds; a product the dialect's driver does not read, or a dialect
//! whose products km43 has not allocated; an address the driver cannot use;
//! an option value the driver cannot honour; devices on one serial bus that
//! need different line settings the bus entry does not settle; a site whose
//! signals or components do not fit the store; and two devices whose
//! signal ids overlap, so that no signal has two writers.
//!
//! cites: P-202, P-261, P-262, P-263, P-264, P-265

use core::num::NonZeroU32;

use km43::{
    Addr, BusEntry, BusesAndDevicesKey, BusesAndDevicesRead, ComponentRole, ConfigError,
    CurrentDirection, DataBits, DevId, DeviceEntry, DeviceOption, DeviceRole, Dialect, DialectRule,
    Direction, Id, MAX_CONFIG_DEVICES, MAX_TOPOLOGY_DEPTH, Parity, Product, PylontechVersion,
    SectionKey, SiteRules, StopBits, Transport, Vtype,
};
use o89_core::{
    BOARD_BUSES, BusesCheck, CONNECTORS, Connector, Descriptor, DeviceAddress, Limits, Millis,
    Port, SIGNAL_SLOTS, SITE_COMPONENTS, SITE_DEVICES, SiteComponent, SiteDevice, SiteSignal,
};

use crate::device::{DEVICE_SIGNALS, Described, Device, Layout, VEDIRECT_FIELDS};
use crate::dialect::Kind;
use crate::ds18b20::{self, Probe};
use crate::epever::{BatteryCurrent, Charger, StateOfCharge};
use crate::modbus::{Address, Timing};
use crate::onewire::Rom;
use crate::pylontech::{self, Pylontech};
use crate::pzem;
use crate::serial::Framing;
use crate::vedirect::Channels;

/// How many ids a device's components and signals each take: its `dev`
/// times this, plus one, is its first.
pub const STRIDE: u16 = 16;

const _: () = assert!(
    DEVICE_SIGNALS < STRIDE as usize,
    "a device's signals must fit its block of ids"
);

/// The highest `dev` whose block of ids fits under `0xFFFF`.
pub const LAST_DEV: u16 = u16::MAX / STRIDE - 1;

/// The id the `index`th component or signal of `dev` takes, or `None`
/// past its block or past [`LAST_DEV`].
#[must_use]
pub fn derived(dev: u16, index: usize) -> Option<Id> {
    let offset = u16::try_from(index)
        .ok()
        .filter(|offset| *offset < STRIDE - 1)?;
    if dev > LAST_DEV {
        return None;
    }
    let first = dev.checked_mul(STRIDE)?.checked_add(1)?;
    Id::new(first.checked_add(offset)?).ok()
}

/// One of the controller's own inputs, `dev 0`'s components and signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LocalInput {
    /// `AIN_HOUSE`: the bank voltage.
    House,
    /// `AIN_START`: the start battery.
    Start,
    /// `AIN_TANK`: the tank sender's 4–20 mA.
    Tank,
}

impl LocalInput {
    /// Every input, in the order its signals are numbered.
    pub const ALL: [Self; 3] = [Self::House, Self::Start, Self::Tank];

    const fn index(self) -> usize {
        match self {
            Self::House => 0,
            Self::Start => 1,
            Self::Tank => 2,
        }
    }

    /// The signal it publishes as, and the component it describes, which
    /// share the number.
    #[must_use]
    pub fn signal(self) -> Option<Id> {
        derived(0, self.index())
    }

    /// What it publishes.
    #[must_use]
    pub const fn kind(self) -> Kind {
        match self {
            Self::House | Self::Start => crate::adc::DIVIDER_KIND,
            Self::Tank => crate::adc::LOOP_KIND,
        }
    }

    /// The part of the site it measures.
    #[must_use]
    pub const fn role(self) -> ComponentRole {
        match self {
            Self::House => ComponentRole::BATTERY_BANK,
            Self::Start => ComponentRole::START_BATTERY,
            Self::Tank => ComponentRole::TANK,
        }
    }
}

/// How often the ADC task reads every input.
pub const LOCAL_PERIOD: Millis = Millis::from_millis(1_000);

/// How long a reading the controller is not told again stays current:
/// three of its device's periods, and never under this.
const LEAST_AGE: Millis = Millis::from_millis(10_000);

/// How long a probe's temperature may read the same before it is presumed
/// to be a probe that missed the conversion and keeps handing back its last
/// one (`ds18b20`'s module comment). A judgement, not a measurement: a
/// still room holds a tenth of a degree for an hour; six is past that.
pub const PROBE_UNCHANGED: Millis = Millis::from_millis(6 * 60 * 60 * 1_000);

/// How long an RS-485 exchange waits for its echo and for its reply to
/// begin. Neither the EPEVER nor the PZEM documents the drivers cite state a
/// response time, so this is an assumption to measure on the bench per
/// device, not a vendor's figure.
pub const RESPONSE: Timing = Timing {
    response: Millis::from_millis(500),
};

/// What the firmware drives, per dialect: what km43 checks a section
/// against. Every dialect with a driver is here, including the two whose
/// products are not allocated yet, so their options are still checked;
/// [`Plan::new`] refuses those.
pub const DIALECTS: [DialectRule<'static>; 6] = [
    DialectRule {
        dialect: Dialect::PZEM_DC,
        transports: &[Transport::Rs485],
        options: &[DeviceOption::PollPeriod],
        min_poll_ms: MODBUS_LEAST_POLL,
    },
    DialectRule {
        dialect: Dialect::EPEVER_B,
        transports: &[Transport::Rs485],
        options: &[DeviceOption::CurrentDirection, DeviceOption::PollPeriod],
        min_poll_ms: MODBUS_LEAST_POLL,
    },
    DialectRule {
        dialect: Dialect::PZEM_AC,
        transports: &[Transport::Rs485],
        options: &[DeviceOption::PollPeriod],
        min_poll_ms: MODBUS_LEAST_POLL,
    },
    DialectRule {
        dialect: Dialect::VE_DIRECT_TEXT,
        transports: &[Transport::VeDirect],
        options: &[DeviceOption::VeDirect3v3],
        min_poll_ms: 0,
    },
    DialectRule {
        dialect: Dialect::PYLONTECH_CAN,
        transports: &[Transport::Can],
        options: &[
            DeviceOption::PylontechVersion,
            DeviceOption::CurrentDirection,
        ],
        min_poll_ms: 0,
    },
    DialectRule {
        dialect: Dialect::DS18B20,
        transports: &[Transport::Onewire],
        options: &[DeviceOption::PollPeriod],
        min_poll_ms: PROBE_LEAST_POLL,
    },
];

/// The shortest period a Modbus device is polled at, in milliseconds.
const MODBUS_LEAST_POLL: u32 = 1_000;
/// A Modbus device's period when the section sets none.
const MODBUS_POLL: Millis = Millis::from_millis(5_000);
/// The shortest period the 1-Wire line converts at: the conversion's
/// 750 ms and a read of every probe.
const PROBE_LEAST_POLL: u32 = 2_000;
/// The 1-Wire line's period when the section sets none.
const PROBE_POLL: Millis = Millis::from_millis(10_000);
/// The bit rate a Pylontech-class BMS talks at, both documents' 500 kbit/s.
const PYLONTECH_RATE: NonZeroU32 = match NonZeroU32::new(500_000) {
    Some(rate) => rate,
    None => NonZeroU32::MIN,
};
/// The period a product that talks unprompted is heard at, once a second.
const HEARD: Millis = Millis::from_millis(1_000);

/// What `0x0003` is checked against: the board's buses, [`DIALECTS`], and
/// the caps `Hello` reports.
pub static RULES: SiteRules<'static> = SiteRules {
    buses: &BOARD_BUSES,
    dialects: &DIALECTS,
    // The controller's own row is one of the table's.
    max_devices: SITE_DEVICES - 1,
    max_topology_depth: MAX_TOPOLOGY_DEPTH,
};

/// The check `o89-core`'s configuration runs on every `0x0003` write.
pub const BUSES_CHECK: BusesCheck = BusesCheck {
    rules: &RULES,
    plan: check,
};

/// [`Plan::new`] as a section refusal.
pub fn check(section: &BusesAndDevicesRead<'_>) -> Result<(), ConfigError> {
    Plan::new(section).map(|_| ()).map_err(PlanError::refusal)
}

/// Why a section cannot be built into a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a section that cannot be built is a site that does not run"]
pub enum PlanError {
    /// km43 refused it.
    Section(ConfigError),
    /// More devices on the bus than its task holds.
    BusFull(u8),
    /// The dialect's driver reads no such product, or km43 has allocated
    /// none for the dialect yet.
    NotDriven {
        /// The device.
        dev: u16,
        /// Its dialect.
        dialect: u16,
        /// Its bus.
        bus: u8,
    },
    /// An address the driver cannot reach the device at.
    Address(u16),
    /// An option value the driver cannot honour, or one it needs and the
    /// device does not carry.
    Option {
        /// The device.
        dev: u16,
        /// The option.
        option: DeviceOption,
    },
    /// Devices on one serial bus whose dialects run it differently, and no
    /// bus entry setting how.
    Framing(u8),
    /// A `dev` past [`LAST_DEV`], whose ids would not fit.
    DevPastIds(u16),
    /// Two devices whose signal ids overlap.
    Overlap(Overlap),
    /// More signals than the store holds.
    Signals,
    /// More components than the inventory holds.
    Components,
}

impl PlanError {
    /// The refusal a `SetConfig` is answered with: outcome 3 `invalid` for
    /// all of them but what km43 itself answers otherwise.
    #[must_use]
    pub const fn refusal(self) -> ConfigError {
        let devices = SectionKey::BusesAndDevices(BusesAndDevicesKey::Devices);
        match self {
            Self::Section(why) => why,
            Self::NotDriven { dialect, bus, .. } => ConfigError::DialectNotCarried { dialect, bus },
            Self::Address(_) => {
                ConfigError::OutOfSchema(SectionKey::BusesAndDevices(BusesAndDevicesKey::Addr))
            }
            Self::Option { option, .. } => ConfigError::OutOfSchema(SectionKey::BusesAndDevices(
                BusesAndDevicesKey::Option(option),
            )),
            Self::Framing(bus) => ConfigError::NotOnTransport {
                bus,
                key: SectionKey::BusesAndDevices(BusesAndDevicesKey::Rate),
            },
            Self::DevPastIds(_) | Self::Overlap(_) => {
                ConfigError::OutOfSchema(SectionKey::BusesAndDevices(BusesAndDevicesKey::Dev))
            }
            Self::BusFull(_) | Self::Signals | Self::Components => ConfigError::TooMany(devices),
        }
    }
}

/// The ids one device's signals take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SignalRange {
    /// The device.
    pub dev: u16,
    /// Its first signal.
    pub first: u16,
    /// How many, at least one.
    pub count: u16,
}

/// Two devices that would write the same signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Overlap {
    /// One.
    pub first: u16,
    /// The other.
    pub second: u16,
}

/// Refuse two ranges that share an id: each signal has one writer, so a
/// value two devices alternate on never restarts its unchanged run and
/// hides a hung instrument behind the other one's readings.
pub fn disjoint(ranges: &[SignalRange]) -> Result<(), Overlap> {
    for (at, a) in ranges.iter().enumerate() {
        for b in ranges.iter().skip(at.saturating_add(1)) {
            let a_end = u32::from(a.first).saturating_add(u32::from(a.count));
            let b_end = u32::from(b.first).saturating_add(u32::from(b.count));
            if u32::from(a.first) < b_end && u32::from(b.first) < a_end {
                return Err(Overlap {
                    first: a.dev,
                    second: b.dev,
                });
            }
        }
    }
    Ok(())
}

/// One configured device, as its bus task polls it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Planned {
    /// Its id.
    pub dev: u16,
    /// Its bus.
    pub connector: Connector,
    /// The driver.
    pub device: Device,
    /// How often it is polled; for a product that talks unprompted, how
    /// often it is expected to.
    pub period: Millis,
    /// Its inventory row.
    pub row: SiteDevice,
}

/// How each bus runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Settings {
    /// Nothing configured on it, and no device to say.
    Idle,
    /// A serial line.
    Serial(Framing),
    /// CAN at this bit rate.
    Can(NonZeroU32),
}

/// The section, built: every device's driver and every bus's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    devices: [Option<Planned>; MAX_CONFIG_DEVICES],
    settings: [Settings; CONNECTORS],
    three_volt: [bool; 2],
}

/// The most rows the boot's topology batch can hold: every bus, the
/// controller and every configured device, every component and every
/// signal.
pub const ROWS: usize = CONNECTORS + 1 + MAX_CONFIG_DEVICES + SITE_COMPONENTS + SIGNAL_SLOTS;

impl Plan {
    /// Nothing configured: the controller's own inputs alone.
    pub const EMPTY: Self = Self {
        devices: [None; MAX_CONFIG_DEVICES],
        settings: [Settings::Idle; CONNECTORS],
        three_volt: [false; 2],
    };

    /// Build `section`, or say why it cannot be.
    pub fn new(section: &BusesAndDevicesRead<'_>) -> Result<Self, PlanError> {
        section.check(&RULES).map_err(PlanError::Section)?;
        let mut plan = Self::EMPTY;
        let mut per_bus = [0usize; CONNECTORS];
        let mut signals = LocalInput::ALL.len();
        let mut components = LocalInput::ALL.len();
        let mut ranges = [SignalRange {
            dev: 0,
            first: 0,
            count: 0,
        }; MAX_CONFIG_DEVICES + 1];
        if let Some(first) = ranges.first_mut() {
            *first = local_range();
        }
        for (slot, entry) in section.devices().enumerate() {
            let planned = planned(entry, &mut plan.three_volt)?;
            let bus = planned.connector.bus();
            let held = per_bus
                .get_mut(usize::from(bus))
                .ok_or(PlanError::BusFull(bus))?;
            *held = held.saturating_add(1);
            if *held > planned.connector.capacity() {
                return Err(PlanError::BusFull(bus));
            }
            let layout = planned.device.layout();
            signals = signals.saturating_add(layout.len());
            components = components.saturating_add(parts(&layout).count());
            let first = derived(planned.dev, 0).ok_or(PlanError::DevPastIds(planned.dev))?;
            if let Some(range) = ranges.get_mut(slot.saturating_add(1)) {
                *range = SignalRange {
                    dev: planned.dev,
                    first: first.get(),
                    count: u16::try_from(layout.len()).unwrap_or(u16::MAX),
                };
            }
            if let Some(free) = plan.devices.get_mut(slot) {
                *free = Some(planned);
            }
        }
        if signals > SIGNAL_SLOTS {
            return Err(PlanError::Signals);
        }
        if components > SITE_COMPONENTS {
            return Err(PlanError::Components);
        }
        let used = section.devices().count().saturating_add(1);
        disjoint(ranges.get(..used).unwrap_or(&[])).map_err(PlanError::Overlap)?;
        for connector in Connector::ALL {
            let entry = section.buses().find(|entry| entry.bus == connector.bus());
            let settings = plan.settle(connector, entry)?;
            if let Some(slot) = plan.settings.get_mut(usize::from(connector.bus())) {
                *slot = settings;
            }
        }
        Ok(plan)
    }

    /// The devices on `connector`, in the section's order.
    pub fn devices_on(&self, connector: Connector) -> impl Iterator<Item = &Planned> {
        self.devices
            .iter()
            .flatten()
            .filter(move |planned| planned.connector == connector)
    }

    /// Every configured device.
    pub fn devices(&self) -> impl Iterator<Item = &Planned> {
        self.devices.iter().flatten()
    }

    /// How `connector` runs.
    #[must_use]
    pub fn settings(&self, connector: Connector) -> Settings {
        self.settings
            .get(usize::from(connector.bus()))
            .copied()
            .unwrap_or(Settings::Idle)
    }

    /// Whether a VE.Direct port is configured for a 3.3 V product, which is
    /// what decides its pull-up on revision A (F-051).
    #[must_use]
    pub const fn three_volt(&self, port: Port) -> bool {
        let [one, two] = self.three_volt;
        match port {
            Port::One => one,
            Port::Two => two,
        }
    }

    /// The boot's topology: every bus, the controller, every device with
    /// parents before children, then every component and signal. Written
    /// into `out`; says how many rows.
    pub fn rows(&self, out: &mut [Descriptor]) -> Result<usize, PlanError> {
        let mut rows = Rows { out, len: 0 };
        for connector in Connector::ALL {
            let rate = match self.settings(connector) {
                Settings::Serial(framing) => Some(framing.rate.get()),
                Settings::Can(rate) => Some(rate.get()),
                Settings::Idle => None,
            };
            rows.push(Descriptor::Bus(connector.row(rate)))?;
        }
        rows.push(Descriptor::Device(CONTROLLER))?;
        // Parents first: each pass takes the devices whose parent is the
        // controller's table already, and a chain is at most this deep.
        let mut placed = [false; MAX_CONFIG_DEVICES];
        for _ in 0..MAX_TOPOLOGY_DEPTH {
            for (at, planned) in self.devices.iter().enumerate() {
                let Some(planned) = planned else { continue };
                if placed.get(at).copied().unwrap_or(true) {
                    continue;
                }
                let ready = planned.row.parent.is_none_or(|parent| {
                    self.devices
                        .iter()
                        .zip(placed)
                        .any(|(other, done)| done && other.is_some_and(|other| other.dev == parent))
                });
                if ready {
                    rows.push(Descriptor::Device(planned.row))?;
                    if let Some(done) = placed.get_mut(at) {
                        *done = true;
                    }
                }
            }
        }
        for input in LocalInput::ALL {
            let cmp = input.signal().ok_or(PlanError::DevPastIds(0))?;
            rows.push(Descriptor::Component(SiteComponent {
                cmp,
                dev: 0,
                parent: None,
                role: input.role(),
                index: None,
            }))?;
        }
        for planned in self.devices() {
            for (index, role) in parts(&planned.device.layout()).enumerate() {
                let cmp = derived(planned.dev, index).ok_or(PlanError::DevPastIds(planned.dev))?;
                rows.push(Descriptor::Component(SiteComponent {
                    cmp,
                    dev: planned.dev,
                    parent: None,
                    role,
                    index: None,
                }))?;
            }
        }
        for input in LocalInput::ALL {
            let sig = input.signal().ok_or(PlanError::DevPastIds(0))?;
            let limits = Limits::new(LEAST_AGE, None).ok_or(PlanError::Signals)?;
            rows.push(Descriptor::Signal(signal_row(
                sig,
                0,
                Some(sig),
                Described {
                    kind: input.kind(),
                    domain: km43::SignalDomain::Live,
                    part: Some(input.role()),
                },
                limits,
            )))?;
        }
        for planned in self.devices() {
            let layout = planned.device.layout();
            let limits = limits(planned)?;
            for (index, described) in layout.iter().enumerate() {
                let sig = planned
                    .device
                    .signal(index)
                    .ok_or(PlanError::DevPastIds(planned.dev))?;
                let cmp = match described.part {
                    Some(role) => {
                        let at = parts(&layout)
                            .position(|part| part == role)
                            .ok_or(PlanError::Components)?;
                        Some(derived(planned.dev, at).ok_or(PlanError::DevPastIds(planned.dev))?)
                    }
                    None => None,
                };
                rows.push(Descriptor::Signal(signal_row(
                    sig,
                    planned.dev,
                    cmp,
                    *described,
                    limits,
                )))?;
            }
        }
        Ok(rows.len)
    }

    /// The settings `connector` runs at: what its entry sets, and for each
    /// setting it leaves out, what its devices' dialects need, which must
    /// agree.
    fn settle(
        &self,
        connector: Connector,
        entry: Option<&BusEntry>,
    ) -> Result<Settings, PlanError> {
        let bus = connector.bus();
        match connector {
            Connector::Local | Connector::OneWire => Ok(Settings::Idle),
            Connector::Can => {
                let wanted = self.devices_on(connector).map(|_| PYLONTECH_RATE).next();
                Ok(entry
                    .and_then(|entry| entry.rate)
                    .or(wanted)
                    .map_or(Settings::Idle, Settings::Can))
            }
            Connector::Rs485(_) | Connector::VeDirect(_) => {
                let mut wanted: Option<Framing> = None;
                for planned in self.devices_on(connector) {
                    let Some(needs) = framing_of(&planned.device) else {
                        continue;
                    };
                    let merged = match wanted {
                        None => needs,
                        Some(held) => agree(held, needs, entry).ok_or(PlanError::Framing(bus))?,
                    };
                    wanted = Some(merged);
                }
                let Some(base) = wanted.or_else(|| entry.copied().and_then(partial)) else {
                    return Ok(Settings::Idle);
                };
                Ok(Settings::Serial(Framing {
                    rate: entry.and_then(|entry| entry.rate).unwrap_or(base.rate),
                    data_bits: entry
                        .and_then(|entry| entry.data_bits)
                        .unwrap_or(base.data_bits),
                    parity: entry.and_then(|entry| entry.parity).unwrap_or(base.parity),
                    stop_bits: entry
                        .and_then(|entry| entry.stop_bits)
                        .unwrap_or(base.stop_bits),
                }))
            }
        }
    }
}

/// The controller's own row: the board's local I/O, with the product and
/// dialect PROTOCOL.md gives the onboard inputs.
pub const CONTROLLER: SiteDevice = SiteDevice {
    dev: 0,
    bus: 0,
    addr: None,
    product: Product::ORIGIN_89_CONTROLLER,
    dialect: Dialect::NO_PROTOCOL,
    role: DeviceRole::CONTROLLER,
    parent: None,
};

/// The rows written so far.
struct Rows<'a> {
    out: &'a mut [Descriptor],
    len: usize,
}

impl Rows<'_> {
    fn push(&mut self, row: Descriptor) -> Result<(), PlanError> {
        let slot = self.out.get_mut(self.len).ok_or(PlanError::Signals)?;
        *slot = row;
        self.len = self.len.saturating_add(1);
        Ok(())
    }
}

fn local_range() -> SignalRange {
    SignalRange {
        dev: 0,
        first: LocalInput::House.signal().map_or(0, Id::get),
        count: 3,
    }
}

/// The distinct parts a layout describes, in the order they first appear,
/// which is their components' numbering.
fn parts(layout: &Layout) -> impl Iterator<Item = ComponentRole> + '_ {
    layout
        .iter()
        .enumerate()
        .filter_map(move |(at, described)| {
            let role = described.part?;
            let first = layout.iter().position(|other| other.part == Some(role))?;
            (first == at).then_some(role)
        })
}

/// A signal's row.
fn signal_row(
    sig: Id,
    dev: u16,
    cmp: Option<Id>,
    described: Described,
    limits: Limits,
) -> SiteSignal {
    let vtype = match described.domain {
        km43::SignalDomain::Lifetime
        | km43::SignalDomain::SinceReset
        | km43::SignalDomain::Today
        | km43::SignalDomain::Yesterday => Vtype::Counter,
        km43::SignalDomain::Live
        | km43::SignalDomain::LimitUpper
        | km43::SignalDomain::LimitLower
        | km43::SignalDomain::Max
        | km43::SignalDomain::Min => Vtype::Gauge,
    };
    // KM43's DC current is positive into its component, and every driver
    // publishes it so; no other kind here says a direction.
    let dir = match described.kind {
        Kind::DcCurrent => Some(Direction::PositiveIsIn),
        Kind::DcVoltage
        | Kind::DcPower
        | Kind::StateOfCharge
        | Kind::AcVoltage
        | Kind::AcCurrent
        | Kind::AcPower
        | Kind::AcFrequency
        | Kind::AcEnergy
        | Kind::Temperature
        | Kind::TankLevel => None,
    };
    SiteSignal {
        sig,
        dev,
        cmp,
        kind: described.kind.metric(),
        vtype,
        domain: described.domain,
        point: None,
        dir,
        esp: None,
        limits,
    }
}

/// How long a device's readings stay current, and for a probe how long one
/// may read the same.
fn limits(planned: &Planned) -> Result<Limits, PlanError> {
    let age = Millis::from_millis(
        planned
            .period
            .as_millis()
            .saturating_mul(3)
            .max(LEAST_AGE.as_millis()),
    );
    let unchanged = match planned.device {
        Device::Ds18b20(_) => Some(PROBE_UNCHANGED),
        Device::Modbus(_)
        | Device::Epever(_)
        | Device::PzemDc(_)
        | Device::PzemAc(_)
        | Device::VeDirect(_)
        | Device::Pylontech(_) => None,
    };
    Limits::new(age, unchanged).ok_or(PlanError::Signals)
}

/// What a device's dialect runs its line at.
fn framing_of(device: &Device) -> Option<Framing> {
    let (rate, parity, stop_bits) = match device {
        Device::Epever(_) => (115_200, Parity::None, StopBits::One),
        Device::PzemDc(_) => (9_600, Parity::None, StopBits::Two),
        Device::PzemAc(_) => (9_600, Parity::None, StopBits::One),
        Device::VeDirect(_) => (19_200, Parity::None, StopBits::One),
        Device::Modbus(_) | Device::Pylontech(_) | Device::Ds18b20(_) => return None,
    };
    Some(Framing {
        rate: NonZeroU32::new(rate)?,
        data_bits: DataBits::Eight,
        parity,
        stop_bits,
    })
}

/// Two dialects' framings, where each setting the bus entry leaves out
/// must agree; `None` when one does not.
fn agree(held: Framing, needs: Framing, entry: Option<&BusEntry>) -> Option<Framing> {
    let set = |pick: fn(&BusEntry) -> bool| entry.is_some_and(pick);
    let ok = (held.rate == needs.rate || set(|entry| entry.rate.is_some()))
        && (held.data_bits == needs.data_bits || set(|entry| entry.data_bits.is_some()))
        && (held.parity == needs.parity || set(|entry| entry.parity.is_some()))
        && (held.stop_bits == needs.stop_bits || set(|entry| entry.stop_bits.is_some()));
    ok.then_some(held)
}

/// A serial bus with no device on it runs at its entry's settings, where
/// it sets a rate: 8N1 for the rest.
fn partial(entry: BusEntry) -> Option<Framing> {
    Some(Framing {
        rate: entry.rate?,
        data_bits: DataBits::Eight,
        parity: Parity::None,
        stop_bits: StopBits::One,
    })
}

/// One entry, built, with the 3.3 V port settings noted.
fn planned(
    entry: &DeviceEntry<'_, DevId>,
    three_volt: &mut [bool; 2],
) -> Result<Planned, PlanError> {
    let dev = entry.dev.get();
    let connector = Connector::from_bus(entry.bus)
        .ok_or(PlanError::Section(ConfigError::UnknownBus(entry.bus)))?;
    let not_driven = PlanError::NotDriven {
        dev,
        dialect: entry.dialect.0,
        bus: entry.bus,
    };
    let first = derived(dev, 0).ok_or(PlanError::DevPastIds(dev))?;
    let poll = |default: Millis| {
        entry
            .options
            .poll_period_ms
            .map_or(default, |ms| Millis::from_millis(u64::from(ms)))
    };
    let (device, period) = match entry.dialect {
        Dialect::PZEM_DC | Dialect::PZEM_AC | Dialect::EPEVER_B => {
            (modbus(entry, first)?, poll(MODBUS_POLL))
        }
        Dialect::VE_DIRECT_TEXT => (vedirect(entry, connector, first, three_volt)?, HEARD),
        Dialect::PYLONTECH_CAN => (bms(entry, first)?, HEARD),
        Dialect::DS18B20 => (probe(entry, first)?, poll(PROBE_POLL)),
        _ => return Err(not_driven),
    };
    if device.bus() != connector_kind(connector) {
        return Err(not_driven);
    }
    let addr = match entry.addr {
        Some(addr) => Some(DeviceAddress::new(addr.as_bytes()).ok_or(PlanError::Address(dev))?),
        None => None,
    };
    Ok(Planned {
        dev,
        connector,
        device,
        period,
        row: SiteDevice {
            dev,
            bus: entry.bus,
            addr,
            product: entry.product,
            dialect: entry.dialect,
            role: entry.role,
            parent: entry.parent.map(DevId::get),
        },
    })
}

/// Why an entry's product is not one its dialect's driver reads.
fn not_driven(entry: &DeviceEntry<'_, DevId>) -> PlanError {
    PlanError::NotDriven {
        dev: entry.dev.get(),
        dialect: entry.dialect.0,
        bus: entry.bus,
    }
}

/// A Modbus dialect's driver, publishing from `first`.
fn modbus(entry: &DeviceEntry<'_, DevId>, first: Id) -> Result<Device, PlanError> {
    let dev = entry.dev.get();
    let address = modbus_address(entry.addr, dev)?;
    match entry.dialect {
        Dialect::PZEM_DC => {
            if entry.product != Product::PZEM_003 && entry.product != Product::PZEM_017 {
                return Err(not_driven(entry));
            }
            Ok(Device::PzemDc(pzem::dc::Meter::new(address, first)))
        }
        Dialect::PZEM_AC => {
            let model = if entry.product == Product::PZEM_014 {
                pzem::ac::Model::Pzem014
            } else if entry.product == Product::PZEM_016 {
                pzem::ac::Model::Pzem016
            } else {
                return Err(not_driven(entry));
            };
            pzem::ac::Meter::new(address, first, model)
                .map(Device::PzemAc)
                .ok_or(PlanError::DevPastIds(dev))
        }
        Dialect::EPEVER_B => {
            if entry.product != Product::EPEVER_TRACER_B {
                return Err(not_driven(entry));
            }
            let current = match entry.options.current_direction {
                None => BatteryCurrent::Unsupported,
                Some(CurrentDirection::PositiveIsIn) => BatteryCurrent::SignedPositiveCharging,
                // The driver reads the current as positive charging only;
                // the other sign would publish every reading inverted.
                Some(CurrentDirection::PositiveIsOut) => {
                    return Err(PlanError::Option {
                        dev,
                        option: DeviceOption::CurrentDirection,
                    });
                }
            };
            // No option says which document's scale this unit's state of
            // charge is at, so it publishes `unsupported`.
            Charger::new(address, first, StateOfCharge::Unsupported, current)
                .map(Device::Epever)
                .ok_or(PlanError::DevPastIds(dev))
        }
        _ => Err(not_driven(entry)),
    }
}

/// A VE.Direct text port's driver, noting a 3.3 V product's port.
fn vedirect(
    entry: &DeviceEntry<'_, DevId>,
    connector: Connector,
    first: Id,
    three_volt: &mut [bool; 2],
) -> Result<Device, PlanError> {
    let dev = entry.dev.get();
    // No product row exists for any VE.Direct product yet
    // (origin89hq/km43#196): none is driven until one does.
    if !VEDIRECT_PRODUCTS.contains(&entry.product) {
        return Err(not_driven(entry));
    }
    let next = |at: u16| Id::new(first.get().checked_add(at)?).ok();
    let channels =
        Channels::new(Some(first), next(1), next(2)).ok_or(PlanError::DevPastIds(dev))?;
    if let Connector::VeDirect(port) = connector
        && entry.options.ve_direct_3v3 == Some(true)
    {
        let [one, two] = three_volt;
        match port {
            Port::One => *one = true,
            Port::Two => *two = true,
        }
    }
    Ok(Device::VeDirect(channels))
}

/// A Pylontech-class BMS's driver.
fn bms(entry: &DeviceEntry<'_, DevId>, first: Id) -> Result<Device, PlanError> {
    let dev = entry.dev.get();
    // No product row exists for a Pylontech-class pack yet
    // (origin89hq/km43#196).
    if !PYLONTECH_PRODUCTS.contains(&entry.product) {
        return Err(not_driven(entry));
    }
    if entry.addr.map(Addr::as_bytes) != Some(&[0][..]) {
        return Err(PlanError::Address(dev));
    }
    let version = match entry.options.pylontech_version {
        Some(PylontechVersion::V12) => pylontech::Version::V12,
        Some(PylontechVersion::V13) => pylontech::Version::V13,
        None => {
            return Err(PlanError::Option {
                dev,
                option: DeviceOption::PylontechVersion,
            });
        }
    };
    let direction = match entry.options.current_direction {
        Some(CurrentDirection::PositiveIsIn) => pylontech::CurrentDirection::IntoPack,
        Some(CurrentDirection::PositiveIsOut) => pylontech::CurrentDirection::OutOfPack,
        None => pylontech::CurrentDirection::Unknown,
    };
    Pylontech::new(first, version, direction)
        .map(Device::Pylontech)
        .ok_or(PlanError::DevPastIds(dev))
}

/// A DS18B20's driver, at the ROM code its address carries.
fn probe(entry: &DeviceEntry<'_, DevId>, first: Id) -> Result<Device, PlanError> {
    let dev = entry.dev.get();
    if entry.product != Product::DS18B20 {
        return Err(not_driven(entry));
    }
    let rom = entry
        .addr
        .and_then(|addr| <[u8; 8]>::try_from(addr.as_bytes()).ok())
        .and_then(|bytes| Rom::new(bytes).ok())
        .ok_or(PlanError::Address(dev))?;
    Probe::new(rom, first)
        .map(Device::Ds18b20)
        .ok_or(PlanError::Address(dev))
}

/// The products a VE.Direct text port is configured as: none, until km43
/// allocates them (origin89hq/km43#196).
const VEDIRECT_PRODUCTS: [Product; 0] = [];
/// The products a Pylontech-class pack is configured as: none, until km43
/// allocates them (origin89hq/km43#196).
const PYLONTECH_PRODUCTS: [Product; 0] = [];

const fn connector_kind(connector: Connector) -> crate::BusKind {
    match connector {
        Connector::Local => crate::BusKind::Adc,
        Connector::Rs485(_) => crate::BusKind::Rs485,
        Connector::VeDirect(_) => crate::BusKind::VeDirect,
        Connector::Can => crate::BusKind::Can,
        Connector::OneWire => crate::BusKind::OneWire,
    }
}

/// A Modbus server's one-byte address, 1 to 247.
fn modbus_address(addr: Option<Addr<'_>>, dev: u16) -> Result<Address, PlanError> {
    match addr.map(Addr::as_bytes) {
        Some([byte]) => Address::new(*byte).ok_or(PlanError::Address(dev)),
        Some(_) | None => Err(PlanError::Address(dev)),
    }
}

/// The 1-Wire line's driver runs no faster than this many probes allow.
const _: () = assert!(o89_core::ONEWIRE_DEVICES <= crate::onewire::MAX_DEVICES);
const _: () = assert!(ds18b20::CONVERSION.as_millis() < PROBE_LEAST_POLL as u64);
const _: () = assert!(VEDIRECT_FIELDS.len() == 3);

#[cfg(test)]
mod tests {
    use super::*;
    use km43::{BusesAndDevicesWrite, DevAllocator, DeviceOptions, TopologyChangeReason};
    use o89_core::{Bus, Site};

    /// A ROM code of the DS18B20's family whose CRC holds, built by hand.
    fn rom(serial: u8) -> [u8; 8] {
        let mut bytes = [0x28, serial, 0, 0, 0, 0, 0, 0];
        bytes[7] = crate::onewire::crc8(&bytes[..7]);
        bytes
    }

    fn entry(
        bus: u8,
        addr: Option<&[u8]>,
        dialect: Dialect,
        product: Product,
    ) -> DeviceEntry<'_, Option<DevId>> {
        DeviceEntry {
            dev: None,
            bus,
            addr: addr.map(|addr| Addr::new(addr).unwrap()),
            product,
            dialect,
            role: DeviceRole::ENERGY_METER,
            parent: None,
            options: DeviceOptions::NONE,
        }
    }

    fn pzem_dc(addr: &[u8]) -> DeviceEntry<'_, Option<DevId>> {
        entry(2, Some(addr), Dialect::PZEM_DC, Product::PZEM_017)
    }

    fn epever(bus: u8, addr: &[u8]) -> DeviceEntry<'_, Option<DevId>> {
        entry(bus, Some(addr), Dialect::EPEVER_B, Product::EPEVER_TRACER_B)
    }

    fn probe(addr: &[u8]) -> DeviceEntry<'_, Option<DevId>> {
        entry(7, Some(addr), Dialect::DS18B20, Product::DS18B20)
    }

    /// What the controller would hold after accepting `devices` and
    /// `buses` as its first write: km43's own acceptance, which gives ids.
    fn accepted<'a>(
        devices: &[DeviceEntry<'a, Option<DevId>>],
        buses: &[BusEntry],
    ) -> Result<BusesAndDevicesRead<'a>, ConfigError> {
        let mut write = BusesAndDevicesWrite::EMPTY;
        for device in devices {
            write.push_device(*device)?;
        }
        for bus in buses {
            write.push_bus(*bus)?;
        }
        write
            .accept(&RULES, &BusesAndDevicesRead::EMPTY, DevAllocator::FIRST)
            .map(|accepted| accepted.section)
    }

    fn plan(devices: &[DeviceEntry<'_, Option<DevId>>]) -> Result<Plan, PlanError> {
        let section = accepted(devices, &[]).map_err(PlanError::Section)?;
        Plan::new(&section)
    }

    fn rows(plan: &Plan) -> ([Descriptor; ROWS], usize) {
        let mut out = [Descriptor::Bus(Connector::Local.row(None)); ROWS];
        let len = plan.rows(&mut out).unwrap();
        (out, len)
    }

    /// The site a boot builds from `plan`.
    fn site(plan: &Plan) -> Site {
        let (out, len) = rows(plan);
        let mut site = Site::new();
        site.apply(TopologyChangeReason::Boot, &out[..len]).unwrap();
        site
    }

    #[test]
    fn a_valid_site_builds_every_device_on_its_bus_at_its_dialect_s_line_settings() {
        let one_wire = rom(1);
        let plan = plan(&[
            epever(1, &[1]),
            pzem_dc(&[1]),
            pzem_dc(&[2]),
            probe(&one_wire),
        ])
        .unwrap();
        assert_eq!(plan.devices().count(), 4);
        assert_eq!(plan.devices_on(Connector::Rs485(Bus::Two)).count(), 2);
        let rate = |rate| NonZeroU32::new(rate).unwrap();
        assert_eq!(
            plan.settings(Connector::Rs485(Bus::One)),
            Settings::Serial(Framing {
                rate: rate(115_200),
                data_bits: DataBits::Eight,
                parity: Parity::None,
                stop_bits: StopBits::One,
            })
        );
        assert_eq!(
            plan.settings(Connector::Rs485(Bus::Two)),
            Settings::Serial(Framing {
                rate: rate(9_600),
                data_bits: DataBits::Eight,
                parity: Parity::None,
                stop_bits: StopBits::Two,
            })
        );
        assert_eq!(plan.settings(Connector::Rs485(Bus::Three)), Settings::Idle);
        assert_eq!(plan.settings(Connector::OneWire), Settings::Idle);
        // Ids follow the dev: the charger is dev 1, its first signal 17.
        let charger = plan.devices().next().unwrap();
        assert_eq!(
            (charger.dev, charger.device.signal(0)),
            (1, Id::new(17).ok())
        );
        let site = site(&plan);
        // 3 local inputs, 9 + 1 + 1 + 1 device signals.
        assert_eq!(site.signals().len(), 15);
        assert!(site.topology().has_device(0));
        assert!(site.topology().has_device(4));
    }

    #[test]
    fn an_empty_site_is_the_controller_s_own_inputs_alone() {
        let plan = plan(&[]).unwrap();
        assert_eq!(plan, Plan::EMPTY);
        let (_, len) = rows(&plan);
        // Eight buses, the controller, three components, three signals.
        assert_eq!(len, CONNECTORS + 1 + 3 + 3);
        let site = site(&plan);
        assert_eq!(site.signals().len(), 3);
        for input in LocalInput::ALL {
            assert!(site.topology().has_signal(input.signal().unwrap()));
        }
    }

    #[test]
    fn a_bus_with_more_devices_than_its_capacity_is_refused() {
        let addrs: [[u8; 1]; 9] = core::array::from_fn(|at| [u8::try_from(at).unwrap() + 1]);
        let devices: [DeviceEntry<'_, Option<DevId>>; 9] =
            core::array::from_fn(|at| pzem_dc(&addrs[at]));
        assert_eq!(plan(&devices[..8]).map(|_| ()), Ok(()));
        assert_eq!(plan(&devices).map(|_| ()), Err(PlanError::BusFull(2)));
        let roms: [[u8; 8]; 9] = core::array::from_fn(|at| rom(u8::try_from(at).unwrap()));
        let probes: [DeviceEntry<'_, Option<DevId>>; 9] =
            core::array::from_fn(|at| probe(&roms[at]));
        assert_eq!(plan(&probes).map(|_| ()), Err(PlanError::BusFull(7)));
        assert_eq!(
            PlanError::BusFull(7).refusal().answer(),
            km43::SectionRefusal::Outcome(km43::SetConfig::Invalid)
        );
    }

    #[test]
    fn p_265_a_device_kind_its_bus_cannot_carry_is_refused() {
        // A meter on the 1-Wire line, a probe on an RS-485 channel.
        let mut meter = pzem_dc(&[1]);
        meter.bus = 7;
        assert_eq!(
            plan(&[meter]).map(|_| ()),
            Err(PlanError::Section(ConfigError::DialectNotCarried {
                dialect: Dialect::PZEM_DC.0,
                bus: 7
            }))
        );
        let one_wire = rom(1);
        let mut misplaced = probe(&one_wire);
        misplaced.bus = 2;
        assert_eq!(
            plan(&[misplaced]).map(|_| ()),
            Err(PlanError::Section(ConfigError::DialectNotCarried {
                dialect: Dialect::DS18B20.0,
                bus: 2
            }))
        );
    }

    #[test]
    fn p_265_vedirect_and_pylontech_are_refused_until_their_products_exist() {
        let vedirect = entry(4, None, Dialect::VE_DIRECT_TEXT, Product(0x0100));
        assert_eq!(
            plan(&[vedirect]).map(|_| ()),
            Err(PlanError::NotDriven {
                dev: 1,
                dialect: Dialect::VE_DIRECT_TEXT.0,
                bus: 4
            })
        );
        let mut bms = entry(6, Some(&[0]), Dialect::PYLONTECH_CAN, Product(0x0101));
        bms.options.pylontech_version = Some(PylontechVersion::V13);
        let refused = plan(&[bms]).map(|_| ());
        assert_eq!(
            refused,
            Err(PlanError::NotDriven {
                dev: 1,
                dialect: Dialect::PYLONTECH_CAN.0,
                bus: 6
            })
        );
        assert_eq!(
            refused.unwrap_err().refusal(),
            ConfigError::DialectNotCarried {
                dialect: Dialect::PYLONTECH_CAN.0,
                bus: 6
            }
        );
    }

    #[test]
    fn a_product_its_dialect_does_not_read_and_an_unreachable_address_are_refused() {
        let wrong = entry(2, Some(&[1]), Dialect::PZEM_DC, Product::PZEM_016);
        assert!(matches!(
            plan(&[wrong]),
            Err(PlanError::NotDriven { dev: 1, .. })
        ));
        assert_eq!(
            plan(&[pzem_dc(&[0])]).map(|_| ()),
            Err(PlanError::Address(1))
        );
        assert_eq!(
            plan(&[pzem_dc(&[248])]).map(|_| ()),
            Err(PlanError::Address(1))
        );
        assert_eq!(
            plan(&[pzem_dc(&[1, 2])]).map(|_| ()),
            Err(PlanError::Address(1))
        );
        assert_eq!(plan(&[pzem_dc(&[247])]).map(|_| ()), Ok(()));
        let mut broken = rom(1);
        broken[7] ^= 1;
        assert_eq!(
            plan(&[probe(&broken)]).map(|_| ()),
            Err(PlanError::Address(1))
        );
        let mut other_family = [0x10, 1, 0, 0, 0, 0, 0, 0];
        other_family[7] = crate::onewire::crc8(&other_family[..7]);
        assert_eq!(
            plan(&[probe(&other_family)]).map(|_| ()),
            Err(PlanError::Address(1))
        );
    }

    #[test]
    fn an_epever_current_counted_the_other_way_is_refused_rather_than_inverted() {
        let mut charger = epever(1, &[1]);
        charger.options.current_direction = Some(CurrentDirection::PositiveIsOut);
        assert_eq!(
            plan(&[charger]).map(|_| ()),
            Err(PlanError::Option {
                dev: 1,
                option: DeviceOption::CurrentDirection
            })
        );
        charger.options.current_direction = Some(CurrentDirection::PositiveIsIn);
        assert_eq!(plan(&[charger]).map(|_| ()), Ok(()));
    }

    #[test]
    fn p_261_dialects_that_run_a_bus_differently_need_its_entry_to_settle_it() {
        let mixed = [epever(2, &[1]), pzem_dc(&[2])];
        assert_eq!(plan(&mixed).map(|_| ()), Err(PlanError::Framing(2)));
        let settled = BusEntry {
            bus: 2,
            rate: NonZeroU32::new(9_600),
            data_bits: None,
            parity: None,
            stop_bits: Some(StopBits::Two),
        };
        let section = accepted(&mixed, &[settled]).unwrap();
        let built = Plan::new(&section).unwrap();
        assert_eq!(
            built.settings(Connector::Rs485(Bus::Two)),
            Settings::Serial(Framing {
                rate: NonZeroU32::new(9_600).unwrap(),
                data_bits: DataBits::Eight,
                parity: Parity::None,
                stop_bits: StopBits::Two,
            })
        );
        // A bus entry alone runs the bus at it.
        let alone = BusEntry {
            bus: 3,
            rate: NonZeroU32::new(19_200),
            data_bits: None,
            parity: Some(Parity::Even),
            stop_bits: None,
        };
        let section = accepted(&[], &[alone]).unwrap();
        assert!(matches!(
            Plan::new(&section)
                .unwrap()
                .settings(Connector::Rs485(Bus::Three)),
            Settings::Serial(Framing {
                parity: Parity::Even,
                ..
            })
        ));
    }

    #[test]
    fn a_site_whose_signals_do_not_fit_the_store_is_refused() {
        // Seven chargers publish 63 signals, beside the three inputs.
        let addrs: [[u8; 1]; 7] = core::array::from_fn(|at| [u8::try_from(at).unwrap() + 1]);
        let chargers: [DeviceEntry<'_, Option<DevId>>; 7] =
            core::array::from_fn(|at| epever(if at < 4 { 1 } else { 3 }, &addrs[at]));
        assert_eq!(plan(&chargers).map(|_| ()), Err(PlanError::Signals));
        assert_eq!(plan(&chargers[..6]).map(|_| ()), Ok(()));
    }

    fn range(dev: u16, first: u16, count: u16) -> SignalRange {
        SignalRange { dev, first, count }
    }

    #[test]
    fn two_devices_whose_signals_overlap_at_the_first_id_are_refused() {
        assert_eq!(
            disjoint(&[range(1, 10, 5), range(2, 10, 3)]),
            Err(Overlap {
                first: 1,
                second: 2
            })
        );
        // And where one's last meets the other's first.
        assert_eq!(
            disjoint(&[range(1, 20, 3), range(2, 10, 11)]),
            Err(Overlap {
                first: 1,
                second: 2
            })
        );
    }

    #[test]
    fn two_devices_whose_signals_overlap_at_the_last_id_are_refused() {
        assert_eq!(
            disjoint(&[range(1, 10, 5), range(2, 14, 3)]),
            Err(Overlap {
                first: 1,
                second: 2
            })
        );
    }

    #[test]
    fn a_device_whose_signals_lie_inside_another_s_is_refused() {
        assert_eq!(
            disjoint(&[range(3, 10, 9), range(4, 12, 2)]),
            Err(Overlap {
                first: 3,
                second: 4
            })
        );
        assert_eq!(
            disjoint(&[range(4, 12, 2), range(3, 10, 9)]),
            Err(Overlap {
                first: 4,
                second: 3
            })
        );
        // A cell given twice is the narrowest containment: one id.
        assert_eq!(
            disjoint(&[range(5, 30, 1), range(6, 30, 1)]),
            Err(Overlap {
                first: 5,
                second: 6
            })
        );
    }

    #[test]
    fn two_devices_whose_signals_are_adjacent_are_accepted() {
        assert_eq!(disjoint(&[range(1, 10, 5), range(2, 15, 3)]), Ok(()));
        assert_eq!(disjoint(&[range(2, 15, 3), range(1, 10, 5)]), Ok(()));
        assert_eq!(disjoint(&[]), Ok(()));
        assert_eq!(disjoint(&[range(1, u16::MAX, 1)]), Ok(()));
    }

    #[test]
    fn p_262_ids_follow_the_dev_and_stop_where_they_no_longer_fit() {
        assert_eq!(derived(0, 0), Id::new(1).ok());
        assert_eq!(derived(1, 0), Id::new(17).ok());
        assert_eq!(derived(1, 14), Id::new(31).ok());
        assert_eq!(derived(1, 15), None);
        assert!(derived(LAST_DEV, 14).is_some());
        assert_eq!(derived(LAST_DEV + 1, 0), None);
        assert_eq!(derived(u16::MAX, 0), None);
        // The blocks of two neighbours never meet.
        assert!(derived(1, 14).unwrap().get() < derived(2, 0).unwrap().get());
    }

    #[test]
    fn the_check_configuration_runs_is_the_plan_s_refusal() {
        let section = accepted(&[pzem_dc(&[0])], &[]).unwrap();
        assert_eq!(
            check(&section),
            Err(ConfigError::OutOfSchema(SectionKey::BusesAndDevices(
                BusesAndDevicesKey::Addr
            )))
        );
        let section = accepted(&[pzem_dc(&[1])], &[]).unwrap();
        assert_eq!((BUSES_CHECK.plan)(&section), Ok(()));
    }
}
