//! The site's descriptors: the cold plane a client reads once and pages.
//!
//! Four of KM43's five row kinds are held here: the buses, the devices on
//! them, the components inside a device, and the signals they publish.
//! Parameters have no capacity on this controller yet, so their table
//! answers empty and `Hello` reports a cap of zero (P-005). Every signal is
//! a scalar, because the store holds one value per signal.
//!
//! **The table changes only as a whole.** [`Topology::apply`] takes a batch
//! of rows, checks every one of them against the table as it would stand,
//! and either takes them all under a new revision or refuses the batch and
//! leaves the table as it was. The revision moves on every applied batch and
//! the digest is computed again from the rows as they then stand, so a
//! client never meets a matching `rev` beside a differing digest (P-149).
//! Rows are added and never removed yet; a configuration that retires a
//! device is a later change.
//!
//! **A page is rebuilt on every request** (P-146): the controller keeps no
//! walk. Rows go out in id order, a page ends at its row cap or its byte cap,
//! and the digest rides on the last page of a kind (P-148, P-208).
//!
//! cites: P-005, P-145, P-146, P-147, P-148, P-149, P-187, P-198, P-200,
//! P-202, P-205, P-207, P-213

use km43::{
    ComponentRole, DeviceRole, Dialect, Direction, EnumSpace, Id, InventoryBody, InventoryError,
    InventoryOutcome, MAX_ADDR, MAX_TOPOLOGY_DEPTH, MeasurementPoint, MetricKind, Page, Product,
    ReadInventory, Row, RowKind, Sel, Shape, SignalDomain, TopoDigest, TopologyChangeReason,
    TopologyChanged, Transport, Value, Vtype,
};

use crate::signals::{Limits, SIGNAL_SLOTS};

/// Buses the table holds: the three RS-485 channels, two VE.Direct ports,
/// CAN, 1-Wire and the local inputs, which is KM43's `MAX_BUSES`. A ninth is
/// refused.
pub const SITE_BUSES: usize = km43::MAX_BUSES;

/// Devices the table holds, KM43's `MAX_DEVICES`. One past it is refused.
pub const SITE_DEVICES: usize = km43::MAX_DEVICES;

/// Component rows: a charger's PV, battery and load sides, a pack's halves.
/// Fewer than KM43's `MAX_COMPONENTS`, and reported as what this table
/// holds, so the site table stays small on a 144 KB part.
pub const SITE_COMPONENTS: usize = 48;

/// Signal rows: one per slot of the store, so a row the table holds always
/// has a reading and a reading always has a row.
pub const SITE_SIGNALS: usize = SIGNAL_SLOTS;

/// What `Hello` reports of this table (P-005): the caps it enforces, the
/// revision and the digest of the rows as they stand.
#[must_use]
pub fn reported(rev: u32, digest: [u8; 8]) -> km43::Topology {
    km43::Topology {
        rev,
        digest,
        buses: km43::Topology::THIS_CONTROLLER.buses,
        devices: km43::Topology::THIS_CONTROLLER.devices,
        components: COMPONENTS_REPORTED,
        signals: SIGNALS_REPORTED,
        series_elements: 0,
        params: 0,
        concerns: km43::Topology::THIS_CONTROLLER.concerns,
        selectors: km43::Topology::THIS_CONTROLLER.selectors,
        history_signals: 0,
        topology_depth: km43::Topology::THIS_CONTROLLER.topology_depth,
    }
}

/// The signal cap as `Hello` key 23 carries it.
const SIGNALS_REPORTED: u16 = {
    assert!(SITE_SIGNALS <= u16::MAX as usize);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above holds the slot count inside a u16"
    )]
    let reported = SITE_SIGNALS as u16;
    reported
};

/// The component cap as `Hello` key 22 carries it.
const COMPONENTS_REPORTED: u16 = {
    assert!(SITE_COMPONENTS <= km43::MAX_COMPONENTS);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above holds it under KM43's cap of 160"
    )]
    let reported = SITE_COMPONENTS as u16;
    reported
};

const _: () = {
    assert!(km43::Topology::THIS_CONTROLLER.buses as usize == SITE_BUSES);
    assert!(km43::Topology::THIS_CONTROLLER.devices as usize == SITE_DEVICES);
};

/// A bus address as the bus defines one, at most `MAX_ADDR` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceAddress {
    bytes: [u8; MAX_ADDR],
    len: u8,
}

impl DeviceAddress {
    /// `None` for an empty address or one longer than `MAX_ADDR`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let len = u8::try_from(bytes.len()).ok()?;
        let mut held = [0u8; MAX_ADDR];
        held.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self { bytes: held, len })
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// A `BusRow` (KM43 `Inventory`, what 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteBus {
    /// Key 1; 0 is the controller's own local I/O.
    pub bus: u8,
    /// Key 2.
    pub transport: Transport,
    /// Key 4, the baud or bitrate, when the bus has one.
    pub rate: Option<u32>,
}

/// A `DeviceRow` as configuration declares it; the table stamps `since`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteDevice {
    /// Key 1; 0 is the controller itself.
    pub dev: u16,
    /// Key 2, a bus the table holds.
    pub bus: u8,
    /// Key 3, required on an addressed transport and unique on its bus
    /// (P-202).
    pub addr: Option<DeviceAddress>,
    /// Key 4.
    pub product: Product,
    /// Key 5.
    pub dialect: Dialect,
    /// Key 6.
    pub role: DeviceRole,
    /// Key 7, the device this is a sub-device of: one the table already
    /// holds, so no chain can close on itself (P-187).
    pub parent: Option<u16>,
}

/// A `ComponentRow`: one part of a device, the table stamps `since`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteComponent {
    /// Key 1, never 0: 0 is the device as a whole (P-200).
    pub cmp: Id,
    /// Key 2, a device the table holds.
    pub dev: u16,
    /// Key 3, the owning component: one of the same device the table
    /// already holds. `None` is the device itself.
    pub parent: Option<Id>,
    /// Key 4.
    pub role: ComponentRole,
    /// Key 5, the 1-based instance within its role, when there are several.
    pub index: Option<u16>,
}

/// A `SignalRow` for a scalar, as a driver declares it.
///
/// No vendor-range `kind` yet: its unit, scale and namespace would have to
/// ride on the row (P-204), and no driver on this controller declares one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteSignal {
    /// Key 1.
    pub sig: Id,
    /// Key 2, a device the table holds.
    pub dev: u16,
    /// Key 3: a component of that device, or `None` for the device as a
    /// whole, which goes out as 0 (P-200).
    pub cmp: Option<Id>,
    /// Key 4.
    pub kind: MetricKind,
    /// Key 6.
    pub vtype: Vtype,
    /// Key 7.
    pub domain: SignalDomain,
    /// Key 8.
    pub point: Option<MeasurementPoint>,
    /// Key 9.
    pub dir: Option<Direction>,
    /// Key 13, required exactly when `vtype` is an enum or flags.
    pub esp: Option<EnumSpace>,
    /// How long its reading stays current in the store; not on the wire.
    pub limits: Limits,
}

/// One row of a batch handed to [`Topology::apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Descriptor {
    /// A bus.
    Bus(SiteBus),
    /// A device on a bus.
    Device(SiteDevice),
    /// A component of a device.
    Component(SiteComponent),
    /// A signal on a device.
    Signal(SiteSignal),
}

/// Why a batch was refused. Nothing of it was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused batch is a topology that did not change"]
pub enum TopologyError {
    /// The table for this kind is full; nothing was evicted.
    Full(RowKind),
    /// The id is taken already.
    Duplicate(RowKind, u16),
    /// A device on a bus the table does not hold.
    NoSuchBus(u8),
    /// A device under a parent, or a signal on a device, the table does not
    /// hold.
    NoSuchDevice(u16),
    /// A component under a parent, or a signal at a component, that the
    /// table does not hold on the same device.
    NoSuchComponent(u16),
    /// A parent chain deeper than `MAX_TOPOLOGY_DEPTH` (P-187).
    TooDeep(u16),
    /// A device on an addressed transport with no address, or one whose
    /// address another device on the bus already holds (P-202).
    Address(u16),
    /// A signal whose identity tuple another signal already has (P-207).
    Collides(Id),
    /// A vendor-range metric kind, which this table cannot describe yet.
    VendorKind(Id),
    /// KM43 refused the row the declaration makes.
    Row(InventoryError),
    /// The revision is at the top of its range.
    RevisionExhausted,
}

/// A component row with the revision it appeared at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeldComponent {
    component: SiteComponent,
    since: u32,
}

/// A device row with the revision it appeared at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    device: SiteDevice,
    since: u32,
}

/// The descriptor tables, their revision and their digest.
#[derive(Debug, Clone)]
pub struct Topology {
    rev: u32,
    digest: [u8; 8],
    buses: [Option<SiteBus>; SITE_BUSES],
    devices: [Option<Held>; SITE_DEVICES],
    components: [Option<HeldComponent>; SITE_COMPONENTS],
    signals: [Option<SiteSignal>; SITE_SIGNALS],
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

impl Topology {
    /// No rows, at revision 0: the revision a client sends when it holds
    /// nothing, so a first request is never mistaken for a current one. The
    /// boot's [`Topology::apply`] moves it to 1.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rev: 0,
            digest: [0; 8],
            buses: [None; SITE_BUSES],
            devices: [None; SITE_DEVICES],
            components: [None; SITE_COMPONENTS],
            signals: [None; SITE_SIGNALS],
        }
    }

    /// The revision the rows stand at.
    #[must_use]
    pub const fn rev(&self) -> u32 {
        self.rev
    }

    /// P-148's digest of the rows as they stand at [`Topology::rev`].
    #[must_use]
    pub const fn digest(&self) -> [u8; 8] {
        self.digest
    }

    /// Take `batch` under a new revision, or refuse all of it.
    ///
    /// Every row is checked against the table as it would stand with the
    /// rows before it in the batch: a device's bus and parent, a signal's
    /// device, each id unique, P-202's address and P-207's identity. The
    /// answer is the `0x0901` the move owes, counting the rows added; the
    /// caller announces it (P-213).
    pub fn apply(
        &mut self,
        reason: TopologyChangeReason,
        batch: &[Descriptor],
    ) -> Result<TopologyChanged, TopologyError> {
        let rev = self
            .rev
            .checked_add(1)
            .ok_or(TopologyError::RevisionExhausted)?;
        let mut draft = self.clone();
        let mut added = 0u16;
        for declared in batch {
            match *declared {
                Descriptor::Bus(bus) => draft.add_bus(bus)?,
                Descriptor::Device(device) => draft.add_device(device, rev)?,
                Descriptor::Component(component) => draft.add_component(component, rev)?,
                Descriptor::Signal(signal) => draft.add_signal(signal)?,
            }
            added = added.saturating_add(1);
        }
        draft.rev = rev;
        draft.digest = draft.digested().map_err(TopologyError::Row)?;
        *self = draft;
        let added = match reason {
            // A boot carries what the tables hold, not the delta (P-213).
            TopologyChangeReason::Boot => self.rows(),
            TopologyChangeReason::ConfigWrite
            | TopologyChangeReason::SubDeviceAdopted
            | TopologyChangeReason::SubDeviceRemoved
            | TopologyChangeReason::DeviceReplaced => added,
        };
        Ok(TopologyChanged {
            rev,
            reason,
            added,
            removed: 0,
        })
    }

    /// The signals in ascending order.
    pub fn signals(&self) -> impl Iterator<Item = &SiteSignal> + '_ {
        self.signals.iter().flatten()
    }

    /// Whether the table holds `sig`.
    #[must_use]
    pub fn has_signal(&self, sig: Id) -> bool {
        self.signal(sig).is_some()
    }

    /// Whether the table holds device `dev`.
    #[must_use]
    pub fn has_device(&self, dev: u16) -> bool {
        self.device(dev).is_some()
    }

    /// Whether `sel` names something at this revision (P-199's outcome 3
    /// when it does not).
    #[must_use]
    pub fn knows(&self, sel: Sel) -> bool {
        match sel {
            Sel::Dev(dev) => self.has_device(dev.get()),
            Sel::Cmp(cmp) => self.component(cmp).is_some(),
            Sel::Sig(sig) => self.has_signal(sig),
        }
    }

    /// Whether `sel` selects `signal`: the signal itself, a component whose
    /// chain of parents reaches the one named, or a device whose chain
    /// does (P-198).
    #[must_use]
    pub fn selects(&self, sel: Sel, signal: &SiteSignal) -> bool {
        match sel {
            Sel::Sig(sig) => sig == signal.sig,
            Sel::Cmp(cmp) => {
                let mut at = signal.cmp;
                // Each hop is a component the table held before its child.
                for _ in 0..=MAX_TOPOLOGY_DEPTH {
                    let Some(here) = at else {
                        return false;
                    };
                    if here == cmp {
                        return true;
                    }
                    at = self.component(here).and_then(|held| held.component.parent);
                }
                false
            }
            Sel::Dev(dev) => {
                let mut at = Some(signal.dev);
                // Each hop is a device the table held before its child, so
                // the chain ends within the depth P-187 caps it at.
                for _ in 0..=MAX_TOPOLOGY_DEPTH {
                    let Some(here) = at else {
                        return false;
                    };
                    if here == dev.get() {
                        return true;
                    }
                    at = self.device(here).and_then(|held| held.device.parent);
                }
                false
            }
        }
    }

    /// The `Inventory 0x8D` body for `request`, written into `dst`, in
    /// P-199's order: a revision neither 0 nor current is superseded, a
    /// `what` outside 1..5 an unknown kind, and a `from` past the last row
    /// out of range. An empty kind read from the beginning is answered, with
    /// no rows.
    pub fn answer(&self, request: &ReadInventory, dst: &mut [u8]) -> Result<usize, InventoryError> {
        let kind = RowKind::from_number(request.what);
        let total = kind.map_or(0, |kind| self.count(kind));
        let refused = |outcome| InventoryBody {
            rev: self.rev,
            what: request.what,
            outcome,
            total,
            page: None,
            digest: None,
        };
        if request.rev != 0 && request.rev != self.rev {
            return refused(InventoryOutcome::Superseded).encode(dst);
        }
        let Some(kind) = kind else {
            return refused(InventoryOutcome::UnknownKind).encode(dst);
        };
        if request.from != 0 && self.last(kind).is_none_or(|last| request.from > last) {
            return refused(InventoryOutcome::OutOfRange).encode(dst);
        }
        let mut page = Page::new(kind);
        self.fill(&mut page, request.from)?;
        let digest = (page.next() == 0 && request.dev.is_none()).then_some(self.digest);
        InventoryBody {
            rev: self.rev,
            what: request.what,
            outcome: InventoryOutcome::Ok,
            total,
            page: Some(&page),
            digest,
        }
        .encode(dst)
    }

    /// Rows of every kind.
    fn rows(&self) -> u16 {
        [
            RowKind::Bus,
            RowKind::Device,
            RowKind::Component,
            RowKind::Signal,
        ]
        .into_iter()
        .fold(0u16, |sum, kind| sum.saturating_add(self.count(kind)))
    }

    fn count(&self, kind: RowKind) -> u16 {
        let count = match kind {
            RowKind::Bus => self.buses.iter().flatten().count(),
            RowKind::Device => self.devices.iter().flatten().count(),
            RowKind::Component => self.components.iter().flatten().count(),
            RowKind::Signal => self.signals.iter().flatten().count(),
            RowKind::Param => 0,
        };
        u16::try_from(count).unwrap_or(u16::MAX)
    }

    /// The largest id of `kind`, if the table holds any.
    fn last(&self, kind: RowKind) -> Option<u16> {
        match kind {
            RowKind::Bus => self
                .buses
                .iter()
                .flatten()
                .last()
                .map(|bus| u16::from(bus.bus)),
            RowKind::Device => self
                .devices
                .iter()
                .flatten()
                .last()
                .map(|held| held.device.dev),
            RowKind::Component => self
                .components
                .iter()
                .flatten()
                .last()
                .map(|held| held.component.cmp.get()),
            RowKind::Signal => self
                .signals
                .iter()
                .flatten()
                .last()
                .map(|signal| signal.sig.get()),
            RowKind::Param => None,
        }
    }

    /// Push every row of the page's kind from `from` on, until the page is
    /// full; the page keeps the id it stopped at.
    fn fill(&self, page: &mut Page, from: u16) -> Result<(), InventoryError> {
        match page.kind() {
            RowKind::Bus => {
                for bus in self.buses.iter().flatten() {
                    let id = u16::from(bus.bus);
                    if id >= from && !page.push(&Row::new(RowKind::Bus, &bus_values(bus))?, id)? {
                        break;
                    }
                }
            }
            RowKind::Device => {
                for held in self.devices.iter().flatten() {
                    let id = held.device.dev;
                    if id >= from
                        && !page.push(&Row::new(RowKind::Device, &device_values(held))?, id)?
                    {
                        break;
                    }
                }
            }
            RowKind::Component => {
                for held in self.components.iter().flatten() {
                    let id = held.component.cmp.get();
                    if id >= from
                        && !page
                            .push(&Row::new(RowKind::Component, &component_values(held))?, id)?
                    {
                        break;
                    }
                }
            }
            RowKind::Signal => {
                for signal in self.signals.iter().flatten() {
                    let id = signal.sig.get();
                    if id >= from
                        && !page.push(&Row::new(RowKind::Signal, &signal_values(signal))?, id)?
                    {
                        break;
                    }
                }
            }
            RowKind::Param => {}
        }
        Ok(())
    }

    /// P-148 over every row in canonical order, each page's bytes exactly as
    /// a page carries them.
    fn digested(&self) -> Result<[u8; 8], InventoryError> {
        let mut digest = TopoDigest::new(self.rev);
        for kind in [
            RowKind::Bus,
            RowKind::Device,
            RowKind::Component,
            RowKind::Signal,
        ] {
            let mut from = 0u16;
            // Each page takes at least one row, so a kind is walked in at most
            // as many pages as it has rows, and one more to find it empty.
            for _ in 0..=SITE_SIGNALS {
                let mut page = Page::new(kind);
                self.fill(&mut page, from)?;
                digest.absorb(&page)?;
                from = page.next();
                if from == 0 {
                    break;
                }
            }
        }
        Ok(digest.finish())
    }

    fn device(&self, dev: u16) -> Option<&Held> {
        self.devices
            .iter()
            .flatten()
            .find(|held| held.device.dev == dev)
    }

    fn component(&self, cmp: Id) -> Option<&HeldComponent> {
        self.components
            .iter()
            .flatten()
            .find(|held| held.component.cmp == cmp)
    }

    fn signal(&self, sig: Id) -> Option<&SiteSignal> {
        self.signals
            .iter()
            .flatten()
            .find(|signal| signal.sig == sig)
    }

    fn add_bus(&mut self, bus: SiteBus) -> Result<(), TopologyError> {
        if self.buses.iter().flatten().any(|held| held.bus == bus.bus) {
            return Err(TopologyError::Duplicate(RowKind::Bus, u16::from(bus.bus)));
        }
        Row::new(RowKind::Bus, &bus_values(&bus)).map_err(TopologyError::Row)?;
        insert(&mut self.buses, bus, |held| held.bus > bus.bus)
            .ok_or(TopologyError::Full(RowKind::Bus))
    }

    fn add_device(&mut self, device: SiteDevice, rev: u32) -> Result<(), TopologyError> {
        if self.has_device(device.dev) {
            return Err(TopologyError::Duplicate(RowKind::Device, device.dev));
        }
        let bus = self
            .buses
            .iter()
            .flatten()
            .find(|bus| bus.bus == device.bus)
            .ok_or(TopologyError::NoSuchBus(device.bus))?;
        let addressed = matches!(
            bus.transport,
            Transport::Rs485 | Transport::Can | Transport::Ip
        );
        let clash = device.addr.is_some_and(|addr| {
            self.devices.iter().flatten().any(|held| {
                held.device.bus == device.bus && held.device.addr.is_some_and(|other| other == addr)
            })
        });
        if (addressed && device.addr.is_none()) || clash {
            return Err(TopologyError::Address(device.dev));
        }
        if let Some(parent) = device.parent {
            // The parent is held already, so the chain is acyclic by
            // construction; its depth is what is left to check.
            let mut depth = 1usize;
            let mut at = Some(parent);
            while let Some(here) = at {
                let held = self.device(here).ok_or(TopologyError::NoSuchDevice(here))?;
                depth = depth.saturating_add(1);
                if depth > MAX_TOPOLOGY_DEPTH {
                    return Err(TopologyError::TooDeep(device.dev));
                }
                at = held.device.parent;
            }
        }
        let held = Held { device, since: rev };
        Row::new(RowKind::Device, &device_values(&held)).map_err(TopologyError::Row)?;
        insert(&mut self.devices, held, |other| {
            other.device.dev > device.dev
        })
        .ok_or(TopologyError::Full(RowKind::Device))
    }

    fn add_component(&mut self, component: SiteComponent, rev: u32) -> Result<(), TopologyError> {
        let cmp = component.cmp;
        if self.component(cmp).is_some() {
            return Err(TopologyError::Duplicate(RowKind::Component, cmp.get()));
        }
        if !self.has_device(component.dev) {
            return Err(TopologyError::NoSuchDevice(component.dev));
        }
        // The parent is held already and on the same device, so the chain
        // is acyclic by construction and never leaves the device; its depth
        // is what is left to check (P-187).
        let mut depth = 1usize;
        let mut at = component.parent;
        while let Some(here) = at {
            let held = self
                .component(here)
                .filter(|held| held.component.dev == component.dev)
                .ok_or(TopologyError::NoSuchComponent(here.get()))?;
            depth = depth.saturating_add(1);
            if depth > MAX_TOPOLOGY_DEPTH {
                return Err(TopologyError::TooDeep(cmp.get()));
            }
            at = held.component.parent;
        }
        let held = HeldComponent {
            component,
            since: rev,
        };
        Row::new(RowKind::Component, &component_values(&held)).map_err(TopologyError::Row)?;
        insert(&mut self.components, held, |other| {
            other.component.cmp > cmp
        })
        .ok_or(TopologyError::Full(RowKind::Component))
    }

    fn add_signal(&mut self, signal: SiteSignal) -> Result<(), TopologyError> {
        if self.has_signal(signal.sig) {
            return Err(TopologyError::Duplicate(RowKind::Signal, signal.sig.get()));
        }
        if !self.has_device(signal.dev) {
            return Err(TopologyError::NoSuchDevice(signal.dev));
        }
        if let Some(cmp) = signal.cmp
            && self
                .component(cmp)
                .is_none_or(|held| held.component.dev != signal.dev)
        {
            return Err(TopologyError::NoSuchComponent(cmp.get()));
        }
        if signal.kind.0 >= VENDOR_KINDS {
            return Err(TopologyError::VendorKind(signal.sig));
        }
        if self.signals().any(|held| same_identity(held, &signal)) {
            return Err(TopologyError::Collides(signal.sig));
        }
        Row::new(RowKind::Signal, &signal_values(&signal)).map_err(TopologyError::Row)?;
        insert(&mut self.signals, signal, |held| held.sig > signal.sig)
            .ok_or(TopologyError::Full(RowKind::Signal))
    }
}

/// Where P-019's vendor range of metric kinds begins.
const VENDOR_KINDS: u16 = 0xF000;

/// P-207's identity; every signal here is a scalar, so `shape` agrees
/// across all of them.
fn same_identity(a: &SiteSignal, b: &SiteSignal) -> bool {
    a.dev == b.dev
        && a.cmp == b.cmp
        && a.kind == b.kind
        && a.vtype == b.vtype
        && a.domain == b.domain
        && a.point == b.point
        && a.dir == b.dir
}

/// Put `row` before the first held row `after` says it precedes, keeping
/// the slice in id order; `None` when every slot is taken.
fn insert<T: Copy>(slots: &mut [Option<T>], row: T, after: impl Fn(&T) -> bool) -> Option<()> {
    let len = slots.iter().flatten().count();
    if len >= slots.len() {
        return None;
    }
    let at = slots
        .iter()
        .take(len)
        .position(|held| held.as_ref().is_some_and(&after))
        .unwrap_or(len);
    let tail = slots.get_mut(at..=len)?;
    tail.rotate_right(1);
    *tail.first_mut()? = Some(row);
    Some(())
}

fn bus_values(bus: &SiteBus) -> [Value<'static>; 4] {
    [
        Value::U8(bus.bus),
        Value::U8(bus.transport as u8),
        Value::Absent,
        bus.rate.map_or(Value::Absent, Value::U32),
    ]
}

fn device_values(held: &Held) -> [Value<'_>; 13] {
    let device = &held.device;
    [
        Value::U16(device.dev),
        Value::U8(device.bus),
        device
            .addr
            .as_ref()
            .map_or(Value::Absent, |addr| Value::Bytes(addr.as_bytes())),
        Value::U16(device.product.0),
        Value::U16(device.dialect.0),
        Value::U16(device.role.0),
        device.parent.map_or(Value::Absent, Value::U16),
        Value::Absent,
        Value::Absent,
        Value::Absent,
        Value::Absent,
        Value::U32(held.since),
        Value::Absent,
    ]
}

fn component_values(held: &HeldComponent) -> [Value<'static>; 9] {
    let component = &held.component;
    [
        Value::U16(component.cmp.get()),
        Value::U16(component.dev),
        component
            .parent
            .map_or(Value::Absent, |parent| Value::U16(parent.get())),
        Value::U16(component.role.0),
        component.index.map_or(Value::Absent, Value::U16),
        Value::Absent,
        Value::Absent,
        Value::Absent,
        Value::U32(held.since),
    ]
}

fn signal_values(signal: &SiteSignal) -> [Value<'static>; 18] {
    [
        Value::U16(signal.sig.get()),
        Value::U16(signal.dev),
        // 0 is the device as a whole (P-200).
        Value::U16(signal.cmp.map_or(0, Id::get)),
        Value::U16(signal.kind.0),
        Value::U8(Shape::Scalar as u8),
        Value::U8(signal.vtype as u8),
        Value::U8(signal.domain as u8),
        signal
            .point
            .map_or(Value::Absent, |point| Value::U16(point.0)),
        signal.dir.map_or(Value::Absent, |dir| Value::U8(dir as u8)),
        Value::Absent,
        Value::Absent,
        Value::Absent,
        signal.esp.map_or(Value::Absent, |esp| Value::U16(esp.0)),
        Value::Absent,
        Value::Absent,
        Value::Absent,
        Value::Absent,
        Value::Absent,
    ]
}

#[cfg(test)]
pub(crate) mod tests {
    use km43::{CborReader, InventoryHeader, TOPO_DIGEST_LABEL};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::tick::Millis;

    pub(crate) fn limits() -> Limits {
        Limits::new(Millis::from_millis(60_000), None).expect("a limit")
    }

    pub(crate) fn bus(bus: u8, transport: Transport) -> Descriptor {
        Descriptor::Bus(SiteBus {
            bus,
            transport,
            rate: None,
        })
    }

    pub(crate) fn device(dev: u16, bus: u8, addr: Option<u8>, parent: Option<u16>) -> Descriptor {
        Descriptor::Device(SiteDevice {
            dev,
            bus,
            addr: addr.and_then(|addr| DeviceAddress::new(&[addr])),
            product: Product(0x0101),
            dialect: Dialect(0x0001),
            role: DeviceRole(0x0001),
            parent,
        })
    }

    /// A DC voltage on `dev`, told apart from its neighbours by `point`.
    pub(crate) fn signal(sig: u16, dev: u16) -> Descriptor {
        Descriptor::Signal(SiteSignal {
            sig: Id::new(sig).expect("non-zero"),
            dev,
            cmp: None,
            kind: MetricKind::DC_VOLTAGE,
            vtype: Vtype::Gauge,
            domain: SignalDomain::Live,
            point: Some(MeasurementPoint(sig)),
            dir: None,
            esp: None,
            limits: limits(),
        })
    }

    /// Bus 1 with one charger at address 1, and `signals` signals on it.
    fn site(signals: u16) -> Topology {
        let mut topology = Topology::new();
        let mut batch = [bus(1, Transport::Rs485); 2 + SITE_SIGNALS];
        batch[1] = device(1, 1, Some(1), None);
        for sig in 1..=signals {
            batch[usize::from(sig) + 1] = signal(sig, 1);
        }
        topology
            .apply(
                TopologyChangeReason::Boot,
                &batch[..usize::from(signals) + 2],
            )
            .expect("a valid site");
        topology
    }

    type Body = ([u8; km43::INNER_BODY_BYTES], usize);

    fn read(topology: &Topology, rev: u32, what: u8, from: u16) -> (InventoryHeader, Body) {
        let mut dst = [0u8; km43::INNER_BODY_BYTES];
        let len = topology
            .answer(
                &ReadInventory {
                    rev,
                    what,
                    from,
                    dev: None,
                },
                &mut dst,
            )
            .expect("answers");
        (
            InventoryHeader::decode(&dst[..len]).expect("a client reads it"),
            (dst, len),
        )
    }

    /// Hash the rows array of a page, row by row, as a client receives them.
    fn absorb_rows(body: &[u8], hash: &mut Sha256) {
        let mut reader = CborReader::new(body);
        let pairs = reader.map().expect("a map");
        for _ in 0..pairs {
            if reader.key().expect("a key") == 3 {
                let n = reader.array().expect("rows");
                for _ in 0..n {
                    hash.update(reader.raw().expect("a row"));
                }
            } else {
                reader.skip().expect("skips");
            }
        }
    }

    #[test]
    fn p_213_the_boot_moves_the_revision_to_one_and_counts_what_the_tables_hold() {
        let mut topology = Topology::new();
        assert_eq!(topology.rev(), 0);
        let changed = topology
            .apply(
                TopologyChangeReason::Boot,
                &[
                    bus(1, Transport::Rs485),
                    device(1, 1, Some(1), None),
                    signal(1, 1),
                ],
            )
            .expect("applies");
        assert_eq!(topology.rev(), 1);
        assert_eq!(changed.rev, 1);
        assert_eq!((changed.added, changed.removed), (3, 0));
        // A later write counts what it added, not the table.
        let changed = topology
            .apply(TopologyChangeReason::ConfigWrite, &[signal(2, 1)])
            .expect("applies");
        assert_eq!((changed.rev, changed.added), (2, 1));
    }

    #[test]
    fn p_149_a_refused_batch_leaves_the_rows_the_revision_and_the_digest() {
        let mut topology = site(2);
        let (rev, digest) = (topology.rev(), topology.digest());
        // A good row, then one on a device that does not exist.
        let refused = topology.apply(
            TopologyChangeReason::ConfigWrite,
            &[signal(3, 1), signal(4, 9)],
        );
        assert_eq!(refused, Err(TopologyError::NoSuchDevice(9)));
        assert_eq!((topology.rev(), topology.digest()), (rev, digest));
        assert!(!topology.has_signal(Id::new(3).expect("non-zero")));
    }

    #[test]
    fn p_148_p_149_the_digest_moves_with_any_row_and_is_p_148s_hash_of_the_rows_as_sent() {
        let a = site(3);
        let b = site(3);
        assert_eq!(
            a.digest(),
            b.digest(),
            "same rows, same revision, same digest"
        );
        let c = site(4);
        assert_ne!(a.digest(), c.digest());
        // A client's own P-148 over the rows it received, in canonical order.
        let mut hash = Sha256::new();
        hash.update(TOPO_DIGEST_LABEL);
        hash.update(a.rev().to_be_bytes());
        for what in [1, 2, 3, 4] {
            let (header, (body, len)) = read(&a, 0, what, 0);
            assert_eq!(header.digest, Some(a.digest()), "the last page carries it");
            absorb_rows(&body[..len], &mut hash);
        }
        assert_eq!(hash.finalize()[..8], a.digest());
    }

    #[test]
    fn p_147_an_empty_kind_from_the_beginning_is_answered_and_a_cursor_on_it_is_out_of_range() {
        let topology = site(0);
        let (header, _) = read(&topology, 0, RowKind::Signal.number(), 0);
        assert_eq!(header.outcome, InventoryOutcome::Ok);
        assert_eq!((header.rows, header.next, header.total), (0, 0, 0));
        let (header, _) = read(&topology, 0, RowKind::Component.number(), 0);
        assert_eq!((header.outcome, header.rows), (InventoryOutcome::Ok, 0));
        let (header, _) = read(&topology, 0, RowKind::Signal.number(), 1);
        assert_eq!(header.outcome, InventoryOutcome::OutOfRange);
    }

    #[test]
    fn p_208_one_row_over_a_page_resumes_at_that_row_and_the_digest_rides_the_last_page() {
        let what = RowKind::Signal.number();
        // A page of these rows ends at the byte cap, below the row cap of 48.
        let (full, _) = read(&site(64), 0, what, 0);
        let page = u16::try_from(full.rows).expect("fits");
        assert!(full.rows < km43::MAX_INVENTORY_PAGE_ROWS && full.next == page + 1);
        // Exactly one page: no cursor, and the digest.
        let one = site(page);
        let (whole, _) = read(&one, 0, what, 0);
        assert_eq!((whole.rows, whole.next), (full.rows, 0));
        assert_eq!(whole.digest, Some(one.digest()));
        // One row over: the next page starts at that row and ends the kind.
        let over = site(page + 1);
        let (first, _) = read(&over, over.rev(), what, 0);
        assert_eq!(
            (first.rows, first.next, first.total),
            (full.rows, page + 1, page + 1)
        );
        assert_eq!(first.digest, None, "no digest mid-walk");
        let (second, _) = read(&over, over.rev(), what, first.next);
        assert_eq!((second.rows, second.next), (1, 0));
        assert_eq!(second.digest, Some(over.digest()));
    }

    #[test]
    fn p_145_p_146_p_147_a_stale_revision_an_unknown_kind_and_a_cursor_past_the_end_answer_nothing()
    {
        let topology = site(3);
        let (header, _) = read(&topology, topology.rev().wrapping_add(7), 4, 0);
        assert_eq!(header.outcome, InventoryOutcome::Superseded);
        assert_eq!(
            (header.rev, header.rows, header.next),
            (topology.rev(), 0, 0)
        );
        let (header, _) = read(&topology, 0, 9, 0);
        assert_eq!(header.outcome, InventoryOutcome::UnknownKind);
        let (header, _) = read(&topology, 0, 4, 4);
        assert_eq!(
            (header.outcome, header.rows, header.digest),
            (InventoryOutcome::OutOfRange, 0, None)
        );
    }

    #[test]
    fn p_202_an_addressed_device_needs_an_address_of_its_own_on_its_bus() {
        let mut topology = site(0);
        let rev = topology.rev();
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[device(2, 1, None, None)]
            ),
            Err(TopologyError::Address(2))
        );
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[device(2, 1, Some(1), None)]
            ),
            Err(TopologyError::Address(2))
        );
        assert_eq!(topology.rev(), rev);
        // The same address on another bus, and none on a bus with no addresses.
        topology
            .apply(
                TopologyChangeReason::ConfigWrite,
                &[
                    bus(2, Transport::Rs485),
                    device(2, 2, Some(1), None),
                    bus(3, Transport::VeDirect),
                    device(3, 3, None, None),
                ],
            )
            .expect("distinct buses");
    }

    #[test]
    fn p_187_a_parent_the_table_does_not_hold_or_a_chain_past_the_depth_is_refused() {
        let mut topology = site(0);
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[device(2, 1, Some(2), Some(9))]
            ),
            Err(TopologyError::NoSuchDevice(9))
        );
        // Three generations below device 1 is the depth of four.
        topology
            .apply(
                TopologyChangeReason::SubDeviceAdopted,
                &[
                    device(2, 1, Some(2), Some(1)),
                    device(3, 1, Some(3), Some(2)),
                    device(4, 1, Some(4), Some(3)),
                ],
            )
            .expect("four deep");
        assert_eq!(
            topology.apply(
                TopologyChangeReason::SubDeviceAdopted,
                &[device(5, 1, Some(5), Some(4))]
            ),
            Err(TopologyError::TooDeep(5))
        );
    }

    #[test]
    fn p_207_two_signals_measuring_the_same_thing_collide_and_neither_repeats_an_id() {
        let mut topology = site(1);
        let mut twin = signal(2, 1);
        if let Descriptor::Signal(sig) = &mut twin {
            sig.point = Some(MeasurementPoint(1));
        }
        assert_eq!(
            topology.apply(TopologyChangeReason::ConfigWrite, &[twin]),
            Err(TopologyError::Collides(Id::new(2).expect("non-zero")))
        );
        assert_eq!(
            topology.apply(TopologyChangeReason::ConfigWrite, &[signal(1, 1)]),
            Err(TopologyError::Duplicate(RowKind::Signal, 1))
        );
    }

    #[test]
    fn p_005_a_full_table_refuses_the_next_row_and_evicts_nothing() {
        let mut topology = Topology::new();
        let mut buses = [bus(0, Transport::Onewire); SITE_BUSES];
        for (n, slot) in buses.iter_mut().enumerate() {
            *slot = bus(u8::try_from(n).expect("fits"), Transport::Onewire);
        }
        topology
            .apply(TopologyChangeReason::Boot, &buses)
            .expect("every slot");
        let rev = topology.rev();
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[bus(200, Transport::Can)]
            ),
            Err(TopologyError::Full(RowKind::Bus))
        );
        assert_eq!(topology.rev(), rev);
        assert_eq!(
            topology.count(RowKind::Bus),
            u16::try_from(SITE_BUSES).expect("fits")
        );
    }

    #[test]
    fn p_198_a_device_selector_reaches_its_sub_devices_and_no_further() {
        let mut topology = site(1);
        topology
            .apply(
                TopologyChangeReason::SubDeviceAdopted,
                &[
                    device(2, 1, Some(2), Some(1)),
                    signal(2, 2),
                    device(3, 1, Some(3), None),
                    signal(3, 3),
                ],
            )
            .expect("applies");
        let dev = |n| Sel::Dev(Id::new(n).expect("non-zero"));
        let selected = |sel| {
            let mut out = [0u16; 3];
            for (slot, signal) in out.iter_mut().zip(
                topology
                    .signals()
                    .filter(|signal| topology.selects(sel, signal)),
            ) {
                *slot = signal.sig.get();
            }
            out
        };
        assert_eq!(selected(dev(1)), [1, 2, 0]);
        assert_eq!(selected(dev(2)), [2, 0, 0]);
        assert_eq!(selected(dev(3)), [3, 0, 0]);
        assert!(!topology.knows(dev(9)));
        assert!(!topology.knows(Sel::Cmp(Id::new(1).expect("non-zero"))));
    }

    pub(crate) fn component(cmp: u16, dev: u16, parent: Option<u16>) -> Descriptor {
        Descriptor::Component(SiteComponent {
            cmp: Id::new(cmp).expect("non-zero"),
            dev,
            parent: parent.map(|parent| Id::new(parent).expect("non-zero")),
            role: ComponentRole::BATTERY_BANK,
            index: None,
        })
    }

    fn at_component(sig: u16, dev: u16, cmp: u16) -> Descriptor {
        let mut declared = signal(sig, dev);
        if let Descriptor::Signal(signal) = &mut declared {
            signal.cmp = Some(Id::new(cmp).expect("non-zero"));
            // One kind on every side: only `cmp` tells them apart.
            signal.point = None;
        }
        declared
    }

    #[test]
    fn p_207_the_same_quantity_on_two_components_of_one_device_is_two_signals() {
        let mut topology = site(0);
        topology
            .apply(
                TopologyChangeReason::ConfigWrite,
                &[
                    component(1, 1, None),
                    component(2, 1, None),
                    at_component(1, 1, 1),
                    at_component(2, 1, 2),
                ],
            )
            .expect("PV and battery sides are different signals");
        assert_eq!(
            topology.apply(TopologyChangeReason::ConfigWrite, &[at_component(3, 1, 2)]),
            Err(TopologyError::Collides(Id::new(3).expect("non-zero")))
        );
        let (header, _) = read(&topology, 0, RowKind::Component.number(), 0);
        assert_eq!(
            (header.outcome, header.rows, header.total),
            (InventoryOutcome::Ok, 2, 2)
        );
    }

    #[test]
    fn p_187_p_200_a_component_belongs_to_its_device_and_its_chain_stays_there() {
        let mut topology = site(0);
        topology
            .apply(
                TopologyChangeReason::ConfigWrite,
                &[
                    bus(2, Transport::Can),
                    device(2, 2, Some(1), None),
                    component(1, 2, None),
                ],
            )
            .expect("applies");
        let rev = topology.rev();
        // A parent on another device, a signal at another device's
        // component, a parent the table does not hold.
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[component(2, 1, Some(1))]
            ),
            Err(TopologyError::NoSuchComponent(1))
        );
        assert_eq!(
            topology.apply(TopologyChangeReason::ConfigWrite, &[at_component(1, 1, 1)]),
            Err(TopologyError::NoSuchComponent(1))
        );
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[component(3, 2, Some(9))]
            ),
            Err(TopologyError::NoSuchComponent(9))
        );
        assert_eq!(topology.rev(), rev, "refused whole");
        // Four deep is the cap.
        topology
            .apply(
                TopologyChangeReason::ConfigWrite,
                &[
                    component(2, 2, Some(1)),
                    component(3, 2, Some(2)),
                    component(4, 2, Some(3)),
                ],
            )
            .expect("four deep");
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[component(5, 2, Some(4))]
            ),
            Err(TopologyError::TooDeep(5))
        );
    }

    #[test]
    fn p_198_a_component_selector_reaches_its_children_and_not_its_device() {
        let mut topology = site(1);
        topology
            .apply(
                TopologyChangeReason::ConfigWrite,
                &[
                    component(1, 1, None),
                    component(2, 1, Some(1)),
                    at_component(2, 1, 1),
                    at_component(3, 1, 2),
                ],
            )
            .expect("applies");
        let cmp = |n| Sel::Cmp(Id::new(n).expect("non-zero"));
        let selected = |sel| {
            let mut out = [0u16; 3];
            for (slot, signal) in out.iter_mut().zip(
                topology
                    .signals()
                    .filter(|signal| topology.selects(sel, signal)),
            ) {
                *slot = signal.sig.get();
            }
            out
        };
        assert_eq!(selected(cmp(1)), [2, 3, 0]);
        assert_eq!(selected(cmp(2)), [3, 0, 0]);
        assert!(topology.knows(cmp(2)));
        assert!(!topology.knows(cmp(9)));
    }

    #[test]
    fn p_005_a_full_component_table_refuses_the_next_and_keeps_its_rows() {
        let mut topology = site(0);
        let mut batch = [component(1, 1, None); SITE_COMPONENTS];
        for (n, slot) in (1u16..).zip(batch.iter_mut()) {
            *slot = component(n, 1, None);
        }
        topology
            .apply(TopologyChangeReason::ConfigWrite, &batch)
            .expect("every slot");
        assert_eq!(
            topology.apply(
                TopologyChangeReason::ConfigWrite,
                &[component(200, 1, None)]
            ),
            Err(TopologyError::Full(RowKind::Component))
        );
        assert_eq!(
            usize::from(topology.count(RowKind::Component)),
            SITE_COMPONENTS
        );
    }

    #[test]
    fn p_005_hello_reports_the_caps_this_table_and_the_store_enforce() {
        let topology = site(1);
        let reported = reported(topology.rev(), topology.digest());
        assert_eq!(reported.rev, topology.rev());
        assert_eq!(reported.digest, topology.digest());
        assert_eq!(usize::from(reported.signals), SITE_SIGNALS);
        assert_eq!(usize::from(reported.buses), SITE_BUSES);
        assert_eq!(usize::from(reported.devices), SITE_DEVICES);
        assert_eq!(usize::from(reported.components), SITE_COMPONENTS);
        assert_eq!((reported.params, reported.series_elements), (0, 0));
        assert_eq!(usize::from(reported.concerns), crate::CONCERN_ROWS);
    }
}
