//! The site as the reading plane sees it: the one store, the descriptors
//! that say what each reading is, the concern table, and what a client has
//! been told about each.
//!
//! One [`Site`] exists on the controller. The bus tasks write readings,
//! device presence and conditions into it; the sessions answer
//! `ReadInventory`, `ReadSignals` and `ReadConcerns` out of it; and the
//! recorder asks it, once a tick, for the class A records the changes owe.
//!
//! **The records a tick owes are derived, never queued** (P-182). Each
//! signal, device and concern keeps the last value a record announced for
//! it, and a tick compares that with what it is now. A tick hands out at
//! most one `0x0102`, one `0x0902`, one `0x0901` and
//! `MAX_CONCERN_EVENTS_PER_TICK` of `0x0501` and `0x0502` together: seven,
//! against a session queue of sixteen, a margin of nine. What does not fit
//! is still different from what was announced, so the next tick finds it
//! again; nothing is dropped because nothing was ever enqueued. The sweep
//! starts where the last one stopped, so a signal that flaps every tick
//! cannot keep the ones after it waiting for ever.
//!
//! A record that does not reach the log is given back with
//! [`Site::not_committed`], and what it announced is owed again. A record is
//! as wide as one ring record allows, so a sweep carries at most
//! [`SWEEP_ENTRIES`] signals and the rest wait a tick.
//!
//! cites: P-093, P-182, P-196, P-198, P-199, P-212, P-213

use km43::{
    ChangeError, ConcernsError, EventKind, Id, InventoryError, MAX_CONCERN_EVENTS_PER_TICK,
    MAX_EVENT_QUEUE, PChange, Presence, PresenceChanged, ReadConcerns, ReadInventory, ReadSignals,
    ReadingsBody, ReadingsError, ReadingsOutcome, ReadingsPage, SignalQuality,
    TopologyChangeReason, TopologyChanged, VChange, Validity, ValidityChanged,
};

use crate::concern_table::{ConcernError, ConcernRecord, ConcernReport, ConcernTable, Latch};
use crate::record::MAX_PAYLOAD;
use crate::signals::{Observation, SignalError, SiteSignals};
use crate::tick::Tick;
use crate::topology::{Descriptor, SITE_DEVICES, SITE_SIGNALS, Topology, TopologyError};

/// The class A records one tick can owe from the reading plane.
pub const TICK_RECORDS: usize = 1 + 1 + 1 + MAX_CONCERN_EVENTS_PER_TICK;

const _: () = assert!(
    TICK_RECORDS < MAX_EVENT_QUEUE,
    "one tick of the reading plane must fit a session's queue with room to spare (P-182)"
);

/// What a record spends around its body: the event map's header, `seq` and
/// `at` at full width, `kind`, and the four keys.
const EVENT_OVERHEAD: usize = 1 + 1 + 9 + 1 + 9 + 1 + 3 + 1;

/// The widest body one ring record holds.
pub const RECORD_BODY: usize = MAX_PAYLOAD - EVENT_OVERHEAD;

/// A sweep's own map around its array: the header, `rev` at full width, and
/// the array's header.
const SWEEP_OVERHEAD: usize = 1 + 1 + 5 + 1 + 3;

/// Signals one `0x0102` carries: as many of the widest entry as one record
/// holds.
pub const SWEEP_ENTRIES: usize = (RECORD_BODY - SWEEP_OVERHEAD) / km43::VCHANGE_MAX_BYTES;

/// Devices one `0x0902` carries.
pub const PRESENCE_ENTRIES: usize = (RECORD_BODY - SWEEP_OVERHEAD) / km43::PCHANGE_MAX_BYTES;

const _: () = {
    assert!(SWEEP_ENTRIES >= 1 && SWEEP_ENTRIES <= km43::MAX_VALIDITY_SWEEP);
    assert!(PRESENCE_ENTRIES >= SITE_DEVICES);
};

/// Why the site refused something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused write is a reading or a condition nobody recorded"]
pub enum SiteError {
    /// The descriptors refused the batch.
    Topology(TopologyError),
    /// The store refused the reading or the registration.
    Store(SignalError),
    /// The concern table refused.
    Concern(ConcernError),
    /// No device of that id.
    UnknownDevice(u16),
}

/// Each device an `0x0902` names and the presence it had been announced at
/// before, for putting back if the record does not land.
pub type Prevs = [Option<(u16, Presence)>; SITE_DEVICES];

/// What one tick has handed out so far (P-182).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tally {
    validity: bool,
    presence: bool,
    topology: bool,
    concerns: usize,
}

impl Tally {
    /// A tick with nothing handed out.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            validity: false,
            presence: false,
            topology: false,
            concerns: 0,
        }
    }
}

/// A record handed out and not yet known to have landed: what to put back
/// if it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// An `0x0102`; its body names each signal and what was announced before.
    Validity,
    /// An `0x0902`, and the presence each device had been announced at.
    Presence(Prevs),
    /// An `0x0901`.
    Topology(TopologyChanged),
    /// An `0x0501` or an `0x0502`.
    Concern(ConcernRecord),
}

/// A record the tick owes: its kind, its body at the head of the buffer it
/// was written into, and what it announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an owed record not handed to the log is a change no client hears of"]
pub struct Owed {
    /// The event kind.
    pub kind: EventKind,
    /// The body's length.
    pub len: usize,
    /// What it announced.
    pub token: Token,
}

/// A signal and the quality last announced for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Announced {
    sig: Id,
    q: SignalQuality,
}

/// A device's presence: as held now, as held before that, and as last
/// announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    dev: u16,
    held: Presence,
    before: Presence,
    announced: Presence,
}

/// The reading plane's one instance.
pub struct Site {
    signals: SiteSignals,
    topology: Topology,
    concerns: ConcernTable,
    announced: [Option<Announced>; SITE_SIGNALS],
    presence: [Option<Seen>; SITE_DEVICES],
    topology_owed: Option<TopologyChanged>,
    /// Where the next validity sweep starts.
    cursor: usize,
}

impl Default for Site {
    fn default() -> Self {
        Self::new()
    }
}

impl Site {
    /// Nothing registered, at topology revision 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            signals: SiteSignals::new(),
            topology: Topology::new(),
            concerns: ConcernTable::new(),
            announced: [None; SITE_SIGNALS],
            presence: [None; SITE_DEVICES],
            topology_owed: None,
            cursor: 0,
        }
    }

    /// The store, read-only: a behaviour's [`SiteSignals::current`] and the
    /// readings a client pages through.
    #[must_use]
    pub const fn signals(&self) -> &SiteSignals {
        &self.signals
    }

    /// The descriptors.
    #[must_use]
    pub const fn topology(&self) -> &Topology {
        &self.topology
    }

    /// The concern table.
    #[must_use]
    pub const fn concerns(&self) -> &ConcernTable {
        &self.concerns
    }

    /// Take `batch` into the descriptors under a new revision, registering
    /// each signal in the store with the limits it declares, or refuse all
    /// of it. The `0x0901` it owes is announced by a later tick.
    pub fn apply(
        &mut self,
        reason: TopologyChangeReason,
        batch: &[Descriptor],
    ) -> Result<(), SiteError> {
        let fresh = batch.iter().filter_map(|declared| match declared {
            Descriptor::Signal(signal) => Some((signal.sig, signal.limits)),
            Descriptor::Bus(_) | Descriptor::Device(_) | Descriptor::Component(_) => None,
        });
        let room = SITE_SIGNALS.saturating_sub(self.signals.len());
        if fresh.clone().count() > room {
            return Err(SiteError::Store(SignalError::Full));
        }
        // The descriptors take the batch whole or not at all; what the store
        // could refuse was checked above, so nothing after this fails.
        let changed = self
            .topology
            .apply(reason, batch)
            .map_err(SiteError::Topology)?;
        // Checked above: the store has room for every new signal, and the
        // descriptors, which hold exactly the store's signals, refused one
        // already held or repeated inside the batch.
        for (sig, limits) in fresh {
            self.signals
                .register(sig, limits)
                .map_err(SiteError::Store)?;
            let initial = SignalQuality::absent(Validity::Initialising)
                .map_err(|why| SiteError::Store(SignalError::Quality(why)))?;
            if let Some(free) = self.announced.iter_mut().find(|slot| slot.is_none()) {
                *free = Some(Announced { sig, q: initial });
            }
        }
        for declared in batch {
            if let Descriptor::Device(device) = declared
                && let Some(free) = self.presence.iter_mut().find(|slot| slot.is_none())
            {
                *free = Some(Seen {
                    dev: device.dev,
                    held: Presence::NeverSeen,
                    before: Presence::NeverSeen,
                    announced: Presence::NeverSeen,
                });
            }
        }
        self.topology_owed = Some(match self.topology_owed {
            // Two moves before the first was announced are one: the newest
            // revision and reason, and every row either added.
            Some(owed) => TopologyChanged {
                added: owed.added.saturating_add(changed.added),
                removed: owed.removed.saturating_add(changed.removed),
                ..changed
            },
            None => changed,
        });
        Ok(())
    }

    /// What `sig`'s source said at `now`.
    pub fn write(&mut self, sig: Id, now: Tick, seen: Observation) -> Result<(), SiteError> {
        self.signals.write(sig, now, seen).map_err(SiteError::Store)
    }

    /// Device `dev` is now `presence`.
    pub fn presence(&mut self, dev: u16, presence: Presence) -> Result<(), SiteError> {
        let seen = self
            .presence
            .iter_mut()
            .flatten()
            .find(|seen| seen.dev == dev)
            .ok_or(SiteError::UnknownDevice(dev))?;
        if seen.held != presence {
            seen.before = seen.held;
            seen.held = presence;
        }
        Ok(())
    }

    /// A source says `report` holds.
    pub fn observe(&mut self, report: ConcernReport, now: Tick) -> Result<Id, SiteError> {
        self.concerns
            .observe(report, now)
            .map_err(SiteError::Concern)
    }

    /// A source says the condition is gone.
    pub fn gone(
        &mut self,
        subject: km43::Subject,
        cond: km43::Condition,
        latch: Latch,
    ) -> Result<Id, SiteError> {
        self.concerns
            .gone(subject, cond, latch)
            .map_err(SiteError::Concern)
    }

    /// A source released the latch of `cid`.
    pub fn released(&mut self, cid: Id) -> Result<(), SiteError> {
        self.concerns.released(cid).map_err(SiteError::Concern)
    }

    /// Somebody acknowledged `cid` (P-168).
    pub fn acknowledge(&mut self, cid: Id) -> Result<km43::ConcernState, SiteError> {
        self.concerns.acknowledge(cid).map_err(SiteError::Concern)
    }

    /// The next record this tick owes, written into `body`, or `None` when
    /// the tick owes nothing more or has handed out all it may. `seq` is the
    /// position the log will give it, which a raise carries as its row's
    /// key 13.
    pub fn next_owed(
        &mut self,
        now: Tick,
        seq: u64,
        tally: &mut Tally,
        body: &mut [u8; RECORD_BODY],
    ) -> Result<Option<Owed>, OwedError> {
        if !tally.topology
            && let Some(changed) = self.topology_owed.take()
        {
            tally.topology = true;
            let len = changed.encode(body).map_err(OwedError::Change)?;
            return Ok(Some(Owed {
                kind: EventKind::TOPOLOGY_CHANGED,
                len,
                token: Token::Topology(changed),
            }));
        }
        if !tally.validity {
            tally.validity = true;
            if let Some(len) = self.validity_sweep(now, body)? {
                return Ok(Some(Owed {
                    kind: EventKind::SIGNAL_VALIDITY_CHANGED,
                    len,
                    token: Token::Validity,
                }));
            }
        }
        if !tally.presence {
            tally.presence = true;
            if let Some((len, prevs)) = self.presence_sweep(body)? {
                return Ok(Some(Owed {
                    kind: EventKind::DEVICE_PRESENCE_CHANGED,
                    len,
                    token: Token::Presence(prevs),
                }));
            }
        }
        if tally.concerns < MAX_CONCERN_EVENTS_PER_TICK {
            let mut record = None;
            let rev = self.topology.rev();
            self.concerns
                .owed(rev, now, 1, |owed| record = Some(owed))
                .map_err(OwedError::Concern)?;
            if let Some(mut record) = record {
                tally.concerns = tally.concerns.saturating_add(1);
                let (kind, len) = match &mut record {
                    ConcernRecord::Raised(raised) => {
                        // Key 13 is the record that opens the row: this one.
                        raised.concern.seq = seq;
                        (
                            EventKind::CONCERN_RAISED,
                            raised.encode(body).map_err(OwedError::Concern)?,
                        )
                    }
                    ConcernRecord::Changed(changed) => (
                        EventKind::CONCERN_CHANGED,
                        changed.encode(body).map_err(OwedError::Concern)?,
                    ),
                };
                return Ok(Some(Owed {
                    kind,
                    len,
                    token: Token::Concern(record),
                }));
            }
        }
        Ok(None)
    }

    /// The record `token` announced landed at `seq`.
    pub fn committed(&mut self, token: &Token, seq: u64) {
        match token {
            Token::Concern(record) => self.concerns.committed(record, seq),
            Token::Validity | Token::Presence(_) | Token::Topology(_) => {}
        }
    }

    /// The record `token` announced, whose body is `body`, did not land:
    /// what it announced is owed again.
    pub fn not_committed(&mut self, token: &Token, body: &[u8]) {
        match token {
            Token::Validity => {
                if let Ok((_, entries)) = ValidityChanged::decode(body) {
                    for change in entries.flatten() {
                        if let Some(announced) = self.announced_mut(change.sig) {
                            announced.q = change.prev;
                        }
                    }
                }
            }
            Token::Presence(prevs) => {
                for (dev, prev) in prevs.iter().flatten() {
                    if let Some(seen) = self
                        .presence
                        .iter_mut()
                        .flatten()
                        .find(|seen| seen.dev == *dev)
                    {
                        seen.announced = *prev;
                    }
                }
            }
            Token::Topology(changed) => {
                if self.topology_owed.is_none() {
                    self.topology_owed = Some(*changed);
                }
            }
            Token::Concern(record) => self.concerns.unannounced(record),
        }
    }

    /// The `Inventory 0x8D` body for `request`.
    pub fn inventory(
        &self,
        request: &ReadInventory,
        dst: &mut [u8],
    ) -> Result<usize, InventoryError> {
        self.topology.answer(request, dst)
    }

    /// The `Concerns 0x8F` body for `request`.
    pub fn concerns_page(
        &self,
        request: &ReadConcerns,
        now: Tick,
        dst: &mut [u8],
    ) -> Result<usize, ConcernsError> {
        self.concerns.answer(request, self.topology.rev(), now, dst)
    }

    /// The `Readings 0x8E` body for `request` at `now`, reflecting the log
    /// up to `seq`, in P-199's order: superseded, then a selector naming
    /// nothing, then a cursor past the selection. The selection is the union
    /// of the selectors in `sig` order (P-198), every signal when there are
    /// none; `at` is left out, since this answer carries no wall clock.
    pub fn readings(
        &self,
        request: &ReadSignals,
        seq: u64,
        now: Tick,
        dst: &mut [u8],
    ) -> Result<usize, ReadingsFailed> {
        let rev = self.topology.rev();
        let selected = |signal: &&crate::topology::SiteSignal| {
            request.is_everything()
                || request
                    .selectors()
                    .any(|sel| self.topology.selects(sel, signal))
        };
        let total =
            u16::try_from(self.topology.signals().filter(selected).count()).unwrap_or(u16::MAX);
        let refused = |outcome| ReadingsBody {
            seq,
            rev,
            at: None,
            outcome,
            total,
            page: None,
        };
        if request.rev != 0 && request.rev != rev {
            return refused(ReadingsOutcome::Superseded)
                .encode(dst)
                .map_err(ReadingsFailed::Encode);
        }
        if request.selectors().any(|sel| !self.topology.knows(sel)) {
            return refused(ReadingsOutcome::UnknownSelector)
                .encode(dst)
                .map_err(ReadingsFailed::Encode);
        }
        let last = self
            .topology
            .signals()
            .filter(selected)
            .map(|signal| signal.sig.get())
            .max();
        if request.from != 0 && last.is_none_or(|last| request.from > last) {
            return refused(ReadingsOutcome::OutOfRange)
                .encode(dst)
                .map_err(ReadingsFailed::Encode);
        }
        let mut page = ReadingsPage::new();
        for signal in self.topology.signals().filter(selected) {
            if signal.sig.get() < request.from {
                continue;
            }
            let sample = self
                .signals
                .sample(signal.sig, now)
                .map_err(ReadingsFailed::Store)?;
            if !page.push_sample(&sample).map_err(ReadingsFailed::Encode)? {
                break;
            }
        }
        ReadingsBody {
            seq,
            rev,
            at: None,
            outcome: ReadingsOutcome::Ok,
            total,
            page: Some(&page),
        }
        .encode(dst)
        .map_err(ReadingsFailed::Encode)
    }

    /// One `0x0102` of the signals whose quality differs from what was last
    /// announced, from where the last sweep stopped; each taken is marked
    /// announced.
    fn validity_sweep(
        &mut self,
        now: Tick,
        body: &mut [u8; RECORD_BODY],
    ) -> Result<Option<usize>, OwedError> {
        let mut sweep = ValidityChanged::new(self.topology.rev());
        let mut taken = 0usize;
        let start = self.cursor;
        for step in 0..SITE_SIGNALS {
            if taken >= SWEEP_ENTRIES {
                break;
            }
            let at = start.saturating_add(step) % SITE_SIGNALS;
            let Some(Some(announced)) = self.announced.get(at).copied() else {
                continue;
            };
            let sample = self
                .signals
                .sample(announced.sig, now)
                .map_err(OwedError::Store)?;
            if sample.q == announced.q {
                continue;
            }
            let change = VChange {
                sig: announced.sig,
                q: sample.q,
                prev: announced.q,
            };
            if !sweep.push(&change).map_err(OwedError::Change)? {
                break;
            }
            if let Some(Some(slot)) = self.announced.get_mut(at) {
                slot.q = sample.q;
            }
            self.cursor = at.saturating_add(1) % SITE_SIGNALS;
            taken = taken.saturating_add(1);
        }
        if sweep.is_empty() {
            return Ok(None);
        }
        sweep.encode(body).map(Some).map_err(OwedError::Change)
    }

    /// One `0x0902` of every device whose presence differs from what was
    /// last announced, each marked announced.
    fn presence_sweep(
        &mut self,
        body: &mut [u8; RECORD_BODY],
    ) -> Result<Option<(usize, Prevs)>, OwedError> {
        let mut sweep = PresenceChanged::new(self.topology.rev());
        let mut prevs = [None; SITE_DEVICES];
        for (seen, prev) in self.presence.iter_mut().flatten().zip(prevs.iter_mut()) {
            if seen.held == seen.announced {
                continue;
            }
            let Ok(dev) = Id::new(seen.dev) else {
                // Device 0 is the controller, whose presence is the session
                // itself: nothing to announce.
                continue;
            };
            // `prev` is the presence held before this one, not the one
            // announced (P-212 names only `0x0102` and `0x0502` for that).
            let change = PChange {
                dev,
                presence: seen.held,
                prev: seen.before,
            };
            if !sweep.push(&change).map_err(OwedError::Change)? {
                continue;
            }
            *prev = Some((seen.dev, seen.announced));
            seen.announced = seen.held;
        }
        if sweep.is_empty() {
            return Ok(None);
        }
        let len = sweep.encode(body).map_err(OwedError::Change)?;
        Ok(Some((len, prevs)))
    }

    fn announced_mut(&mut self, sig: Id) -> Option<&mut Announced> {
        self.announced
            .iter_mut()
            .flatten()
            .find(|announced| announced.sig == sig)
    }
}

/// Why a readings page was not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadingsFailed {
    /// The store refused a sample: a defect, surfaced.
    Store(SignalError),
    /// KM43 refused the body.
    Encode(ReadingsError),
}

/// Why an owed record was not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OwedError {
    /// The store refused a sample.
    Store(SignalError),
    /// KM43 refused a sweep or a topology body.
    Change(ChangeError),
    /// KM43 refused a concern body.
    Concern(ConcernsError),
}

#[cfg(test)]
mod tests {
    use km43::{
        Condition, MetricKind, Part, Provenance, ReadingsHeader, Sel, Severity, Subject, Transport,
    };

    use super::*;
    use crate::concern_table::ConcernReport;
    use crate::tick::Millis;
    use crate::topology::tests::{bus, device, signal};

    fn at(secs: u64) -> Tick {
        Tick::ZERO
            .after(Millis::from_millis(secs.checked_mul(1_000).expect("fits")))
            .expect("fits")
    }

    fn sig(n: u16) -> Id {
        Id::new(n).expect("non-zero")
    }

    fn reading(value: i32) -> Observation {
        Observation::value(value, Provenance::Measured).expect("a value")
    }

    /// Bus 1, device 1 at address 1, and signals `1..=signals` on it.
    fn site(signals: u16) -> Site {
        let mut site = Site::new();
        let mut batch = [bus(1, Transport::Rs485); 2 + SITE_SIGNALS];
        batch[1] = device(1, 1, Some(1), None);
        for n in 1..=signals {
            batch[usize::from(n) + 1] = signal(n, 1);
        }
        site.apply(
            TopologyChangeReason::Boot,
            &batch[..usize::from(signals) + 2],
        )
        .expect("a valid site");
        site
    }

    /// One tick's records: each kind, and the signals the `0x0102` named.
    #[derive(Default)]
    struct Tick1 {
        kinds: [Option<EventKind>; TICK_RECORDS + 1],
        sigs: [Option<(u16, SignalQuality, SignalQuality)>; SWEEP_ENTRIES],
    }

    fn tick(site: &mut Site, now: Tick) -> Tick1 {
        let mut tally = Tally::new();
        let mut body = [0u8; RECORD_BODY];
        let mut out = Tick1::default();
        for (seq, kind) in (1u64..).zip(out.kinds.iter_mut()) {
            let Some(owed) = site
                .next_owed(now, seq, &mut tally, &mut body)
                .expect("writes")
            else {
                break;
            };
            *kind = Some(owed.kind);
            if owed.kind == EventKind::SIGNAL_VALIDITY_CHANGED {
                let (_, entries) = ValidityChanged::decode(&body[..owed.len]).expect("a sweep");
                for (slot, change) in out.sigs.iter_mut().zip(entries) {
                    let change = change.expect("an entry");
                    *slot = Some((change.sig.get(), change.q, change.prev));
                }
            }
            site.committed(&owed.token, seq);
        }
        out
    }

    fn count(kinds: &[Option<EventKind>], kind: EventKind) -> usize {
        kinds.iter().flatten().filter(|k| **k == kind).count()
    }

    #[test]
    fn p_182_a_tick_with_more_changes_than_fit_carries_the_rest_and_drops_none() {
        let mut site = site(64);
        for n in 1..=64 {
            site.write(sig(n), at(1), reading(i32::from(n)))
                .expect("registered");
        }
        let mut seen = [0u8; 65];
        let mut ticks = 0;
        for second in 2..20 {
            let one = tick(&mut site, at(second));
            let sweeps = count(&one.kinds, EventKind::SIGNAL_VALIDITY_CHANGED);
            assert!(sweeps <= 1, "one 0x0102 a tick");
            if sweeps == 0 {
                break;
            }
            ticks += 1;
            for (n, q, prev) in one.sigs.iter().flatten() {
                seen[usize::from(*n)] += 1;
                assert_eq!(q.validity_of(), Validity::Ok);
                assert_eq!(prev.validity_of(), Validity::Initialising);
            }
        }
        assert!(
            seen[1..].iter().all(|n| *n == 1),
            "every signal announced exactly once"
        );
        assert_eq!(ticks, 64usize.div_ceil(SWEEP_ENTRIES));
    }

    #[test]
    fn p_182_p_212_two_tick_boundaries_never_merge_and_prev_is_what_was_announced() {
        let mut site = site(1);
        site.write(sig(1), at(1), reading(5)).expect("registered");
        let first = tick(&mut site, at(2));
        let (_, q, _) = first.sigs[0].expect("announced");
        assert_eq!(q.validity_of(), Validity::Ok);
        // Absent, then a sensor fault, before the next tick: one entry, from
        // what the last record said.
        site.write(
            sig(1),
            at(3),
            Observation::missing(Validity::Absent).expect("absent"),
        )
        .expect("registered");
        site.write(
            sig(1),
            at(3),
            Observation::missing(Validity::SensorFault).expect("fault"),
        )
        .expect("registered");
        let second = tick(&mut site, at(4));
        assert_eq!(
            second.sigs[0],
            Some((
                1,
                SignalQuality::absent(Validity::SensorFault).expect("q"),
                q
            ))
        );
        assert_eq!(second.sigs[1], None);
        // Nothing moved since: nothing owed.
        assert_eq!(
            count(
                &tick(&mut site, at(5)).kinds,
                EventKind::SIGNAL_VALIDITY_CHANGED
            ),
            0
        );
    }

    #[test]
    fn p_182_a_signal_that_moves_and_moves_back_between_ticks_owes_nothing() {
        let mut site = site(1);
        site.write(sig(1), at(1), reading(5)).expect("registered");
        let _ = tick(&mut site, at(2));
        site.write(
            sig(1),
            at(3),
            Observation::missing(Validity::Absent).expect("absent"),
        )
        .expect("registered");
        site.write(sig(1), at(3), reading(6)).expect("registered");
        assert_eq!(
            count(
                &tick(&mut site, at(4)).kinds,
                EventKind::SIGNAL_VALIDITY_CHANGED
            ),
            0
        );
    }

    #[test]
    fn p_182_silence_turns_a_signal_stale_on_the_tick_and_that_is_announced() {
        let mut site = site(1);
        site.write(sig(1), at(1), reading(5)).expect("registered");
        let _ = tick(&mut site, at(2));
        // The limit is a minute; nothing written since.
        let later = tick(&mut site, at(62));
        let (n, q, prev) = later.sigs[0].expect("announced");
        assert_eq!(
            (n, q.validity_of(), prev.validity_of()),
            (1, Validity::Stale, Validity::Ok)
        );
    }

    #[test]
    fn p_182_a_record_that_did_not_land_is_owed_again_and_one_that_did_is_not() {
        let mut site = site(2);
        site.write(sig(1), at(1), reading(5)).expect("registered");
        let mut tally = Tally::new();
        let mut body = [0u8; RECORD_BODY];
        let lost = loop {
            let owed = site
                .next_owed(at(2), 1, &mut tally, &mut body)
                .expect("writes")
                .expect("owed");
            if owed.kind == EventKind::SIGNAL_VALIDITY_CHANGED {
                break owed;
            }
            site.committed(&owed.token, 1);
        };
        site.not_committed(&lost.token, &body[..lost.len]);
        let again = tick(&mut site, at(3));
        assert_eq!(again.sigs[0].map(|(n, _, _)| n), Some(1), "owed again");
        assert_eq!(again.sigs[1], None);
        assert_eq!(
            count(
                &tick(&mut site, at(4)).kinds,
                EventKind::SIGNAL_VALIDITY_CHANGED
            ),
            0
        );
    }

    #[test]
    fn p_182_one_tick_owes_at_most_one_of_each_sweep_and_four_concern_records() {
        let mut site = site(1);
        site.write(sig(1), at(1), reading(5)).expect("registered");
        site.presence(1, Presence::Online).expect("a device");
        for n in 1..=6 {
            let report = ConcernReport {
                subject: Subject::Part(Part::device(sig(1))),
                cond: Condition(n),
                sev: Severity::Fault,
                code: None,
            };
            site.observe(report, at(1)).expect("admitted");
        }
        let first = tick(&mut site, at(2));
        assert_eq!(first.kinds.iter().flatten().count(), TICK_RECORDS);
        assert_eq!(count(&first.kinds, EventKind::TOPOLOGY_CHANGED), 1);
        assert_eq!(count(&first.kinds, EventKind::DEVICE_PRESENCE_CHANGED), 1);
        assert_eq!(
            count(&first.kinds, EventKind::CONCERN_RAISED),
            MAX_CONCERN_EVENTS_PER_TICK
        );
        let second = tick(&mut site, at(3));
        assert_eq!(
            count(&second.kinds, EventKind::CONCERN_RAISED),
            2,
            "the rest, next tick"
        );
        assert_eq!(second.kinds.iter().flatten().count(), 2);
    }

    #[test]
    fn p_182_presence_announces_the_move_with_the_presence_held_before() {
        let mut site = site(0);
        let _ = tick(&mut site, at(1));
        site.presence(1, Presence::Online).expect("a device");
        site.presence(1, Presence::Offline).expect("a device");
        let mut tally = Tally::new();
        let mut body = [0u8; RECORD_BODY];
        let owed = site
            .next_owed(at(2), 1, &mut tally, &mut body)
            .expect("writes")
            .expect("owed");
        assert_eq!(owed.kind, EventKind::DEVICE_PRESENCE_CHANGED);
        let (_, mut entries) = PresenceChanged::decode(&body[..owed.len]).expect("a sweep");
        let change = entries.next().expect("one").expect("reads");
        assert_eq!(
            (change.presence, change.prev),
            (Presence::Offline, Presence::Online)
        );
        assert_eq!(
            site.presence(9, Presence::Online),
            Err(SiteError::UnknownDevice(9))
        );
    }

    #[test]
    fn p_149_a_refused_batch_registers_nothing_in_the_store_or_the_descriptors() {
        let mut site = site(2);
        let rev = site.topology().rev();
        let refused = site.apply(
            TopologyChangeReason::ConfigWrite,
            &[signal(3, 1), signal(4, 9)],
        );
        assert!(matches!(refused, Err(SiteError::Topology(_))));
        assert_eq!(site.signals().len(), 2);
        assert_eq!(site.topology().rev(), rev);
        assert_eq!(
            site.write(sig(3), at(1), reading(1)),
            Err(SiteError::Store(SignalError::Unknown(sig(3))))
        );
        // A batch past the store's capacity is refused before either moves.
        let mut full = [signal(3, 1); SITE_SIGNALS];
        for (n, slot) in (3u16..).zip(full.iter_mut()) {
            *slot = signal(n, 1);
        }
        assert_eq!(
            site.apply(TopologyChangeReason::ConfigWrite, &full),
            Err(SiteError::Store(SignalError::Full))
        );
        assert_eq!((site.signals().len(), site.topology().rev()), (2, rev));
    }

    #[test]
    fn p_196_an_unrelated_topology_change_keeps_every_reading_it_did_not_touch() {
        let mut site = site(1);
        site.write(sig(1), at(1), reading(42)).expect("registered");
        let mut other = signal(2, 2);
        if let Descriptor::Signal(signal) = &mut other {
            signal.kind = MetricKind::DC_CURRENT;
        }
        site.apply(
            TopologyChangeReason::ConfigWrite,
            &[device(2, 1, Some(2), None), other],
        )
        .expect("applies");
        let sample = site.signals().sample(sig(1), at(2)).expect("held");
        assert_eq!(sample.value(), Some(42));
        assert_eq!(sample.q.validity_of(), Validity::Ok);
    }

    fn readings(site: &Site, request: &ReadSignals) -> ReadingsHeader {
        let mut dst = [0u8; km43::INNER_BODY_BYTES];
        let len = site.readings(request, 9, at(2), &mut dst).expect("answers");
        ReadingsHeader::decode(&dst[..len]).expect("a client reads it")
    }

    #[test]
    fn p_199_readings_page_an_empty_store_one_page_one_over_and_a_cursor_past_the_end() {
        let empty = site(0);
        let header = readings(&empty, &ReadSignals::everything(0, 0));
        assert_eq!(header.outcome, ReadingsOutcome::Ok);
        assert_eq!(
            (header.samples, header.next, header.total, header.seq),
            (0, 0, 0, 9)
        );
        // Initialising samples, the narrowest: the row cap binds at forty.
        let cap = u16::try_from(km43::MAX_SAMPLES).expect("fits");
        let one = site(cap);
        let header = readings(&one, &ReadSignals::everything(0, 0));
        assert_eq!(
            (header.samples, header.next, header.total),
            (km43::MAX_SAMPLES, 0, cap)
        );
        let over = site(cap + 1);
        let header = readings(&over, &ReadSignals::everything(over.topology().rev(), 0));
        assert_eq!((header.samples, header.next), (km43::MAX_SAMPLES, cap + 1));
        let header = readings(&over, &ReadSignals::everything(0, header.next));
        assert_eq!((header.samples, header.next), (1, 0));
        let header = readings(&over, &ReadSignals::everything(0, cap + 2));
        assert_eq!(
            (header.outcome, header.samples),
            (ReadingsOutcome::OutOfRange, 0)
        );
    }

    #[test]
    fn p_199_a_stale_revision_is_superseded_before_a_selector_that_names_nothing() {
        let site = site(2);
        let mut request = ReadSignals::everything(site.topology().rev() + 1, 0);
        request.select(Sel::Dev(sig(9))).expect("room");
        assert_eq!(
            readings(&site, &request).outcome,
            ReadingsOutcome::Superseded
        );
        request.rev = 0;
        assert_eq!(
            readings(&site, &request).outcome,
            ReadingsOutcome::UnknownSelector
        );
        let mut request = ReadSignals::everything(0, 0);
        request.select(Sel::Cmp(sig(1))).expect("room");
        assert_eq!(
            readings(&site, &request).outcome,
            ReadingsOutcome::UnknownSelector
        );
    }

    #[test]
    fn p_198_selectors_resolve_to_their_union_in_sig_order() {
        let site = site(3);
        let mut request = ReadSignals::everything(0, 0);
        request.select(Sel::Sig(sig(3))).expect("room");
        request.select(Sel::Dev(sig(1))).expect("room");
        request.select(Sel::Sig(sig(1))).expect("room");
        let header = readings(&site, &request);
        assert_eq!(
            (header.outcome, header.total, header.samples),
            (ReadingsOutcome::Ok, 3, 3)
        );
    }

    #[test]
    fn p_196_a_reading_carries_its_quality_and_an_unwritten_one_no_value() {
        let mut site = site(2);
        site.write(sig(1), at(1), reading(7)).expect("registered");
        let mut dst = [0u8; km43::INNER_BODY_BYTES];
        let len = site
            .readings(&ReadSignals::everything(0, 0), 1, at(2), &mut dst)
            .expect("answers");
        let mut values = [None; 2];
        let read = ReadingsHeader::for_each_sample(&dst[..len], |sample| {
            let n = usize::from(sample.sig.get()) - 1;
            values[n] = Some((sample.value(), sample.q.validity_of()));
        })
        .expect("reads");
        assert_eq!(read, 2);
        assert_eq!(values[0], Some((Some(7), Validity::Ok)));
        assert_eq!(values[1], Some((None, Validity::Initialising)));
    }
}
