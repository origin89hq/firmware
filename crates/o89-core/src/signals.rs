//! The reading store: every signal carries its quality beside its value.
//!
//! A slot holds what the last write said, as KM43 spells it: a
//! [`SignalQuality`] and a value exactly when that quality carries one
//! (P-196). A driver writes an [`Observation`], which cannot be built with a
//! value and no provenance or a provenance and no value, and cannot say
//! `stale`: staleness is the store's to decide, on the tick (P-004).
//!
//! A slot goes stale two ways. The bus goes quiet and nothing is written, and
//! the **maximum age** since the last write catches that. Or the instrument
//! keeps answering the same plausible number, and the optional **maximum
//! unchanged run** catches that. The run restarts on a changed value, a
//! changed quality, or a channel coming back from silence; a channel with no
//! run limit never goes stale for holding still, because for a starts counter
//! or a full tank an unchanging number is the truth.
//!
//! Provenance is read as a set, never as a threshold: a behaviour names the
//! [`ProvenanceSet`] it acts on, and [`ChargeSource`] is the generator's
//! charge-source rule as that set.
//!
//! cites: P-004, P-196

use km43::{Id, Provenance, QualityError, Sample, SignalQuality, Validity};

use crate::tick::{Millis, Tick};

/// The number of signals the controller's store holds.
///
/// Sized for M5's site: three RS-485 channels with a charger and two meters
/// between them, a BMS, two VE.Direct ports, eight probes and the ADC
/// channels, each device publishing well under ten signals. A signal
/// registered past it is refused ([`SignalError::Full`]), never evicted.
pub const SIGNAL_SLOTS: usize = 64;

/// The store the controller runs, at its named capacity.
pub type SiteSignals = Signals<SIGNAL_SLOTS>;

/// What a driver hands the store: a value with the provenance its source can
/// justify, or no value and the reason there is none.
///
/// Built only through KM43's own constructors, so the two shapes P-196
/// forbids cannot be built at all, and `stale` cannot be written: it is not
/// something a source says about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Observation {
    q: SignalQuality,
    value: Option<i32>,
}

impl Observation {
    /// A current value from `provenance`.
    ///
    /// Refuses [`Provenance::None`]: a value with no source is the claim
    /// P-196 exists against.
    pub fn value(value: i32, provenance: Provenance) -> Result<Self, QualityError> {
        Ok(Self {
            q: SignalQuality::carrying(Validity::Ok, provenance)?,
            value: Some(value),
        })
    }

    /// No value, and why.
    ///
    /// Refuses a validity that carries a value, `ok` or `stale`: a source
    /// that has a number writes it with [`Observation::value`], and staleness
    /// is the store's to decide.
    pub fn missing(validity: Validity) -> Result<Self, QualityError> {
        Ok(Self {
            q: SignalQuality::absent(validity)?,
            value: None,
        })
    }

    /// The quality as KM43 spells it.
    #[must_use]
    pub const fn quality(self) -> SignalQuality {
        self.q
    }

    /// The value, present exactly when the quality carries one.
    #[must_use]
    pub const fn reading(self) -> Option<i32> {
        self.value
    }
}

/// How long a channel's reading stays current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Limits {
    max_age: Millis,
    max_unchanged: Option<Millis>,
}

impl Limits {
    /// A channel whose value goes stale `max_age` after its last write, and,
    /// when given, `max_unchanged` after it last changed.
    ///
    /// `None` for a zero duration: a limit of zero is a channel that is stale
    /// the moment the tick moves, which is a configuration mistake and not a
    /// policy.
    #[must_use]
    pub const fn new(max_age: Millis, max_unchanged: Option<Millis>) -> Option<Self> {
        if max_age.as_millis() == 0 {
            return None;
        }
        if let Some(run) = max_unchanged
            && run.as_millis() == 0
        {
            return None;
        }
        Some(Self {
            max_age,
            max_unchanged,
        })
    }

    /// The longest a reading stays current without a write.
    #[must_use]
    pub const fn max_age(self) -> Millis {
        self.max_age
    }

    /// The longest a reading stays current without changing, if the channel
    /// has such a limit.
    #[must_use]
    pub const fn max_unchanged(self) -> Option<Millis> {
        self.max_unchanged
    }
}

/// Why the store would not do what it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused store operation is a reading that was not recorded or not read"]
pub enum SignalError {
    /// Every slot is taken. The new signal is refused and no existing one is
    /// evicted.
    Full,
    /// The signal is registered already.
    Duplicate(Id),
    /// No slot holds this signal.
    Unknown(Id),
    /// The tick is earlier than the slot's last write: a tick from another
    /// boot, or a caller that read the clock before the writer did. Refused
    /// rather than measured, because the duration would be a guess.
    TickBehind(Id),
    /// KM43 refused the sample the slot would make. The store only builds
    /// shapes KM43 accepts, so this is a defect surfaced rather than hidden.
    Quality(QualityError),
}

/// What a slot remembers of its last write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    seen: Observation,
    written: Tick,
    /// When the current unchanged run began.
    run_from: Tick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    sig: Id,
    limits: Limits,
    held: Option<Held>,
}

impl Slot {
    /// The sample this slot publishes at `now`.
    fn sample(&self, now: Tick) -> Result<Sample, SignalError> {
        let Some(held) = self.held else {
            // Registered and never written: the source is up and has not
            // produced a first reading.
            let q = SignalQuality::absent(Validity::Initialising).map_err(SignalError::Quality)?;
            return Sample::new(self.sig, q, None, None).map_err(SignalError::Quality);
        };
        let Some(value) = held.seen.value else {
            return Sample::new(self.sig, held.seen.q, None, None).map_err(SignalError::Quality);
        };
        let since_write = now
            .since(held.written)
            .ok_or(SignalError::TickBehind(self.sig))?;
        let since_change = now
            .since(held.run_from)
            .ok_or(SignalError::TickBehind(self.sig))?;
        let age = if since_write > self.limits.max_age {
            // Silence: the value is as old as its last write.
            Some(since_write)
        } else if self
            .limits
            .max_unchanged
            .is_some_and(|run| since_change > run)
        {
            // A hung instrument: the value is as old as its run.
            Some(since_change)
        } else {
            None
        };
        let provenance = held.seen.q.provenance_of();
        match age {
            None => Sample::new(self.sig, held.seen.q, Some(value), None),
            Some(age) => SignalQuality::carrying(Validity::Stale, provenance)
                .and_then(|q| Sample::new(self.sig, q, Some(value), Some(seconds(age)))),
        }
        .map_err(SignalError::Quality)
    }
}

/// A duration in whole seconds, as KM43's `age` carries it, saturating at
/// the top of a `u32` (136 years) rather than wrapping to a young reading.
fn seconds(age: Millis) -> u32 {
    u32::try_from(age.as_secs()).unwrap_or(u32::MAX)
}

/// The store of signals, `N` slots, kept in ascending signal order so a page
/// of readings is already in P-198's order.
#[derive(Debug, Clone)]
pub struct Signals<const N: usize> {
    slots: [Option<Slot>; N],
    len: usize,
}

impl<const N: usize> Default for Signals<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Signals<N> {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
            len: 0,
        }
    }

    /// How many signals are registered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no signal is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Give `sig` a slot with its `limits`. It reads `initialising` until the
    /// first write.
    ///
    /// Refuses a signal already registered, and refuses any signal once all
    /// `N` slots are taken; nothing is evicted to make room.
    pub fn register(&mut self, sig: Id, limits: Limits) -> Result<(), SignalError> {
        let Err(at) = self.find(sig) else {
            return Err(SignalError::Duplicate(sig));
        };
        if self.len >= N {
            return Err(SignalError::Full);
        }
        let end = self.len;
        let tail = self.slots.get_mut(at..=end).ok_or(SignalError::Full)?;
        tail.rotate_right(1);
        let slot = tail.first_mut().ok_or(SignalError::Full)?;
        *slot = Some(Slot {
            sig,
            limits,
            held: None,
        });
        self.len = end.saturating_add(1);
        Ok(())
    }

    /// Record what `sig`'s source said at `now`.
    ///
    /// The unchanged run restarts when the value or the quality differs from
    /// the last write, and when the last write is older than the channel's
    /// maximum age: a channel coming back from silence starts a new run
    /// rather than continuing the one it left.
    pub fn write(&mut self, sig: Id, now: Tick, seen: Observation) -> Result<(), SignalError> {
        let at = self.find(sig).map_err(|_| SignalError::Unknown(sig))?;
        let slot = self
            .slots
            .get_mut(at)
            .and_then(Option::as_mut)
            .ok_or(SignalError::Unknown(sig))?;
        let run_from = match slot.held {
            None => now,
            Some(held) => {
                let since = now
                    .since(held.written)
                    .ok_or(SignalError::TickBehind(sig))?;
                let silent = since > slot.limits.max_age;
                if silent || held.seen != seen {
                    now
                } else {
                    held.run_from
                }
            }
        };
        slot.held = Some(Held {
            seen,
            written: now,
            run_from,
        });
        Ok(())
    }

    /// What `sig` publishes at `now`: its value and quality, `stale` with its
    /// age once either limit has passed, `initialising` before its first
    /// write.
    pub fn sample(&self, sig: Id, now: Tick) -> Result<Sample, SignalError> {
        self.slot(sig)?.sample(now)
    }

    /// `sig`'s value for a behaviour that acts only on a current reading from
    /// one of `accepts`.
    ///
    /// Refuses no value, a stale value, and a value from a provenance outside
    /// the set, each as itself, so a behaviour can say which it met.
    pub fn current(
        &self,
        sig: Id,
        now: Tick,
        accepts: ProvenanceSet,
    ) -> Result<Eligible, Ineligible> {
        let sample = self.sample(sig, now).map_err(Ineligible::Store)?;
        let validity = sample.q.validity_of();
        let Some(value) = sample.value() else {
            return Err(Ineligible::NoValue(validity));
        };
        let provenance = sample.q.provenance_of();
        match validity {
            Validity::Ok => {}
            Validity::Stale => return Err(Ineligible::Stale(provenance)),
            Validity::Initialising
            | Validity::Unsupported
            | Validity::SensorFault
            | Validity::OutOfRange
            | Validity::Absent
            | Validity::UnnamedState => return Err(Ineligible::NoValue(validity)),
        }
        if !accepts.contains(provenance) {
            return Err(Ineligible::Provenance(provenance));
        }
        Ok(Eligible { value, provenance })
    }

    /// Every signal's sample at `now`, in ascending signal order.
    pub fn samples(&self, now: Tick) -> impl Iterator<Item = Result<Sample, SignalError>> + '_ {
        self.slots
            .iter()
            .take(self.len)
            .flatten()
            .map(move |slot| slot.sample(now))
    }

    fn slot(&self, sig: Id) -> Result<&Slot, SignalError> {
        let at = self.find(sig).map_err(|_| SignalError::Unknown(sig))?;
        self.slots
            .get(at)
            .and_then(Option::as_ref)
            .ok_or(SignalError::Unknown(sig))
    }

    /// Where `sig` is, or where it would go.
    fn find(&self, sig: Id) -> Result<usize, usize> {
        self.slots
            .get(..self.len)
            .unwrap_or(&[])
            .binary_search_by(|slot| slot.as_ref().map(|slot| slot.sig).cmp(&Some(sig)))
    }
}

/// A value a behaviour may act on, with the provenance it was accepted at.
///
/// Only [`Signals::current`] makes one, so holding one is the proof that the
/// store judged it current and from an accepted source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an eligible reading is an input a behaviour was asked to decide on"]
pub struct Eligible {
    value: i32,
    provenance: Provenance,
}

impl Eligible {
    /// The scaled integer, in the metric kind's unit and scale.
    #[must_use]
    pub const fn value(self) -> i32 {
        self.value
    }

    /// Where it came from, one of the provenances the caller accepted.
    #[must_use]
    pub const fn provenance(self) -> Provenance {
        self.provenance
    }
}

/// Why a reading is not one a behaviour may act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an ineligible reading is an input a behaviour must answer for"]
pub enum Ineligible {
    /// There is no value, and this is why.
    NoValue(Validity),
    /// There is a value and it is stale.
    Stale(Provenance),
    /// There is a current value from a provenance the behaviour does not
    /// accept.
    Provenance(Provenance),
    /// The store refused the read.
    Store(SignalError),
}

/// A set of provenances a behaviour will act on.
///
/// A set and never a threshold: KM43's provenance numbers are an allocation
/// order, and `reported` above `estimated` says nothing about trust.
/// [`Provenance::None`] is never a member, because it is what *no value* is
/// spelled as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProvenanceSet(u8);

impl ProvenanceSet {
    /// The set of nothing.
    pub const EMPTY: Self = Self(0);

    /// The set of `members`.
    #[must_use]
    pub const fn of(members: &[Provenance]) -> Self {
        let mut bits = 0u8;
        let mut rest = members;
        while let [member, tail @ ..] = rest {
            bits |= Self::bit(*member);
            rest = tail;
        }
        Self(bits)
    }

    /// Whether `provenance` is in the set.
    #[must_use]
    pub const fn contains(self, provenance: Provenance) -> bool {
        self.0 & Self::bit(provenance) != 0
    }

    const fn bit(provenance: Provenance) -> u8 {
        match provenance {
            Provenance::None => 0,
            Provenance::Measured => 1 << 1,
            Provenance::Counted => 1 << 2,
            Provenance::Derived => 1 << 3,
            Provenance::Estimated => 1 << 4,
            Provenance::Reported => 1 << 5,
            Provenance::Commanded => 1 << 6,
        }
    }
}

/// The generator's charge-source rule: which state of charge autostart may
/// act on.
///
/// A named parameter rather than a flag, because accepting an estimate is a
/// decision somebody makes about their bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChargeSource {
    /// Only a state of charge the source counted: a shunt's, or a BMS's
    /// own. An estimate from terminal voltage is refused.
    CountedOnly,
    /// A counted state of charge, or an estimate somebody has accepted as
    /// one.
    EstimateAccepted,
}

impl ChargeSource {
    /// The provenances this rule acts on.
    #[must_use]
    pub const fn accepts(self) -> ProvenanceSet {
        match self {
            Self::CountedOnly => ProvenanceSet::of(&[Provenance::Counted]),
            Self::EstimateAccepted => {
                ProvenanceSet::of(&[Provenance::Counted, Provenance::Estimated])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(n: u16) -> Id {
        Id::new(n).expect("a non-zero id")
    }

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    fn secs(n: u64) -> Millis {
        Millis::from_secs(n).expect("a representable duration")
    }

    /// A minute's maximum age and, when given, an unchanged-run limit.
    fn limits(run: Option<u64>) -> Limits {
        Limits::new(secs(60), run.map(secs)).expect("non-zero limits")
    }

    fn measured(value: i32) -> Observation {
        Observation::value(value, Provenance::Measured).expect("a measured value")
    }

    fn store_with(run: Option<u64>) -> Signals<4> {
        let mut store = Signals::<4>::new();
        store.register(sig(1), limits(run)).expect("room");
        store
    }

    fn validity(store: &Signals<4>, now: u64) -> Validity {
        store
            .sample(sig(1), at(now))
            .expect("a sample")
            .q
            .validity_of()
    }

    #[test]
    fn a_registered_signal_reads_initialising_with_no_value_before_its_first_write() {
        let store = store_with(None);
        let sample = store.sample(sig(1), at(0)).expect("a sample");
        assert_eq!(sample.q.validity_of(), Validity::Initialising);
        assert_eq!(sample.q.provenance_of(), Provenance::None);
        assert_eq!(sample.value(), None);
    }

    #[test]
    fn a_written_value_publishes_with_its_provenance_and_no_age() {
        let mut store = store_with(None);
        store
            .write(
                sig(1),
                at(0),
                Observation::value(1234, Provenance::Counted).unwrap(),
            )
            .unwrap();
        let sample = store.sample(sig(1), at(1_000)).unwrap();
        assert_eq!(sample.value(), Some(1234));
        assert_eq!(sample.q.validity_of(), Validity::Ok);
        assert_eq!(sample.q.provenance_of(), Provenance::Counted);
        assert_eq!(sample.age(), None);
    }

    #[test]
    fn p_196_absent_never_carries_a_value_or_a_provenance() {
        for validity in [
            Validity::Initialising,
            Validity::Unsupported,
            Validity::SensorFault,
            Validity::OutOfRange,
            Validity::Absent,
            Validity::UnnamedState,
        ] {
            let mut store = store_with(Some(10));
            store.write(sig(1), at(0), measured(215)).unwrap();
            store
                .write(sig(1), at(1_000), Observation::missing(validity).unwrap())
                .unwrap();
            // Long past both limits: a missing reading has nothing to go
            // stale, and the value before it never comes back.
            for now in [1_000, 30_000, 3_600_000] {
                let sample = store.sample(sig(1), at(now)).unwrap();
                assert_eq!(sample.value(), None, "{validity:?} at {now}");
                assert_eq!(sample.q.validity_of(), validity);
                assert_eq!(sample.q.provenance_of(), Provenance::None);
                assert_eq!(sample.age(), None);
            }
        }
    }

    #[test]
    fn p_196_an_observation_refuses_a_value_without_provenance_and_a_missing_value_that_says_ok_or_stale()
     {
        assert_eq!(
            Observation::value(1, Provenance::None),
            Err(QualityError::CarryingWithoutProvenance)
        );
        assert_eq!(
            Observation::missing(Validity::Ok),
            Err(QualityError::ValueOmitted(Validity::Ok))
        );
        // A driver cannot declare its own reading stale.
        assert_eq!(
            Observation::missing(Validity::Stale),
            Err(QualityError::ValueOmitted(Validity::Stale))
        );
    }

    #[test]
    fn a_full_store_refuses_a_new_signal_and_keeps_every_existing_one() {
        let mut store = Signals::<2>::new();
        store.register(sig(5), limits(None)).unwrap();
        store.register(sig(3), limits(None)).unwrap();
        store.write(sig(5), at(0), measured(50)).unwrap();
        store.write(sig(3), at(0), measured(30)).unwrap();

        assert_eq!(store.register(sig(4), limits(None)), Err(SignalError::Full));
        assert_eq!(store.len(), 2);
        assert_eq!(store.sample(sig(5), at(0)).unwrap().value(), Some(50));
        assert_eq!(store.sample(sig(3), at(0)).unwrap().value(), Some(30));
        assert_eq!(
            store.sample(sig(4), at(0)),
            Err(SignalError::Unknown(sig(4)))
        );
    }

    #[test]
    fn a_store_of_no_slots_refuses_the_first_signal() {
        let mut store = Signals::<0>::new();
        assert!(store.is_empty());
        assert_eq!(store.register(sig(1), limits(None)), Err(SignalError::Full));
    }

    #[test]
    fn a_duplicate_registration_and_a_write_to_an_unknown_signal_are_refused() {
        let mut store = store_with(None);
        store.write(sig(1), at(0), measured(7)).unwrap();
        assert_eq!(
            store.register(sig(1), limits(Some(5))),
            Err(SignalError::Duplicate(sig(1)))
        );
        // The first registration and its value survive the refusal.
        assert_eq!(store.sample(sig(1), at(0)).unwrap().value(), Some(7));
        assert_eq!(
            store.write(sig(2), at(0), measured(1)),
            Err(SignalError::Unknown(sig(2)))
        );
    }

    #[test]
    fn samples_come_out_in_ascending_signal_order_whatever_the_registration_order() {
        let mut store = Signals::<4>::new();
        for n in [9, 2, 7, 4] {
            store.register(sig(n), limits(None)).unwrap();
        }
        let order: [u16; 4] = {
            let mut ids = store.samples(at(0)).map(|s| s.unwrap().sig.get());
            core::array::from_fn(|_| ids.next().unwrap())
        };
        assert_eq!(order, [2, 4, 7, 9]);
    }

    #[test]
    fn a_zero_limit_is_refused() {
        assert_eq!(Limits::new(Millis::from_millis(0), None), None);
        assert_eq!(Limits::new(secs(1), Some(Millis::from_millis(0))), None);
        let ok = Limits::new(secs(1), Some(secs(2))).unwrap();
        assert_eq!(ok.max_age(), secs(1));
        assert_eq!(ok.max_unchanged(), Some(secs(2)));
    }

    #[test]
    fn maximum_age_turns_a_silent_slot_stale_after_the_limit_and_not_at_it() {
        let mut store = store_with(None);
        store
            .write(
                sig(1),
                at(0),
                Observation::value(80, Provenance::Counted).unwrap(),
            )
            .unwrap();
        assert_eq!(validity(&store, 60_000), Validity::Ok);
        let stale = store.sample(sig(1), at(60_001)).unwrap();
        assert_eq!(stale.q.validity_of(), Validity::Stale);
        // Counted and stale is sayable: the provenance survives.
        assert_eq!(stale.q.provenance_of(), Provenance::Counted);
        assert_eq!(stale.value(), Some(80));
        assert_eq!(stale.age(), Some(60));
    }

    #[test]
    fn maximum_unchanged_run_turns_a_hung_instrument_stale_while_it_keeps_answering() {
        let mut store = store_with(Some(10));
        for second in 0..=10 {
            store
                .write(sig(1), at(second * 1_000), measured(215))
                .unwrap();
        }
        assert_eq!(validity(&store, 10_000), Validity::Ok);
        store.write(sig(1), at(11_000), measured(215)).unwrap();
        let stale = store.sample(sig(1), at(11_000)).unwrap();
        assert_eq!(stale.q.validity_of(), Validity::Stale);
        assert_eq!(stale.q.provenance_of(), Provenance::Measured);
        // As old as the run, though written this instant.
        assert_eq!(stale.age(), Some(11));
    }

    #[test]
    fn a_channel_with_no_unchanged_run_limit_never_goes_stale_for_holding_still() {
        let mut store = store_with(None);
        for minute in 0..=60 * 24 * 7 {
            store
                .write(sig(1), at(minute * 60_000), measured(1))
                .unwrap();
        }
        assert_eq!(validity(&store, 60 * 24 * 7 * 60_000), Validity::Ok);
    }

    #[test]
    fn a_changed_value_restarts_the_unchanged_run() {
        let mut store = store_with(Some(10));
        store.write(sig(1), at(0), measured(215)).unwrap();
        store.write(sig(1), at(9_000), measured(216)).unwrap();
        store.write(sig(1), at(18_000), measured(216)).unwrap();
        assert_eq!(validity(&store, 19_000), Validity::Ok);
        assert_eq!(validity(&store, 19_001), Validity::Stale);
    }

    #[test]
    fn a_changed_quality_restarts_the_unchanged_run() {
        let mut store = store_with(Some(10));
        store.write(sig(1), at(0), measured(215)).unwrap();
        // The same number from another source is another reading.
        store
            .write(
                sig(1),
                at(9_000),
                Observation::value(215, Provenance::Estimated).unwrap(),
            )
            .unwrap();
        store
            .write(
                sig(1),
                at(18_000),
                Observation::value(215, Provenance::Estimated).unwrap(),
            )
            .unwrap();
        assert_eq!(validity(&store, 19_000), Validity::Ok);
        assert_eq!(validity(&store, 19_001), Validity::Stale);

        // A fault between two equal values restarts it too.
        let mut store = store_with(Some(10));
        store.write(sig(1), at(0), measured(215)).unwrap();
        store
            .write(
                sig(1),
                at(5_000),
                Observation::missing(Validity::SensorFault).unwrap(),
            )
            .unwrap();
        store.write(sig(1), at(9_000), measured(215)).unwrap();
        assert_eq!(validity(&store, 19_000), Validity::Ok);
        assert_eq!(validity(&store, 19_001), Validity::Stale);
    }

    #[test]
    fn a_channel_back_from_silence_starts_a_new_run_rather_than_continuing_the_old_one() {
        let mut store = store_with(Some(90));
        store.write(sig(1), at(0), measured(215)).unwrap();
        store.write(sig(1), at(30_000), measured(215)).unwrap();
        // Silent from 30 s to 100 s, past the minute's maximum age.
        assert_eq!(validity(&store, 100_000), Validity::Stale);
        store.write(sig(1), at(100_000), measured(215)).unwrap();
        // Continuing the old run would be 100 s unchanged and stale; the
        // new one is a second old.
        assert_eq!(validity(&store, 101_000), Validity::Ok);
        for now in [130_000, 160_000, 190_000] {
            store.write(sig(1), at(now), measured(215)).unwrap();
        }
        assert_eq!(validity(&store, 190_000), Validity::Ok);
        assert_eq!(validity(&store, 190_001), Validity::Stale);
    }

    #[test]
    fn a_write_at_exactly_the_maximum_age_continues_the_run() {
        let mut store = store_with(Some(90));
        store.write(sig(1), at(0), measured(215)).unwrap();
        store.write(sig(1), at(60_000), measured(215)).unwrap();
        assert_eq!(validity(&store, 90_000), Validity::Ok);
        assert_eq!(validity(&store, 90_001), Validity::Stale);
    }

    #[test]
    fn a_tick_behind_the_last_write_is_refused_for_writes_and_reads() {
        let mut store = store_with(None);
        store.write(sig(1), at(5_000), measured(1)).unwrap();
        assert_eq!(
            store.write(sig(1), at(4_999), measured(2)),
            Err(SignalError::TickBehind(sig(1)))
        );
        assert_eq!(
            store.sample(sig(1), at(4_999)),
            Err(SignalError::TickBehind(sig(1)))
        );
        // The refused write left the value it would have replaced.
        assert_eq!(store.sample(sig(1), at(5_000)).unwrap().value(), Some(1));
    }

    #[test]
    fn a_stale_age_saturates_rather_than_wrapping() {
        assert_eq!(seconds(Millis::from_millis(u64::MAX)), u32::MAX);
        assert_eq!(seconds(Millis::from_millis(1_999)), 1);
    }

    #[test]
    fn current_refuses_no_value_stale_and_an_unaccepted_provenance_each_as_itself() {
        let every = ProvenanceSet::of(&[Provenance::Measured]);
        let mut store = store_with(None);
        assert_eq!(
            store.current(sig(1), at(0), every),
            Err(Ineligible::NoValue(Validity::Initialising))
        );
        store.write(sig(1), at(0), measured(5)).unwrap();
        assert_eq!(
            store.current(sig(1), at(0), every),
            Ok(Eligible {
                value: 5,
                provenance: Provenance::Measured
            })
        );
        assert_eq!(
            store.current(sig(1), at(60_001), every),
            Err(Ineligible::Stale(Provenance::Measured))
        );
        assert_eq!(
            store.current(sig(1), at(0), ProvenanceSet::EMPTY),
            Err(Ineligible::Provenance(Provenance::Measured))
        );
        assert_eq!(
            store.current(sig(2), at(0), every),
            Err(Ineligible::Store(SignalError::Unknown(sig(2))))
        );
    }

    #[test]
    fn f_052_counted_only_refuses_an_estimated_state_of_charge_and_accepts_a_counted_one() {
        let mut store = store_with(None);
        store
            .write(
                sig(1),
                at(0),
                Observation::value(640, Provenance::Estimated).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.current(sig(1), at(0), ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Provenance(Provenance::Estimated))
        );
        assert_eq!(
            store.current(sig(1), at(0), ChargeSource::EstimateAccepted.accepts()),
            Ok(Eligible {
                value: 640,
                provenance: Provenance::Estimated
            })
        );

        store
            .write(
                sig(1),
                at(1_000),
                Observation::value(655, Provenance::Counted).unwrap(),
            )
            .unwrap();
        for rule in [ChargeSource::CountedOnly, ChargeSource::EstimateAccepted] {
            assert_eq!(
                store.current(sig(1), at(1_000), rule.accepts()),
                Ok(Eligible {
                    value: 655,
                    provenance: Provenance::Counted
                })
            );
        }
        // Counted is still subject to the other guards: stale is refused.
        assert_eq!(
            store.current(sig(1), at(61_001), ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Stale(Provenance::Counted))
        );
    }

    #[test]
    fn a_provenance_set_is_a_set_and_not_a_threshold() {
        let reported = ProvenanceSet::of(&[Provenance::Reported]);
        // Reported sits above estimated in allocation order and says nothing
        // about it.
        assert!(reported.contains(Provenance::Reported));
        assert!(!reported.contains(Provenance::Estimated));
        assert!(!reported.contains(Provenance::Measured));
        // None is never a member, even when asked for.
        assert!(!ProvenanceSet::of(&[Provenance::None]).contains(Provenance::None));
        let all = ProvenanceSet::of(&[
            Provenance::Measured,
            Provenance::Counted,
            Provenance::Derived,
            Provenance::Estimated,
            Provenance::Reported,
            Provenance::Commanded,
        ]);
        assert!(!all.contains(Provenance::None));
        assert!(!ProvenanceSet::EMPTY.contains(Provenance::Measured));
    }
}
