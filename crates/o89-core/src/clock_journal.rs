//! The calendar's retained audit: five backup words, with the marker committed
//! last. A reset before that marker leaves the clock unknown; a reset after it
//! recovers the exact old/new values without applying the calendar again.
//!
//! cites: P-111, P-267

use km43::TimeSource;

use crate::{Calendar, ClockChange, UnixMillis};

/// One marker/fraction word and two words for each timestamp; no spare slots.
pub const CLOCK_BACKUP_WORDS: usize = 5;
const CLEAN: u32 = 0x8934_0000;
/// A change owed to the log, one marker per source, so a reset cannot
/// turn a client's write into NTP's (P-111).
const PENDING: u32 = 0x8935_0000;
const PENDING_CLIENT: u32 = 0x8937_0000;
const FRACTION: u32 = 0x0000_FFFF;

/// Calendar and retained-word operations supplied by the adapter.
pub trait CalendarStore {
    /// Calendar-write failure reported by the device.
    type Error;
    /// Read one retained word, or `None` when the index is unavailable.
    fn read_word(&self, index: usize) -> Option<u32>;
    /// Write a retained word. The journal verifies every write by reading it.
    fn write_word(&mut self, index: usize, value: u32);
    /// Set the calendar's whole seconds; the journal retains its fraction.
    /// An error means the calendar was not changed: the journal puts the
    /// clock it had back on the strength of it (P-267 rule 1).
    fn set_calendar(&mut self, at: UnixMillis) -> Result<(), Self::Error>;
}

/// A change not committed, with the reason preserved.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JournalError<E> {
    /// An earlier applied change still needs its audit record.
    Pending,
    /// The date is outside the calendar's century or cannot be represented.
    InvalidDate,
    /// A retained write did not read back exactly.
    Verify,
    /// The calendar refused the write.
    Calendar(E),
}

/// At most one applied change awaits its log record. New writes refuse while
/// it is pending; neither a link reset nor a failed append may evict it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockJournal {
    fraction: Option<u32>,
    pending: Option<ClockChange>,
    unretained: bool,
}

impl ClockJournal {
    /// No trustworthy calendar marker.
    pub const UNKNOWN: Self = Self {
        fraction: None,
        pending: None,
        unretained: false,
    };

    /// Recover only a complete marker and, when pending, valid timestamps.
    #[must_use]
    pub fn load(store: &impl CalendarStore) -> Self {
        Self::decode(store).unwrap_or(Self::UNKNOWN)
    }

    fn decode(store: &impl CalendarStore) -> Option<Self> {
        let word = store.read_word(0)?;
        let fraction = word & FRACTION;
        if fraction >= 1_000 {
            return None;
        }
        let source = match word & !FRACTION {
            CLEAN => None,
            PENDING => Some(TimeSource::NtpViaComms),
            PENDING_CLIENT => Some(TimeSource::Client),
            _ => return None,
        };
        let pending = match source {
            None => None,
            Some(source) => {
                let old = read_time(store, 1, 2)?;
                let new = UnixMillis::new(read_time(store, 3, 4)?)?;
                Calendar::from_unix(new)?;
                if new.as_millis().checked_rem(1_000)? != u64::from(fraction) {
                    return None;
                }
                let old = UnixMillis::new(old);
                if let Some(old) = old {
                    Calendar::from_unix(old)?;
                }
                Some(ClockChange::recovered(old, new, source))
            }
        };
        Some(Self {
            fraction: Some(fraction),
            pending,
            unretained: false,
        })
    }

    /// Fraction added to the hardware's whole-second set, absent when unknown.
    #[must_use]
    pub const fn fraction(self) -> Option<u32> {
        self.fraction
    }

    /// The applied change still owed to the log.
    #[must_use]
    pub const fn pending(self) -> Option<ClockChange> {
        self.pending
    }

    /// Whether the change owed to the log is held by this boot alone, its
    /// marker not read back: a reset before its record lands finds no clock
    /// and owes nothing.
    #[must_use]
    pub const fn unretained(self) -> bool {
        self.unretained
    }

    /// Invalidate, retain both timestamps, set the calendar, then commit the
    /// pending marker. Every retained write is verified. A cut leaves either
    /// the old valid state, an unknown clock, or the new recoverable audit.
    ///
    /// A write the calendar did not take spends nothing: the journal goes
    /// back to the clock it had, still known, and the error is returned
    /// (P-267 rule 1). Once the calendar has taken the time the change
    /// stands, and a marker that does not read back still returns `Ok`
    /// with the change pending here, so its record is owed and no other
    /// change applies before it lands (P-267 rule 2). Until
    /// [`recorded`](Self::recorded) commits the new clock, a reset finds
    /// it unknown, as one at the same step would.
    pub fn apply<S: CalendarStore>(
        &mut self,
        store: &mut S,
        change: ClockChange,
    ) -> Result<(), JournalError<S::Error>> {
        if self.pending.is_some() {
            return Err(JournalError::Pending);
        }
        let at = change.new_value();
        if Calendar::from_unix(at).is_none() {
            return Err(JournalError::InvalidDate);
        }
        let fraction = u32::try_from(
            at.as_millis()
                .checked_rem(1_000)
                .ok_or(JournalError::InvalidDate)?,
        )
        .map_err(|_| JournalError::InvalidDate)?;
        if let Err(error) = Self::set(store, change, at) {
            self.restore(store);
            return Err(error);
        }
        let marker = match change.source() {
            TimeSource::NtpViaComms => PENDING,
            TimeSource::Client => PENDING_CLIENT,
        };
        // The calendar moved: a marker that did not read back leaves the
        // record owed, not the write undone.
        *self = Self {
            fraction: Some(fraction),
            pending: Some(change),
            unretained: put(store, 0, marker | fraction).is_err(),
        };
        Ok(())
    }

    /// Everything up to and including the calendar write.
    fn set<S: CalendarStore>(
        store: &mut S,
        change: ClockChange,
        at: UnixMillis,
    ) -> Result<(), JournalError<S::Error>> {
        put(store, 0, 0)?;
        let old = change.old().map_or(0, UnixMillis::as_millis);
        write_time(store, 1, 2, old)?;
        write_time(store, 3, 4, at.as_millis())?;
        store.set_calendar(at).map_err(JournalError::Calendar)
    }

    /// Put back the clean marker for the clock held before a write the
    /// calendar did not take. A marker that does not read back leaves the
    /// clock unknown, as a reset would find it.
    fn restore<S: CalendarStore>(&mut self, store: &mut S) {
        let Some(fraction) = self.fraction else {
            return;
        };
        if put(store, 0, CLEAN | fraction).is_err() {
            *self = Self::UNKNOWN;
        }
    }

    /// Clear the pending marker only after the log append succeeded. A cut
    /// between append and acknowledgement can repeat the record after reset,
    /// but never loses it or applies the clock a second time.
    ///
    /// An unretained change has no marker a reset could repeat the record
    /// from, so the record that landed ends it even when the clean marker
    /// does not read back either.
    pub fn recorded<S: CalendarStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), JournalError<S::Error>> {
        let fraction = self.fraction.ok_or(JournalError::InvalidDate)?;
        let cleaned = put(store, 0, CLEAN | fraction);
        if !self.unretained {
            cleaned?;
        }
        self.pending = None;
        self.unretained = false;
        Ok(())
    }
}

fn put<S: CalendarStore>(
    store: &mut S,
    index: usize,
    value: u32,
) -> Result<(), JournalError<S::Error>> {
    store.write_word(index, value);
    if store.read_word(index) == Some(value) {
        Ok(())
    } else {
        Err(JournalError::Verify)
    }
}

fn read_time(store: &impl CalendarStore, low: usize, high: usize) -> Option<u64> {
    u64::from(store.read_word(high)?)
        .checked_shl(32)?
        .checked_add(u64::from(store.read_word(low)?))
}

fn write_time<S: CalendarStore>(
    store: &mut S,
    low: usize,
    high: usize,
    at: u64,
) -> Result<(), JournalError<S::Error>> {
    let lo = u32::try_from(at & u64::from(u32::MAX)).map_err(|_| JournalError::InvalidDate)?;
    let hi = u32::try_from(at.checked_shr(32).ok_or(JournalError::InvalidDate)?)
        .map_err(|_| JournalError::InvalidDate)?;
    put(store, low, lo)?;
    put(store, high, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Part {
        words: [u32; CLOCK_BACKUP_WORDS],
        calendar: Option<UnixMillis>,
        writes: usize,
        /// Power lost at this step: it and every later one do not happen.
        cut: usize,
        /// This one step fails, a word reading back other than written,
        /// and the part carries on.
        fail: Option<usize>,
        sets: usize,
    }
    impl Part {
        fn new(cut: usize) -> Self {
            Self {
                words: [0; CLOCK_BACKUP_WORDS],
                calendar: None,
                writes: 0,
                cut,
                fail: None,
                sets: 0,
            }
        }
        fn step(&mut self) -> bool {
            let before = self.writes;
            self.writes = self.writes.saturating_add(1);
            before < self.cut && self.fail != Some(before)
        }
    }
    impl CalendarStore for Part {
        type Error = ();
        fn read_word(&self, index: usize) -> Option<u32> {
            self.words.get(index).copied()
        }
        fn write_word(&mut self, index: usize, value: u32) {
            let step = self.writes;
            if self.step() {
                self.words[index] = value;
            } else if self.fail == Some(step) {
                self.words[index] = !value;
            }
        }
        fn set_calendar(&mut self, at: UnixMillis) -> Result<(), ()> {
            if !self.step() {
                return Err(());
            }
            self.calendar = Some(at);
            self.sets = self.sets.saturating_add(1);
            Ok(())
        }
    }
    fn change() -> ClockChange {
        ClockChange::recovered(
            UnixMillis::new(1_800_000_000_000),
            UnixMillis::new(1_800_000_001_123).unwrap(),
            TimeSource::NtpViaComms,
        )
    }

    /// Steps in a write that lands: the invalidation, four timestamp
    /// words, the calendar, then the marker.
    const CALENDAR_STEP: usize = 5;
    const MARKER_STEP: usize = 6;
    const WRITE_STEPS: usize = 7;
    /// The fraction of the clock a part holds before `change()`.
    const KEPT_FRACTION: u32 = 456;

    /// A part whose clock was never set, its marker neither clean nor
    /// pending, or one known at `KEPT_FRACTION` with its record landed.
    fn part(known: bool) -> (Part, ClockJournal) {
        let mut part = Part::new(usize::MAX);
        let mut journal = ClockJournal::UNKNOWN;
        if known {
            let first = ClockChange::recovered(
                None,
                UnixMillis::new(1_799_999_999_456).unwrap(),
                TimeSource::Client,
            );
            journal
                .apply(&mut part, first)
                .expect("the part takes the first set");
            journal.recorded(&mut part).expect("its record lands");
            assert_eq!(journal.fraction(), Some(KEPT_FRACTION));
        } else {
            part.words[0] = u32::MAX;
        }
        assert_eq!(ClockJournal::load(&part), journal);
        (part, journal)
    }

    /// A reset at every step of a write, from a clock never set and from
    /// one known. Either the calendar kept its time, the write is an error
    /// the controller answers busy, and a reboot finds the old clock or
    /// none; or the calendar took the new time, the change stands, and a
    /// reboot finds it owed to the log or no clock at all. Never a moved
    /// calendar under a clean marker: that is a change whose record is
    /// lost (P-267).
    #[test]
    fn p_267_a_reset_at_every_step_keeps_the_old_clock_or_owes_the_change() {
        for known in [false, true] {
            for step in 0..=WRITE_STEPS {
                let (mut part, mut journal) = part(known);
                let before = journal;
                let sets = part.sets;
                part.cut = part.writes.saturating_add(step);
                let result = journal.apply(&mut part, change());
                let rebooted = ClockJournal::load(&part);
                if part.sets > sets {
                    assert_eq!(result, Ok(()), "known {known} step {step}");
                    assert_eq!(
                        journal.pending(),
                        Some(change()),
                        "known {known} step {step}"
                    );
                    assert_eq!(part.calendar, Some(change().new_value()));
                    assert!(
                        rebooted == ClockJournal::UNKNOWN
                            || (rebooted.pending() == Some(change())
                                && rebooted.fraction() == Some(123)),
                        "known {known} step {step}: {rebooted:?}"
                    );
                } else {
                    assert!(result.is_err(), "known {known} step {step}");
                    assert!(
                        journal == before || journal == ClockJournal::UNKNOWN,
                        "known {known} step {step}: {journal:?}"
                    );
                    assert!(
                        rebooted == before || rebooted == ClockJournal::UNKNOWN,
                        "known {known} step {step}: {rebooted:?}"
                    );
                }
                if step == WRITE_STEPS {
                    assert_eq!(rebooted.pending(), Some(change()), "known {known}");
                }
            }
        }
    }

    /// A write the RTC did not take, whichever step before it failed,
    /// spends nothing: the clock stays known at its old fraction, now and
    /// across a reset, a clock never set stays unknown rather than taking
    /// a default, and the same change lands on the next try (P-267 rule 1).
    #[test]
    fn p_267_a_write_the_rtc_did_not_take_keeps_the_clock_it_had() {
        for known in [true, false] {
            for step in 0..=CALENDAR_STEP {
                let (mut part, mut journal) = part(known);
                let before = journal;
                let sets = part.sets;
                part.fail = Some(part.writes.saturating_add(step));
                let failed = if step == CALENDAR_STEP {
                    JournalError::Calendar(())
                } else {
                    JournalError::Verify
                };
                assert_eq!(
                    journal.apply(&mut part, change()),
                    Err(failed),
                    "known {known} step {step}"
                );
                assert_eq!(journal, before, "known {known} step {step}");
                assert_eq!(
                    ClockJournal::load(&part),
                    before,
                    "known {known} step {step}"
                );
                assert_eq!(part.sets, sets, "known {known} step {step}");
                assert_eq!(journal.apply(&mut part, change()), Ok(()));
                assert_eq!(ClockJournal::load(&part).pending(), Some(change()));
            }
        }
    }

    /// The RTC took the time and the marker did not read back: the change
    /// stands and its record is owed (P-267 rule 2). The journal holds it,
    /// so no other change lands first, and the record's acknowledgement
    /// commits the new clock. Until then only this boot holds it: a reset
    /// finds no clock, as a reset at the same step would.
    #[test]
    fn p_267_a_marker_that_does_not_read_back_after_the_rtc_took_the_time_owes_the_record() {
        for known in [true, false] {
            let (mut part, mut journal) = part(known);
            part.fail = Some(part.writes.saturating_add(MARKER_STEP));
            assert_eq!(journal.apply(&mut part, change()), Ok(()), "known {known}");
            assert_eq!(part.calendar, Some(change().new_value()));
            assert_eq!(journal.pending(), Some(change()));
            assert_eq!(journal.fraction(), Some(123));
            assert!(journal.unretained());
            assert_eq!(ClockJournal::load(&part), ClockJournal::UNKNOWN);
            let sets = part.sets;
            assert_eq!(
                journal.apply(&mut part, change()),
                Err(JournalError::Pending)
            );
            assert_eq!(part.sets, sets);
            journal
                .recorded(&mut part)
                .expect("the acknowledgement lands");
            let rebooted = ClockJournal::load(&part);
            assert_eq!(rebooted.pending(), None);
            assert_eq!(rebooted.fraction(), Some(123));
        }
    }

    /// A reset between applying a client's set and its record landing must
    /// not turn the client's write into NTP's when the boot finishes the
    /// record: the source is fixed by which message moved the clock (P-111).
    #[test]
    fn p_111_a_change_owed_to_the_log_keeps_its_source_across_a_reset() {
        for source in [TimeSource::Client, TimeSource::NtpViaComms] {
            let change = ClockChange::recovered(
                UnixMillis::new(1_800_000_000_000),
                UnixMillis::new(1_800_000_001_123).unwrap(),
                source,
            );
            // Every cut: unknown, or the change with its own source.
            for cut in 0..=7 {
                let mut part = Part::new(cut);
                let mut journal = ClockJournal::UNKNOWN;
                let result = journal.apply(&mut part, change);
                let rebooted = ClockJournal::load(&part);
                if let Some(pending) = rebooted.pending() {
                    assert_eq!(result, Ok(()), "{source:?} cut {cut}");
                    assert_eq!(pending, change, "{source:?} cut {cut}");
                    assert_eq!(
                        pending.record(),
                        km43::ControllerRecord::TimeSet {
                            old: Some(1_800_000_000_000),
                            new: 1_800_000_001_123,
                            source,
                        }
                    );
                } else {
                    assert_eq!(rebooted, ClockJournal::UNKNOWN, "{source:?} cut {cut}");
                }
                if cut == 7 {
                    assert_eq!(rebooted.pending(), Some(change), "{source:?}");
                }
            }
        }
    }

    /// The retained words stop taking writes once the RTC has taken the
    /// time and stay that way. The record that lands meets the change's
    /// obligation although no clean marker reads back: nothing retained
    /// could repeat it after a reset, so holding the change owed would
    /// only append the same record again every retry (P-267 rule 2).
    #[test]
    fn p_267_a_record_landed_under_a_lasting_fault_ends_the_owed_change() {
        for known in [true, false] {
            let (mut part, mut journal) = part(known);
            part.cut = part.writes.saturating_add(MARKER_STEP);
            assert_eq!(journal.apply(&mut part, change()), Ok(()), "known {known}");
            assert!(journal.unretained());
            assert_eq!(journal.recorded(&mut part), Ok(()), "known {known}");
            assert_eq!(journal.pending(), None);
            assert!(!journal.unretained());
            assert_eq!(journal.fraction(), Some(123));
            assert_eq!(ClockJournal::load(&part), ClockJournal::UNKNOWN);
        }
    }

    #[test]
    fn failed_append_and_reset_keep_original_audit_without_reapplying_calendar() {
        let mut part = Part::new(usize::MAX);
        let mut journal = ClockJournal::UNKNOWN;
        journal.apply(&mut part, change()).unwrap();
        // No recorded() after a failed NOR append. A new boot reads this.
        let mut rebooted = ClockJournal::load(&part);
        assert_eq!(rebooted.pending(), Some(change()));
        assert_eq!(
            rebooted.apply(&mut part, change()),
            Err(JournalError::Pending)
        );
        assert_eq!(part.sets, 1);
        part.cut = part.writes;
        assert_eq!(rebooted.recorded(&mut part), Err(JournalError::Verify));
        assert_eq!(ClockJournal::load(&part).pending(), Some(change()));
        part.cut = usize::MAX;
        rebooted.recorded(&mut part).unwrap();
        assert_eq!(ClockJournal::load(&part).pending(), None);
        assert_eq!(ClockJournal::load(&part).fraction(), Some(123));
        assert_eq!(part.sets, 1);
    }

    #[test]
    fn first_set_has_no_old_value_and_corrupt_metadata_is_unknown() {
        let mut part = Part::new(usize::MAX);
        let first = ClockChange::recovered(None, change().new_value(), TimeSource::NtpViaComms);
        let mut journal = ClockJournal::UNKNOWN;
        journal.apply(&mut part, first).unwrap();
        assert_eq!(ClockJournal::load(&part).pending(), Some(first));
        for marker in [0, CLEAN | 0x03E8, PENDING | 0x007A, 0x8936_0000] {
            part.words[0] = marker;
            assert_eq!(ClockJournal::load(&part), ClockJournal::UNKNOWN);
        }
    }

    #[test]
    fn failed_invalidation_preserves_previous_valid_clock() {
        let mut part = Part::new(usize::MAX);
        let mut journal = ClockJournal::UNKNOWN;
        journal.apply(&mut part, change()).unwrap();
        journal.recorded(&mut part).unwrap();
        part.cut = part.writes;
        assert_eq!(
            journal.apply(&mut part, change()),
            Err(JournalError::Verify)
        );
        assert_eq!(ClockJournal::load(&part).fraction(), Some(123));
        assert_eq!(part.sets, 1);
    }
}
