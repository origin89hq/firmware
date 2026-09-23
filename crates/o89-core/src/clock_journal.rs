//! The calendar's retained audit: five backup words, with the marker committed
//! last. A reset before that marker leaves the clock unknown; a reset after it
//! recovers the exact old/new values without applying the calendar again.

use crate::{Calendar, ClockChange, UnixMillis};

/// One marker/fraction word and two words for each timestamp; no spare slots.
pub const CLOCK_BACKUP_WORDS: usize = 5;
const CLEAN: u32 = 0x8934_0000;
const PENDING: u32 = 0x8935_0000;
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
}

impl ClockJournal {
    /// No trustworthy calendar marker.
    pub const UNKNOWN: Self = Self {
        fraction: None,
        pending: None,
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
        let pending = match word & !FRACTION {
            CLEAN => None,
            PENDING => {
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
                Some(ClockChange::recovered(old, new))
            }
            _ => return None,
        };
        Some(Self {
            fraction: Some(fraction),
            pending,
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

    /// Invalidate, retain both timestamps, set the calendar, then commit the
    /// pending marker. Every retained write is verified. A cut leaves either
    /// the old valid state, an unknown clock, or the new recoverable audit.
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
        put(store, 0, 0)?;
        *self = Self::UNKNOWN;
        let old = change.old().map_or(0, UnixMillis::as_millis);
        write_time(store, 1, 2, old)?;
        write_time(store, 3, 4, at.as_millis())?;
        store.set_calendar(at).map_err(JournalError::Calendar)?;
        put(store, 0, PENDING | fraction)?;
        *self = Self {
            fraction: Some(fraction),
            pending: Some(change),
        };
        Ok(())
    }

    /// Clear the pending marker only after the log append succeeded. A cut
    /// between append and acknowledgement can repeat the record after reset,
    /// but never loses it or applies the clock a second time.
    pub fn recorded<S: CalendarStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), JournalError<S::Error>> {
        let fraction = self.fraction.ok_or(JournalError::InvalidDate)?;
        put(store, 0, CLEAN | fraction)?;
        self.pending = None;
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
        cut: usize,
        sets: usize,
    }
    impl Part {
        fn new(cut: usize) -> Self {
            Self {
                words: [0; CLOCK_BACKUP_WORDS],
                calendar: None,
                writes: 0,
                cut,
                sets: 0,
            }
        }
        fn step(&mut self) -> bool {
            let before = self.writes;
            self.writes = self.writes.saturating_add(1);
            before < self.cut
        }
    }
    impl CalendarStore for Part {
        type Error = ();
        fn read_word(&self, index: usize) -> Option<u32> {
            self.words.get(index).copied()
        }
        fn write_word(&mut self, index: usize, value: u32) {
            if self.step() {
                self.words[index] = value;
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
        )
    }

    #[test]
    fn every_cut_before_commit_leaves_unknown_or_recoverable_audit() {
        for cut in 0..=7 {
            let mut part = Part::new(cut);
            let mut journal = ClockJournal::UNKNOWN;
            let result = journal.apply(&mut part, change());
            let recovered = ClockJournal::load(&part);
            if cut == 7 {
                assert_eq!(result, Ok(()));
                assert_eq!(recovered.pending(), Some(change()));
                assert_eq!(recovered.fraction(), Some(123));
                assert_eq!(part.calendar, Some(change().new_value()));
            } else {
                assert!(result.is_err());
                assert_eq!(recovered, ClockJournal::UNKNOWN);
            }
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
        let first = ClockChange::recovered(None, change().new_value());
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
