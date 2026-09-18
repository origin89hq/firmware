//! The global byte budget on the event log: a rolling 24-hour write-volume
//! counter, compared on every append.
//!
//! A per-channel rate cap does not bound the ring: forty-eight channels at
//! one event a minute is 3.9 MiB a day, which empties it in under four
//! days. What protects the ring is this counter against a configured target
//! of 85 KiB a day: past it, class B is dropped first and counted; past it
//! on class A alone, the record is still appended and a concern is raised,
//! because a site producing that many state changes has something wrong
//! with it (F-024).
//!
//! The window is on the wall clock, and that is a deliberate exception to
//! P-004: the counter must survive a reboot to mean anything, the tick does
//! not, and a day's byte budget is a retention control rather than a bound
//! anybody's safety rests on. A clock moved back reopens the window, which
//! under-counts by at most one day's budget. With no clock set the window
//! cannot be placed and the count keeps accumulating until one is, which
//! is the cautious direction.
//!
//! cites: F-024

use crate::body::{Body, Malformed, Reader, Writer};
use crate::tick::{Millis, UnixMillis};

/// The bytes the counter takes in its record.
pub const WRITE_VOLUME_BYTES: usize = 16;

/// The window: one day.
pub const BUDGET_WINDOW: Millis = Millis::from_millis(24 * 60 * 60 * 1_000);

/// The record class, as the ring distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Class {
    /// Durable: state changes, commands and outcomes, alarms, boot records.
    A,
    /// Droppable: periodic aggregates, diagnostics, telemetry.
    B,
}

/// What the budget says about an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a budget consulted and not obeyed is a ring that fills anyway"]
pub enum Budget {
    /// Inside the target: append.
    Append,
    /// Past the target and class B: drop it; the counter counted it.
    Drop,
    /// Past the target on class A: append it anyway, and raise the
    /// concern.
    AppendAndRaise,
}

/// The bytes written inside the current window, and what was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WriteVolume {
    opened: Option<UnixMillis>,
    bytes: u32,
    dropped: u32,
}

impl Default for WriteVolume {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl WriteVolume {
    /// Nothing written, no window placed.
    pub const EMPTY: Self = Self {
        opened: None,
        bytes: 0,
        dropped: 0,
    };

    /// When the window opened, if a clock has placed it.
    #[must_use]
    pub const fn opened(&self) -> Option<UnixMillis> {
        self.opened
    }

    /// The bytes appended inside the window.
    #[must_use]
    pub const fn bytes(&self) -> u32 {
        self.bytes
    }

    /// The class B records dropped inside the window.
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Ask the budget about a record of `bytes` in `class`, at `now` if a
    /// clock is set, against `target` bytes a day, and count it either
    /// way. The record's bytes are the framed bytes the ring would write.
    pub fn append(
        &mut self,
        now: Option<UnixMillis>,
        class: Class,
        bytes: u32,
        target: u32,
    ) -> Budget {
        self.roll(now);
        let after = self.bytes.saturating_add(bytes);
        if after <= target {
            self.bytes = after;
            return Budget::Append;
        }
        match class {
            Class::A => {
                self.bytes = after;
                Budget::AppendAndRaise
            }
            Class::B => {
                self.dropped = self.dropped.saturating_add(1);
                Budget::Drop
            }
        }
    }

    /// Reopen the window when a day has passed, the clock went backwards,
    /// or a clock has appeared where there was none.
    fn roll(&mut self, now: Option<UnixMillis>) {
        let Some(now) = now else {
            return;
        };
        let stale = match self.opened {
            None => true,
            Some(opened) => now.since(opened).is_none_or(|since| since >= BUDGET_WINDOW),
        };
        if stale {
            *self = Self {
                opened: Some(now),
                bytes: 0,
                dropped: 0,
            };
        }
    }
}

impl Body<WRITE_VOLUME_BYTES> for WriteVolume {
    fn encode(&self) -> [u8; WRITE_VOLUME_BYTES] {
        let mut out = [0u8; WRITE_VOLUME_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.u64(self.opened.map_or(0, UnixMillis::as_millis));
        writer.u32(self.bytes);
        writer.u32(self.dropped);
        out
    }

    fn decode(bytes: &[u8; WRITE_VOLUME_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let opened = UnixMillis::new(reader.u64()?);
        let bytes = reader.u32()?;
        let dropped = reader.u32()?;
        Ok(Self {
            opened,
            bytes,
            dropped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: u32 = 85 * 1024;

    fn at(ms: u64) -> Option<UnixMillis> {
        UnixMillis::new(ms)
    }

    #[test]
    fn f_024_class_b_is_dropped_first_and_counted_and_class_a_over_budget_is_appended_and_raised() {
        let mut volume = WriteVolume::EMPTY;
        let clock = at(1_790_000_000_000);
        assert_eq!(
            volume.append(clock, Class::B, TARGET - 10, TARGET),
            Budget::Append
        );
        assert_eq!(volume.append(clock, Class::B, 11, TARGET), Budget::Drop);
        assert_eq!(volume.dropped(), 1);
        assert_eq!(volume.bytes(), TARGET - 10);
        assert_eq!(
            volume.append(clock, Class::A, 11, TARGET),
            Budget::AppendAndRaise
        );
        assert_eq!(volume.bytes(), TARGET + 1);
        // Exactly at the target is inside it.
        let mut exact = WriteVolume::EMPTY;
        assert_eq!(
            exact.append(clock, Class::A, TARGET, TARGET),
            Budget::Append
        );
    }

    #[test]
    fn f_024_the_window_rolls_after_a_day_and_when_the_clock_moves_back() {
        let mut volume = WriteVolume::EMPTY;
        let opened = 1_790_000_000_000;
        assert_eq!(
            volume.append(at(opened), Class::A, TARGET, TARGET),
            Budget::Append
        );
        assert_eq!(
            volume.append(
                at(opened + BUDGET_WINDOW.as_millis() - 1),
                Class::B,
                1,
                TARGET
            ),
            Budget::Drop
        );
        assert_eq!(
            volume.append(at(opened + BUDGET_WINDOW.as_millis()), Class::B, 1, TARGET),
            Budget::Append
        );
        assert_eq!(volume.opened(), at(opened + BUDGET_WINDOW.as_millis()));
        assert_eq!(volume.bytes(), 1);
        assert_eq!(volume.dropped(), 0);
        // The clock moved back: a new window, honestly under-counted.
        assert_eq!(
            volume.append(at(opened - 1), Class::B, 1, TARGET),
            Budget::Append
        );
        assert_eq!(volume.opened(), at(opened - 1));
    }

    #[test]
    fn f_024_with_no_clock_the_count_accumulates_until_one_places_the_window() {
        let mut volume = WriteVolume::EMPTY;
        assert_eq!(
            volume.append(None, Class::A, TARGET, TARGET),
            Budget::Append
        );
        assert_eq!(volume.append(None, Class::B, 1, TARGET), Budget::Drop);
        assert_eq!(volume.opened(), None);
        // A clock appears: the window is placed and the count restarts.
        assert_eq!(volume.append(at(5), Class::B, 1, TARGET), Budget::Append);
        assert_eq!(volume.opened(), at(5));
        assert_eq!(volume.bytes(), 1);
    }

    #[test]
    fn the_counter_survives_the_round_trip_and_zero_is_no_clock() {
        let mut volume = WriteVolume::EMPTY;
        let _ = volume.append(at(77), Class::A, 5, TARGET);
        let _ = volume.append(at(77), Class::B, TARGET, TARGET);
        assert_eq!(WriteVolume::decode(&volume.encode()), Ok(volume));
        assert_eq!(
            WriteVolume::decode(&[0; WRITE_VOLUME_BYTES]),
            Ok(WriteVolume::EMPTY)
        );
    }
}
