//! The monotonic tick every duration is measured on, and the clock that reads it.
//!
//! Every duration in the protocol — the 15-minute session expiry, the
//! 120-second challenge and pairing windows, the dedup table's 10 minutes, the
//! 50 ms incomplete-frame timeout — is measured on a tick since boot, never on
//! the wall clock, because the wall clock is settable by any enrolled client
//! and movable by the comms processor, and a duration measured on it is a
//! duration somebody else sets. The tick is milliseconds in a `u64`: a `u32`
//! wraps at 49.7 days, and seven weeks into an uninterrupted run is the
//! ordinary state of this site.
//!
//! cites: P-004

/// Milliseconds since boot on a counter that never runs backwards.
///
/// A clock write does not move it. Two ticks from different boots compare
/// meaninglessly, which is why [`Tick::since`] refuses rather than wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(u64);

/// A duration in milliseconds, the unit every bound in the protocol is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(u64);

impl Tick {
    /// The moment of boot.
    pub const ZERO: Self = Self(0);

    /// A tick at `millis` since boot.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since boot.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// How long has passed since `earlier`.
    ///
    /// `None` when `earlier` is later than this tick. The tick never runs
    /// backwards, so that is a caller holding a tick from a different boot,
    /// and a duration invented for it would be a bound measured against
    /// nothing.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Option<Millis> {
        match self.0.checked_sub(earlier.0) {
            Some(elapsed) => Some(Millis(elapsed)),
            None => None,
        }
    }

    /// The tick `later` after this one.
    ///
    /// `None` past the end of the counter, which is 584 million years away;
    /// the refusal exists so that no arithmetic on a tick is unchecked, not
    /// because a unit will reach it.
    #[must_use]
    pub const fn after(self, later: Millis) -> Option<Self> {
        match self.0.checked_add(later.0) {
            Some(at) => Some(Self(at)),
            None => None,
        }
    }
}

impl Millis {
    /// No time at all.
    pub const ZERO: Self = Self(0);

    /// A duration of `millis` milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// A duration of `secs` seconds, or `None` past the end of the counter.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Option<Self> {
        match secs.checked_mul(1_000) {
            Some(millis) => Some(Self(millis)),
            None => None,
        }
    }

    /// The duration in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Reads the tick.
///
/// The firmware fills this from its time driver; the simulator fills it from
/// a number it controls, which is what lets a hundred days of being asked late
/// run in a millisecond.
pub trait Clock {
    /// The tick now.
    fn now(&self) -> Tick;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_004_a_later_tick_reports_how_long_has_passed() {
        let earlier = Tick::from_millis(1_000);
        let later = Tick::from_millis(1_750);
        assert_eq!(later.since(earlier), Some(Millis::from_millis(750)));
    }

    #[test]
    fn p_004_the_same_moment_has_passed_nothing() {
        let now = Tick::from_millis(42);
        assert_eq!(now.since(now), Some(Millis::ZERO));
    }

    #[test]
    fn p_004_a_tick_from_a_later_moment_is_not_a_negative_duration() {
        let earlier = Tick::from_millis(2_000);
        let later = Tick::from_millis(2_001);
        assert_eq!(earlier.since(later), None);
    }

    #[test]
    fn p_004_the_tick_is_wide_enough_for_a_winter() {
        // A `u32` of milliseconds wraps here. Seven weeks into a run this tick
        // has to keep counting, and every duration above it has to stay
        // positive.
        let past_a_u32 = Millis::from_millis(4_294_967_296);
        let seven_weeks_in = Tick::ZERO.after(past_a_u32);
        assert_eq!(seven_weeks_in, Some(Tick::from_millis(4_294_967_296)));
        let then = seven_weeks_in.expect("fits a u64");
        assert_eq!(then.since(Tick::ZERO), Some(past_a_u32));
    }

    #[test]
    fn a_tick_past_the_end_of_the_counter_is_refused() {
        let end = Tick::from_millis(u64::MAX);
        assert_eq!(end.after(Millis::from_millis(1)), None);
        assert_eq!(end.after(Millis::ZERO), Some(end));
    }

    #[test]
    fn seconds_convert_to_milliseconds_until_the_counter_ends() {
        assert_eq!(
            Millis::from_secs(15 * 60),
            Some(Millis::from_millis(900_000))
        );
        assert_eq!(Millis::from_secs(0), Some(Millis::ZERO));
        assert_eq!(Millis::from_secs(u64::MAX), None);
    }
}
