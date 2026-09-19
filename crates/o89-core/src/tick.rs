//! The clock that reads the tick, and the wall clock a client sets.
//!
//! The tick itself, [`Tick`] and [`Millis`], is `o89-link`'s, because the
//! comms processor measures its link on the same counter: every duration
//! here is measured on it, never on the wall clock (P-004).

pub use o89_link::{Millis, Tick};

/// Reads the tick.
///
/// The firmware fills this from its time driver; the simulator fills it from
/// a number it controls, which is what lets a hundred days of being asked late
/// run in a millisecond.
pub trait Clock {
    /// The tick now.
    fn now(&self) -> Tick;
}

/// The wall clock as a client last set it: milliseconds since the Unix
/// epoch.
///
/// A moment a record carries so a person can read when, and never the
/// base of a duration (P-004): it is settable by any enrolled client and
/// movable by the comms processor. Zero is not a time this controller
/// accepts, so a body stores *no clock* as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnixMillis(u64);

impl UnixMillis {
    /// `millis` since the Unix epoch, or nothing for zero.
    #[must_use]
    pub const fn new(millis: u64) -> Option<Self> {
        if millis == 0 {
            None
        } else {
            Some(Self(millis))
        }
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// How long after `earlier` this is, or `None` when it is not after.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Option<Millis> {
        match self.0.checked_sub(earlier.0) {
            Some(elapsed) => Some(Millis::from_millis(elapsed)),
            None => None,
        }
    }
}
