//! The board revision, and the policies the firmware reads from it.
//!
//! Revision A of controller board A has defects the firmware lives with and
//! revision B fixes some of. Which board an image runs on is chosen at build
//! time by the board module that names its pins; the policies below are what
//! the rest of the firmware reads, so that a rule like *never switch the
//! module rail on after minutes off* is a value a test can read rather than
//! an `if` in an adapter. `BOARD-A.md` carries the whole table with the
//! issues behind each row.
//!
//! This file is the whole list of what revision A makes the firmware do
//! differently: every method below has an arm per revision and nothing else
//! in the tree matches on [`Revision`]. The `B` arms are written from the
//! hardware repository's decisions before a revision B board exists, so
//! moving to one is the constant in the board module and a bench that
//! confirms each arm, not a search.
//!
//! cites: F-005, F-012, F-014

use crate::Millis;

/// Controller board A, by revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Revision {
    /// The 2026-09-09 export: the boards on the bench.
    A,
    /// The rework decided on origin89hq/hardware#48 and #51.
    B,
}

/// Whether the strap alone enters the ROM's serial download mode, which
/// the board decides: the controller drives IO9, and the ROM wants IO8 high
/// with it, or it picks its USB-only mode (hardware#6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StrapRoute {
    /// IO8 floats and reads low: the route works only with a wire holding
    /// IO8 high, so it is the bench's, never the firmware's own.
    NeedsIo8Wire,
    /// IO8 is pulled up (hardware#48): the strap alone is enough, and the
    /// firmware may take this route by itself.
    Wired,
}

/// What the module rail does through a controller reset, which the board
/// decides and the firmware can only report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RailThroughReset {
    /// The switch defaults off with the controller's pin high-impedance, so
    /// every reset reboots the module and is a switch-on event nobody chose.
    Off,
    /// The switch defaults on with the pin high-impedance; a reset never
    /// power-cycles the radio, and the controller takes ownership once booted.
    On,
}

/// The heartbeat ladder's third rung, which asks for the rail off for fifteen
/// minutes (L-112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ThirdRung {
    /// Cut the rail for this long, as the ladder says.
    Cut(Millis),
    /// Stop cycling, leave the rail on, raise comms unrecoverable and log
    /// which policy applied. Switching the rail on after minutes off corrupts
    /// the controller within milliseconds, 22 times of 22
    /// (origin89hq/hardware#5), so the rung is not executed.
    LeaveOnAndRaise,
}

/// Whether the part may ever enter a stop mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StopMode {
    /// The debug header carries no `NRST`, so a part in stop mode is one the
    /// probe cannot reach again (origin89hq/hardware#29).
    Forbidden,
    /// `NRST` is on the header and low power becomes possible.
    Allowed,
}

/// The longest a rail cycle may leave the module off on revision A.
const REVISION_A_LONGEST_OFF: Millis = Millis::from_millis(5_000);

/// The ladder's third rung as L-112 states it: fifteen minutes.
const THIRD_RUNG_CUT: Millis = Millis::from_millis(15 * 60 * 1_000);

impl Revision {
    /// What the board does to the module rail through a reset.
    #[must_use]
    pub const fn rail_through_reset(self) -> RailThroughReset {
        match self {
            Self::A => RailThroughReset::Off,
            Self::B => RailThroughReset::On,
        }
    }

    /// The longest any rail cycle may leave the module off.
    ///
    /// Revision A: five seconds, because short cycles passed hundreds of
    /// times on the bench and a switch-on after minutes off never did.
    /// Revision B has a slew-limited switch, and the ladder's own rung is
    /// the bound.
    #[must_use]
    pub const fn longest_rail_off(self) -> Millis {
        match self {
            Self::A => REVISION_A_LONGEST_OFF,
            Self::B => THIRD_RUNG_CUT,
        }
    }

    /// How the ROM's strapping route into download mode is reached on this
    /// board: with IO9 held low across a reset, the ROM reads IO8 too.
    #[must_use]
    pub const fn strap_route(self) -> StrapRoute {
        match self {
            Self::A => StrapRoute::NeedsIo8Wire,
            Self::B => StrapRoute::Wired,
        }
    }

    /// What the ladder's third rung does on this board.
    #[must_use]
    pub const fn third_rung(self) -> ThirdRung {
        match self {
            Self::A => ThirdRung::LeaveOnAndRaise,
            Self::B => ThirdRung::Cut(THIRD_RUNG_CUT),
        }
    }

    /// Whether any code may enter a stop mode.
    #[must_use]
    pub const fn stop_mode(self) -> StopMode {
        match self {
            Self::A => StopMode::Forbidden,
            Self::B => StopMode::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_005_revision_a_never_leaves_the_rail_off_longer_than_five_seconds() {
        assert_eq!(Revision::A.longest_rail_off(), Millis::from_millis(5_000));
        // The rung the ladder asks for is longer than the cap, so it is not
        // executed: the rail stays on and the concern is raised instead.
        assert_eq!(Revision::A.third_rung(), ThirdRung::LeaveOnAndRaise);
    }

    #[test]
    fn f_005_revision_b_runs_the_full_ladder_inside_its_own_bound() {
        let ThirdRung::Cut(cut) = Revision::B.third_rung() else {
            panic!("revision B executes the rung");
        };
        assert_eq!(cut, Millis::from_millis(900_000));
        assert!(cut <= Revision::B.longest_rail_off());
    }

    #[test]
    fn f_005_no_revision_cuts_the_rail_longer_than_it_allows() {
        for revision in [Revision::A, Revision::B] {
            match revision.third_rung() {
                ThirdRung::Cut(cut) => assert!(cut <= revision.longest_rail_off()),
                ThirdRung::LeaveOnAndRaise => {}
            }
        }
    }

    #[test]
    fn f_012_revision_a_forbids_stop_mode_and_b_allows_it() {
        assert_eq!(Revision::A.stop_mode(), StopMode::Forbidden);
        assert_eq!(Revision::B.stop_mode(), StopMode::Allowed);
    }

    #[test]
    fn f_014_the_rail_is_off_through_a_reset_on_a_and_on_through_one_on_b() {
        assert_eq!(Revision::A.rail_through_reset(), RailThroughReset::Off);
        assert_eq!(Revision::B.rail_through_reset(), RailThroughReset::On);
    }
}
