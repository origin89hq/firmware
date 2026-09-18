//! One lamp, meaning by pattern.
//!
//! Two LEDs share one light pipe, so what a person sees is one lamp: a slow
//! heartbeat is a controller that is alive, linked and on the network; a
//! double heartbeat is alive with no network; a fast blink is a fault. The
//! pattern is a function of the time since boot on a 100 ms grid, which is
//! what lets the supervisor render it without keeping state and lets a test
//! read every slot of it.

use crate::Millis;

/// What the lamp is saying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Pattern {
    /// Alive, linked and on the network: one short pulse every two seconds.
    Heartbeat,
    /// Alive with no network: two short pulses every two seconds.
    DoubleHeartbeat,
    /// A fault: the fault lamp at 5 Hz, the status lamp dark.
    Fault,
}

/// The two LEDs behind the pipe, lit or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Lamps {
    /// `PC6` on board A.
    pub status: bool,
    /// `PC7` on board A.
    pub fault: bool,
}

/// The grid the patterns are drawn on.
const SLOT: u64 = 100;
/// Slots per period: two seconds.
const PERIOD: u64 = 20;

impl Pattern {
    /// What the lamps show at `since_boot`.
    #[must_use]
    pub const fn lamps(self, since_boot: Millis) -> Lamps {
        let slot = (since_boot.as_millis() / SLOT) % PERIOD;
        match self {
            Self::Heartbeat => Lamps {
                status: slot == 0,
                fault: false,
            },
            Self::DoubleHeartbeat => Lamps {
                status: slot == 0 || slot == 3,
                fault: false,
            },
            Self::Fault => Lamps {
                status: false,
                fault: slot.is_multiple_of(2),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(millis: u64) -> Millis {
        Millis::from_millis(millis)
    }

    /// Which 100 ms slots of four seconds light the status lamp.
    fn status_slots(pattern: Pattern) -> [bool; 40] {
        let mut lit = [false; 40];
        for (slot, ms) in (0..4_000).step_by(100).enumerate() {
            lit[slot] = pattern.lamps(at(ms)).status;
        }
        lit
    }

    #[test]
    fn a_heartbeat_is_one_pulse_every_two_seconds() {
        let expected: [bool; 40] = core::array::from_fn(|slot| slot == 0 || slot == 20);
        assert_eq!(status_slots(Pattern::Heartbeat), expected);
        assert!((0..4_000).all(|ms| !Pattern::Heartbeat.lamps(at(ms)).fault));
    }

    #[test]
    fn a_double_heartbeat_is_two_pulses_a_gap_apart() {
        let expected: [bool; 40] = core::array::from_fn(|slot| matches!(slot, 0 | 3 | 20 | 23));
        assert_eq!(status_slots(Pattern::DoubleHeartbeat), expected);
    }

    #[test]
    fn a_fault_blinks_the_fault_lamp_at_five_hertz_and_darkens_the_status() {
        for ms in (0..2_000).step_by(100) {
            let lamps = Pattern::Fault.lamps(at(ms));
            assert_eq!(lamps.fault, (ms / 100) % 2 == 0, "{ms}");
            assert!(!lamps.status);
        }
    }

    #[test]
    fn the_pattern_holds_across_a_slot_and_far_from_boot() {
        // Inside one slot the answer does not change.
        for ms in 0..100 {
            assert!(Pattern::Heartbeat.lamps(at(ms)).status);
        }
        assert!(!Pattern::Heartbeat.lamps(at(100)).status);
        // Seven weeks in, the grid still lines up.
        let seven_weeks = 7 * 7 * 24 * 60 * 60 * 1_000;
        assert!(Pattern::Heartbeat.lamps(at(seven_weeks)).status);
    }
}
