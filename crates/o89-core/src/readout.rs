//! What a pin read off the part means for the module rail, keyed on the
//! board revision: the two fields the bench tool reports.
//!
//! The rail's switch is enabled by `PC5`. On revision A the switch defaults
//! off, so a pin nobody drives leaves the rail down until firmware drives
//! it high. Revision B reverses the default (origin89hq/hardware#48, rule
//! A-23): the pin high-impedance means the rail is on, and the pin driven
//! low cuts it. The driven levels keep their meaning on both. A tool that
//! reads *not driven* as *off* misreads revision B in the one case the
//! default-on decision was made for, a controller that has not driven the
//! pin yet (#4). So the pin and the rail are two fields, and the rail is
//! a function of the pin and the revision.
//!
//! cites: F-014

use crate::revision::{RailThroughReset, Revision};

/// What the pin is doing, as its registers say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PinState {
    /// An input, or analog: nobody drives it.
    HighImpedance,
    /// Driven low.
    DrivenLow,
    /// Driven high.
    DrivenHigh,
    /// Handed to a peripheral, which no firmware of ours does with this
    /// pin: what the rail is doing cannot be told from the registers.
    Alternate,
}

/// What the rail is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RailState {
    /// The module is powered.
    On,
    /// The module is not.
    Off,
    /// The pin's state does not say; a reading nobody should act on.
    Unknown,
}

/// The rail readout: the pin as read and the rail it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RailReadout {
    /// The pin.
    pub pin: PinState,
    /// The rail, on this revision.
    pub rail: RailState,
}

impl RailReadout {
    /// What `pin` means for the rail on `revision`.
    #[must_use]
    pub const fn of(revision: Revision, pin: PinState) -> Self {
        let rail = match pin {
            PinState::DrivenHigh => RailState::On,
            PinState::DrivenLow => RailState::Off,
            PinState::HighImpedance => match revision.rail_through_reset() {
                RailThroughReset::Off => RailState::Off,
                RailThroughReset::On => RailState::On,
            },
            PinState::Alternate => RailState::Unknown,
        };
        Self { pin, rail }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_014_a_high_impedance_pin_is_the_rail_off_on_revision_a_and_on_on_revision_b() {
        assert_eq!(
            RailReadout::of(Revision::A, PinState::HighImpedance).rail,
            RailState::Off
        );
        // The case #4 was filed for: a revision B board whose firmware has
        // not driven the pin, a blank part or one in a crash loop.
        assert_eq!(
            RailReadout::of(Revision::B, PinState::HighImpedance).rail,
            RailState::On
        );
    }

    #[test]
    fn f_014_the_driven_levels_keep_their_meaning_on_both_revisions() {
        for revision in [Revision::A, Revision::B] {
            assert_eq!(
                RailReadout::of(revision, PinState::DrivenHigh).rail,
                RailState::On
            );
            assert_eq!(
                RailReadout::of(revision, PinState::DrivenLow).rail,
                RailState::Off
            );
        }
    }

    #[test]
    fn a_pin_handed_to_a_peripheral_says_the_rail_is_unknown_on_both_revisions() {
        for revision in [Revision::A, Revision::B] {
            assert_eq!(
                RailReadout::of(revision, PinState::Alternate).rail,
                RailState::Unknown
            );
        }
    }

    #[test]
    fn the_readout_carries_the_pin_it_was_read_from() {
        let readout = RailReadout::of(Revision::B, PinState::HighImpedance);
        assert_eq!(readout.pin, PinState::HighImpedance);
        assert_eq!(readout.rail, RailState::On);
    }
}
