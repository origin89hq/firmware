//! The module rail's pin, read from the part's registers.
//!
//! `PC5` enables the rail's switch (BOARD-A.md). What the registers say
//! about the pin is one thing; what that means for the rail is another,
//! and depends on the revision (#4, F-014): `o89-core`'s readout does that
//! mapping, and this module only reads the registers. The port's clock is
//! read first, because a port without its clock is at reset, and every
//! pin of a port at reset is analog: nobody drives it.

use anyhow::Result;
use o89_core::{PinState, RailReadout, Revision};

use crate::link::Link;

/// `RCC_IOPENR`: which ports have their clock.
const RCC_IOPENR: u64 = 0x4002_1034;
/// `GPIOCEN` in it.
const GPIOC_ENABLED: u32 = 1 << 2;
/// Port C's registers.
const GPIOC: u64 = 0x5000_0800;
/// `MODER`, two bits a pin.
const MODER: u64 = GPIOC;
/// `ODR`, one bit a pin.
const ODR: u64 = GPIOC + 0x14;
/// The rail's pin.
const PIN: u32 = 5;

/// What the two mode bits of a pin say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Input,
    Output,
    Alternate,
    Analog,
}

impl Mode {
    /// The mode of `pin` in a `MODER` word.
    fn of(moder: u32, pin: u32) -> Self {
        match (moder >> pin.saturating_mul(2)) & 0b11 {
            0b00 => Self::Input,
            0b01 => Self::Output,
            0b10 => Self::Alternate,
            _ => Self::Analog,
        }
    }
}

/// What the registers say the pin is doing.
fn pin_state(clocked: bool, moder: u32, odr: u32, pin: u32) -> PinState {
    if !clocked {
        return PinState::HighImpedance;
    }
    match Mode::of(moder, pin) {
        Mode::Input | Mode::Analog => PinState::HighImpedance,
        Mode::Output => {
            if (odr >> pin) & 1 == 1 {
                PinState::DrivenHigh
            } else {
                PinState::DrivenLow
            }
        }
        Mode::Alternate => PinState::Alternate,
    }
}

/// The rail's pin as the registers say, and what it means on `revision`.
pub fn read(link: &mut Link, revision: Revision) -> Result<RailReadout> {
    let clocked = link.read_word(RCC_IOPENR)? & GPIOC_ENABLED != 0;
    let (moder, odr) = if clocked {
        (link.read_word(MODER)?, link.read_word(ODR)?)
    } else {
        (0, 0)
    };
    Ok(RailReadout::of(
        revision,
        pin_state(clocked, moder, odr, PIN),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use o89_core::RailState;

    /// `MODER` with `pin` in `mode` and every other pin analog, as at reset.
    fn moder_with(pin: u32, mode: u32) -> u32 {
        let shift = pin.saturating_mul(2);
        !(0b11 << shift) | (mode << shift)
    }

    #[test]
    fn f_014_an_output_driven_high_is_the_rail_on_and_low_is_off_on_both_revisions() {
        let moder = moder_with(PIN, 0b01);
        for revision in [Revision::A, Revision::B] {
            let high = RailReadout::of(revision, pin_state(true, moder, 1 << PIN, PIN));
            assert_eq!((high.pin, high.rail), (PinState::DrivenHigh, RailState::On));
            let low = RailReadout::of(revision, pin_state(true, moder, 0, PIN));
            assert_eq!((low.pin, low.rail), (PinState::DrivenLow, RailState::Off));
        }
    }

    #[test]
    fn f_014_a_port_without_its_clock_or_a_pin_left_analog_is_high_impedance_which_is_on_for_revision_b()
     {
        // The port at reset: no clock, and the registers not even read.
        let at_reset = RailReadout::of(Revision::B, pin_state(false, 0, 0, PIN));
        assert_eq!(
            (at_reset.pin, at_reset.rail),
            (PinState::HighImpedance, RailState::On)
        );
        // The clock on and the pin still analog, as a firmware that never
        // took the pin leaves it.
        let analog = pin_state(true, moder_with(PIN, 0b11), 0, PIN);
        assert_eq!(analog, PinState::HighImpedance);
        assert_eq!(RailReadout::of(Revision::A, analog).rail, RailState::Off);
        let input = pin_state(true, moder_with(PIN, 0b00), 1 << PIN, PIN);
        assert_eq!(
            input,
            PinState::HighImpedance,
            "an input's ODR bit drives nothing"
        );
    }

    #[test]
    fn a_pin_handed_to_a_peripheral_is_reported_and_the_rail_is_unknown() {
        let alternate = pin_state(true, moder_with(PIN, 0b10), 1 << PIN, PIN);
        assert_eq!(alternate, PinState::Alternate);
        assert_eq!(
            RailReadout::of(Revision::B, alternate).rail,
            RailState::Unknown
        );
    }

    #[test]
    fn the_mode_is_read_from_the_pins_own_two_bits() {
        // Pin 4 an output driven high, pin 5 analog: pin 5 is not driven.
        let moder = moder_with(4, 0b01);
        assert_eq!(pin_state(true, moder, 1 << 4, PIN), PinState::HighImpedance);
        assert_eq!(pin_state(true, moder, 1 << 4, 4), PinState::DrivenHigh);
    }
}
