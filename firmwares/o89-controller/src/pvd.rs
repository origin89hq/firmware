//! The programmable voltage detector, armed above the FRAM's minimum supply.
//!
//! Seven brown-outs on the bench destroyed both counter slots at once; the
//! write discipline that answers it (no FRAM transaction starts on a falling
//! supply, one in flight completes) is M2's, and this arms the detector it
//! reads. Level 6 is about 2.96 V falling and 3.06 V rising on this part,
//! above the FM24W256's 2.7 V floor; the self-test armed the same level
//! across every module switch-on.

use stm32_metapac::{PWR, RCC};

/// `PVDFT`/`PVDRT` code 6 (RM0444, `PWR_CR2`).
const LEVEL: u8 = 6;

/// Enable the detector at its level.
pub fn arm() {
    RCC.apbenr1().modify(|w| w.set_pwren(true));
    PWR.cr2().modify(|w| {
        w.set_pvdft(LEVEL);
        w.set_pvdrt(LEVEL);
        w.set_pvde(true);
    });
}
