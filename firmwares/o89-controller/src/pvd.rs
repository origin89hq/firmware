//! The programmable voltage detector, armed above the FRAM's minimum supply.
//!
//! Seven brown-outs on the bench destroyed both counter slots at once; the
//! write discipline that answers it (no FRAM transaction starts on a falling
//! supply, one in flight completes) is M2's, and this arms the detector it
//! reads. Level 6 is about 2.96 V falling and 3.06 V rising on this part,
//! above the FM24W256's 2.7 V floor; the self-test armed the same level
//! across every module switch-on.

#[cfg(feature = "rail-fault")]
use stm32_metapac::EXTI;
use stm32_metapac::{PWR, RCC};

/// `PVDFT`/`PVDRT` code 6 (RM0444, `PWR_CR2`).
const LEVEL: u8 = 6;

/// Whether the supply is below the level right now: the answer the FRAM
/// adapter reads at the last instant before it claims the bus.
pub fn supply_is_below_level() -> bool {
    PWR.sr2().read().pvdo()
}

/// Enable the detector at its level.
pub fn arm() {
    RCC.apbenr1().modify(|w| w.set_pwren(true));
    PWR.cr2().modify(|w| {
        w.set_pvdft(LEVEL);
        w.set_pvdrt(LEVEL);
        w.set_pvde(true);
    });
}

/// The detector's own EXTI line on this part (RM0444, "EXTI line 16").
#[cfg(feature = "rail-fault")]
const LINE: usize = 16;

/// Latch every crossing of the level in hardware (#62).
///
/// Both edges armed, the pending bits cleared, and the interrupt left
/// masked: nothing runs on a crossing, the flag simply stands. That is
/// the point. The fault under investigation corrupts the part within
/// milliseconds of the rail switching on, so a record the CPU has to
/// write is one it may never live to write, while a pending bit the edge
/// detector sets is still there to be read over the probe afterwards —
/// and it is set by a crossing of any width, where a poll between two
/// FRAM transactions sees only the instants it happens to look at.
///
/// `supply_is_below_level` keeps answering as it did; this adds a record
/// beside it and takes nothing away.
#[cfg(feature = "rail-fault")]
pub fn latch_crossings() {
    EXTI.rtsr(0).modify(|w| w.set_line(LINE, true));
    EXTI.ftsr(0).modify(|w| w.set_line(LINE, true));
    clear_crossings();
}

/// Whether the supply has crossed the level upward or downward since the
/// flags were last cleared, as `(rising, falling)`.
#[must_use]
#[cfg(feature = "rail-fault")]
pub fn crossings() -> (bool, bool) {
    (EXTI.rpr(0).read().line(LINE), EXTI.fpr(0).read().line(LINE))
}

/// Clear both flags. Write-one-to-clear, so this writes only the line's
/// own bit and leaves every other line's pending state alone.
#[cfg(feature = "rail-fault")]
pub fn clear_crossings() {
    let mut clear = stm32_metapac::exti::regs::Lines(0);
    clear.set_line(LINE, true);
    EXTI.rpr(0).write_value(clear);
    EXTI.fpr(0).write_value(clear);
}
