//! A hard fault is written down and the part resets, as a panic is.
//!
//! The Cortex-M0+ has no fault status registers; what it has is the frame
//! it stacked, and the program counter in it is the whole of the evidence.
//! It goes out on the probe, and the part resets into its fail state
//! rather than sit in the handler with the outputs where they were. The
//! last words do not carry it yet: that variant lands with the panic
//! record's schema, and until then the boot after a fault reads as a
//! watchdog or a software reset with nothing to blame.

use cortex_m::asm;
use cortex_m::peripheral::SCB;
use cortex_m_rt::{ExceptionFrame, exception};

/// Cycles at 64 MHz the probe is given to drain the line before the
/// reset takes the buffer with it: about a tenth of a second.
const DRAIN_CYCLES: u32 = 6_400_000;

#[exception]
unsafe fn HardFault(frame: &ExceptionFrame) -> ! {
    defmt::error!(
        "hard fault at pc {=u32:#x}, lr {=u32:#x}, xpsr {=u32:#x}; reset follows",
        frame.pc(),
        frame.lr(),
        frame.xpsr()
    );
    asm::delay(DRAIN_CYCLES);
    SCB::sys_reset()
}
