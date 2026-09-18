//! The controller's bootloader.
//!
//! It will do four things and nothing else: drive `RUN` and `KICK` low before
//! anything else runs, verify the selected bank's manifest, count trial boots
//! and flip back an image that never confirmed healthy, and jump. It is the
//! same bytes at the bottom of both banks, written at manufacture and never
//! by an update, which is what makes the bank swap safe to rely on.
//!
//! Today it does none of that: it links inside its 8 KB and waits, so the
//! gate measures a bootloader before there is one to measure. The generator
//! lines arrive with M1, the manifest with M7.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use cortex_m::asm;
use cortex_m::peripheral::SCB;
use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    loop {
        asm::wfi();
    }
}

/// A bootloader that panics resets the part.
///
/// There is nothing to print to and nobody to read it, and a halted
/// bootloader is a unit that never boots. A reset runs this code again, which
/// is either a boot or the same panic at a rate the watchdog will bound once
/// it is armed.
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    SCB::sys_reset()
}
