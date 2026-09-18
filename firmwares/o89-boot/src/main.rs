//! The controller's bootloader.
//!
//! It will do four things and nothing else: drive `RUN` and `KICK` low before
//! anything else runs, verify the selected bank's manifest, count trial boots
//! and flip back an image that never confirmed healthy, and jump. It is the
//! same bytes at the bottom of both banks, written at manufacture and never
//! by an update, which is what makes the bank swap safe to rely on.
//!
//! Today it does the first and the last. The generator lines go low as the
//! first statement of `main`, which on this runtime is a few instructions
//! after the reset vector, once the (empty) RAM image is laid out. Then it
//! jumps to the application at the fixed address past its own 8 KB. An
//! application whose first two words are not a stack pointer in RAM and a
//! reset vector in flash is not jumped to: the part waits with the lines
//! low, where a probe can reach it. The manifest and the trial count arrive
//! with M7.
//!
//! This is the one file in this image that names a pin: `PD0` is `RUN` and
//! `PD1` is `KICK` on board A revision A (`BOARD-A.md`).

#![no_std]
#![no_main]

use core::ops::{Range, RangeInclusive};
use core::panic::PanicInfo;
use core::ptr;

use cortex_m::asm;
use cortex_m::peripheral::SCB;
use cortex_m_rt::entry;
use stm32_metapac::gpio::vals::{Moder, Ot};
use stm32_metapac::{GPIOD, RCC};

/// Where the application's vector table sits: past the bootloader's 8 KB,
/// the same in either bank. `o89-controller/memory.x` says the same number,
/// and the application sets its own `VTOR` from it on the way in.
const APPLICATION: usize = 0x0800_2000;

/// The part's RAM, which is where an initial stack pointer has to point.
/// The top is included: the runtime puts the first stack at the very end
/// of RAM, and the first push moves below it.
const RAM: RangeInclusive<u32> = 0x2000_0000..=0x2002_4000;

/// The application's part of the bank as the core sees it, which is where a
/// reset vector has to point: past this image's 8 KB, inside the bank.
const APPLICATION_FLASH: Range<u32> = 0x0800_2000..0x0804_0000;

/// Whether two words could be an application's initial stack pointer and
/// reset vector. The reset vector's Thumb bit is not judged: `bootload`
/// sets it on the way.
const fn plausible(stack: u32, reset: u32) -> bool {
    let start = *RAM.start();
    let end = *RAM.end();
    let reset = reset & !1;
    start <= stack
        && stack <= end
        && APPLICATION_FLASH.start <= reset
        && reset < APPLICATION_FLASH.end
}

const _: () = {
    // The real application: the stack at the top of RAM, the reset handler
    // just past the vector table and the build-id note.
    assert!(plausible(0x2002_4000, 0x0800_2101));
    assert!(plausible(0x2001_0000, 0x0800_2100));
    // A stack past the top of RAM, or below it.
    assert!(!plausible(0x2002_4004, 0x0800_2101));
    assert!(!plausible(0x1FFF_FFFC, 0x0800_2101));
    // A reset vector into this image's own 8 KB, or past the bank.
    assert!(!plausible(0x2002_4000, 0x0800_0101));
    assert!(!plausible(0x2002_4000, 0x0804_0001));
    // Erased flash.
    assert!(!plausible(0xFFFF_FFFF, 0xFFFF_FFFF));
};

/// `RUN`, on `PD0`.
const RUN: usize = 0;
/// `KICK`, on `PD1`.
const KICK: usize = 1;

#[entry]
fn main() -> ! {
    generator_lines_low();
    jump_to_the_application()
}

/// `RUN` and `KICK` low, push-pull, before anything else.
///
/// The output bits are cleared before the pins become outputs, so each pin
/// goes from high-impedance to driven low with no instant at which it is
/// driven high.
fn generator_lines_low() {
    RCC.gpioenr().modify(|w| w.set_gpioden(true));
    GPIOD.bsrr().write(|w| {
        w.set_br(RUN, true);
        w.set_br(KICK, true);
    });
    GPIOD.otyper().modify(|w| {
        w.set_ot(RUN, Ot::PUSH_PULL);
        w.set_ot(KICK, Ot::PUSH_PULL);
    });
    GPIOD.moder().modify(|w| {
        w.set_moder(RUN, Moder::OUTPUT);
        w.set_moder(KICK, Moder::OUTPUT);
    });
}

/// Jump to the application if its first two words look like a vector
/// table's; otherwise wait, with the generator lines low.
///
/// The check is plausibility, not validity: a corrupt image whose first two
/// words pass it is jumped to, faults, and lands in this image's fault
/// handler with the lines still low, which is the fail state. Validity is
/// the manifest's signature, which is M7.
#[expect(
    unsafe_code,
    reason = "the jump reads the application's vector table at a fixed flash address and hands it the core, which no safe API does"
)]
fn jump_to_the_application() -> ! {
    let table = ptr::with_exposed_provenance::<u32>(APPLICATION);
    // SAFETY: `APPLICATION` is inside the part's flash, which is always
    // mapped, readable and 4-byte aligned at this address, and the second
    // word is inside the same bank.
    let (stack, reset) = unsafe { (ptr::read_volatile(table), ptr::read_volatile(table.add(1))) };
    if !plausible(stack, reset) {
        wait_for_a_probe();
    }
    // SAFETY: the table's first word is a stack pointer inside RAM and its
    // second a reset vector inside the application's flash, which is what
    // `bootload` requires; nothing of ours is live past this point.
    unsafe { asm::bootload(table) }
}

/// No application to run: hold the lines low and wait for somebody with a
/// probe. `wfi` is not a stop mode, so the probe still connects (F-012).
fn wait_for_a_probe() -> ! {
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
