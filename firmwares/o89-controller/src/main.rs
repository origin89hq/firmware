//! The controller firmware: an adapter, and nothing that decides.
//!
//! Nothing here may contain an `if` about a generator, a threshold or a
//! timeout policy. Those live in `o89-core`, where a simulated winter can
//! drive them. This crate reads pins and writes pins, and the day it stops
//! being able to say that is the day a decision has escaped somewhere no test
//! can reach.
//!
//! Today it links, initialises the part and idles. The boot order the hazards
//! dictate — the generator lines low at the reset vector, the RS-485 drivers
//! idle, the watchdog fed only by a rollcall, the outputs to their fail state
//! — arrives with M1, and each step lands with the issue that argued for it.

#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use panic_probe as _;

/// The one task there is: it keeps the time driver ticking so the image is
/// measured with the executor and the timer queue linked in, which is the
/// floor every later task is costed against.
#[embassy_executor::task]
async fn idle() -> ! {
    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let _peripherals = embassy_stm32::init(embassy_stm32::Config::default());
    defmt::info!("o89-controller up; nothing runs yet");
    // The pool holds one `idle` and this is its only spawn, so the refusal is
    // unreachable; it is still answered rather than ignored.
    if let Ok(token) = idle() {
        spawner.spawn(token);
    } else {
        defmt::error!("the idle task did not spawn");
    }
}
