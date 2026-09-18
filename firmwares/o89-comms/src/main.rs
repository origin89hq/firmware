//! The comms processor: a pipe, and nothing the controller trusts.
//!
//! This chip is hostile by assumption. It carries frames between a client and
//! the controller and can read none of them: every client message is
//! authenticated end to end under a key derived from the printed secret,
//! which this part never holds. So the rule this crate lives under is narrow
//! and absolute: it forwards bytes and never inspects them. It must never
//! depend on `o89-core`, and the gate refuses the dependency.
//!
//! The order its boot will take is fixed by the recovery story on board A
//! revision A: the watchdog re-armed as the first statement after
//! `esp_hal::init`, which disables every watchdog; UART0 to the controller;
//! the download window, listening for one link-local request and nothing
//! else; only then the scheduler, the radio and the link. Today it
//! initialises the part and waits; the window and the link arrive with M3.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::delay::Delay;
use esp_hal::main;

// The ESP-IDF application descriptor, which the ROM bootloader reads before
// it will run anything. Without it `espflash` refuses the image outright.
esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    let _peripherals = esp_hal::init(esp_hal::Config::default());
    esp_println::println!("o89-comms up; nothing runs yet");
    let delay = Delay::new();
    loop {
        delay.delay_millis(1_000);
    }
}
