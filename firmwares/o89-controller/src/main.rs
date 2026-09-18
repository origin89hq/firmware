//! The controller firmware: an adapter, and nothing that decides.
//!
//! Nothing here may contain an `if` about a generator, a threshold or a
//! timeout policy. Those live in `o89-core`, where a simulated winter can
//! drive them. This crate reads pins and writes pins, and the day it stops
//! being able to say that is the day a decision has escaped somewhere no test
//! can reach.
//!
//! Boot runs in the order the hazards dictate (`ARCHITECTURE.md`): the
//! generator and bus lines through the registers as the first statement;
//! the reset cause read and cleared and the last words taken, both before
//! the HAL; the clocks, with the LSE asserted; the watchdog, fed only by the
//! rollcall; the voltage detector; every output to its declared fail state;
//! then the control tick. The FRAM read, the buses and the module rail
//! arrive with the milestones that name them.

#![no_std]
#![no_main]

mod board;
mod clock;
mod first;
mod last_words;
mod panic;
mod pvd;
mod reset;
mod supervisor;

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_time::{Duration, Ticker};
use o89_core::{BootRecord, Bus, FailState, LastWords, Line, ResetCause, RtcClock, Task};

use crate::board::{Board, REVISION};

/// The level a driven line is held at, from the table `o89-core` declares.
///
/// Only lines the table declares driven are passed here; the assertions
/// below hold that at compile time for each one this image drives.
const fn driven(line: Line) -> Level {
    match line.fail_state(REVISION) {
        FailState::DrivenHigh | FailState::On => Level::High,
        FailState::DrivenLow
        | FailState::InputOrLow
        | FailState::Off
        | FailState::LeftToTheBoard => Level::Low,
    }
}

const _: () = {
    assert!(matches!(
        Line::Run.fail_state(REVISION),
        FailState::DrivenLow
    ));
    assert!(matches!(
        Line::Kick.fail_state(REVISION),
        FailState::DrivenLow
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::One).fail_state(REVISION),
        FailState::DrivenHigh
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::Two).fail_state(REVISION),
        FailState::DrivenHigh
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::Three).fail_state(REVISION),
        FailState::DrivenHigh
    ));
};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // 1. The lines with a hazard, before anything else.
    first::generator_and_bus_lines();

    // 2. Why the part reset, and what the previous run said last.
    let cause = ResetCause::from_flags(reset::take_flags());
    let words = last_words::take();

    // 3. The clocks.
    let mut config = embassy_stm32::Config::default();
    config.rcc = clock::config();
    let p = embassy_stm32::init(config);
    let rtc = reset::rtc_clock();
    let backup = reset::backup_domain();

    let blame = match words {
        Some(LastWords::Starved(blame)) => Some(blame),
        Some(LastWords::Panicked(site)) => {
            defmt::error!(
                "the previous run panicked at file {=u32:#x} line {=u32}",
                site.file,
                site.line
            );
            None
        }
        None => None,
    };
    let record = BootRecord::new(cause, blame, rtc, backup, REVISION);
    defmt::info!("boot: {}", record);
    if let RtcClock::Fault { lse_ready, source } = record.rtc {
        defmt::error!(
            "the RTC is not on the LSE: lse_ready={} source={}; a fault, not a fallback",
            lse_ready,
            source
        );
    }

    let b = Board::split(p);

    // 4. The watchdog, armed now and fed only by the rollcall.
    let mut wdg = IndependentWatchdog::new(b.iwdg, supervisor::WATCHDOG_US);
    wdg.unleash();

    // 5. The voltage detector.
    pvd::arm();

    // 7. Every output this image drives, to its declared fail state. Held
    // for the life of this task, which never returns; a bus takes its
    // transmit line from here when it comes up.
    let _run = Output::new(b.gen_run, driven(Line::Run), Speed::Low);
    let _kick = Output::new(b.gen_kick, driven(Line::Kick), Speed::Low);
    let _rs485_1_tx = Output::new(b.rs485_1.tx, driven(Line::Rs485Tx(Bus::One)), Speed::Low);
    let _rs485_2_tx = Output::new(b.rs485_2.tx, driven(Line::Rs485Tx(Bus::Two)), Speed::Low);
    let _rs485_3_tx = Output::new(b.rs485_3.tx, driven(Line::Rs485Tx(Bus::Three)), Speed::Low);
    let status = Output::new(b.led_status, Level::Low, Speed::Low);
    let fault = Output::new(b.led_fault, Level::Low, Speed::Low);

    supervisor::check_in(Task::Supervisor);
    // The pool holds one supervisor and this is its only spawn; an unfed
    // watchdog is the answer if it ever refuses.
    if let Ok(token) = supervisor::run(wdg, status, fault) {
        spawner.spawn(token);
    } else {
        defmt::error!("the supervisor did not spawn; the watchdog will reset the part");
    }

    // 10. The control tick, 1 Hz. Nothing decides yet; it checks in.
    supervisor::check_in(Task::Control);
    let mut ticker = Ticker::every(Duration::from_secs(1));
    #[cfg(feature = "bench")]
    let mut proof = bench::Proof::new(cause);
    loop {
        ticker.next().await;
        #[cfg(feature = "bench")]
        if proof.starve_now() {
            defmt::warn!(
                "watchdog proof: the control tick stops checking in on purpose; the part resets in about 8 s and the next boot names it"
            );
            loop {
                ticker.next().await;
            }
        }
        supervisor::check_in(Task::Control);
    }
}

/// The one-shot starvation that proves the watchdog on the bench.
#[cfg(feature = "bench")]
mod bench {
    use o89_core::ResetCause;

    /// Seconds of ordinary running before the starvation.
    const AFTER_TICKS: u32 = 15;

    /// Starves once per flash: on a boot the watchdog did not cause, after
    /// fifteen ticks; never on the boot that follows.
    pub struct Proof {
        armed: bool,
        ticks: u32,
    }

    impl Proof {
        pub fn new(cause: ResetCause) -> Self {
            Self {
                armed: !matches!(cause, ResetCause::Watchdog),
                ticks: 0,
            }
        }

        pub fn starve_now(&mut self) -> bool {
            if !self.armed {
                return false;
            }
            self.ticks = self.ticks.saturating_add(1);
            self.ticks >= AFTER_TICKS
        }
    }
}
