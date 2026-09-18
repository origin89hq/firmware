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
//! the module rail sequence; then the control tick. The FRAM read and the
//! buses arrive with the milestones that name them. The `bench` build adds
//! the one-shot proofs: a starvation on a boot the watchdog did not cause,
//! and a panic on the boot that follows, so three boots in a row show the
//! watchdog, the blame it leaves, the panic path and the site it leaves.

#![no_std]
#![no_main]

mod board;
mod clock;
mod first;
mod last_words;
mod panic;
mod pvd;
mod rail;
mod reset;
mod supervisor;

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Flex, Level, Output, Speed};
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_time::{Duration, Ticker};
use o89_core::{
    BootRecord, Bus, Clock, FailState, LastWords, Line, RailSequencer, ResetCause, RtcClock, Task,
};

use crate::board::{Board, REVISION};
use crate::supervisor::Uptime;

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

    // 9. The module rail sequence: the module powered with EN held low,
    // released once the rail has settled. The boot lines are applied here,
    // before the task exists, so EN is held from the instant the pins are
    // taken and the rail never rises with the module's reset released.
    let mut rail = rail::Pins::new(
        Output::new(b.module.rail, Level::Low, Speed::Low),
        Flex::new(b.module.en),
    );
    let mut sequencer = RailSequencer::new(REVISION);
    rail.apply(sequencer.power_on(Uptime.now()));
    defmt::info!("rail: powering the module, EN held low");
    supervisor::check_in(Task::Rail);
    // The rail is on the roll from the check-in above, so a task that did
    // not spawn is one that stops checking in: the watchdog resets the part.
    if let Ok(token) = rail::run(rail, sequencer) {
        spawner.spawn(token);
    } else {
        defmt::error!("the rail task did not spawn; the watchdog will reset the part");
    }

    // 10. The control tick, 1 Hz. Nothing decides yet; it checks in.
    supervisor::check_in(Task::Control);
    let mut ticker = Ticker::every(Duration::from_secs(1));
    #[cfg(feature = "bench")]
    let mut proof = bench::Proof::new(cause);
    loop {
        ticker.next().await;
        #[cfg(feature = "bench")]
        match proof.tick() {
            bench::Step::Run => {}
            bench::Step::Starve => {
                defmt::warn!(
                    "watchdog proof: the control tick stops checking in on purpose; the part resets in about 8 s and the next boot names it"
                );
                loop {
                    ticker.next().await;
                }
            }
            bench::Step::Panic => {
                defmt::warn!(
                    "panic proof: panicking on purpose; the part resets and the next boot names the site"
                );
                bench::panic_on_purpose();
            }
        }
        supervisor::check_in(Task::Control);
    }
}

/// The one-shot proofs that show the safety floor on the bench.
#[cfg(feature = "bench")]
mod bench {
    use o89_core::ResetCause;

    /// Seconds of ordinary running before a proof.
    const AFTER_TICKS: u32 = 15;

    /// What the control tick does this second.
    pub enum Step {
        /// Check in as usual.
        Run,
        /// Stop checking in: the watchdog proof.
        Starve,
        /// Panic: the panic-path proof.
        Panic,
    }

    /// Which proof this boot runs, from what reset it: a boot the watchdog
    /// did not cause starves; the boot after a watchdog reset panics; the
    /// boot after a software reset runs, and the three records in a row are
    /// the evidence.
    pub struct Proof {
        step: Step,
        ticks: u32,
    }

    impl Proof {
        pub fn new(cause: ResetCause) -> Self {
            let step = match cause {
                ResetCause::Watchdog => Step::Panic,
                ResetCause::Software => Step::Run,
                ResetCause::Power
                | ResetCause::Pin
                | ResetCause::WindowWatchdog
                | ResetCause::LowPower
                | ResetCause::OptionByte => Step::Starve,
            };
            Self { step, ticks: 0 }
        }

        /// One second passed: the proof's step once its time has come, and
        /// `Run` before.
        pub fn tick(&mut self) -> Step {
            self.ticks = self.ticks.saturating_add(1);
            if self.ticks < AFTER_TICKS {
                return Step::Run;
            }
            match self.step {
                Step::Run => Step::Run,
                Step::Starve => Step::Starve,
                Step::Panic => Step::Panic,
            }
        }
    }

    /// The panic-path proof: the production handler writes the site to the
    /// last words and resets, and the next boot reports it.
    #[expect(
        clippy::panic,
        reason = "the one deliberate panic in the firmware, in the bench build alone, to prove the path a real one takes"
    )]
    pub fn panic_on_purpose() -> ! {
        panic!("the panic proof");
    }
}
