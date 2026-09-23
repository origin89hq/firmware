//! Feeds the watchdog only when every task has checked in, and shows it on
//! the lamp.
//!
//! The decision is `o89_core`'s [`Rollcall`]; this owns the peripheral. Every
//! 100 ms it asks whether the feed is earned. Earned, the watchdog is petted
//! and the lamp shows the heartbeat. Withheld, the blamed task's name is
//! written to the last words once, the lamp shows the fault, and nothing
//! pets the part, which resets about eight seconds later with the blame in
//! RAM for the next boot to read (F-007, F-008).
//!
//! **It runs from an interrupt, above the thread executor.** The tasks it
//! judges are cooperative, and a bus transfer that never returns blocks
//! the executor they share; a supervisor on that executor would then never
//! run, the watchdog would still reset the part, and the boot after would
//! have no name to blame. From its own interrupt the supervisor keeps
//! running through a blocked executor, so the watchdog is the floor and
//! the blame is still written. The line is `CEC`, which nothing on this
//! board drives, at the lowest interrupt priority, so the time driver and
//! every bus come first and the supervisor never delays them.

use core::cell::Cell;

use embassy_executor::{InterruptExecutor, SpawnError};
use embassy_stm32::gpio::Output;
use embassy_stm32::interrupt;
use embassy_stm32::interrupt::{InterruptExt, Priority};
use embassy_stm32::peripherals::IWDG;
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_sync::blocking_mutex::CriticalSectionMutex;
use embassy_time::{Duration, Instant, Ticker};
use o89_core::{Blame, Clock, Feed, LastWords, Millis, Pattern, Rollcall, Task, Tick};

use crate::last_words;

/// The supervisor's own executor, driven by the `CEC` interrupt.
static EXECUTOR: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
fn CEC() {
    // SAFETY: the one place this executor is polled, from the interrupt
    // `start` unmasked for it and nowhere else.
    unsafe { EXECUTOR.on_interrupt() }
}

/// Start the supervisor on its own executor, above the thread executor.
pub fn start(
    wdg: IndependentWatchdog<'static, IWDG>,
    status: Output<'static>,
    fault: Output<'static>,
) -> Result<(), SpawnError> {
    interrupt::CEC.set_priority(Priority::P3);
    let spawner = EXECUTOR.start(interrupt::CEC);
    spawner.spawn(run(wdg, status, fault)?);
    Ok(())
}

/// How long the part may go unfed before it resets.
pub const WATCHDOG_US: u32 = 8_000_000;

/// The supervisor's own period, which is also the lamp's grid.
const PERIOD: Duration = Duration::from_millis(100);

static ROLL: CriticalSectionMutex<Cell<Rollcall>> =
    CriticalSectionMutex::<Cell<Rollcall>>::new(Cell::new(Rollcall::new()));

/// The tick since boot, from the time driver.
pub struct Uptime;

impl Clock for Uptime {
    fn now(&self) -> Tick {
        Tick::from_millis(Instant::now().as_millis())
    }
}

/// A task has completed one pass of its work, or is about to start.
pub fn check_in(task: Task) {
    let now = Uptime.now();
    ROLL.lock(|cell| {
        let mut roll = cell.get();
        roll.check_in(task, now);
        cell.set(roll);
    });
}

fn verdict(now: Tick) -> Feed {
    ROLL.lock(|cell| cell.get().verdict(now))
}

/// The supervisor task: the feed, the blame and the lamp.
#[embassy_executor::task]
pub async fn run(
    mut wdg: IndependentWatchdog<'static, IWDG>,
    mut status: Output<'static>,
    mut fault: Output<'static>,
) {
    let mut ticker = Ticker::every(PERIOD);
    let mut withheld: Option<Blame> = None;
    // When the feed was first withheld, and the last whole second reported
    // since, so the log bounds the interval to the watchdog's reset within
    // a second: the number F-016's budget is built on.
    let mut withheld_at: Option<Tick> = None;
    let mut reported_secs: u64 = 0;
    loop {
        ticker.next().await;
        let now = Uptime.now();
        match verdict(now) {
            Feed::Earned => {
                wdg.pet();
                withheld = None;
                withheld_at = None;
            }
            Feed::NobodyOnTheRoll => {
                // Not health: the part is not fed on an empty roll.
                defmt::debug!("supervisor: nobody on the roll yet");
            }
            Feed::Withheld(blame) => {
                if withheld.map(|b| b.task) != Some(blame.task) {
                    last_words::write(LastWords::Starved(blame));
                    defmt::error!(
                        "feed withheld: {} is {} ms past its window; reset follows",
                        blame.task,
                        blame.overdue.as_millis()
                    );
                }
                // The episode starts at the first withheld feed and runs
                // until the reset: a change of the task named in the middle
                // updates the last words, not the clock.
                if withheld_at.is_none() {
                    withheld_at = Some(now);
                    reported_secs = 0;
                }
                withheld = Some(blame);
            }
        }
        if let Some(since) = withheld_at
            && let Some(elapsed) = now.since(since)
        {
            let secs = elapsed.as_millis() / 1_000;
            if secs > reported_secs {
                reported_secs = secs;
                defmt::warn!("feed withheld for {} s; reset pending", secs);
            }
        }
        let pattern = if withheld.is_some() {
            Pattern::Fault
        } else if crate::selector::pairing_open() {
            Pattern::Pairing
        } else {
            // No link yet: alive with no network.
            Pattern::DoubleHeartbeat
        };
        let lamps = pattern.lamps(Millis::from_millis(now.as_millis()));
        status.set_level(lamps.status.into());
        fault.set_level(lamps.fault.into());
        check_in(Task::Supervisor);
    }
}
