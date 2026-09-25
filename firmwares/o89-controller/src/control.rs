//! The control executor, and the control tick that runs on it.
//!
//! **Every task that times anything runs here, above thread mode** (P-243).
//! Thread mode is the lowest priority a Cortex-M0+ has, so it is left to the
//! one job that may take a second and a half, key agreement, which every
//! task here preempts. The tasks here share this executor cooperatively,
//! exactly as they shared the thread executor before; what changed is that
//! nothing on it computes an X25519.
//!
//! The executor is driven by `USB_UCPD1_2`, whose peripherals board A never
//! uses (`PA11` and `PA12` stay untouched), at the lowest priority, `P3`.
//! The supervisor's executor sits one above at `P2`, so a task that blocks
//! this executor is still named in the last words before the watchdog
//! fires; the time driver and every bus interrupt are above both.
//!
//! The control tick holds every output this image drives at its declared
//! fail state for the life of the part: they are moved in here, and this
//! task never returns.

use embassy_executor::{InterruptExecutor, SendSpawner};
use embassy_futures::select::{Either, select};
use embassy_stm32::gpio::{Input, Output};
use embassy_stm32::interrupt;
use embassy_stm32::interrupt::{InterruptExt, Priority};
use embassy_time::{Duration, Ticker};
use o89_core::{Contact, Feedback, LastWords, Task};

use crate::selector::Selector;
use crate::supervisor::check_in;

/// The control executor, driven by the `USB_UCPD1_2` interrupt.
static EXECUTOR: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
fn USB_UCPD1_2() {
    // SAFETY: the one place this executor is polled, from the interrupt
    // `start` unmasked for it and nowhere else.
    unsafe { EXECUTOR.on_interrupt() }
}

/// Start the control executor, below the supervisor's and above thread
/// mode, and hand back what spawns onto it.
pub fn start() -> SendSpawner {
    interrupt::USB_UCPD1_2.set_priority(Priority::P3);
    EXECUTOR.start(interrupt::USB_UCPD1_2)
}

/// Every output this image drives, at its declared fail state.
#[expect(
    dead_code,
    reason = "held and never read: each output stays at its declared level while this lives, and it lives for the part's life"
)]
pub struct Held {
    /// `RUN`.
    pub run: Output<'static>,
    /// `KICK`.
    pub kick: Output<'static>,
    /// The three RS-485 transmit lines, until each bus takes its own.
    pub rs485_tx: [Output<'static>; 3],
}

/// The control tick, 1 Hz. Nothing decides yet; it reads the generator's
/// contact, samples the selector every 10 ms, and checks in.
#[embassy_executor::task]
pub async fn run(
    held: Held,
    feedback: Input<'static>,
    selector: Selector,
    words: Option<LastWords>,
) {
    let _held = held;
    let mut contact: Option<Contact> = None;
    let mut ticker = Ticker::every(Duration::from_secs(1));
    let mut samples = Ticker::every(Duration::from_millis(10));
    #[cfg(feature = "bench")]
    let mut proof = bench::Proof::new(words);
    #[cfg(not(feature = "bench"))]
    let _ = words;
    loop {
        match select(ticker.next(), samples.next()).await {
            Either::First(()) => {}
            Either::Second(()) => {
                selector.sample();
                continue;
            }
        }
        let seen = Feedback::contact(feedback.is_high());
        if contact != Some(seen) {
            defmt::info!("generator contact: {}", seen);
            contact = Some(seen);
        }
        #[cfg(feature = "bench")]
        match proof.tick() {
            bench::Step::Run => {}
            bench::Step::Starve => {
                defmt::warn!(
                    "watchdog proof: the control tick blocks its executor on purpose; the part resets in about 8 s and the next boot names it"
                );
                // A spin, not a yield: the whole control executor is held,
                // and only the supervisor above it can still name this task.
                loop {
                    cortex_m::asm::nop();
                }
            }
            bench::Step::Panic => {
                defmt::warn!(
                    "panic proof: panicking on purpose; the part resets and the next boot names the site"
                );
                bench::panic_on_purpose();
            }
        }
        check_in(Task::Control);
    }
}

/// The one-shot proofs that show the safety floor on the bench.
#[cfg(feature = "bench")]
mod bench {
    use o89_core::LastWords;

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

    /// Which proof this boot runs, from what the previous run left: nothing
    /// means this boot starves; a blame means the watchdog just fired, so
    /// this boot panics; a panic site means the chain is done and this boot
    /// runs. The last words rather than the reset cause, because a reset the
    /// probe requests reads as a software reset, the same as the one after
    /// a panic. The three records in a row are the evidence.
    pub struct Proof {
        step: Step,
        ticks: u32,
    }

    impl Proof {
        pub fn new(words: Option<LastWords>) -> Self {
            let step = match words {
                None => Step::Starve,
                Some(LastWords::Starved(_)) => Step::Panic,
                Some(LastWords::Panicked(_)) => Step::Run,
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
