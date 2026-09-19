//! The module rail and its `EN` line, driven as `o89_core`'s sequencer says.
//!
//! Two pins, and the whole of the rule about them is elsewhere: `main`
//! applies the sequencer's boot lines before this task exists, so there is
//! no instant between the pins being taken and `EN` being held; the task
//! then asks the sequencer every 20 ms how the lines should be and writes
//! only what changed. `EN` is driven low or
//! released to the board's pull-up, never driven high, and never pulled up
//! by this part, because a pin held high into an unpowered module
//! back-powers it (F-003). The rail on revision A is on when driven high
//! and off when driven low; revision B's switch defaults on with the pin
//! high-impedance, and that mapping lands with its board.
//!
//! The ladder's recoveries come from the link task, which drops its UART
//! before asking so the lines into the module are inputs before the rail
//! goes (F-003); what the sequencer answered, and every settling of the
//! rail, go back to it as words on a bounded channel. The ladder's cuts of
//! the last hour go to the FRAM through the recorder whenever they change,
//! before the lines move, so a cut is kept before the rail goes off and a
//! controller reset does not lower the count (F-017). The task never waits
//! on the recorder: what a turn does, and in what order, is `o89_core`'s
//! [`Rail`], and this task only carries its request, its answer and its
//! words.

use embassy_stm32::gpio::{Flex, Level, Output, Pull, Speed};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Ticker};
use o89_core::{
    BootLine, Clock, EnLine, Lines, ModuleBoot, ModuleReset, Rail, RailEvent, RailLine,
    RailRequest, Recovery, StrapRoute, Task,
};

use crate::REVISION;
use crate::recorder;
use crate::supervisor::{Uptime, check_in};

/// What the rail tells the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum RailWord {
    /// The rail is up and `EN` released: the module is booting.
    Settled,
    /// What a recovery request did.
    Recovered(Recovery),
    /// What a module reset did.
    Reset(ModuleReset),
}

/// The link's request. One at a time: a second before the first is served
/// replaces it, which the link never does.
static REQUEST: Signal<CriticalSectionRawMutex, RailRequest> = Signal::new();

/// The words to the link. Four deep: a recovery answers at most one word
/// and settles at most once, and a word that does not fit is logged, not
/// evicted.
static WORDS: Channel<CriticalSectionRawMutex, RailWord, 4> = Channel::new();

/// Ask the rail task to recover the module.
pub fn request_recovery() {
    REQUEST.signal(RailRequest::Recover);
}

/// Ask the rail task to reset the module into `boot`, the rail staying on.
pub fn request_module_reset(boot: ModuleBoot) {
    REQUEST.signal(RailRequest::ResetModule(boot));
}

/// The rail's words, for the link task to receive.
pub fn words() -> &'static Channel<CriticalSectionRawMutex, RailWord, 4> {
    &WORDS
}

fn say(word: RailWord) {
    if WORDS.try_send(word).is_err() {
        defmt::error!("rail: the link did not take {}; the word is lost", word);
    }
}

/// How often the sequencer is asked. Its phases are 100 ms and up.
const PERIOD: Duration = Duration::from_millis(20);

/// The two pins, as the sequencer's lines.
pub struct Pins {
    rail: Output<'static>,
    en: Flex<'static>,
    boot: Flex<'static>,
    applied: Lines,
}

impl Pins {
    /// Take the pins in their reset state: the rail off, `EN` an input.
    #[must_use]
    pub fn new(rail: Output<'static>, en: Flex<'static>, boot: Flex<'static>) -> Self {
        Self {
            rail,
            en,
            boot,
            applied: Lines {
                rail: RailLine::Off,
                en: EnLine::Released,
                boot: BootLine::Released,
            },
        }
    }

    /// Write what changed, `EN` before the rail on the way down and the
    /// rail before `EN` on the way up, which is the order that never lets
    /// the module see its rail without its reset held.
    pub fn apply(&mut self, lines: Lines) {
        if lines == self.applied {
            return;
        }
        // The strap goes low before the reset it is read at, and back to an
        // input only after it (F-003: low or an input, never high).
        if lines.boot == BootLine::HeldLow && self.applied.boot != BootLine::HeldLow {
            self.boot.set_low();
            self.boot.set_as_output(Speed::Low);
        }
        match lines.en {
            EnLine::HeldLow if self.applied.en != EnLine::HeldLow => {
                self.en.set_low();
                self.en.set_as_output(Speed::Low);
            }
            EnLine::HeldLow | EnLine::Released => {}
        }
        match lines.rail {
            RailLine::On => self.rail.set_level(Level::High),
            RailLine::Off => self.rail.set_level(Level::Low),
        }
        if lines.en == EnLine::Released && self.applied.en != EnLine::Released {
            self.en.set_as_input(Pull::None);
        }
        if lines.boot == BootLine::Released && self.applied.boot != BootLine::Released {
            self.boot.set_as_input(Pull::None);
        }
        self.applied = lines;
    }
}

/// The rail task: the sequencer's lines from here on. The boot power-on
/// was applied by `main` before this task was spawned, and the ladder's
/// cuts carried and kept. A boot with no store has no link either (F-039),
/// so nothing asks it for a cut; were one asked, the recorder would refuse
/// its count and the cut would be deferred, because a count held only here
/// is one a later boot that reads the part does not carry (F-017).
#[embassy_executor::task]
pub async fn run(mut pins: Pins, mut rail: Rail) {
    let mut ticker = Ticker::every(PERIOD);
    let mut keeper = recorder::CutsKeeper::new();
    loop {
        ticker.next().await;
        let now = Uptime.now();
        let answer = keeper.poll();
        if let Some((keep, kept)) = answer {
            match kept {
                Ok(()) => defmt::info!("rail: {} cuts in the last hour kept", keep.cuts().count()),
                Err(why) => defmt::error!("rail: the ladder's cuts not kept: {}", why),
            }
        }
        let request = REQUEST.try_take();
        let turn = rail.turn(now, request, answer);
        if let Some(recovery) = turn.recovered {
            answer_recovery(recovery);
        }
        // A reset is only ever the answer to a request for one.
        if let (Some(reset), Some(RailRequest::ResetModule(boot))) = (turn.reset, request) {
            log_reset(reset, boot);
            say(RailWord::Reset(reset));
        }
        if let Some(event) = turn.event {
            match event {
                RailEvent::Settled => {
                    defmt::info!("rail: settled, EN released");
                    say(RailWord::Settled);
                }
                RailEvent::PowerCycled { count } => {
                    defmt::warn!("rail: power restored, {} cycles in the last hour", count);
                }
                RailEvent::Unrecoverable => {
                    defmt::error!("rail: left on; comms unrecoverable");
                }
            }
        }
        if let Some(keep) = turn.keep {
            keeper.hand(keep);
        }
        pins.apply(rail.lines());
        check_in(Task::Rail);
    }
}

/// Log what a module reset into `boot` did.
fn log_reset(reset: ModuleReset, boot: ModuleBoot) {
    match (reset, boot) {
        (ModuleReset::Holding, ModuleBoot::Normal) => {
            defmt::info!("rail: resetting the module, EN held");
        }
        (ModuleReset::Holding, ModuleBoot::Download) => match REVISION.strap_route() {
            StrapRoute::NeedsIo8Wire => defmt::warn!(
                "rail: resetting the module with IO9 low; this revision needs IO8 held high by a wire"
            ),
            StrapRoute::Wired => {
                defmt::info!("rail: resetting the module with IO9 low, EN held");
            }
        },
        (ModuleReset::NotPowered, ModuleBoot::Normal | ModuleBoot::Download) => {
            defmt::warn!("rail: no module to reset");
        }
    }
}

/// Tell the link what its recovery request did.
fn answer_recovery(recovery: Recovery) {
    match recovery {
        Recovery::Cycling { count, off_for } => defmt::warn!(
            "rail: cutting for {} ms, cycle {} in the last hour",
            off_for.as_millis(),
            count
        ),
        Recovery::LeftOnAndRaised => {
            defmt::error!("rail: the third rung; left on, comms unrecoverable");
        }
        Recovery::Busy => defmt::warn!("rail: a cycle is already in progress"),
        Recovery::Deferred => {
            defmt::warn!(
                "rail: the cut deferred, its count not kept or the module reset; the ladder asks again"
            );
        }
    }
    say(RailWord::Recovered(recovery));
}
