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
//! controller reset does not lower the count (F-017).

use embassy_stm32::gpio::{Flex, Level, Output, Pull, Speed};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Ticker};
use o89_core::{
    BootLine, Clock, CutsOnPart, EnLine, Lines, ModuleBoot, ModuleReset, RailEvent, RailLine,
    RailSequencer, RecentCuts, Recovery, StrapRoute, Task,
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

/// What the link asks of the rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum RailRequest {
    /// Recover, by whatever rung the sequencer is at.
    Recover,
    /// Reset the module with the rail on: `EN` held and released, which is
    /// the boot the download window opens in, or with the strap held for
    /// the ROM's own download mode (F-038).
    ResetModule(ModuleBoot),
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
/// was applied by `main` before this task was spawned; `kept` is the
/// ladder's cuts as the part holds them, carried to this boot.
#[embassy_executor::task]
pub async fn run(mut pins: Pins, mut sequencer: RailSequencer, kept: RecentCuts) {
    let mut ticker = Ticker::every(PERIOD);
    let mut on_part = CutsOnPart::read(kept);
    loop {
        ticker.next().await;
        let now = Uptime.now();
        match REQUEST.try_take() {
            Some(RailRequest::Recover) => {
                // Planned on a copy: a cut and the count it adds are on the
                // FRAM before the sequencer moves, and a count that does not
                // land moves nothing (F-017). The ladder asks again.
                let mut planned = sequencer;
                let mut recovery = planned.recover(now);
                if let Recovery::Cycling { .. } = recovery {
                    let cuts = planned.recent_cuts(now);
                    match recorder::keep_cuts(cuts).await {
                        Ok(()) => {
                            on_part.landed(cuts);
                            sequencer = planned;
                            // The lines move at the end of this turn: the
                            // whole off time runs from here (L-111).
                            sequencer.start_cut(Uptime.now());
                        }
                        Err(why) => {
                            defmt::error!("rail: the cut's count not kept: {}; no cut", why);
                            on_part.unknown(Uptime.now());
                            recovery = Recovery::Deferred;
                        }
                    }
                } else {
                    sequencer = planned;
                }
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
                        defmt::warn!("rail: the cut deferred; the ladder asks again");
                    }
                }
                say(RailWord::Recovered(recovery));
            }
            Some(RailRequest::ResetModule(boot)) => {
                let reset = sequencer.reset_module(now, boot);
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
                say(RailWord::Reset(reset));
            }
            None => {}
        }
        if let Some(event) = sequencer.tick(now) {
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
        // A cut is kept before it is made, above; what changes here is the
        // cut this boot's reset counts, a cut that aged out, which must be
        // off the part before a boot could carry it again, and a write that
        // did not land, whose part is rewritten a retry later (F-017).
        let cuts = sequencer.recent_cuts(now);
        if on_part.due(cuts, now) {
            match recorder::keep_cuts(cuts).await {
                Ok(()) => {
                    defmt::info!("rail: {} cuts in the last hour kept", cuts.count());
                    on_part.landed(cuts);
                }
                Err(why) => {
                    defmt::error!("rail: the ladder's cuts not kept: {}", why);
                    on_part.unknown(Uptime.now());
                }
            }
        }
        pins.apply(sequencer.lines());
        check_in(Task::Rail);
    }
}
