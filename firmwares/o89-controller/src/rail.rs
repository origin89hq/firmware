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
    // Never returns: the experiment owns the pins for the life of the
    // image (#62). The sequencer below it is the production path and is
    // compiled beside it, which is what keeps this image honest about
    // being the same firmware with one thing replaced.
    #[cfg(feature = "rail-fault")]
    fault_cycle(&mut pins).await;
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

/// Say whether the edge disturbed anything.
#[cfg(feature = "rail-fault")]
fn report_disturbance(trial: u32, page: usize, disturbed: u32, first_at: usize, cleared: u32) {
    if disturbed > 0 || cleared > 0 {
        defmt::error!(
            "rail fault: trial {}, RAM DISTURBED: {} of {} canary bytes wrong, first at {}, {} clears left rubbish",
            trial,
            disturbed,
            page,
            first_at,
            cleared
        );
    } else {
        defmt::info!(
            "rail fault: trial {}, {} canary bytes intact and every clear held across the edge",
            trial,
            page
        );
    }
}

/// What a canary byte should hold at `at`. Not a constant fill: a pattern
/// that differs byte to byte catches a run written from somewhere else,
/// which a page of one value would hide.
#[cfg(feature = "rail-fault")]
fn stamp_of(at: usize) -> u8 {
    // `at` indexes a 1 KiB page; its low byte is all this needs, and
    // taking it by truncation rather than by a cast keeps the lint that
    // watches casts meaningful elsewhere.
    let low = u8::try_from(at & 0xff).unwrap_or(0);
    low.wrapping_mul(31).wrapping_add(7)
}

/// Read the canary back: how many bytes are not what was stamped, and
/// where the first of them is.
#[cfg(feature = "rail-fault")]
fn canary_read_back(canary: &[u8]) -> (u32, usize) {
    let mut disturbed = 0u32;
    let mut first_at = 0usize;
    for (at, byte) in canary.iter().enumerate() {
        if *byte != stamp_of(at) {
            if disturbed == 0 {
                first_at = at;
            }
            disturbed = disturbed.saturating_add(1);
        }
    }
    (disturbed, first_at)
}

/// Clear and re-read `scratch` flat out until `until`, counting the
/// clears that left something behind (#62).
///
/// No await in it: the fault arrives within milliseconds of the line
/// moving, and a loop that yielded would be somewhere else when it did.
/// This is the shape of the work `__aeabi_memclr8` was doing in
/// origin89hq/hardware#5 when it took a branch its code cannot produce.
#[cfg(feature = "rail-fault")]
fn busy_until_checked(scratch: &mut [u8], until: embassy_time::Instant) -> u32 {
    let mut cleared = 0u32;
    while embassy_time::Instant::now() < until {
        scratch.fill(0xa5);
        scratch.fill(0);
        if scratch.iter().any(|byte| *byte != 0) {
            cleared = cleared.saturating_add(1);
        }
    }
    cleared
}

/// The rail switch-on fault (#62).
///
/// origin89hq/hardware#5 is that driving `PC5` high after the module rail
/// has been off for ten minutes corrupts this part within milliseconds, 22
/// of 22 times, while the module is still in its ROM. Revision B answers it
/// with a slew-limited switch on the assumption that inrush is the cause,
/// and that assumption has never been measured.
///
/// This holds the rail off for the ten minutes the fault needs, drives it
/// on, and says what the detector saw across the edge. Nothing here decides
/// anything: the sequencer and the ladder do not run while it does, because
/// it owns the pins instead of them.
#[cfg(feature = "rail-fault")]
async fn fault_cycle(pins: &mut Pins) {
    use crate::pvd;
    use embassy_time::{Instant, Timer};

    /// How long the rail is off before the edge. The fault needs ten
    /// minutes; `hardware#5` found nothing at shorter times, and the
    /// sessions of the 19th and 20th cycled it for five seconds all day
    /// without once reproducing it.
    const OFF: Duration = Duration::from_secs(600);
    /// How long the edge is watched closely before the trial is called.
    const WATCH: Duration = Duration::from_secs(2);
    /// How long the rail stays on between trials.
    const ON: Duration = Duration::from_secs(10);
    /// How long the CPU works flat out across the edge, with no await in
    /// it: the fault arrives within milliseconds of the line moving.
    const BUSY: Duration = Duration::from_millis(50);
    /// The page stamped before the edge and read back after.
    const CANARY: usize = 1024;
    /// The buffer cleared and checked in the busy loop. 264 bytes is the
    /// size of the one `__aeabi_memclr8` was zeroing in #5.
    const SCRATCH: usize = 264;

    // `EN` and `BOOT` are left as inputs throughout, which is what the
    // self-test that found the fault did: origin89hq/hardware#5 says
    // nothing holds the rail up after ten minutes "since the self-test
    // leaves the module's EN and BOOT pins untouched", and every fault it
    // saw came while the module was up in its ROM. Holding `EN` low would
    // keep the module in reset, draw a different current at switch-on and
    // reproduce a different experiment.
    let off = Lines {
        rail: RailLine::Off,
        en: EnLine::Released,
        boot: BootLine::Released,
    };
    let on = Lines {
        rail: RailLine::On,
        en: EnLine::Released,
        boot: BootLine::Released,
    };
    pvd::latch_crossings();
    let mut canary = [0u8; CANARY];
    let mut scratch = [0u8; SCRATCH];
    let mut trial: u32 = 0;
    // Bounded by the bench: it runs until the part is reflashed, and each
    // turn is `OFF + WATCH + ON`.
    loop {
        trial = trial.saturating_add(1);
        pins.apply(off);
        defmt::info!(
            "rail fault: trial {}, the rail is off for {} s",
            trial,
            OFF.as_secs()
        );
        let Some(until) = Instant::now().checked_add(OFF) else {
            continue;
        };
        // Bounded by `OFF`; the roll is kept through the wait, because a
        // task that stops checking in is a part the watchdog resets and
        // this one waits ten minutes on purpose.
        while Instant::now() < until {
            check_in(Task::Rail);
            Timer::after(PERIOD).await;
        }
        // Stamped last, so the page holds this trial's pattern and not a
        // previous trial's when the edge arrives.
        for (at, byte) in canary.iter_mut().enumerate() {
            *byte = stamp_of(at);
        }
        // USART1 up before the edge, with the module unpowered and
        // holding the line low. #5 names the receive path as a suspect it
        // could not exclude precisely because the self-test enabled the
        // UART just before `PC5` went high; the production order is the
        // other way round, so an experiment that kept it would be testing
        // the one arrangement the fault was never seen in.
        // Stamped last, so the page holds this trial's pattern and not a
        // previous trial's when the edge arrives.
        for (at, byte) in canary.iter_mut().enumerate() {
            *byte = stamp_of(at);
        }
        say(RailWord::Settled);
        Timer::after(Duration::from_millis(200)).await;
        // Cleared at the last instant, so what the flags hold afterwards
        // is this edge and nothing before it.
        pvd::clear_crossings();
        let below_before = pvd::supply_is_below_level();
        pins.apply(on);
        defmt::info!(
            "rail fault: trial {}, PC5 driven high; below the level before the edge: {}",
            trial,
            below_before
        );
        // The work the edge lands on, and a page of RAM to land in.
        //
        // origin89hq/hardware#5 caught the fault inside `__aeabi_memclr8`
        // zeroing a 264-byte buffer "a few instructions after `PC5` goes
        // high", and in a return through a function the self-test happened
        // to be in. This firmware is doing none of that at the edge — it
        // logs and awaits a timer — so a disturbance could be arriving and
        // landing nowhere anyone would see. This gives it somewhere to
        // land: a page stamped before the edge and read back after, and a
        // scratch cleared and checked in a tight loop across it, which is
        // the shape of the work the fault was found in.
        let Some(busy_until) = Instant::now().checked_add(BUSY) else {
            continue;
        };
        let cleared = busy_until_checked(&mut scratch, busy_until);
        let (disturbed, first_at) = canary_read_back(&canary);
        let Some(until) = Instant::now().checked_add(WATCH) else {
            continue;
        };
        while Instant::now() < until {
            check_in(Task::Rail);
            Timer::after(PERIOD).await;
        }
        report_disturbance(trial, canary.len(), disturbed, first_at, cleared);
        let (rising, falling) = pvd::crossings();
        defmt::info!(
            "rail fault: trial {}, across the edge the detector latched falling={} rising={}, below now={}",
            trial,
            falling,
            rising,
            pvd::supply_is_below_level()
        );
        if !falling {
            defmt::info!(
                "rail fault: trial {}, no crossing of {} at switch-on",
                trial,
                "the level"
            );
        }
        let Some(until) = Instant::now().checked_add(ON) else {
            continue;
        };
        while Instant::now() < until {
            check_in(Task::Rail);
            Timer::after(PERIOD).await;
        }
    }
}
