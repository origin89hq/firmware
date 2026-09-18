//! The module rail and its `EN` line, driven as `o89_core`'s sequencer says.
//!
//! Two pins, and the whole of the rule about them is elsewhere: this task
//! powers the module at boot, then asks the sequencer every 20 ms how the
//! lines should be and writes only what changed. `EN` is driven low or
//! released to the board's pull-up, never driven high, and never pulled up
//! by this part, because a pin held high into an unpowered module
//! back-powers it (F-003). The rail on revision A is on when driven high
//! and off when driven low; revision B's switch defaults on with the pin
//! high-impedance, and that mapping lands with its board.
//!
//! The ladder's recoveries arrive with the link (M3); until then nothing
//! asks for a cut, and the task's only cycle is the boot power-on.

use embassy_stm32::gpio::{Flex, Level, Output, Pull, Speed};
use embassy_time::{Duration, Ticker};
use o89_core::{Clock, EnLine, Lines, RailEvent, RailLine, RailSequencer, Task};

use crate::board::REVISION;
use crate::supervisor::{Uptime, check_in};

/// How often the sequencer is asked. Its phases are 100 ms and up.
const PERIOD: Duration = Duration::from_millis(20);

/// The two pins, as the sequencer's lines.
pub struct Pins {
    rail: Output<'static>,
    en: Flex<'static>,
    applied: Lines,
}

impl Pins {
    /// Take the pins in their reset state: the rail off, `EN` an input.
    #[must_use]
    pub fn new(rail: Output<'static>, en: Flex<'static>) -> Self {
        Self {
            rail,
            en,
            applied: Lines {
                rail: RailLine::Off,
                en: EnLine::Released,
            },
        }
    }

    /// Write what changed, `EN` before the rail on the way down and the
    /// rail before `EN` on the way up, which is the order that never lets
    /// the module see its rail without its reset held.
    fn apply(&mut self, lines: Lines) {
        if lines == self.applied {
            return;
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
        self.applied = lines;
    }
}

/// The rail task: the boot power-on, then the sequencer's lines.
#[embassy_executor::task]
pub async fn run(mut pins: Pins) {
    let mut sequencer = RailSequencer::new(REVISION);
    pins.apply(sequencer.power_on(Uptime.now()));
    defmt::info!("rail: powering the module, EN held low");
    let mut ticker = Ticker::every(PERIOD);
    loop {
        ticker.next().await;
        let now = Uptime.now();
        if let Some(event) = sequencer.tick(now) {
            match event {
                RailEvent::Settled => defmt::info!("rail: settled, EN released"),
                RailEvent::PowerCycled { count } => {
                    defmt::warn!("rail: power cycled, {} in the last hour", count);
                }
                RailEvent::Unrecoverable => {
                    defmt::error!("rail: left on; comms unrecoverable");
                }
            }
        }
        pins.apply(sequencer.lines());
        check_in(Task::Rail);
    }
}
