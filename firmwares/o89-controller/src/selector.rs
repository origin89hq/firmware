//! The panel inputs; all gesture and permission decisions live in o89-core.

use crate::{link, supervisor::Uptime};
use core::cell::Cell;
use embassy_stm32::gpio::Input;
use embassy_sync::blocking_mutex::CriticalSectionMutex;
use o89_core::{Clock, Gesture, Panel, SelectorPosition};

static PANEL: CriticalSectionMutex<Cell<Panel>> =
    CriticalSectionMutex::new(Cell::new(Panel::new()));

/// Pulled-up inputs supplied by the board module.
pub struct Selector {
    pub auto: Input<'static>,
    pub manual: Input<'static>,
}

impl Selector {
    /// One bounded sample on the control task, every ten milliseconds.
    pub fn sample(&self) {
        let position = SelectorPosition::from_contacts(self.auto.is_high(), self.manual.is_high());
        let gesture = PANEL.lock(|cell| {
            let mut panel = cell.get();
            let gesture = panel.sample(position, Uptime.now());
            cell.set(panel);
            gesture
        });
        if let Some(gesture) = gesture {
            defmt::info!("selector: {}", gesture);
            match gesture {
                Gesture::Pairing | Gesture::FloorOverride => {}
                Gesture::FactoryReset => {
                    if link::request_reset().is_err() {
                        defmt::error!("selector: reset request refused; pairing stays blocked");
                    }
                }
            }
        }
    }
}

/// Read at render time; the supervisor does not cache an open-window flag.
pub fn pairing_open() -> bool {
    PANEL.lock(|cell| cell.get().pairing_open(Uptime.now()))
}

/// The link task completed the epoch/table transaction, or failed closed.
pub fn reset_finished(succeeded: bool) {
    PANEL.lock(|cell| {
        let mut panel = cell.get();
        panel.reset_finished(succeeded);
        cell.set(panel);
    });
}
