//! The controller's one site: the store every reading lands in, the
//! descriptors that say what each is, and the concern table.
//!
//! The bus tasks write it, the link task's sessions answer clients out of
//! it, and the recorder asks it once a plane period for the records its
//! changes owe. All three reach it through [`Shared`], which holds the lock
//! for one synchronous call and reads the tick inside it, so no reading is
//! asked about at a tick older than its last write and no lock is held
//! across an await.
//!
//! The ring belongs to the recorder, so a session's read of the log goes
//! to it as a [`LogWant`] and comes back as a batch, one at a time.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::channel::Channel;
use km43::TopologyChangeReason;
use o89_core::{Clock, LogBatch, LogTicket, LogWant, Site, SiteCell, Tick};
use static_cell::StaticCell;

use crate::supervisor::Uptime;

/// Where the site lives: uninitialised memory until [`boot`] builds it, so
/// its twelve kilobytes are zeroed RAM and not an initialiser in flash.
static SITE: StaticCell<Mutex<CriticalSectionRawMutex, RefCell<Site>>> = StaticCell::new();

/// The one site, however many hold it.
#[derive(Clone, Copy)]
pub struct Shared(&'static Mutex<CriticalSectionRawMutex, RefCell<Site>>);

impl SiteCell for Shared {
    fn with<R>(&self, with: impl FnOnce(&mut Site, Tick) -> R) -> R {
        self.0
            .lock(|site| with(&mut site.borrow_mut(), Uptime.now()))
    }
}

/// The read of the log the sessions want, one at a time: the sessions hold
/// one out and ask for the next only when it is answered or given up.
pub static WANTS: Channel<CriticalSectionRawMutex, LogWant, 1> = Channel::new();

/// The recorder's answer to [`WANTS`].
pub static BATCHES: Channel<CriticalSectionRawMutex, (LogTicket, LogBatch), 1> = Channel::new();

/// The site, built once, at the boot's revision of the topology before any
/// configuration names a bus: revision 1 and the `0x0901` a boot owes
/// (P-213). The configured buses, devices and signals arrive with #196, in
/// this same batch. Called once, from `main`, as `fram::share` is.
pub fn boot() -> Shared {
    let site = Shared(SITE.init_with(|| Mutex::new(RefCell::new(Site::new()))));
    let applied = site.with(|site, _| site.apply(TopologyChangeReason::Boot, &[]));
    if let Err(error) = applied {
        defmt::error!("site: the boot topology was refused: {}", error);
    }
    site
}
