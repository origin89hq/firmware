//! The controller's one site: the store every reading lands in, the
//! descriptors that say what each is, and the concern table.
//!
//! The bus tasks write it, the link task's sessions answer clients out of
//! it, and the recorder asks it once a plane period for the records its
//! changes owe. All three run on the control executor and reach it through
//! [`Shared`]: an async mutex taken with `try_lock` for one synchronous
//! call, the tick read while it is held, and never held across an await.
//! No interrupt is masked while a page is built or a digest computed, and
//! on one cooperative executor a holder always finishes before another
//! task runs, so `try_lock` finds it free; if it ever does not, the caller
//! answers a retry (`SiteBusy`) rather than wait.
//!
//! The ring belongs to the recorder, so a session's read of the log goes
//! to it as a [`LogWant`] and comes back as a batch, one at a time.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use km43::TopologyChangeReason;
use o89_core::{Clock, LogBatch, LogTicket, LogWant, Site, SiteBusy, SiteCell, Tick};
#[cfg(feature = "buses")]
use o89_core::{Configuration, Descriptor, Held};
#[cfg(feature = "buses")]
use o89_drivers::plan::{Plan, ROWS};
use static_cell::StaticCell;

use crate::supervisor::Uptime;

/// Where the site lives: uninitialised memory until [`boot`] builds it, so
/// its twelve kilobytes are zeroed RAM and not an initialiser in flash.
static SITE: StaticCell<Mutex<CriticalSectionRawMutex, Site>> = StaticCell::new();

/// The one site, however many hold it.
#[derive(Clone, Copy)]
pub struct Shared(&'static Mutex<CriticalSectionRawMutex, Site>);

impl SiteCell for Shared {
    fn with<R>(&self, with: impl FnOnce(&mut Site, Tick) -> R) -> Result<R, SiteBusy> {
        let mut site = self.0.try_lock().map_err(|_| SiteBusy)?;
        Ok(with(&mut site, Uptime.now()))
    }
}

/// The read of the log the sessions want, one at a time: the sessions hold
/// one out and ask for the next only when it is answered or given up. The
/// recorder waits on it and answers at once, not on its ticker.
pub static WANTS: Channel<CriticalSectionRawMutex, LogWant, 1> = Channel::new();

/// The recorder's answer to [`WANTS`].
pub static BATCHES: Channel<CriticalSectionRawMutex, (LogTicket, LogBatch), 1> = Channel::new();

/// The site, built once, at the boot's revision of the topology before any
/// configuration names a bus: revision 1 and the `0x0901` a boot owes
/// (P-213). Without the bus tasks, no bus, device or signal is configured.
/// Called once, from `main`, as `fram::share` is.
#[cfg(not(feature = "buses"))]
pub fn boot() -> Shared {
    let site = Shared(SITE.init_with(|| Mutex::new(Site::new())));
    match site.with(|site, _| site.apply(TopologyChangeReason::Boot, &[])) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => defmt::error!("site: the boot topology was refused: {}", error),
        Err(SiteBusy) => defmt::error!("site: held before any task ran"),
    }
    site
}

/// The section of buses and devices on the part, built: an absent or
/// damaged section, or one the plan refuses, is no configured device, said
/// so in the log, never a partial site.
#[cfg(feature = "buses")]
#[inline(never)]
pub fn plan(configuration: &Configuration) -> Plan {
    let record = match configuration.buses().held() {
        Held::Present(record) => record,
        Held::Absent => return Plan::EMPTY,
        Held::Corrupt | Held::Malformed(_) => {
            defmt::error!("site: the buses and devices section is damaged; no device runs");
            return Plan::EMPTY;
        }
    };
    match record
        .section()
        .map_err(o89_drivers::plan::PlanError::Section)
        .and_then(|section| Plan::new(&section))
    {
        Ok(plan) => plan,
        Err(error) => {
            defmt::error!(
                "site: buses and devices section {} refused: {}; no device runs",
                record.version(),
                error
            );
            Plan::EMPTY
        }
    }
}

/// The site, built once, at the boot's revision of the topology: revision 1
/// and the `0x0901` a boot owes (P-213), with the board's buses, the
/// controller's own inputs and every configured device, component and
/// signal in the one batch. Called once, from `main`, as `fram::share` is.
/// The rows are built on this function's own frame and gone once it
/// returns.
#[cfg(feature = "buses")]
#[inline(never)]
pub fn boot(plan: &Plan) -> Shared {
    let site = Shared(SITE.init_with(|| Mutex::new(Site::new())));
    let mut rows = [Descriptor::Bus(o89_core::Connector::Local.row(None)); ROWS];
    let len = match plan.rows(&mut rows) {
        Ok(len) => len,
        Err(error) => {
            defmt::error!("site: the boot's rows did not build: {}", error);
            0
        }
    };
    let batch = rows.get(..len).unwrap_or(&[]);
    match site.with(|site, _| site.apply(TopologyChangeReason::Boot, batch)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => defmt::error!("site: the boot topology was refused: {}", error),
        Err(SiteBusy) => defmt::error!("site: held before any task ran"),
    }
    site
}
