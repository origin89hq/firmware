//! The one task that owns the FRAM and the NOR.
//!
//! The store was read in `main`, before any output moved, because the run
//! reason has to be known before the contact is (F-022, F-016); this task
//! takes it from there. It identifies the NOR, opens the ring, writes the
//! boot record, and from then on holds both parts for whoever asks: the
//! requests arrive with the milestones that make them (M4's counters, M5's
//! configuration, the event queue). A board whose NOR does not answer
//! still has its store; the ring is simply absent and says so. The rail
//! task hands it the recovery ladder's cuts to keep before the rail goes
//! off, and polls for the answer without waiting on it (F-017).
//!
//! cites: F-023

use core::num::NonZeroU32;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, TrySendError};
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Ticker};

use km43::{
    BOOT_MAX_BYTES, Boot, CONTROLLER_RECORD_MAX_BYTES, ControllerRecord, Event, EventKind, LogSeq,
    MAX_EVENT_QUEUE,
};
use o89_core::{
    Class, CutsRecord, Keep, KeepAnswer, LinkEvent, MAX_PAYLOAD, NotKept, RecentCuts, Ring,
    SCRATCH, Store, Task,
};

use crate::fram::Fram;
use crate::mailbox;
use crate::nor::{JEDEC, Nor, SECTOR};
use crate::supervisor::check_in;

/// The ring's span: 14.5 MiB of the 16, in sectors. The rest is for the
/// aggregates and, later, the last authorised comms image.
pub const RING_BLOCKS: u32 = 3712;
const _: () = assert!((RING_BLOCKS as usize) * SECTOR <= 16 * 1024 * 1024);

/// How often the task looks at the mailbox and checks in; its window on
/// the roll is thirty seconds.
const PERIOD: Duration = Duration::from_millis(100);

/// Events waiting for the ring, from the tasks that raise them. As deep
/// as the protocol's event queue; a task whose event does not fit is told
/// so and says so, and nothing is evicted.
static EVENTS: Channel<CriticalSectionRawMutex, LinkEvent, MAX_EVENT_QUEUE> = Channel::new();

/// At most one reset waits for the FRAM owner. A full queue refuses;
/// requests never replace an earlier physical act.
static RESETS: Channel<CriticalSectionRawMutex, (), 1> = Channel::new();

/// Queue a physical reset. The panel has already closed enrolment.
pub fn request_reset() -> Result<(), TrySendError<()>> {
    RESETS.try_send(())
}

/// The recovery ladder's cuts, to be kept on the FRAM before the rail
/// moves, under the request's number. One at a time: a request the
/// recorder has not taken is replaced by the next.
static CUTS: Signal<CriticalSectionRawMutex, (u32, RecentCuts)> = Signal::new();

/// The answer to [`CUTS`], under the number of the request it answers.
static CUTS_KEPT: Signal<CriticalSectionRawMutex, (u32, Result<(), NotKept>)> = Signal::new();

/// How long the rail task gives the cuts to land: a write the recorder
/// takes at once, behind at most one ring append or mailbox request, and an
/// append may erase a NOR sector first, 400 ms at most on the W25Q128JV.
const KEEP_DEADLINE: Duration = Duration::from_millis(2_000);

/// The rail task's side of keeping the ladder's cuts: each request
/// numbered, so an answer to one abandoned late is never taken for the
/// answer to the next.
pub struct CutsKeeper {
    next: u32,
    in_flight: Option<InFlight>,
}

/// A keep started and not yet answered.
#[derive(Clone, Copy)]
struct InFlight {
    request: u32,
    keep: Keep,
    deadline: Option<Instant>,
}

impl CutsKeeper {
    /// No request made yet.
    pub const fn new() -> Self {
        Self {
            next: 0,
            in_flight: None,
        }
    }

    fn ask(&mut self, keep: Keep) {
        let request = self.next;
        self.next = self.next.wrapping_add(1);
        CUTS.signal((request, keep.cuts()));
        self.in_flight = Some(InFlight {
            request,
            keep,
            deadline: Instant::now().checked_add(KEEP_DEADLINE),
        });
    }

    /// Hand the recorder `keep`. A cut's count supersedes the keep in
    /// flight, whose answer is passed over, because the recorder writes in
    /// order and the part ends with these; any other keep waits for none
    /// to be in flight, and the rail asks for it again next turn.
    pub fn hand(&mut self, keep: Keep) {
        match keep {
            Keep::Cut(_) => self.ask(keep),
            Keep::Changed(_) => {
                if self.in_flight.is_none() {
                    self.ask(keep);
                }
            }
        }
    }

    /// The answer to the keep in flight, once it has come or its deadline
    /// has passed; a request the recorder has not taken by then is
    /// withdrawn, and one it took may still land, which the rail counts as
    /// not knowing what the part holds. Never waits: the rail task serves
    /// a module reset while the recorder is busy, as it is while a bench
    /// download holds the link.
    pub fn poll(&mut self) -> Option<KeepAnswer> {
        let flight = self.in_flight?;
        if let Some((answered, kept)) = CUTS_KEPT.try_take()
            && answered == flight.request
        {
            self.in_flight = None;
            return Some((flight.keep, kept));
        }
        if flight
            .deadline
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            CUTS.reset();
            self.in_flight = None;
            return Some((flight.keep, Err(NotKept::Late)));
        }
        None
    }
}

/// Queue an event for the ring, or hand it back when the queue is full.
pub fn post(event: LinkEvent) -> Result<(), LinkEvent> {
    EVENTS.try_send(event).map_err(|refused| match refused {
        TrySendError::Full(event) => event,
    })
}

/// The recorder task: the only owner of the FRAM and the NOR, and so the
/// one that serves the bench tool's mailbox.
#[embassy_executor::task]
pub async fn run(mut store: Option<Store>, mut fram: Fram, mut nor: Nor, boot: Boot) {
    let mut scratch = [0u8; SCRATCH];
    defmt::info!("recorder: identifying the NOR");
    let jedec = nor.jedec().await;
    defmt::info!("recorder: identification answered {}", jedec);
    let ring = match jedec {
        Ok(JEDEC) => {
            defmt::info!("recorder: opening the ring");
            let opened = Ring::open(nor, 0, RING_BLOCKS, &mut scratch).await;
            match opened {
                Ok(ring) => {
                    defmt::info!(
                        "ring: open at block {} offset {}, next seq {}, oldest {}, damage {}",
                        ring.head().block,
                        ring.head().at,
                        ring.head().next_seq,
                        ring.head().oldest,
                        ring.damage()
                    );
                    Some(ring)
                }
                Err(error) => {
                    defmt::error!("ring: not opened: {}", error);
                    None
                }
            }
        }
        Ok(other) => {
            defmt::error!(
                "nor: JEDEC id {=[u8]:#x} is not the W25Q128JV's {=[u8]:#x}; no ring",
                other,
                JEDEC
            );
            None
        }
        Err(error) => {
            defmt::error!("nor: no answer to the identification: {}; no ring", error);
            None
        }
    };
    let mut ring = ring;
    if let Some(ring) = ring.as_mut() {
        defmt::info!("recorder: writing the boot record");
        boot_records(ring, &mut scratch, boot).await;
    }
    let boot = store
        .as_ref()
        .and_then(|store| store.boots.present().map(|count| count.get()))
        .unwrap_or(0);
    mailbox::init();
    let mut ticker = Ticker::every(PERIOD);
    check_in(Task::Recorder);
    loop {
        match select(ticker.next(), CUTS.wait()).await {
            Either::First(()) => {
                if RESETS.try_receive().is_ok() {
                    reset_clients(store.as_mut(), &mut fram).await;
                }
                // Bounded by the queue's depth: what arrives meanwhile waits
                // a turn.
                for _ in 0..MAX_EVENT_QUEUE {
                    let Ok(event) = EVENTS.try_receive() else {
                        break;
                    };
                    if let Some(ring) = ring.as_mut() {
                        append_record(ring, &mut scratch, event.record()).await;
                    } else {
                        defmt::error!("recorder: no ring; {} not recorded", event);
                    }
                }
                mailbox::serve(mailbox::Parts {
                    fram: &mut fram,
                    ring: ring.as_mut(),
                    scratch: &mut scratch,
                    boot,
                })
                .await;
            }
            Either::Second((request, cuts)) => {
                // Under the boot count the part holds, by which a later
                // boot counts the boots whose own record never landed
                // (F-018).
                let kept = match store.as_mut() {
                    Some(store) => {
                        let record = CutsRecord {
                            boot: store.boots.present().copied(),
                            cuts,
                        };
                        store
                            .cuts
                            .write(&mut fram, record)
                            .await
                            .map_err(|_| NotKept::Refused)
                    }
                    None => Err(NotKept::NoStore),
                };
                CUTS_KEPT.signal((request, kept));
            }
        }
        check_in(Task::Recorder);
    }
}

/// Serve one physical reset on the task that owns persistence.
/// P-085 failures reach the probe here. The persisted `ConcernRaised` body
/// requires the concern lifecycle and inventory from firmware#12; an empty
/// map is not a valid concern event. That integration remains part of #85.
async fn reset_clients(store: Option<&mut Store>, fram: &mut Fram) {
    let succeeded = if let Some(store) = store {
        match o89_core::reset_clients(&mut store.epoch, &mut store.clients, fram).await {
            Ok(()) => {
                defmt::info!("factory reset: epoch advanced and clients cleared");
                true
            }
            Err(error) => {
                defmt::error!("factory reset: {}; pairing blocked", error);
                match error {
                    o89_core::ResetFailed::Epoch(_) => {
                        defmt::error!("reset fault: epoch write failed");
                    }
                    o89_core::ResetFailed::Clients(_) => {
                        defmt::error!("reset fault: client clear failed");
                    }
                }
                false
            }
        }
    } else {
        defmt::error!("reset fault: epoch write failed, no store; pairing blocked");
        false
    };
    crate::selector::reset_finished(succeeded);
}

/// The class A boot record (`0x0601`): why the part reset, what the RTC
/// kept, and the previous run's last words, in KM43's body (F-009, L-143).
/// Written first, because a boot nobody had a probe on is one only the
/// ring remembers. Then the boot's scan of the ring, summed once it
/// finished: the records it stepped over because their CRC failed (P-096,
/// P-215), when there were any.
async fn boot_records(ring: &mut Ring<Nor>, scratch: &mut [u8], boot: Boot) {
    boot_record(ring, scratch, boot).await;
    if let Some(count) = NonZeroU32::new(ring.damage().failed_crc) {
        append_record(ring, scratch, ControllerRecord::RecordFailedCrc { count }).await;
    }
}

async fn boot_record(ring: &mut Ring<Nor>, scratch: &mut [u8], boot: Boot) {
    let mut body = [0u8; BOOT_MAX_BYTES];
    match boot.encode(&mut body) {
        Ok(len) => {
            append_body(
                ring,
                scratch,
                EventKind::BOOT,
                body.get(..len).unwrap_or(&[]),
            )
            .await;
        }
        Err(error) => defmt::error!("record 0x0601: the boot body did not encode: {}", error),
    }
}

/// One class A record with the body KM43 gives its kind (P-215): the
/// ladder's counts and branch, the boot noise, the CRC failures.
async fn append_record(ring: &mut Ring<Nor>, scratch: &mut [u8], record: ControllerRecord) {
    let mut body = [0u8; CONTROLLER_RECORD_MAX_BYTES];
    match record.encode(&mut body) {
        Ok(len) => append_body(ring, scratch, record.kind(), body.get(..len).unwrap_or(&[])).await,
        Err(error) => defmt::error!(
            "record {=u16:#06x}: the body did not encode: {}",
            record.kind().0,
            error
        ),
    }
}

/// One class A record of `kind` carrying `body`, a CBOR map KM43 defines.
async fn append_body(ring: &mut Ring<Nor>, scratch: &mut [u8], kind: EventKind, body: &[u8]) {
    let mut payload = [0u8; MAX_PAYLOAD];
    let Ok(event) = Event::new(LogSeq(ring.next_seq()), None, kind, body) else {
        defmt::error!("record {=u16:#06x}: the event did not build", kind.0);
        return;
    };
    let Ok(len) = event.encode(&mut payload) else {
        defmt::error!("record {=u16:#06x}: the event did not encode", kind.0);
        return;
    };
    match ring
        .append(Class::A, payload.get(..len).unwrap_or(&[]), scratch)
        .await
    {
        Ok(seq) => defmt::info!("record {=u16:#06x}: seq {}", kind.0, seq),
        Err(error) => defmt::error!("record {=u16:#06x}: not appended: {}", kind.0, error),
    }
}
