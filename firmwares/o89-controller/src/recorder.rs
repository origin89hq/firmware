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
//! off, and waits for the answer (F-017).
//!
//! cites: F-023

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, TrySendError};
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Ticker, with_timeout};
use km43::{Event, EventKind, LogSeq, MAX_EVENT_QUEUE};
use o89_core::{Class, LinkEvent, RecentCuts, Ring, SCRATCH, Store, Task};

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

/// The recovery ladder's cuts, to be kept on the FRAM before the rail
/// moves, under the request's number. One at a time: the rail task waits
/// for the answer.
static CUTS: Signal<CriticalSectionRawMutex, (u32, RecentCuts)> = Signal::new();

/// The answer to [`CUTS`], under the number of the request it answers.
static CUTS_KEPT: Signal<CriticalSectionRawMutex, (u32, Result<(), NotKept>)> = Signal::new();

/// How long the rail task waits for the cuts to land: a write the recorder
/// takes at once, behind at most one ring append or mailbox request, and an
/// append may erase a NOR sector first, 400 ms at most on the W25Q128JV.
const KEEP_DEADLINE: Duration = Duration::from_millis(2_000);

/// Why the ladder's cuts did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum NotKept {
    /// This boot has no store: the FRAM did not answer at boot.
    NoStore,
    /// The part refused the write.
    Refused,
    /// The recorder did not answer inside [`KEEP_DEADLINE`].
    Late,
}

/// The rail task's side of keeping the ladder's cuts: each request
/// numbered, so an answer to one abandoned late is never taken for the
/// answer to the next.
pub struct CutsKeeper {
    next: u32,
}

impl CutsKeeper {
    /// No request made yet.
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Keep `cuts` on the FRAM (F-017), and wait for them to land or for
    /// the deadline. A request the recorder has not started by then is
    /// withdrawn; one it has started may still land, which the caller
    /// counts as not knowing what the part holds.
    pub async fn keep(&mut self, cuts: RecentCuts) -> Result<(), NotKept> {
        let request = self.next;
        self.next = self.next.wrapping_add(1);
        CUTS.signal((request, cuts));
        let deadline = Instant::now().checked_add(KEEP_DEADLINE);
        // Bounded by the deadline: every turn takes an answer, and an
        // answer to an earlier request is passed over.
        loop {
            let left = deadline.map_or(Duration::from_ticks(0), |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            match with_timeout(left, CUTS_KEPT.wait()).await {
                Ok((answered, kept)) if answered == request => return kept,
                Ok(_) => {}
                Err(_) => {
                    CUTS.reset();
                    return Err(NotKept::Late);
                }
            }
        }
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
pub async fn run(mut store: Option<Store>, mut fram: Fram, mut nor: Nor) {
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
        boot_record(ring, &mut scratch).await;
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
                // Bounded by the queue's depth: what arrives meanwhile waits
                // a turn.
                for _ in 0..MAX_EVENT_QUEUE {
                    let Ok(event) = EVENTS.try_receive() else {
                        break;
                    };
                    if let Some(ring) = ring.as_mut() {
                        append(ring, &mut scratch, event.kind()).await;
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
                let kept = match store.as_mut() {
                    Some(store) => store
                        .cuts
                        .write(&mut fram, cuts)
                        .await
                        .map_err(|_| NotKept::Refused),
                    None => Err(NotKept::NoStore),
                };
                CUTS_KEPT.signal((request, kept));
            }
        }
        check_in(Task::Recorder);
    }
}

/// The class A boot record.
async fn boot_record(ring: &mut Ring<Nor>, scratch: &mut [u8]) {
    append(ring, scratch, EventKind::BOOT).await;
}

/// One class A record of `kind`, with the body the schema will give it
/// once origin89hq/km43#32 settles what each carries: an empty map until
/// then, which is a record that says the thing happened at this sequence
/// and nothing it should not. The count a power cycle carries (L-111) is
/// on the probe's log until then; a body written under a layout of this
/// firmware's own would persist on a unit past the schema that replaces
/// it, which is the one place nothing shipped does not apply.
async fn append(ring: &mut Ring<Nor>, scratch: &mut [u8], kind: EventKind) {
    let mut payload = [0u8; 32];
    let Ok(event) = Event::new(LogSeq(ring.next_seq()), None, kind, &[0xA0]) else {
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
