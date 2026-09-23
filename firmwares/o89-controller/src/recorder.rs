//! The one task that owns the NOR, and the records on the FRAM that are not
//! the client protocol's.
//!
//! The store was read in `main`, before any output moved, because the run
//! reason has to be known before the contact is (F-022, F-016); this task
//! takes the ladder's cuts and the boot count from there, and the link task
//! takes the epoch, the challenge counter and the client table, each
//! through its own lease on the part. It identifies the NOR, opens the
//! ring, writes the boot record, publishes the span of the log a `Hello`
//! reports, and from then on holds the ring for whoever asks. A board whose NOR does not answer
//! still has its store; the ring is simply absent and says so. The rail
//! task hands it the recovery ladder's cuts to keep before the rail goes
//! off, and polls for the answer without waiting on it (F-017).
//!
//! cites: F-023

use core::cell::{Cell, RefCell};
use core::num::NonZeroU32;

use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::channel::{Channel, TrySendError};
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Ticker};
use km43::{
    BOOT_MAX_BYTES, Boot, CONTROLLER_RECORD_MAX_BYTES, ControllerRecord, Event, EventKind, LogSeq,
    MAX_EVENT_QUEUE, ReqId, Time, TimeAck, TimeOffer,
};
use o89_core::{
    Answered, BootCount, CUTS_RECORD_BYTES, Class, ClientSet, CutsRecord, Keep, KeepAnswer, Kept,
    LinkEvent, LogSpan, MAX_PAYLOAD, NotKept, OfferIntake, OfferedTime, Outgoing, RecentCuts, Ring,
    SCRATCH, Task, Tick, TimeAnswer, TimeAsked, UnixMillis, WallClock,
};

use crate::fram::Lease;
use crate::mailbox;
use crate::nor::{JEDEC, Nor, SECTOR};
use crate::rtc::CalendarClock;
use crate::selector;
use crate::supervisor::check_in;

/// Pending work and replies share the protocol's four-request bound. Excess
/// work is refused, never overwritten; retries retain their original request.
/// The link continues its heartbeat loop while the recorder recovers the floor.
const TIME_REQUESTS: usize = km43::MAX_INFLIGHT;
static TIME: Channel<CriticalSectionRawMutex, (u32, ReqId, OfferedTime), TIME_REQUESTS> =
    Channel::new();
static TIME_ANSWER: Channel<
    CriticalSectionRawMutex,
    (u32, ReqId, Option<TimeOffer>),
    TIME_REQUESTS,
> = Channel::new();
static TIME_GENERATION: Mutex<CriticalSectionRawMutex, Cell<u32>> = Mutex::new(Cell::new(0));

/// One client `Time` at a time: the session keeps one waiting and refuses
/// the next with 7 (P-118), so a depth of one never refuses a request.
static CLIENT_TIME: Channel<CriticalSectionRawMutex, (TimeAsked, Tick), 1> = Channel::new();
static CLIENT_ANSWER: Channel<CriticalSectionRawMutex, (u32, TimeAnswer), 1> = Channel::new();

static CLOCK: Mutex<CriticalSectionRawMutex, RefCell<WallClock>> =
    Mutex::new(RefCell::new(WallClock::new()));

fn generation() -> u32 {
    TIME_GENERATION.lock(Cell::get)
}

pub fn offer(req_id: ReqId, at: u64) -> Option<Outgoing> {
    let now = Tick::from_millis(Instant::now().as_millis());
    match CLOCK.lock(|clock| clock.borrow_mut().intake(req_id, at, now)) {
        OfferIntake::Pending => None,
        OfferIntake::Accepted => Some(Outgoing::TimeVerdict {
            req_id,
            outcome: TimeOffer::Accepted,
        }),
        OfferIntake::RateLimited => Some(Outgoing::TimeVerdict {
            req_id,
            outcome: TimeOffer::RefusedRateLimited,
        }),
        OfferIntake::Full => Some(Outgoing::Refuse {
            code: km43::LinkErrorCode::TooManyOutstanding,
        }),
        OfferIntake::Queued => {
            if TIME
                .try_send((generation(), req_id, OfferedTime::new(at, now)))
                .is_err()
            {
                CLOCK.lock(|clock| clock.borrow_mut().finished(req_id));
                Some(Outgoing::Refuse {
                    code: km43::LinkErrorCode::TooManyOutstanding,
                })
            } else {
                None
            }
        }
    }
}

/// Hand a client's `Time` to the recorder, anchored to the tick it arrived
/// on so a wait in the queue or a floor scan advances it (as an offer's).
pub fn client_time(asked: TimeAsked) {
    let now = Tick::from_millis(Instant::now().as_millis());
    if CLIENT_TIME.try_send((asked, now)).is_err() {
        // The session holds one at a time; the next expires unanswered.
        defmt::error!("clock: a client time found the queue full");
    }
}

/// The recorder's answer to a client's `Time`, for the session that asked.
pub fn client_time_answer() -> Option<(u32, TimeAnswer)> {
    CLIENT_ANSWER.try_receive().ok()
}

pub fn time_answer() -> Option<(ReqId, TimeOffer)> {
    let (epoch, req_id, outcome) = TIME_ANSWER.try_receive().ok()?;
    if epoch != generation() {
        return None;
    }
    CLOCK.lock(|clock| clock.borrow_mut().finished(req_id));
    outcome.map(|outcome| (req_id, outcome))
}

pub fn cancel_offers() {
    CLOCK.lock(|clock| clock.borrow_mut().cancel_pending());
    TIME_GENERATION.lock(|epoch| epoch.set(epoch.get().wrapping_add(1)));
    while TIME.try_receive().is_ok() {}
    while TIME_ANSWER.try_receive().is_ok() {}
}

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

/// The span of the log, as the ring last stood: zero for none (P-104's
/// reading of an empty log), until the ring opens.
static SPAN: Mutex<CriticalSectionRawMutex, Cell<LogSpan>> = Mutex::new(Cell::new(LogSpan {
    oldest: LogSeq(0),
    newest: LogSeq(0),
}));

/// The log's span, for a `Hello` (keys 7 and 8).
pub fn log_span() -> LogSpan {
    SPAN.lock(Cell::get)
}

fn publish(ring: &Ring<Nor>) {
    let head = ring.head();
    let span = LogSpan {
        oldest: LogSeq(head.oldest.unwrap_or(0)),
        newest: LogSeq(head.next_seq.saturating_sub(1)),
    };
    SPAN.lock(|cell| cell.set(span));
}

/// The ladder's cuts as the boot read them, and the boot count they are
/// kept under (F-018). No record is a boot without a store.
pub struct Cuts {
    /// The record.
    pub kept: Option<Kept<CutsRecord, CUTS_RECORD_BYTES>>,
    /// The count the part holds.
    pub boot: Option<BootCount>,
}

/// Queue an event for the ring, or hand it back when the queue is full.
pub fn post(event: LinkEvent) -> Result<(), LinkEvent> {
    EVENTS.try_send(event).map_err(|refused| match refused {
        TrySendError::Full(event) => event,
    })
}

/// The recorder task: the only owner of the NOR, and so the one that serves
/// the bench tool's mailbox.
#[embassy_executor::task]
pub async fn run(
    mut cuts: Cuts,
    mut fram: Lease,
    nor: Nor,
    boot: Boot,
    mut calendar: CalendarClock,
) {
    if let Some(change) = calendar.pending() {
        let _ = CLOCK.lock(|clock| clock.borrow_mut().recover_audit(change));
    }
    let mut scratch = [0u8; SCRATCH];
    let ring = open_ring(nor, &mut scratch).await;
    let mut ring = ring;
    if let Some(ring) = ring.as_mut() {
        defmt::info!("recorder: writing the boot record");
        boot_records(ring, &mut scratch, boot, calendar.now()).await;
    }
    if let Some(ring) = ring.as_ref() {
        publish(ring);
    }
    let boot = cuts.boot.map_or(0, BootCount::get);
    // The client whose set is applied and owed to the log, and the clock it
    // set, answered once the record lands.
    let mut client_waiting: Option<(u32, u64)> = None;
    mailbox::init();
    let mut ticker = Ticker::every(PERIOD);
    check_in(Task::Recorder);
    loop {
        match select(ticker.next(), CUTS.wait()).await {
            Either::First(()) => {
                serve_time(
                    ring.as_mut(),
                    &mut scratch,
                    &mut calendar,
                    &mut cuts,
                    &mut fram,
                    &mut client_waiting,
                )
                .await;
                // Bounded by the queue's depth: what arrives meanwhile waits
                // a turn.
                for _ in 0..MAX_EVENT_QUEUE {
                    let Ok(event) = EVENTS.try_receive() else {
                        break;
                    };
                    if let Some(ring) = ring.as_mut() {
                        let _ =
                            append_record(ring, &mut scratch, event.record(), calendar.now()).await;
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
                // Records appended this turn, and a block the bench dropped.
                if let Some(ring) = ring.as_ref() {
                    publish(ring);
                }
            }
            Either::Second((request, recent)) => {
                keep_cuts(&mut cuts, &mut fram, request, recent).await;
            }
        }
        check_in(Task::Recorder);
    }
}

/// The class A boot record (`0x0601`): why the part reset, what the RTC
/// kept, and the previous run's last words, in KM43's body (F-009, L-143).
/// Written first, because a boot nobody had a probe on is one only the
/// ring remembers.
async fn boot_records(
    ring: &mut Ring<Nor>,
    scratch: &mut [u8],
    boot: Boot,
    at: Option<UnixMillis>,
) {
    boot_record(ring, scratch, boot, at).await;
    if let Some(count) = NonZeroU32::new(ring.damage().failed_crc) {
        let _ = append_record(
            ring,
            scratch,
            ControllerRecord::RecordFailedCrc { count },
            at,
        )
        .await;
    }
}

async fn boot_record(ring: &mut Ring<Nor>, scratch: &mut [u8], boot: Boot, at: Option<UnixMillis>) {
    let mut body = [0u8; BOOT_MAX_BYTES];
    match boot.encode(&mut body) {
        Ok(len) => {
            let _ = append_body(
                ring,
                scratch,
                EventKind::BOOT,
                body.get(..len).unwrap_or(&[]),
                at,
            )
            .await;
        }
        Err(error) => defmt::error!("record 0x0601: the boot body did not encode: {}", error),
    }
}

/// One class A record with the body KM43 gives its kind (P-215).
async fn append_record(
    ring: &mut Ring<Nor>,
    scratch: &mut [u8],
    record: ControllerRecord,
    at: Option<UnixMillis>,
) -> Result<(), ()> {
    let mut body = [0; CONTROLLER_RECORD_MAX_BYTES];
    match record.encode(&mut body) {
        Ok(len) => {
            append_body(
                ring,
                scratch,
                record.kind(),
                body.get(..len).unwrap_or(&[]),
                at,
            )
            .await
        }
        Err(error) => {
            defmt::error!(
                "record {=u16:#06x}: the body did not encode: {}",
                record.kind().0,
                error
            );
            Err(())
        }
    }
}

/// One class A record of `kind` carrying `body`, a CBOR map KM43 defines.
async fn append_body(
    ring: &mut Ring<Nor>,
    scratch: &mut [u8],
    kind: EventKind,
    body: &[u8],
    at: Option<UnixMillis>,
) -> Result<(), ()> {
    let mut payload = [0u8; MAX_PAYLOAD];
    let Ok(event) = Event::new(
        LogSeq(ring.next_seq()),
        at.map(UnixMillis::as_millis),
        kind,
        body,
    ) else {
        defmt::error!("record {=u16:#06x}: the event did not build", kind.0);
        return Err(());
    };
    let Ok(len) = event.encode(&mut payload) else {
        defmt::error!("record {=u16:#06x}: the event did not encode", kind.0);
        return Err(());
    };
    match ring
        .append(Class::A, payload.get(..len).unwrap_or(&[]), scratch)
        .await
    {
        Ok(seq) => {
            defmt::info!("record {=u16:#06x}: seq {}", kind.0, seq);
            Ok(())
        }
        Err(error) => {
            defmt::error!("record {=u16:#06x}: not appended: {}", kind.0, error);
            Err(())
        }
    }
}

/// A failed floor scan or calendar write produces no successful acknowledgement.
/// No fallback is permitted for an unreadable history.
enum OfferResult {
    AwaitingAudit,
    Finished(Option<TimeOffer>),
}

fn process_offer(
    calendar: &mut CalendarClock,
    epoch: u32,
    req_id: ReqId,
    offered: OfferedTime,
    floor: UnixMillis,
) -> OfferResult {
    if epoch != generation() {
        return OfferResult::Finished(None);
    }
    let now = Tick::from_millis(Instant::now().as_millis());
    let Some(at) = offered.at(now) else {
        return OfferResult::Finished(Some(TimeOffer::RefusedImplausible));
    };
    let current = match calendar.read() {
        Ok(at) => at,
        Err(error) => {
            defmt::error!("clock: calendar read failed: {}", error);
            return OfferResult::Finished(None);
        }
    };
    let change = match CLOCK.lock(|clock| clock.borrow_mut().offer(at, current, floor, now)) {
        Ok(change) => change,
        Err(outcome) => return OfferResult::Finished(Some(outcome)),
    };
    if let Err(error) = calendar.set(change) {
        defmt::error!("clock: calendar write refused: {}", error);
        return OfferResult::Finished(None);
    }
    // No await between durable apply and retaining its completion. serve_time
    // refuses another offer while an audit is pending.
    let _ = CLOCK.lock(|clock| clock.borrow_mut().applied(req_id, offered, change, now));
    OfferResult::AwaitingAudit
}

fn answer_client(ticket: u32, answer: TimeAnswer) {
    if CLIENT_ANSWER.try_send((ticket, answer)).is_err() {
        defmt::error!("clock: a client time answer found the queue full");
    }
}

/// A client's signed `Time`, its counter already spent: decided against the
/// RTC and the floor the log gives (P-113, P-114), with the override read
/// now (P-117 rule 3), and applied as an offer is: the calendar, then the
/// audit, then the answer once the `time set` record lands (P-111).
async fn serve_client(
    ring: &mut Ring<Nor>,
    scratch: &mut [u8],
    calendar: &mut CalendarClock,
    cuts: &mut Cuts,
    fram: &mut Lease,
    (asked, received): (TimeAsked, Tick),
    client_waiting: &mut Option<(u32, u64)>,
) {
    let now = Tick::from_millis(Instant::now().as_millis());
    let current = match calendar.read() {
        Ok(current) => current,
        Err(error) => {
            defmt::error!("clock: calendar unavailable: {}", error);
            return answer_client(asked.ticket, TimeAnswer::Busy);
        }
    };
    let refused = |outcome| {
        TimeAck::new(outcome, current.map(UnixMillis::as_millis))
            .map_or(TimeAnswer::Busy, TimeAnswer::Ack)
    };
    if !asked.authorised {
        return answer_client(asked.ticket, refused(Time::Unauthorised));
    }
    if CLOCK.lock(|clock| clock.borrow().client_rate_limited(now)) {
        return answer_client(asked.ticket, TimeAnswer::Busy);
    }
    let Some(at) = OfferedTime::new(asked.at, received).at(now) else {
        return answer_client(asked.ticket, refused(Time::Rejected));
    };
    let Some(floor) = recover_floor(ring, scratch, cuts, fram).await else {
        return answer_client(asked.ticket, TimeAnswer::Busy);
    };
    let (change, stepped, overridden) =
        match WallClock::client(at, current, floor, selector::floor_override()) {
            ClientSet::Set {
                change,
                stepped,
                overridden,
            } => (change, stepped, overridden),
            ClientSet::Rejected => return answer_client(asked.ticket, refused(Time::Rejected)),
            ClientSet::NeedsButton => {
                return answer_client(asked.ticket, refused(Time::NeedsButton));
            }
        };
    if let Err(error) = calendar.set(change) {
        defmt::error!("clock: calendar write refused: {}", error);
        return answer_client(asked.ticket, TimeAnswer::Busy);
    }
    let now = Tick::from_millis(Instant::now().as_millis());
    if !CLOCK.lock(|clock| clock.borrow_mut().client_applied(change, now)) {
        // Only the recorder applies a change and it checked none was owed.
        defmt::error!("clock: a client set applied beside another owed to the log");
    }
    if overridden {
        selector::floor_used();
        // P-116's `floor overridden` concern waits on the concern table.
        defmt::error!("clock: the floor was overridden at the panel");
    }
    if stepped {
        // P-115's `clock stepped` concern waits on the concern table.
        defmt::error!("clock: a client stepped the clock more than an hour");
    }
    *client_waiting = Some((asked.ticket, change.new_value().as_millis()));
}

async fn keep_cuts(cuts: &mut Cuts, fram: &mut Lease, request: u32, recent: RecentCuts) {
    // Under the boot count the part holds, by which a later
    // boot counts the boots whose own record never landed
    // (F-018).
    let boot = cuts.boot;
    let kept = match cuts.kept.as_mut() {
        Some(kept) => kept
            .write(fram, CutsRecord { boot, cuts: recent })
            .await
            .map_err(|_| NotKept::Refused),
        None => Err(NotKept::NoStore),
    };
    CUTS_KEPT.signal((request, kept));
}

/// Floor recovery may walk the whole NOR. Keep serving the FRAM recovery
/// requests while it yields; a scan must not hold the rail's cut past its deadline.
async fn recover_floor(
    ring: &mut Ring<Nor>,
    scratch: &mut [u8],
    cuts: &mut Cuts,
    fram: &mut Lease,
) -> Option<UnixMillis> {
    let scan = embassy_time::with_timeout(Duration::from_secs(30), ring.floor(scratch));
    let mut scan = core::pin::pin!(scan);
    let mut ticker = Ticker::every(PERIOD);
    loop {
        match select3(&mut scan, CUTS.wait(), ticker.next()).await {
            Either3::First(result) => {
                return match result {
                    Ok(Ok(newest)) => env!("BUILD_UNIX_MS")
                        .parse()
                        .ok()
                        .and_then(|build| WallClock::floor(newest, build)),
                    Ok(Err(error)) => {
                        defmt::error!("clock: floor unavailable: {}", error);
                        None
                    }
                    Err(_) => {
                        defmt::error!("clock: floor scan timed out");
                        None
                    }
                };
            }
            Either3::Second((request, recent)) => keep_cuts(cuts, fram, request, recent).await,
            Either3::Third(()) => {}
        }
        check_in(Task::Recorder);
    }
}

async fn open_ring(mut nor: Nor, scratch: &mut [u8]) -> Option<Ring<Nor>> {
    defmt::info!("recorder: identifying the NOR");
    let jedec = nor.jedec().await;
    defmt::info!("recorder: identification answered {}", jedec);
    match jedec {
        Ok(JEDEC) => {
            defmt::info!("recorder: opening the ring");
            let opened = Ring::open(nor, 0, RING_BLOCKS, scratch).await;
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
    }
}

async fn serve_time(
    ring: Option<&mut Ring<Nor>>,
    scratch: &mut [u8],
    calendar: &mut CalendarClock,
    cuts: &mut Cuts,
    fram: &mut Lease,
    client_waiting: &mut Option<(u32, u64)>,
) {
    let Some(ring) = ring else {
        return;
    };
    let now = Tick::from_millis(Instant::now().as_millis());
    if CLOCK.lock(|clock| clock.borrow().audit_pending()) {
        if let Some(change) = CLOCK.lock(|clock| clock.borrow_mut().audit_due(now))
            && append_record(ring, scratch, change.record(), calendar.now())
                .await
                .is_ok()
        {
            match calendar.recorded() {
                Ok(()) => {
                    let now = Tick::from_millis(Instant::now().as_millis());
                    match CLOCK.lock(|clock| clock.borrow_mut().audit_written(now)) {
                        Some(Answered::Offer(req_id)) => {
                            if TIME_ANSWER
                                .try_send((generation(), req_id, Some(TimeOffer::Accepted)))
                                .is_err()
                            {
                                CLOCK.lock(|clock| clock.borrow_mut().finished(req_id));
                                defmt::warn!(
                                    "clock: reply queue full; acceptance retained for retry"
                                );
                            }
                        }
                        Some(Answered::Client) => {
                            if let Some((ticket, at)) = client_waiting.take() {
                                answer_client(
                                    ticket,
                                    TimeAck::new(Time::Accepted, Some(at))
                                        .map_or(TimeAnswer::Busy, TimeAnswer::Ack),
                                );
                            }
                        }
                        None => {}
                    }
                }
                Err(error) => {
                    defmt::error!("clock: audit journal acknowledgement failed: {}", error);
                }
            }
        }
        return;
    }
    if let Ok((asked, received)) = CLIENT_TIME.try_receive() {
        serve_client(
            ring,
            scratch,
            calendar,
            cuts,
            fram,
            (asked, received),
            client_waiting,
        )
        .await;
        return;
    }
    if !CLOCK.lock(|clock| clock.borrow().ready_for_offer(now)) {
        return;
    }
    if let Ok((epoch, req_id, offered)) = TIME.try_receive()
        && epoch == generation()
    {
        let floor = match calendar.read() {
            Ok(Some(current)) => Some(current), // Known-clock admission does not use the floor.
            Ok(None) => recover_floor(ring, scratch, cuts, fram).await,
            Err(error) => {
                defmt::error!("clock: calendar unavailable: {}", error);
                None
            }
        };
        let result = match floor {
            Some(floor) => process_offer(calendar, epoch, req_id, offered, floor),
            None => OfferResult::Finished(None),
        };
        match result {
            OfferResult::AwaitingAudit => {}
            OfferResult::Finished(outcome) => {
                if epoch == generation() && TIME_ANSWER.try_send((epoch, req_id, outcome)).is_err()
                {
                    CLOCK.lock(|clock| clock.borrow_mut().finished(req_id));
                    defmt::warn!("clock: reply queue full");
                }
            }
        }
    }
}
