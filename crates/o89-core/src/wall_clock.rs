//! Wall-clock admission; every duration remains on the monotonic tick.
//!
//! The recorder supplies the newest timestamp from `Ring::floor`. A failed
//! scan is not an empty ring and must never become the build-time fallback.
//!
//! cites: L-014, L-140, L-141, L-142, L-150, L-151, L-152, L-153, L-154, L-160, L-162, P-111, P-215, P-266, P-267

use km43::{ControllerRecord, MAX_INFLIGHT, ReqId, TimeOffer, TimeSource};

use crate::{Calendar, Millis, Tick, TimeAnswer, UnixMillis};

/// Ten Julian years, in milliseconds, shared by both clock-setting paths.
pub const PLAUSIBILITY_SPAN: u64 = 315_576_000_000;
/// One accepted offer per fifteen minutes, independent of wall-clock changes.
pub const OFFER_INTERVAL: Millis = Millis::from_millis(900_000);
/// Largest correction an unauthenticated offer may make to a known clock.
pub const OFFER_STEP: u64 = 5_000;
/// A completed acceptance remains replayable for all three 500 ms attempts
/// (L-015). Expiry permits L-013 request-ID reuse without an unbounded cache.
pub const OFFER_REPLAY: Millis = Millis::from_millis(1_500);
/// A failed audit append is retried at most once per second.
pub const AUDIT_RETRY: Millis = Millis::from_millis(1_000);
/// One accepted client `Time` per fifteen minutes on the tick, the width of
/// the offers' limit and counted apart from it (P-118).
pub const CLIENT_INTERVAL: Millis = Millis::from_millis(900_000);
/// A move of a known clock past this raises `clock stepped` (P-115).
pub const TIME_STEP_ALARM: u64 = 3_600_000;

/// A received time value anchored to the controller's monotonic tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedTime {
    at: u64,
    received: Tick,
}

impl OfferedTime {
    /// Anchor the value when the complete offer arrives, before any queue wait.
    #[must_use]
    pub const fn new(at: u64, received: Tick) -> Self {
        Self { at, received }
    }

    /// Advance by queue/scan time. Refuse a backwards tick or integer overflow.
    #[must_use]
    pub fn at(self, now: Tick) -> Option<u64> {
        self.at.checked_add(now.since(self.received)?.as_millis())
    }

    /// The value as the offer carried it, before any queue delay.
    #[must_use]
    pub const fn sent(self) -> u64 {
        self.at
    }
}

#[derive(Debug, Clone, Copy)]
struct Audit {
    change: ClockChange,
    reply: Owed,
    retry_at: Option<Tick>,
}

/// Who is answered once an audit lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed {
    /// Nobody: recovered at boot, or its link was lost.
    Nobody,
    /// A link offer, replayable by its request id and value.
    Offer(ReqId, u64),
    /// The client whose signed `Time` moved the clock.
    Client,
}

/// Who an audit that landed is answered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an acceptance nobody answers is a client left to time out"]
pub enum Answered {
    /// The link offer with this request id.
    Offer(ReqId),
    /// The client whose `Time` is waiting.
    Client,
}

/// What a client's signed `Time 0x0A` becomes, decided before the clock
/// moves and never with the clock moved for a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a decision nobody applies is a client answered by nothing"]
pub enum ClientSet {
    /// Move the clock to this, record it, and answer `accepted` once the
    /// record is durable.
    Set {
        /// The change, sourced `client` (P-111).
        change: ClockChange,
        /// A known clock moved by more than an hour: `clock stepped` (P-115).
        stepped: bool,
        /// Below the floor, accepted on the armed override: `floor
        /// overridden`, and the override is spent (P-116, P-117).
        overridden: bool,
    },
    /// Outcome 2: past the window's upper edge, which nothing lifts
    /// (P-113), or outside the century the RTC holds (P-266).
    Rejected,
    /// Outcome 4: below the floor with no override armed (P-114).
    NeedsButton,
}

/// Why a client's signed `Time` is answered error 7 before it executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refusal nobody answers is a client left to time out"]
pub enum ClientBusy {
    /// A `time set` record is owed: no other clock change until it lands,
    /// and the refusal is sent now rather than held (P-267 rule 2).
    RecordOwed,
    /// Inside the fifteen minutes after the last one accepted (P-118).
    RateLimited,
}

impl ClientBusy {
    /// Error 7 for either reason: the client's answer says not now.
    #[must_use]
    pub const fn answer(self) -> TimeAnswer {
        match self {
            Self::RecordOwed | Self::RateLimited => TimeAnswer::Busy,
        }
    }
}

/// A client's accepted `Time` once the adapter has tried to write it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a write nobody answers is a client left to time out"]
pub enum ClientWritten<E> {
    /// The calendar holds the change and its audit is owed: `accepted` is
    /// answered once the `time set` record lands (P-111).
    Applied {
        /// The change lifted the floor on the armed override, which is
        /// spent now and not before (P-116, P-117).
        spend_override: bool,
        /// False when another change was already owed to the log, which
        /// the recorder rules out before it decides.
        retained: bool,
    },
    /// The RTC or the retained words refused the write before the RTC
    /// took it. The clock stays as it was, still known when it was, no
    /// P-118 window starts and the override is not spent (P-267).
    Failed {
        /// Why the write failed.
        error: E,
        /// Error 7, never outcome 2: the same time may land on the next
        /// try, where one the clock cannot hold never will (P-266).
        answer: TimeAnswer,
    },
}

/// An offer's accepted change once the adapter has tried to write it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a landed write owes its audit and a failed one its release"]
pub enum OfferWritten<E> {
    /// The calendar holds the change and its audit is owed: `accepted` is
    /// answered once the `time set` record lands (L-160).
    Applied {
        /// False when another change was already owed to the log, which
        /// the recorder rules out before it decides.
        retained: bool,
    },
    /// The RTC refused the write. Nothing is retained, L-151's window does
    /// not start and no outcome is owed: not 2, because the same time may
    /// land on the comms processor's retry (L-153).
    Failed {
        /// Why the write failed.
        error: E,
    },
}

#[derive(Debug, Clone, Copy)]
struct Completed {
    req_id: ReqId,
    at: u64,
    expires: Option<Tick>,
}

/// Admission state for one controller boot. A comms reset does not reset it.
#[derive(Debug, Default)]
pub struct WallClock {
    last_offer: Option<Tick>,
    last_client: Option<Tick>,
    rate_refusals: u64,
    pending: [Option<ReqId>; MAX_INFLIGHT],
    audit: Option<Audit>,
    completed: Option<Completed>,
}

/// Intake of a decoded offer before the recorder touches storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferIntake {
    /// A new request reserved one of the four pending slots.
    Queued,
    /// Replay the accepted result without applying or recording it again.
    Accepted,
    /// A retry of a request still being processed; do not execute it twice.
    Pending,
    /// Refused and counted on the monotonic acceptance limit.
    RateLimited,
    /// Four requests await answers; refuse the fifth, never evict (L-014).
    Full,
}

/// A proposed change. Applying it and recording it belong to the adapter.
///
/// It carries its source from the decision that made it to the record that
/// names it, through the calendar's journal across a reset, because the
/// source is fixed by which message moved the clock and read from nowhere
/// else (P-111).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClockChange {
    old: Option<UnixMillis>,
    new: UnixMillis,
    source: TimeSource,
}

impl ClockChange {
    pub(crate) const fn recovered(
        old: Option<UnixMillis>,
        new: UnixMillis,
        source: TimeSource,
    ) -> Self {
        Self { old, new, source }
    }

    /// The `time set` record's body (P-111, P-215): `ntp-via-comms` for an
    /// accepted link offer, never the link-local source number (L-162), and
    /// `client` for a signed client write.
    #[must_use]
    pub fn record(self) -> ControllerRecord {
        ControllerRecord::TimeSet {
            old: self.old.map(UnixMillis::as_millis),
            new: self.new.as_millis(),
            source: self.source,
        }
    }

    /// Which message moved the clock.
    #[must_use]
    pub const fn source(self) -> TimeSource {
        self.source
    }

    /// The previous reading, absent when the RTC was unknown.
    #[must_use]
    pub const fn old(self) -> Option<UnixMillis> {
        self.old
    }

    /// The accepted reading.
    #[must_use]
    pub const fn new_value(self) -> UnixMillis {
        self.new
    }
}

impl WallClock {
    /// No offer accepted during this boot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_offer: None,
            last_client: None,
            rate_refusals: 0,
            pending: [None; MAX_INFLIGHT],
            audit: None,
            completed: None,
        }
    }

    /// Recover the floor after a successful log scan. A present timestamp
    /// always wins, even when it predates the build (L-142).
    #[must_use]
    pub const fn floor(newest: Option<u64>, build: u64) -> Option<UnixMillis> {
        match newest {
            Some(at) => UnixMillis::new(at),
            None => UnixMillis::new(build),
        }
    }

    /// Check an offer against the current RTC and the recovered floor.
    /// `floor` is the newest timestamped record, or the build timestamp only
    /// after a successful scan found none (L-140–L-142).
    ///
    /// While a `time set` record is owed the answer is
    /// `refused_rate_limited`, after L-151 and L-153 and before L-150, not
    /// counted and starting no window (L-154).
    ///
    /// This does not move the clock. Call `offer_applied` only after the
    /// adapter successfully sets it. No peer accuracy or source claim enters
    /// this decision (L-152, L-162).
    pub fn offer(
        &mut self,
        offered: OfferedTime,
        current: Option<UnixMillis>,
        floor: UnixMillis,
        now: Tick,
    ) -> Result<ClockChange, TimeOffer> {
        if self.refuse_rate_limited(now) {
            return Err(TimeOffer::RefusedRateLimited);
        }
        // Neither the window nor the step cap keeps an offer inside the
        // RTC's century. Checked before the cap, whose answer sends the
        // correction to a client `Time` that P-266 refuses too, and on the
        // value as sent as well as advanced: queue time can carry one sent
        // before 2000 into it (L-153).
        let new = offered
            .at(now)
            .filter(|at| Calendar::holds(offered.sent()) && Calendar::holds(*at))
            .and_then(UnixMillis::new)
            .ok_or(TimeOffer::RefusedImplausible)?;
        // Before the step cap, whose answer points at a client `Time` that
        // P-267 refuses too while the record is owed. Not L-151's refusal:
        // nobody exceeded a rate, and its window starts only on a landed
        // change (L-154).
        if self.audit.is_some() {
            return Err(TimeOffer::RefusedRateLimited);
        }
        let at = new.as_millis();
        match current {
            Some(old) => {
                if at.abs_diff(old.as_millis()) > OFFER_STEP {
                    return Err(TimeOffer::RefusedStepTooLarge);
                }
            }
            None => {
                if at < floor.as_millis() || at.abs_diff(floor.as_millis()) > PLAUSIBILITY_SPAN {
                    return Err(TimeOffer::RefusedImplausible);
                }
            }
        }
        Ok(ClockChange {
            old: current,
            new,
            source: TimeSource::NtpViaComms,
        })
    }

    /// Reserve a request until its answer is taken. Storage work and queued
    /// responses count toward the same bound; retries do not consume a slot.
    pub fn intake(&mut self, req_id: ReqId, at: u64, now: Tick) -> OfferIntake {
        if self
            .completed
            .is_some_and(|done| done.expires.is_some_and(|until| now >= until))
        {
            self.completed = None;
        }
        if self
            .completed
            .is_some_and(|done| done.req_id == req_id && done.at == at)
        {
            return OfferIntake::Accepted;
        }
        if self.pending.contains(&Some(req_id)) {
            return OfferIntake::Pending;
        }
        if self.refuse_rate_limited(now) {
            return OfferIntake::RateLimited;
        }
        // Never replace an unexpired acceptance. Normally the rate limit
        // already refused; this also covers an audit completed very late.
        if self.completed.is_some() {
            return OfferIntake::Full;
        }
        let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_none()) else {
            return OfferIntake::Full;
        };
        *slot = Some(req_id);
        OfferIntake::Queued
    }

    /// Release a request after its answer, or after a storage failure.
    pub fn finished(&mut self, req_id: ReqId) {
        if let Some(slot) = self.pending.iter_mut().find(|slot| **slot == Some(req_id)) {
            *slot = None;
        }
    }

    /// Forget a lost link's work while retaining the controller's rate limit.
    pub fn cancel_pending(&mut self) {
        self.pending.fill(None);
        self.completed = None;
        if let Some(audit) = self.audit.as_mut()
            && matches!(audit.reply, Owed::Offer(..))
        {
            audit.reply = Owed::Nobody;
        }
    }

    /// Retain an applied change until its audit is durable. The adapter must
    /// persist the same change in its calendar journal before calling this.
    /// An occupied audit slot refuses replacement, even after link loss.
    #[must_use]
    fn applied(
        &mut self,
        req_id: ReqId,
        offered: OfferedTime,
        change: ClockChange,
        now: Tick,
    ) -> bool {
        if self.audit.is_some() {
            return false;
        }
        self.offer_applied(now);
        self.audit = Some(Audit {
            change,
            reply: Owed::Offer(req_id, offered.at),
            retry_at: Some(now),
        });
        true
    }

    /// Take the result of writing an offer's change to the calendar: retain
    /// it and start L-151's window when it landed; when it failed, change
    /// nothing and owe no outcome (L-153).
    pub fn offer_written<E>(
        &mut self,
        req_id: ReqId,
        offered: OfferedTime,
        change: ClockChange,
        written: Result<(), E>,
        now: Tick,
    ) -> OfferWritten<E> {
        match written {
            Ok(()) => OfferWritten::Applied {
                retained: self.applied(req_id, offered, change, now),
            },
            Err(error) => OfferWritten::Failed { error },
        }
    }

    /// Recover a retained calendar change after reset, without an old-link reply.
    #[must_use]
    pub fn recover_audit(&mut self, change: ClockChange) -> bool {
        if self.audit.is_some() {
            return false;
        }
        self.audit = Some(Audit {
            change,
            reply: Owed::Nobody,
            retry_at: Some(Tick::ZERO),
        });
        true
    }

    /// Whether another calendar change must wait for the audit to land.
    #[must_use]
    pub const fn audit_pending(&self) -> bool {
        self.audit.is_some()
    }

    /// Whether a queued offer can be decided now. It waits for a late
    /// audit's reply-cache horizon, so an older queued request cannot evict
    /// a completed acceptance, but never for an owed record: `offer` refuses
    /// it straight away then and completes nothing (L-154).
    #[must_use]
    pub fn ready_for_offer(&self, now: Tick) -> bool {
        self.audit.is_some()
            || self
                .completed
                .is_none_or(|done| done.expires.is_some_and(|until| now >= until))
    }

    /// One bounded audit attempt. A failure leaves the original record intact.
    pub fn audit_due(&mut self, now: Tick) -> Option<ClockChange> {
        let audit = self.audit.as_mut()?;
        if now < audit.retry_at? {
            return None;
        }
        audit.retry_at = now.after(AUDIT_RETRY);
        Some(audit.change)
    }

    /// Complete only after both append and journal acknowledgement succeed.
    /// Retain the accepted result through L-015's retry horizon, even if its
    /// UART reply is lost. A cancelled link gets no reply.
    pub fn audit_written(&mut self, now: Tick) -> Option<Answered> {
        let audit = self.audit.take()?;
        match audit.reply {
            Owed::Nobody => None,
            Owed::Client => Some(Answered::Client),
            Owed::Offer(req_id, at) => {
                self.completed = Some(Completed {
                    req_id,
                    at,
                    expires: now.after(OFFER_REPLAY),
                });
                Some(Answered::Offer(req_id))
            }
        }
    }

    /// Decide a client's signed `Time` against the RTC and the floor, the
    /// same floor an offer meets (P-113, P-114, L-140). Every client write
    /// meets it, a known clock's too: there is no drift allowance on this
    /// door. The override lifts the floor and nothing else; the ten-year
    /// edge above it binds whatever the panel says (P-116, P-117).
    ///
    /// This does not move the clock or spend the override: the adapter
    /// writes the calendar, hands the result to
    /// [`client_written`](Self::client_written), and spends the override
    /// only when that says to.
    pub fn client(
        at: u64,
        current: Option<UnixMillis>,
        floor: UnixMillis,
        override_armed: bool,
    ) -> ClientSet {
        let lower = floor.as_millis();
        if at.saturating_sub(lower) > PLAUSIBILITY_SPAN {
            return ClientSet::Rejected;
        }
        let overridden = at < lower;
        if overridden && !override_armed {
            return ClientSet::NeedsButton;
        }
        // The override has no lower bound and the RTC holds one century:
        // what the calendar cannot hold is refused before the clock moves.
        let Some(new) = UnixMillis::new(at).filter(|_| Calendar::holds(at)) else {
            return ClientSet::Rejected;
        };
        // A first set is not a step: there is nothing to subtract (P-115).
        let stepped = current.is_some_and(|old| at.abs_diff(old.as_millis()) > TIME_STEP_ALARM);
        ClientSet::Set {
            change: ClockChange {
                old: current,
                new,
                source: TimeSource::Client,
            },
            stepped,
            overridden,
        }
    }

    /// Whether a client's `Time` arrives inside the fifteen minutes after
    /// the last one accepted: error 7, before it executes, override or not
    /// (P-117 rule 4, P-118).
    #[must_use]
    pub fn client_rate_limited(&self, now: Tick) -> bool {
        self.last_client.is_some_and(|last| {
            now.since(last)
                .is_none_or(|elapsed| elapsed < CLIENT_INTERVAL)
        })
    }

    /// Whether a client's signed `Time` may execute now: error 7 while a
    /// `time set` record is owed, whatever P-118's window says (P-267 rule
    /// 2), and inside that window (P-118). Decided before the floor scan
    /// and the clock is never moved for either.
    pub fn client_admitted(&self, now: Tick) -> Result<(), ClientBusy> {
        if self.audit.is_some() {
            return Err(ClientBusy::RecordOwed);
        }
        if self.client_rate_limited(now) {
            return Err(ClientBusy::RateLimited);
        }
        Ok(())
    }

    /// Retain a client's applied change until its audit is durable, and
    /// start P-118's window. Refused, like an offer's, while another audit
    /// is owed.
    #[must_use]
    fn client_applied(&mut self, change: ClockChange, now: Tick) -> bool {
        if self.audit.is_some() {
            return false;
        }
        self.last_client = Some(now);
        self.audit = Some(Audit {
            change,
            reply: Owed::Client,
            retry_at: Some(now),
        });
        true
    }

    /// Take the result of writing a [`ClientSet::Set`]'s change to the
    /// calendar: retain it and start P-118's window when it landed; when it
    /// failed, change nothing and answer busy.
    pub fn client_written<E>(
        &mut self,
        change: ClockChange,
        overridden: bool,
        written: Result<(), E>,
        now: Tick,
    ) -> ClientWritten<E> {
        match written {
            Ok(()) => ClientWritten::Applied {
                spend_override: overridden,
                retained: self.client_applied(change, now),
            },
            Err(error) => ClientWritten::Failed {
                error,
                answer: TimeAnswer::Busy,
            },
        }
    }

    /// Refuse and count an offer at intake without waiting for storage. This
    /// keeps a flood inside the rate window out of the recorder queue (L-151).
    pub fn refuse_rate_limited(&mut self, now: Tick) -> bool {
        if self.last_offer.is_some_and(|last| {
            now.since(last)
                .is_none_or(|elapsed| elapsed < OFFER_INTERVAL)
        }) {
            self.rate_refusals = self.rate_refusals.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Start the offer limit after the RTC accepted the change.
    pub fn offer_applied(&mut self, now: Tick) {
        self.last_offer = Some(now);
    }

    /// Every offer refused inside the limit, saturating rather than wrapping.
    #[must_use]
    pub const fn rate_refusals(&self) -> u64 {
        self.rate_refusals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: u64 = 1_800_000_000_000;
    fn time(at: u64) -> UnixMillis {
        UnixMillis::new(at).unwrap()
    }

    #[test]
    fn queue_delay_advances_first_set_and_known_clock_correction() {
        let received = Tick::from_millis(100);
        let now = Tick::from_millis(30_100);
        let offered = OfferedTime::new(FLOOR, received);
        assert_eq!(offered.at(now), Some(FLOOR + 30_000));
        for current in [None, Some(time(FLOOR + 30_000))] {
            let change = WallClock::new()
                .offer(offered, current, time(FLOOR), now)
                .unwrap();
            assert_eq!(change.new_value(), time(FLOOR + 30_000));
        }
        assert_eq!(offered.at(Tick::ZERO), None);
        assert_eq!(OfferedTime::new(u64::MAX, Tick::ZERO).at(now), None);
    }

    fn applied(clock: &mut WallClock) -> ClockChange {
        let change = clock
            .offer(
                OfferedTime::new(FLOOR, Tick::ZERO),
                None,
                time(FLOOR),
                Tick::ZERO,
            )
            .unwrap();
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::ZERO),
            OfferIntake::Queued
        );
        assert!(clock.applied(
            ReqId(1),
            OfferedTime::new(FLOOR, Tick::ZERO),
            change,
            Tick::ZERO
        ));
        change
    }

    #[test]
    fn failed_audit_keeps_original_until_durable_and_lost_reply_replays() {
        let mut clock = WallClock::new();
        let change = applied(&mut clock);
        assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
        assert_eq!(clock.audit_due(Tick::from_millis(999)), None);
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::from_millis(500)),
            OfferIntake::Pending
        );
        assert!(clock.audit_pending());
        assert!(!clock.applied(
            ReqId(2),
            OfferedTime::new(FLOOR, Tick::ZERO),
            change,
            Tick::ZERO
        ));
        let now = Tick::from_millis(1_000);
        assert_eq!(clock.audit_due(now), Some(change));
        assert_eq!(clock.audit_written(now), Some(Answered::Offer(ReqId(1))));
        clock.finished(ReqId(1)); // UART can now fail or the response can be lost.
        for tick in [1_000, 1_500, 2_499] {
            assert_eq!(
                clock.intake(ReqId(1), FLOOR, Tick::from_millis(tick)),
                OfferIntake::Accepted
            );
        }
        assert_eq!(
            clock.intake(ReqId(1), FLOOR + 1, now),
            OfferIntake::RateLimited
        );
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::from_millis(2_500)),
            OfferIntake::RateLimited
        );
        assert!(!clock.audit_pending());
        assert_eq!(clock.audit_due(Tick::from_millis(3_000)), None);
    }

    #[test]
    fn disconnect_and_restart_keep_audit_without_reply_to_new_link() {
        let mut clock = WallClock::new();
        let change = applied(&mut clock);
        clock.cancel_pending();
        assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
        assert_eq!(clock.audit_written(Tick::ZERO), None);
        assert!(!clock.audit_pending());
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::ZERO),
            OfferIntake::RateLimited
        );
        let mut rebooted = WallClock::new();
        assert!(rebooted.recover_audit(change));
        assert!(!rebooted.recover_audit(change));
        assert_eq!(rebooted.audit_due(Tick::ZERO), Some(change));
        assert_eq!(rebooted.audit_written(Tick::ZERO), None);
        assert!(!rebooted.audit_pending());
    }

    #[test]
    fn late_completion_is_not_evicted_and_request_id_can_be_reused_after_expiry() {
        let mut clock = WallClock::new();
        applied(&mut clock);
        let now = Tick::from_millis(900_000);
        assert_eq!(clock.audit_written(now), Some(Answered::Offer(ReqId(1))));
        clock.finished(ReqId(1));
        assert!(!clock.ready_for_offer(now));
        assert!(clock.ready_for_offer(Tick::from_millis(901_500)));
        assert_eq!(clock.intake(ReqId(2), FLOOR, now), OfferIntake::Full);
        assert_eq!(clock.intake(ReqId(1), FLOOR, now), OfferIntake::Accepted);
        assert_eq!(
            clock.intake(ReqId(1), FLOOR + 10, Tick::from_millis(901_500)),
            OfferIntake::Queued
        );
        clock.cancel_pending();
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::from_millis(901_500)),
            OfferIntake::Queued
        );
    }

    #[test]
    fn only_ready_lse_enables_calendar_access() {
        use crate::{RtcClock, RtcSource};
        for ready in [false, true] {
            for source in [
                RtcSource::None,
                RtcSource::Lse,
                RtcSource::Lsi,
                RtcSource::Hse,
            ] {
                assert_eq!(
                    RtcClock::from_backup_domain(ready, source).calendar_enabled(),
                    ready && source == RtcSource::Lse
                );
            }
        }
    }

    #[test]
    fn l_014_pending_work_and_answers_share_four_slots_without_eviction() {
        let mut clock = WallClock::new();
        for id in 1..=4 {
            assert_eq!(
                clock.intake(ReqId(id), FLOOR, Tick::ZERO),
                OfferIntake::Queued
            );
        }
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::ZERO),
            OfferIntake::Pending
        );
        assert_eq!(clock.intake(ReqId(5), FLOOR, Tick::ZERO), OfferIntake::Full);
        clock.finished(ReqId(2));
        assert_eq!(
            clock.intake(ReqId(5), FLOOR, Tick::ZERO),
            OfferIntake::Queued
        );
        clock.cancel_pending();
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::ZERO),
            OfferIntake::Queued
        );
        clock.offer_applied(Tick::ZERO);
        clock.cancel_pending();
        assert_eq!(
            clock.intake(ReqId(1), FLOOR, Tick::ZERO),
            OfferIntake::RateLimited
        );
        assert_eq!(clock.rate_refusals(), 1);
    }

    #[test]
    fn l_142_only_an_empty_timestamp_history_uses_the_build() {
        assert_eq!(WallClock::floor(None, FLOOR), Some(time(FLOOR)));
        assert_eq!(
            WallClock::floor(Some(FLOOR - 1), FLOOR),
            Some(time(FLOOR - 1))
        );
        assert_eq!(
            WallClock::floor(Some(FLOOR + 1), FLOOR),
            Some(time(FLOOR + 1))
        );
        assert_eq!(WallClock::floor(Some(0), FLOOR), None);
        assert_eq!(WallClock::floor(Some(FLOOR), 0), Some(time(FLOOR)));
        assert_eq!(WallClock::floor(None, 0), None);
    }

    #[test]
    fn l_140_l_142_first_set_checks_both_window_edges() {
        let mut clock = WallClock::new();
        for at in [0, FLOOR - 1, FLOOR + PLAUSIBILITY_SPAN + 1, u64::MAX] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    None,
                    time(FLOOR),
                    Tick::ZERO
                ),
                Err(TimeOffer::RefusedImplausible)
            );
        }
        for at in [FLOOR, FLOOR + PLAUSIBILITY_SPAN] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    None,
                    time(FLOOR),
                    Tick::ZERO
                ),
                Ok(ClockChange {
                    old: None,
                    new: time(at),
                    source: TimeSource::NtpViaComms,
                })
            );
        }
    }

    #[test]
    fn l_141_l_150_known_clock_corrects_both_ways_even_below_floor() {
        let mut clock = WallClock::new();
        for at in [FLOOR - 5_000, FLOOR + 5_000] {
            assert!(
                clock
                    .offer(
                        OfferedTime::new(at, Tick::ZERO),
                        Some(time(FLOOR)),
                        time(FLOOR + 10_000),
                        Tick::ZERO
                    )
                    .is_ok()
            );
        }
        for at in [FLOOR - 5_001, FLOOR + 5_001] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    Some(time(FLOOR)),
                    time(FLOOR),
                    Tick::ZERO
                ),
                Err(TimeOffer::RefusedStepTooLarge)
            );
        }
    }

    #[test]
    fn l_151_limit_uses_tick_and_counts_every_refusal() {
        let mut clock = WallClock::new();
        clock.offer_applied(Tick::from_millis(100));
        for now in [0, 100, 900_099] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(FLOOR, Tick::from_millis(now)),
                    None,
                    time(FLOOR),
                    Tick::from_millis(now)
                ),
                Err(TimeOffer::RefusedRateLimited)
            );
        }
        assert_eq!(clock.rate_refusals(), 3);
        assert!(
            clock
                .offer(
                    OfferedTime::new(FLOOR, Tick::from_millis(900_100)),
                    None,
                    time(FLOOR),
                    Tick::from_millis(900_100)
                )
                .is_ok()
        );
    }

    #[test]
    fn l_160_l_162_p_111_record_names_old_new_and_comms_provenance() {
        let mut clock = WallClock::new();
        for old in [None, Some(time(FLOOR))] {
            let change = clock
                .offer(
                    OfferedTime::new(FLOOR + 1, Tick::ZERO),
                    old,
                    time(FLOOR),
                    Tick::ZERO,
                )
                .unwrap();
            assert_eq!(
                change.record(),
                ControllerRecord::TimeSet {
                    old: old.map(UnixMillis::as_millis),
                    new: FLOOR + 1,
                    source: TimeSource::NtpViaComms,
                }
            );
            let mut bytes = [0; km43::CONTROLLER_RECORD_MAX_BYTES];
            let len = change.record().encode(&mut bytes).unwrap();
            assert_eq!(
                ControllerRecord::decode(km43::EventKind::TIME_SET, &bytes[..len]),
                Ok(change.record())
            );
        }
    }

    /// A floor past the clock's century refuses every first set: what the
    /// calendar can hold is below it, and what is not below it the calendar
    /// cannot hold.
    #[test]
    fn l_140_l_153_a_floor_past_the_clock_century_refuses_every_first_set() {
        let mut clock = WallClock::new();
        for at in [1, CENTURY_START, CENTURY_END, u64::MAX] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    None,
                    time(u64::MAX - 1),
                    Tick::ZERO
                ),
                Err(TimeOffer::RefusedImplausible)
            );
        }
    }

    fn at_floor(offset: i64) -> u64 {
        FLOOR.checked_add_signed(offset).unwrap()
    }

    #[test]
    fn p_113_a_client_time_past_the_ten_year_edge_is_rejected_armed_or_not() {
        for armed in [false, true] {
            assert_eq!(
                WallClock::client(FLOOR + PLAUSIBILITY_SPAN + 1, None, time(FLOOR), armed),
                ClientSet::Rejected
            );
            assert_eq!(
                WallClock::client(u64::MAX, Some(time(FLOOR)), time(FLOOR), armed),
                ClientSet::Rejected
            );
        }
        // The edge itself is inside.
        assert!(matches!(
            WallClock::client(FLOOR + PLAUSIBILITY_SPAN, None, time(FLOOR), false),
            ClientSet::Set { .. }
        ));
    }

    /// Every client write meets the floor, a known clock's too: there is no
    /// drift allowance on this door (P-114's "one floor, both doors").
    #[test]
    fn p_114_a_client_time_below_the_floor_needs_the_button_even_with_a_known_clock() {
        for current in [None, Some(time(FLOOR + 10_000))] {
            assert_eq!(
                WallClock::client(at_floor(-1), current, time(FLOOR), false),
                ClientSet::NeedsButton
            );
        }
        assert!(matches!(
            WallClock::client(FLOOR, None, time(FLOOR), false),
            ClientSet::Set {
                overridden: false,
                ..
            }
        ));
    }

    #[test]
    fn p_116_the_armed_override_accepts_below_the_floor_and_says_so() {
        let decided =
            WallClock::client(at_floor(-86_400_000), Some(time(FLOOR)), time(FLOOR), true);
        let ClientSet::Set {
            change,
            stepped,
            overridden,
        } = decided
        else {
            panic!("accepted on the override: {decided:?}");
        };
        assert!(overridden);
        assert!(stepped, "a day back from a known clock is a step too");
        assert_eq!(change.source(), TimeSource::Client);
        assert_eq!(change.new_value(), time(at_floor(-86_400_000)));
        // Above the floor, an armed override changes nothing and is not
        // spent.
        assert!(matches!(
            WallClock::client(at_floor(1), None, time(FLOOR), true),
            ClientSet::Set {
                overridden: false,
                ..
            }
        ));
    }

    /// The first and the last millisecond of the RTC's century.
    const CENTURY_START: u64 = 946_684_800_000;
    const CENTURY_END: u64 = 4_102_444_799_999;

    /// The override lifts the floor with no lower bound, and the RTC holds
    /// only its century: a value it cannot hold is refused here, before the
    /// clock moves, rather than failing at the write and answered busy for
    /// a retry that can never land.
    #[test]
    fn p_116_p_266_an_armed_override_below_the_clock_century_is_rejected() {
        for current in [None, Some(time(FLOOR))] {
            for at in [0, CENTURY_START - 1] {
                assert_eq!(
                    WallClock::client(at, current, time(FLOOR), true),
                    ClientSet::Rejected
                );
            }
            assert!(matches!(
                WallClock::client(CENTURY_START, current, time(FLOOR), true),
                ClientSet::Set {
                    overridden: true,
                    ..
                }
            ));
        }
    }

    /// P-114 comes first: unarmed, below the floor is the button however
    /// far below, the century's edge included.
    #[test]
    fn p_266_p_114_unarmed_below_the_floor_and_the_century_needs_the_button() {
        for current in [None, Some(time(FLOOR))] {
            for at in [0, CENTURY_START - 1, CENTURY_START] {
                assert_eq!(
                    WallClock::client(at, current, time(FLOOR), false),
                    ClientSet::NeedsButton
                );
            }
        }
    }

    /// A floor in 2095 opens a window to 2105: past the end of 2099 is
    /// inside P-113's window and outside the RTC, refused in either
    /// override state.
    #[test]
    fn p_266_past_the_clock_century_inside_the_window_is_rejected_armed_or_not() {
        let floor = time(3_944_678_400_000);
        assert!(CENTURY_END + 1 - floor.as_millis() < PLAUSIBILITY_SPAN);
        for armed in [false, true] {
            for current in [None, Some(floor)] {
                assert_eq!(
                    WallClock::client(CENTURY_END + 1, current, floor, armed),
                    ClientSet::Rejected
                );
                assert!(matches!(
                    WallClock::client(CENTURY_END, current, floor, armed),
                    ClientSet::Set {
                        overridden: false,
                        ..
                    }
                ));
            }
        }
    }

    /// An offer at `at` and then one at `next`, both at the same tick, on a
    /// fresh clock: the refusal's answer, the rate refusals it counted, and
    /// the next offer's answer, which is taken only if the refusal moved
    /// nothing and started no window.
    fn refused_then(
        at: u64,
        current: Option<UnixMillis>,
        floor: UnixMillis,
        next: u64,
    ) -> (
        Result<ClockChange, TimeOffer>,
        u64,
        Result<ClockChange, TimeOffer>,
    ) {
        let mut clock = WallClock::new();
        let offer = |clock: &mut WallClock, at| {
            clock.offer(OfferedTime::new(at, Tick::ZERO), current, floor, Tick::ZERO)
        };
        let refused = offer(&mut clock, at);
        let refusals = clock.rate_refusals();
        (refused, refusals, offer(&mut clock, next))
    }

    fn taken(current: Option<UnixMillis>, at: u64) -> ClockChange {
        ClockChange {
            old: current,
            new: time(at),
            source: TimeSource::NtpViaComms,
        }
    }

    /// A floor in 2095 opens L-140's window to 2105, and one before 2000
    /// opens it below the RTC's century: the first set is refused at both
    /// edges the window lets through.
    #[test]
    fn l_153_a_first_set_outside_the_clock_century_is_refused_implausible() {
        let late = time(3_944_678_400_000);
        assert!(CENTURY_END + 1 - late.as_millis() < PLAUSIBILITY_SPAN);
        assert_eq!(
            refused_then(CENTURY_END + 1, None, late, CENTURY_END),
            (
                Err(TimeOffer::RefusedImplausible),
                0,
                Ok(taken(None, CENTURY_END))
            )
        );
        let early = time(CENTURY_START - 1_000_000);
        assert_eq!(
            refused_then(CENTURY_START - 1, None, early, CENTURY_START),
            (
                Err(TimeOffer::RefusedImplausible),
                0,
                Ok(taken(None, CENTURY_START))
            )
        );
    }

    /// L-150's cap lets a known clock in the last seconds of 2099 or the
    /// first of 2000 step across the century's edge; L-153 does not.
    #[test]
    fn l_153_a_correction_across_either_century_edge_is_refused_implausible() {
        let late = Some(time(4_102_444_798_000));
        assert_eq!(
            refused_then(4_102_444_801_000, late, time(FLOOR), CENTURY_END),
            (
                Err(TimeOffer::RefusedImplausible),
                0,
                Ok(taken(late, CENTURY_END))
            )
        );
        let early = Some(time(946_684_801_000));
        assert_eq!(
            refused_then(946_684_799_000, early, time(FLOOR), CENTURY_START),
            (
                Err(TimeOffer::RefusedImplausible),
                0,
                Ok(taken(early, CENTURY_START))
            )
        );
    }

    /// The range binds the value as sent: queue time that carries one sent
    /// before 2000 into the century does not make it an offer the clock can
    /// hold. One sent inside it and carried past 2099 is refused too.
    #[test]
    fn l_153_queue_time_does_not_carry_an_offer_into_or_out_of_range_unrefused() {
        let received = Tick::ZERO;
        let now = Tick::from_millis(2);
        let early = Some(time(CENTURY_START + 1_000));
        let mut clock = WallClock::new();
        assert_eq!(
            clock.offer(
                OfferedTime::new(CENTURY_START - 1, received),
                early,
                time(FLOOR),
                now
            ),
            Err(TimeOffer::RefusedImplausible)
        );
        assert_eq!(
            clock.offer(
                OfferedTime::new(CENTURY_START, received),
                early,
                time(FLOOR),
                now
            ),
            Ok(taken(early, CENTURY_START + 2))
        );
        let late = Some(time(CENTURY_END - 1_000));
        assert_eq!(
            clock.offer(
                OfferedTime::new(CENTURY_END - 1, received),
                late,
                time(FLOOR),
                now
            ),
            Err(TimeOffer::RefusedImplausible)
        );
        assert_eq!(clock.rate_refusals(), 0);
    }

    /// An offer queued behind an accepted one and processed inside its
    /// window is rate limited even when its queue-advanced time overflows,
    /// and counted.
    #[test]
    fn l_151_l_153_a_queued_offer_whose_advance_overflows_is_still_rate_limited() {
        let mut clock = WallClock::new();
        clock.offer_applied(Tick::ZERO);
        let now = Tick::from_millis(10);
        assert_eq!(
            clock.offer(
                OfferedTime::new(u64::MAX, Tick::ZERO),
                None,
                time(FLOOR),
                now
            ),
            Err(TimeOffer::RefusedRateLimited)
        );
        assert_eq!(clock.rate_refusals(), 1);
        let mut clock = WallClock::new();
        assert_eq!(
            clock.offer(
                OfferedTime::new(u64::MAX, Tick::ZERO),
                None,
                time(FLOOR),
                now
            ),
            Err(TimeOffer::RefusedImplausible)
        );
    }

    /// A write the RTC refuses for a time it can hold is not L-153's
    /// refusal: no outcome is owed, nothing is retained, and L-151's window
    /// does not start, so the retry lands and then does start it.
    #[test]
    fn l_153_a_failed_calendar_write_owes_no_outcome_and_starts_nothing() {
        let mut clock = WallClock::new();
        let offered = OfferedTime::new(FLOOR, Tick::ZERO);
        let change = clock
            .offer(offered, None, time(FLOOR), Tick::ZERO)
            .expect("in range");
        assert_eq!(
            clock.offer_written(ReqId(1), offered, change, Err("rtc"), Tick::ZERO),
            OfferWritten::Failed { error: "rtc" }
        );
        assert!(!clock.audit_pending());
        assert_eq!(clock.audit_due(Tick::ZERO), None);
        let change = clock
            .offer(offered, None, time(FLOOR), Tick::ZERO)
            .expect("no window started");
        assert_eq!(
            clock.offer_written(ReqId(1), offered, change, Ok::<(), &str>(()), Tick::ZERO),
            OfferWritten::Applied { retained: true }
        );
        assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
        assert_eq!(
            clock.offer(offered, None, time(FLOOR), Tick::ZERO),
            Err(TimeOffer::RefusedRateLimited)
        );
    }

    #[test]
    fn l_151_l_153_an_offer_inside_the_rate_window_is_rate_limited_whatever_its_time() {
        let mut clock = WallClock::new();
        clock.offer_applied(Tick::ZERO);
        for (at, current) in [
            (CENTURY_END + 1, None),
            (CENTURY_END + 1, Some(time(CENTURY_END - 1_000))),
            (CENTURY_START - 1, Some(time(CENTURY_START + 1_000))),
        ] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::from_millis(1)),
                    current,
                    time(FLOOR),
                    Tick::from_millis(1)
                ),
                Err(TimeOffer::RefusedRateLimited)
            );
        }
        assert_eq!(clock.rate_refusals(), 3);
    }

    /// `refused_step_too_large` sends the correction to a client `Time`,
    /// which P-266 refuses for the same value: outcome 2 is the true answer.
    #[test]
    fn l_150_l_153_past_the_century_and_past_the_cap_is_implausible_not_a_step() {
        let mut clock = WallClock::new();
        let known = Some(time(CENTURY_END - 1_000));
        for at in [CENTURY_END + 10_000, u64::MAX] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    known,
                    time(FLOOR),
                    Tick::ZERO
                ),
                Err(TimeOffer::RefusedImplausible)
            );
        }
        let known = Some(time(CENTURY_START + 1_000));
        for at in [0, CENTURY_START - 10_000] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, Tick::ZERO),
                    known,
                    time(FLOOR),
                    Tick::ZERO
                ),
                Err(TimeOffer::RefusedImplausible)
            );
        }
        assert_eq!(
            clock.offer(
                OfferedTime::new(CENTURY_END - 10_000, Tick::ZERO),
                Some(time(CENTURY_END - 1_000)),
                time(FLOOR),
                Tick::ZERO
            ),
            Err(TimeOffer::RefusedStepTooLarge)
        );
    }

    #[test]
    fn p_115_only_a_known_clock_moved_past_an_hour_is_a_step() {
        let known = Some(time(FLOOR + TIME_STEP_ALARM));
        let set = |at| WallClock::client(at, known, time(FLOOR), false);
        let stepped = |decided: ClientSet| match decided {
            ClientSet::Set { stepped, .. } => stepped,
            ClientSet::Rejected | ClientSet::NeedsButton => panic!("{decided:?}"),
        };
        assert!(
            !stepped(set(FLOOR + TIME_STEP_ALARM * 2)),
            "exactly an hour"
        );
        assert!(stepped(set(FLOOR + TIME_STEP_ALARM * 2 + 1)));
        assert!(!stepped(set(FLOOR)), "exactly an hour back");
        // A first set is never a step, however far.
        assert!(!stepped(WallClock::client(
            FLOOR + PLAUSIBILITY_SPAN,
            None,
            time(FLOOR),
            false
        )));
    }

    #[test]
    fn p_118_one_client_time_per_fifteen_minutes_counted_apart_from_offers() {
        let mut clock = WallClock::new();
        let start = Tick::from_millis(1_000);
        assert!(!clock.client_rate_limited(start));
        let ClientSet::Set { change, .. } = WallClock::client(FLOOR, None, time(FLOOR), false)
        else {
            panic!("accepted");
        };
        assert!(clock.client_applied(change, start));
        let limit = start.after(CLIENT_INTERVAL).unwrap();
        assert!(clock.client_rate_limited(Tick::from_millis(1_001)));
        assert!(clock.client_rate_limited(Tick::from_millis(limit.as_millis() - 1)));
        assert!(!clock.client_rate_limited(limit));
        // An offer's limit is its own: a client set does not start it.
        assert!(!clock.refuse_rate_limited(Tick::from_millis(1_001)));
    }

    /// How the part fails the journal's write of a client's time.
    #[derive(Clone, Copy)]
    enum Fault {
        None,
        /// The RTC refuses a time it can hold.
        Calendar,
        /// A retained word does not read back: the time is not stored.
        Storage,
        /// The RTC takes the time and no retained word written after it
        /// reads back: the change's marker is not stored.
        Marker,
    }

    struct Part {
        words: [u32; crate::CLOCK_BACKUP_WORDS],
        fault: Fault,
        calendar: Option<UnixMillis>,
        taken: bool,
    }

    impl Part {
        fn new(fault: Fault) -> Self {
            Self {
                words: [0; crate::CLOCK_BACKUP_WORDS],
                fault,
                calendar: None,
                taken: false,
            }
        }
    }

    impl crate::CalendarStore for Part {
        type Error = ();
        fn read_word(&self, index: usize) -> Option<u32> {
            self.words.get(index).copied()
        }
        fn write_word(&mut self, index: usize, value: u32) {
            let stored = match self.fault {
                Fault::None | Fault::Calendar => true,
                Fault::Storage => false,
                Fault::Marker => !self.taken,
            };
            if let (Some(word), true) = (self.words.get_mut(index), stored) {
                *word = value;
            }
        }
        fn set_calendar(&mut self, at: UnixMillis) -> Result<(), ()> {
            match self.fault {
                Fault::Calendar => Err(()),
                Fault::None | Fault::Storage | Fault::Marker => {
                    self.calendar = Some(at);
                    self.taken = true;
                    Ok(())
                }
            }
        }
    }

    /// A write that fails, on the RTC or in the retained words, is not the
    /// range refusal: error 7, the clock and P-118's window untouched, the
    /// override kept, and the same time lands once the part takes it.
    #[test]
    fn p_266_a_failed_calendar_or_storage_write_is_busy_and_spends_nothing() {
        let at = CENTURY_START;
        let ClientSet::Set {
            change, overridden, ..
        } = WallClock::client(at, None, time(FLOOR), true)
        else {
            panic!("accepted on the override");
        };
        assert!(overridden);
        for (fault, error) in [
            (Fault::Calendar, crate::JournalError::Calendar(())),
            (Fault::Storage, crate::JournalError::Verify),
        ] {
            let mut clock = WallClock::new();
            let mut part = Part::new(fault);
            let mut journal = crate::ClockJournal::UNKNOWN;
            let written = journal.apply(&mut part, change);
            assert_eq!(
                clock.client_written(change, overridden, written, Tick::ZERO),
                ClientWritten::Failed {
                    error,
                    answer: TimeAnswer::Busy
                }
            );
            assert_eq!(journal.pending(), None);
            assert_eq!(part.calendar, None);
            assert!(!clock.audit_pending());
            assert!(!clock.client_rate_limited(Tick::ZERO));
            part.fault = Fault::None;
            let written = journal.apply(&mut part, change);
            assert_eq!(
                clock.client_written(change, overridden, written, Tick::ZERO),
                ClientWritten::Applied {
                    spend_override: true,
                    retained: true
                }
            );
            assert_eq!(part.calendar, Some(time(at)));
            assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
            assert!(clock.client_rate_limited(Tick::ZERO));
        }
    }

    /// The clock a part holds before a client's write: known, its record
    /// landed, with a fraction a lost marker could not fake.
    const KEPT: u64 = FLOOR + 456;
    /// Below the floor and more than an hour back from `KEPT`: accepted
    /// only on the armed override.
    const BELOW: u64 = FLOOR - 7_200_000 + 789;

    fn known(fault: Fault) -> (Part, crate::ClockJournal) {
        let mut part = Part::new(Fault::None);
        let mut journal = crate::ClockJournal::UNKNOWN;
        let first = ClockChange::recovered(None, time(KEPT), TimeSource::NtpViaComms);
        journal
            .apply(&mut part, first)
            .expect("the part takes the first set");
        journal.recorded(&mut part).expect("its record lands");
        part.fault = fault;
        part.taken = false;
        (part, journal)
    }

    fn overriding() -> ClockChange {
        let ClientSet::Set {
            change,
            stepped,
            overridden,
        } = WallClock::client(BELOW, Some(time(KEPT)), time(FLOOR), true)
        else {
            panic!("accepted on the override");
        };
        assert!(stepped && overridden);
        change
    }

    /// The RTC refuses a time it can hold, or the retained words refuse
    /// it first: error 7 and never outcome 2 (#238), and nothing spent.
    /// The clock is still known at the value it had, now and across a
    /// reset, P-118's window has not started, and the armed override is
    /// still there for the next write, which is the one that spends it.
    #[test]
    fn p_267_a_write_the_rtc_did_not_take_is_busy_and_spends_nothing() {
        let change = overriding();
        for (fault, error) in [
            (Fault::Calendar, crate::JournalError::Calendar(())),
            (Fault::Storage, crate::JournalError::Verify),
        ] {
            let (mut part, mut journal) = known(fault);
            let kept = journal;
            let mut clock = WallClock::new();
            let written = journal.apply(&mut part, change);
            assert_eq!(
                clock.client_written(change, true, written, Tick::ZERO),
                ClientWritten::Failed {
                    error,
                    answer: TimeAnswer::Busy
                }
            );
            assert_eq!(journal, kept);
            assert_eq!(journal.fraction(), Some(456));
            assert_eq!(crate::ClockJournal::load(&part), kept);
            assert_eq!(part.calendar, Some(time(KEPT)));
            assert!(!clock.audit_pending());
            assert!(!clock.client_rate_limited(Tick::ZERO));
            part.fault = Fault::None;
            let now = Tick::from_millis(1_000);
            let written = journal.apply(&mut part, change);
            assert_eq!(
                clock.client_written(change, true, written, now),
                ClientWritten::Applied {
                    spend_override: true,
                    retained: true
                }
            );
            assert_eq!(part.calendar, Some(time(BELOW)));
            assert!(clock.client_rate_limited(now));
        }
    }

    /// The RTC took the time and its marker did not read back: the change
    /// stands with its record owed, not a busy write with the RTC moved.
    /// The override is spent, P-118's window runs from the write, and the
    /// audit is due (P-267 rule 2).
    #[test]
    fn p_267_a_marker_that_does_not_read_back_after_the_rtc_took_the_time_owes_the_record() {
        let change = overriding();
        let (mut part, mut journal) = known(Fault::Marker);
        let mut clock = WallClock::new();
        let now = Tick::from_millis(5_000);
        let written = journal.apply(&mut part, change);
        assert_eq!(
            clock.client_written(change, true, written, now),
            ClientWritten::Applied {
                spend_override: true,
                retained: true
            }
        );
        assert_eq!(part.calendar, Some(time(BELOW)));
        assert_eq!(journal.pending(), Some(change));
        assert!(clock.client_rate_limited(now));
        assert!(!clock.client_rate_limited(now.after(CLIENT_INTERVAL).unwrap()));
        assert_eq!(clock.audit_due(now), Some(change));
    }

    /// A client's change with its record owed, whether the first append
    /// or the change's marker failed: the RTC moved, the override spent,
    /// the audit's first attempt taken and not landed.
    fn owed(fault: Fault, now: Tick) -> (Part, crate::ClockJournal, WallClock, ClockChange) {
        owed_by(WallClock::new(), fault, now)
    }

    /// The same, on a clock that already carries its own state.
    fn owed_by(
        mut clock: WallClock,
        fault: Fault,
        now: Tick,
    ) -> (Part, crate::ClockJournal, WallClock, ClockChange) {
        let change = overriding();
        let (mut part, mut journal) = known(fault);
        let written = journal.apply(&mut part, change);
        assert_eq!(
            clock.client_written(change, true, written, now),
            ClientWritten::Applied {
                spend_override: true,
                retained: true
            }
        );
        // The append fails: neither `recorded` nor `audit_written` runs.
        assert_eq!(clock.audit_due(now), Some(change));
        (part, journal, clock, change)
    }

    /// The `time set` append fails and the change stands: the clock stays
    /// moved, the rate limit runs from the write and not from the record,
    /// and outcome 1 is owed to nobody until a retry lands (P-267 rule 2).
    #[test]
    fn p_267_an_owed_record_holds_outcome_one_until_a_retried_append_lands() {
        let now = Tick::from_millis(5_000);
        for fault in [Fault::None, Fault::Marker] {
            let (mut part, mut journal, mut clock, change) = owed(fault, now);
            assert!(clock.audit_pending());
            assert_eq!(part.calendar, Some(time(BELOW)));
            assert_eq!(journal.pending(), Some(change));
            let early = now.after(Millis::from_millis(999)).unwrap();
            assert_eq!(clock.audit_due(early), None);
            let retry = now.after(AUDIT_RETRY).unwrap();
            assert_eq!(clock.audit_due(retry), Some(change));
            // A marker fault lasts: the record still ends the audit.
            journal
                .recorded(&mut part)
                .expect("the retried append lands");
            assert_eq!(clock.audit_written(retry), Some(Answered::Client));
            assert!(!clock.audit_pending());
            assert_eq!(journal.fraction(), Some(789));
            let rebooted = crate::ClockJournal::load(&part);
            match fault {
                Fault::Marker => assert_eq!(rebooted, crate::ClockJournal::UNKNOWN),
                Fault::None | Fault::Calendar | Fault::Storage => {
                    assert_eq!(rebooted.pending(), None);
                    assert_eq!(rebooted.fraction(), Some(789));
                }
            }
            let window = now.after(CLIENT_INTERVAL).unwrap();
            assert!(clock.client_rate_limited(Tick::from_millis(window.as_millis() - 1)));
            assert!(!clock.client_rate_limited(window));
        }
    }

    /// While the record is owed, the calendar's journal refuses a second
    /// change too, a client's past P-118's window or an offer's inside
    /// L-150's step, whatever the decisions above it say: two changes with
    /// one record owed are two records that could land in either order
    /// (P-267 rule 2).
    #[test]
    fn p_267_while_a_record_is_owed_no_other_clock_change_is_applied() {
        let now = Tick::from_millis(5_000);
        for fault in [Fault::None, Fault::Marker] {
            let (mut part, mut journal, mut clock, change) = owed(fault, now);
            part.fault = Fault::None;
            let later = now.after(CLIENT_INTERVAL).unwrap();
            assert!(!clock.client_rate_limited(later));
            let ClientSet::Set { change: client, .. } =
                WallClock::client(FLOOR + 60_000, Some(time(BELOW)), time(FLOOR), false)
            else {
                panic!("a client time the rules accept");
            };
            let offer = ClockChange::recovered(
                Some(time(BELOW)),
                time(BELOW + 1_000),
                TimeSource::NtpViaComms,
            );
            for other in [client, offer] {
                assert_eq!(
                    journal.apply(&mut part, other),
                    Err(crate::JournalError::Pending)
                );
                assert_eq!(part.calendar, Some(time(BELOW)));
                assert_eq!(journal.pending(), Some(change));
            }
            assert_eq!(clock.audit_due(later), Some(change));
        }
    }

    /// A signed client `Time` that arrives while the record is owed, past
    /// P-118's window, is error 7 before it executes, and nothing moves:
    /// not the calendar, not the owed change, not P-118's window, and the
    /// audit still retries the same record (P-267 rule 2).
    #[test]
    fn p_267_a_client_time_while_a_record_is_owed_gets_busy_and_changes_nothing() {
        let now = Tick::from_millis(5_000);
        for fault in [Fault::None, Fault::Marker] {
            let (part, journal, mut clock, change) = owed(fault, now);
            let later = now.after(CLIENT_INTERVAL).unwrap();
            assert!(!clock.client_rate_limited(later));
            let busy = clock.client_admitted(later).unwrap_err();
            assert_eq!(busy, ClientBusy::RecordOwed);
            assert_eq!(busy.answer(), TimeAnswer::Busy);
            // Inside P-118's window the owed record still names the refusal.
            assert_eq!(clock.client_admitted(now), Err(ClientBusy::RecordOwed));
            assert_eq!(part.calendar, Some(time(BELOW)));
            assert_eq!(journal.pending(), Some(change));
            assert!(!clock.client_rate_limited(later));
            assert_eq!(clock.audit_due(later), Some(change));
        }
    }

    /// Inside P-118's window with nothing owed the answer is the same
    /// error 7 for the window's reason, and past it the client is admitted.
    #[test]
    fn p_118_a_client_time_inside_the_window_is_busy_for_the_rate() {
        let mut clock = WallClock::new();
        assert_eq!(clock.client_admitted(Tick::ZERO), Ok(()));
        let ClientSet::Set { change, .. } = WallClock::client(FLOOR, None, time(FLOOR), false)
        else {
            panic!("accepted");
        };
        assert!(clock.client_applied(change, Tick::ZERO));
        assert_eq!(clock.audit_written(Tick::ZERO), Some(Answered::Client));
        let inside = Tick::from_millis(CLIENT_INTERVAL.as_millis() - 1);
        let busy = clock.client_admitted(inside).unwrap_err();
        assert_eq!(busy, ClientBusy::RateLimited);
        assert_eq!(busy.answer(), TimeAnswer::Busy);
        assert_eq!(
            clock.client_admitted(Tick::ZERO.after(CLIENT_INTERVAL).unwrap()),
            Ok(())
        );
    }

    /// While the record is owed an offer is `refused_rate_limited` when it
    /// is decided, whether it would correct inside L-150's step or past
    /// it, and the clock stays: not counted under L-151 and its window not
    /// started, so the first offer after the record lands is decided on
    /// the ordinary rules (L-154).
    #[test]
    fn l_154_an_offer_while_a_record_is_owed_is_refused_rate_limited_and_leaves_the_l_151_window_untouched()
     {
        let now = Tick::from_millis(5_000);
        for fault in [Fault::None, Fault::Marker] {
            let (mut part, mut journal, mut clock, change) = owed(fault, now);
            let later = now.after(Millis::from_millis(2_000)).unwrap();
            // The clock reads as known while its record is owed, so the
            // recorder decides against it with no floor scan first.
            assert_eq!(journal.fraction(), Some(789));
            assert!(clock.ready_for_offer(later));
            for at in [BELOW + 1_000, BELOW + OFFER_STEP + 1] {
                assert_eq!(
                    clock.offer(
                        OfferedTime::new(at, later),
                        Some(time(BELOW)),
                        time(FLOOR),
                        later
                    ),
                    Err(TimeOffer::RefusedRateLimited)
                );
            }
            assert_eq!(clock.rate_refusals(), 0);
            assert_eq!(part.calendar, Some(time(BELOW)));
            assert_eq!(journal.pending(), Some(change));
            // L-153 comes first: a time the clock can never hold is
            // implausible whether or not a record is owed, and not counted.
            assert_eq!(
                clock.offer(
                    OfferedTime::new(CENTURY_END + 1, later),
                    Some(time(BELOW)),
                    time(FLOOR),
                    later
                ),
                Err(TimeOffer::RefusedImplausible)
            );
            assert_eq!(clock.rate_refusals(), 0);
            // The record lands in the same tick; the next offer is the
            // ordinary rules', not a rate nobody exceeded.
            journal
                .recorded(&mut part)
                .expect("the retried append lands");
            assert_eq!(clock.audit_written(later), Some(Answered::Client));
            let next = OfferedTime::new(BELOW + 1_000, later);
            assert_eq!(
                clock.offer(next, Some(time(BELOW)), time(FLOOR), later),
                Ok(ClockChange::recovered(
                    Some(time(BELOW)),
                    time(BELOW + 1_000),
                    TimeSource::NtpViaComms
                ))
            );
            assert_eq!(
                clock.offer(
                    OfferedTime::new(BELOW + OFFER_STEP + 1, later),
                    Some(time(BELOW)),
                    time(FLOOR),
                    later
                ),
                Err(TimeOffer::RefusedStepTooLarge)
            );
            assert_eq!(clock.rate_refusals(), 0);
        }
    }

    /// An offer inside L-151's window while a record is owed gets L-151's
    /// refusal, which comes first and is counted, and the window it meets
    /// is the one the last accepted offer started (L-151, L-154).
    #[test]
    fn l_151_l_154_an_offer_inside_the_window_while_a_record_is_owed_is_counted() {
        let mut limited = WallClock::new();
        limited.offer_applied(Tick::ZERO);
        let now = Tick::from_millis(5_000);
        let (_, _, mut clock, change) = owed_by(limited, Fault::None, now);
        let inside = Tick::from_millis(OFFER_INTERVAL.as_millis() - 1);
        for (at, counted) in [(BELOW + 1_000, 1), (CENTURY_END + 1, 2)] {
            assert_eq!(
                clock.offer(
                    OfferedTime::new(at, inside),
                    Some(time(BELOW)),
                    time(FLOOR),
                    inside
                ),
                Err(TimeOffer::RefusedRateLimited)
            );
            assert_eq!(clock.rate_refusals(), counted);
        }
        // Past L-151's window with the record still owed: L-154's, uncounted.
        let past = Tick::ZERO.after(OFFER_INTERVAL).unwrap();
        assert_eq!(
            clock.offer(
                OfferedTime::new(BELOW + 1_000, past),
                Some(time(BELOW)),
                time(FLOOR),
                past
            ),
            Err(TimeOffer::RefusedRateLimited)
        );
        assert_eq!(clock.rate_refusals(), 2);
        assert_eq!(clock.audit_due(past), Some(change));
    }

    /// Once the record lands both doors open on their ordinary rules: a
    /// client `Time` past P-118's window is admitted and decided, and an
    /// offer inside L-150's step is accepted (P-267, L-154).
    #[test]
    fn p_267_l_154_a_client_time_and_an_offer_are_answered_normally_once_the_record_lands() {
        let now = Tick::from_millis(5_000);
        for fault in [Fault::None, Fault::Marker] {
            let (mut part, mut journal, mut clock, _) = owed(fault, now);
            let later = now.after(CLIENT_INTERVAL).unwrap();
            assert_eq!(clock.client_admitted(later), Err(ClientBusy::RecordOwed));
            journal
                .recorded(&mut part)
                .expect("the retried append lands");
            assert_eq!(clock.audit_written(later), Some(Answered::Client));
            assert_eq!(clock.client_admitted(later), Ok(()));
            let offer = clock
                .offer(
                    OfferedTime::new(BELOW + 1_000, later),
                    Some(time(BELOW)),
                    time(FLOOR),
                    later,
                )
                .expect("an offer inside the step once the record landed");
            part.fault = Fault::None;
            let written = journal.apply(&mut part, offer);
            assert_eq!(
                clock.offer_written(
                    ReqId(1),
                    OfferedTime::new(BELOW + 1_000, later),
                    offer,
                    written,
                    later
                ),
                OfferWritten::Applied { retained: true }
            );
            assert_eq!(part.calendar, Some(time(BELOW + 1_000)));
            assert_eq!(clock.rate_refusals(), 0);
        }
    }

    #[test]
    fn a_landed_write_at_the_floor_spends_no_override() {
        let ClientSet::Set {
            change, overridden, ..
        } = WallClock::client(FLOOR, None, time(FLOOR), true)
        else {
            panic!("accepted");
        };
        assert_eq!(
            WallClock::new().client_written::<()>(change, overridden, Ok(()), Tick::ZERO),
            ClientWritten::Applied {
                spend_override: false,
                retained: true
            }
        );
    }

    #[test]
    fn a_client_set_waits_for_its_audit_and_is_answered_to_the_client() {
        let mut clock = WallClock::new();
        let ClientSet::Set { change, .. } = WallClock::client(FLOOR, None, time(FLOOR), false)
        else {
            panic!("accepted");
        };
        assert!(clock.client_applied(change, Tick::ZERO));
        // One audit at a time: another change waits for this one.
        assert!(!clock.client_applied(change, Tick::ZERO));
        assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
        // A lost link cancels offers' replies and not a client's.
        clock.cancel_pending();
        assert_eq!(clock.audit_written(Tick::ZERO), Some(Answered::Client));
        assert!(clock.ready_for_offer(Tick::ZERO));
    }
}
