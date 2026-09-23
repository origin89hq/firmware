//! Wall-clock admission; every duration remains on the monotonic tick.
//!
//! The recorder supplies the newest timestamp from `Ring::floor`. A failed
//! scan is not an empty ring and must never become the build-time fallback.
//!
//! cites: L-014, L-140, L-141, L-142, L-150, L-151, L-152, L-160, L-162, P-111, P-215

use km43::{ControllerRecord, MAX_INFLIGHT, ReqId, TimeOffer, TimeSource};

use crate::{Calendar, Millis, Tick, UnixMillis};

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
    /// Outcome 2: past the window's upper edge, which nothing lifts (P-113).
    Rejected,
    /// Outcome 4: below the floor with no override armed (P-114).
    NeedsButton,
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
    /// This does not move the clock. Call `offer_applied` only after the
    /// adapter successfully sets it. No peer accuracy or source claim enters
    /// this decision (L-152, L-162).
    pub fn offer(
        &mut self,
        at: u64,
        current: Option<UnixMillis>,
        floor: UnixMillis,
        now: Tick,
    ) -> Result<ClockChange, TimeOffer> {
        if self.refuse_rate_limited(now) {
            return Err(TimeOffer::RefusedRateLimited);
        }
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
        let new = UnixMillis::new(at).ok_or(TimeOffer::RefusedImplausible)?;
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
    pub fn applied(
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

    /// Queued work also waits for a late audit's reply-cache horizon. This
    /// prevents an older queued request from evicting a completed acceptance.
    #[must_use]
    pub fn ready_for_offer(&self, now: Tick) -> bool {
        self.audit.is_none()
            && self
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
    /// This does not move the clock or spend the override: the adapter sets
    /// the calendar, then calls [`client_applied`](Self::client_applied),
    /// then spends the override if this was `overridden`.
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
        let Some(new) = UnixMillis::new(at).filter(|new| Calendar::from_unix(*new).is_some())
        else {
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

    /// Retain a client's applied change until its audit is durable, and
    /// start P-118's window. Refused, like an offer's, while another audit
    /// is owed.
    #[must_use]
    pub fn client_applied(&mut self, change: ClockChange, now: Tick) -> bool {
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
                .offer(offered.at(now).unwrap(), current, time(FLOOR), now)
                .unwrap();
            assert_eq!(change.new_value(), time(FLOOR + 30_000));
        }
        assert_eq!(offered.at(Tick::ZERO), None);
        assert_eq!(OfferedTime::new(u64::MAX, Tick::ZERO).at(now), None);
    }

    fn applied(clock: &mut WallClock) -> ClockChange {
        let change = clock.offer(FLOOR, None, time(FLOOR), Tick::ZERO).unwrap();
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
                clock.offer(at, None, time(FLOOR), Tick::ZERO),
                Err(TimeOffer::RefusedImplausible)
            );
        }
        for at in [FLOOR, FLOOR + PLAUSIBILITY_SPAN] {
            assert_eq!(
                clock.offer(at, None, time(FLOOR), Tick::ZERO),
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
                    .offer(at, Some(time(FLOOR)), time(FLOOR + 10_000), Tick::ZERO)
                    .is_ok()
            );
        }
        for at in [0, FLOOR - 5_001, FLOOR + 5_001] {
            assert_eq!(
                clock.offer(at, Some(time(FLOOR)), time(FLOOR), Tick::ZERO),
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
                clock.offer(FLOOR, None, time(FLOOR), Tick::from_millis(now)),
                Err(TimeOffer::RefusedRateLimited)
            );
        }
        assert_eq!(clock.rate_refusals(), 3);
        assert!(
            clock
                .offer(FLOOR, None, time(FLOOR), Tick::from_millis(900_100))
                .is_ok()
        );
    }

    #[test]
    fn l_160_l_162_p_111_record_names_old_new_and_comms_provenance() {
        let mut clock = WallClock::new();
        for old in [None, Some(time(FLOOR))] {
            let change = clock
                .offer(FLOOR + 1, old, time(FLOOR), Tick::ZERO)
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

    #[test]
    fn failed_calendar_write_does_not_start_the_limit() {
        let mut clock = WallClock::new();
        assert!(clock.offer(FLOOR, None, time(FLOOR), Tick::ZERO).is_ok());
        assert!(clock.offer(FLOOR, None, time(FLOOR), Tick::ZERO).is_ok());
        assert_eq!(clock.rate_refusals(), 0);
    }

    #[test]
    fn l_140_window_near_integer_limit_does_not_wrap() {
        let mut clock = WallClock::new();
        assert!(
            clock
                .offer(u64::MAX, None, time(u64::MAX - 1), Tick::ZERO)
                .is_ok()
        );
        assert_eq!(
            clock.offer(1, None, time(u64::MAX - 1), Tick::ZERO),
            Err(TimeOffer::RefusedImplausible)
        );
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

    /// The override lifts the floor with no lower bound, and the RTC holds
    /// only its century: a value it cannot hold is refused here, before the
    /// clock moves, rather than failing at the write and answered busy for
    /// a retry that can never land.
    #[test]
    fn p_116_an_armed_override_below_the_calendar_century_is_rejected() {
        assert_eq!(
            WallClock::client(0, Some(time(FLOOR)), time(FLOOR), true),
            ClientSet::Rejected
        );
        assert_eq!(
            WallClock::client(946_684_799_999, None, time(FLOOR), true),
            ClientSet::Rejected
        );
        assert!(matches!(
            WallClock::client(946_684_800_000, None, time(FLOOR), true),
            ClientSet::Set {
                overridden: true,
                ..
            }
        ));
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
        assert!(!clock.ready_for_offer(Tick::ZERO));
        assert_eq!(clock.audit_due(Tick::ZERO), Some(change));
        // A lost link cancels offers' replies and not a client's.
        clock.cancel_pending();
        assert_eq!(clock.audit_written(Tick::ZERO), Some(Answered::Client));
        assert!(clock.ready_for_offer(Tick::ZERO));
    }
}
