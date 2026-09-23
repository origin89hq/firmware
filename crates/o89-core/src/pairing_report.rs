//! What the controller owes the comms processor about its pairing window
//! (L-195): the window's current state after every link-up, on the
//! physical opening and on every closure.
//!
//! The panel owns the window; this owns only what was last reported of it.
//! A report is owed whenever the window the panel describes differs from
//! the one last reported, or the link came up. It is built when it is
//! first sent: `remaining_ms` from the monotonic deadline at that instant,
//! so a report held back by four requests in flight (L-014) is never the
//! original duration after a delay, and an opening that expired before it
//! left is sent as the closed state it has become. Each report takes the
//! next revision of this boot, from 1; a retry carries the one it was
//! built with, body and all (L-015). A newer report supersedes the one in
//! flight, so a closure is never queued behind the open state's retries.
//! The revisions never wrap: once the last has been used, the next report
//! owed is [`Unbuilt::Spent`], and the link falls for the rest of the boot.
//!
//! Nothing here holds a request slot or a request id of its own making:
//! the link issues and retires both, and this is told which.

use core::num::NonZeroU64;

use km43::{MAX_PAIRING_WINDOW_MS, PairingWindowNotice, ReqId};

use crate::tick::{Millis, Tick};

/// Why an owed report could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unbuilt {
    /// Every revision of this boot has been used (L-195).
    Spent,
    /// The body was refused by its codec. `remaining_ms` is clamped to the
    /// bound the codec checks, so this is a bug, reported rather than sent.
    Refused,
}

/// Where the revisions of this boot stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Revisions {
    /// The one the next report takes.
    Next(NonZeroU64),
    /// The last was used; the next report owed cannot be built.
    Exhausted,
    /// Exhausted, and the link fell for it: nothing is reported, and the
    /// link does not come back, until the controller reboots.
    Retired,
}

/// The report of the window, as far as the link has taken it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PairingReports {
    /// The panel's deadline while its window is open, as last observed.
    window: Option<Tick>,
    /// A report is owed: the window changed, or the link came up, since
    /// the last one was built.
    owed: bool,
    /// The revision the next report takes, or why there is none.
    next: Revisions,
    /// The report in flight, under the request carrying it.
    in_flight: Option<(ReqId, PairingWindowNotice)>,
}

impl PairingReports {
    /// At boot: the window closed, nothing reported, revision 1 next. The
    /// first link-up owes the closed state (L-195).
    pub(crate) const fn new() -> Self {
        Self {
            window: None,
            owed: false,
            next: Revisions::Next(NonZeroU64::MIN),
            in_flight: None,
        }
    }

    /// The panel's window at `now`: its deadline while open. A deadline
    /// already reached is the window closed.
    pub(crate) fn observe(&mut self, deadline: Option<Tick>, now: Tick) {
        let open = deadline.filter(|at| at.since(now).is_some_and(|left| left.as_millis() > 0));
        if open != self.window {
            self.window = open;
            self.owed = true;
        }
    }

    /// The link came up: the window's state is owed afresh, under a new
    /// revision, whether or not it changed (L-195).
    pub(crate) fn linked(&mut self) {
        self.owed = true;
    }

    /// Whether a report is owed.
    pub(crate) const fn owed(&self) -> bool {
        self.owed
    }

    /// The report in flight gives way to a newer one: its request, for the
    /// link to retire.
    pub(crate) fn supersede(&mut self) -> Option<ReqId> {
        self.in_flight.take().map(|(req_id, _)| req_id)
    }

    /// The owed report as it would leave at `now`, under the next
    /// revision; nothing is taken until [`PairingReports::sent`] says it
    /// left.
    pub(crate) fn prepare(&self, now: Tick) -> Result<PairingWindowNotice, Unbuilt> {
        let revision = match self.next {
            Revisions::Next(revision) => revision,
            Revisions::Exhausted | Revisions::Retired => return Err(Unbuilt::Spent),
        };
        let remaining = self
            .window
            .and_then(|deadline| deadline.since(now))
            .map_or(0, Millis::as_millis)
            .min(u64::from(MAX_PAIRING_WINDOW_MS));
        let remaining = u32::try_from(remaining).map_err(|_| Unbuilt::Refused)?;
        PairingWindowNotice::new(revision, remaining).map_err(|_| Unbuilt::Refused)
    }

    /// `notice`, from [`PairingReports::prepare`], left under `req_id`: its
    /// revision is used, and it is the report in flight.
    pub(crate) fn sent(&mut self, req_id: ReqId, notice: PairingWindowNotice) {
        self.next = notice
            .revision()
            .checked_add(1)
            .map_or(Revisions::Exhausted, Revisions::Next);
        self.owed = false;
        self.in_flight = Some((req_id, notice));
    }

    /// The report `req_id` carries, to send again unchanged; `None` when
    /// it has been superseded or answered.
    pub(crate) fn resend(&self, req_id: ReqId) -> Option<PairingWindowNotice> {
        self.in_flight
            .filter(|(id, _)| *id == req_id)
            .map(|(_, notice)| notice)
    }

    /// An acknowledgement of `revision` under `req_id`: it consumes the
    /// report in flight only when both are that report's.
    pub(crate) fn acknowledged(&mut self, req_id: ReqId, revision: NonZeroU64) -> bool {
        let matches = self
            .in_flight
            .is_some_and(|(id, notice)| id == req_id && notice.revision() == revision);
        if matches {
            self.in_flight = None;
        }
        matches
    }

    /// The report under `req_id` was given up after its attempts (L-015).
    pub(crate) fn given_up(&mut self, req_id: ReqId) {
        if self.in_flight.is_some_and(|(id, _)| id == req_id) {
            self.in_flight = None;
        }
    }

    /// The link fell or its requests were forgotten: the report in flight
    /// goes with it, and its request, if any, is the link's to retire.
    pub(crate) fn forget(&mut self) -> Option<ReqId> {
        self.supersede()
    }

    /// The link fell because the revisions ran out: it stays down for the
    /// rest of the boot (L-195).
    pub(crate) fn retire(&mut self) {
        self.next = Revisions::Retired;
    }

    /// Whether the link fell for want of a revision.
    pub(crate) const fn retired(&self) -> bool {
        matches!(self.next, Revisions::Retired)
    }

    /// Start the next report at `next`, so a test can reach exhaustion.
    #[cfg(test)]
    pub(crate) fn skip_to(&mut self, next: NonZeroU64) {
        self.next = Revisions::Next(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    /// Prepare the owed report and send it under `req_id`, as the link does.
    fn build(
        reports: &mut PairingReports,
        req_id: ReqId,
        now: Tick,
    ) -> Result<PairingWindowNotice, Unbuilt> {
        let notice = reports.prepare(now)?;
        reports.sent(req_id, notice);
        Ok(notice)
    }

    fn rev(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).expect("non-zero")
    }

    #[test]
    fn l_195_nothing_is_owed_before_the_link_and_the_first_link_up_owes_the_closed_state() {
        let mut reports = PairingReports::new();
        assert!(!reports.owed());
        reports.observe(None, at(10));
        assert!(!reports.owed(), "a closed window at boot is no change");
        reports.linked();
        assert!(reports.owed());
        let notice = build(&mut reports, ReqId(4), at(20)).expect("a revision");
        assert_eq!(notice.revision(), rev(1));
        assert_eq!(notice.remaining_ms(), 0);
        assert!(!reports.owed());
    }

    #[test]
    fn l_195_remaining_is_measured_from_the_deadline_when_the_report_is_built() {
        let mut reports = PairingReports::new();
        reports.observe(Some(at(125_000)), at(5_000));
        assert!(reports.owed());
        // Held back three seconds, the report says what is left then.
        let notice = build(&mut reports, ReqId(1), at(8_000)).expect("a revision");
        assert_eq!(notice.remaining_ms(), 117_000);
        // The same deadline observed again owes nothing.
        reports.observe(Some(at(125_000)), at(9_000));
        assert!(!reports.owed());
        // A second gesture moves the deadline: a new report.
        reports.observe(Some(at(130_000)), at(10_000));
        let notice = build(&mut reports, ReqId(2), at(10_000)).expect("a revision");
        assert_eq!(notice.remaining_ms(), 120_000);
        assert_eq!(notice.revision(), rev(2));
    }

    #[test]
    fn l_195_an_opening_that_expired_before_it_was_sent_goes_out_closed() {
        let mut reports = PairingReports::new();
        reports.observe(Some(at(125_000)), at(5_000));
        let notice = build(&mut reports, ReqId(1), at(125_000)).expect("a revision");
        assert_eq!(notice.remaining_ms(), 0, "built at its deadline");
        // A deadline handed in once it has passed is the window closed.
        let mut reports = PairingReports::new();
        reports.observe(Some(at(125_000)), at(5_000));
        let _ = build(&mut reports, ReqId(1), at(5_000)).expect("a revision");
        reports.observe(Some(at(125_000)), at(124_999));
        assert!(!reports.owed(), "still open");
        reports.observe(Some(at(125_000)), at(125_000));
        assert!(reports.owed(), "expiry is a closure");
        let notice = build(&mut reports, ReqId(1), at(126_000)).expect("a revision");
        assert_eq!(notice.remaining_ms(), 0);
    }

    #[test]
    fn l_193_a_deadline_further_than_the_physical_window_is_reported_as_the_window() {
        let mut reports = PairingReports::new();
        reports.observe(Some(at(1_000_000)), at(0));
        let notice = build(&mut reports, ReqId(1), at(0)).expect("a revision");
        assert_eq!(notice.remaining_ms(), MAX_PAIRING_WINDOW_MS);
    }

    #[test]
    fn l_195_every_report_takes_a_strictly_greater_revision_and_a_retry_keeps_its_own() {
        let mut reports = PairingReports::new();
        let mut last = 0;
        for (n, deadline) in [None, Some(at(200_000)), None, None]
            .into_iter()
            .enumerate()
        {
            reports.observe(deadline, at(100_000));
            reports.linked();
            let req_id = ReqId(u32::try_from(n).expect("small"));
            let notice = build(&mut reports, req_id, at(100_000)).expect("a revision");
            assert!(notice.revision().get() > last);
            last = notice.revision().get();
            assert_eq!(reports.resend(req_id), Some(notice), "the same body");
        }
        assert_eq!(last, 4);
    }

    #[test]
    fn l_195_a_newer_report_supersedes_the_one_in_flight() {
        let mut reports = PairingReports::new();
        reports.observe(Some(at(125_000)), at(5_000));
        let open = build(&mut reports, ReqId(1), at(5_000)).expect("a revision");
        reports.observe(None, at(6_000));
        assert_eq!(reports.supersede(), Some(ReqId(1)));
        assert_eq!(reports.resend(ReqId(1)), None, "no retry of the open state");
        let closed = build(&mut reports, ReqId(2), at(6_000)).expect("a revision");
        assert_eq!(closed.remaining_ms(), 0);
        assert!(closed.revision() > open.revision());
        // A late acknowledgement of the superseded report consumes nothing.
        assert!(!reports.acknowledged(ReqId(1), open.revision()));
        assert_eq!(reports.resend(ReqId(2)), Some(closed));
    }

    #[test]
    fn l_195_only_an_acknowledgement_of_the_request_and_its_revision_consumes_it() {
        let mut reports = PairingReports::new();
        reports.linked();
        let notice = build(&mut reports, ReqId(7), at(0)).expect("a revision");
        assert!(!reports.acknowledged(ReqId(8), notice.revision()));
        assert!(!reports.acknowledged(ReqId(7), rev(99)));
        assert_eq!(reports.resend(ReqId(7)), Some(notice));
        assert!(reports.acknowledged(ReqId(7), notice.revision()));
        assert_eq!(reports.resend(ReqId(7)), None);
        assert!(
            !reports.acknowledged(ReqId(7), notice.revision()),
            "used up"
        );
    }

    #[test]
    fn l_195_a_report_given_up_or_forgotten_is_not_sent_again() {
        let mut reports = PairingReports::new();
        reports.linked();
        let _ = build(&mut reports, ReqId(3), at(0)).expect("a revision");
        reports.given_up(ReqId(4));
        assert!(reports.resend(ReqId(3)).is_some(), "another request's");
        reports.given_up(ReqId(3));
        assert_eq!(reports.resend(ReqId(3)), None);
        assert_eq!(reports.forget(), None);
        reports.linked();
        let _ = build(&mut reports, ReqId(5), at(0)).expect("a revision");
        assert_eq!(reports.forget(), Some(ReqId(5)));
        assert_eq!(reports.resend(ReqId(5)), None);
    }

    #[test]
    fn l_195_the_revisions_never_wrap() {
        let mut reports = PairingReports::new();
        reports.skip_to(NonZeroU64::MAX);
        reports.linked();
        let last = build(&mut reports, ReqId(1), at(0)).expect("the last revision");
        assert_eq!(last.revision(), NonZeroU64::MAX);
        reports.linked();
        assert_eq!(reports.prepare(at(0)), Err(Unbuilt::Spent));
        assert!(!reports.retired(), "exhausted, not yet retired");
        reports.retire();
        assert!(reports.retired());
        assert_eq!(reports.prepare(at(0)), Err(Unbuilt::Spent));
        assert!(reports.owed(), "still owed, never sent");
        assert_eq!(
            reports.resend(ReqId(1)),
            Some(last),
            "the last is untouched"
        );
    }
}
