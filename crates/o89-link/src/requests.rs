//! The requests a side has in flight (L-014, L-015).

use km43::{LinkMessageType, ReqId};

use crate::{Millis, Tick};

/// How long a request waits for its answer before it goes again under its
/// own id (L-015).
pub const RESPONSE_TIMEOUT: Millis = Millis::from_millis(500);

/// How many times a request goes out before it is given up (L-015).
pub const ATTEMPTS: u8 = 3;

/// A request of ours the peer has not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    kind: LinkMessageType,
    req_id: ReqId,
    sent: Tick,
    attempts: u8,
}

/// What an overdue request comes to (L-015).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an overdue request nobody resends or reports is a rule nothing performed"]
pub enum Overdue {
    /// Send it again, under its own id.
    Resend {
        /// What it asks.
        kind: LinkMessageType,
        /// Its id, the same as every attempt before.
        req_id: ReqId,
    },
    /// Its last attempt went unanswered: given up, and failed to whatever
    /// asked.
    GivenUp {
        /// What it asked.
        kind: LinkMessageType,
        /// Its id.
        req_id: ReqId,
    },
}

/// The requests a side has in flight, at most `N` (L-014). Full, a new one
/// is refused rather than one in flight forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requests<const N: usize> {
    slots: [Option<Pending>; N],
}

impl<const N: usize> Requests<N> {
    /// None in flight.
    pub const NONE: Self = Self { slots: [None; N] };

    /// Whether `N` are in flight, so that no other may be issued.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.slots.iter().all(Option::is_some)
    }

    /// Put `kind` in flight under `req_id`, first sent at `now`. `false`,
    /// and nothing changed, when `N` already are (L-014).
    #[must_use = "a request refused for want of room was never sent"]
    pub fn issue(&mut self, kind: LinkMessageType, req_id: ReqId, now: Tick) -> bool {
        let Some(free) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *free = Some(Pending {
            kind,
            req_id,
            sent: now,
            attempts: 1,
        });
        true
    }

    /// Whether a request of `kind` is in flight.
    #[must_use]
    pub fn in_flight(&self, kind: LinkMessageType) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|pending| pending.kind == kind)
    }

    /// Whether `req_id` answers a request of `kind` in flight.
    #[must_use]
    pub fn awaits(&self, req_id: ReqId, kind: LinkMessageType) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|pending| pending.req_id == req_id && pending.kind == kind)
    }

    /// Use up the request of `kind` that `req_id` answers; `false` when it
    /// answers none.
    pub fn answered(&mut self, req_id: ReqId, kind: LinkMessageType) -> bool {
        let Some(slot) = self.slots.iter_mut().find(|slot| {
            slot.is_some_and(|pending| pending.req_id == req_id && pending.kind == kind)
        }) else {
            return false;
        };
        *slot = None;
        true
    }

    /// The first request whose answer is overdue at `now`, sent again or
    /// given up after its last attempt (L-015). Call until `None`: each call
    /// moves one request on, and one sent again is not overdue until another
    /// timeout passes, so `N` calls at most return something.
    pub fn overdue(&mut self, now: Tick) -> Option<Overdue> {
        for slot in &mut self.slots {
            let Some(pending) = slot else {
                continue;
            };
            let late = now
                .since(pending.sent)
                .is_some_and(|waited| waited >= RESPONSE_TIMEOUT);
            if !late {
                continue;
            }
            let (kind, req_id) = (pending.kind, pending.req_id);
            if pending.attempts >= ATTEMPTS {
                *slot = None;
                return Some(Overdue::GivenUp { kind, req_id });
            }
            pending.attempts = pending.attempts.saturating_add(1);
            pending.sent = now;
            return Some(Overdue::Resend { kind, req_id });
        }
        None
    }

    /// Forget every request in flight.
    pub fn forget(&mut self) {
        *self = Self::NONE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK_UP: LinkMessageType = LinkMessageType::LinkUp;

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    #[test]
    fn l_015_a_request_goes_again_under_its_own_id_and_is_given_up_after_three_attempts() {
        let mut requests = Requests::<1>::NONE;
        assert!(requests.issue(LINK_UP, ReqId(9), at(0)));
        assert_eq!(requests.overdue(at(499)), None);
        let resend = Some(Overdue::Resend {
            kind: LINK_UP,
            req_id: ReqId(9),
        });
        assert_eq!(requests.overdue(at(500)), resend);
        assert_eq!(requests.overdue(at(999)), None);
        assert_eq!(requests.overdue(at(1_000)), resend);
        assert_eq!(
            requests.overdue(at(1_500)),
            Some(Overdue::GivenUp {
                kind: LINK_UP,
                req_id: ReqId(9)
            })
        );
        assert!(!requests.in_flight(LINK_UP));
        assert_eq!(requests.overdue(at(9_000)), None);
    }

    #[test]
    fn l_015_an_answer_uses_its_request_up_and_only_its_own_kind_and_id_answer_it() {
        let mut requests = Requests::<2>::NONE;
        assert!(requests.issue(LINK_UP, ReqId(1), at(0)));
        assert!(!requests.awaits(ReqId(2), LINK_UP));
        assert!(!requests.awaits(ReqId(1), LinkMessageType::Heartbeat));
        assert!(!requests.answered(ReqId(1), LinkMessageType::Heartbeat));
        assert!(requests.awaits(ReqId(1), LINK_UP));
        assert!(requests.answered(ReqId(1), LINK_UP));
        assert!(!requests.answered(ReqId(1), LINK_UP), "used up");
        assert_eq!(requests.overdue(at(5_000)), None);
    }

    #[test]
    fn l_014_a_full_table_refuses_the_next_request_and_keeps_the_ones_in_flight() {
        let mut requests = Requests::<2>::NONE;
        assert!(requests.issue(LINK_UP, ReqId(1), at(0)));
        assert!(requests.issue(LINK_UP, ReqId(2), at(0)));
        assert!(requests.is_full());
        assert!(!requests.issue(LINK_UP, ReqId(3), at(0)));
        assert!(requests.awaits(ReqId(1), LINK_UP));
        assert!(requests.awaits(ReqId(2), LINK_UP));
        assert!(!requests.awaits(ReqId(3), LINK_UP));
        requests.forget();
        assert!(!requests.is_full());
        assert!(!requests.in_flight(LINK_UP));
    }
}
