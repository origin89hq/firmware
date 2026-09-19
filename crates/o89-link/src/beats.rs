//! This side's own heartbeats whose answers still count (L-100).

use km43::ReqId;

/// How many of our own beats' answers still count: three periods, the whole
/// of the dead-link timer (L-100, L-110, L-120).
pub const BEATS_REMEMBERED: usize = 3;

/// Our own heartbeats waiting for their answers, newest first.
///
/// A heartbeat is not a request: one unanswered is a beat missed, and three
/// of those are the dead link, not a request to retry (L-015). Only the
/// first answer to a beat of ours proves the peer hears; an answer to
/// nothing, or one replayed, proves nothing. Full, the oldest is forgotten:
/// its answer, three periods late, proves nothing the newer ones cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beats([Option<ReqId>; BEATS_REMEMBERED]);

impl Beats {
    /// No beat waiting.
    pub const NONE: Self = Self([None; BEATS_REMEMBERED]);

    /// A beat of ours went out under `req_id`.
    pub fn sent(&mut self, req_id: ReqId) {
        self.0.rotate_right(1);
        if let Some(newest) = self.0.first_mut() {
            *newest = Some(req_id);
        }
    }

    /// Use up the beat `req_id` answers; `false` when it answers none.
    #[must_use = "an answer that proves nothing must not be heard"]
    pub fn answered(&mut self, req_id: ReqId) -> bool {
        match self.0.iter_mut().find(|sent| **sent == Some(req_id)) {
            Some(sent) => {
                *sent = None;
                true
            }
            None => false,
        }
    }

    /// Forget every beat: the link they belonged to fell, or the peer
    /// rebooted and its new boot answers none of them.
    pub fn forget(&mut self) {
        *self = Self::NONE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_100_a_beats_answer_counts_once() {
        let mut beats = Beats::NONE;
        beats.sent(ReqId(7));
        assert!(beats.answered(ReqId(7)));
        assert!(!beats.answered(ReqId(7)), "a replay is heard no more");
    }

    #[test]
    fn l_100_an_answer_to_a_beat_never_sent_counts_for_nothing() {
        let mut beats = Beats::NONE;
        assert!(!beats.answered(ReqId(1)));
        beats.sent(ReqId(2));
        assert!(!beats.answered(ReqId(3)));
        assert!(beats.answered(ReqId(2)));
    }

    #[test]
    fn l_100_the_fourth_beat_forgets_the_first_and_forgetting_forgets_all() {
        let mut beats = Beats::NONE;
        for req in 1..=4 {
            beats.sent(ReqId(req));
        }
        assert!(!beats.answered(ReqId(1)), "three periods late");
        assert!(beats.answered(ReqId(2)));
        beats.forget();
        assert!(!beats.answered(ReqId(3)));
        assert!(!beats.answered(ReqId(4)));
    }
}
