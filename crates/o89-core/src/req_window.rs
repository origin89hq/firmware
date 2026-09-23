//! P-022's `req_id` window, one per session.
//!
//! The highest `req_id` the session has accepted and which of the ids just
//! below it it has accepted too. A request is refused when its id was
//! accepted already, or when it is below `highest − MAX_INFLIGHT`; inside
//! that band it may arrive in any order, which is the reorder four requests
//! in flight already permit. The check sits after the MAC and before the
//! counter is read, and the window is dropped with the session it belongs
//! to.
//!
//! This is what bounds how old a signed write can be when it lands: a frame
//! held back is refused once the client's next requests move the highest
//! past it, or once the session and its key are gone. It is also what keeps
//! a response recorded earlier in the session from answering a later
//! request under the same `(session_id, req_id)`.
//!
//! `req_id` is a `u32` that KM43 says outlasts the hardware, so there is no
//! wrap: an id past `u32::MAX` does not exist, and a zero after it is below
//! the window like any other old id.
//!
//! cites: P-022

use km43::{MAX_INFLIGHT, ReqId};

/// Ids the window remembers: the highest and the `MAX_INFLIGHT` below it.
/// The floor is accepted, so the band is one wider than the in-flight
/// count. Remember only `MAX_INFLIGHT` and the id at the floor falls out
/// of memory while still inside the window, and its replay passes both
/// checks.
const SPAN: usize = MAX_INFLIGHT.saturating_add(1);

/// Why a `req_id` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a req_id refused and acted on anyway is the replay P-022 exists to stop"]
pub enum OutOfWindow {
    /// Accepted already in this session.
    Replayed,
    /// Below `highest − MAX_INFLIGHT`: too old to say whether it was seen.
    BelowWindow,
}

/// A session's `req_id` window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqWindow {
    /// The highest `req_id` accepted.
    highest: u32,
    /// `seen[d]`: whether `highest − d` was accepted.
    seen: [bool; SPAN],
}

impl ReqWindow {
    /// The window of a session that `opened` bound: the `Hello` is its
    /// first accepted request.
    #[must_use]
    pub fn opened_by(opened: ReqId) -> Self {
        let mut seen = [false; SPAN];
        if let Some(newest) = seen.first_mut() {
            *newest = true;
        }
        Self {
            highest: opened.0,
            seen,
        }
    }

    /// Accept `req_id`, or say why not. A refusal changes nothing.
    pub fn accept(&mut self, req_id: ReqId) -> Result<(), OutOfWindow> {
        let ReqId(id) = req_id;
        if let Some(ahead) = id.checked_sub(self.highest).filter(|ahead| *ahead > 0) {
            self.advance(ahead);
            self.highest = id;
            if let Some(newest) = self.seen.first_mut() {
                *newest = true;
            }
            return Ok(());
        }
        let slot = self
            .highest
            .checked_sub(id)
            .and_then(|behind| usize::try_from(behind).ok())
            .and_then(|behind| self.seen.get_mut(behind))
            .ok_or(OutOfWindow::BelowWindow)?;
        if *slot {
            return Err(OutOfWindow::Replayed);
        }
        *slot = true;
        Ok(())
    }

    /// Move the band up by `ahead`: what falls below the new floor is
    /// forgotten, and the ids it skipped have not been seen.
    fn advance(&mut self, ahead: u32) {
        let shift = usize::try_from(ahead).unwrap_or(usize::MAX);
        for at in (0..SPAN).rev() {
            let was = at
                .checked_sub(shift)
                .and_then(|from| self.seen.get(from))
                .copied()
                .unwrap_or(false);
            if let Some(slot) = self.seen.get_mut(at) {
                *slot = was;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(opened: u32) -> ReqWindow {
        ReqWindow::opened_by(ReqId(opened))
    }

    #[test]
    fn p_022_each_new_req_id_is_accepted_once_and_its_replay_refused() {
        let mut window = window(1);
        for id in 2..=40 {
            assert_eq!(window.accept(ReqId(id)), Ok(()), "{id}");
            assert_eq!(window.accept(ReqId(id)), Err(OutOfWindow::Replayed), "{id}");
        }
        // The Hello that opened the session is inside the window and was
        // accepted.
        let mut fresh = self::window(7);
        assert_eq!(fresh.accept(ReqId(7)), Err(OutOfWindow::Replayed));
    }

    #[test]
    fn p_022_a_req_id_below_highest_minus_max_inflight_is_refused() {
        let mut window = window(10);
        assert_eq!(window.accept(ReqId(20)), Ok(()));
        // 16 is the floor, 20 − 4: never seen, accepted.
        assert_eq!(window.accept(ReqId(16)), Ok(()));
        // 15 is below it, never seen, and refused anyway: the controller
        // cannot tell a delayed frame from a withheld one.
        assert_eq!(window.accept(ReqId(15)), Err(OutOfWindow::BelowWindow));
        assert_eq!(window.accept(ReqId(10)), Err(OutOfWindow::BelowWindow));
        assert_eq!(window.accept(ReqId(0)), Err(OutOfWindow::BelowWindow));
    }

    #[test]
    fn p_022_requests_reordered_inside_the_window_are_each_accepted_once() {
        let mut window = window(1);
        // Four in flight, 2 to 5, arriving 5, 3, 2, 4.
        for id in [5, 3, 2, 4] {
            assert_eq!(window.accept(ReqId(id)), Ok(()), "{id}");
        }
        for id in 1..=5 {
            assert_eq!(window.accept(ReqId(id)), Err(OutOfWindow::Replayed), "{id}");
        }
        // A gap stays open until the band moves past it.
        assert_eq!(window.accept(ReqId(8)), Ok(()));
        assert_eq!(window.accept(ReqId(7)), Ok(()));
        assert_eq!(window.accept(ReqId(6)), Ok(()));
        // 4 is the floor of the band under 8, and was accepted.
        assert_eq!(window.accept(ReqId(4)), Err(OutOfWindow::Replayed));
        assert_eq!(window.accept(ReqId(3)), Err(OutOfWindow::BelowWindow));
    }

    #[test]
    fn p_022_the_id_at_the_floor_is_still_remembered_when_accepted_earlier() {
        // The band is five wide: an id accepted, then the highest moved
        // four past it, is at the floor, and its replay must still be
        // caught rather than read as unseen.
        let mut window = window(100);
        assert_eq!(window.accept(ReqId(104)), Ok(()));
        assert_eq!(window.accept(ReqId(100)), Err(OutOfWindow::Replayed));
        assert_eq!(window.accept(ReqId(99)), Err(OutOfWindow::BelowWindow));
    }

    #[test]
    fn p_022_a_jump_past_the_band_forgets_everything_below_the_new_floor() {
        let mut window = window(1);
        assert_eq!(window.accept(ReqId(2)), Ok(()));
        assert_eq!(window.accept(ReqId(1_000)), Ok(()));
        // Skipped ids inside the new band are unseen, and accepted.
        assert_eq!(window.accept(ReqId(996)), Ok(()));
        assert_eq!(window.accept(ReqId(995)), Err(OutOfWindow::BelowWindow));
        assert_eq!(window.accept(ReqId(2)), Err(OutOfWindow::BelowWindow));
    }

    #[test]
    fn p_022_the_top_of_the_u32_space_does_not_wrap() {
        let mut window = window(u32::MAX - 1);
        assert_eq!(window.accept(ReqId(u32::MAX)), Ok(()));
        assert_eq!(window.accept(ReqId(u32::MAX)), Err(OutOfWindow::Replayed));
        assert_eq!(window.accept(ReqId(u32::MAX - 4)), Ok(()));
        assert_eq!(
            window.accept(ReqId(u32::MAX - 5)),
            Err(OutOfWindow::BelowWindow)
        );
        // Zero after the top is an old id, not the next one.
        assert_eq!(window.accept(ReqId(0)), Err(OutOfWindow::BelowWindow));
        assert_eq!(window.accept(ReqId(1)), Err(OutOfWindow::BelowWindow));
    }

    #[test]
    fn p_022_near_zero_the_floor_saturates_and_nothing_underflows() {
        let mut window = window(0);
        assert_eq!(window.accept(ReqId(0)), Err(OutOfWindow::Replayed));
        assert_eq!(window.accept(ReqId(2)), Ok(()));
        assert_eq!(window.accept(ReqId(1)), Ok(()));
        assert_eq!(window.accept(ReqId(1)), Err(OutOfWindow::Replayed));
    }
}
