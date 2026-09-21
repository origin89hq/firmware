//! The link from the comms processor's side (L-030 to L-051, L-100, L-120).
//!
//! `LinkUp` from boot and every two seconds until the controller answers
//! one of them, each retried under its own id and given up after three
//! attempts (L-015), and linked only by that answer (L-033). The
//! controller's own statement is recorded and answered, never a link; a
//! changed controller `boot_id` unlinks this side and closes every client
//! connection, of which there are none yet (L-042). A heartbeat every two
//! seconds while linked, the controller's answered at once (L-100); six
//! seconds since the controller last answered a request of ours and the
//! link is down, clients closed, nothing served from memory, `LinkUp`
//! retried (L-120, L-121). What the controller says of its own accord keeps
//! no link alive, and neither does an answer to a request this side never
//! made or has already heard answered: only the first answer to one of its
//! own proves the controller hears. A refusal from the controller is never
//! answered (L-181); an `EnterDownload` after the window is refused as such
//! (L-191); a request the session layer does not exist for is answered with
//! a real outcome, never silence. The version agreed is the lower minor; a
//! major mismatch keeps `LinkUp`, `Heartbeat` and `CommsRelease` only
//! (L-050).
//!
//! The mechanics are `o89-link`'s, shared with the controller's link: the
//! requests in flight and their retries, the beats whose answers count, and
//! the rules every link-local frame meets.

use km43::{
    CloseConnection, CloseConnections, CloseReport, DownloadRequest, DownloadVerdict,
    EnterDownload, FrameWriter, Heartbeat, Intake, LinkEnvelope, LinkErrorCode, LinkMessageType,
    LinkUp, MAX_FRAME, NetChange, NetConfig, NetVerdict, ReqId, Side, Version, arriving,
};
use o89_link::{
    Beats, DEAD_AFTER, EncodeError, HEARTBEAT_PERIOD, LINK_ENVELOPE, LINKUP_PERIOD, Millis, OURS,
    Overdue, Requests, Tick, crosses_mismatch, frame_refusal, is_peer_refusal, link_header,
    refused_before_link,
};

/// What this side says of itself in every `LinkUp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a> {
    /// Key 4: this firmware (L-034).
    pub fw: &'a str,
    /// Key 6: the board the module sits on (L-034).
    pub hw: &'a str,
    /// Key 5: drawn at this boot (L-040).
    pub boot_id: u32,
}

/// A frame the link asks the firmware to put on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a frame the link asked for and nobody sent is a rule nothing performed"]
pub enum Frame {
    /// This side's statement (L-030).
    LinkUp {
        /// The request, in flight until answered or given up.
        req_id: ReqId,
    },
    /// The answer to the controller's statement.
    LinkUpAck {
        /// The controller's request.
        req_id: ReqId,
    },
    /// A heartbeat (L-100).
    Heartbeat {
        /// The beat, remembered until answered.
        req_id: ReqId,
    },
    /// The answer to the controller's heartbeat, sent at once (L-100).
    HeartbeatAck {
        /// The controller's request.
        req_id: ReqId,
    },
    /// `refused_outside_window` (L-191).
    DownloadRefused {
        /// The controller's request.
        req_id: ReqId,
    },
    /// The report on a close the controller asked for.
    CloseReport {
        /// The controller's request.
        req_id: ReqId,
        /// What happened.
        outcome: CloseConnection,
    },
    /// A network configuration that could not be stored (L-137).
    NetFailed {
        /// The controller's request.
        req_id: ReqId,
    },
    /// A link-local refusal, on session 0 with request 0 (L-181).
    Refuse {
        /// Why.
        code: LinkErrorCode,
    },
}

/// What the controller last said about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Controller {
    boot_id: u32,
    /// Whether the majors agree: under a mismatch only `LinkUp`,
    /// `Heartbeat` and `CommsRelease` cross (L-050).
    agreed: bool,
}

/// The link's state on this side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    #[cfg(any(test, feature = "frames"))]
    controller_bench_mode: Option<bool>,
    boot: Tick,
    /// The controller's last statement, from its `LinkUp` or its answer to
    /// ours.
    controller: Option<Controller>,
    /// Our `LinkUp` was answered by the controller's current boot (L-033).
    linked: bool,
    /// When the controller last answered a request of ours (L-100, L-120).
    last_heard: Option<Tick>,
    next_statement: Tick,
    next_beat: Tick,
    next_req: u32,
    /// Our `LinkUp` in flight: one at a time, like the controller's, because
    /// two statements out for one answer would each claim it.
    statement: Requests<1>,
    /// Our last heartbeats: only the first answer to one of these is the
    /// controller heard (L-100).
    beats: Beats,
}

impl Link {
    /// The link at boot: unlinked, with a `LinkUp` due at once (L-120).
    #[must_use]
    pub const fn new(now: Tick) -> Self {
        Self {
            #[cfg(any(test, feature = "frames"))]
            controller_bench_mode: None,
            boot: now,
            controller: None,
            linked: false,
            last_heard: None,
            next_statement: now,
            next_beat: now,
            next_req: 1,
            statement: Requests::NONE,
            beats: Beats::NONE,
        }
    }

    /// Whether this side is linked (L-033).
    #[must_use]
    pub const fn is_linked(&self) -> bool {
        self.linked
    }

    /// Bench mode advertised by a validated controller handshake, if any.
    #[cfg(any(test, feature = "frames"))]
    #[must_use]
    pub const fn controller_bench_mode(&self) -> Option<bool> {
        self.controller_bench_mode
    }

    #[cfg(any(test, feature = "frames"))]
    fn record_bench(&mut self, firmware: &str) {
        self.controller_bench_mode = crate::frame_bench::controller_mode(firmware);
    }

    /// When the controller last answered a request of ours.
    #[must_use]
    pub const fn last_heard(&self) -> Option<Tick> {
        self.last_heard
    }

    /// Time passed: the link drops six seconds after the controller last
    /// answered (L-120), a beat goes out on its cadence while linked
    /// (L-100), and while not, the statement in flight is sent again or
    /// given up (L-015) and a new one goes out on its cadence.
    pub fn tick(&mut self, now: Tick) -> Option<Frame> {
        if self.linked
            && self
                .last_heard
                .and_then(|heard| now.since(heard))
                .is_some_and(|silent| silent >= DEAD_AFTER)
        {
            // L-120: close every client, stop advertising, refuse new ones:
            // none exist before M4, and the statement below is what remains.
            self.unlink(now);
        }
        if self.linked {
            if now < self.next_beat {
                return None;
            }
            self.next_beat = now.after(HEARTBEAT_PERIOD).unwrap_or(now);
            let req_id = self.take_req();
            self.beats.sent(req_id);
            return Some(Frame::Heartbeat { req_id });
        }
        match self.statement.overdue(now) {
            Some(Overdue::Resend { req_id, .. }) => return Some(Frame::LinkUp { req_id }),
            // Given up: nothing asked for it but the cadence, which states
            // anew.
            Some(Overdue::GivenUp { .. }) | None => {}
        }
        if now < self.next_statement {
            return None;
        }
        self.next_statement = now.after(LINKUP_PERIOD).unwrap_or(now);
        if self.statement.in_flight(LinkMessageType::LinkUp) {
            return None;
        }
        let req_id = self.take_req();
        self.statement
            .issue(LinkMessageType::LinkUp, req_id, now)
            .then_some(Frame::LinkUp { req_id })
    }

    /// A frame from the controller, and what it is answered with, if
    /// anything.
    pub fn received(&mut self, envelope: LinkEnvelope<'_>, now: Tick) -> Option<Frame> {
        if is_peer_refusal(&envelope) {
            // The controller refused something of ours: never answered with
            // another error (L-181), and nothing waits on it.
            return None;
        }
        let kind = match arriving(envelope.opcode(), Side::Comms, envelope.session()) {
            Intake::Act(kind) => kind,
            Intake::Refuse(code) => return Some(Frame::Refuse { code }),
        };
        let req_id = envelope.req_id();
        if let Some(Controller { agreed: false, .. }) = self.controller
            && !crosses_mismatch(Side::Comms, kind)
        {
            return Some(Frame::Refuse {
                code: LinkErrorCode::LinkMajorMismatch,
            });
        }
        if !self.linked && refused_before_link(Side::Comms, kind) {
            // Before the link only the handshake is admitted (L-033): a
            // request answered now would be answered for a controller whose
            // statement this side has not had answered.
            return Some(Frame::Refuse {
                code: LinkErrorCode::BeforeLinkUp,
            });
        }
        match kind {
            LinkMessageType::LinkUp => {
                let theirs = LinkUp::decode(envelope).ok()?;
                if theirs.role != Side::Controller {
                    return Some(Frame::Refuse {
                        code: LinkErrorCode::WrongSide,
                    });
                }
                self.stated(theirs.boot_id, theirs.version, now);
                #[cfg(any(test, feature = "frames"))]
                self.record_bench(theirs.fw);
                Some(Frame::LinkUpAck { req_id })
            }
            LinkMessageType::LinkUpAck => {
                // Only an answer to the statement in flight links, and it
                // is used up only once it validates: a malformed one, or one
                // claiming the wrong role, leaves the statement waiting.
                if !self.statement.awaits(req_id, LinkMessageType::LinkUp) {
                    return None;
                }
                let theirs = LinkUp::decode(envelope).ok()?;
                if theirs.role != Side::Controller {
                    return Some(Frame::Refuse {
                        code: LinkErrorCode::WrongSide,
                    });
                }
                let _ = self.statement.answered(req_id, LinkMessageType::LinkUp);
                self.linked(theirs.boot_id, theirs.version, now);
                #[cfg(any(test, feature = "frames"))]
                self.record_bench(theirs.fw);
                None
            }
            LinkMessageType::Heartbeat => {
                // Answered at once, and not heard: it proves the controller
                // can talk, not that it can hear (L-100).
                Heartbeat::decode(envelope).ok()?;
                Some(Frame::HeartbeatAck { req_id })
            }
            LinkMessageType::HeartbeatAck => {
                Heartbeat::decode(envelope).ok()?;
                if self.beats.answered(req_id) {
                    self.last_heard = Some(now);
                }
                None
            }
            LinkMessageType::EnterDownload => {
                // The window has closed (L-191): answered, never acted on.
                DownloadRequest::decode(envelope).ok()?;
                Some(Frame::DownloadRefused { req_id })
            }
            LinkMessageType::CloseConnection => {
                // No connection rows before M4: nothing to close, which is a
                // real report and not silence.
                let close = CloseConnections::decode(envelope).ok()?;
                let outcome = if close.is_every_connection() {
                    CloseConnection::Closed
                } else {
                    CloseConnection::UnknownHandle
                };
                Some(Frame::CloseReport { req_id, outcome })
            }
            LinkMessageType::NetConfig => {
                // No credential store before M4: the write fails, which
                // L-137 says to report as such, and the controller pushes
                // again after the next `LinkUp` (L-133).
                NetChange::decode(envelope).ok()?;
                Some(Frame::NetFailed { req_id })
            }
            LinkMessageType::CommsRelease => {
                // No installer before M7: refused with the one code that
                // says nothing was authorised to land here.
                Some(Frame::Refuse {
                    code: LinkErrorCode::NoAuthorisation,
                })
            }
            LinkMessageType::ClientConnectedAck
            | LinkMessageType::ClientDisconnectedAck
            | LinkMessageType::TimeOfferAck => {
                // Answers to requests this side does not make yet: nothing
                // waits, and an answer to nothing is not heard.
                None
            }
            LinkMessageType::ClientConnected
            | LinkMessageType::ClientDisconnected
            | LinkMessageType::CloseConnectionAck
            | LinkMessageType::NetConfigAck
            | LinkMessageType::TimeOffer
            | LinkMessageType::CommsReleaseAck
            | LinkMessageType::EnterDownloadAck => {
                // Refused by `arriving` at this side; an arm so a change to
                // the direction table lands here.
                Some(Frame::Refuse {
                    code: LinkErrorCode::WrongSide,
                })
            }
        }
    }

    /// Build `frame` as this side sends it at `now`, framed into `dst`, and
    /// its length.
    pub fn build(
        &self,
        frame: Frame,
        me: &Identity<'_>,
        now: Tick,
        writer: &mut FrameWriter,
        dst: &mut [u8; MAX_FRAME],
    ) -> Result<usize, EncodeError> {
        let mut envelope = [0u8; LINK_ENVELOPE];
        let statement = |kind, req_id, envelope: &mut [u8]| {
            LinkUp {
                version: OURS,
                role: Side::Comms,
                fw: me.fw,
                boot_id: me.boot_id,
                hw: me.hw,
                net_version: Some(0),
            }
            .write(link_header(kind, req_id), envelope)
        };
        let beat = |kind, req_id, envelope: &mut [u8]| {
            Heartbeat {
                uptime_s: self.uptime_s(now),
                conns: 0,
            }
            .write(link_header(kind, req_id), envelope)
        };
        let written = match frame {
            Frame::LinkUp { req_id } => statement(LinkMessageType::LinkUp, req_id, &mut envelope),
            Frame::LinkUpAck { req_id } => {
                statement(LinkMessageType::LinkUpAck, req_id, &mut envelope)
            }
            Frame::Heartbeat { req_id } => beat(LinkMessageType::Heartbeat, req_id, &mut envelope),
            Frame::HeartbeatAck { req_id } => {
                beat(LinkMessageType::HeartbeatAck, req_id, &mut envelope)
            }
            Frame::DownloadRefused { req_id } => DownloadVerdict {
                outcome: EnterDownload::RefusedOutsideWindow,
            }
            .write(
                link_header(LinkMessageType::EnterDownloadAck, req_id),
                &mut envelope,
            ),
            Frame::CloseReport { req_id, outcome } => CloseReport { outcome, closed: 0 }.write(
                link_header(LinkMessageType::CloseConnectionAck, req_id),
                &mut envelope,
            ),
            Frame::NetFailed { req_id } => NetVerdict {
                outcome: NetConfig::NvsWriteFailed,
                version: 0,
            }
            .write(
                link_header(LinkMessageType::NetConfigAck, req_id),
                &mut envelope,
            ),
            Frame::Refuse { code } => return frame_refusal(code, writer, dst),
        };
        let len = written.map_err(|_| EncodeError::Body)?;
        let envelope = envelope.get(..len).ok_or(EncodeError::Body)?;
        writer.write(envelope, dst).map_err(EncodeError::Frame)
    }

    /// Record a statement of the controller's. A changed `boot_id` is a
    /// controller that rebooted: every client connection closes (L-042),
    /// none before M4, and this side is unlinked, because the new boot has
    /// answered nothing of ours (L-033); a beat sent to the old boot is
    /// forgotten with it.
    fn record(&mut self, boot_id: u32, version: Version) {
        if self
            .controller
            .is_some_and(|known| known.boot_id != boot_id)
        {
            self.linked = false;
            self.beats.forget();
        }
        let agreed = OURS.agreed(version).is_ok();
        self.controller = Some(Controller { boot_id, agreed });
    }

    /// The controller stated itself of its own accord: recorded and
    /// answered, never a link (L-033). Unlinked, this side states itself at
    /// once, or as soon as the statement in flight is answered or given up.
    fn stated(&mut self, boot_id: u32, version: Version, now: Tick) {
        self.record(boot_id, version);
        if !self.linked {
            self.next_statement = now;
        }
    }

    /// The controller answered our statement: that is the link (L-033), and
    /// a round trip, so it is heard (L-100).
    fn linked(&mut self, boot_id: u32, version: Version, now: Tick) {
        self.record(boot_id, version);
        self.linked = true;
        self.last_heard = Some(now);
        self.next_beat = now.after(HEARTBEAT_PERIOD).unwrap_or(now);
    }

    /// The link is down (L-120): every beat still waiting is forgotten, and
    /// this side states itself at once.
    fn unlink(&mut self, now: Tick) {
        self.linked = false;
        self.beats.forget();
        self.next_statement = now;
    }

    fn take_req(&mut self) -> ReqId {
        let req = ReqId(self.next_req);
        // Wraps, and may recur: nothing here carries a MAC (L-013).
        self.next_req = self.next_req.wrapping_add(1);
        req
    }

    /// Seconds since this side started, saturating (key 1 of a heartbeat).
    fn uptime_s(&self, now: Tick) -> u32 {
        now.since(self.boot)
            .map_or(0, Millis::as_secs)
            .try_into()
            .unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use km43::{
        CloseReason, ErrorBody, FrameReader, Header, Incoming, LinkError, MessageType, Received,
        SessionId,
    };

    use super::*;

    const CONTROLLER_BOOT: u32 = 0x00C0_FFEE;
    const ME: Identity<'static> = Identity {
        fw: "0.0.0+g0123abcd",
        hw: "controller-a rev A",
        boot_id: 0x5939_BB7A,
    };

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    fn decoded(envelope: &[u8; 256], len: Result<usize, LinkError>) -> LinkEnvelope<'_> {
        let len = len.expect("the controller's frame encodes");
        LinkEnvelope::decode(envelope.get(..len).expect("fits")).expect("an envelope")
    }

    /// A statement from a side claiming `role`, as `kind`.
    fn statement(
        buf: &mut [u8; 256],
        kind: LinkMessageType,
        req_id: ReqId,
        role: Side,
        boot_id: u32,
        version: Version,
    ) -> LinkEnvelope<'_> {
        let len = LinkUp {
            version,
            role,
            fw: "0.0.0+g0123abcd",
            boot_id,
            hw: "controller-a rev A",
            net_version: None,
        }
        .write(link_header(kind, req_id), buf);
        decoded(buf, len)
    }

    fn from_controller(
        buf: &mut [u8; 256],
        kind: LinkMessageType,
        req_id: ReqId,
    ) -> LinkEnvelope<'_> {
        statement(buf, kind, req_id, Side::Controller, CONTROLLER_BOOT, OURS)
    }

    fn beat(buf: &mut [u8; 256], kind: LinkMessageType, req_id: ReqId) -> LinkEnvelope<'_> {
        let len = Heartbeat {
            uptime_s: 3,
            conns: 0,
        }
        .write(link_header(kind, req_id), buf);
        decoded(buf, len)
    }

    #[test]
    fn bench_mode_comes_only_from_an_accepted_controller_statement() {
        for kind in [LinkMessageType::LinkUp, LinkMessageType::LinkUpAck] {
            for (role, req_id, accepted) in [
                (Side::Controller, ReqId(1), true),
                (Side::Comms, ReqId(1), false),
                (Side::Controller, ReqId(99), kind == LinkMessageType::LinkUp),
            ] {
                let mut link = Link::new(Tick::ZERO);
                assert!(matches!(
                    link.tick(Tick::ZERO),
                    Some(Frame::LinkUp { req_id: ReqId(1) })
                ));
                let mut buf = [0u8; 256];
                let len = LinkUp {
                    version: OURS,
                    role,
                    fw: "0.0.0-bn+g0123abcd",
                    boot_id: CONTROLLER_BOOT,
                    hw: "controller-a rev A",
                    net_version: None,
                }
                .write(link_header(kind, req_id), &mut buf);
                let _ = link.received(decoded(&buf, len), at(1));
                assert_eq!(link.controller_bench_mode(), accepted.then_some(true));
                // A later ordinary controller must remove the bench identity.
                let ordinary = from_controller(&mut buf, LinkMessageType::LinkUp, ReqId(2));
                let _ = link.received(ordinary, at(2));
                assert_eq!(link.controller_bench_mode(), None);
            }
        }
    }

    /// A link that stated itself at boot and heard the controller answer.
    fn linked_at_boot() -> Link {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        let mut buf = [0u8; 256];
        let answer = from_controller(&mut buf, LinkMessageType::LinkUpAck, req_id);
        assert_eq!(link.received(answer, Tick::ZERO), None);
        assert!(link.is_linked());
        link
    }

    #[test]
    fn l_033_this_side_is_linked_only_by_an_answer_to_its_own_link_up() {
        let link = linked_at_boot();
        assert_eq!(link.last_heard(), Some(Tick::ZERO));
    }

    #[test]
    fn l_033_the_controllers_own_statement_is_answered_and_links_nothing() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id: first }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        assert_eq!(link.tick(at(500)), Some(Frame::LinkUp { req_id: first }));
        assert_eq!(link.tick(at(1_000)), Some(Frame::LinkUp { req_id: first }));
        assert_eq!(link.tick(at(1_500)), None, "the first statement given up");
        let mut buf = [0u8; 256];
        let theirs = from_controller(&mut buf, LinkMessageType::LinkUp, ReqId(40));
        assert_eq!(
            link.received(theirs, at(1_600)),
            Some(Frame::LinkUpAck { req_id: ReqId(40) })
        );
        assert!(!link.is_linked());
        // Unlinked with nothing in flight, this side states itself at once
        // rather than at its cadence.
        let Some(Frame::LinkUp { req_id }) = link.tick(at(1_600)) else {
            panic!("a statement at once");
        };
        assert_ne!(req_id, first);
    }

    #[test]
    fn l_033_an_answer_to_a_link_up_this_side_never_sent_links_nothing() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        let mut buf = [0u8; 256];
        let stray = from_controller(
            &mut buf,
            LinkMessageType::LinkUpAck,
            ReqId(req_id.0.wrapping_add(100)),
        );
        assert_eq!(link.received(stray, at(10)), None);
        assert!(!link.is_linked());
        assert_eq!(link.last_heard(), None);
    }

    #[test]
    fn l_033_an_answer_claiming_the_comms_role_is_refused_and_the_statement_still_waits() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        let mut buf = [0u8; 256];
        let wrong = statement(
            &mut buf,
            LinkMessageType::LinkUpAck,
            req_id,
            Side::Comms,
            CONTROLLER_BOOT,
            OURS,
        );
        assert_eq!(
            link.received(wrong, at(10)),
            Some(Frame::Refuse {
                code: LinkErrorCode::WrongSide
            })
        );
        assert!(!link.is_linked());
        let right = from_controller(&mut buf, LinkMessageType::LinkUpAck, req_id);
        assert_eq!(link.received(right, at(20)), None);
        assert!(link.is_linked());
    }

    #[test]
    fn l_120_from_boot_link_up_goes_out_every_two_seconds_until_answered() {
        let mut link = Link::new(Tick::ZERO);
        let mut statements = 0u32;
        let mut last = None;
        // Bounded: a tick every 100 ms for ten seconds.
        for step in 0..100u64 {
            let now = at(step.checked_mul(100).expect("fits"));
            match link.tick(now) {
                Some(Frame::LinkUp { req_id }) if last != Some(req_id) => {
                    assert_eq!(
                        now.as_millis() % 2_000,
                        0,
                        "a new statement off cadence at {now:?}"
                    );
                    statements = statements.checked_add(1).expect("fits");
                    last = Some(req_id);
                }
                Some(Frame::LinkUp { .. }) | None => {}
                Some(other) => panic!("{other:?} while unlinked"),
            }
        }
        assert_eq!(statements, 5);
    }

    #[test]
    fn l_015_a_statement_is_retried_under_its_own_id_and_given_up_after_three_attempts() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        assert_eq!(link.tick(at(499)), None);
        assert_eq!(link.tick(at(500)), Some(Frame::LinkUp { req_id }));
        assert_eq!(link.tick(at(999)), None);
        assert_eq!(link.tick(at(1_000)), Some(Frame::LinkUp { req_id }));
        // The third attempt unanswered at 1 500 ms is given up, and the
        // next statement waits for the cadence under a new id.
        assert_eq!(link.tick(at(1_500)), None);
        assert_eq!(link.tick(at(1_999)), None);
        let Some(Frame::LinkUp { req_id: next }) = link.tick(at(2_000)) else {
            panic!("a new statement at two seconds");
        };
        assert_ne!(next, req_id);
        // An answer to the one given up links nothing.
        let mut buf = [0u8; 256];
        let late = from_controller(&mut buf, LinkMessageType::LinkUpAck, req_id);
        assert_eq!(link.received(late, at(2_100)), None);
        assert!(!link.is_linked());
    }

    #[test]
    fn l_015_an_answer_to_a_retry_links() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        assert_eq!(link.tick(at(500)), Some(Frame::LinkUp { req_id }));
        let mut buf = [0u8; 256];
        let answer = from_controller(&mut buf, LinkMessageType::LinkUpAck, req_id);
        assert_eq!(link.received(answer, at(700)), None);
        assert!(link.is_linked());
        assert_eq!(link.last_heard(), Some(at(700)));
    }

    #[test]
    fn l_015_the_controllers_statement_waits_for_the_one_in_flight() {
        let mut link = Link::new(Tick::ZERO);
        let Some(Frame::LinkUp { req_id }) = link.tick(Tick::ZERO) else {
            panic!("a statement at boot");
        };
        let mut buf = [0u8; 256];
        let theirs = from_controller(&mut buf, LinkMessageType::LinkUp, ReqId(40));
        assert_eq!(
            link.received(theirs, at(100)),
            Some(Frame::LinkUpAck { req_id: ReqId(40) })
        );
        // Due at once, but one statement is in flight: nothing new goes out
        // until it is answered or given up.
        assert_eq!(link.tick(at(100)), None);
        assert_eq!(link.tick(at(500)), Some(Frame::LinkUp { req_id }));
    }

    #[test]
    fn l_100_a_beat_goes_out_every_two_seconds_and_its_answer_is_heard_once() {
        let mut link = linked_at_boot();
        assert_eq!(link.tick(at(1_999)), None);
        let Some(Frame::Heartbeat { req_id }) = link.tick(at(2_000)) else {
            panic!("a beat at two seconds");
        };
        let mut buf = [0u8; 256];
        let answer = beat(&mut buf, LinkMessageType::HeartbeatAck, req_id);
        assert_eq!(link.received(answer, at(2_010)), None);
        assert_eq!(link.last_heard(), Some(at(2_010)));
        // The same answer again is a replay: used up, and heard no more.
        let replay = beat(&mut buf, LinkMessageType::HeartbeatAck, req_id);
        assert_eq!(link.received(replay, at(3_000)), None);
        assert_eq!(link.last_heard(), Some(at(2_010)));
    }

    #[test]
    fn l_120_answers_to_beats_never_sent_do_not_keep_the_link_up() {
        // A controller that stopped hearing, or a line that invents one: an
        // answer every second to a request this side never made.
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let mut dropped_at = None;
        // Bounded: a step every 500 ms for ten seconds.
        for step in 1..=20u64 {
            let now = at(step.checked_mul(500).expect("fits"));
            let stray = beat(&mut buf, LinkMessageType::HeartbeatAck, ReqId(0xDEAD));
            assert_eq!(link.received(stray, now), None);
            let _ = link.tick(now);
            if dropped_at.is_none() && !link.is_linked() {
                dropped_at = Some(now);
            }
        }
        assert_eq!(
            dropped_at,
            Some(at(6_000)),
            "six seconds after the last answer"
        );
        assert_eq!(link.last_heard(), Some(Tick::ZERO));
    }

    #[test]
    fn l_120_a_link_whose_beats_are_answered_stays_up() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        // Bounded: a step every 100 ms for a minute.
        for step in 1..=600u64 {
            let now = at(step.checked_mul(100).expect("fits"));
            if let Some(Frame::Heartbeat { req_id }) = link.tick(now) {
                let answer = beat(&mut buf, LinkMessageType::HeartbeatAck, req_id);
                assert_eq!(link.received(answer, now), None);
            }
            assert!(link.is_linked(), "dropped at {now:?}");
        }
    }

    #[test]
    fn l_120_the_dropped_link_states_itself_in_the_same_tick() {
        let mut link = linked_at_boot();
        let _ = link.tick(at(2_000));
        let _ = link.tick(at(4_000));
        assert!(matches!(link.tick(at(6_000)), Some(Frame::LinkUp { .. })));
        assert!(!link.is_linked());
        // An answer to a beat sent before the drop counts for nothing now.
        let mut buf = [0u8; 256];
        let late = beat(&mut buf, LinkMessageType::HeartbeatAck, ReqId(2));
        assert_eq!(link.received(late, at(6_100)), None);
        assert_eq!(link.last_heard(), Some(Tick::ZERO));
    }

    #[test]
    fn l_100_the_controllers_heartbeat_is_answered_at_once_and_not_heard() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let theirs = beat(&mut buf, LinkMessageType::Heartbeat, ReqId(77));
        assert_eq!(
            link.received(theirs, at(1_500)),
            Some(Frame::HeartbeatAck { req_id: ReqId(77) })
        );
        assert_eq!(link.last_heard(), Some(Tick::ZERO));
    }

    #[test]
    fn l_042_a_controller_that_rebooted_unlinks_this_side_and_its_old_beats_count_for_nothing() {
        let mut link = linked_at_boot();
        let Some(Frame::Heartbeat { req_id }) = link.tick(at(2_000)) else {
            panic!("a beat at two seconds");
        };
        let mut buf = [0u8; 256];
        let rebooted = statement(
            &mut buf,
            LinkMessageType::LinkUp,
            ReqId(1),
            Side::Controller,
            CONTROLLER_BOOT.wrapping_add(1),
            OURS,
        );
        assert_eq!(
            link.received(rebooted, at(2_100)),
            Some(Frame::LinkUpAck { req_id: ReqId(1) })
        );
        assert!(!link.is_linked());
        let old = beat(&mut buf, LinkMessageType::HeartbeatAck, req_id);
        assert_eq!(link.received(old, at(2_200)), None);
        assert_eq!(link.last_heard(), Some(Tick::ZERO));
    }

    #[test]
    fn l_181_a_refusal_from_the_controller_is_never_answered() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let len = ErrorBody {
            code: Incoming::LinkLocal(LinkErrorCode::WrongSide),
            detail: "",
        }
        .write(
            Header {
                kind: MessageType::ErrorResponse,
                session: SessionId::None,
                req_id: ReqId(0),
            },
            &mut buf,
        )
        .expect("encodes");
        let refusal = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert_eq!(link.received(refusal, at(100)), None);
        assert!(link.is_linked());
    }

    #[test]
    fn l_191_enter_download_after_the_window_is_refused_as_such() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let len = DownloadRequest {
            reason: km43::DownloadReason::Recovery,
        }
        .write(
            link_header(LinkMessageType::EnterDownload, ReqId(9)),
            &mut buf,
        );
        let request = decoded(&buf, len);
        assert_eq!(
            link.received(request, at(100)),
            Some(Frame::DownloadRefused { req_id: ReqId(9) })
        );
    }

    #[test]
    fn l_050_under_a_major_mismatch_only_link_local_frames_cross() {
        let mut link = Link::new(Tick::ZERO);
        let mut buf = [0u8; 256];
        let newer = statement(
            &mut buf,
            LinkMessageType::LinkUp,
            ReqId(1),
            Side::Controller,
            CONTROLLER_BOOT,
            Version { major: 2, minor: 0 },
        );
        assert_eq!(
            link.received(newer, at(10)),
            Some(Frame::LinkUpAck { req_id: ReqId(1) })
        );
        let len = CloseConnections {
            conn: 0,
            reason: CloseReason::Resync,
        }
        .write(
            link_header(LinkMessageType::CloseConnection, ReqId(2)),
            &mut buf,
        );
        let close = decoded(&buf, len);
        assert_eq!(
            link.received(close, at(20)),
            Some(Frame::Refuse {
                code: LinkErrorCode::LinkMajorMismatch
            })
        );
        let theirs = beat(&mut buf, LinkMessageType::Heartbeat, ReqId(3));
        assert_eq!(
            link.received(theirs, at(30)),
            Some(Frame::HeartbeatAck { req_id: ReqId(3) })
        );
    }

    #[test]
    fn l_033_a_request_before_the_link_is_refused_with_258_and_answered_after() {
        let mut link = Link::new(Tick::ZERO);
        let mut buf = [0u8; 256];
        let close = |buf: &mut [u8; 256], req| {
            let len = CloseConnections {
                conn: 0,
                reason: CloseReason::Resync,
            }
            .write(link_header(LinkMessageType::CloseConnection, req), buf);
            len.expect("encodes")
        };
        let len = close(&mut buf, ReqId(5));
        let early = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert_eq!(
            link.received(early, at(10)),
            Some(Frame::Refuse {
                code: LinkErrorCode::BeforeLinkUp
            })
        );
        let mut link = linked_at_boot();
        let len = close(&mut buf, ReqId(6));
        let later = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert_eq!(
            link.received(later, at(20)),
            Some(Frame::CloseReport {
                req_id: ReqId(6),
                outcome: CloseConnection::Closed
            })
        );
    }

    #[test]
    fn l_090_a_close_of_every_connection_reports_closed_with_none_to_close() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let len = CloseConnections {
            conn: 0,
            reason: CloseReason::Resync,
        }
        .write(
            link_header(LinkMessageType::CloseConnection, ReqId(5)),
            &mut buf,
        );
        let close = decoded(&buf, len);
        assert_eq!(
            link.received(close, at(20)),
            Some(Frame::CloseReport {
                req_id: ReqId(5),
                outcome: CloseConnection::Closed
            })
        );
        let len = CloseConnections {
            conn: 3,
            reason: CloseReason::Shedding,
        }
        .write(
            link_header(LinkMessageType::CloseConnection, ReqId(6)),
            &mut buf,
        );
        let close = decoded(&buf, len);
        assert_eq!(
            link.received(close, at(30)),
            Some(Frame::CloseReport {
                req_id: ReqId(6),
                outcome: CloseConnection::UnknownHandle
            })
        );
    }

    /// The one frame in `wire`, its envelope copied into `out`, and the
    /// envelope's length.
    fn read_back(wire: &[u8], out: &mut [u8; 256]) -> usize {
        let mut reader = FrameReader::new();
        let mut len = None;
        for byte in wire {
            if let Received::Frame(frame) = reader.push(*byte) {
                assert_eq!(len, None, "one frame on the wire");
                out.get_mut(..frame.len())
                    .expect("fits")
                    .copy_from_slice(frame);
                len = Some(frame.len());
            }
        }
        len.expect("a frame on the wire")
    }

    fn envelope_in(out: &[u8; 256], len: usize) -> LinkEnvelope<'_> {
        LinkEnvelope::decode(out.get(..len).expect("fits")).expect("an envelope")
    }

    #[test]
    fn l_030_the_statement_this_side_builds_carries_its_identity() {
        let link = Link::new(Tick::ZERO);
        let mut wire = [0u8; MAX_FRAME];
        let len = link
            .build(
                Frame::LinkUp { req_id: ReqId(12) },
                &ME,
                at(5),
                &mut FrameWriter::new(),
                &mut wire,
            )
            .expect("builds");
        let mut out = [0u8; 256];
        let len = read_back(wire.get(..len).expect("fits"), &mut out);
        let envelope = envelope_in(&out, len);
        assert_eq!(envelope.opcode(), LinkMessageType::LinkUp as u8);
        assert_eq!(envelope.req_id(), ReqId(12));
        let ours = LinkUp::decode(envelope).expect("a statement");
        assert_eq!(ours.role, Side::Comms);
        assert_eq!(ours.fw, ME.fw);
        assert_eq!(ours.hw, ME.hw);
        assert_eq!(ours.boot_id, ME.boot_id);
        assert_eq!(ours.version, OURS);
    }

    #[test]
    fn l_100_every_frame_this_side_builds_reads_back_with_its_request() {
        let link = Link::new(Tick::ZERO);
        let frames = [
            (
                Frame::LinkUpAck { req_id: ReqId(1) },
                LinkMessageType::LinkUpAck,
                ReqId(1),
            ),
            (
                Frame::Heartbeat { req_id: ReqId(2) },
                LinkMessageType::Heartbeat,
                ReqId(2),
            ),
            (
                Frame::HeartbeatAck { req_id: ReqId(3) },
                LinkMessageType::HeartbeatAck,
                ReqId(3),
            ),
            (
                Frame::DownloadRefused { req_id: ReqId(4) },
                LinkMessageType::EnterDownloadAck,
                ReqId(4),
            ),
            (
                Frame::CloseReport {
                    req_id: ReqId(5),
                    outcome: CloseConnection::Closed,
                },
                LinkMessageType::CloseConnectionAck,
                ReqId(5),
            ),
            (
                Frame::NetFailed { req_id: ReqId(6) },
                LinkMessageType::NetConfigAck,
                ReqId(6),
            ),
        ];
        for (frame, kind, req_id) in frames {
            let mut wire = [0u8; MAX_FRAME];
            let len = link
                .build(frame, &ME, at(3_500), &mut FrameWriter::new(), &mut wire)
                .expect("builds");
            let mut out = [0u8; 256];
            let len = read_back(wire.get(..len).expect("fits"), &mut out);
            let envelope = envelope_in(&out, len);
            assert_eq!(envelope.opcode(), kind as u8, "{frame:?}");
            assert_eq!(envelope.req_id(), req_id, "{frame:?}");
            assert_eq!(envelope.session(), SessionId::None, "{frame:?}");
        }
    }

    #[test]
    fn l_181_a_refusal_this_side_builds_carries_session_zero_and_request_zero() {
        let link = Link::new(Tick::ZERO);
        let mut wire = [0u8; MAX_FRAME];
        let len = link
            .build(
                Frame::Refuse {
                    code: LinkErrorCode::WrongSide,
                },
                &ME,
                at(1),
                &mut FrameWriter::new(),
                &mut wire,
            )
            .expect("builds");
        let mut out = [0u8; 256];
        let len = read_back(wire.get(..len).expect("fits"), &mut out);
        let envelope = envelope_in(&out, len);
        assert_eq!(envelope.opcode(), MessageType::ErrorResponse as u8);
        assert_eq!(envelope.session(), SessionId::None);
        assert_eq!(envelope.req_id(), ReqId(0));
    }

    #[test]
    fn l_100_a_heartbeat_carries_whole_seconds_since_this_side_started() {
        let link = Link::new(at(1_000));
        let mut wire = [0u8; MAX_FRAME];
        let len = link
            .build(
                Frame::Heartbeat { req_id: ReqId(2) },
                &ME,
                at(4_999),
                &mut FrameWriter::new(),
                &mut wire,
            )
            .expect("builds");
        let mut out = [0u8; 256];
        let len = read_back(wire.get(..len).expect("fits"), &mut out);
        let beat = Heartbeat::decode(envelope_in(&out, len)).expect("a heartbeat");
        assert_eq!(beat.uptime_s, 3);
    }
}
