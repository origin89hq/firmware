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
//! The controller's pairing-window report is acted on only here, which
//! reads the controller UART and nothing a client sent, and only once this
//! side is linked; before that it is discarded with no answer (L-194). The
//! greatest revision accepted and one local deadline, measured from its
//! receipt, are all that is kept of it; an older or repeated revision is
//! acknowledged and changes nothing, link loss ends the lifetime, and a
//! controller that rebooted clears the history. What the access point
//! does with the lifetime is #90's.
//!
//! The mechanics are `o89-link`'s, shared with the controller's link: the
//! requests in flight and their retries, the beats whose answers count, and
//! the rules every link-local frame meets.

use core::num::NonZeroU64;

use km43::{
    CloseConnection, CloseConnections, CloseReport, DownloadRequest, DownloadVerdict,
    EnterDownload, FrameWriter, Heartbeat, Intake, LinkEnvelope, LinkErrorCode, LinkMessageType,
    LinkUp, MAX_FRAME, NetChange, NetConfig, NetVerdict, PairingWindowAck, PairingWindowNotice,
    ReqId, Side, Version, arriving,
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
    /// The result of a credential update (L-136, L-137).
    NetReport {
        /// The controller's request.
        req_id: ReqId,
        /// Persistence or validation outcome.
        outcome: NetConfig,
        /// Version held in RAM, including after a failed write.
        version: u32,
    },
    /// The controller's pairing report processed: its revision echoed,
    /// whether it changed anything or not (L-193).
    PairingWindowAck {
        /// The controller's request.
        req_id: ReqId,
        /// The report's revision.
        revision: NonZeroU64,
    },
    /// A retry of the same NTP offer (L-015), never a fresh sample.
    TimeOffer {
        /// Unchanged correlation id.
        req_id: ReqId,
        /// Unchanged sample, retained only until acknowledgment or retry expiry.
        offer: km43::ClockOffer<'static>,
    },
    /// A link-local refusal, on session 0 with request 0 (L-181).
    Refuse {
        /// Why.
        code: LinkErrorCode,
    },
}

/// Result of the most recent NTP offer, for its producer to inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDelivery {
    /// No offer this boot.
    None,
    /// Waiting for an answer within the three-attempt budget.
    Pending,
    /// The controller's verdict, never used to set a local clock.
    Answered(km43::TimeOffer),
    /// Link loss or the final response deadline ended delivery.
    Failed,
}

/// What this side kept of the controller's pairing reports: the greatest
/// revision it accepted, and while the window it reported is open, when
/// that ends on this side's own clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reach {
    revision: NonZeroU64,
    until: Option<Tick>,
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
    network: crate::Network,
    offer_rate: crate::OfferRate,
    offer_requests: Requests<1>,
    offer_sample: Option<km43::ClockOffer<'static>>,
    offer_delivery: OfferDelivery,
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
    /// The controller's pairing window as its reports left it; `None`
    /// before any report from its current boot.
    pairing: Option<Reach>,
}

impl Link {
    /// The link at boot: unlinked, with a `LinkUp` due at once (L-120).
    #[must_use]
    pub const fn new(now: Tick) -> Self {
        Self {
            #[cfg(any(test, feature = "frames"))]
            controller_bench_mode: None,
            network: crate::Network::new(None),
            offer_rate: crate::OfferRate::new(),
            offer_requests: Requests::NONE,
            offer_sample: None,
            offer_delivery: OfferDelivery::None,
            boot: now,
            controller: None,
            linked: false,
            last_heard: None,
            next_statement: now,
            next_beat: now,
            next_req: 1,
            statement: Requests::NONE,
            beats: Beats::NONE,
            pairing: None,
        }
    }

    /// How long the controller's pairing window stays open as this side
    /// measures it: from the receipt of the report that opened it, until a
    /// newer closed report, the link falling, or the controller rebooting.
    /// `None` is closed or never reported, which grants the access point no
    /// pairing-based lifetime (L-193).
    #[must_use]
    pub fn pairing_window(&self, now: Tick) -> Option<Millis> {
        self.pairing
            .and_then(|reach| reach.until)
            .and_then(|until| until.since(now))
            .filter(|left| left.as_millis() > 0)
    }

    /// Restore durable credentials before the first handshake.
    pub fn restore_network(&mut self, credential: Option<crate::Credential>) {
        self.network = crate::Network::new(credential);
    }

    /// The active RAM credential, including a clear.
    #[must_use]
    pub const fn credential(&self) -> Option<&crate::Credential> {
        self.network.credential()
    }

    /// Frame a fresh NTP sample only on a compatible link and outside the rate
    /// window. Failed writes consume the interval. Only the same request can be
    /// retried within it, at most three transmissions (L-015).
    pub fn time_offer(
        &mut self,
        offer: km43::ClockOffer<'static>,
        now: Tick,
        writer: &mut FrameWriter,
        dst: &mut [u8; MAX_FRAME],
    ) -> Result<Option<usize>, EncodeError> {
        if !self.linked || !self.controller.is_some_and(|controller| controller.agreed) {
            return Ok(None);
        }
        let mut bytes = [0; LINK_ENVELOPE];
        let req_id = self.take_req();
        let len = offer
            .write(link_header(LinkMessageType::TimeOffer, req_id), &mut bytes)
            .map_err(|_| EncodeError::Body)?;
        if self.offer_requests.is_full() || !self.offer_rate.take(now) {
            return Ok(None);
        }
        let len = writer
            .write(bytes.get(..len).ok_or(EncodeError::Body)?, dst)
            .map_err(EncodeError::Frame)?;
        if !self
            .offer_requests
            .issue(LinkMessageType::TimeOffer, req_id, now)
        {
            return Ok(None);
        }
        self.offer_sample = Some(offer);
        self.offer_delivery = OfferDelivery::Pending;
        Ok(Some(len))
    }

    /// Delivery status; refusals are diagnostics, not authority over a clock.
    #[must_use]
    pub const fn offer_delivery(&self) -> OfferDelivery {
        self.offer_delivery
    }

    fn retry_offer(&mut self, now: Tick) -> Option<Frame> {
        match self.offer_requests.overdue(now) {
            Some(Overdue::Resend { req_id, .. }) => self
                .offer_sample
                .map(|offer| Frame::TimeOffer { req_id, offer }),
            Some(Overdue::GivenUp { .. }) => {
                self.offer_sample = None;
                self.offer_delivery = OfferDelivery::Failed;
                None
            }
            None => None,
        }
    }

    fn forget_offer(&mut self) {
        if self.offer_sample.take().is_some() {
            self.offer_delivery = OfferDelivery::Failed;
        }
        self.offer_requests = Requests::NONE;
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
                return self.retry_offer(now);
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
        self.received_with_store(envelope, now, |_| false)
    }

    /// Handle the link-local frame with a durable credential writer. The writer
    /// is never called before the handshake, for a wrong-side frame, or for
    /// client payloads. A write failure retains the new RAM credential.
    pub fn received_with_store(
        &mut self,
        envelope: LinkEnvelope<'_>,
        now: Tick,
        store: impl FnMut(&crate::Credential) -> bool,
    ) -> Option<Frame> {
        if is_peer_refusal(&envelope) {
            // The controller refused something of ours: never answered with
            // another error (L-181), and nothing waits on it.
            return None;
        }
        let kind = match arriving(envelope.opcode(), Side::Comms, envelope.session()) {
            Intake::Act(kind) => kind,
            Intake::Refuse(code) => return Some(Frame::Refuse { code }),
        };
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
        self.received_valid(kind, envelope, now, store)
    }

    fn received_valid(
        &mut self,
        kind: LinkMessageType,
        envelope: LinkEnvelope<'_>,
        now: Tick,
        store: impl FnMut(&crate::Credential) -> bool,
    ) -> Option<Frame> {
        let req_id = envelope.req_id();
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
            LinkMessageType::CloseConnection => Self::close_report(envelope, req_id),
            LinkMessageType::NetConfig => Some(self.configure_network(envelope, store)),
            LinkMessageType::CommsRelease => {
                // No installer before M7: refused with the one code that
                // says nothing was authorised to land here.
                Some(Frame::Refuse {
                    code: LinkErrorCode::NoAuthorisation,
                })
            }
            LinkMessageType::TimeOfferAck => {
                let verdict = km43::TimeVerdict::decode(envelope).ok()?;
                if self
                    .offer_requests
                    .answered(req_id, LinkMessageType::TimeOffer)
                {
                    self.offer_sample = None;
                    self.offer_delivery = OfferDelivery::Answered(verdict.outcome);
                    self.last_heard = Some(now);
                }
                None
            }
            LinkMessageType::PairingWindow => {
                if !self.linked {
                    // Before this side's own statement is answered: discarded
                    // with no answer and nothing learned (L-194).
                    return None;
                }
                let notice = PairingWindowNotice::decode(envelope).ok()?;
                self.pairing_report(notice, req_id, now)
            }
            LinkMessageType::ClientConnectedAck | LinkMessageType::ClientDisconnectedAck => {
                // Answers to requests not made yet.
                None
            }
            LinkMessageType::ClientConnected
            | LinkMessageType::ClientDisconnected
            | LinkMessageType::CloseConnectionAck
            | LinkMessageType::NetConfigAck
            | LinkMessageType::PairingWindowAck
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

    /// A valid report on a linked link. A newer revision replaces what was
    /// kept: open, a deadline from now; closed, none. An older or repeated
    /// one is acknowledged and changes nothing, so a retry never restarts
    /// the deadline and never reopens a closed window. A deadline past the
    /// end of the tick is refused: unanswered, and nothing kept.
    fn pairing_report(
        &mut self,
        notice: PairingWindowNotice,
        req_id: ReqId,
        now: Tick,
    ) -> Option<Frame> {
        let revision = notice.revision();
        if self.pairing.is_none_or(|kept| revision > kept.revision) {
            let until = match notice.remaining_ms() {
                0 => None,
                remaining => Some(now.after(Millis::from_millis(u64::from(remaining)))?),
            };
            self.pairing = Some(Reach { revision, until });
        }
        Some(Frame::PairingWindowAck { req_id, revision })
    }

    fn configure_network(
        &mut self,
        envelope: LinkEnvelope<'_>,
        store: impl FnMut(&crate::Credential) -> bool,
    ) -> Frame {
        let req_id = envelope.req_id();
        let verdict = match NetChange::decode(envelope) {
            Ok(change) => self.network.apply(change, store),
            Err(_) => NetVerdict {
                outcome: NetConfig::RejectedInvalid,
                version: self.network.stored_version(),
            },
        };
        Frame::NetReport {
            req_id,
            outcome: verdict.outcome,
            version: verdict.version,
        }
    }

    /// The answer to a `CloseConnection`. No connection rows before M4:
    /// nothing to close, which is a real report and not silence.
    fn close_report(envelope: LinkEnvelope<'_>, req_id: ReqId) -> Option<Frame> {
        let close = CloseConnections::decode(envelope).ok()?;
        let outcome = if close.is_every_connection() {
            CloseConnection::Closed
        } else {
            CloseConnection::UnknownHandle
        };
        Some(Frame::CloseReport { req_id, outcome })
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
                net_version: Some(self.network.stored_version()),
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
            Frame::NetReport {
                req_id,
                outcome,
                version,
            } => NetVerdict { outcome, version }.write(
                link_header(LinkMessageType::NetConfigAck, req_id),
                &mut envelope,
            ),
            Frame::PairingWindowAck { req_id, revision } => PairingWindowAck { revision }.write(
                link_header(LinkMessageType::PairingWindowAck, req_id),
                &mut envelope,
            ),
            Frame::TimeOffer { req_id, offer } => offer.write(
                link_header(LinkMessageType::TimeOffer, req_id),
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
            self.forget_offer();
            // Another boot's revisions start again from 1.
            self.pairing = None;
        }
        let agreed = OURS.agreed(version).is_ok();
        if !agreed {
            self.forget_offer();
        }
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
        self.forget_offer();
        // The lifetime ends with the link; the revision stays, and the
        // controller's resynchronisation brings a newer one.
        if let Some(reach) = &mut self.pairing {
            reach.until = None;
        }
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
                Frame::NetReport {
                    req_id: ReqId(6),
                    outcome: NetConfig::NvsWriteFailed,
                    version: 0,
                },
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
    fn net_change(buf: &mut [u8; 256], ssid: &str) -> usize {
        NetChange::Set {
            version: 7,
            ssid,
            psk: "password",
            country: "CA",
            hostname: "origin89",
        }
        .write(link_header(LinkMessageType::NetConfig, ReqId(55)), buf)
        .unwrap()
    }

    #[test]
    fn l_136_netconfig_is_guarded_and_reports_durable_success_on_the_wire() {
        let mut buf = [0; 256];
        let len = net_change(&mut buf, "site");
        let envelope = || LinkEnvelope::decode(&buf[..len]).unwrap();
        let mut early = Link::new(Tick::ZERO);
        assert_eq!(
            early.received_with_store(envelope(), at(1), |_| panic!("before link")),
            Some(Frame::Refuse {
                code: LinkErrorCode::BeforeLinkUp
            })
        );
        let mut link = linked_at_boot();
        let frame = link
            .received_with_store(envelope(), at(10), |_| true)
            .unwrap();
        assert_eq!(
            frame,
            Frame::NetReport {
                req_id: ReqId(55),
                outcome: NetConfig::Stored,
                version: 7
            }
        );
        // A duplicate after a lost acknowledgment must not erase flash again.
        assert_eq!(
            link.received_with_store(envelope(), at(11), |_| panic!("duplicate write")),
            Some(frame)
        );
        let mut wire = [0; MAX_FRAME];
        let len = link
            .build(frame, &ME, at(12), &mut FrameWriter::new(), &mut wire)
            .unwrap();
        let mut decoded = [0; 256];
        let len = read_back(&wire[..len], &mut decoded);
        let verdict = NetVerdict::decode(envelope_in(&decoded, len)).unwrap();
        assert_eq!(verdict.outcome, NetConfig::Stored);
        assert_eq!(verdict.version, 7);
    }

    #[test]
    fn l_137_netconfig_reports_failure_and_retries_persistence() {
        let mut link = linked_at_boot();
        let mut buf = [0; 256];
        let len = net_change(&mut buf, "site");
        let envelope = || LinkEnvelope::decode(&buf[..len]).unwrap();
        assert_eq!(
            link.received_with_store(envelope(), at(10), |_| false),
            Some(Frame::NetReport {
                req_id: ReqId(55),
                outcome: NetConfig::NvsWriteFailed,
                version: 0
            })
        );
        assert_eq!(link.credential().unwrap().version(), 7);
        assert_eq!(link.network.stored_version(), 0);
        assert_eq!(
            link.received_with_store(envelope(), at(11), |_| true),
            Some(Frame::NetReport {
                req_id: ReqId(55),
                outcome: NetConfig::Stored,
                version: 7
            })
        );
    }

    #[test]
    fn invalid_netconfig_is_answered_without_a_write() {
        let mut link = linked_at_boot();
        let mut buf = [0; 256];
        let len = net_change(&mut buf, "");
        assert_eq!(
            link.received_with_store(
                LinkEnvelope::decode(&buf[..len]).unwrap(),
                at(10),
                |_| panic!("invalid")
            ),
            Some(Frame::NetReport {
                req_id: ReqId(55),
                outcome: NetConfig::RejectedInvalid,
                version: 0
            })
        );
        // A valid envelope with a malformed NetConfig body also gets a verdict.
        let len = Heartbeat {
            uptime_s: 1,
            conns: 0,
        }
        .write(link_header(LinkMessageType::NetConfig, ReqId(56)), &mut buf)
        .unwrap();
        assert_eq!(
            link.received_with_store(
                LinkEnvelope::decode(&buf[..len]).unwrap(),
                at(11),
                |_| panic!("malformed")
            ),
            Some(Frame::NetReport {
                req_id: ReqId(56),
                outcome: NetConfig::RejectedInvalid,
                version: 0
            })
        );
        assert!(link.credential().is_none());
    }

    #[test]
    fn time_offer_requires_a_link_and_rate_limits_even_without_an_ack() {
        let offer = km43::ClockOffer {
            unix_ms: 1_700_000_000_000,
            source: 1,
            accuracy_ms: 20,
            server: "pool.ntp.org",
        };
        let mut wire = [0; MAX_FRAME];
        let mut writer = FrameWriter::new();
        let mut early = Link::new(Tick::ZERO);
        assert_eq!(
            early.time_offer(offer, at(10), &mut writer, &mut wire),
            Ok(None)
        );
        let mut link = linked_at_boot();
        let len = link
            .time_offer(offer, at(10), &mut writer, &mut wire)
            .unwrap()
            .unwrap();
        let mut body = [0; 256];
        let len = read_back(&wire[..len], &mut body);
        let envelope = envelope_in(&body, len);
        assert_eq!(envelope.opcode(), LinkMessageType::TimeOffer as u8);
        assert_eq!(km43::ClockOffer::decode(envelope).unwrap(), offer);
        assert!(matches!(
            link.retry_offer(at(510)),
            Some(Frame::TimeOffer { .. })
        ));
        assert!(matches!(
            link.retry_offer(at(1010)),
            Some(Frame::TimeOffer { .. })
        ));
        assert_eq!(link.retry_offer(at(1510)), None);
        assert_eq!(link.offer_delivery(), OfferDelivery::Failed);
        assert_eq!(
            link.time_offer(offer, at(900_009), &mut writer, &mut wire),
            Ok(None)
        );
        assert!(
            link.time_offer(offer, at(900_010), &mut writer, &mut wire)
                .unwrap()
                .is_some()
        );
    }
    fn pending_offer(link: &mut Link) -> (ReqId, km43::ClockOffer<'static>) {
        let offer = km43::ClockOffer {
            unix_ms: 1_700_000_000_000,
            source: 1,
            accuracy_ms: 20,
            server: "pool.ntp.org",
        };
        let mut wire = [0; MAX_FRAME];
        let len = link
            .time_offer(offer, at(10), &mut FrameWriter::new(), &mut wire)
            .unwrap()
            .unwrap();
        let mut body = [0; 256];
        let len = read_back(&wire[..len], &mut body);
        (envelope_in(&body, len).req_id(), offer)
    }

    #[test]
    fn l_015_time_retries_keep_the_same_sample_and_request_then_report_failure() {
        let mut link = linked_at_boot();
        let (req_id, offer) = pending_offer(&mut link);
        assert_eq!(link.tick(at(509)), None);
        let retry = Frame::TimeOffer { req_id, offer };
        assert_eq!(link.tick(at(510)), Some(retry));
        assert_eq!(link.tick(at(1_009)), None);
        assert_eq!(link.tick(at(1_010)), Some(retry));
        assert_eq!(link.tick(at(1_510)), None);
        assert_eq!(link.offer_delivery(), OfferDelivery::Failed);
        assert!(link.offer_sample.is_none());
    }

    #[test]
    fn time_ack_counts_once_and_stops_retries_for_every_controller_verdict() {
        for outcome in [
            km43::TimeOffer::Accepted,
            km43::TimeOffer::RefusedImplausible,
            km43::TimeOffer::RefusedStepTooLarge,
            km43::TimeOffer::RefusedRateLimited,
        ] {
            let mut link = linked_at_boot();
            let (req_id, _) = pending_offer(&mut link);
            let mut bytes = [0; 256];
            let len = km43::TimeVerdict { outcome }
                .write(
                    link_header(LinkMessageType::TimeOfferAck, req_id),
                    &mut bytes,
                )
                .unwrap();
            assert_eq!(
                link.received(LinkEnvelope::decode(&bytes[..len]).unwrap(), at(20)),
                None
            );
            assert_eq!(link.last_heard(), Some(at(20)));
            assert_eq!(link.offer_delivery(), OfferDelivery::Answered(outcome));
            link.received(LinkEnvelope::decode(&bytes[..len]).unwrap(), at(30));
            assert_eq!(link.last_heard(), Some(at(20)));
            assert_eq!(link.tick(at(510)), None);
            assert!(link.offer_sample.is_none());
        }
    }

    #[test]
    fn unknown_or_malformed_time_acks_and_old_link_acks_are_not_heard() {
        let mut link = linked_at_boot();
        let (req_id, _) = pending_offer(&mut link);
        let heard = link.last_heard();
        let mut bytes = [0; 256];
        let len = km43::TimeVerdict {
            outcome: km43::TimeOffer::Accepted,
        }
        .write(
            link_header(LinkMessageType::TimeOfferAck, ReqId(99)),
            &mut bytes,
        )
        .unwrap();
        link.received(LinkEnvelope::decode(&bytes[..len]).unwrap(), at(20));
        assert_eq!(link.last_heard(), heard);
        let len = NetVerdict {
            outcome: NetConfig::NvsWriteFailed,
            version: 7,
        }
        .write(
            link_header(LinkMessageType::TimeOfferAck, req_id),
            &mut bytes,
        )
        .unwrap();
        link.received(LinkEnvelope::decode(&bytes[..len]).unwrap(), at(30));
        assert_eq!(link.last_heard(), heard);
        link.unlink(at(40));
        assert_eq!(link.offer_delivery(), OfferDelivery::Failed);
        let len = km43::TimeVerdict {
            outcome: km43::TimeOffer::Accepted,
        }
        .write(
            link_header(LinkMessageType::TimeOfferAck, req_id),
            &mut bytes,
        )
        .unwrap();
        link.received(LinkEnvelope::decode(&bytes[..len]).unwrap(), at(50));
        assert_eq!(link.last_heard(), heard);
        assert!(!link.offer_rate.take(at(900_009)));
    }
    /// A pairing report from the controller, on `session`.
    fn report(
        buf: &mut [u8; 256],
        req_id: ReqId,
        revision: u64,
        remaining_ms: u32,
        session: u16,
    ) -> LinkEnvelope<'_> {
        let notice =
            PairingWindowNotice::new(NonZeroU64::new(revision).expect("non-zero"), remaining_ms)
                .expect("bounded");
        let len = notice.write(
            km43::LinkHeader {
                kind: LinkMessageType::PairingWindow,
                session: SessionId::from(session),
                req_id,
            },
            buf,
        );
        decoded(buf, len)
    }

    fn ack(req_id: u32, revision: u64) -> Frame {
        Frame::PairingWindowAck {
            req_id: ReqId(req_id),
            revision: NonZeroU64::new(revision).expect("non-zero"),
        }
    }

    #[test]
    fn l_194_a_report_before_this_side_is_linked_is_discarded_without_an_answer() {
        let mut link = Link::new(Tick::ZERO);
        let mut buf = [0u8; 256];
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 1, 120_000, 0), at(10)),
            None
        );
        assert_eq!(link.pairing_window(at(10)), None, "nothing learned");
        // The controller's own statement is not this side's link either.
        let theirs = from_controller(&mut buf, LinkMessageType::LinkUp, ReqId(2));
        let _ = link.received(theirs, at(20));
        assert_eq!(
            link.received(report(&mut buf, ReqId(3), 1, 120_000, 0), at(30)),
            None
        );
        assert_eq!(link.pairing_window(at(30)), None);
        // Linked, the same report is acted on.
        let mut link = linked_at_boot();
        assert_eq!(
            link.received(report(&mut buf, ReqId(4), 1, 120_000, 0), at(40)),
            Some(ack(4, 1))
        );
        assert_eq!(
            link.pairing_window(at(40)),
            Some(Millis::from_millis(120_000))
        );
    }

    #[test]
    fn l_194_a_report_on_a_client_session_is_refused_and_changes_nothing() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        for session in [1, 3, u16::MAX] {
            assert_eq!(
                link.received(report(&mut buf, ReqId(5), 9, 120_000, session), at(10)),
                Some(Frame::Refuse {
                    code: LinkErrorCode::NonZeroSession
                }),
                "session {session}"
            );
            assert_eq!(link.pairing_window(at(10)), None);
        }
        // Nor did it take the revision: revision 1 is still newer.
        assert_eq!(
            link.received(report(&mut buf, ReqId(6), 1, 60_000, 0), at(20)),
            Some(ack(6, 1))
        );
        assert_eq!(
            link.pairing_window(at(20)),
            Some(Millis::from_millis(60_000))
        );
    }

    #[test]
    fn l_194_under_a_major_mismatch_a_report_is_refused_with_261() {
        let mut link = linked_at_boot();
        link.record(CONTROLLER_BOOT, Version { major: 2, minor: 0 });
        let mut buf = [0u8; 256];
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 1, 120_000, 0), at(10)),
            Some(Frame::Refuse {
                code: LinkErrorCode::LinkMajorMismatch
            })
        );
        assert_eq!(link.pairing_window(at(10)), None);
    }

    #[test]
    fn l_193_a_report_is_acknowledged_with_its_revision_and_opens_the_window_from_receipt() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let answer = link.received(report(&mut buf, ReqId(8), 2, 90_000, 0), at(1_000));
        assert_eq!(answer, Some(ack(8, 2)));
        assert_eq!(
            link.pairing_window(at(1_000)),
            Some(Millis::from_millis(90_000))
        );
        assert_eq!(
            link.pairing_window(at(90_999)),
            Some(Millis::from_millis(1))
        );
        assert_eq!(link.pairing_window(at(91_000)), None, "expired locally");
        // The acknowledgement reads back as the controller reads it.
        let mut wire = [0u8; MAX_FRAME];
        let len = link
            .build(
                answer.expect("an answer"),
                &ME,
                at(1_000),
                &mut FrameWriter::new(),
                &mut wire,
            )
            .expect("builds");
        let mut out = [0u8; 256];
        let len = read_back(wire.get(..len).expect("fits"), &mut out);
        let envelope = envelope_in(&out, len);
        assert_eq!(envelope.opcode(), LinkMessageType::PairingWindowAck as u8);
        assert_eq!(envelope.req_id(), ReqId(8));
        assert_eq!(envelope.session(), SessionId::None);
        assert_eq!(
            PairingWindowAck::decode(envelope)
                .expect("an ack")
                .revision
                .get(),
            2
        );
    }

    #[test]
    fn l_193_a_malformed_report_is_unanswered_and_learns_nothing() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        // A duration longer than the physical window, written by hand.
        let mut body = link_header(LinkMessageType::PairingWindow, ReqId(3))
            .write(2, &mut buf)
            .expect("fits");
        body.key(1).expect("fits");
        body.u64(1).expect("fits");
        body.key(2).expect("fits");
        body.u64(120_001).expect("fits");
        let len = body.finish().map_err(LinkError::from);
        assert_eq!(link.received(decoded(&buf, len), at(10)), None);
        assert_eq!(link.pairing_window(at(10)), None);
    }

    #[test]
    fn a_retried_or_older_report_is_acknowledged_and_never_restarts_or_reopens_the_window() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 5, 120_000, 0), at(0)),
            Some(ack(1, 5))
        );
        // The retry, a second later: acknowledged, deadline unchanged.
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 5, 120_000, 0), at(1_000)),
            Some(ack(1, 5))
        );
        assert_eq!(
            link.pairing_window(at(1_000)),
            Some(Millis::from_millis(119_000))
        );
        // Closed by a newer revision; an older open one reopens nothing.
        assert_eq!(
            link.received(report(&mut buf, ReqId(2), 6, 0, 0), at(2_000)),
            Some(ack(2, 6))
        );
        assert_eq!(link.pairing_window(at(2_000)), None);
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 5, 120_000, 0), at(2_500)),
            Some(ack(1, 5))
        );
        assert_eq!(link.pairing_window(at(2_500)), None);
    }

    #[test]
    fn link_loss_ends_the_window_and_only_a_rebooted_controller_starts_its_revisions_again() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let _ = link.received(report(&mut buf, ReqId(1), 5, 120_000, 0), at(0));
        // Six seconds unanswered: the link and the window go, and this side
        // states itself in the same tick.
        let Some(Frame::LinkUp { req_id }) = link.tick(at(6_000)) else {
            panic!("a statement at once");
        };
        assert!(!link.is_linked());
        assert_eq!(link.pairing_window(at(6_000)), None);
        // The same boot links again: its old revision still reopens nothing.
        let answer = from_controller(&mut buf, LinkMessageType::LinkUpAck, req_id);
        let _ = link.received(answer, at(6_100));
        assert!(link.is_linked());
        let _ = link.received(report(&mut buf, ReqId(1), 5, 120_000, 0), at(6_200));
        assert_eq!(link.pairing_window(at(6_200)), None);
        // A controller that rebooted starts again from 1.
        link.record(CONTROLLER_BOOT.wrapping_add(1), OURS);
        link.linked(CONTROLLER_BOOT.wrapping_add(1), OURS, at(7_000));
        let _ = link.received(report(&mut buf, ReqId(1), 1, 30_000, 0), at(7_000));
        assert_eq!(
            link.pairing_window(at(7_000)),
            Some(Millis::from_millis(30_000))
        );
    }

    #[test]
    fn a_deadline_past_the_end_of_the_tick_is_refused_unanswered() {
        let mut link = linked_at_boot();
        let mut buf = [0u8; 256];
        let late = at(u64::MAX - 10);
        assert_eq!(
            link.received(report(&mut buf, ReqId(1), 1, 120_000, 0), late),
            None
        );
        assert_eq!(link.pairing_window(late), None);
        // A closed report needs no deadline and is taken there.
        assert_eq!(
            link.received(report(&mut buf, ReqId(2), 2, 0, 0), late),
            Some(ack(2, 2))
        );
    }

    #[test]
    fn changed_major_or_controller_boot_discards_pending_time_offer() {
        for (boot_id, version) in [
            (
                CONTROLLER_BOOT,
                Version {
                    major: 99,
                    minor: 0,
                },
            ),
            (CONTROLLER_BOOT.wrapping_add(1), OURS),
        ] {
            let mut link = linked_at_boot();
            pending_offer(&mut link);
            link.record(boot_id, version);
            assert_eq!(link.offer_delivery(), OfferDelivery::Failed);
            assert_eq!(link.retry_offer(at(510)), None);
            assert!(!link.offer_rate.take(at(900_009)));
        }
    }
}
