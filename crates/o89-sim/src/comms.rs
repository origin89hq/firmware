//! The hostile comms processor: the other end of the link, on a laptop,
//! with a named set of things it can do to the controller.
//!
//! What it does honestly is the comms processor's own link,
//! `o89_comms_core::Link`, the state machine the module runs: its statement
//! and the retries of it, its heartbeats once linked, its answers, each of
//! the controller's answers matched to a request of its own. So the
//! controller's tests run against the peer the firmware is, and a rule
//! written for that side is written once. What it may do on top is named,
//! and every test declares what it uses: answer nothing, hear nothing while
//! still talking, withhold its statement or its heartbeats, beat without a
//! link, deliver late, speak the ROM's text before its own `LinkUp`, cut a
//! frame in half before every frame, speak another version, claim to be a
//! controller, reboot with a new `boot_id`, lose a release on the wire, and
//! put on the wire the frames a real peer would not.
//!
//! It connects clients honestly through its link's own connection table
//! (#90): a row per transport, announced, counted in every heartbeat
//! (L-101), closed and counted when the controller asks (L-090), dropped
//! when the controller refuses it. On top of that it can invent
//! connections outside the table, with handles of its choosing: it keeps
//! the handles it announced that way and has not released, counts them in
//! its heartbeats with the table's, and closes them when asked, reporting
//! how many with the table's. One it invented that the controller refused
//! for a full table is not kept. It builds those with `km43`'s own
//! writers, so what the controller reads is what a real peer would have
//! sent, and a frame it cannot build is an error a test reads, never a
//! panic in this crate.

use std::collections::VecDeque;

use km43::{
    ClientConnected, ClientDown, ClientUp, ClockOffer, CloseConnection, CloseConnections,
    CloseReason, CloseReport, Conn, DisconnectReason, Envelope, ErrorBody, FrameReader,
    FrameWriter, Header, Heartbeat, Incoming, LinkEnvelope, LinkHeader, LinkMessageType,
    LinkTransport, LinkUp, MAX_FRAME, MessageType, PairingWindowNotice, Received, ReqId, SessionId,
    Side, Version,
};
use o89_comms_core::{Frame, Identity, Link as CommsLink, Peer, Refused, Status};
use o89_core::{HEARTBEAT_PERIOD, Millis, OURS, Tick};

/// Whether the peer answers at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answers {
    /// Everything its link says.
    Everything,
    /// Nothing: it reads and stays silent.
    Nothing,
    /// Whatever its link says of its own accord, and nothing of the
    /// controller's heard: a comms processor whose receiver has hung,
    /// stating itself forever because no answer reaches it.
    TalksOnly,
}

/// Whether the peer states itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statement {
    /// `LinkUp` at boot and an acknowledgement to the controller's.
    Given,
    /// Neither, ever.
    Withheld,
}

/// Whether the peer beats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beats {
    /// As its link does: its own every two seconds once linked, the
    /// controller's answered.
    Given,
    /// As its link does, and every two seconds while unlinked too: a peer
    /// that beats without having been answered.
    Regardless,
    /// None sent, none answered.
    Withheld,
}

/// What the peer's frames look like on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frames {
    /// As `km43` frames them.
    Whole,
    /// Before every frame, the head of one that never finished: the pair
    /// pulled mid-frame.
    CutBeforeEach,
}

/// What the peer claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claims {
    /// The comms processor.
    Comms,
    /// A controller, which is the wrong side.
    Controller,
}

/// Whether the peer's releases reach the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Releases {
    /// A transport that goes is released over the link.
    Sent,
    /// The transport goes and its `ClientDisconnected` is lost on the wire:
    /// the peer stops counting it, and the controller is never told. A
    /// release from its link's table is lost at every attempt.
    Lost,
}

/// What the peer may do. The default is a peer that behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Network version claimed at `LinkUp`; supports a module moved between units.
    pub net_version: u32,
    /// Drop only network acknowledgements, leaving the handshake and beats intact.
    pub withhold_network_ack: bool,
    /// Whether it answers at all.
    pub answers: Answers,
    /// Whether it states itself.
    pub statement: Statement,
    /// Whether it beats.
    pub beats: Beats,
    /// Every frame it sends arrives this much later.
    pub delay: Option<Millis>,
    /// Bytes that are not frames before its `LinkUp` at boot: what the
    /// ROM's text at its own baud looks like to a receiver at ours.
    pub rom_text: usize,
    /// Whether its frames arrive whole.
    pub frames: Frames,
    /// The version it speaks.
    pub version: Version,
    /// What it claims to be.
    pub claims: Claims,
    /// Whether its releases arrive.
    pub releases: Releases,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            net_version: 0,
            withhold_network_ack: false,
            answers: Answers::Everything,
            statement: Statement::Given,
            beats: Beats::Given,
            delay: None,
            rom_text: 0,
            frames: Frames::Whole,
            version: Version::V1_0,
            claims: Claims::Comms,
            releases: Releases::Sent,
        }
    }
}

/// A frame the peer could not build, which is a bug in the test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// The body would not encode.
    Body,
    /// The envelope would not frame.
    Frame,
}

/// What the peer decoded from the controller, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard {
    /// A decoded network update; its passphrase is redacted by the owned type.
    NetConfig {
        /// Version offered by the controller.
        version: u32,
        /// Redacted decoded body (its synthetic version is one).
        network: o89_core::Network,
    },
    /// The controller stated itself.
    LinkUp {
        /// Its request id.
        req_id: ReqId,
        /// Its `boot_id`.
        boot_id: u32,
        /// Its firmware text.
        fw: String,
        /// The version it speaks.
        version: Version,
    },
    /// The controller answered our statement.
    LinkUpAck {
        /// Our request id, echoed.
        req_id: ReqId,
        /// Its `boot_id`.
        boot_id: u32,
    },
    /// A beat.
    Heartbeat {
        /// Its request id.
        req_id: ReqId,
        /// Its uptime.
        uptime_s: u32,
        /// Its connection count.
        conns: u8,
    },
    /// Our beat answered.
    HeartbeatAck {
        /// Our request id, echoed.
        req_id: ReqId,
    },
    /// A frame for a client, which the comms processor would put on the
    /// connection its `session_id` names: every client-space frame but a
    /// refusal of a link frame of its own.
    ToClient {
        /// The handle it is addressed to.
        session: u16,
        /// The envelope, as it arrived.
        frame: Vec<u8>,
    },
    /// The controller asked for a connection to be closed.
    Close {
        /// Its request id.
        req_id: ReqId,
        /// The handle, 0 for every one.
        conn: u16,
        /// Why.
        reason: CloseReason,
    },
    /// The controller reported its pairing window.
    PairingWindow {
        /// Its request id.
        req_id: ReqId,
        /// The report's revision.
        revision: u64,
        /// What was left of the window when it was first sent; 0 closed.
        remaining_ms: u32,
    },
    /// A refusal, with the code as the wire carries it.
    Refusal {
        /// The code.
        code: u16,
        /// The session the refusal carried.
        session: u16,
        /// The request id it carried.
        req_id: ReqId,
    },
    /// Anything else, by opcode and request id.
    Other {
        /// The opcode.
        opcode: u8,
        /// The request id.
        req_id: ReqId,
        /// The value of the body's key 1, which is every ack's outcome.
        outcome: Option<u8>,
    },
}

/// The firmware text and board it states, as the comms firmware would.
const IDENTITY_FW: &str = "0.1.0-sim+g89abcdef";
/// The board it states.
const IDENTITY_HW: &str = "controller-a rev A";

/// Request ids for the frames it puts on the wire outside its own link:
/// far from the link's own, which count up from one.
const INJECTED_FROM: u32 = 0x4000_0000;

/// The peer.
pub struct HostileComms {
    caps: Capabilities,
    boot_id: u32,
    boots: u32,
    booted_at: Tick,
    /// The comms processor's link, from its boot until its power goes.
    link: Option<CommsLink>,
    reader: FrameReader,
    writer: FrameWriter,
    next_injected: u32,
    /// When it next beats without a link, for [`Beats::Regardless`].
    next_unlinked_beat: Tick,
    outbox: VecDeque<(Tick, Vec<u8>)>,
    /// Everything decoded from the controller.
    pub heard: Vec<Heard>,
    /// Every frame kind it put on the wire, in order.
    pub sent: Vec<LinkMessageType>,
    /// The handles it announced and has not released or closed.
    live: Vec<u16>,
    /// Announcements not yet answered, by request id.
    announcing: Vec<(ReqId, u16)>,
    /// What the close it is answering did, for its report.
    close_report: Option<(CloseConnection, u8)>,
}

impl HostileComms {
    /// A peer that has not booted.
    #[must_use]
    pub fn new(caps: Capabilities) -> Self {
        Self {
            caps,
            boot_id: 0,
            boots: 0,
            booted_at: Tick::ZERO,
            link: None,
            reader: FrameReader::new(),
            writer: FrameWriter::new(),
            next_injected: INJECTED_FROM,
            next_unlinked_beat: Tick::ZERO,
            outbox: VecDeque::new(),
            heard: Vec::new(),
            sent: Vec::new(),
            live: Vec::new(),
            announcing: Vec::new(),
            close_report: None,
        }
    }

    /// Its current `boot_id`.
    #[must_use]
    pub const fn boot_id(&self) -> u32 {
        self.boot_id
    }

    /// Whether its own link is up: its statement answered by the
    /// controller's current boot (L-033).
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.link.as_ref().is_some_and(CommsLink::is_linked)
    }

    /// What it may do, to change mid-test.
    pub fn capabilities(&mut self) -> &mut Capabilities {
        &mut self.caps
    }

    /// The rail was cut: the module loses power, hears nothing, and drops
    /// whatever it had not yet put on the wire.
    pub fn power_off(&mut self) {
        self.link = None;
        self.forget_connections();
        self.outbox.clear();
        self.reader = FrameReader::new();
    }

    /// The peer boots: a new `boot_id`, the ROM's text, then whatever its
    /// link says first, which is its `LinkUp`. Answers the bytes the
    /// controller sees.
    pub fn boot(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
        self.boots = self.boots.wrapping_add(1);
        // Distinct per boot and never zero, as a random draw would be.
        self.boot_id = 0x5EED_0000u32.wrapping_add(self.boots.wrapping_mul(0x9E37));
        self.booted_at = now;
        self.link = Some(CommsLink::new(now));
        self.forget_connections();
        self.next_unlinked_beat = now.after(HEARTBEAT_PERIOD).unwrap_or(now);
        self.reader = FrameReader::new();
        self.outbox.clear();
        let mut bytes = Vec::new();
        for i in 0..self.caps.rom_text {
            // The ROM's text as a wrong-baud receiver sees it: bytes of
            // every value, a zero among them now and then, so the run is
            // refused as a frame rather than swallowed as an idle line.
            let byte = u8::try_from(i.wrapping_mul(37) % 251).unwrap_or(1);
            bytes.push(if i % 17 == 16 { 0 } else { byte.max(1) });
        }
        if self.caps.rom_text > 0 {
            bytes.push(0);
        }
        bytes.extend(self.tick(now)?);
        Ok(bytes)
    }

    /// Time passed on its own clock: what its link says of its own accord,
    /// a statement or its retry, or a heartbeat once linked, and, with
    /// [`Beats::Regardless`], a heartbeat every two seconds while unlinked.
    pub fn tick(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
        let mut bytes = Vec::new();
        let Some(link) = self.link.as_mut() else {
            return Ok(bytes);
        };
        let linked = link.is_linked();
        if let Some(frame) = link.tick(now) {
            bytes.extend(self.emit(frame, now)?);
        }
        if !linked
            && self.caps.beats == Beats::Regardless
            && now.since(self.next_unlinked_beat).is_some()
        {
            self.next_unlinked_beat = now.after(HEARTBEAT_PERIOD).unwrap_or(now);
            bytes.extend(self.heartbeat(now)?);
        }
        Ok(bytes)
    }

    /// Bytes from the controller. Answers what goes back now; frames held
    /// by a delay come out of [`drain`](Self::drain) when their time comes.
    pub fn take(&mut self, bytes: &[u8], now: Tick) -> Result<Vec<u8>, Broken> {
        let mut out = Vec::new();
        if self.link.is_none() {
            return Ok(out);
        }
        for byte in bytes {
            let received = self.reader.push(*byte);
            let frame = match received {
                Received::Frame(frame) => frame.to_vec(),
                Received::Nothing | Received::Dropped(_) | Received::Abandoned => continue,
            };
            self.overhear(&frame);
            // A receiver that has hung hears nothing, and its link with it.
            if self.caps.answers == Answers::TalksOnly {
                continue;
            }
            self.connections(&frame);
            let answer = match (self.link.as_mut(), LinkEnvelope::decode(&frame)) {
                (Some(link), Ok(envelope)) => link.received(envelope, now),
                (None, _) | (_, Err(_)) => None,
            };
            if let Some(answer) = answer {
                out.extend(self.emit(answer, now)?);
            }
        }
        out.extend(self.drain(now));
        Ok(out)
    }

    /// Frames whose delay has passed.
    pub fn drain(&mut self, now: Tick) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some((due, _)) = self.outbox.front() {
            if now.since(*due).is_none() {
                break;
            }
            if let Some((_, frame)) = self.outbox.pop_front() {
                out.extend(frame);
            }
        }
        out
    }

    /// A heartbeat outside its link's own cadence, under a request id its
    /// link does not track: its answer counts for nothing on this side.
    /// Nothing from a peer that answers nothing or withholds its beats.
    pub fn heartbeat(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
        if self.caps.answers == Answers::Nothing || self.caps.beats == Beats::Withheld {
            return Ok(Vec::new());
        }
        let req_id = self.take_injected();
        let frame = self.build(Frame::Heartbeat { req_id }, now)?;
        Ok(self.wire(&frame, Some(LinkMessageType::Heartbeat), now))
    }

    /// Its statement again, with the `boot_id` it already has (L-030), under
    /// a request id its link does not track.
    pub fn restate(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let frame = self.build(Frame::LinkUp { req_id }, now)?;
        Ok(self.wire(&frame, Some(LinkMessageType::LinkUp), now))
    }

    /// An error of its own about something of ours: session 0, request 0,
    /// as L-181 has it.
    pub fn refuse(&mut self, code: u16, now: Tick) -> Result<Vec<u8>, Broken> {
        self.refuse_as(code, SessionId::None, ReqId(0), now)
    }

    /// An error frame carrying a session and a request id: a client's error,
    /// which is not a refusal of anything of the controller's.
    pub fn refuse_as(
        &mut self,
        code: u16,
        session: SessionId,
        req_id: ReqId,
        now: Tick,
    ) -> Result<Vec<u8>, Broken> {
        let mut dst = [0u8; MAX_FRAME];
        let len = ErrorBody {
            code: Incoming::Unknown(code),
            detail: "",
        }
        .write(
            Header {
                kind: MessageType::ErrorResponse,
                session,
                req_id,
            },
            &mut dst,
        )
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, None)?;
        Ok(self.queue(frame, now))
    }

    /// A heartbeat answer with a request id the controller never sent: an
    /// answer to nothing.
    pub fn unsolicited_heartbeat_ack(
        &mut self,
        req_id: ReqId,
        now: Tick,
    ) -> Result<Vec<u8>, Broken> {
        let frame = self.build(Frame::HeartbeatAck { req_id }, now)?;
        Ok(self.wire(&frame, Some(LinkMessageType::HeartbeatAck), now))
    }

    /// A client connects honestly: its link's table gives it a row and a
    /// handle, and announces it at its next turn (L-060).
    pub fn connect(&mut self) -> Result<Conn, Refused> {
        let peer = Peer::Ipv4 {
            addr: [192, 168, 4, 2],
            port: 50_000,
        };
        self.link
            .as_mut()
            .ok_or(Refused::NotLinked)?
            .connect(LinkTransport::WifiLocal, peer)
    }

    /// What the table asks of the transport holding `conn`.
    #[must_use]
    pub fn status(&self, conn: Conn) -> Option<Status> {
        self.link.as_ref().and_then(|link| link.status(conn))
    }

    /// The transport holding `conn` went.
    pub fn transport_gone(&mut self, conn: Conn, reason: DisconnectReason) {
        if let Some(link) = self.link.as_mut() {
            link.gone(conn, reason);
        }
    }

    /// Rows its table holds a transport for (L-101).
    #[must_use]
    pub fn table_conns(&self) -> u8 {
        self.link
            .as_ref()
            .map_or(0, |link| link.connections().allocated())
    }

    /// A connection announced with this handle, over local Wi-Fi.
    pub fn announce_connection(&mut self, conn: u16, now: Tick) -> Result<Vec<u8>, Broken> {
        self.announce_as(conn, LinkTransport::WifiLocal, "192.168.4.2", now)
    }

    /// A connection announced with this handle, claiming this transport and
    /// this peer: assertions the controller must not decide on (L-072).
    pub fn announce_as(
        &mut self,
        conn: u16,
        transport: LinkTransport,
        peer: &str,
        now: Tick,
    ) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let len = ClientUp {
            conn,
            transport,
            peer,
        }
        .write(header(LinkMessageType::ClientConnected, req_id), &mut dst)
        .map_err(|_| Broken::Body)?;
        if !self.live.contains(&conn) {
            self.live.push(conn);
        }
        self.announcing.push((req_id, conn));
        let frame = self.frame(&dst, len, Some(LinkMessageType::ClientConnected))?;
        Ok(self.queue(frame, now))
    }

    /// A connection released, with this handle; with [`Releases::Lost`],
    /// released here and lost on the wire.
    pub fn release_connection(&mut self, conn: u16, now: Tick) -> Result<Vec<u8>, Broken> {
        self.live.retain(|live| *live != conn);
        if self.caps.releases == Releases::Lost {
            return Ok(Vec::new());
        }
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let len = ClientDown {
            conn,
            reason: DisconnectReason::ClosedByClient,
        }
        .write(
            header(LinkMessageType::ClientDisconnected, req_id),
            &mut dst,
        )
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(LinkMessageType::ClientDisconnected))?;
        Ok(self.queue(frame, now))
    }

    /// A client's envelope, relayed as it stands: whatever `session_id` it
    /// carries is what the controller reads, which is the stamp an honest
    /// comms processor puts there (P-021) or any other one it chooses.
    /// Nothing from a peer that answers nothing.
    pub fn relay(&mut self, envelope: &[u8], now: Tick) -> Result<Vec<u8>, Broken> {
        if self.caps.answers == Answers::Nothing {
            return Ok(Vec::new());
        }
        let frame = self.frame(envelope, envelope.len(), None)?;
        Ok(self.queue(frame, now))
    }

    /// Every frame the controller addressed to the client on `session`.
    #[must_use]
    pub fn to_client(&self, session: u16) -> Vec<Vec<u8>> {
        self.heard
            .iter()
            .filter_map(|heard| match heard {
                Heard::ToClient { session: to, frame } if *to == session => Some(frame.clone()),
                Heard::ToClient { .. }
                | Heard::NetConfig { .. }
                | Heard::Close { .. }
                | Heard::LinkUp { .. }
                | Heard::LinkUpAck { .. }
                | Heard::Heartbeat { .. }
                | Heard::HeartbeatAck { .. }
                | Heard::Refusal { .. }
                | Heard::PairingWindow { .. }
                | Heard::Other { .. } => None,
            })
            .collect()
    }

    /// How long the pairing window its link learned from the controller
    /// stays open, measured on its own clock; `None` closed, never
    /// reported, or with no link since its power went.
    #[must_use]
    pub fn pairing_window(&self, now: Tick) -> Option<Millis> {
        self.link.as_ref().and_then(|link| link.pairing_window(now))
    }

    /// Every pairing report heard, in order: request, revision, remaining.
    #[must_use]
    pub fn pairing_reports(&self) -> Vec<(ReqId, u64, u32)> {
        self.heard
            .iter()
            .filter_map(|heard| match heard {
                Heard::PairingWindow {
                    req_id,
                    revision,
                    remaining_ms,
                } => Some((*req_id, *revision, *remaining_ms)),
                Heard::ToClient { .. }
                | Heard::NetConfig { .. }
                | Heard::Close { .. }
                | Heard::LinkUp { .. }
                | Heard::LinkUpAck { .. }
                | Heard::Heartbeat { .. }
                | Heard::HeartbeatAck { .. }
                | Heard::Refusal { .. }
                | Heard::Other { .. } => None,
            })
            .collect()
    }

    /// A time offer.
    pub fn offer_time(&mut self, unix_ms: u64, now: Tick) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let len = ClockOffer {
            unix_ms,
            source: 1,
            accuracy_ms: 50,
            server: "pool.ntp.org",
        }
        .write(header(LinkMessageType::TimeOffer, req_id), &mut dst)
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(LinkMessageType::TimeOffer))?;
        Ok(self.queue(frame, now))
    }

    /// Inject a diagnostic body over the hostile peer's framing and delay path.
    pub fn wifi_body(
        &mut self,
        kind: LinkMessageType,
        req_id: ReqId,
        body: &[u8],
        now: Tick,
    ) -> Result<Vec<u8>, Broken> {
        let mut dst = [0; km43::MAX_PAYLOAD];
        let len = if kind == LinkMessageType::WifiScanAck {
            km43::ScanOrderVerdict::decode(
                km43::LinkEnvelope::decode(body).map_err(|_| Broken::Body)?,
            )
            .map_err(|_| Broken::Body)?
            .write(header(kind, req_id), &mut dst)
        } else if kind == LinkMessageType::WifiScanResult {
            km43::ScanResult::decode(km43::LinkEnvelope::decode(body).map_err(|_| Broken::Body)?)
                .map_err(|_| Broken::Body)?
                .write(header(kind, req_id), &mut dst)
        } else if kind == LinkMessageType::WifiState {
            km43::RadioReport::decode(km43::LinkEnvelope::decode(body).map_err(|_| Broken::Body)?)
                .map_err(|_| Broken::Body)?
                .write(header(kind, req_id), &mut dst)
        } else {
            return Err(Broken::Body);
        }
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(kind))?;
        Ok(self.queue(frame, now))
    }

    /// A request of `kind` whose body is an empty map: a frame that is not
    /// the message it claims, where P-015 requires keys.
    pub fn request_with_no_body(
        &mut self,
        kind: LinkMessageType,
        now: Tick,
    ) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let cbor = header(kind, req_id)
            .write(0, &mut dst)
            .map_err(|_| Broken::Body)?;
        let len = cbor.finish().map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(kind))?;
        Ok(self.queue(frame, now))
    }

    /// A `CommsRelease` request, which only a controller may send: a frame
    /// from the wrong side.
    pub fn send_from_the_wrong_side(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let cbor = header(LinkMessageType::CommsRelease, req_id)
            .write(0, &mut dst)
            .map_err(|_| Broken::Body)?;
        let len = cbor.finish().map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(LinkMessageType::CommsRelease))?;
        Ok(self.queue(frame, now))
    }

    /// A heartbeat stamped with a session it should not carry (L-012).
    pub fn beat_on_a_session(&mut self, session: u16, now: Tick) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let len = Heartbeat {
            uptime_s: 1,
            conns: 0,
        }
        .write(
            LinkHeader {
                kind: LinkMessageType::Heartbeat,
                session: SessionId::from(session),
                req_id,
            },
            &mut dst,
        )
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(LinkMessageType::Heartbeat))?;
        Ok(self.queue(frame, now))
    }

    /// A frame its link asks for, put on the wire as the capabilities
    /// allow: nothing at all from a peer that answers nothing, no statement
    /// from one that withholds it, no beat from one that withholds those.
    fn emit(&mut self, frame: Frame, now: Tick) -> Result<Vec<u8>, Broken> {
        let (kind, statement, beat) = match frame {
            Frame::LinkUp { .. } => (Some(LinkMessageType::LinkUp), true, false),
            Frame::LinkUpAck { .. } => (Some(LinkMessageType::LinkUpAck), true, false),
            Frame::Heartbeat { .. } => (Some(LinkMessageType::Heartbeat), false, true),
            Frame::HeartbeatAck { .. } => (Some(LinkMessageType::HeartbeatAck), false, true),
            Frame::DownloadRefused { .. } => {
                (Some(LinkMessageType::EnterDownloadAck), false, false)
            }
            Frame::CloseReport { .. } => (Some(LinkMessageType::CloseConnectionAck), false, false),
            Frame::TimeOffer { .. } => (Some(LinkMessageType::TimeOffer), false, false),
            Frame::NetReport { .. } => (Some(LinkMessageType::NetConfigAck), false, false),
            Frame::PairingWindowAck { .. } => {
                (Some(LinkMessageType::PairingWindowAck), false, false)
            }
            Frame::ClientConnected { .. } => (Some(LinkMessageType::ClientConnected), false, false),
            Frame::ClientDisconnected { .. } => {
                (Some(LinkMessageType::ClientDisconnected), false, false)
            }
            Frame::WifiScanAck { .. } => (Some(LinkMessageType::WifiScanAck), false, false),
            Frame::WifiScanResult { .. } => (Some(LinkMessageType::WifiScanResult), false, false),
            Frame::WifiState { .. } => (Some(LinkMessageType::WifiState), false, false),
            Frame::Refuse { .. } => (None, false, false),
        };
        let silent = match self.caps.answers {
            Answers::Nothing => true,
            Answers::Everything | Answers::TalksOnly => false,
        };
        let lost = matches!(frame, Frame::ClientDisconnected { .. })
            && self.caps.releases == Releases::Lost;
        if (kind == Some(LinkMessageType::NetConfigAck) && self.caps.withhold_network_ack)
            || silent
            || lost
            || (statement && self.caps.statement == Statement::Withheld)
            || (beat && self.caps.beats == Beats::Withheld)
        {
            return Ok(Vec::new());
        }
        let whole = self.build(frame, now)?;
        Ok(self.wire(&whole, kind, now))
    }

    /// `frame` as the wire carries it. Built by its link, as the module
    /// would, unless the peer claims another version or the other side, in
    /// which case its statements say so.
    fn build(&mut self, frame: Frame, now: Tick) -> Result<Vec<u8>, Broken> {
        if let Some(own) = self.own_frame(frame, now) {
            return own;
        }
        let honest = self.caps.version == OURS
            && self.caps.claims == Claims::Comms
            && self.caps.net_version == 0;
        if !honest {
            if let Frame::LinkUp { req_id } = frame {
                return self.claimed_statement(LinkMessageType::LinkUp, req_id);
            }
            if let Frame::LinkUpAck { req_id } = frame {
                return self.claimed_statement(LinkMessageType::LinkUpAck, req_id);
            }
        }
        let me = Identity {
            fw: IDENTITY_FW,
            hw: IDENTITY_HW,
            boot_id: self.boot_id,
        };
        let mut dst = [0u8; MAX_FRAME];
        let built = match self.link.as_ref() {
            Some(link) => link.build(frame, &me, now, &mut self.writer, &mut dst),
            // Before its boot, or after its power went: the frame as a link
            // started then would build it.
            None => {
                CommsLink::new(self.booted_at).build(frame, &me, now, &mut self.writer, &mut dst)
            }
        };
        let len = built.map_err(|_| Broken::Frame)?;
        Ok(dst.get(..len).ok_or(Broken::Frame)?.to_vec())
    }

    /// The frames that carry its connections, which its link cannot write
    /// because it holds none: a beat with the count, and a close's report
    /// with what the close did.
    fn own_frame(&mut self, frame: Frame, now: Tick) -> Option<Result<Vec<u8>, Broken>> {
        let mut envelope = [0u8; MAX_FRAME];
        let beat = |kind, req_id, envelope: &mut [u8]| {
            let uptime_s = now
                .since(self.booted_at)
                .and_then(|up| up.as_millis().checked_div(1_000))
                .map_or(0, |secs| u32::try_from(secs).unwrap_or(u32::MAX));
            let table = self
                .link
                .as_ref()
                .map_or(0, |link| link.connections().allocated());
            Heartbeat {
                uptime_s,
                conns: u8::try_from(self.live.len())
                    .unwrap_or(u8::MAX)
                    .saturating_add(table),
            }
            .write(header(kind, req_id), envelope)
        };
        let written = match frame {
            Frame::Heartbeat { req_id } => beat(LinkMessageType::Heartbeat, req_id, &mut envelope),
            Frame::HeartbeatAck { req_id } => {
                beat(LinkMessageType::HeartbeatAck, req_id, &mut envelope)
            }
            Frame::CloseReport {
                req_id,
                outcome: table_outcome,
                closed: table_closed,
            } => {
                // What the close did to the connections it invented, with
                // what it did to its table's.
                let (outcome, closed) = self.close_report.take()?;
                let outcome = if table_outcome == CloseConnection::Closed {
                    CloseConnection::Closed
                } else {
                    outcome
                };
                let closed = closed.saturating_add(table_closed);
                CloseReport { outcome, closed }.write(
                    header(LinkMessageType::CloseConnectionAck, req_id),
                    &mut envelope,
                )
            }
            Frame::LinkUp { .. }
            | Frame::LinkUpAck { .. }
            | Frame::DownloadRefused { .. }
            | Frame::TimeOffer { .. }
            | Frame::NetReport { .. }
            | Frame::PairingWindowAck { .. }
            | Frame::ClientConnected { .. }
            | Frame::ClientDisconnected { .. }
            | Frame::WifiScanAck { .. }
            | Frame::WifiScanResult { .. }
            | Frame::WifiState { .. }
            | Frame::Refuse { .. } => return None,
        };
        let Ok(len) = written else {
            return Some(Err(Broken::Body));
        };
        let mut dst = [0u8; MAX_FRAME];
        Some(
            envelope
                .get(..len)
                .ok_or(Broken::Body)
                .and_then(|payload| {
                    self.writer
                        .write(payload, &mut dst)
                        .map_err(|_| Broken::Frame)
                })
                .and_then(|len| Ok(dst.get(..len).ok_or(Broken::Frame)?.to_vec())),
        )
    }

    /// What a frame from the controller does to its connections: an
    /// announcement refused for a full table is not kept, and a close
    /// closes what it names, every one for handle 0 (L-090).
    fn connections(&mut self, frame: &[u8]) {
        let Ok(envelope) = LinkEnvelope::decode(frame) else {
            return;
        };
        let req_id = envelope.req_id();
        match LinkMessageType::try_from(envelope.opcode()) {
            Ok(LinkMessageType::ClientConnectedAck) => {
                let Some(at) = self.announcing.iter().position(|(id, _)| *id == req_id) else {
                    return;
                };
                let (_, conn) = self.announcing.remove(at);
                if first_value(envelope) == Some(ClientConnected::RefusedTableFull as u8) {
                    self.live.retain(|live| *live != conn);
                }
            }
            Ok(LinkMessageType::CloseConnection) => {
                let Ok(close) = CloseConnections::decode(envelope) else {
                    return;
                };
                let before = self.live.len();
                if close.is_every_connection() {
                    self.live.clear();
                } else {
                    self.live.retain(|live| *live != close.conn);
                }
                let closed = before.saturating_sub(self.live.len());
                let outcome = if close.is_every_connection() || closed > 0 {
                    CloseConnection::Closed
                } else {
                    CloseConnection::UnknownHandle
                };
                self.close_report = Some((outcome, u8::try_from(closed).unwrap_or(u8::MAX)));
            }
            Ok(_) | Err(()) => {}
        }
    }

    /// Its connections go with its boot or its power.
    fn forget_connections(&mut self) {
        self.live.clear();
        self.announcing.clear();
        self.close_report = None;
    }

    /// A statement with the version and the side the peer claims.
    fn claimed_statement(
        &mut self,
        kind: LinkMessageType,
        req_id: ReqId,
    ) -> Result<Vec<u8>, Broken> {
        let mut envelope = [0u8; MAX_FRAME];
        let role = match self.caps.claims {
            Claims::Comms => Side::Comms,
            Claims::Controller => Side::Controller,
        };
        let net_version = match self.caps.claims {
            Claims::Comms => Some(self.caps.net_version),
            Claims::Controller => None,
        };
        let len = LinkUp {
            version: self.caps.version,
            role,
            fw: IDENTITY_FW,
            boot_id: self.boot_id,
            hw: IDENTITY_HW,
            net_version,
        }
        .write(header(kind, req_id), &mut envelope)
        .map_err(|_| Broken::Body)?;
        let payload = envelope.get(..len).ok_or(Broken::Body)?;
        let mut dst = [0u8; MAX_FRAME];
        let len = self
            .writer
            .write(payload, &mut dst)
            .map_err(|_| Broken::Frame)?;
        Ok(dst.get(..len).ok_or(Broken::Frame)?.to_vec())
    }

    /// What the controller sent, written down for the test to read.
    fn overhear(&mut self, frame: &[u8]) {
        let Ok(envelope) = LinkEnvelope::decode(frame) else {
            return;
        };
        let opcode = envelope.opcode();
        let req_id = envelope.req_id();
        let session = u16::from(envelope.session());
        let link_local = (0x60..=0x7E).contains(&(opcode & 0x7F));
        let about_ours =
            opcode == MessageType::ErrorResponse as u8 && session == 0 && req_id == ReqId(0);
        if !link_local && !about_ours {
            self.heard.push(Heard::ToClient {
                session,
                frame: frame.to_vec(),
            });
            return;
        }
        if opcode == MessageType::ErrorResponse as u8 {
            // A refusal travels as the shared `Error 0xFF`, which the link
            // envelope admits; the body is read as the client path reads
            // it, from the same bytes.
            let Ok(client) = Envelope::decode(frame) else {
                return;
            };
            let header = client.header();
            if let Ok(hint) = ErrorBody::from_envelope(client) {
                let code = match hint.code() {
                    Incoming::Client(code) => code as u16,
                    Incoming::LinkLocal(code) => code as u16,
                    Incoming::Unknown(raw) => raw,
                };
                self.heard.push(Heard::Refusal {
                    code,
                    session: u16::from(header.session),
                    req_id: header.req_id,
                });
            }
            return;
        }
        let heard =
            match LinkMessageType::try_from(opcode) {
                Ok(LinkMessageType::LinkUp) => {
                    LinkUp::decode(envelope).ok().map(|theirs| Heard::LinkUp {
                        req_id,
                        boot_id: theirs.boot_id,
                        fw: theirs.fw.to_owned(),
                        version: theirs.version,
                    })
                }
                Ok(LinkMessageType::LinkUpAck) => {
                    LinkUp::decode(envelope)
                        .ok()
                        .map(|theirs| Heard::LinkUpAck {
                            req_id,
                            boot_id: theirs.boot_id,
                        })
                }
                Ok(LinkMessageType::Heartbeat) => {
                    Heartbeat::decode(envelope)
                        .ok()
                        .map(|beat| Heard::Heartbeat {
                            req_id,
                            uptime_s: beat.uptime_s,
                            conns: beat.conns,
                        })
                }
                Ok(LinkMessageType::NetConfig) => heard_network(envelope),
                Ok(LinkMessageType::HeartbeatAck) => Some(Heard::HeartbeatAck { req_id }),
                Ok(LinkMessageType::PairingWindow) => PairingWindowNotice::decode(envelope)
                    .ok()
                    .map(|notice| Heard::PairingWindow {
                        req_id,
                        revision: notice.revision().get(),
                        remaining_ms: notice.remaining_ms(),
                    }),
                Ok(LinkMessageType::CloseConnection) => CloseConnections::decode(envelope)
                    .ok()
                    .map(|close| Heard::Close {
                        req_id,
                        conn: close.conn,
                        reason: close.reason,
                    }),
                Ok(_) | Err(()) => Some(Heard::Other {
                    opcode,
                    req_id,
                    outcome: first_value(envelope),
                }),
            };
        if let Some(heard) = heard {
            self.heard.push(heard);
        }
    }

    /// Frame the first `len` bytes of `payload` for the wire.
    fn frame(
        &mut self,
        payload: &[u8],
        len: usize,
        kind: Option<LinkMessageType>,
    ) -> Result<Vec<u8>, Broken> {
        let payload = payload.get(..len).ok_or(Broken::Body)?;
        let mut dst = [0u8; MAX_FRAME];
        let len = self
            .writer
            .write(payload, &mut dst)
            .map_err(|_| Broken::Frame)?;
        Ok(self.cut(dst.get(..len).ok_or(Broken::Frame)?, kind))
    }

    /// A whole frame as the wire carries it, with a cut frame in front of it
    /// when the capability says so, and its kind written down.
    fn cut(&mut self, whole: &[u8], kind: Option<LinkMessageType>) -> Vec<u8> {
        let mut out = Vec::new();
        if self.caps.frames == Frames::CutBeforeEach {
            // The pair pulled mid-frame: the head of this frame, then the
            // line idle, which the receiver's timeout ends as a delimiter
            // would. Here the delimiter is written, which is the same run
            // ended the same way.
            out.extend_from_slice(whole.get(..whole.len() / 2).unwrap_or(&[]));
            out.push(0);
        }
        out.extend_from_slice(whole);
        if let Some(kind) = kind {
            self.sent.push(kind);
        }
        out
    }

    /// A whole frame onto the wire, now or after the delay.
    fn wire(&mut self, whole: &[u8], kind: Option<LinkMessageType>, now: Tick) -> Vec<u8> {
        let framed = self.cut(whole, kind);
        self.queue(framed, now)
    }

    fn queue(&mut self, frame: Vec<u8>, now: Tick) -> Vec<u8> {
        match self.caps.delay {
            Some(delay) => {
                let due = now.after(delay).unwrap_or(now);
                self.outbox.push_back((due, frame));
                Vec::new()
            }
            None => frame,
        }
    }

    /// A request id its link never issued, for a frame put on the wire
    /// outside it.
    fn take_injected(&mut self) -> ReqId {
        let req = ReqId(self.next_injected);
        self.next_injected = self.next_injected.wrapping_add(1);
        req
    }
}

const fn header(kind: LinkMessageType, req_id: ReqId) -> LinkHeader {
    LinkHeader {
        kind,
        session: SessionId::None,
        req_id,
    }
}

/// The value of key 1 in a body, which is every ack's outcome.
fn first_value(envelope: LinkEnvelope<'_>) -> Option<u8> {
    let mut body = envelope.into_body();
    let key = body.key().ok()?;
    if key != 1 {
        return None;
    }
    body.u8().ok()
}

fn heard_network(envelope: LinkEnvelope<'_>) -> Option<Heard> {
    km43::NetChange::decode(envelope).ok().and_then(|change| {
        let (version, join, country, hostname) = match change {
            km43::NetChange::ClearUnwritten => {
                return Some(Heard::NetConfig {
                    version: 0,
                    network: o89_core::Network::NONE,
                });
            }
            km43::NetChange::Set {
                version,
                ssid,
                psk,
                country,
                hostname,
            } => (
                version,
                Some(km43::JoinWrite {
                    ssid: km43::Ssid::new(ssid).ok()?,
                    psk: Some(km43::Passphrase::new(psk).ok()?),
                }),
                country,
                hostname,
            ),
            km43::NetChange::Clear {
                version,
                country,
                hostname,
            } => (version, None, country, hostname),
        };
        let network = o89_core::Network::NONE
            .changed(km43::NetworkWrite {
                join,
                country: km43::Country::new(country).ok()?,
                hostname: km43::Hostname::new(hostname).ok()?,
            })
            .ok()?;
        Some(Heard::NetConfig { version, network })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every heartbeat the peer put on the wire in five seconds from its
    /// boot, ticked every ten milliseconds, before anyone answers it.
    fn beats_in_five_seconds(caps: Capabilities) -> usize {
        let mut peer = HostileComms::new(caps);
        let _ = peer.boot(Tick::ZERO).expect("the peer boots");
        for ms in (10..=5_000).step_by(10) {
            let _ = peer.tick(Tick::from_millis(ms)).expect("the peer ticks");
        }
        let _ = peer.heartbeat(Tick::from_millis(5_000)).expect("builds");
        peer.sent
            .iter()
            .filter(|kind| **kind == LinkMessageType::Heartbeat)
            .count()
    }

    #[test]
    fn a_peer_that_beats_regardless_beats_without_a_link() {
        let beats = beats_in_five_seconds(Capabilities {
            beats: Beats::Regardless,
            ..Capabilities::default()
        });
        assert_eq!(beats, 3, "two on its clock and the one injected");
    }

    #[test]
    fn a_peer_that_answers_nothing_beats_nothing_even_regardless() {
        let beats = beats_in_five_seconds(Capabilities {
            answers: Answers::Nothing,
            beats: Beats::Regardless,
            ..Capabilities::default()
        });
        assert_eq!(beats, 0);
    }

    #[test]
    fn a_peer_that_withholds_its_beats_injects_none_either() {
        let beats = beats_in_five_seconds(Capabilities {
            beats: Beats::Withheld,
            ..Capabilities::default()
        });
        assert_eq!(beats, 0);
    }
}
