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
//! controller, reboot with a new `boot_id`, and put on the wire the frames a
//! real peer would not. It builds those with `km43`'s own writers, so what
//! the controller reads is what a real peer would have sent, and a frame it
//! cannot build is an error a test reads, never a panic in this crate.

use std::collections::VecDeque;

use km43::{
    ClientUp, ClockOffer, Envelope, ErrorBody, FrameReader, FrameWriter, Header, Heartbeat,
    Incoming, LinkEnvelope, LinkHeader, LinkMessageType, LinkTransport, LinkUp, MAX_FRAME,
    MessageType, Received, ReqId, SessionId, Side, Version,
};
use o89_comms_core::{Frame, Identity, Link as CommsLink};
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

/// What the peer may do. The default is a peer that behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
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
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            answers: Answers::Everything,
            statement: Statement::Given,
            beats: Beats::Given,
            delay: None,
            rom_text: 0,
            frames: Frames::Whole,
            version: Version::V1_0,
            claims: Claims::Comms,
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
    pub fn heartbeat(&mut self, now: Tick) -> Result<Vec<u8>, Broken> {
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

    /// A connection announced with this handle.
    pub fn announce_connection(&mut self, conn: u16, now: Tick) -> Result<Vec<u8>, Broken> {
        let req_id = self.take_injected();
        let mut dst = [0u8; MAX_FRAME];
        let len = ClientUp {
            conn,
            transport: LinkTransport::WifiLocal,
            peer: "192.168.4.2",
        }
        .write(header(LinkMessageType::ClientConnected, req_id), &mut dst)
        .map_err(|_| Broken::Body)?;
        let frame = self.frame(&dst, len, Some(LinkMessageType::ClientConnected))?;
        Ok(self.queue(frame, now))
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
            Frame::NetFailed { .. } => (Some(LinkMessageType::NetConfigAck), false, false),
            Frame::Refuse { .. } => (None, false, false),
        };
        let silent = match self.caps.answers {
            Answers::Nothing => true,
            Answers::Everything | Answers::TalksOnly => false,
        };
        if silent
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
        let honest = self.caps.version == OURS && self.caps.claims == Claims::Comms;
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
            Claims::Comms => Some(0),
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
        let heard = match LinkMessageType::try_from(opcode) {
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
            Ok(LinkMessageType::HeartbeatAck) => Some(Heard::HeartbeatAck { req_id }),
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
