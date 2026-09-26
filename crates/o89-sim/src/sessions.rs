//! The session layer driven over the link: the hostile comms processor
//! announcing, relaying, replaying, dropping and rebooting through the
//! handshake, and a client on the far side of it built from `km43`'s own
//! client half, so what the controller answers is checked the way a
//! client checks it. Then the mint behind every challenge, crashed at
//! every step.

use std::cell::RefCell;

use embassy_futures::block_on;
use km43::{
    ClientChannel, ClientId, ClientKind, CloseReason, CommandKind, CommandOperation, Conn,
    DeviceId, Discovery, EmptyBody, EnrolAnswer, Envelope, Epoch, ErrorBody, Fingerprint, Header,
    HelloOffer, HelloPending, Incoming, LinkTransport, LogSeq, MAX_FRAME, MAX_PAYLOAD, MessageType,
    PairOffer, PairPending, PairRefusal, PairReply, Prologue, PrologueFields, ReqId, Sealed,
    SessionId, Signed, Suite, Version,
};
use o89_core::{Compat, DropReason, Facts, Millis, Sessions};

use crate::link::{
    Bench, DEVICE, LOG, MODEL, STEP, client_key, controller, enrolled, reread, secret, unit,
};
use crate::{Answers, Capabilities, Heard, Releases, SimFram, crash_at_every_step};

/// The one suite (P-226).
pub(crate) const SUITE: Suite = Suite::X25519ChachapolySha256;

/// P-236's fingerprint, as the label prints it.
pub(crate) fn fingerprint() -> Fingerprint {
    controller().fingerprint()
}

/// A client install on one connection, speaking through the bench's comms
/// processor, which stamps the handle into every frame (P-021). Built from
/// `km43`'s client half: it pairs from the label, checks the controller key
/// message 2 proves against the label's fingerprint (P-236), keeps its
/// enrolment before message 3 (P-064), says `Hello` against the key it
/// pinned, and seals every request after it.
pub(crate) struct Client {
    handle: u16,
    req: u32,
    draws: u8,
    /// Which install's static key this client holds (`client_key`).
    install: u8,
    challenge: Option<[u8; 16]>,
    epoch: Epoch,
    enrolment: Option<km43::Enrolment>,
    channel: Option<ClientChannel>,
    /// What the last `Hello 0x81` reported of the log and the topology.
    pub(crate) reported: Option<(LogSeq, km43::Topology)>,
}

impl Client {
    /// The unit's phone, install 1, as `unit()` enrolled it at slot 1.
    pub(crate) fn on(handle: u16) -> Self {
        let mut client = Self::install(handle, 1);
        client.enrolment = Some(client.kept());
        client
    }

    /// Install `n`, not enrolled anywhere yet.
    pub(crate) fn install(handle: u16, n: u8) -> Self {
        Self {
            handle,
            req: 0,
            draws: 0,
            install: n,
            challenge: None,
            epoch: Epoch::FIRST,
            enrolment: None,
            channel: None,
            reported: None,
        }
    }

    /// The enrolment this install keeps once message 2 checked out (P-222).
    fn kept(&self) -> km43::Enrolment {
        km43::Enrolment::new(
            DeviceId::new(DEVICE),
            controller().public(),
            client_key(self.install),
            SUITE,
            self.epoch,
        )
    }

    pub(crate) fn header(&mut self, kind: MessageType) -> Header {
        self.req = self.req.wrapping_add(1);
        Header {
            kind,
            session: SessionId::from(self.handle),
            req_id: ReqId(self.req),
        }
    }

    fn entropy(&mut self) -> km43::Entropy {
        self.draws = self.draws.wrapping_add(1);
        let mut bytes = [0u8; 32];
        bytes[0] = self.handle.to_le_bytes()[0];
        bytes[1] = self.draws;
        bytes[2] = self.install;
        bytes[31] = 0x40;
        km43::Entropy::new(bytes)
    }

    /// Put `frame` on the wire and let the bench settle; what the
    /// controller sent this client since.
    pub(crate) fn send(&self, bench: &mut Bench, frame: &[u8]) -> Vec<Vec<u8>> {
        let before = bench.comms.to_client(self.handle).len();
        let bytes = bench.comms.relay(frame, bench.now).expect("relays");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(20));
        bench.comms.to_client(self.handle).split_off(before)
    }

    /// A handshake message: put on the wire, then the bench run until the
    /// worker has nothing left, as a client waits out a second of X25519.
    pub(crate) fn exchange(&self, bench: &mut Bench, frame: &[u8]) -> Vec<Vec<u8>> {
        let before = bench.comms.to_client(self.handle).len();
        let bytes = bench.comms.relay(frame, bench.now).expect("relays");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(20));
        for _ in 0..100_000 {
            if !bench.computing() {
                break;
            }
            bench.run_for(STEP);
        }
        bench.run_for(Millis::from_millis(20));
        bench.comms.to_client(self.handle).split_off(before)
    }

    pub(crate) fn empty(&mut self, kind: MessageType) -> Vec<u8> {
        let mut dst = [0u8; 64];
        let cbor = self.header(kind).write(0, &mut dst).expect("fits");
        let len = cbor.finish().expect("fits");
        dst[..len].to_vec()
    }

    pub(crate) fn discover(&mut self, bench: &mut Bench) -> [u8; 16] {
        let frame = self.empty(MessageType::Discover);
        let answers = self.send(bench, &frame);
        let answer = answers.last().expect("Discover is answered");
        let envelope = Envelope::decode(answer).expect("an envelope");
        assert_eq!(
            envelope.header().session,
            SessionId::from(self.handle),
            "P-026"
        );
        let discovery = Discovery::decode(envelope).expect("a Discover answer");
        assert_eq!(discovery.model, MODEL);
        assert_eq!(
            discovery.provisioned,
            enrolled(&bench.endpoint.sessions) > 0
        );
        self.challenge = Some(discovery.challenge);
        self.epoch = discovery.epoch;
        discovery.challenge
    }

    /// P-227's prologue for the live challenge this client holds.
    pub(crate) fn prologue(&self) -> Prologue {
        Prologue::new(&PrologueFields {
            suite: SUITE,
            version: Version::V1_0,
            device_id: DeviceId::new(DEVICE),
            epoch: self.epoch,
            challenge: self.challenge.as_ref().expect("a challenge to present"),
            handle: SessionId::from(self.handle),
        })
    }

    /// Pairing message 1 under `under`, offering `label`.
    pub(crate) fn pair_frame(
        &mut self,
        under: &km43::Label,
        label: &str,
    ) -> (PairPending, Vec<u8>) {
        let mut dst = [0u8; MAX_FRAME];
        let entropy = self.entropy();
        let header = self.header(MessageType::Pair);
        let (pending, len) = PairPending::start(
            &self.prologue(),
            SUITE,
            under,
            entropy,
            &PairOffer {
                version: Version::V1_0,
                client_version: "sim/1",
                client_kind: ClientKind::Cli,
                label,
            },
            header,
            &mut dst,
        )
        .expect("message 1");
        (pending, dst[..len].to_vec())
    }

    /// `Discover`, then a whole pairing from the label: message 2 checked
    /// against the fingerprint the label prints, the enrolment kept, message
    /// 3, and `Enrol 0x93` opened under the pairing's keys. A refusal is
    /// believed only if the label's refusal key vouches for it (P-241).
    pub(crate) fn pair(
        &mut self,
        bench: &mut Bench,
        label: &str,
    ) -> Result<EnrolAnswer, PairRefusal> {
        let _ = self.discover(bench);
        let (pending, frame) = self.pair_frame(&secret().label(), label);
        let answers = self.exchange(bench, &frame);
        let answer = answers.last().expect("Pair is answered");
        let envelope = Envelope::decode(answer).expect("an envelope");
        assert_eq!(envelope.header().kind, MessageType::PairResponse);
        let proceeding = match pending
            .read(envelope, &secret().label(), &fingerprint())
            .expect("an answer the label vouches for")
        {
            PairReply::Proceed(proceeding) => proceeding,
            PairReply::Refused(refusal) => return Err(refusal),
        };
        let mut dst = [0u8; MAX_FRAME];
        let header = self.header(MessageType::Enrol);
        let (enrol, len) = proceeding
            .finish(&client_key(self.install), header, &mut dst)
            .expect("message 3");
        // Kept before message 3 leaves (P-064).
        self.enrolment = Some(self.kept());
        let answers = self.exchange(bench, &dst[..len]);
        let answer = answers.last().expect("Enrol is answered");
        let mut plain = [0u8; MAX_PAYLOAD];
        let answer = enrol
            .read(Envelope::decode(answer).expect("an envelope"), &mut plain)
            .expect("sealed under the pairing's keys");
        self.challenge = Some(answer.next_challenge);
        Ok(answer)
    }

    /// A `Hello` against the kept enrolment and the live challenge.
    pub(crate) fn hello_frame(&mut self) -> (HelloPending, Vec<u8>) {
        let mut dst = [0u8; MAX_FRAME];
        let entropy = self.entropy();
        let header = self.header(MessageType::Hello);
        let (pending, len) = HelloPending::start(
            &self.prologue(),
            self.enrolment.as_ref().expect("enrolled"),
            entropy,
            &HelloOffer {
                version: Version::V1_0,
                client_version: "sim/1",
            },
            header,
            &mut dst,
        )
        .expect("message 1");
        (pending, dst[..len].to_vec())
    }

    /// The `Hello 0x81` in `answer`, opened under the pinned key: the slot
    /// and generation it names, and the session kept.
    pub(crate) fn finish(
        &mut self,
        pending: HelloPending,
        answer: &[u8],
    ) -> Option<(ClientId, km43::Generation)> {
        let envelope = Envelope::decode(answer).ok()?;
        if envelope.header().kind != MessageType::HelloResponse {
            return None;
        }
        let mut plain = [0u8; MAX_PAYLOAD];
        let session = pending
            .finish(
                self.enrolment.as_ref().expect("enrolled"),
                envelope,
                &mut plain,
            )
            .expect("message 2 opens under the pinned key");
        self.reported = Some((session.report().log_newest_seq, session.report().topology));
        let named = (session.report().client_id, session.report().generation);
        self.channel = Some(session.into_channel());
        Some(named)
    }

    /// `Discover` then `Hello`, and the session opened as a client opens it.
    /// The `Hello` frame comes back for a replay.
    pub(crate) fn open(&mut self, bench: &mut Bench) -> Vec<u8> {
        let _ = self.discover(bench);
        let (pending, frame) = self.hello_frame();
        let answers = self.exchange(bench, &frame);
        let answer = answers.last().expect("Hello is answered");
        assert!(
            self.finish(pending, answer).is_some(),
            "Hello refused: {:?}",
            code(answer)
        );
        // The report describes the log as it stood when the `Hello` was
        // queued; the recorder may have written since.
        assert!(
            self.reported
                .is_some_and(|(newest, _)| newest <= bench.log_span().newest),
            "Hello reports the log as the recorder published it"
        );
        frame
    }

    /// A request sealed under the session (P-231).
    pub(crate) fn sealed(&mut self, kind: MessageType, inner: &[u8]) -> Vec<u8> {
        let mut dst = [0u8; MAX_FRAME];
        let channel = self.channel.as_mut().expect("a session");
        let (req_id, len) = channel
            .tx
            .seal(kind, SessionId::from(self.handle), inner, &mut dst)
            .expect("sealed");
        self.req = req_id.0;
        dst[..len].to_vec()
    }

    /// A request with an empty map inside.
    pub(crate) fn wrapped(&mut self, kind: MessageType) -> Vec<u8> {
        self.sealed(kind, &[0xa0])
    }

    /// A sealed request whose tag was broken on the way: what a relay
    /// without the session's keys can make.
    pub(crate) fn forged(&mut self, kind: MessageType) -> Vec<u8> {
        let mut frame = self.wrapped(kind);
        if let Some(last) = frame.last_mut() {
            *last ^= 1;
        }
        frame
    }

    /// A write, sealed.
    pub(crate) fn signed(&mut self, kind: MessageType, operation: &[u8]) -> Vec<u8> {
        let mut dst = [0u8; MAX_FRAME];
        let channel = self.channel.as_mut().expect("a session");
        let (req_id, len) = Signed::new(kind, operation)
            .expect("a write")
            .seal(&mut channel.tx, SessionId::from(self.handle), &mut dst)
            .expect("sealed");
        self.req = req_id.0;
        dst[..len].to_vec()
    }

    /// A `StartGenerator` command under `cmd_id`, sealed.
    pub(crate) fn command(&mut self, cmd_id: u32) -> Vec<u8> {
        let mut op = [0u8; 16];
        let len = CommandOperation {
            cmd_id,
            kind: CommandKind::StartGenerator,
            args: &[0xa0],
        }
        .encode(&mut op)
        .expect("fits");
        self.signed(MessageType::Command, &op[..len])
    }

    /// An answer opened under the session: its header and inner body, or
    /// nothing if it does not open.
    pub(crate) fn opened(&mut self, answer: &[u8]) -> Option<(Header, Vec<u8>)> {
        let channel = self.channel.as_mut().expect("a session");
        let envelope = Envelope::decode(answer).ok()?;
        let header = envelope.header();
        let mut plain = [0u8; MAX_PAYLOAD];
        let opened = Sealed::decode(envelope)
            .and_then(|sealed| sealed.open(&mut channel.rx, &mut plain))
            .ok()?;
        Some((header, opened.inner().to_vec()))
    }
}

/// The code a bare error carries, whatever a client makes of it.
fn code(answer: &[u8]) -> Option<u16> {
    let envelope = Envelope::decode(answer).ok()?;
    let hint = ErrorBody::from_envelope(envelope).ok()?;
    Some(match hint.code() {
        Incoming::Client(code) => code as u16,
        Incoming::LinkLocal(code) => code as u16,
        Incoming::Unknown(raw) => raw,
    })
}

/// The outcome of every acknowledgement of `opcode` the comms processor
/// heard, in order.
fn outcomes(bench: &Bench, opcode: u8) -> Vec<u8> {
    bench
        .comms
        .heard
        .iter()
        .filter_map(|heard| match heard {
            Heard::Other {
                opcode: heard,
                outcome,
                ..
            } if *heard == opcode => *outcome,
            Heard::Other { .. }
            | Heard::ToClient { .. }
            | Heard::Close { .. }
            | Heard::LinkUp { .. }
            | Heard::LinkUpAck { .. }
            | Heard::Heartbeat { .. }
            | Heard::HeartbeatAck { .. }
            | Heard::Refusal { .. }
            | Heard::PairingWindow { .. }
            | Heard::NetConfig { .. } => None,
        })
        .collect()
}

fn closes(bench: &Bench) -> Vec<(u16, CloseReason)> {
    bench
        .comms
        .heard
        .iter()
        .filter_map(|heard| match heard {
            Heard::Close { conn, reason, .. } => Some((*conn, *reason)),
            Heard::Other { .. }
            | Heard::ToClient { .. }
            | Heard::LinkUp { .. }
            | Heard::LinkUpAck { .. }
            | Heard::Heartbeat { .. }
            | Heard::HeartbeatAck { .. }
            | Heard::Refusal { .. }
            | Heard::PairingWindow { .. }
            | Heard::NetConfig { .. } => None,
        })
        .collect()
}

/// The last `conns` the controller put in a heartbeat.
fn conns(bench: &Bench) -> Option<u8> {
    bench
        .comms
        .heard
        .iter()
        .rev()
        .find_map(|heard| match heard {
            Heard::Heartbeat { conns, .. } => Some(*conns),
            Heard::Other { .. }
            | Heard::ToClient { .. }
            | Heard::Close { .. }
            | Heard::LinkUp { .. }
            | Heard::LinkUpAck { .. }
            | Heard::HeartbeatAck { .. }
            | Heard::Refusal { .. }
            | Heard::PairingWindow { .. }
            | Heard::NetConfig { .. } => None,
        })
}

/// A linked bench.
fn linked() -> Bench {
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up());
    bench
}

pub(crate) fn announce(bench: &mut Bench, handle: u16) {
    let bytes = bench
        .comms
        .announce_connection(handle, bench.now)
        .expect("builds");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(20));
}

fn release(bench: &mut Bench, handle: u16) {
    let bytes = bench
        .comms
        .release_connection(handle, bench.now)
        .expect("builds");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(20));
}

#[test]
fn l_070_p_076_a_client_connects_opens_a_session_says_goodbye_and_its_row_goes_with_its_transport()
{
    // Capabilities: none.
    let mut bench = linked();
    announce(&mut bench, 1);
    assert_eq!(outcomes(&bench, 0xE2), vec![1], "accepted");
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    assert!(
        bench
            .endpoint
            .sessions
            .is_bound(Conn::new(1).expect("a handle"))
    );
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(1), "L-101: the row, bound");
    let frame = client.wrapped(MessageType::Goodbye);
    let answers = client.send(&mut bench, &frame);
    let (header, body) = client
        .opened(answers.last().expect("answered"))
        .expect("sealed under the session it ended");
    assert_eq!(header.kind, MessageType::GoodbyeResponse);
    assert!(EmptyBody::decode(MessageType::GoodbyeResponse, &body).is_ok());
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(1), "P-076: goodbye leaves the row");
    release(&mut bench, 1);
    assert_eq!(outcomes(&bench, 0xE3), vec![1], "released");
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(0));
}

#[test]
fn l_061_a_ninth_transport_is_refused_over_the_wire_and_no_row_is_evicted() {
    // Capabilities: invent_connection, exhaust tables.
    let mut bench = linked();
    for handle in 1..=9 {
        announce(&mut bench, handle);
    }
    assert_eq!(outcomes(&bench, 0xE2), vec![1, 1, 1, 1, 1, 1, 1, 1, 2]);
    // The ninth's frames reach a handle nobody was told about (L-062).
    let mut ninth = Client::on(9);
    let frame = ninth.empty(MessageType::Discover);
    let answers = ninth.send(&mut bench, &frame);
    assert_eq!(code(answers.last().expect("answered")), Some(0x103));
    let mut first = Client::on(1);
    let _ = first.discover(&mut bench);
}

#[test]
fn l_072_what_the_comms_processor_claims_of_a_transport_decides_nothing() {
    // Capabilities: invent a connection (a transport and a peer it claims).
    let mut bench = linked();
    let claims = [
        (LinkTransport::Usb, "the installer's laptop"),
        (LinkTransport::Cloud, "admin@origin89"),
        (LinkTransport::Ble, "00:00:00:00:00:00"),
    ];
    for (handle, (transport, peer)) in (1..).zip(claims) {
        let bytes = bench
            .comms
            .announce_as(handle, transport, peer, bench.now)
            .expect("builds");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(20));
        // The same row, the same challenge rules, and no session without
        // a proof, whatever the transport says it is.
        let mut client = Client::on(handle);
        let frame = client.empty(MessageType::Readings);
        let answers = client.send(&mut bench, &frame);
        assert_eq!(code(answers.last().expect("answered")), Some(4), "{peer}");
        let _ = client.open(&mut bench);
    }
    assert_eq!(outcomes(&bench, 0xE2), vec![1, 1, 1]);
}

#[test]
fn l_080_p_061_replays_bind_nothing_and_allocate_nothing() {
    // Capabilities: replay.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let hello = client.open(&mut bench);
    // The announcement again, before any release: refused, one row.
    announce(&mut bench, 1);
    assert_eq!(outcomes(&bench, 0xE2), vec![1, 3]);
    assert_eq!(bench.endpoint.sessions.allocated(), 1);
    // The Hello again: its challenge was spent on its first presentation.
    let answers = client.send(&mut bench, &hello);
    assert_eq!(code(answers.last().expect("answered")), Some(14));
    // The session the first one bound is untouched.
    let goodbye = client.wrapped(MessageType::Goodbye);
    let _ = client.send(&mut bench, &goodbye);
    // The goodbye again: no session is held on the row now.
    let answers = client.send(&mut bench, &goodbye);
    assert_eq!(code(answers.last().expect("answered")), Some(9));
    // The release again: unknown the second time.
    release(&mut bench, 1);
    release(&mut bench, 1);
    assert_eq!(outcomes(&bench, 0xE3), vec![1, 2]);
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
}

#[test]
fn l_041_a_comms_reboot_takes_every_row_and_session_with_it() {
    // Capabilities: reboot.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let bytes = bench.comms.boot(bench.now).expect("the peer reboots");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up(), "linked again, to the new boot");
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
    // The old handle is one this controller no longer knows (L-062).
    let frame = client.wrapped(MessageType::Readings);
    let answers = client.send(&mut bench, &frame);
    assert_eq!(code(answers.last().expect("answered")), Some(0x103));
}

#[test]
fn l_062_a_transport_whose_release_was_dropped_is_reclaimed_by_the_reboot_that_follows() {
    // Capabilities: lose a release, reboot.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    // The transport goes and the release never reaches the controller: the
    // row stays, and the heartbeat says so (L-101).
    bench.comms.capabilities().releases = Releases::Lost;
    release(&mut bench, 1);
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(1));
    // The reboot comes before three beats have disagreed, so it is what
    // reclaims the row here; L-102's resync is the path without one.
    let bytes = bench.comms.boot(bench.now).expect("the peer reboots");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(3_000));
    assert_eq!(conns(&bench), Some(0), "no row leaked past the reboot");
    assert!(
        closes(&bench).is_empty(),
        "reclaimed by the reboot, not a resync"
    );
}

/// Against the peer's invented connections. The same resync driven by the
/// comms processor's own table is in `connections.rs`.
#[test]
fn l_102_a_row_whose_release_was_lost_is_reclaimed_within_three_heartbeats_without_a_reboot() {
    // Capabilities: lose a release.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let boot_id = bench.comms.boot_id();
    bench.comms.capabilities().releases = Releases::Lost;
    // Counted from the release that was lost, whatever the beat's phase.
    let lost_at = bench.comms.heard.len();
    release(&mut bench, 1);
    assert_eq!(
        bench.endpoint.sessions.allocated(),
        2,
        "the controller was never told"
    );
    bench.run_for(Millis::from_millis(7_000));
    // The close of every connection went out on the third beat the two
    // counts disagreed on, and not before.
    let since = &bench.comms.heard[lost_at..];
    let close = since
        .iter()
        .position(|heard| matches!(heard, Heard::Close { .. }))
        .expect("a resync");
    let beats = since[..close]
        .iter()
        .filter(|heard| matches!(heard, Heard::Heartbeat { .. }))
        .count();
    assert_eq!(beats, 3);
    assert_eq!(closes(&bench), vec![(0, CloseReason::Resync)]);
    // Its answer freed every row, with the session on it, and no reboot.
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
    assert!(
        !bench
            .endpoint
            .sessions
            .is_bound(Conn::new(1).expect("a handle"))
    );
    assert!(
        bench
            .drops()
            .iter()
            .any(|(_, why)| *why == DropReason::Resync)
    );
    assert_eq!(bench.comms.boot_id(), boot_id, "no reboot");
    assert!(bench.endpoint.link.is_up());
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(0));
    // The client that was still connected reconnects and is announced
    // again, and the counts agree from there on.
    bench.comms.capabilities().releases = Releases::Sent;
    announce(&mut bench, 2);
    assert_eq!(outcomes(&bench, 0xE2), vec![1, 1, 1]);
    let mut again = Client::on(2);
    let _ = again.open(&mut bench);
    bench.run_for(Millis::from_millis(10_000));
    assert_eq!(conns(&bench), Some(1));
    assert_eq!(closes(&bench), vec![(0, CloseReason::Resync)], "once");
}

#[test]
fn p_022_a_sealed_command_the_comms_processor_replays_acts_once_and_is_answered_once() {
    // Capabilities: replay.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let frame = client.command(7);
    let answers = client.send(&mut bench, &frame);
    let (header, _) = client
        .opened(answers.last().expect("answered"))
        .expect("sealed");
    assert_eq!(header.kind, MessageType::CommandResponse);
    // The same bytes, relayed again and again as the comms processor
    // chooses: the opener's window drops each unanswered and uncounted, and
    // the connection is not shed (P-022, P-051).
    for n in 1..=9 {
        let answers = client.send(&mut bench, &frame);
        assert!(answers.is_empty(), "replay {n} answered");
    }
    assert!(closes(&bench).is_empty());
    assert!(
        bench
            .endpoint
            .sessions
            .is_bound(Conn::new(1).expect("a handle"))
    );
    // The client's next request is served as if nothing had happened.
    let next = client.command(8);
    let answers = client.send(&mut bench, &next);
    let (header, _) = client
        .opened(answers.last().expect("answered"))
        .expect("sealed");
    assert_eq!(header.kind, MessageType::CommandResponse);
}

#[test]
fn p_077_a_quiet_session_is_closed_at_fifteen_minutes_and_its_row_freed_by_the_answer() {
    // Capabilities: none.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    bench.run_for(Millis::from_millis(14 * 60 * 1_000));
    assert!(closes(&bench).is_empty(), "not yet");
    // The controller talking to the session does not keep it alive; only
    // the client proving itself would.
    bench.run_for(Millis::from_millis(61 * 1_000));
    assert_eq!(closes(&bench), vec![(1, CloseReason::SessionExpired)]);
    // The comms processor answered, and the row went with the answer.
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
}

#[test]
fn p_051_eight_bad_macs_inside_a_minute_close_the_connection_over_the_wire() {
    // Capabilities: stamp (frames under a key the session does not hold).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    for n in 1..=8 {
        let frame = client.forged(MessageType::Readings);
        let answers = client.send(&mut bench, &frame);
        assert_eq!(code(answers.last().expect("answered")), Some(10), "{n}");
    }
    assert_eq!(
        closes(&bench),
        vec![(1, CloseReason::AuthenticationFailures)]
    );
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
}

#[test]
fn l_080_a_close_owed_for_a_released_handle_is_forgotten_before_the_handle_is_reused() {
    // Capabilities: withhold (the close's answer), reuse a handle.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    for _ in 1..=7 {
        let frame = client.forged(MessageType::Readings);
        let _ = client.send(&mut bench, &frame);
    }
    // The comms processor stops hearing the controller: the close the
    // eighth failure asks for is never answered.
    bench.comms.capabilities().answers = Answers::TalksOnly;
    let frame = client.forged(MessageType::Readings);
    let _ = client.send(&mut bench, &frame);
    assert_eq!(
        closes(&bench),
        vec![(1, CloseReason::AuthenticationFailures)]
    );
    // It closed the transport anyway and says so; the release is answered,
    // which frees the handle for the next transport (L-080).
    release(&mut bench, 1);
    announce(&mut bench, 1);
    assert_eq!(outcomes(&bench, 0xE2), vec![1, 1]);
    // Past every retry the close would have had: nothing closes the new
    // transport, and its row stands.
    bench.run_for(Millis::from_millis(2_000));
    assert_eq!(
        closes(&bench),
        vec![(1, CloseReason::AuthenticationFailures)]
    );
    assert_eq!(bench.endpoint.sessions.allocated(), 1);
}

#[test]
fn p_237_a_challenge_never_leaves_before_its_successor_is_on_the_part_and_none_repeats_across_a_cut()
 {
    let (start, _) = unit();
    // What the uncut path handed out, and what each cut one did.
    let handed: RefCell<Vec<[u8; 16]>> = RefCell::new(Vec::new());
    let facts = Facts {
        model: MODEL,
        fw_controller: "0.0.0-sim",
        fw_comms: "",
        log: LOG,
        topology: Some(o89_core::reported(0, [0; 8])),
        time_known: false,
        pairing_open: false,
        link: Some(Compat::Agreed(Version::V1_0)),
    };
    // A fresh unit connects two clients and each discovers.
    let path = |part: &mut SimFram, keys| -> Result<(), ()> {
        let mut sessions = Sessions::new(keys);
        let mut wifi = o89_core::Wifi::EMPTY;
        let now = o89_core::Tick::from_millis(1_000);
        for handle in 1..=2u16 {
            let conn = Conn::new(handle).ok_or(())?;
            let _ = sessions.admit(conn);
            block_on(sessions.settle(now, part));
            let mut dst = [0u8; 256];
            let mut frame = [0u8; 16];
            let cbor = Header {
                kind: MessageType::Discover,
                session: SessionId::from(handle),
                req_id: ReqId(1),
            }
            .write(0, &mut frame)
            .map_err(|_| ())?;
            let len = cbor.finish().map_err(|_| ())?;
            let reply = block_on(sessions.frame(
                &frame[..len],
                now,
                (&facts, &mut wifi, &crate::link::SimSite::empty()),
                part,
                &mut dst,
            ));
            let len = reply.answer.ok_or(())?;
            let envelope = Envelope::decode(&dst[..len]).map_err(|_| ())?;
            let discovery = Discovery::decode(envelope).map_err(|_| ())?;
            handed.borrow_mut().push(discovery.challenge);
        }
        Ok(())
    };
    let crashes = crash_at_every_step(
        &start,
        |part| {
            // Each run boots the records the part holds, as `main` does, and
            // counts only what it handed out itself.
            handed.borrow_mut().clear();
            let read = reread(part).ok_or(())?;
            path(part, read)
        },
        |part, step| {
            // Whatever the cut left, the unit that boots from it hands out
            // a challenge nobody has seen: the generator's state on the part
            // is past every draw that left (P-237).
            let read = reread(part).expect("the part is back");
            let before: Vec<[u8; 16]> = handed.borrow_mut().drain(..).collect();
            path(part, read).expect("the supply is steady");
            let after = handed.borrow();
            assert_eq!(
                after.len(),
                2,
                "cut at {step}: both answered after the boot"
            );
            for fresh in after.iter() {
                assert!(
                    !before.contains(fresh),
                    "cut at {step}: a challenge repeated"
                );
            }
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
}

impl Client {
    fn config_write(&mut self, expected: u32, body: &[u8]) -> Vec<u8> {
        let mut operation = [0; 128];
        let len = km43::SetConfigOperation {
            section: km43::ConfigSection::IdentityAndSite,
            expected_version: expected,
            body,
        }
        .encode(&mut operation)
        .expect("operation");
        self.signed(MessageType::SetConfig, &operation[..len])
    }

    /// A signed write of the network section at version 1, accepted.
    fn write_network(&mut self, bench: &mut Bench) {
        let write = km43::NetworkWrite {
            join: Some(km43::JoinWrite {
                ssid: km43::Ssid::new("cabin").expect("ssid"),
                psk: Some(km43::Passphrase::new("correct horse").expect("psk")),
            }),
            country: km43::Country::new("CA").expect("country"),
            hostname: km43::Hostname::new("origin89").expect("host"),
        };
        let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
        let len = write.encode(&mut body).expect("body");
        let mut operation = [0; km43::CONFIG_HEADER_BYTES + km43::MAX_NETWORK_WRITE_BYTES];
        let len = km43::SetConfigOperation {
            section: km43::ConfigSection::Network,
            expected_version: 0,
            body: &body[..len],
        }
        .encode(&mut operation)
        .expect("operation");
        let frame = self.signed(MessageType::SetConfig, &operation[..len]);
        let answers = self.send(bench, &frame);
        let (_, body) = self
            .opened(answers.last().expect("answer"))
            .expect("sealed");
        assert_eq!(
            km43::SetConfigAck::decode(&body).expect("ack").outcome,
            km43::SetConfig::Accepted
        );
    }
}

#[test]
fn p_102_signed_set_config_cut_at_every_step_keeps_the_old_section_or_the_new_one() {
    // Capabilities: none; cuts happen behind the FRAM seam, after authentication.
    let mut initial = linked();
    announce(&mut initial, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut initial);
    let first = client.config_write(0, &[0xa1, 1, 0x61, b'a']);
    let answers = client.send(&mut initial, &first);
    let (_, body) = client
        .opened(answers.last().expect("answer"))
        .expect("sealed");
    assert_eq!(
        km43::SetConfigAck::decode(&body).expect("ack").outcome,
        km43::SetConfig::Accepted
    );
    let seed = initial.fram.clone();
    let facts = Facts {
        model: MODEL,
        fw_controller: "sim",
        fw_comms: "sim",
        log: LOG,
        topology: Some(o89_core::reported(0, [0; 8])),
        time_known: false,
        pairing_open: false,
        link: Some(Compat::Agreed(Version::V1_0)),
    };
    // Establish the exact write length once; each replay below gets a fresh session
    // over the same persisted first version, then the cut starts immediately.
    let mut steps = None;
    for cut in 0..3000 {
        if steps.is_some_and(|steps| cut > steps) {
            break;
        }
        let mut bench = linked();
        bench.fram = seed.clone();
        let keys = reread(&mut bench.fram).expect("boot");
        bench.endpoint.sessions = Sessions::new(keys);
        announce(&mut bench, 1);
        let mut client = Client::on(1);
        let _ = client.open(&mut bench);
        let frame = client.config_write(1, &[0xa1, 1, 0x61, b'b']);
        bench.fram.reboot();
        if steps.is_some() {
            bench.fram.cut_after(cut - 1);
        }
        let mut dst = [0; 256];
        let _ = block_on(bench.endpoint.sessions.frame(
            &frame,
            bench.now,
            (&facts, &mut bench.endpoint.link.wifi, &bench.site),
            &mut bench.fram,
            &mut dst,
        ));
        if steps.is_none() {
            steps = Some(bench.fram.bytes_written());
            continue;
        }
        bench.fram.reboot();
        let keys = reread(&mut bench.fram).expect("recover");
        let mut body = [0; 100];
        let len = keys
            .configuration
            .answer(
                km43::ConfigSection::IdentityAndSite,
                &keys.network,
                &mut body,
            )
            .expect("answer");
        let answer = km43::ConfigAnswer::decode(&body[..len]).expect("decode");
        assert!(
            matches!(
                (answer.version(), answer.body()),
                (1, Some([0xa1, 1, 0x61, b'a'])) | (2, Some([0xa1, 1, 0x61, b'b']))
            ),
            "cut {cut}"
        );
    }
    assert!(steps.is_some_and(|steps| steps > 0 && steps < 2999));
}

#[test]
fn p_080_p_079_a_sealed_command_cut_at_every_step_leaves_its_entry_in_flight_or_absent() {
    // Capabilities: none; cuts happen behind the FRAM seam, after the tag.
    let seed = linked().fram;
    let facts = Facts {
        model: MODEL,
        fw_controller: "sim",
        fw_comms: "sim",
        log: LOG,
        topology: Some(o89_core::reported(0, [0; 8])),
        time_known: false,
        pairing_open: false,
        link: Some(Compat::Agreed(Version::V1_0)),
    };
    let fingerprint = {
        let mut op = [0u8; 16];
        let len = CommandOperation {
            cmd_id: 7,
            kind: CommandKind::StartGenerator,
            args: &[0xa0],
        }
        .encode(&mut op)
        .expect("fits");
        o89_core::Fingerprint::of(&op[..len])
    };
    let (mut absent, mut in_flight) = (0, 0);
    let mut steps = None;
    for cut in 0..5_000 {
        if steps.is_some_and(|steps| cut > steps) {
            break;
        }
        // A fresh session over the same part each time: the keys are the
        // session's, and the cut starts with the command.
        let mut bench = linked();
        bench.fram = seed.clone();
        bench.endpoint.sessions = Sessions::new(reread(&mut bench.fram).expect("boot"));
        announce(&mut bench, 1);
        let mut client = Client::on(1);
        let _ = client.open(&mut bench);
        let frame = client.command(7);
        bench.fram.reboot();
        if steps.is_some() {
            bench.fram.cut_after(cut - 1);
        }
        let mut dst = [0; 256];
        let _ = block_on(bench.endpoint.sessions.frame(
            &frame,
            bench.now,
            (&facts, &mut bench.endpoint.link.wifi, &bench.site),
            &mut bench.fram,
            &mut dst,
        ));
        if steps.is_none() {
            steps = Some(bench.fram.bytes_written());
            continue;
        }
        bench.fram.reboot();
        let keys = reread(&mut bench.fram).expect("recover");
        let commands = keys.clients.commands().present().expect("the dedup record");
        let retry = commands.clone().dedup_mut().admit(
            ClientId::new(1).expect("a slot"),
            7,
            fingerprint,
            o89_core::Tick::from_millis(1),
        );
        match retry {
            o89_core::Verdict::Fresh(_) => absent += 1,
            // Reserved and landed, its `rejected` not recorded: the state
            // store answers the retry (P-080).
            o89_core::Verdict::InFlight(_) => in_flight += 1,
            other => panic!("cut {cut}: {other:?}"),
        }
    }
    assert!(steps.is_some_and(|steps| steps > 0 && steps < 4_999));
    assert!(
        absent > 0 && in_flight > 0,
        "{absent} absent, {in_flight} in flight"
    );
}

/// The link opcode of a scan order, `WifiScan`.
const WIFI_SCAN: u8 = 0x6a;

#[test]
fn p_218_l_200_a_refresh_under_a_major_mismatch_is_link_down_and_orders_no_scan() {
    // Capabilities: version 2.0 restated under the same boot, which keeps
    // the session (L-030); the agreed run restates 1.0.
    for (version, refused) in [
        (
            Version { major: 2, minor: 0 },
            Some(km43::ScanRefusal::LinkDown),
        ),
        (Version::V1_0, None),
    ] {
        let mut bench = linked();
        announce(&mut bench, 1);
        let mut client = Client::on(1);
        let _ = client.open(&mut bench);
        client.write_network(&mut bench);
        bench.comms.capabilities().version = version;
        let statement = bench.comms.restate(bench.now).expect("restates");
        bench.feed(&statement);
        bench.run_for(Millis::from_millis(20));
        assert!(bench.endpoint.link.is_up());
        assert_eq!(
            bench.endpoint.link.compat().is_some_and(Compat::is_agreed),
            refused.is_none()
        );
        let mut body = [0; 8];
        let len = km43::ScanRequest { refresh: true }
            .encode(&mut body)
            .expect("request");
        let frame = client.sealed(MessageType::WifiScan, &body[..len]);
        let answers = client.send(&mut bench, &frame);
        let (_, payload) = client
            .opened(answers.last().expect("answer"))
            .expect("sealed");
        let answer = km43::ScanAnswer::decode(&payload).expect("scan");
        assert_eq!(answer.refused(), refused, "{version:?}");
        bench.run_for(Millis::from_millis(2_000));
        let orders = bench
            .comms
            .heard
            .iter()
            .filter(|heard| {
                matches!(
                    heard,
                    Heard::Other {
                        opcode: WIFI_SCAN,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(orders, usize::from(refused.is_none()), "{version:?}");
    }
}

#[test]
fn p_106_signed_network_write_reads_only_presence_and_pushes_the_secret_privately() {
    // Capabilities: none; the honest transport relays a signed write and wrapped read.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    client.write_network(&mut bench);
    let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
    let len = km43::GetConfigRequest {
        section: km43::ConfigSection::Network,
    }
    .encode(&mut body)
    .expect("get");
    let frame = client.sealed(MessageType::GetConfig, &body[..len]);
    let answers = client.send(&mut bench, &frame);
    let (_, payload) = client
        .opened(answers.last().expect("answer"))
        .expect("sealed");
    let answer = km43::ConfigAnswer::decode(&payload).expect("config");
    let read = km43::NetworkRead::decode(answer.body().expect("body")).expect("read");
    assert_eq!(answer.version(), 1);
    assert!(read.join.expect("join").psk_set);
    assert!(!payload.windows(13).any(|window| window == b"correct horse"));
    assert!(bench.comms.heard.iter().any(|heard| matches!(heard, Heard::NetConfig { version: 1, network } if network.credentials().is_some())));
}

#[test]
fn p_237_a_unit_whose_generator_is_damaged_gives_no_challenge_and_a_new_label_does_not_reseed_it() {
    // Capabilities: none; the damage is behind the storage seam.
    use o89_core::{Fram as _, map, stage_secret};
    let mut bench = Bench::new(Capabilities::default());
    let at = usize::from(map::DRBG.end().0) - 2 * 44;
    let at = o89_core::Address(u16::try_from(at).expect("in the part"));
    block_on(bench.fram.write(at, &[0x55; 88])).expect("damage both copies");
    // A replacement label carries no generator: the unit is born already.
    let fresh = o89_core::Secret::new(DEVICE, [0x35; 32]).expect("new entropy");
    block_on(stage_secret(&mut bench.fram, fresh, None, true)).expect("stage");
    let keys = reread(&mut bench.fram).expect("recover before sessions");
    assert!(!keys.generator.is_available());
    bench.endpoint.sessions = Sessions::new(keys);
    bench.run_for(Millis::from_millis(2_000));
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let frame = client.empty(MessageType::Discover);
    let answers = client.send(&mut bench, &frame);
    assert_eq!(
        code(answers.last().expect("answered")),
        Some(km43::ErrorCode::ChallengeUnavailable as u16)
    );
}

mod adversarial;
mod agreement;
mod configuration;
mod conformance;
mod reading;
