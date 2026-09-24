//! The session layer driven over the link: the hostile comms processor
//! announcing, relaying, replaying, dropping and rebooting through the
//! handshake, and a client on the far side of it built from `km43`'s own
//! client half, so what the controller answers is checked the way a
//! client checks it. Then the mint behind every challenge, crashed at
//! every step.

use std::cell::RefCell;

use embassy_futures::block_on;
use km43::{
    Attempt, ClientId, ClientKind, CloseReason, CommandKind, CommandOperation, Conn, Counter,
    DeviceId, DeviceSecret, Discovery, EmptyBody, Envelope, Epoch, ErrorBody, Handshake, Header,
    HelloInner, Incoming, LinkTransport, MessageType, PairAckClaim, PairRequest, PairResponse,
    PrintedSecret, ReqId, Session, SessionId, SessionKey, Signed, Tagged, Version, Wrapper,
};
use o89_core::{DropReason, Facts, Millis, Sessions};

use crate::link::{Bench, DEVICE, LOG, MODEL, PRINTED, unit};
use crate::{Answers, Capabilities, Heard, Releases, SimFram, crash_at_every_step};

fn device() -> DeviceSecret {
    DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new(PRINTED))
}

fn epoch() -> Epoch {
    Epoch::FIRST
}

/// A client on one connection, speaking through the bench's comms
/// processor, which stamps the handle into every frame (P-021).
pub(crate) struct Client {
    handle: u16,
    req: u32,
    key: Option<SessionKey>,
}

impl Client {
    pub(crate) const fn on(handle: u16) -> Self {
        Self {
            handle,
            req: 0,
            key: None,
        }
    }

    fn header(&mut self, kind: MessageType) -> Header {
        self.req = self.req.wrapping_add(1);
        Header {
            kind,
            session: SessionId::from(self.handle),
            req_id: ReqId(self.req),
        }
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

    fn empty(&mut self, kind: MessageType) -> Vec<u8> {
        let mut dst = [0u8; 64];
        let cbor = self.header(kind).write(0, &mut dst).expect("fits");
        let len = cbor.finish().expect("fits");
        dst[..len].to_vec()
    }

    fn discover(&mut self, bench: &mut Bench) -> [u8; 16] {
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
            bench
                .endpoint
                .sessions
                .keys()
                .clients
                .present()
                .unwrap()
                .enrolled()
                > 0
        );
        discovery.challenge
    }

    /// `Discover`, then a `Pair` from `label` proved under the printed
    /// secret's pair key, and its `Pair 0x8B` verified as a client verifies
    /// it.
    pub(crate) fn pair(&mut self, bench: &mut Bench, label: &str) -> PairResponse {
        let challenge = self.discover(bench);
        let attempt = Attempt {
            device_id: DEVICE,
            challenge,
            client_nonce: [self.handle.to_le_bytes()[0] ^ 0x5a; 16],
        };
        let mut dst = [0u8; 256];
        let header = self.header(MessageType::Pair);
        let len = PairRequest {
            client_kind: ClientKind::Cli,
            label,
        }
        .write(&device().pair_key(), &attempt, header, &mut dst)
        .expect("fits");
        let answers = self.send(bench, &dst[..len]);
        let answer = answers.last().expect("Pair is answered");
        let envelope = Envelope::decode(answer).expect("an envelope");
        assert_eq!(envelope.header().kind, MessageType::PairResponse);
        PairAckClaim::decode(envelope)
            .expect("a pair ack")
            .verify(&device().pair_key(), &attempt, epoch())
            .expect("MAC'd under the pair key")
    }

    fn hello_frame(&mut self, challenge: [u8; 16], nonce: [u8; 16]) -> Vec<u8> {
        let enrolment = device().enrolment(epoch(), ClientId::new(1).expect("a slot"));
        let mut inner = [0u8; 128];
        let request = HelloInner {
            version: Version::V1_0,
            client_id: ClientId::new(1).expect("a slot"),
            client_version: "sim/1",
            client_nonce: nonce,
        }
        .prove(&enrolment.client_key(), &challenge, &mut inner)
        .expect("proves");
        let mut dst = [0u8; 256];
        let len = request
            .write(self.header(MessageType::Hello), &mut dst)
            .expect("fits");
        dst[..len].to_vec()
    }

    /// `Discover` then `Hello`, and the session opened as a client opens it
    /// (P-072): the key from the envelope's handle, then the MAC.
    fn open(&mut self, bench: &mut Bench) -> Vec<u8> {
        let challenge = self.discover(bench);
        let nonce = [self.handle.to_le_bytes()[0]; 16];
        let frame = self.hello_frame(challenge, nonce);
        let answers = self.send(bench, &frame);
        let answer = answers.last().expect("Hello is answered");
        let enrolment = device().enrolment(epoch(), ClientId::new(1).expect("a slot"));
        let handshake = Handshake {
            challenge,
            client_nonce: nonce,
        };
        let session = Session::open(
            Envelope::decode(answer).expect("an envelope"),
            &enrolment,
            &handshake,
            Version::V1_0,
        )
        .expect("the client opens the session");
        assert_eq!(session.report().log_newest_seq, LOG.newest);
        self.key = Some(enrolment.session_key(&handshake, SessionId::from(self.handle)));
        frame
    }

    /// A signed `Command` under `counter`, as the client signs it.
    fn command(&mut self, counter: u64, cmd_id: u32, key: &SessionKey) -> Vec<u8> {
        let header = self.header(MessageType::Command);
        let mut op = [0u8; 16];
        let len = CommandOperation {
            cmd_id,
            kind: CommandKind::StartGenerator,
            args: &[0xa0],
        }
        .encode(&mut op)
        .expect("fits");
        let mut dst = [0u8; 128];
        let len = Signed::over(
            header,
            ClientId::new(1).expect("a slot"),
            Counter(counter),
            &op[..len],
            key,
        )
        .expect("signs")
        .write(&mut dst)
        .expect("fits");
        dst[..len].to_vec()
    }

    fn wrapped(&mut self, kind: MessageType, key: &SessionKey) -> Vec<u8> {
        let header = self.header(kind);
        let mut dst = [0u8; 128];
        let len = Tagged::over(header, &[0xa0], key)
            .expect("wraps")
            .write(&mut dst)
            .expect("fits");
        dst[..len].to_vec()
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
    let key = client.key.take().expect("a session");
    let frame = client.wrapped(MessageType::Goodbye, &key);
    let answers = client.send(&mut bench, &frame);
    let envelope = Envelope::decode(answers.last().expect("answered")).expect("an envelope");
    let verified = Wrapper::decode(envelope)
        .and_then(|wrapper| wrapper.verify(&key))
        .expect("under the key it ended");
    assert!(EmptyBody::decode(MessageType::GoodbyeResponse, verified.payload()).is_ok());
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
    let key = client.key.take().expect("a session");
    let goodbye = client.wrapped(MessageType::Goodbye, &key);
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
    let key = client.key.take().expect("a session");
    let frame = client.wrapped(MessageType::Readings, &key);
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
    release(&mut bench, 1);
    assert_eq!(
        bench.endpoint.sessions.allocated(),
        2,
        "the controller was never told"
    );
    let lost_at = bench.comms.heard.len();
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
fn p_022_a_verified_command_the_comms_processor_replays_acts_once_and_is_answered_once() {
    // Capabilities: replay.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().expect("a session");
    let frame = client.command(1, 7, &key);
    let answers = client.send(&mut bench, &frame);
    let envelope = Envelope::decode(answers.last().expect("answered")).expect("an envelope");
    assert_eq!(envelope.header().kind, MessageType::CommandResponse);
    let accepted = |bench: &Bench| {
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .and_then(|table| table.accepted(ClientId::new(1).expect("a slot")))
    };
    assert_eq!(accepted(&bench), Some(Counter(1)));
    // The same bytes, relayed again and again as the comms processor
    // chooses: nothing reaches the client that it could take for an answer,
    // the counter is not read again, and the connection is not shed.
    for n in 1..=9 {
        let answers = client.send(&mut bench, &frame);
        assert!(answers.is_empty(), "replay {n} answered");
    }
    assert_eq!(accepted(&bench), Some(Counter(1)));
    assert!(closes(&bench).is_empty());
    assert!(
        bench
            .endpoint
            .sessions
            .is_bound(Conn::new(1).expect("a handle"))
    );
    // The client's next request is served as if nothing had happened.
    let next = client.command(2, 8, &key);
    let answers = client.send(&mut bench, &next);
    let envelope = Envelope::decode(answers.last().expect("answered")).expect("an envelope");
    assert_eq!(envelope.header().kind, MessageType::CommandResponse);
    assert_eq!(accepted(&bench), Some(Counter(2)));
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
    let forged = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]))
        .enrolment(epoch(), ClientId::new(1).expect("a slot"))
        .session_key(
            &Handshake {
                challenge: [0; 16],
                client_nonce: [0; 16],
            },
            SessionId::from(1),
        );
    for n in 1..=8 {
        let frame = client.wrapped(MessageType::Readings, &forged);
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
    let forged = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]))
        .enrolment(epoch(), ClientId::new(1).expect("a slot"))
        .session_key(
            &Handshake {
                challenge: [0; 16],
                client_nonce: [0; 16],
            },
            SessionId::from(1),
        );
    for _ in 1..=7 {
        let frame = client.wrapped(MessageType::Readings, &forged);
        let _ = client.send(&mut bench, &frame);
    }
    // The comms processor stops hearing the controller: the close the
    // eighth failure asks for is never answered.
    bench.comms.capabilities().answers = Answers::TalksOnly;
    let frame = client.wrapped(MessageType::Readings, &forged);
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
fn f_041_a_challenge_never_leaves_before_its_counter_and_none_repeats_across_a_cut() {
    let (start, _) = unit();
    // What the uncut path handed out, and what each cut one did.
    let handed: RefCell<Vec<[u8; 16]>> = RefCell::new(Vec::new());
    let facts = Facts {
        model: MODEL,
        fw_controller: "0.0.0-sim",
        fw_comms: "",
        log: LOG,
        time_known: false,
        pairing_open: false,
        link_up: true,
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
            let reply =
                block_on(sessions.frame(&frame[..len], now, (&facts, &mut wifi), part, &mut dst));
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
            // a challenge nobody has seen: its counter is past every one
            // that left.
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

/// The four records the sessions take, read from `part` as a boot reads
/// them.
fn reread(part: &mut SimFram) -> Option<o89_core::Keys> {
    let (store, report) = block_on(o89_core::Store::boot(part, None)).ok()?;
    Some(o89_core::Keys {
        configuration: store.configuration,
        network: store.network,
        secret: store.secret.present().copied(),
        epoch: report.epoch.epoch(),
        epoch_record: store.epoch,
        clients: store.clients,
        challenges: store.challenges,
    })
}

impl Client {
    fn config_write(
        &mut self,
        counter: u64,
        expected: u32,
        body: &[u8],
        key: &SessionKey,
    ) -> Vec<u8> {
        let mut operation = [0; 128];
        let len = km43::SetConfigOperation {
            section: km43::ConfigSection::IdentityAndSite,
            expected_version: expected,
            body,
        }
        .encode(&mut operation)
        .expect("operation");
        let mut frame = [0; 256];
        let len = Signed::over(
            self.header(MessageType::SetConfig),
            ClientId::new(1).expect("client"),
            Counter(counter),
            &operation[..len],
            key,
        )
        .expect("signed")
        .write(&mut frame)
        .expect("frame");
        frame[..len].to_vec()
    }
}

#[test]
fn p_102_signed_set_config_cut_at_every_step_keeps_counter_and_section_order() {
    // Capabilities: none; cuts happen behind the FRAM seam, after authentication.
    let mut initial = linked();
    announce(&mut initial, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut initial);
    let key = client.key.take().expect("key");
    let first = client.config_write(1, 0, &[0xa1, 1, 0x61, b'a'], &key);
    let answers = client.send(&mut initial, &first);
    let verified =
        Wrapper::decode(Envelope::decode(answers.last().expect("answer")).expect("envelope"))
            .expect("wrapper")
            .verify(&key)
            .expect("MAC");
    assert_eq!(
        km43::SetConfigAck::decode(verified.payload())
            .expect("ack")
            .outcome,
        km43::SetConfig::Accepted
    );
    let seed = initial.fram.clone();
    let facts = Facts {
        model: MODEL,
        fw_controller: "sim",
        fw_comms: "sim",
        log: LOG,
        time_known: false,
        pairing_open: false,
        link_up: true,
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
        let key = client.key.take().expect("key");
        let frame = client.config_write(2, 1, &[0xa1, 1, 0x61, b'b'], &key);
        bench.fram.reboot();
        if steps.is_some() {
            bench.fram.cut_after(cut - 1);
        }
        let mut dst = [0; 256];
        let _ = block_on(bench.endpoint.sessions.frame(
            &frame,
            bench.now,
            (&facts, &mut bench.endpoint.link.wifi),
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
        if answer.version() == 2 {
            assert_eq!(
                keys.clients
                    .present()
                    .expect("table")
                    .accepted(ClientId::new(1).expect("client")),
                Some(Counter(2))
            );
        }
    }
    assert!(steps.is_some_and(|steps| steps > 0 && steps < 2999));
}

#[test]
fn p_106_signed_network_write_reads_only_presence_and_pushes_the_secret_privately() {
    // Capabilities: none; the honest transport relays a signed write and wrapped read.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().expect("key");
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
    let mut frame = [0; 256];
    let len = Signed::over(
        client.header(MessageType::SetConfig),
        ClientId::new(1).expect("client"),
        Counter(1),
        &operation[..len],
        &key,
    )
    .expect("signed")
    .write(&mut frame)
    .expect("frame");
    let answers = client.send(&mut bench, &frame[..len]);
    let verified =
        Wrapper::decode(Envelope::decode(answers.last().expect("answer")).expect("envelope"))
            .expect("wrapper")
            .verify(&key)
            .expect("MAC");
    assert_eq!(
        km43::SetConfigAck::decode(verified.payload())
            .expect("ack")
            .outcome,
        km43::SetConfig::Accepted
    );
    let len = km43::GetConfigRequest {
        section: km43::ConfigSection::Network,
    }
    .encode(&mut body)
    .expect("get");
    let len = Tagged::over(client.header(MessageType::GetConfig), &body[..len], &key)
        .expect("wrapped")
        .write(&mut frame)
        .expect("frame");
    let answers = client.send(&mut bench, &frame[..len]);
    let verified =
        Wrapper::decode(Envelope::decode(answers.last().expect("answer")).expect("envelope"))
            .expect("wrapper")
            .verify(&key)
            .expect("MAC");
    let answer = km43::ConfigAnswer::decode(verified.payload()).expect("config");
    let read = km43::NetworkRead::decode(answer.body().expect("body")).expect("read");
    assert_eq!(answer.version(), 1);
    assert!(read.join.expect("join").psk_set);
    assert!(
        !verified
            .payload()
            .windows(13)
            .any(|window| window == b"correct horse")
    );
    assert!(bench.comms.heard.iter().any(|heard| matches!(heard, Heard::NetConfig { version: 1, network } if network.credentials().is_some())));
}

mod adversarial;
mod configuration;
mod conformance;

#[test]
fn f_041_discover_after_secret_replacement_over_a_corrupt_counter_has_a_challenge() {
    use o89_core::{Address, Fram as _, Secret, stage_secret};
    let mut bench = Bench::new(Capabilities::default());
    block_on(bench.fram.write(Address(32), &[0x55; 40])).expect("damage counter");
    let fresh = Secret::new(DEVICE, [0x35; 32]).expect("new entropy");
    block_on(stage_secret(&mut bench.fram, fresh, true)).expect("stage");
    let keys = reread(&mut bench.fram).expect("recover before sessions");
    bench.endpoint.sessions = Sessions::new(keys);
    bench.run_for(Millis::from_millis(2_000));
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let challenge = client.discover(&mut bench);
    assert_ne!(challenge, [0; 16]);
    assert_eq!(challenge, fresh.device_secret().challenge(1));
}
