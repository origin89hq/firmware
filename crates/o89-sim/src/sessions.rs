//! The session layer driven over the link: the hostile comms processor
//! announcing, relaying, replaying, dropping and rebooting through the
//! handshake, and a client on the far side of it built from `km43`'s own
//! client half, so what the controller answers is checked the way a
//! client checks it. Then the mint behind every challenge, crashed at
//! every step.

use std::cell::RefCell;

use embassy_futures::block_on;
use km43::{
    ClientId, CloseReason, Conn, DeviceId, DeviceSecret, Discovery, EmptyBody, Envelope, Epoch,
    ErrorBody, Handshake, Header, HelloInner, Incoming, LinkTransport, MessageType, PrintedSecret,
    ReqId, Session, SessionId, SessionKey, Tagged, Version, Wrapper,
};
use o89_core::{Facts, Millis, Sessions};

use crate::link::{Bench, DEVICE, LOG, MODEL, PRINTED, unit};
use crate::{Capabilities, Heard, SimFram, crash_at_every_step};

fn device() -> DeviceSecret {
    DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new(PRINTED))
}

fn epoch() -> Epoch {
    Epoch::FIRST
}

/// A client on one connection, speaking through the bench's comms
/// processor, which stamps the handle into every frame (P-021).
struct Client {
    handle: u16,
    req: u32,
    key: Option<SessionKey>,
}

impl Client {
    const fn on(handle: u16) -> Self {
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
    fn send(&self, bench: &mut Bench, frame: &[u8]) -> Vec<Vec<u8>> {
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
        assert!(discovery.provisioned);
        discovery.challenge
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
            | Heard::Refusal { .. } => None,
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
            | Heard::Refusal { .. } => None,
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
            | Heard::Refusal { .. } => None,
        })
}

/// A linked bench.
fn linked() -> Bench {
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up());
    bench
}

fn announce(bench: &mut Bench, handle: u16) {
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
    // Capabilities: none.
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
    // Capabilities: drop, reboot.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    // The transport goes and the release never reaches the controller: the
    // row stays, and the heartbeat says so (L-101).
    bench.run_for(Millis::from_millis(2_100));
    assert_eq!(conns(&bench), Some(1));
    let bytes = bench.comms.boot(bench.now).expect("the peer reboots");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(3_000));
    assert_eq!(conns(&bench), Some(0), "no row leaked past the reboot");
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
        link_up: true,
    };
    // A fresh unit connects two clients and each discovers.
    let path = |part: &mut SimFram, keys| -> Result<(), ()> {
        let mut sessions = Sessions::new(keys);
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
            let reply = block_on(sessions.frame(&frame[..len], now, &facts, part, &mut dst));
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
        secret: store.secret.present().copied(),
        epoch: report.epoch.epoch(),
        epoch_record: store.epoch,
        clients: store.clients,
        challenges: store.challenges,
    })
}
