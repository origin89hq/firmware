//! Attacker A: a compromised relay, with no client key.
use super::*;

#[test]
fn p_022_reordered_wrapped_requests_are_answered_once_and_replays_stay_silent() {
    // Capabilities: reorder, replay, read forwarded plaintext.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let first = client.wrapped(MessageType::Readings, &key);
    let second = client.wrapped(MessageType::Readings, &key);
    for frame in [&second, &first] {
        let answers = client.send(&mut bench, frame);
        let answer = Envelope::decode(answers.last().unwrap()).unwrap();
        assert_eq!(
            answer.header().req_id,
            Envelope::decode(frame).unwrap().header().req_id
        );
        assert!(Wrapper::decode(answer).unwrap().verify(&key).is_ok());
        assert!(client.send(&mut bench, frame).is_empty());
    }
    assert!(closes(&bench).is_empty());
}

#[test]
fn p_022_p_077_withheld_request_below_the_window_and_replays_cannot_extend_a_session() {
    // Capabilities: withhold, replay.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let withheld = client.wrapped(MessageType::Readings, &key);
    let mut latest = Vec::new();
    for _ in 0..65 {
        latest = client.wrapped(MessageType::Readings, &key);
        assert_eq!(client.send(&mut bench, &latest).len(), 1);
    }
    assert!(client.send(&mut bench, &withheld).is_empty());
    bench.run_for(Millis::from_millis(14 * 60 * 1_000));
    assert!(client.send(&mut bench, &latest).is_empty());
    bench.run_for(Millis::from_millis(61 * 1_000));
    assert_eq!(closes(&bench), vec![(1, CloseReason::SessionExpired)]);
}

#[test]
fn p_072_stamping_another_live_handle_does_not_transfer_authority() {
    // Capabilities: stamp, invent_connection.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut first = Client::on(1);
    let mut second = Client::on(2);
    let _ = first.open(&mut bench);
    let _ = second.open(&mut bench);
    let key = first.key.take().unwrap();
    let mut frame = first.wrapped(MessageType::Goodbye, &key);
    assert_eq!(frame[2], 1, "fixture has a one-byte handle");
    frame[2] = 2;
    let answers = second.send(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert!(bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
    assert!(bench.endpoint.sessions.is_bound(Conn::new(2).unwrap()));
}

#[test]
fn p_047_response_moved_to_another_request_fails_its_mac() {
    // Capabilities: stamp (req_id), read forwarded plaintext.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let request = client.wrapped(MessageType::Readings, &key);
    let answers = client.send(&mut bench, &request);
    let mut answer = answers.last().unwrap().clone();
    assert!(
        Wrapper::decode(Envelope::decode(&answer).unwrap())
            .unwrap()
            .verify(&key)
            .is_ok()
    );
    // Error opcode uses two bytes; handle and req_id use one each here.
    assert_eq!(answer[4], u8::try_from(client.req).unwrap());
    answer[4] += 1;
    assert!(
        Wrapper::decode(Envelope::decode(&answer).unwrap())
            .unwrap()
            .verify(&key)
            .is_err()
    );
}

#[test]
fn p_004_clock_moved_eleven_minutes_under_a_session_does_not_move_the_tick() {
    // Capabilities: offer_time, replay; enrolled client signs the clock change.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let initial = 1_800_000_000_000;
    let bytes = bench.comms.offer_time(initial, bench.now).unwrap();
    bench.feed(&bytes);
    assert_eq!(bench.calendar.unwrap().0.as_millis(), initial);
    let tick = bench.now;
    let target = initial + 11 * 60 * 1_000;
    let mut operation = [0; 32];
    let len = km43::TimeOperation { at: target }
        .encode(&mut operation)
        .unwrap();
    let mut dst = [0; 128];
    let len = Signed::over(
        client.header(MessageType::Time),
        ClientId::new(1).unwrap(),
        Counter(1),
        &operation[..len],
        &key,
    )
    .unwrap()
    .write(&mut dst)
    .unwrap();
    let frame = &dst[..len];
    let before = bench.comms.to_client(1).len();
    let bytes = bench.comms.relay(frame, bench.now).unwrap();
    bench.feed(&bytes);
    assert_eq!(bench.now, tick);
    assert_eq!(
        bench.calendar,
        Some((o89_core::UnixMillis::new(target).unwrap(), tick))
    );
    let answers = bench.comms.to_client(1);
    assert_eq!(answers.len(), before + 1);
    let verified = Wrapper::decode(Envelope::decode(answers.last().unwrap()).unwrap())
        .unwrap()
        .verify(&key)
        .unwrap();
    assert_eq!(
        km43::TimeAck::decode(verified.payload()).unwrap().outcome(),
        km43::Time::Accepted
    );
    assert!(
        matches!(bench.clock_records.last(), Some(km43::ControllerRecord::TimeSet { old: Some(old), new, source: km43::TimeSource::Client }) if *old == initial && *new == target)
    );
    assert!(bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
    assert!(client.send(&mut bench, frame).is_empty());
    bench.run_for(Millis::from_millis(14 * 60 * 1_000));
    assert!(closes(&bench).is_empty());
    bench.run_for(Millis::from_millis(61 * 1_000));
    assert_eq!(closes(&bench), vec![(1, CloseReason::SessionExpired)]);
}

#[test]
fn p_051_hello_proof_for_another_challenge_binds_nothing() {
    // Capabilities: invent_connection, replay (Hello from another challenge).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let challenge = client.discover(&mut bench);
    let mut wrong = challenge;
    wrong[0] ^= 1;
    let frame = client.hello_frame(wrong, [1; 16]);
    let answers = client.send(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert!(!bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
}

#[test]
fn p_064_pair_proof_under_a_foreign_printed_secret_enrols_nothing() {
    // Capabilities: invent_connection, forge proof; attacker A lacks the printed secret.
    let mut bench = linked();
    announce(&mut bench, 1);
    bench.open_pairing();
    let mut client = Client::on(1);
    let challenge = client.discover(&mut bench);
    let attempt = Attempt {
        device_id: DEVICE,
        challenge,
        client_nonce: [1; 16],
    };
    let wrong = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
    let mut dst = [0; 256];
    let len = PairRequest {
        client_kind: ClientKind::Cli,
        label: "forged",
    }
    .write(
        &wrong.pair_key(),
        &attempt,
        client.header(MessageType::Pair),
        &mut dst,
    )
    .unwrap();
    let answers = client.send(&mut bench, &dst[..len]);
    let reply = PairAckClaim::decode(Envelope::decode(answers.last().unwrap()).unwrap())
        .unwrap()
        .verify(&device().pair_key(), &attempt, epoch())
        .unwrap();
    assert_eq!(reply.outcome, km43::Outcome::BadProof);
    assert!(
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .unwrap()
            .row(ClientId::new(2).unwrap())
            .is_none()
    );
    assert!(bench.window.is_open(bench.now));
}

#[test]
fn p_080_a_signed_command_under_another_session_key_spends_no_counter() {
    // Capabilities: stamp, invent_connection.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut first = Client::on(1);
    let mut second = Client::on(2);
    let _ = first.open(&mut bench);
    let _ = second.open(&mut bench);
    let key = second.key.take().unwrap();
    let frame = first.command(1, 7, &key);
    let answers = first.send(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert_eq!(
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .unwrap()
            .accepted(ClientId::new(1).unwrap()),
        Some(Counter(0))
    );
}

#[test]
fn f_091_p_066_wrong_proof_inside_boot_window_is_bad_proof_and_keeps_it_open() {
    // Capabilities: invent_connection, forge proof; attacker A lacks the printed secret.
    let mut bench = Bench::first_enrolment(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let challenge = client.discover(&mut bench);
    let attempt = Attempt {
        device_id: DEVICE,
        challenge,
        client_nonce: [1; 16],
    };
    let wrong = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
    let mut dst = [0; 256];
    let len = PairRequest {
        client_kind: ClientKind::Cli,
        label: "forged",
    }
    .write(
        &wrong.pair_key(),
        &attempt,
        client.header(MessageType::Pair),
        &mut dst,
    )
    .unwrap();
    let answers = client.send(&mut bench, &dst[..len]);
    let reply = PairAckClaim::decode(Envelope::decode(answers.last().unwrap()).unwrap())
        .unwrap()
        .verify(&device().pair_key(), &attempt, epoch())
        .unwrap();
    assert_eq!(reply.outcome, km43::Outcome::BadProof);
    assert!(
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .unwrap()
            .row(ClientId::new(1).unwrap())
            .is_none()
    );
    assert!(bench.window.is_open(bench.now));
}
