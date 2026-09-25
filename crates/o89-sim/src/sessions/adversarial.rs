//! Attacker A: a compromised relay, with no client key.
use super::*;

#[test]
fn p_022_reordered_sealed_requests_are_answered_once_and_replays_stay_silent() {
    // Capabilities: reorder, replay, read forwarded ciphertext.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let first = client.wrapped(MessageType::Readings);
    let second = client.wrapped(MessageType::Readings);
    for frame in [&second, &first] {
        let answers = client.send(&mut bench, frame);
        let answer = answers.last().unwrap();
        let (header, _) = client.opened(answer).expect("sealed for this session");
        assert_eq!(
            header.req_id,
            Envelope::decode(frame).unwrap().header().req_id
        );
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
    let withheld = client.wrapped(MessageType::Readings);
    let mut latest = Vec::new();
    for _ in 0..65 {
        latest = client.wrapped(MessageType::Readings);
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
    let mut frame = first.wrapped(MessageType::Goodbye);
    assert_eq!(frame[2], 1, "fixture has a one-byte handle");
    frame[2] = 2;
    let answers = second.send(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert!(bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
    assert!(bench.endpoint.sessions.is_bound(Conn::new(2).unwrap()));
}

#[test]
fn p_234_a_response_moved_to_another_request_does_not_open() {
    // Capabilities: stamp (req_id), read forwarded ciphertext.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let request = client.wrapped(MessageType::Readings);
    let answers = client.send(&mut bench, &request);
    let mut answer = answers.last().unwrap().clone();
    let req_id = u8::try_from(client.req).unwrap();
    // Error opcode uses two bytes; handle and req_id use one each here.
    assert_eq!(answer[4], req_id);
    answer[4] += 1;
    assert!(client.opened(&answer).is_none(), "the moved answer opened");
    answer[4] = req_id;
    assert!(client.opened(&answer).is_some(), "the untouched one opens");
}

#[test]
fn p_004_clock_moved_eleven_minutes_under_a_session_does_not_move_the_tick() {
    // Capabilities: offer_time, replay; enrolled client signs the clock change.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
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
    let frame = client.signed(MessageType::Time, &operation[..len]);
    let before = bench.comms.to_client(1).len();
    let bytes = bench.comms.relay(&frame, bench.now).unwrap();
    bench.feed(&bytes);
    assert_eq!(bench.now, tick);
    assert_eq!(
        bench.calendar,
        Some((o89_core::UnixMillis::new(target).unwrap(), tick))
    );
    let answers = bench.comms.to_client(1);
    assert_eq!(answers.len(), before + 1);
    let (_, body) = client.opened(answers.last().unwrap()).unwrap();
    assert_eq!(
        km43::TimeAck::decode(&body).unwrap().outcome(),
        km43::Time::Accepted
    );
    assert!(
        matches!(bench.clock_records.last(), Some(km43::ControllerRecord::TimeSet { old: Some(old), new, source: km43::TimeSource::Client }) if *old == initial && *new == target)
    );
    assert!(bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
    assert!(client.send(&mut bench, &frame).is_empty());
    bench.run_for(Millis::from_millis(14 * 60 * 1_000));
    assert!(closes(&bench).is_empty());
    bench.run_for(Millis::from_millis(61 * 1_000));
    assert_eq!(closes(&bench), vec![(1, CloseReason::SessionExpired)]);
}

#[test]
fn p_227_a_hello_built_for_another_challenge_binds_nothing() {
    // Capabilities: invent_connection, replay (Hello against another challenge).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let challenge = client.discover(&mut bench);
    let mut wrong = challenge;
    wrong[0] ^= 1;
    client.challenge = Some(wrong);
    let (_, frame) = client.hello_frame();
    let answers = client.exchange(&mut bench, &frame);
    // The admission tag covers the prologue: no slot's key vouches for it,
    // and no DH was spent on it (P-238).
    assert_eq!(code(answers.last().unwrap()), Some(12));
    assert!(!bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
}

#[test]
fn p_066_pairing_under_a_foreign_printed_secret_is_10_and_enrols_nothing() {
    // Capabilities: invent_connection, forge; attacker A lacks the printed secret.
    let mut bench = linked();
    announce(&mut bench, 1);
    bench.open_pairing();
    let mut client = Client::install(1, 9);
    let _ = client.discover(&mut bench);
    let wrong = km43::Label::new(DeviceId::new(DEVICE), km43::PrintedSecret::new([1; 32]));
    let (_, frame) = client.pair_frame(&wrong, "forged");
    let answers = client.exchange(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert!(!bench.computing(), "no DH for a label nobody holds");
    assert_eq!(enrolled(&bench.endpoint.sessions), 1);
    assert!(bench.window.is_open(bench.now));
}

#[test]
fn p_080_a_command_sealed_under_another_session_opens_nothing() {
    // Capabilities: stamp, invent_connection.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut first = Client::on(1);
    let mut second = Client::on(2);
    let _ = first.open(&mut bench);
    let _ = second.open(&mut bench);
    // The second session's request, stamped onto the first's handle.
    let mut frame = second.command(7);
    assert_eq!(frame[2], 2, "fixture has a one-byte handle");
    frame[2] = 1;
    let answers = first.send(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    let dedup = bench.endpoint.sessions.keys().clients.commands();
    assert!(
        !dedup
            .present()
            .is_some_and(|commands| commands.dedup().holds(ClientId::new(1).unwrap()))
    );
}

#[test]
fn f_091_p_066_a_foreign_label_inside_the_boot_window_is_10_and_keeps_it_open() {
    // Capabilities: invent_connection, forge; attacker A lacks the printed secret.
    let mut bench = Bench::first_enrolment(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    announce(&mut bench, 1);
    let mut client = Client::install(1, 9);
    let _ = client.discover(&mut bench);
    let wrong = km43::Label::new(DeviceId::new(DEVICE), km43::PrintedSecret::new([1; 32]));
    let (_, frame) = client.pair_frame(&wrong, "forged");
    let answers = client.exchange(&mut bench, &frame);
    assert_eq!(code(answers.last().unwrap()), Some(10));
    assert_eq!(enrolled(&bench.endpoint.sessions), 0);
    assert!(bench.window.is_open(bench.now));
}
