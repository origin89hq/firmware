//! Controller-side conformance checks; partial items are mapped in traceability.toml.
use super::*;

#[test]
fn p_019_unknown_get_config_key_is_accepted_but_duplicate_key_is_malformed() {
    // Capabilities: inject map keys under an enrolled client's MAC (attacker B).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    // Identity/site section plus an unknown key; then section key duplicated.
    for (payload, expected) in [
        (
            &[0xa2, 1, 1, 0x18, 99, 0][..],
            MessageType::GetConfigResponse,
        ),
        (&[0xa2, 1, 1, 1, 1][..], MessageType::ErrorResponse),
    ] {
        let header = client.header(MessageType::GetConfig);
        let mut dst = [0; 128];
        let len = Tagged::over(header, payload, &key)
            .unwrap()
            .write(&mut dst)
            .unwrap();
        let answers = client.send(&mut bench, &dst[..len]);
        let envelope = Envelope::decode(answers.last().unwrap()).unwrap();
        assert_eq!(envelope.header().kind, expected);
        let verified = Wrapper::decode(envelope).unwrap().verify(&key).unwrap();
        if expected == MessageType::ErrorResponse {
            assert_eq!(
                ErrorBody::authenticated(verified.payload()).unwrap().code,
                Incoming::Client(km43::ErrorCode::MalformedFrame)
            );
        }
    }
}

#[test]
fn p_019_unknown_command_discriminant_is_refused_without_spending_a_counter() {
    // Capabilities: invent a signed command kind (attacker B).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let header = client.header(MessageType::Command);
    // cmd_id 7, unallocated kind 0xffff, empty arguments.
    let operation = [0xa3, 1, 7, 2, 0x19, 0xff, 0xff, 3, 0xa0];
    let mut dst = [0; 128];
    let len = Signed::over(
        header,
        ClientId::new(1).unwrap(),
        Counter(1),
        &operation,
        &key,
    )
    .unwrap()
    .write(&mut dst)
    .unwrap();
    let answers = client.send(&mut bench, &dst[..len]);
    let verified = Wrapper::decode(Envelope::decode(answers.last().unwrap()).unwrap())
        .unwrap()
        .verify(&key)
        .unwrap();
    assert_eq!(
        ErrorBody::authenticated(verified.payload()).unwrap().code,
        Incoming::Client(km43::ErrorCode::MalformedFrame)
    );
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
fn p_080_fresh_request_id_does_not_make_an_old_signed_counter_fresh() {
    // Capabilities: replay; attacker B can re-sign under a fresh req_id.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let first = client.command(1, 7, &key);
    assert_eq!(client.send(&mut bench, &first).len(), 1);
    let retry = client.command(1, 7, &key);
    let answers = client.send(&mut bench, &retry);
    let envelope = Envelope::decode(answers.last().unwrap()).unwrap();
    assert_eq!(
        envelope.header().req_id,
        Envelope::decode(&retry).unwrap().header().req_id
    );
    assert_eq!(envelope.header().kind, MessageType::ErrorResponse);
    let verified = Wrapper::decode(envelope).unwrap().verify(&key).unwrap();
    assert_eq!(
        ErrorBody::authenticated(verified.payload()).unwrap().code,
        Incoming::Client(km43::ErrorCode::CounterNotFresh)
    );
    assert_eq!(
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .unwrap()
            .accepted(ClientId::new(1).unwrap()),
        Some(Counter(1))
    );
    // P-080 checks freshness before it decodes even malformed operation bytes.
    // The table has a second guard; this distinguishes the admission guard.
    let mut dst = [0; 128];
    let len = Signed::over(
        client.header(MessageType::Command),
        ClientId::new(1).unwrap(),
        Counter(1),
        &[0xa0],
        &key,
    )
    .unwrap()
    .write(&mut dst)
    .unwrap();
    let answers = client.send(&mut bench, &dst[..len]);
    let verified = Wrapper::decode(Envelope::decode(answers.last().unwrap()).unwrap())
        .unwrap()
        .verify(&key)
        .unwrap();
    assert_eq!(
        ErrorBody::authenticated(verified.payload()).unwrap().code,
        Incoming::Client(km43::ErrorCode::CounterNotFresh)
    );
}

#[test]
fn p_028_five_element_envelope_cannot_execute_its_goodbye() {
    // Capabilities: inject malformed envelope.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let key = client.key.take().unwrap();
    let mut frame = client.wrapped(MessageType::Goodbye, &key);
    assert_eq!(frame[0], 0x84);
    frame[0] = 0x85;
    frame.push(0);
    // Refused before any element is read, so at 0, 0 (P-025): it names no
    // connection and stays on the link, as a refusal of the comms
    // processor's frame. An honest one answers its client itself.
    let before = bench.comms.heard.len();
    assert!(client.send(&mut bench, &frame).is_empty());
    let refusals: Vec<_> = bench
        .comms
        .heard
        .iter()
        .skip(before)
        .filter_map(|heard| match heard {
            Heard::Refusal {
                code,
                session,
                req_id,
            } => Some((*code, *session, *req_id)),
            Heard::Other { .. }
            | Heard::ToClient { .. }
            | Heard::Close { .. }
            | Heard::LinkUp { .. }
            | Heard::LinkUpAck { .. }
            | Heard::Heartbeat { .. }
            | Heard::HeartbeatAck { .. }
            | Heard::PairingWindow { .. }
            | Heard::NetConfig { .. } => None,
        })
        .collect();
    assert_eq!(refusals, [(1, 0, ReqId(0))]);
    assert!(bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
    assert!(bench.endpoint.link.is_up());
    // The same goodbye in four elements still ends the session.
    frame.pop();
    frame[0] = 0x84;
    let answers = client.send(&mut bench, &frame);
    let envelope = Envelope::decode(answers.last().unwrap()).unwrap();
    assert_eq!(envelope.header().kind, MessageType::GoodbyeResponse);
    assert!(!bench.endpoint.sessions.is_bound(Conn::new(1).unwrap()));
}
