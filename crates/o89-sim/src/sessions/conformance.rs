//! Controller-side conformance checks; partial items are mapped in traceability.toml.
use super::*;

#[test]
fn p_019_unknown_get_config_key_is_accepted_but_duplicate_key_is_malformed() {
    // Capabilities: inject map keys under an enrolled client's MAC (attacker B).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    // Identity/site section plus an unknown key; then section key duplicated.
    for (payload, expected) in [
        (
            &[0xa2, 1, 1, 0x18, 99, 0][..],
            MessageType::GetConfigResponse,
        ),
        (&[0xa2, 1, 1, 1, 1][..], MessageType::ErrorResponse),
    ] {
        let frame = client.sealed(MessageType::GetConfig, payload);
        let answers = client.send(&mut bench, &frame);
        let (header, body) = client.opened(answers.last().unwrap()).unwrap();
        assert_eq!(header.kind, expected);
        if expected == MessageType::ErrorResponse {
            assert_eq!(
                ErrorBody::authenticated(&body).unwrap().code,
                Incoming::Client(km43::ErrorCode::MalformedFrame)
            );
        }
    }
}

#[test]
fn p_019_unknown_command_discriminant_is_refused_and_remembers_nothing() {
    // Capabilities: invent a signed command kind (attacker B).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    // cmd_id 7, unallocated kind 0xffff, empty arguments.
    let operation = [0xa3, 1, 7, 2, 0x19, 0xff, 0xff, 3, 0xa0];
    let frame = client.signed(MessageType::Command, &operation);
    let answers = client.send(&mut bench, &frame);
    let (_, body) = client.opened(answers.last().unwrap()).unwrap();
    assert_eq!(
        ErrorBody::authenticated(&body).unwrap().code,
        Incoming::Client(km43::ErrorCode::MalformedFrame)
    );
    let dedup = bench.endpoint.sessions.keys().clients.commands();
    assert!(
        !dedup
            .present()
            .is_some_and(|commands| commands.dedup().holds(ClientId::new(1).unwrap()))
    );
}

#[test]
fn p_082_a_retried_command_under_a_new_req_id_is_answered_again() {
    // Capabilities: none; the client retries as P-082 says.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let first = client.command(7);
    assert_eq!(client.send(&mut bench, &first).len(), 1);
    let retry = client.command(7);
    let answers = client.send(&mut bench, &retry);
    let (header, _) = client.opened(answers.last().unwrap()).unwrap();
    assert_eq!(
        header.req_id,
        Envelope::decode(&retry).unwrap().header().req_id
    );
    assert_eq!(header.kind, MessageType::CommandResponse);
}

#[test]
fn p_028_five_element_envelope_cannot_execute_its_goodbye() {
    // Capabilities: inject malformed envelope.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    let mut frame = client.wrapped(MessageType::Goodbye);
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
