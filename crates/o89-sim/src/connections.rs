//! The comms processor's connection table against the controller's rows:
//! the real table from `o89-comms-core`, inside the hostile peer, announcing
//! and releasing through its own link to the controller's (#90).

use km43::{CloseReason, DisconnectReason};
use o89_comms_core::{Closed, ROWS, Refused, Status};
use o89_core::Millis;

use crate::link::Bench;
use crate::{Capabilities, Heard, Releases};

fn linked() -> Bench {
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up());
    assert!(bench.comms.is_linked());
    bench
}

/// The last count the controller's heartbeats carried.
fn controller_conns(bench: &Bench) -> Option<u8> {
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

/// A client connected through the table and accepted by the controller.
fn connect(bench: &mut Bench) -> km43::Conn {
    let conn = bench.comms.connect().expect("a row");
    bench.run_for(Millis::from_millis(50));
    assert_eq!(bench.comms.status(conn), Some(Status::Open));
    conn
}

#[test]
fn l_060_l_101_eight_clients_fill_both_tables_and_a_ninth_is_refused_before_the_link() {
    // Capabilities: none.
    let mut bench = linked();
    let conns: Vec<_> = (0..ROWS).map(|_| connect(&mut bench)).collect();
    let handles: Vec<u16> = conns.iter().map(|conn| conn.get()).collect();
    assert_eq!(handles, (1..=8).collect::<Vec<u16>>());
    assert_eq!(usize::from(bench.endpoint.sessions.allocated()), ROWS);
    assert_eq!(bench.comms.connect(), Err(Refused::TableFull));
    // Past three heartbeats: counts that disagreed would have been resynced.
    bench.run_for(Millis::from_millis(7_000));
    assert_eq!(controller_conns(&bench), Some(8));
    assert_eq!(bench.comms.table_conns(), 8);
    assert!(closes(&bench).is_empty(), "the counts agree");
}

#[test]
fn l_080_a_handle_released_and_answered_is_the_controllers_to_forget() {
    // Capabilities: none.
    let mut bench = linked();
    let first = connect(&mut bench);
    bench
        .comms
        .transport_gone(first, DisconnectReason::ClosedByClient);
    bench.run_for(Millis::from_millis(50));
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
    let second = connect(&mut bench);
    assert_ne!(second, first, "the counter moves on");
    assert_eq!(bench.endpoint.sessions.allocated(), 1);
}

#[test]
fn l_061_a_connection_the_controller_refuses_for_a_full_table_is_dropped() {
    // Capabilities: invent connections.
    let mut bench = linked();
    // Eight rows the controller holds that the table never gave out.
    for handle in 100..108 {
        let bytes = bench
            .comms
            .announce_connection(handle, bench.now)
            .expect("builds");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(20));
    }
    assert_eq!(bench.endpoint.sessions.allocated(), 8);
    let refused = bench.comms.connect().expect("the table has room");
    bench.run_for(Millis::from_millis(50));
    assert_eq!(
        bench.comms.status(refused),
        Some(Status::Close(Closed::TableFull))
    );
    assert_eq!(bench.comms.table_conns(), 0, "not counted");
    bench
        .comms
        .transport_gone(refused, DisconnectReason::ClosedByComms);
    assert_eq!(bench.comms.status(refused), None);
    bench.run_for(Millis::from_millis(6_500));
    assert!(
        closes(&bench).is_empty(),
        "the counts agree: eight and eight"
    );
}

#[test]
fn l_102_after_a_resync_the_tables_agree_and_the_reconnected_clients_are_announced_again() {
    // Capabilities: lose a release.
    let mut bench = linked();
    let lost = connect(&mut bench);
    let kept = connect(&mut bench);
    assert_eq!(bench.endpoint.sessions.allocated(), 2);
    bench.comms.capabilities().releases = Releases::Lost;
    bench
        .comms
        .transport_gone(lost, DisconnectReason::ClosedByClient);
    bench.run_for(Millis::from_millis(100));
    assert_eq!(
        bench.endpoint.sessions.allocated(),
        2,
        "the controller never heard"
    );
    assert_eq!(bench.comms.table_conns(), 1);
    bench.run_for(Millis::from_millis(7_000));
    assert_eq!(closes(&bench), vec![(0, CloseReason::Resync)]);
    // The close answered with what the table closed: the one transport
    // still open, now told to close; and both sides count none.
    assert_eq!(
        bench.comms.status(kept),
        Some(Status::Close(Closed::ByController(CloseReason::Resync)))
    );
    assert_eq!(bench.endpoint.sessions.allocated(), 0);
    assert_eq!(bench.comms.table_conns(), 0);
    bench
        .comms
        .transport_gone(kept, DisconnectReason::ClosedByComms);
    bench.comms.capabilities().releases = Releases::Sent;
    // The client that was connected reconnects: announced afresh, and the
    // counts agree from there on.
    let again = connect(&mut bench);
    assert!(again != lost && again != kept);
    bench.run_for(Millis::from_millis(10_000));
    assert_eq!(bench.endpoint.sessions.allocated(), 1);
    assert_eq!(controller_conns(&bench), Some(1));
    assert_eq!(bench.comms.table_conns(), 1);
    assert_eq!(closes(&bench), vec![(0, CloseReason::Resync)], "once");
}

#[test]
fn l_120_the_link_falling_closes_the_tables_transports() {
    // Capabilities: none, then the controller goes quiet.
    let mut bench = linked();
    let conn = connect(&mut bench);
    bench.comms.capabilities().answers = crate::Answers::TalksOnly;
    bench.run_for(Millis::from_millis(7_000));
    assert_eq!(
        bench.comms.status(conn),
        Some(Status::Close(Closed::LinkLost))
    );
    assert_eq!(bench.comms.connect(), Err(Refused::NotLinked));
}
