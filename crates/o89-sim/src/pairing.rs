//! The pairing window reported over the link (L-193 to L-195), driven by
//! the hostile comms processor: the controller's reports as its link
//! sends and retries them, the comms processor's own link acknowledging
//! and keeping what it learned, and a client on the far side whose `Pair`
//! closes the window it came through.

use std::num::NonZeroU64;

use km43::{
    Envelope, LinkHeader, LinkMessageType, MAX_FRAME, MessageType, Outcome, PairingWindowNotice,
    ReqId, SessionId,
};
use o89_core::{DropReason, Millis, Note, PAIRING_WINDOW};

use crate::link::Bench;
use crate::sessions::{Client, announce};
use crate::{Answers, Capabilities, Heard};

/// A bench linked for a second, its first report acknowledged.
fn linked(caps: Capabilities) -> Bench {
    let mut bench = Bench::new(caps);
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up());
    bench
}

/// How many `PairingWindowAck`s the comms processor has put on the wire.
fn acks(bench: &Bench) -> usize {
    bench
        .comms
        .sent
        .iter()
        .filter(|kind| **kind == LinkMessageType::PairingWindowAck)
        .count()
}

/// The reports heard, by revision and remaining time.
fn reports(bench: &Bench) -> Vec<(u64, u32)> {
    bench
        .comms
        .pairing_reports()
        .into_iter()
        .map(|(_, revision, remaining)| (revision, remaining))
        .collect()
}

#[test]
fn l_195_linking_reports_the_closed_window_under_revision_one_and_its_ack_consumes_it() {
    // Capabilities: none.
    let mut bench = linked(Capabilities::default());
    assert_eq!(reports(&bench), vec![(1, 0)], "the closed state, from 1");
    assert_eq!(acks(&bench), 1);
    assert_eq!(bench.comms.pairing_window(bench.now), None);
    // Acknowledged: never sent again, and nothing more owed.
    bench.run_for(Millis::from_millis(3_000));
    assert_eq!(reports(&bench), vec![(1, 0)]);
    assert!(
        !bench
            .notes()
            .contains(&Note::RequestFailed(LinkMessageType::PairingWindow))
    );
    assert!(
        !bench
            .notes()
            .contains(&Note::UnexpectedAck(LinkMessageType::PairingWindowAck))
    );
}

#[test]
fn l_193_every_report_and_acknowledgement_on_the_wire_reads_back_within_its_bounds() {
    // Capabilities: none.
    let mut bench = linked(Capabilities::default());
    bench.open_pairing();
    bench.run_for(Millis::from_millis(60_000));
    bench.open_pairing();
    bench.run_for(Millis::from_millis(125_000));
    let heard = bench.comms.pairing_reports();
    assert_eq!(heard.len(), 4, "closed, open, reopened, expired: {heard:?}");
    let mut last = 0;
    for (_, revision, remaining) in &heard {
        assert!(*revision > last, "{heard:?}");
        last = *revision;
        assert!(*remaining <= 120_000, "{heard:?}");
    }
    // Every acknowledgement read back at the controller and consumed its
    // report: none unexpected, none malformed, none given up.
    assert_eq!(acks(&bench), heard.len());
    let ack = LinkMessageType::PairingWindowAck;
    for note in [
        Note::UnexpectedAck(ack),
        Note::Malformed(ack),
        Note::RequestFailed(LinkMessageType::PairingWindow),
    ] {
        assert!(!bench.notes().contains(&note), "{note:?}");
    }
}

#[test]
fn l_195_the_opening_and_its_expiry_are_each_reported_and_the_comms_processor_keeps_the_window() {
    // Capabilities: none.
    let mut bench = linked(Capabilities::default());
    bench.open_pairing();
    let opened = bench.now;
    bench.run_for(Millis::from_millis(20));
    let heard = reports(&bench);
    let (revision, remaining) = *heard.last().expect("the opening");
    assert_eq!(revision, 2);
    assert!(
        (119_980..=120_000).contains(&remaining),
        "{remaining} ms left when first sent"
    );
    let left = bench
        .comms
        .pairing_window(bench.now)
        .expect("open at the comms processor")
        .as_millis();
    assert!((119_900..=120_000).contains(&left), "{left} ms left there");
    // At the window's end the controller reports the closure, and the
    // comms processor's own deadline has run out with it.
    let until = opened.after(PAIRING_WINDOW).expect("fits");
    bench.run_for(until.since(bench.now).expect("ahead"));
    bench.run_for(Millis::from_millis(20));
    assert_eq!(
        reports(&bench).last(),
        Some(&(3, 0)),
        "{:?}",
        reports(&bench)
    );
    assert_eq!(
        reports(&bench).len(),
        3,
        "nothing between opening and expiry"
    );
    assert_eq!(bench.comms.pairing_window(bench.now), None);
}

#[test]
fn l_195_an_enrolment_answers_pair_before_the_closed_report() {
    // Capabilities: none.
    let mut bench = linked(Capabilities::default());
    announce(&mut bench, 3);
    bench.open_pairing();
    bench.run_for(Millis::from_millis(20));
    assert!(bench.comms.pairing_window(bench.now).is_some());
    let mut client = Client::on(3);
    let answer = client.pair(&mut bench, "laptop");
    assert!(matches!(answer.outcome, Outcome::Enrolled(_)), "{answer:?}");
    bench.run_for(Millis::from_millis(20));
    // On the wire, in order: the `Pair 0x8B`, then the closed report.
    let pair_answer = bench
        .comms
        .heard
        .iter()
        .position(|heard| {
            if let Heard::ToClient { session: 3, frame } = heard {
                Envelope::decode(frame)
                    .is_ok_and(|envelope| envelope.header().kind == MessageType::PairResponse)
            } else {
                false
            }
        })
        .expect("the Pair answer reached the client");
    let closed = bench
        .comms
        .heard
        .iter()
        .position(|heard| {
            matches!(
                heard,
                Heard::PairingWindow {
                    revision: 3,
                    remaining_ms: 0,
                    ..
                }
            )
        })
        .expect("the closed report");
    assert!(pair_answer < closed, "{pair_answer} then {closed}");
    assert_eq!(bench.comms.pairing_window(bench.now), None);
    // One press, one enrolment: a second `Pair` meets a closed window.
    let again = client.pair(&mut bench, "tablet");
    assert_eq!(again.outcome, Outcome::WindowClosed);
    assert_eq!(reports(&bench).len(), 3, "no report for a refused Pair");
}

#[test]
fn l_195_a_factory_reset_at_the_panel_reports_the_window_closed() {
    // Capabilities: none.
    let mut bench = linked(Capabilities::default());
    bench.open_pairing();
    bench.run_for(Millis::from_millis(5_000));
    assert!(bench.comms.pairing_window(bench.now).is_some());
    bench.reset_at_the_panel();
    bench.run_for(Millis::from_millis(20));
    assert_eq!(reports(&bench).last(), Some(&(3, 0)));
    assert_eq!(bench.comms.pairing_window(bench.now), None);
}

#[test]
fn l_195_retries_keep_the_revision_and_body_and_never_restart_the_comms_deadline() {
    // Capabilities: answers nothing for a second and a half, then
    // everything; its link still hears what arrives.
    let mut bench = linked(Capabilities::default());
    bench.comms.capabilities().answers = Answers::Nothing;
    bench.open_pairing();
    let first = bench.now;
    bench.run_for(Millis::from_millis(1_490));
    let heard = bench.comms.pairing_reports();
    let sent: Vec<_> = heard.iter().skip(1).copied().collect();
    assert_eq!(sent.len(), 3, "three attempts: {sent:?}");
    let (req_id, revision, remaining) = sent[0];
    assert_eq!(revision, 2);
    for attempt in &sent {
        assert_eq!(
            *attempt,
            (req_id, revision, remaining),
            "the same request, revision and body"
        );
    }
    // The comms processor kept the first receipt's deadline: the retries
    // were duplicates, acknowledged into the silence, and changed nothing.
    let left = bench
        .comms
        .pairing_window(bench.now)
        .expect("open")
        .as_millis();
    let elapsed = bench.now.since(first).expect("after").as_millis();
    assert!(
        left <= 120_000 - elapsed + 20,
        "{left} ms left after {elapsed} ms: a retry restarted it"
    );
    // Given up after its third attempt, and failed to nothing but the note.
    bench.comms.capabilities().answers = Answers::Everything;
    bench.run_for(Millis::from_millis(100));
    assert!(
        bench
            .notes()
            .contains(&Note::RequestFailed(LinkMessageType::PairingWindow))
    );
    assert_eq!(bench.comms.pairing_reports().len(), 4, "not sent again");
}

#[test]
fn l_195_a_closure_supersedes_the_open_reports_retries() {
    // Capabilities: answers nothing for the second the reports cross.
    let mut bench = linked(Capabilities::default());
    bench.comms.capabilities().answers = Answers::Nothing;
    bench.open_pairing();
    bench.run_for(Millis::from_millis(100));
    bench.reset_at_the_panel();
    bench.run_for(Millis::from_millis(1_400));
    let heard = reports(&bench);
    let open: Vec<_> = heard
        .iter()
        .filter(|(revision, _)| *revision == 2)
        .collect();
    let closed: Vec<_> = heard
        .iter()
        .filter(|(revision, _)| *revision == 3)
        .collect();
    assert_eq!(open.len(), 1, "the open report never retried: {heard:?}");
    assert!(closed.len() >= 2, "the closed one retried: {heard:?}");
    assert!(closed.iter().all(|(_, remaining)| *remaining == 0));
    assert_eq!(bench.comms.pairing_window(bench.now), None);
}

#[test]
fn l_195_every_link_up_resynchronises_under_a_fresh_revision_with_what_is_left() {
    // Capabilities: none; the peer reboots.
    let mut bench = linked(Capabilities::default());
    bench.open_pairing();
    bench.run_for(Millis::from_millis(10_000));
    let bytes = bench.comms.boot(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(100));
    assert!(
        bench
            .drops()
            .iter()
            .any(|(_, why)| *why == DropReason::CommsRebooted)
    );
    assert!(bench.endpoint.link.is_up());
    let heard = reports(&bench);
    let (revision, remaining) = *heard.last().expect("a resynchronisation");
    assert_eq!(revision, 3, "{heard:?}");
    assert!(
        (109_800..=110_000).contains(&remaining),
        "{remaining} ms: the deadline, not the original duration"
    );
    // The rebooted comms processor learned it afresh.
    assert!(bench.comms.pairing_window(bench.now).is_some());
}

/// Client frames shaped like the report: the `PairingWindow` envelope
/// stamped with the client's handle, as a hostile client would send it, and
/// the same body nested under a client opcode.
fn shaped_like_a_report(session: u8) -> [Vec<u8>; 2] {
    let notice =
        PairingWindowNotice::new(NonZeroU64::new(99).expect("non-zero"), 120_000).expect("fits");
    let mut dst = [0u8; MAX_FRAME];
    let len = notice
        .write(
            LinkHeader {
                kind: LinkMessageType::PairingWindow,
                session: SessionId::from(u16::from(session)),
                req_id: ReqId(7),
            },
            &mut dst,
        )
        .expect("fits");
    let link = dst[..len].to_vec();
    // The link header is the array head, the one-byte opcode after its
    // prefix, the session and the request; a client's opcode is smaller
    // than 24 and takes no prefix.
    assert_eq!(&link[..5], &[0x84, 0x18, 0x69, session, 7]);
    let mut nested = vec![0x84, MessageType::Discover as u8, session, 7];
    nested.extend_from_slice(&link[5..]);
    [link, nested]
}

#[test]
fn l_194_a_relayed_client_frame_shaped_like_the_report_changes_nothing() {
    // Capabilities: relays whatever a client sends.
    let mut bench = linked(Capabilities::default());
    announce(&mut bench, 3);
    let before = reports(&bench);
    for frame in shaped_like_a_report(3) {
        let bytes = bench.comms.relay(&frame, bench.now).expect("relays");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(100));
        assert_eq!(bench.comms.pairing_window(bench.now), None, "{frame:x?}");
        assert_eq!(reports(&bench), before, "{frame:x?}");
        assert!(!bench.window.is_open(bench.now), "{frame:x?}");
    }
    // The link-local opcode on a client's session was refused, not acted on.
    assert!(bench.comms.heard.iter().any(|heard| matches!(
        heard,
        Heard::Refusal {
            session: 0,
            req_id: ReqId(0),
            ..
        }
    )));
}

#[test]
fn f_091_p_066_l_195_boot_window_is_reported_after_link_up_and_expires() {
    // HostileComms capabilities: none.
    let mut bench = Bench::first_enrolment(Capabilities::default());
    assert!(bench.window.is_open(bench.now));
    assert!(reports(&bench).is_empty());
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.endpoint.link.is_up());
    let heard = reports(&bench);
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].0, 1);
    assert!((119_000..120_000).contains(&heard[0].1));
    assert!(bench.comms.pairing_window(bench.now).is_some());
    bench.run_for(Millis::from_millis(119_020));
    assert!(!bench.window.is_open(bench.now));
    assert_eq!(reports(&bench).last(), Some(&(2, 0)));
    assert_eq!(bench.comms.pairing_window(bench.now), None);
}

#[test]
fn f_091_p_066_enrolment_closes_boot_window_and_next_boot_stays_closed() {
    // HostileComms capabilities: invent a connection, relay an honest Pair.
    let mut bench = Bench::first_enrolment(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    announce(&mut bench, 3);
    let answer = Client::on(3).pair(&mut bench, "first phone");
    assert!(matches!(answer.outcome, Outcome::Enrolled(_)));
    assert!(!bench.window.is_open(bench.now));
    bench.run_for(Millis::from_millis(20));
    assert_eq!(bench.comms.pairing_window(bench.now), None);
    bench.boot_clients(o89_core::Revision::A);
    assert_eq!(
        bench
            .endpoint
            .sessions
            .keys()
            .clients
            .present()
            .unwrap()
            .enrolled(),
        1
    );
    assert!(!bench.window.is_open(bench.now));
}

#[test]
fn f_091_p_066_factory_reset_new_epoch_reopens_on_next_boot() {
    // HostileComms capabilities: none; factory reset is local to the controller.
    let mut bench = Bench::new(Capabilities::default());
    let (mut store, report) =
        embassy_futures::block_on(o89_core::Store::boot(&mut bench.fram, None)).unwrap();
    let previous = report.epoch.epoch().unwrap();
    embassy_futures::block_on(o89_core::reset_clients(
        &mut store.epoch,
        &mut store.clients,
        &mut bench.fram,
    ))
    .unwrap();
    bench.boot_clients(o89_core::Revision::A);
    let table = bench.endpoint.sessions.keys().clients.present().unwrap();
    assert!(table.epoch() > previous);
    assert_eq!(table.enrolled(), 0);
    assert!(bench.window.is_open(bench.now));
}
