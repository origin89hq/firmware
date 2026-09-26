//! The reading plane over the link: a client reading the site's inventory,
//! readings and concerns, subscribing to its events and paging its log,
//! through the hostile comms processor's honest relay and a ring on a
//! simulated NOR. The site is built by hand here, as #196's configuration
//! will build it; no frame or reading comes from a bench.

use km43::{
    ConcernsHeader, Condition, EventKind, Id, InventoryHeader, Part, Provenance, ReadingsHeader,
    Severity, Subject, TopologyChangeReason, Transport,
};
use o89_core::{
    ConcernReport, Descriptor, DeviceAddress, Limits, Observation, SiteBus, SiteDevice, SiteSignal,
};

use super::*;
use crate::link::SimSite;
use crate::{Lent, SimNor};
use o89_core::SiteCell;

fn id(n: u16) -> Id {
    Id::new(n).expect("non-zero")
}

/// One RS-485 bus, a charger at address 1 on it, and `signals` DC voltages
/// the charger publishes, told apart by measurement point.
fn charger(signals: u16) -> Vec<Descriptor> {
    let mut batch = vec![
        Descriptor::Bus(SiteBus {
            bus: 1,
            transport: Transport::Rs485,
            rate: Some(115_200),
        }),
        Descriptor::Device(SiteDevice {
            dev: 1,
            bus: 1,
            addr: DeviceAddress::new(&[1]),
            product: km43::Product(0x0101),
            dialect: km43::Dialect(0x0001),
            role: km43::DeviceRole(0x0001),
            parent: None,
        }),
    ];
    batch.extend((1..=signals).map(|n| {
        Descriptor::Signal(SiteSignal {
            sig: id(n),
            dev: 1,
            cmp: None,
            kind: km43::MetricKind::DC_VOLTAGE,
            vtype: km43::Vtype::Gauge,
            domain: km43::SignalDomain::Live,
            point: Some(km43::MeasurementPoint(n)),
            dir: None,
            esp: None,
            limits: Limits::new(Millis::from_millis(60_000), None).expect("a limit"),
        })
    }));
    batch
}

/// A linked bench whose recorder has a ring and whose site holds `signals`
/// signals, with one plane tick run so the boot's `0x0901` is logged.
fn site_bench(signals: u16) -> Bench {
    let mut bench = linked();
    bench.open_log();
    bench
        .site
        .with(|site, _| site.apply(TopologyChangeReason::Boot, &charger(signals)))
        .expect("a valid site");
    bench.run_for(Millis::from_millis(1_100));
    bench
}

fn write(bench: &SimSite, sig: u16, value: i32) {
    bench
        .with(|site, now| {
            site.write(
                id(sig),
                now,
                Observation::value(value, Provenance::Measured).expect("a value"),
            )
        })
        .expect("registered");
}

/// A client with a session on handle 1.
fn session(bench: &mut Bench) -> Client {
    announce(bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(bench);
    client
}

/// Send a sealed read and open its answer: the kind and the inner body.
fn ask(
    client: &mut Client,
    bench: &mut Bench,
    kind: MessageType,
    body: &[u8],
) -> (MessageType, Vec<u8>) {
    let frame = client.sealed(kind, body);
    let answers = client.send(bench, &frame);
    // Events a subscription is owed can follow the answer on the wire.
    let answer = answers
        .iter()
        .rev()
        .find(|frame| {
            Envelope::decode(frame)
                .is_ok_and(|envelope| envelope.header().kind != MessageType::EventResponse)
        })
        .expect("answered");
    let (header, inner) = client.opened(answer).expect("opens under the session");
    (header.kind, inner)
}

/// Every event this client has been sent, opened: its `seq` and kind.
fn events(client: &mut Client, bench: &Bench) -> Vec<(u64, EventKind)> {
    bench
        .comms
        .to_client(1)
        .iter()
        .filter(|frame| {
            Envelope::decode(frame)
                .is_ok_and(|envelope| envelope.header().kind == MessageType::EventResponse)
        })
        .map(|frame| {
            let (header, inner) = client
                .opened(frame)
                .expect("an event opens under the session");
            assert_eq!(header.req_id, ReqId(0), "an event answers nothing");
            let event = km43::Event::decode(&inner).expect("an event");
            (event.seq.0, event.kind)
        })
        .collect()
}

#[test]
fn p_077_subscription_is_active_before_testing_outbound_only_expiry() {
    // Capabilities: withhold client requests after subscribing.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::on(1);
    let _ = client.open(&mut bench);
    // `Subscribe` with `from_seq = 0`: live only, no replay.
    let frame = client.sealed(MessageType::Subscribe, &[0xa1, 1, 0]);
    let answers = client.send(&mut bench, &frame);
    assert_eq!(
        Envelope::decode(answers.last().unwrap())
            .unwrap()
            .header()
            .kind,
        MessageType::SubscribeResponse
    );
}

#[test]
fn p_149_hello_reports_the_revision_and_digest_an_inventory_walk_ends_on() {
    // Capabilities: none; the honest relay.
    let mut bench = site_bench(3);
    let mut client = session(&mut bench);
    let (_, topology) = client.reported.expect("a Hello");
    assert_eq!(topology.rev, 1);
    assert_eq!(usize::from(topology.signals), o89_core::SITE_SIGNALS);
    let (kind, body) = ask(
        &mut client,
        &mut bench,
        MessageType::Inventory,
        &[0xa3, 1, 0, 2, 4, 3, 0],
    );
    assert_eq!(kind, MessageType::InventoryResponse);
    let header = InventoryHeader::decode(&body).expect("a page");
    assert_eq!((header.rev, header.rows, header.next), (1, 3, 0));
    assert_eq!(header.digest, Some(topology.digest));
}

#[test]
fn p_199_readings_arrive_with_their_quality_and_the_log_position_they_reflect() {
    // Capabilities: none; the honest relay.
    let mut bench = site_bench(2);
    write(&bench.site, 1, 25_600);
    let mut client = session(&mut bench);
    let (kind, body) = ask(
        &mut client,
        &mut bench,
        MessageType::Readings,
        &[0xa2, 1, 0, 3, 0],
    );
    assert_eq!(kind, MessageType::ReadingsResponse);
    let header = ReadingsHeader::decode(&body).expect("a page");
    assert_eq!(header.seq, bench.log_span().newest.0);
    assert_eq!((header.samples, header.total, header.next), (2, 2, 0));
    let mut seen = Vec::new();
    ReadingsHeader::for_each_sample(&body, |sample| {
        seen.push((sample.sig.get(), sample.value(), sample.q.validity_of()));
    })
    .expect("samples");
    assert_eq!(
        seen,
        [
            (1, Some(25_600), km43::Validity::Ok),
            (2, None, km43::Validity::Initialising)
        ]
    );
}

#[test]
fn p_094_p_104_a_live_subscriber_hears_each_change_once_and_nothing_from_before() {
    // Capabilities: none; the honest relay.
    let mut bench = site_bench(2);
    let mut client = session(&mut bench);
    let before = bench.log_span().newest.0;
    assert!(before >= 1, "the boot's topology record is logged");
    let (kind, body) = ask(
        &mut client,
        &mut bench,
        MessageType::Subscribe,
        &[0xa1, 1, 0],
    );
    assert_eq!(kind, MessageType::SubscribeResponse);
    let ack = km43::SubscribeAck::decode(&body).expect("an ack");
    assert_eq!(ack.accepted_from_seq().0, before + 1);
    write(&bench.site, 1, 12_000);
    bench
        .site
        .with(|site, now| {
            site.observe(
                ConcernReport {
                    subject: Subject::Part(Part::device(id(1))),
                    cond: Condition(0x0101),
                    sev: Severity::Fault,
                    code: None,
                },
                now,
            )
        })
        .expect("admitted");
    bench.run_for(Millis::from_millis(2_500));
    let heard = events(&mut client, &bench);
    assert_eq!(
        heard,
        [
            (before + 1, EventKind::SIGNAL_VALIDITY_CHANGED),
            (before + 2, EventKind::CONCERN_RAISED)
        ]
    );
    // The concern is in the table a client reads, opened by that record.
    let (_, body) = ask(
        &mut client,
        &mut bench,
        MessageType::Concerns,
        &[0xa2, 1, 0, 2, 0],
    );
    let header = ConcernsHeader::decode(&body).expect("a page");
    assert_eq!((header.total, header.seq), (1, before + 2));
}

#[test]
fn p_094_a_replay_runs_into_live_delivery_with_no_gap_and_no_repeat() {
    // Capabilities: none; the honest relay.
    let mut bench = site_bench(12);
    // Twelve changes over three ticks: more than one delivery read's worth.
    for (second, sigs) in [(0, 1..=4), (1, 5..=8), (2, 9..=12)] {
        for sig in sigs {
            write(&bench.site, sig, i32::from(sig) + second);
        }
        bench.run_for(Millis::from_millis(1_000));
    }
    let mut client = session(&mut bench);
    let (_, body) = ask(
        &mut client,
        &mut bench,
        MessageType::Subscribe,
        &[0xa1, 1, 1],
    );
    let ack = km43::SubscribeAck::decode(&body).expect("an ack");
    assert_eq!((ack.accepted_from_seq().0, ack.gap()), (1, false));
    // A change while the replay is still owed.
    bench
        .site
        .with(|site, _| site.presence(1, km43::Presence::Online))
        .expect("a device");
    bench.run_for(Millis::from_millis(3_000));
    let heard = events(&mut client, &bench);
    let seqs: Vec<u64> = heard.iter().map(|(seq, _)| *seq).collect();
    let newest = bench.log_span().newest.0;
    assert_eq!(
        seqs,
        (1..=newest).collect::<Vec<_>>(),
        "every record once, in order"
    );
    assert_eq!(
        heard.last().map(|(_, kind)| *kind),
        Some(EventKind::DEVICE_PRESENCE_CHANGED)
    );
}

#[test]
fn p_099_read_log_pages_the_ring_from_the_oldest_and_says_when_it_caught_up() {
    // Capabilities: none; the honest relay.
    let mut bench = site_bench(4);
    for sig in 1..=4 {
        write(&bench.site, sig, 1);
        bench.run_for(Millis::from_millis(1_000));
    }
    let newest = bench.log_span().newest.0;
    assert!(newest >= 3);
    let mut client = session(&mut bench);
    // From 0, which is behind the ring: answered from the oldest, two a page.
    let frame = client.sealed(MessageType::ReadLog, &[0xa2, 1, 0, 2, 2]);
    let _ = client.send(&mut bench, &frame);
    bench.run_for(Millis::from_millis(300));
    let answers = bench.comms.to_client(1);
    let page_frame = answers
        .iter()
        .rev()
        .find(|frame| {
            Envelope::decode(frame)
                .is_ok_and(|envelope| envelope.header().kind == MessageType::ReadLogResponse)
        })
        .expect("the page came back");
    let (_, inner) = client.opened(page_frame).expect("opens");
    let page = km43::LogPage::decode(&inner).expect("a page");
    let seqs: Vec<u64> = page.entries().iter().map(|entry| entry.seq.0).collect();
    assert_eq!(seqs, [1, 2]);
    assert_eq!(
        (page.next_seq().0, page.oldest_seq.0, page.complete),
        (3, 1, false)
    );
}

#[test]
fn p_182_a_record_the_ring_refused_is_logged_once_the_ring_takes_it() {
    // Capabilities: none. The NOR loses power before the first append.
    let mut part = SimNor::<{ crate::link::LOG_BLOCK }>::fresh(8);
    let site = SimSite::empty();
    site.with(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    let mut scratch = [0u8; o89_core::SCRATCH];
    {
        part.cut_after(0);
        let mut ring =
            block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
        let turn = block_on(o89_core::record_owed(&site, &mut ring, &mut scratch, None));
        assert_eq!((turn.landed, turn.refused), (0, true));
    }
    part.reboot();
    let mut ring =
        block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
    let turn = block_on(o89_core::record_owed(&site, &mut ring, &mut scratch, None));
    assert_eq!(
        (turn.landed, turn.refused),
        (1, false),
        "the topology record, once"
    );
    let again = block_on(o89_core::record_owed(&site, &mut ring, &mut scratch, None));
    assert_eq!(again.landed, 0, "and not twice");
    assert_eq!(ring.next_seq(), 2);
}
