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

/// The site with its one owner, which never finds it held.
trait Free {
    fn free<R>(&self, with: impl FnOnce(&mut o89_core::Site, o89_core::Tick) -> R) -> R;
}

impl Free for SimSite {
    fn free<R>(&self, with: impl FnOnce(&mut o89_core::Site, o89_core::Tick) -> R) -> R {
        self.with(with)
            .expect("one owner never finds the site held")
    }
}

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
        .free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(signals)))
        .expect("a valid site");
    bench.run_for(Millis::from_millis(1_100));
    bench
}

fn write(bench: &SimSite, sig: u16, value: i32) {
    bench
        .free(|site, now| {
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
    events_on(client, bench, 1)
}

/// The same for the client on `handle`.
fn events_on(client: &mut Client, bench: &Bench, handle: u16) -> Vec<(u64, EventKind)> {
    bench
        .comms
        .to_client(handle)
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
        .free(|site, now| {
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
        .free(|site, _| site.presence(1, km43::Presence::Online))
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
    site.free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut unsettled = None;
    {
        part.cut_after(0);
        let mut ring =
            block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
        let turn = block_on(o89_core::record_owed(
            &site,
            &mut ring,
            &mut scratch,
            None,
            |_| {},
            &mut unsettled,
        ));
        // An error is not an absence: kept until the part can say.
        assert_eq!((turn.landed, turn.refused, turn.adrift), (0, true, true));
        assert!(unsettled.is_some());
    }
    part.reboot();
    let mut ring =
        block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.refused),
        (1, false),
        "found absent, owed again, logged once"
    );
    let again = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(again.landed, 0, "and not twice");
    assert_eq!(ring.next_seq(), 2);
}

#[test]
fn p_104_p_095_the_log_extent_is_published_as_each_record_lands_not_at_the_end_of_the_turn() {
    // Capabilities: none.
    let mut part = SimNor::<{ crate::link::LOG_BLOCK }>::fresh(8);
    let site = SimSite::empty();
    site.free(|site, now| {
        site.apply(TopologyChangeReason::Boot, &charger(1))?;
        site.write(
            id(1),
            now,
            Observation::value(1, Provenance::Measured).expect("a value"),
        )
    })
    .expect("a valid site");
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring =
        block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
    let mut published = Vec::new();
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |extent| {
            published.push(match extent {
                o89_core::Extent::Moving => None,
                o89_core::Extent::Settled(ring) => Some(ring.next_seq()),
            });
        },
        &mut None,
    ));
    assert_eq!(turn.landed, 2, "the topology and the validity sweep");
    assert_eq!(
        published,
        [Some(1), None, Some(2), None, Some(3)],
        "settled once proven before anything is taken, moving before each append, settled as each landed"
    );
}

/// Every signal's quality moved once for each tick in `ticks`, and a
/// plane period run after each when `wait`.
fn flap(bench: &mut Bench, ticks: std::ops::Range<u16>, wait: bool) {
    for tick in ticks {
        for sig in 1..=64u16 {
            bench
                .site
                .free(|site, now| {
                    let seen = if tick.wrapping_add(sig) % 2 == 0 {
                        Observation::value(i32::from(sig), Provenance::Measured).expect("a value")
                    } else {
                        Observation::missing(km43::Validity::Absent).expect("absent")
                    };
                    site.write(id(sig), now, seen)
                })
                .expect("registered");
        }
        if wait {
            bench.run_for(Millis::from_millis(1_000));
        }
    }
}

#[test]
fn p_098_p_182_eight_subscribers_keep_up_with_a_twelve_tick_burst_and_none_is_shed() {
    // Capabilities: none; the honest relay, delivery paced as the firmware
    // paces it (one read out, taken back once a 100 ms link turn).
    let mut bench = site_bench(64);
    // A log long enough that replaying it competes with the burst.
    flap(&mut bench, 0..60, true);
    let mut clients = Vec::new();
    let mut accepted = Vec::new();
    for handle in 1..=8u16 {
        announce(&mut bench, handle);
        let mut client = Client::on(handle);
        let _ = client.open(&mut bench);
        // Three replay the log from three places; the rest are live only.
        let from: u8 = match handle {
            1 => 1,
            2 => 20,
            3 => 23,
            _ => 0,
        };
        let frame = client.sealed(MessageType::Subscribe, &[0xa1, 1, 0x18, from]);
        let answers = client.send(&mut bench, &frame);
        let ack = answers
            .iter()
            .rev()
            .find_map(|frame| {
                let (header, inner) = client.opened(frame)?;
                (header.kind == MessageType::SubscribeResponse)
                    .then(|| km43::SubscribeAck::decode(&inner).expect("an ack"))
            })
            .expect("acknowledged");
        accepted.push(ack.accepted_from_seq().0);
        clients.push(client);
    }
    // Twelve ticks, each moving every signal's quality, a device's
    // presence, and raising concerns: more than a tick holds.
    for tick in 0..12u16 {
        flap(&mut bench, tick..tick.wrapping_add(1), false);
        let presence = if tick % 2 == 0 {
            km43::Presence::Online
        } else {
            km43::Presence::Offline
        };
        bench
            .site
            .free(|site, _| site.presence(1, presence))
            .expect("a device");
        for n in 0..4u16 {
            let subject = Subject::Signal(Part::device(id(1)), id(tick * 4 + n + 1));
            bench
                .site
                .free(|site, now| {
                    site.observe(
                        ConcernReport {
                            subject,
                            cond: Condition(0x0101),
                            sev: Severity::Fault,
                            code: None,
                        },
                        now,
                    )
                })
                .expect("admitted");
        }
        bench.run_for(Millis::from_millis(1_000));
    }
    bench.run_for(Millis::from_millis(10_000));
    let newest = bench.log_span().newest.0;
    assert!(newest > 12 * 3, "the burst was logged: {newest}");
    assert!(
        closes(&bench).is_empty(),
        "nobody shed: {:?}",
        closes(&bench)
    );
    for ((handle, client), from) in (1u16..).zip(clients.iter_mut()).zip(accepted) {
        let seqs: Vec<u64> = events_on(client, &bench, handle)
            .iter()
            .map(|(seq, _)| *seq)
            .collect();
        assert_eq!(
            seqs,
            (from..=newest).collect::<Vec<_>>(),
            "handle {handle}: every record from its start, once, in order"
        );
    }
}

/// The site behind an owner that is held on one chosen call: what a
/// holder on another executor would look like.
struct HeldOnce {
    inner: SimSite,
    calls: std::cell::Cell<usize>,
    held_on: usize,
}

impl o89_core::SiteCell for HeldOnce {
    fn with<R>(
        &self,
        with: impl FnOnce(&mut o89_core::Site, o89_core::Tick) -> R,
    ) -> Result<R, o89_core::SiteBusy> {
        let call = self.calls.get().checked_add(1).expect("fits");
        self.calls.set(call);
        if call == self.held_on {
            return Err(o89_core::SiteBusy);
        }
        self.inner.with(with)
    }
}

/// A site whose boot record is logged, with one fault concern observed
/// since, and the ring it was logged to.
fn concern_owed(part: &mut SimNor<{ crate::link::LOG_BLOCK }>, scratch: &mut [u8]) -> SimSite {
    let site = SimSite::empty();
    site.free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    {
        let mut ring = block_on(o89_core::Ring::open(Lent(part), 0, 8, scratch)).expect("opens");
        let turn = block_on(o89_core::record_owed(
            &site,
            &mut ring,
            scratch,
            None,
            |_| {},
            &mut None,
        ));
        assert_eq!(turn.landed, 1, "the boot's topology record");
    }
    site.free(|site, now| {
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
    site
}

fn concerns_total(site: &SimSite) -> (u16, u64) {
    site.free(|site, now| {
        let mut dst = [0u8; 1024];
        let len = site
            .concerns_page(&km43::ReadConcerns::new(0, 0), now, &mut dst)
            .expect("answers");
        let header = ConcernsHeader::decode(&dst[..len]).expect("a page");
        (header.total, header.seq)
    })
}

#[test]
fn p_180_a_raise_that_landed_while_the_site_was_held_is_told_to_it_next_turn_once() {
    // Capabilities: none. The site is held when the raise's landing is known.
    let mut part = SimNor::<{ crate::link::LOG_BLOCK }>::fresh(8);
    let mut scratch = [0u8; o89_core::SCRATCH];
    let site = HeldOnce {
        inner: concern_owed(&mut part, &mut scratch),
        calls: std::cell::Cell::new(0),
        held_on: 2,
    };
    let mut ring =
        block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
    let mut unsettled = None;
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.busy), (1, true));
    assert!(unsettled.is_some(), "the landing is kept, not lost");
    assert_eq!(concerns_total(&site.inner), (0, 0), "not yet in the table");
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.busy),
        (0, false),
        "told, and nothing appended twice"
    );
    assert!(unsettled.is_none());
    assert_eq!(
        concerns_total(&site.inner),
        (1, 2),
        "opened by the record at 2"
    );
    assert_eq!(ring.next_seq(), 3);
}

#[test]
fn p_182_a_raise_the_ring_refused_while_the_site_was_held_is_owed_again_once() {
    // Capabilities: none. The NOR loses power under the append; once it is
    // back and the part says the raise is absent, the site is held.
    let mut part = SimNor::<{ crate::link::LOG_BLOCK }>::fresh(8);
    let mut scratch = [0u8; o89_core::SCRATCH];
    let site = HeldOnce {
        inner: concern_owed(&mut part, &mut scratch),
        calls: std::cell::Cell::new(0),
        held_on: 2,
    };
    let mut unsettled = None;
    {
        part.cut_after(0);
        let mut ring =
            block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
        let turn = block_on(o89_core::record_owed(
            &site,
            &mut ring,
            &mut scratch,
            None,
            |_| {},
            &mut unsettled,
        ));
        assert_eq!((turn.landed, turn.adrift, turn.busy), (0, true, false));
    }
    assert!(unsettled.is_some(), "the uncertain raise is kept, not lost");
    part.reboot();
    let mut ring =
        block_on(o89_core::Ring::open(Lent(&mut part), 0, 8, &mut scratch)).expect("opens");
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.adrift, turn.busy),
        (0, false, true),
        "absent, and the site held"
    );
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.busy),
        (1, false),
        "owed again, and logged once"
    );
    assert_eq!(concerns_total(&site.inner), (1, 2));
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(turn.landed, 0);
}

/// A NOR part shared with the test, which can hold the first program
/// after an erase pending once: the moment an append has turned the page
/// and erased the oldest block, and has not yet written its record. It can
/// also fail the program it holds after performing it, as a part whose
/// completion poll errs after the bytes landed does.
#[derive(Clone)]
struct Pausing {
    nor: std::rc::Rc<RefCell<SimNor<{ crate::link::LOG_BLOCK }>>>,
    /// Armed: the next erase arms `hold`.
    armed: std::rc::Rc<std::cell::Cell<bool>>,
    /// The next write is held once.
    hold: std::rc::Rc<std::cell::Cell<bool>>,
    /// A write is being held now.
    held: std::rc::Rc<std::cell::Cell<bool>>,
    /// Writes to let through before one that lands and then reports an
    /// error; `None` for none.
    err_after: std::rc::Rc<std::cell::Cell<Option<u8>>>,
    /// The part loses power right after that error, reads included.
    die_after_err: std::rc::Rc<std::cell::Cell<bool>>,
}

impl embedded_storage_async::nor_flash::ErrorType for Pausing {
    type Error = crate::NorError;
}

impl embedded_storage_async::nor_flash::ReadNorFlash for Pausing {
    const READ_SIZE: usize = 1;

    fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), crate::NorError>> {
        core::future::ready(self.nor.borrow_mut().read_now(offset, bytes))
    }

    fn capacity(&self) -> usize {
        self.nor.borrow().bytes().len()
    }
}

impl embedded_storage_async::nor_flash::NorFlash for Pausing {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = crate::link::LOG_BLOCK;

    fn erase(
        &mut self,
        from: u32,
        to: u32,
    ) -> impl core::future::Future<Output = Result<(), crate::NorError>> {
        if self.armed.replace(false) {
            self.hold.set(true);
        }
        core::future::ready(self.nor.borrow_mut().erase_now(from, to))
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), crate::NorError> {
        if self.hold.replace(false) {
            self.held.set(true);
            let mut yielded = false;
            core::future::poll_fn(|cx| {
                if yielded {
                    core::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    core::task::Poll::Pending
                }
            })
            .await;
            self.held.set(false);
        }
        let written = self.nor.borrow_mut().write_now(offset, bytes);
        match self.err_after.get() {
            Some(0) => {
                self.err_after.set(None);
                if self.die_after_err.get() {
                    self.nor.borrow_mut().kill();
                }
                written.and(Err(crate::NorError::PowerLost))
            }
            Some(n) => {
                self.err_after.set(Some(n.saturating_sub(1)));
                written
            }
            None => written,
        }
    }
}

impl embedded_storage_async::nor_flash::MultiwriteNorFlash for Pausing {}

/// The extent as a publisher would hold it: oldest, newest, and whether it
/// is known to hold.
type Published = std::rc::Rc<std::cell::Cell<(u64, u64, bool)>>;

/// A three-block ring on `nor`, filled until its head is near the end of
/// its second block, so the next append turns the page into the third and
/// erases the first, where the oldest records are.
fn ring_before_rollover(nor: &Pausing, scratch: &mut [u8]) -> o89_core::Ring<Pausing> {
    let mut ring = block_on(o89_core::Ring::open(nor.clone(), 0, 3, scratch)).expect("opens");
    let block = u32::try_from(crate::link::LOG_BLOCK).expect("fits");
    for _ in 0..10_000 {
        let head = ring.head();
        if head.block == 1 && block.saturating_sub(head.at) < 40 {
            break;
        }
        let mut payload = [0u8; 32];
        let len = km43::Event::new(
            km43::LogSeq(ring.next_seq()),
            None,
            EventKind::BOOT,
            &[0xa0],
        )
        .expect("an event")
        .encode(&mut payload)
        .expect("fits");
        block_on(ring.append(o89_core::Class::A, &payload[..len], scratch)).expect("appends");
    }
    assert_eq!(ring.head().oldest, Some(1), "nothing dropped yet");
    ring
}

/// Poll `turn` until it is held inside its append, then call `during`,
/// then run it to the end.
fn held_turn<F: core::future::Future>(nor: &Pausing, turn: F, during: impl FnOnce()) -> F::Output {
    let mut turn = core::pin::pin!(turn);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    for _ in 0..100_000 {
        match turn.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(_) => panic!("the turn finished without being held"),
            core::task::Poll::Pending if nor.held.get() => break,
            core::task::Poll::Pending => {}
        }
    }
    during();
    loop {
        if let core::task::Poll::Ready(out) = turn.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

fn pausing() -> Pausing {
    Pausing {
        nor: std::rc::Rc::new(RefCell::new(SimNor::fresh(3))),
        armed: std::rc::Rc::default(),
        hold: std::rc::Rc::default(),
        held: std::rc::Rc::default(),
        err_after: std::rc::Rc::default(),
        die_after_err: std::rc::Rc::default(),
    }
}

fn publisher(published: &Published) -> impl FnMut(o89_core::Extent<'_, Pausing>) + '_ {
    move |extent| match extent {
        o89_core::Extent::Moving => {
            let (oldest, newest, _) = published.get();
            published.set((oldest, newest, false));
        }
        o89_core::Extent::Settled(ring) => {
            let head = ring.head();
            published.set((
                head.oldest.unwrap_or(0),
                head.next_seq.saturating_sub(1),
                true,
            ));
        }
    }
}

#[test]
fn p_095_p_104_while_an_append_has_erased_the_oldest_block_the_extent_is_not_published_as_held() {
    // Capabilities: none. The part holds the append after its page turn.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = ring_before_rollover(&nor, &mut scratch);
    let site = SimSite::empty();
    site.free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    let before = ring.head();
    let published: Published = std::rc::Rc::new(std::cell::Cell::new((
        1,
        before.next_seq.saturating_sub(1),
        true,
    )));
    nor.armed.set(true);
    let turn = held_turn(
        &nor,
        o89_core::record_owed(
            &site,
            &mut ring,
            &mut scratch,
            None,
            publisher(&published),
            &mut None,
        ),
        || {
            // The oldest block is gone from the part, and what a
            // `Subscribe` would answer from says it is not known to hold.
            let nor = nor.nor.borrow();
            assert!(
                nor.bytes()[..crate::link::LOG_BLOCK]
                    .iter()
                    .all(|byte| *byte == 0xFF)
            );
            let (oldest, _, settled) = published.get();
            assert_eq!((oldest, settled), (1, false));
        },
    );
    assert_eq!(turn.landed, 1);
    let (oldest, newest, settled) = published.get();
    assert!(settled, "published once the append landed");
    assert!(oldest > 1, "with the oldest the erase left: {oldest}");
    assert_eq!(newest, before.next_seq);
}

#[test]
fn p_095_an_append_that_fails_after_erasing_the_oldest_block_leaves_the_extent_unknown_until_found_again()
 {
    // Capabilities: none. The part loses power while the append is held
    // after its page turn; the next turn runs as it would, with no manual
    // recovery.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = ring_before_rollover(&nor, &mut scratch);
    let site = SimSite::empty();
    site.free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    let before = ring.head();
    let published: Published = std::rc::Rc::new(std::cell::Cell::new((
        1,
        before.next_seq.saturating_sub(1),
        true,
    )));
    let mut unsettled = None;
    nor.armed.set(true);
    let turn = held_turn(
        &nor,
        o89_core::record_owed(
            &site,
            &mut ring,
            &mut scratch,
            None,
            publisher(&published),
            &mut unsettled,
        ),
        || nor.nor.borrow_mut().cut_after(0),
    );
    assert_eq!((turn.landed, turn.refused, turn.adrift), (0, true, true));
    assert!(!ring.is_proven());
    let (oldest, _, settled) = published.get();
    assert_eq!(
        (oldest, settled),
        (1, false),
        "the stale oldest is never published as held"
    );
    // Still dead: the next turn cannot say, publishes nothing, appends
    // nothing over the unknown outcome.
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        publisher(&published),
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.adrift), (0, true));
    assert!(!published.get().2);
    // Power back: the next turn finds the head from the bytes, learns the
    // record never landed, and logs it once.
    nor.nor.borrow_mut().reboot();
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        publisher(&published),
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.adrift), (1, false));
    let head = ring.head();
    let (oldest, newest, settled) = published.get();
    assert!(settled && head.oldest == Some(oldest) && oldest > 1);
    assert_eq!(
        newest, before.next_seq,
        "the record at the position the failed one had"
    );
}

/// A site whose boot record is logged on `ring`, with one fault concern
/// observed since.
fn concern_on(ring: &mut o89_core::Ring<Pausing>, scratch: &mut [u8]) -> SimSite {
    let site = SimSite::empty();
    site.free(|site, _| site.apply(TopologyChangeReason::Boot, &charger(1)))
        .expect("a valid site");
    let turn = block_on(o89_core::record_owed(
        &site,
        ring,
        scratch,
        None,
        |_| {},
        &mut None,
    ));
    assert_eq!(turn.landed, 1, "the boot's topology record");
    site.free(|site, now| site.observe(fault(), now))
        .expect("admitted");
    site
}

fn fault() -> ConcernReport {
    ConcernReport {
        subject: Subject::Part(Part::device(id(1))),
        cond: Condition(0x0101),
        sev: Severity::Fault,
        code: None,
    }
}

/// Every record the ring holds from `from`: its position and kind.
fn logged(
    ring: &mut o89_core::Ring<Pausing>,
    from: u64,
    scratch: &mut [u8],
) -> Vec<(u64, EventKind)> {
    let mut batch = o89_core::LogBatch::new();
    block_on(o89_core::read_log(ring, from, 64, scratch, &mut batch)).expect("reads");
    (0..batch.len())
        .map(|index| {
            let (seq, bytes) = batch.get(index).expect("taken");
            (seq, km43::Event::decode(bytes).expect("an event").kind)
        })
        .collect()
}

#[test]
fn p_180_a_raise_that_landed_though_its_append_erred_is_committed_and_its_clear_follows() {
    // Capabilities: none. The part programs the raise's magic and then
    // reports an error; the condition clears while the append is out.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = block_on(o89_core::Ring::open(nor.clone(), 0, 3, &mut scratch)).expect("opens");
    let site = concern_on(&mut ring, &mut scratch);
    let raise_at = ring.next_seq();
    nor.hold.set(true);
    nor.err_after.set(Some(1));
    let mut unsettled = None;
    let turn = held_turn(
        &nor,
        o89_core::record_owed(&site, &mut ring, &mut scratch, None, |_| {}, &mut unsettled),
        || {
            site.free(|site, _| site.gone(fault().subject, fault().cond, o89_core::Latch::None))
                .expect("open");
        },
    );
    assert_eq!(
        (turn.landed, turn.adrift),
        (2, false),
        "found on the part and committed, then its clear owed and logged in the same tick"
    );
    assert!(unsettled.is_none());
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(turn.landed, 0, "nothing more");
    assert_eq!(
        logged(&mut ring, raise_at, &mut scratch),
        [
            (raise_at, EventKind::CONCERN_RAISED),
            (raise_at + 1, EventKind::CONCERN_CHANGED)
        ],
        "one raise, then its clear"
    );
    assert_eq!(
        concerns_total(&site),
        (0, raise_at + 1),
        "the row left with its clear"
    );
}

#[test]
fn p_180_an_erred_append_whose_part_cannot_be_read_is_kept_until_it_can_and_nothing_goes_over_it() {
    // Capabilities: none. As above, and the part loses power right after
    // the error, so nothing can say whether the raise landed until it is
    // back.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = block_on(o89_core::Ring::open(nor.clone(), 0, 3, &mut scratch)).expect("opens");
    let site = concern_on(&mut ring, &mut scratch);
    let raise_at = ring.next_seq();
    nor.hold.set(true);
    nor.err_after.set(Some(1));
    nor.die_after_err.set(true);
    let mut unsettled = None;
    let turn = held_turn(
        &nor,
        o89_core::record_owed(&site, &mut ring, &mut scratch, None, |_| {}, &mut unsettled),
        || {
            site.free(|site, _| site.gone(fault().subject, fault().cond, o89_core::Latch::None))
                .expect("open");
        },
    );
    assert_eq!((turn.landed, turn.adrift), (0, true));
    // Still dead: kept, and nothing appended over it.
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.adrift), (0, true));
    assert!(unsettled.is_some());
    nor.nor.borrow_mut().reboot();
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.adrift),
        (1, false),
        "the raise found, then its clear logged"
    );
    assert_eq!(
        logged(&mut ring, raise_at, &mut scratch),
        [
            (raise_at, EventKind::CONCERN_RAISED),
            (raise_at + 1, EventKind::CONCERN_CHANGED)
        ]
    );
    assert_eq!(concerns_total(&site), (0, raise_at + 1));
}

#[test]
fn p_099_a_drop_that_fails_leaves_the_ring_unproven_and_the_next_read_finds_the_head_first() {
    // Capabilities: none. The part loses power under a bench drop of the
    // oldest block.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = ring_before_rollover(&nor, &mut scratch);
    let newest = ring.next_seq().saturating_sub(1);
    nor.nor.borrow_mut().cut_after(100);
    assert!(block_on(ring.drop_oldest(&mut scratch)).is_err());
    assert!(!ring.is_proven());
    // Still dead: a read cannot prove the head, and says so.
    let mut batch = o89_core::LogBatch::new();
    assert!(
        block_on(o89_core::read_log(
            &mut ring,
            1,
            4,
            &mut scratch,
            &mut batch
        ))
        .is_err()
    );
    // Back: the read finds the head from the bytes first, with no manual
    // recovery, and answers from what the part holds.
    nor.nor.borrow_mut().reboot();
    block_on(o89_core::read_log(
        &mut ring,
        1,
        4,
        &mut scratch,
        &mut batch,
    ))
    .expect("reads");
    assert!(ring.is_proven());
    let first = batch.get(0).map(|(seq, _)| seq).expect("records remain");
    assert!(
        first > 1,
        "the half-erased block's records are gone: {first}"
    );
    assert_eq!(batch.oldest(), first);
    assert_eq!(
        ring.next_seq().saturating_sub(1),
        newest,
        "nothing newer lost"
    );
}

#[test]
fn p_095_an_append_after_a_page_turn_that_failed_finds_the_head_before_it_writes() {
    // Capabilities: none. The part loses power while a page turn erases the
    // oldest block, before the ring learns the new oldest; power comes back
    // and the next append is an ordinary one, as a diagnostic's is.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = ring_before_rollover(&nor, &mut scratch);
    let filler = |seq: u64| {
        let mut payload = [0u8; 64];
        let len = km43::Event::new(
            km43::LogSeq(seq),
            None,
            EventKind::BOOT,
            &[
                0xa1, 1, 0x58, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .expect("an event")
        .encode(&mut payload)
        .expect("fits");
        (payload, len)
    };
    let (payload, len) = filler(ring.next_seq());
    nor.nor.borrow_mut().cut_after(100);
    assert!(block_on(ring.append(o89_core::Class::A, &payload[..len], &mut scratch)).is_err());
    assert!(!ring.is_proven());
    nor.nor.borrow_mut().reboot();
    let (payload, len) = filler(ring.next_seq());
    block_on(ring.append(o89_core::Class::A, &payload[..len], &mut scratch)).expect("appends");
    assert!(ring.is_proven());
    let oldest = ring.head().oldest.expect("records");
    assert!(
        oldest > 1,
        "the half-erased block's records are not claimed: {oldest}"
    );
    let mut batch = o89_core::LogBatch::new();
    block_on(o89_core::read_log(
        &mut ring,
        1,
        1,
        &mut scratch,
        &mut batch,
    ))
    .expect("reads");
    assert_eq!(
        batch.get(0).map(|(seq, _)| seq),
        Some(oldest),
        "the first record held is the oldest said"
    );
}

/// A diagnostic appended as the recorder's `append_body` appends one: the
/// head proven first, then numbered from it.
fn diagnostic(ring: &mut o89_core::Ring<Pausing>, scratch: &mut [u8]) -> Result<u64, ()> {
    block_on(ring.prove(scratch)).map_err(|_| ())?;
    let mut payload = [0u8; 32];
    let len = km43::Event::new(
        km43::LogSeq(ring.next_seq()),
        None,
        EventKind::BOOT,
        &[0xa0],
    )
    .expect("an event")
    .encode(&mut payload)
    .expect("fits");
    block_on(ring.append(o89_core::Class::A, &payload[..len], scratch)).map_err(|_| ())
}

/// The body of the record at `seq`.
fn body_at(ring: &mut o89_core::Ring<Pausing>, seq: u64, scratch: &mut [u8]) -> Vec<u8> {
    let mut batch = o89_core::LogBatch::new();
    block_on(o89_core::read_log(ring, seq, 1, scratch, &mut batch)).expect("reads");
    let (at, bytes) = batch.get(0).expect("a record");
    assert_eq!(at, seq);
    km43::Event::decode(bytes)
        .expect("an event")
        .body()
        .to_vec()
}

#[test]
fn p_180_a_torn_raise_then_a_diagnostic_at_its_position_is_owed_again_after_it_with_its_identity() {
    // Capabilities: none. The raise's append is torn and the part dies;
    // it comes back, the recorder appends a diagnostic first, as its turn
    // does, then the plane runs.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = block_on(o89_core::Ring::open(nor.clone(), 0, 3, &mut scratch)).expect("opens");
    let site = concern_on(&mut ring, &mut scratch);
    let n = ring.next_seq();
    let mut unsettled = None;
    nor.nor.borrow_mut().cut_after(0);
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.adrift), (0, true));
    nor.nor.borrow_mut().reboot();
    assert_eq!(
        diagnostic(&mut ring, &mut scratch),
        Ok(n),
        "the diagnostic takes the torn position"
    );
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(
        (turn.landed, turn.adrift),
        (1, false),
        "not there, owed again, logged after it"
    );
    let raised =
        km43::ConcernRaised::decode(&body_at(&mut ring, n + 1, &mut scratch)).expect("a raise");
    assert_eq!(
        raised.concern.seq,
        n + 1,
        "opened by the record that carries it"
    );
    assert_eq!(concerns_total(&site), (1, n + 1));
    site.free(|site, _| site.gone(fault().subject, fault().cond, o89_core::Latch::None))
        .expect("open");
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!(turn.landed, 1);
    let changed =
        km43::ConcernChanged::decode(&body_at(&mut ring, n + 2, &mut scratch)).expect("a change");
    assert_eq!(
        (changed.cid, changed.state, changed.prev),
        (
            raised.concern.cid,
            km43::ConcernState::Cleared,
            km43::ConcernState::Active
        )
    );
    assert_eq!(
        concerns_total(&site),
        (0, n + 2),
        "the row left with its clear"
    );
}

#[test]
fn p_182_a_diagnostic_that_landed_though_it_erred_is_not_overwritten_or_waited_on_by_the_plane() {
    // Capabilities: none. A diagnostic's magic lands and the part reports
    // an error and dies; it comes back and the plane runs first.
    let nor = pausing();
    let mut scratch = [0u8; o89_core::SCRATCH];
    let mut ring = block_on(o89_core::Ring::open(nor.clone(), 0, 3, &mut scratch)).expect("opens");
    let site = concern_on(&mut ring, &mut scratch);
    let n = ring.next_seq();
    nor.err_after.set(Some(1));
    nor.die_after_err.set(true);
    assert!(diagnostic(&mut ring, &mut scratch).is_err());
    assert!(!ring.is_proven());
    nor.nor.borrow_mut().reboot();
    let mut unsettled = None;
    let turn = block_on(o89_core::record_owed(
        &site,
        &mut ring,
        &mut scratch,
        None,
        |_| {},
        &mut unsettled,
    ));
    assert_eq!((turn.landed, turn.adrift), (1, false));
    assert!(unsettled.is_none(), "nothing left unknown");
    assert_eq!(
        logged(&mut ring, n, &mut scratch),
        [(n, EventKind::BOOT), (n + 1, EventKind::CONCERN_RAISED)],
        "the diagnostic kept at its position, the raise after it"
    );
}
