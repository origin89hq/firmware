//! Key agreement off the control loop, and the handshakes it serves, driven
//! by the hostile comms processor against the worker the bench simulates
//! (P-243): a job held for as long as a Cortex-M0+ takes over it, while
//! the link, the rail and the other connections go on.
use std::cell::Cell;

use km43::{Generation, PairRefusal, PrintedSecret};
use o89_core::{Outgoing, Tick};

use super::*;
use crate::link::{agreement, enrolment, manufactured};

/// Every heartbeat the controller put on the wire, by tick.
fn beats(bench: &Bench) -> Vec<Tick> {
    bench
        .sent(|outgoing| matches!(outgoing, Outgoing::Heartbeat { .. }))
        .into_iter()
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn p_243_the_link_beats_on_time_while_a_hello_computes() {
    // Capabilities: none; the worker takes five seconds over one job.
    let mut quiet = linked();
    let mut busy = linked();
    for bench in [&mut quiet, &mut busy] {
        bench.compute = Millis::from_millis(5_000);
        announce(bench, 1);
    }
    let mut client = Client::on(1);
    let _ = client.discover(&mut busy);
    let (pending, frame) = client.hello_frame();
    // `quiet` runs the same span with nothing to compute.
    let mut idle = Client::on(1);
    let _ = idle.discover(&mut quiet);
    let bytes = busy.comms.relay(&frame, busy.now).expect("relays");
    busy.feed(&bytes);
    let before = (beats(&quiet).len(), beats(&busy).len());
    busy.run_for(Millis::from_millis(20));
    quiet.run_for(Millis::from_millis(20));
    assert!(busy.computing(), "the Hello is out at the worker");
    busy.run_for(Millis::from_millis(4_000));
    quiet.run_for(Millis::from_millis(4_000));
    assert!(busy.computing(), "and still is");
    assert_eq!(
        beats(&busy)[before.1..],
        beats(&quiet)[before.0..],
        "a job out moved the link's beats"
    );
    assert!(beats(&busy).len() > before.1, "beats went out meanwhile");
    busy.run_for(Millis::from_millis(1_500));
    assert!(!busy.computing());
    let answers = busy.comms.to_client(1);
    assert!(
        client
            .finish(pending, answers.last().expect("answered"))
            .is_some()
    );
}

#[test]
fn p_229_a_connection_that_drops_while_its_hello_computes_is_answered_nothing() {
    // Capabilities: invent_connection; the transport goes mid-computation.
    let mut bench = linked();
    bench.compute = Millis::from_millis(5_000);
    announce(&mut bench, 1);
    let mut gone = Client::on(1);
    let _ = gone.discover(&mut bench);
    let (_, frame) = gone.hello_frame();
    let before = bench.comms.to_client(1).len();
    let bytes = bench.comms.relay(&frame, bench.now).expect("relays");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(100));
    assert!(bench.computing());
    release(&mut bench, 1);
    bench.run_for(Millis::from_millis(6_000));
    assert!(!bench.computing(), "the worker is free again");
    assert_eq!(bench.comms.to_client(1).len(), before, "nobody to answer");
    // The next connection is served.
    announce(&mut bench, 2);
    let mut next = Client::on(2);
    let _ = next.open(&mut bench);
}

#[test]
fn p_229_p_085_a_factory_reset_while_a_pairing_computes_abandons_it() {
    // Capabilities: none; the reset is at the panel.
    let mut bench = linked();
    bench.compute = Millis::from_millis(5_000);
    announce(&mut bench, 1);
    bench.open_pairing();
    let mut client = Client::install(1, 2);
    let _ = client.discover(&mut bench);
    let (_, frame) = client.pair_frame(&secret().label(), "laptop");
    let before = bench.comms.to_client(1).len();
    let bytes = bench.comms.relay(&frame, bench.now).expect("relays");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(100));
    assert!(bench.computing());
    block_on(bench.endpoint.sessions.factory_reset(&mut bench.fram)).expect("resets");
    bench.run_for(Millis::from_millis(6_000));
    assert!(!bench.computing());
    assert_eq!(
        bench.comms.to_client(1).len(),
        before,
        "message 2 for an abandoned handshake"
    );
    assert_eq!(enrolled(&bench.endpoint.sessions), 0);
}

#[test]
fn p_241_a_refusal_the_relay_forges_or_rewrites_is_not_believed() {
    // Capabilities: forge (a refusal), rewrite (its outcome).
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut client = Client::install(1, 2);
    // The window is closed: the controller refuses under the refusal key.
    let _ = client.discover(&mut bench);
    let (pending, frame) = client.pair_frame(&secret().label(), "laptop");
    let answers = client.exchange(&mut bench, &frame);
    let read = pending.read(
        Envelope::decode(answers.last().expect("refused")).expect("an envelope"),
        &secret().label(),
        &fingerprint(),
    );
    assert!(matches!(
        read,
        Ok(PairReply::Refused(PairRefusal::WindowClosed))
    ));
    // The tag's last byte, then the outcome: `window_closed` said as
    // `table_full`. The body is `{1: outcome, 3: bstr16}`.
    let rewrites: [fn(&mut Vec<u8>); 2] = [
        |frame| {
            let last = frame.len() - 1;
            frame[last] ^= 1;
        },
        |frame| {
            let at = frame
                .windows(4)
                .position(|window| window == [0x01, 0x02, 0x03, 0x50])
                .expect("the refusal's body");
            frame[at + 1] = 0x04;
        },
    ];
    for rewrite in rewrites {
        let _ = client.discover(&mut bench);
        let (pending, frame) = client.pair_frame(&secret().label(), "laptop");
        let answers = client.exchange(&mut bench, &frame);
        let mut forged = answers.last().expect("refused").clone();
        rewrite(&mut forged);
        let read = pending.read(
            Envelope::decode(&forged).expect("an envelope"),
            &secret().label(),
            &fingerprint(),
        );
        assert!(read.is_err(), "a forged refusal was believed");
    }
}

#[test]
fn p_066_a_relay_rewriting_message_1_is_answered_bare_10_and_costs_no_job() {
    // Capabilities: rewrite.
    let mut bench = linked();
    announce(&mut bench, 1);
    bench.open_pairing();
    let mut client = Client::install(1, 2);
    let _ = client.discover(&mut bench);
    let (_, mut frame) = client.pair_frame(&secret().label(), "laptop");
    let last = frame.len() - 1;
    frame[last] ^= 1;
    let answers = client.exchange(&mut bench, &frame);
    assert_eq!(code(answers.last().expect("answered")), Some(10));
    assert!(!bench.computing());
    assert!(bench.window.is_open(bench.now), "nothing was enrolled");
}

#[test]
fn p_238_a_recorded_hello_replayed_on_another_connection_is_12_and_costs_no_job() {
    // Capabilities: replay, stamp, invent_connection.
    let mut bench = linked();
    announce(&mut bench, 1);
    announce(&mut bench, 2);
    let mut client = Client::on(1);
    let mut hello = client.open(&mut bench);
    let mut other = Client::on(2);
    let _ = other.discover(&mut bench);
    assert_eq!(hello[2], 1, "fixture has a one-byte handle");
    hello[2] = 2;
    let answers = other.exchange(&mut bench, &hello);
    // The admission tag is over the prologue, which names the other
    // connection's challenge and handle: no slot's key vouches for it.
    assert_eq!(code(answers.last().expect("answered")), Some(12));
    assert!(!bench.computing());
    assert!(!bench.endpoint.sessions.is_bound(Conn::new(2).unwrap()));
}

#[test]
fn p_238_p_051_a_flood_of_hellos_from_a_stranger_never_reaches_the_worker() {
    // Capabilities: invent_connection, replay; the stranger holds a key no
    // slot does.
    let mut bench = linked();
    announce(&mut bench, 1);
    let mut stranger = Client::install(1, 9);
    stranger.enrolment = Some(stranger.kept());
    for n in 1..=8 {
        let _ = stranger.discover(&mut bench);
        let (_, frame) = stranger.hello_frame();
        let answers = stranger.send(&mut bench, &frame);
        assert_eq!(code(answers.last().expect("answered")), Some(12), "{n}");
        assert!(!bench.computing(), "{n}: a DH for a stranger");
    }
    // Eight failures inside a minute shed the connection.
    assert_eq!(
        closes(&bench),
        vec![(1, CloseReason::AuthenticationFailures)]
    );
}

#[test]
fn p_242_the_relay_drops_enrol_0x93_and_the_phone_learns_its_slot_from_hello() {
    // Capabilities: drop (the one answer that says the phone is enrolled).
    let mut bench = linked();
    announce(&mut bench, 1);
    bench.open_pairing();
    let mut phone = Client::install(1, 2);
    let _ = phone.discover(&mut bench);
    let (pending, frame) = phone.pair_frame(&secret().label(), "laptop");
    let answers = phone.exchange(&mut bench, &frame);
    let Ok(PairReply::Proceed(proceeding)) = pending.read(
        Envelope::decode(answers.last().expect("message 2")).expect("an envelope"),
        &secret().label(),
        &fingerprint(),
    ) else {
        panic!("message 2 expected");
    };
    let mut dst = [0u8; MAX_FRAME];
    let header = phone.header(MessageType::Enrol);
    let (_, len) = proceeding
        .finish(&client_key(2), header, &mut dst)
        .expect("message 3");
    phone.enrolment = Some(phone.kept());
    // The answer reaches the relay and goes no further.
    let _dropped = phone.exchange(&mut bench, &dst[..len]);
    let _ = phone.discover(&mut bench);
    let (pending, frame) = phone.hello_frame();
    let answers = phone.exchange(&mut bench, &frame);
    let named = phone.finish(pending, answers.last().expect("answered"));
    assert_eq!(
        named,
        Some((ClientId::new(2).unwrap(), Generation::FIRST)),
        "keys 30 and 31 name the slot the lost answer would have"
    );
}

#[test]
fn p_237_boots_between_draws_never_repeat_a_challenge() {
    // Capabilities: none; five boots of the same part, three connections each.
    let mut part = manufactured();
    let facts = Facts {
        model: MODEL,
        fw_controller: "0.0.0-sim",
        fw_comms: "",
        log: LOG,
        time_known: false,
        pairing_open: false,
        link: Some(Compat::Agreed(Version::V1_0)),
    };
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for _ in 0..5 {
        part.reboot();
        let mut sessions = Sessions::new(reread(&mut part).expect("boots"));
        let mut wifi = o89_core::Wifi::EMPTY;
        let now = o89_core::Tick::from_millis(1_000);
        for handle in 1..=3u16 {
            let _ = sessions.admit(Conn::new(handle).unwrap());
            block_on(sessions.settle(now, &mut part));
            let mut client = Client::on(handle);
            let frame = client.empty(MessageType::Discover);
            let mut dst = [0u8; 256];
            let reply =
                block_on(sessions.frame(&frame, now, (&facts, &mut wifi), &mut part, &mut dst));
            let len = reply.answer.expect("answered");
            let discovery =
                Discovery::decode(Envelope::decode(&dst[..len]).unwrap()).expect("a challenge");
            assert!(!seen.contains(&discovery.challenge), "a challenge repeated");
            seen.push(discovery.challenge);
        }
    }
    assert_eq!(seen.len(), 15);
}

/// A whole pairing against `sessions` with no bench: message 1 and 3 each
/// computed by `worker` at once, as a zero-latency worker would. What the
/// label says of `Enrol 0x93`, or `Err` if any step did not get there.
fn pair_directly(
    sessions: &mut Sessions,
    part: &mut SimFram,
    install: u8,
    label: &str,
) -> Result<EnrolAnswer, ()> {
    let worker = agreement();
    let facts = Facts {
        model: MODEL,
        fw_controller: "0.0.0-sim",
        fw_comms: "",
        log: LOG,
        time_known: false,
        pairing_open: true,
        link: Some(Compat::Agreed(Version::V1_0)),
    };
    let now = o89_core::Tick::from_millis(1_000);
    let mut wifi = o89_core::Wifi::EMPTY;
    let conn = Conn::new(1).ok_or(())?;
    let _ = sessions.admit(conn);
    block_on(sessions.settle(now, part));
    let mut client = Client::install(1, install);
    let mut dst = [0u8; MAX_FRAME];
    let discover = client.empty(MessageType::Discover);
    let reply = block_on(sessions.frame(&discover, now, (&facts, &mut wifi), part, &mut dst));
    let discovery =
        Discovery::decode(Envelope::decode(&dst[..reply.answer.ok_or(())?]).map_err(|_| ())?)
            .map_err(|_| ())?;
    client.challenge = Some(discovery.challenge);
    client.epoch = discovery.epoch;
    let mut computed = |sessions: &mut Sessions,
                        part: &mut SimFram,
                        frame: &[u8],
                        dst: &mut [u8]|
     -> Result<usize, ()> {
        let _ = block_on(sessions.frame(frame, now, (&facts, &mut wifi), part, dst));
        let job = sessions.next_job().ok_or(())?;
        let done = worker.run(job);
        block_on(sessions.completed(done, now, &facts, part, dst))
            .answer
            .ok_or(())
    };
    let (pending, frame) = client.pair_frame(&secret().label(), label);
    let len = computed(sessions, part, &frame, &mut dst)?;
    let PairReply::Proceed(proceeding) = pending
        .read(
            Envelope::decode(&dst[..len]).map_err(|_| ())?,
            &secret().label(),
            &fingerprint(),
        )
        .map_err(|_| ())?
    else {
        return Err(());
    };
    let mut message = [0u8; MAX_FRAME];
    let header = client.header(MessageType::Enrol);
    let (enrol, len) = proceeding
        .finish(&client_key(install), header, &mut message)
        .map_err(|_| ())?;
    let len = computed(sessions, part, &message[..len], &mut dst)?;
    let mut plain = [0u8; MAX_PAYLOAD];
    enrol
        .read(Envelope::decode(&dst[..len]).map_err(|_| ())?, &mut plain)
        .map_err(|_| ())
}

#[test]
fn p_239_a_reclaim_cut_at_every_step_leaves_the_old_install_or_a_free_slot_or_the_new_one() {
    // Capabilities: none; the cuts are behind the storage seam. A full table
    // with install 1 as "phone" at slot 1; install 9 pairs as "phone" and
    // reclaims it (P-240 step 3).
    let (mut start, mut keys) = unit();
    let epoch = keys.epoch.expect("an epoch");
    for n in 2..=8u8 {
        block_on(keys.clients.enrol(
            ClientId::new(u32::from(n)).unwrap(),
            enrolment(n, "other", ClientKind::App),
            epoch,
            &mut start,
        ))
        .expect("lands");
    }
    let slot = ClientId::new(1).unwrap();
    let old = client_key(1).public();
    let new = client_key(9).public();
    // Once a cut has left the old key gone, no later cut brings it back.
    let gone = Cell::new(false);
    let (mut free, mut reclaimed) = (0, 0);
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let mut sessions = Sessions::new(reread(part).ok_or(())?);
            let answer = pair_directly(&mut sessions, part, 9, "phone")?;
            match answer.outcome {
                km43::Outcome::Reclaimed(id, _) if id == slot => Ok(()),
                _ => Err(()),
            }
        },
        |part, step| {
            let keys = reread(part).expect("the part is back");
            let epoch = keys.epoch.expect("an epoch");
            assert!(keys.clients.enrolled(epoch) >= 7, "cut at {step}");
            let mark = keys
                .clients
                .mark(slot)
                .and_then(|mark| mark.present().copied())
                .expect("a mark");
            match keys.clients.occupant(slot, epoch) {
                Some(occupant) if occupant.client().matches(&old) => {
                    assert!(!gone.get(), "cut at {step}: the old key came back");
                    assert_eq!(occupant.generation(), Generation::FIRST, "cut at {step}");
                }
                Some(occupant) if occupant.client().matches(&new) => {
                    gone.set(true);
                    reclaimed += 1;
                    let issued = Generation::new(2).unwrap();
                    assert_eq!(occupant.generation(), issued, "cut at {step}");
                    assert_eq!(mark.next(), issued.next(), "cut at {step}");
                }
                Some(_) => panic!("cut at {step}: a key nobody enrolled"),
                None => {
                    gone.set(true);
                    free += 1;
                    // Never issued twice: the mark is at least what the
                    // freed record was written under.
                    assert!(mark.next() >= Generation::new(3), "cut at {step}");
                }
            }
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
    assert!(free > 0, "no cut ever found the slot free");
    assert!(reclaimed == 0, "the whole reclaim is the uncut path's");
}

#[test]
fn p_066_a_foreign_label_never_reaches_the_worker_even_inside_the_window() {
    // Capabilities: invent_connection, forge.
    let mut bench = linked();
    bench.open_pairing();
    for handle in 1..=3 {
        announce(&mut bench, handle);
        let mut client = Client::install(handle, 9);
        let _ = client.discover(&mut bench);
        let byte = u8::try_from(handle).unwrap();
        let label = km43::Label::new(DeviceId::new(DEVICE), PrintedSecret::new([byte; 32]));
        let (_, frame) = client.pair_frame(&label, "forged");
        let answers = client.send(&mut bench, &frame);
        assert_eq!(code(answers.last().unwrap()), Some(10));
        assert!(!bench.computing());
    }
    assert!(bench.window.is_open(bench.now));
}
