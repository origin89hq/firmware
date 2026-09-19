//! The link's rules, each driven by the hostile comms processor through
//! the controller's state machine, the rail sequencer and `km43`'s own
//! framing: what the adapter will do with bytes, done here with vectors.
//!
//! The bench below is the adapter without a board. It advances the tick
//! ten milliseconds at a time, asks the sequencer and the link what they
//! want, performs it, and keeps every action with the tick it was asked
//! at. Nothing in it is recursive: what the link sends goes into a queue
//! the pump drains, and what the peer answers goes back through the same
//! reader the controller will use.

use std::collections::VecDeque;
use std::num::NonZeroU16;

use km43::{
    FrameReader, FrameWriter, LinkEnvelope, LinkMessageType, MAX_FRAME, Received, ReqId, SessionId,
    Version,
};
use o89_core::{
    Action, Actions, BootCount, BootId, CUT_AFTER, Compat, DEAD_AFTER, DropReason,
    HEARTBEAT_PERIOD, Identity, Link, LinkEvent, LinkText, Millis, Note, Outgoing, RailEvent,
    RailLine, RailSequencer, Recovery, Revision, Tick,
};

use crate::{Answers, Beats, Capabilities, Claims, Frames, Heard, HostileComms, Statement};

const STEP: Millis = Millis::from_millis(10);

fn boot_count(n: u32) -> BootCount {
    // The sole way to a count is the store; a test builds one from bytes.
    use o89_core::{BOOT_COUNT_BYTES, Body};
    let mut bytes = [0u8; BOOT_COUNT_BYTES];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    BootCount::decode(&bytes).expect("a count decodes")
}

fn identity() -> Identity {
    Identity {
        fw: LinkText::new("ctrl 0.0.0-sim").expect("fits"),
        hw: LinkText::new("A rev A").expect("fits"),
        boot_id: BootId::derive(b"unit-1", boot_count(7)),
    }
}

struct Bench {
    now: Tick,
    link: Link,
    comms: HostileComms,
    reader: FrameReader,
    writer: FrameWriter,
    rail: RailSequencer,
    install_in_flight: bool,
    next_comms_beat: Tick,
    /// Everything the link asked for, with the tick it asked at.
    asked: Vec<(Tick, Action)>,
    /// What each tick asked for by itself, apart from the answers to frames
    /// that arrived in its step; empty batches are not kept.
    ticked: Vec<(Tick, Actions)>,
    /// Refusals and abandoned runs the controller's reader reported.
    noise: u32,
    /// What the comms processor's module has been told to be.
    module_booted: bool,
}

impl Bench {
    /// Boot at one second on the tick: the rail powered, the module coming
    /// up when it settles.
    fn new(caps: Capabilities) -> Self {
        let now = Tick::from_millis(1_000);
        let mut rail = RailSequencer::new(Revision::A);
        let _ = rail.power_on(now);
        Self {
            now,
            link: Link::new(identity(), now),
            comms: HostileComms::new(caps),
            reader: FrameReader::new(),
            writer: FrameWriter::new(),
            rail,
            install_in_flight: false,
            next_comms_beat: Tick::from_millis(u64::MAX),
            asked: Vec::new(),
            ticked: Vec::new(),
            noise: 0,
            module_booted: false,
        }
    }

    fn run_for(&mut self, span: Millis) {
        let until = self.now.after(span).expect("fits");
        while self.now.since(until).is_none() {
            self.step();
        }
    }

    fn step(&mut self) {
        self.now = self.now.after(STEP).expect("fits");
        let now = self.now;
        if let Some(event) = self.rail.tick(now) {
            match event {
                RailEvent::Settled => {
                    let actions = self.link.module_settled(now);
                    self.perform(actions);
                    let bytes = self.comms.boot(now).expect("the peer boots");
                    self.module_booted = true;
                    self.next_comms_beat = now.after(HEARTBEAT_PERIOD).expect("fits");
                    self.feed(&bytes);
                }
                RailEvent::PowerCycled { .. } | RailEvent::Unrecoverable => {}
            }
        }
        if self.module_booted && now.since(self.next_comms_beat).is_some() {
            self.next_comms_beat = now.after(HEARTBEAT_PERIOD).expect("fits");
            let bytes = self.comms.heartbeat(now).expect("the peer beats");
            self.feed(&bytes);
        }
        let late = self.comms.drain(now);
        self.feed(&late);
        let actions = self.link.tick(now, self.install_in_flight);
        if actions.iter().next().is_some() {
            self.ticked.push((now, actions));
        }
        self.perform(actions);
    }

    /// Perform actions, pumping what the peer answers back through the
    /// controller's reader until nothing moves.
    fn perform(&mut self, actions: Actions) {
        let mut to_comms: VecDeque<Vec<u8>> = VecDeque::new();
        let mut pending: VecDeque<Actions> = VecDeque::from([actions]);
        // Bounded: every round either consumes a queued frame or a queued
        // set of actions, and the peer answers a frame with at most one.
        for _ in 0..10_000 {
            if let Some(actions) = pending.pop_front() {
                for action in &actions {
                    self.asked.push((self.now, *action));
                    match action {
                        Action::Send(outgoing) => {
                            let mut dst = [0u8; MAX_FRAME];
                            let len = self
                                .link
                                .encode(*outgoing, self.now, &mut self.writer, &mut dst)
                                .expect("every outgoing frame encodes");
                            to_comms.push_back(dst[..len].to_vec());
                        }
                        Action::CutRail => {
                            let recovery = self.rail.recover(self.now);
                            if matches!(recovery, Recovery::Cycling { .. }) {
                                // The module loses its power with the rail.
                                self.comms.power_off();
                                self.module_booted = false;
                            }
                            pending.push_back(self.link.rail(recovery, self.now));
                        }
                        Action::DropConnections(_) | Action::Log(_) | Action::Note(_) => {}
                    }
                }
                continue;
            }
            if let Some(bytes) = to_comms.pop_front() {
                let back = self.comms.take(&bytes, self.now).expect("the peer answers");
                let answered = self.receive(&back);
                pending.extend(answered);
                continue;
            }
            return;
        }
        panic!("the pump did not settle");
    }

    /// Bytes from the peer into the controller's reader.
    fn feed(&mut self, bytes: &[u8]) {
        let answered = self.receive(bytes);
        for actions in answered {
            self.perform(actions);
        }
    }

    fn receive(&mut self, bytes: &[u8]) -> Vec<Actions> {
        let mut out = Vec::new();
        for byte in bytes {
            match self.reader.push(*byte) {
                Received::Frame(frame) => {
                    let Ok(envelope) = LinkEnvelope::decode(frame) else {
                        continue;
                    };
                    out.push(self.link.received(envelope, self.now));
                }
                Received::Dropped(_) | Received::Abandoned => {
                    self.noise = self.noise.saturating_add(1);
                    self.link.noise();
                }
                Received::Nothing => {}
            }
        }
        out
    }

    fn events(&self) -> Vec<(Tick, LinkEvent)> {
        self.asked
            .iter()
            .filter_map(|(at, action)| match action {
                Action::Log(event) => Some((*at, *event)),
                Action::Send(_)
                | Action::DropConnections(_)
                | Action::CutRail
                | Action::Note(_) => None,
            })
            .collect()
    }

    fn drops(&self) -> Vec<(Tick, DropReason)> {
        self.asked
            .iter()
            .filter_map(|(at, action)| match action {
                Action::DropConnections(why) => Some((*at, *why)),
                Action::Send(_) | Action::Log(_) | Action::CutRail | Action::Note(_) => None,
            })
            .collect()
    }

    fn cuts(&self) -> Vec<Tick> {
        self.asked
            .iter()
            .filter_map(|(at, action)| matches!(action, Action::CutRail).then_some(*at))
            .collect()
    }

    fn notes(&self) -> Vec<Note> {
        self.asked
            .iter()
            .filter_map(|(_, action)| match action {
                Action::Note(note) => Some(*note),
                Action::Send(_) | Action::Log(_) | Action::CutRail | Action::DropConnections(_) => {
                    None
                }
            })
            .collect()
    }

    fn sent(&self, wanted: fn(Outgoing) -> bool) -> Vec<(Tick, Outgoing)> {
        self.asked
            .iter()
            .filter_map(|(at, action)| match action {
                Action::Send(outgoing) if wanted(*outgoing) => Some((*at, *outgoing)),
                Action::Send(_)
                | Action::Log(_)
                | Action::CutRail
                | Action::DropConnections(_)
                | Action::Note(_) => None,
            })
            .collect()
    }
}

fn since_boot(at: Tick) -> u64 {
    at.since(Tick::from_millis(1_000))
        .expect("after the boot")
        .as_millis()
}

fn is_heartbeat(outgoing: Outgoing) -> bool {
    matches!(outgoing, Outgoing::Heartbeat { .. })
}

fn is_link_up(outgoing: Outgoing) -> bool {
    matches!(outgoing, Outgoing::LinkUp { .. })
}

#[test]
fn l_030_both_sides_state_themselves_at_boot_and_one_exchange_brings_the_link_up() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.link.is_up());
    let peer = bench.link.peer().expect("a peer");
    assert_eq!(peer.boot_id, bench.comms.boot_id());
    assert_eq!(peer.fw.as_str(), "comms 0.0.0-sim");
    assert_eq!(peer.net_version, Some(0));
    // The peer heard the controller state itself, and the controller
    // acknowledged the peer's statement.
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::LinkUp { .. }))
    );
    assert!(bench.comms.sent.contains(&LinkMessageType::LinkUpAck));
    assert!(
        bench.drops().is_empty(),
        "nothing was dropped on a clean boot"
    );
    // The same statement again changes nothing (L-030).
    let first = bench.comms.boot_id();
    let same = bench.comms.restate(bench.now).expect("the peer builds it");
    bench.feed(&same);
    assert!(bench.link.is_up());
    assert_eq!(bench.link.peer().expect("a peer").boot_id, first);
    assert!(bench.drops().is_empty(), "the same boot_id drops nothing");
}

#[test]
fn l_110_traffic_that_is_not_a_heartbeat_keeps_no_link_alive() {
    // Capabilities: beats withheld and nothing answered once up; time
    // offers instead, which the controller answers.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().beats = Beats::Withheld;
    bench.comms.capabilities().answers = Answers::Nothing;
    let quiet_from = bench.link.last_heard().expect("something was heard");
    // An offer every second: answered every time, and not a heartbeat.
    for _ in 0..8 {
        bench.run_for(Millis::from_millis(1_000));
        let bytes = bench
            .comms
            .offer_time(1_800_000_000_000, bench.now)
            .expect("the peer builds it");
        bench.feed(&bytes);
    }
    assert!(!bench.link.is_up());
    let (at, why) = bench.drops().first().copied().expect("a drop");
    assert_eq!(why, DropReason::LinkLost);
    let silence = at.since(quiet_from).expect("after").as_millis();
    assert!(
        (DEAD_AFTER.as_millis()..=DEAD_AFTER.as_millis() + 1_020).contains(&silence),
        "dropped after {silence} ms"
    );
    // Every offer up to the drop got its verdict, and none of them counted
    // as the peer being heard; after the drop they are refused as early.
    assert!(
        bench.sent(is_time_verdict).len() >= 4,
        "the offers were answered until the drop"
    );
}

fn is_time_verdict(out: Outgoing) -> bool {
    matches!(out, Outgoing::TimeVerdict { .. })
}

#[test]
fn l_031_the_last_statement_is_kept_through_a_drop() {
    // Capabilities: answers nothing, from the moment the link is up.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    let fw = bench.link.peer().expect("a peer").fw;
    bench.comms.capabilities().answers = Answers::Nothing;
    bench.run_for(Millis::from_millis(7_000));
    assert!(!bench.link.is_up());
    assert_eq!(
        bench.link.peer().expect("kept through the drop").fw,
        fw,
        "fw_comms is the last successful statement's"
    );
}

#[test]
fn l_033_a_request_before_the_link_is_up_is_refused_with_258() {
    // Capabilities: statement withheld.
    let mut bench = Bench::new(Capabilities {
        statement: Statement::Withheld,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert!(!bench.link.is_up());
    let bytes = bench
        .comms
        .offer_time(1_800_000_000_000, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::Refusal { code: 258, .. })),
        "refused as before link-up"
    );
    assert!(
        !bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::Other { opcode: 0xE6, .. })),
        "no verdict on an offer the link cannot take yet"
    );
}

#[test]
fn l_181_an_error_from_the_peer_is_noted_and_never_answered() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    let refusals_before = bench
        .comms
        .heard
        .iter()
        .filter(|h| matches!(h, Heard::Refusal { .. }))
        .count();
    let bytes = bench
        .comms
        .refuse(262, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.notes().contains(&Note::PeerRefused(Some(262))));
    let refusals_after = bench
        .comms
        .heard
        .iter()
        .filter(|h| matches!(h, Heard::Refusal { .. }))
        .count();
    assert_eq!(
        refusals_before, refusals_after,
        "an error is never answered with one"
    );
    assert!(bench.link.is_up(), "a refusal is not a drop");
    // An error carrying a session is a client's frame, not a refusal of
    // anything of ours.
    let session = SessionId::Assigned(NonZeroU16::new(5).expect("not zero"));
    let bytes = bench
        .comms
        .refuse_as(259, session, ReqId(9), bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(
        !bench.notes().contains(&Note::PeerRefused(Some(259))),
        "a client's error is not the peer refusing us"
    );
}

#[test]
fn l_015_an_acknowledgement_that_does_not_validate_leaves_the_request_to_retry() {
    // Capabilities: claims to be a controller.
    let mut bench = Bench::new(Capabilities {
        claims: Claims::Controller,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(2_500));
    let ids: Vec<u32> = bench
        .sent(is_link_up)
        .into_iter()
        .filter_map(|(_, out)| match out {
            Outgoing::LinkUp { req_id } => Some(req_id.0),
            _ => None,
        })
        .collect();
    assert!(ids.len() >= 3, "the request was retried: {ids:?}");
    assert_eq!(ids[0], ids[1], "under the same id");
    assert_eq!(ids[1], ids[2]);
    assert!(
        bench
            .notes()
            .contains(&Note::RequestFailed(LinkMessageType::LinkUp)),
        "and given up"
    );
}

#[test]
fn l_033_a_statement_received_does_not_link_until_ours_is_answered() {
    // Capabilities: talks only, then everything.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::TalksOnly,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert!(
        bench.comms.sent.contains(&LinkMessageType::LinkUp),
        "the peer stated itself"
    );
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::LinkUpAck { .. })),
        "and was answered"
    );
    assert!(!bench.link.is_up(), "a statement received is not a link");
    assert_eq!(
        bench.link.peer().expect("recorded").boot_id,
        bench.comms.boot_id(),
        "though it is recorded"
    );
    // The peer hears again: the next statement of ours is answered, and
    // that is the link.
    bench.comms.capabilities().answers = Answers::Everything;
    bench.run_for(Millis::from_millis(2_500));
    assert!(bench.link.is_up());
}

#[test]
fn l_100_the_peers_own_heartbeats_do_not_keep_a_link_alive() {
    // Capabilities: talks only, once the link is up.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::TalksOnly;
    let quiet_from = bench.link.last_heard().expect("an answer was heard");
    bench.run_for(Millis::from_millis(7_000));
    assert!(
        bench.comms.sent.contains(&LinkMessageType::Heartbeat),
        "the peer kept beating"
    );
    assert!(!bench.link.is_up());
    let (at, why) = bench.drops().first().copied().expect("a drop");
    assert_eq!(why, DropReason::LinkLost);
    let silence = at.since(quiet_from).expect("after").as_millis();
    assert!(
        (DEAD_AFTER.as_millis()..=DEAD_AFTER.as_millis() + 20).contains(&silence),
        "dropped {silence} ms after the last answer"
    );
}

#[test]
fn l_100_an_answer_to_a_heartbeat_never_sent_keeps_no_link_alive() {
    // Capabilities: talks only once the link is up, and forges heartbeat
    // answers with request ids the controller never used.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::TalksOnly;
    let quiet_from = bench.link.last_heard().expect("an answer was heard");
    for forged in 0..7u32 {
        bench.run_for(Millis::from_millis(1_000));
        let bytes = bench
            .comms
            .unsolicited_heartbeat_ack(ReqId(0xF0F0_0000 + forged), bench.now)
            .expect("the peer builds it");
        bench.feed(&bytes);
    }
    assert!(!bench.link.is_up());
    assert!(
        bench
            .notes()
            .contains(&Note::UnexpectedAck(LinkMessageType::HeartbeatAck))
    );
    let (at, why) = bench.drops().first().copied().expect("a drop");
    assert_eq!(why, DropReason::LinkLost);
    let silence = at.since(quiet_from).expect("after").as_millis();
    assert!(
        (DEAD_AFTER.as_millis()..=DEAD_AFTER.as_millis() + 20).contains(&silence),
        "dropped {silence} ms after the last real answer"
    );
}

#[test]
fn l_100_a_heartbeat_answer_counts_once_and_never_after_a_drop() {
    // Capabilities: talks only once the link is up, and replays the answer
    // to the last heartbeat it heard, every second, for seventy seconds.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    let last_beat = bench
        .comms
        .heard
        .iter()
        .rev()
        .find_map(|h| match h {
            Heard::Heartbeat { req_id, .. } => Some(*req_id),
            _ => None,
        })
        .expect("the controller beat");
    bench.comms.capabilities().answers = Answers::TalksOnly;
    let quiet_from = bench.link.last_heard().expect("an answer was heard");
    for _ in 0..70 {
        bench.run_for(Millis::from_millis(1_000));
        let bytes = bench
            .comms
            .unsolicited_heartbeat_ack(last_beat, bench.now)
            .expect("the peer builds it");
        bench.feed(&bytes);
    }
    let (at, why) = bench.drops().first().copied().expect("a drop");
    assert_eq!(why, DropReason::LinkLost);
    let silence = at.since(quiet_from).expect("after").as_millis();
    assert!(
        (DEAD_AFTER.as_millis()..=DEAD_AFTER.as_millis() + 20).contains(&silence),
        "dropped {silence} ms after the last real answer"
    );
    let cut = bench.cuts().first().copied().expect("a cut");
    let after = cut.since(quiet_from).expect("after").as_millis();
    assert!(
        (CUT_AFTER.as_millis()..=CUT_AFTER.as_millis() + 1_100).contains(&after),
        "cut {after} ms after the last real answer"
    );
}

#[test]
fn l_041_after_a_peer_reboots_an_answer_to_a_beat_of_the_old_boot_does_not_count() {
    // Capabilities: talks only once the link is up, then reboots and
    // replays the answer to a beat of its old boot.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::TalksOnly;
    bench.run_for(Millis::from_millis(2_100));
    let unanswered = bench
        .comms
        .heard
        .iter()
        .rev()
        .find_map(|h| match h {
            Heard::Heartbeat { req_id, .. } => Some(*req_id),
            _ => None,
        })
        .expect("a beat the peer did not answer");
    let bytes = bench.comms.boot(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    assert!(!bench.link.is_up(), "a new boot unlinks");
    let before = bench.link.last_heard();
    let replay = bench
        .comms
        .unsolicited_heartbeat_ack(unanswered, bench.now)
        .expect("the peer builds it");
    bench.feed(&replay);
    assert_eq!(
        bench.link.last_heard(),
        before,
        "an answer to the old boot's beat is not heard"
    );
    assert!(
        bench
            .notes()
            .contains(&Note::UnexpectedAck(LinkMessageType::HeartbeatAck))
    );
}

#[test]
fn l_111_the_tick_that_asks_for_the_cut_says_nothing_to_the_module() {
    // Capabilities: answers nothing, from boot.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::Nothing,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(70_000));
    let cut = bench.cuts().first().copied().expect("a cut");
    let said: Vec<&Action> = bench
        .asked
        .iter()
        .filter(|(at, action)| *at == cut && matches!(action, Action::Send(_)))
        .map(|(_, action)| action)
        .collect();
    assert!(said.is_empty(), "frames asked for with the cut: {said:?}");
}

#[test]
fn l_111_a_retry_due_with_the_cut_is_not_sent_before_it() {
    // Capabilities: talks only, from boot. A statement half a second before
    // the cut makes the controller ask, and the retry falls due with the cut.
    let talks_only = || Capabilities {
        answers: Answers::TalksOnly,
        ..Capabilities::default()
    };
    let cut_at = {
        let mut dry = Bench::new(talks_only());
        dry.run_for(Millis::from_millis(70_000));
        dry.cuts().first().copied().expect("a cut")
    };
    let mut bench = Bench::new(talks_only());
    let ahead = cut_at
        .since(bench.now)
        .expect("the cut is ahead")
        .as_millis();
    bench.run_for(Millis::from_millis(ahead - 500));
    let bytes = bench.comms.restate(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    bench.run_for(Millis::from_millis(1_000));
    let cut = bench.cuts().first().copied().expect("a cut");
    assert_eq!(cut, cut_at, "the statement moves no cut");
    let (_, batch) = bench
        .ticked
        .iter()
        .find(|(at, _)| *at == cut)
        .expect("the tick that cut");
    let asked: Vec<&Action> = batch.iter().collect();
    assert_eq!(asked, [&Action::CutRail], "the cut goes alone");
}

#[test]
fn l_111_a_peer_that_talks_but_cannot_hear_is_cut_at_sixty_seconds() {
    // Capabilities: talks only, from boot; restates itself every two
    // seconds as L-120 has an unlinked comms processor do.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::TalksOnly,
        ..Capabilities::default()
    });
    let settled = bench.now;
    for _ in 0..33 {
        bench.run_for(Millis::from_millis(2_000));
        let bytes = bench.comms.restate(bench.now).expect("the peer builds it");
        bench.feed(&bytes);
        assert!(!bench.link.is_up(), "never linked");
    }
    let cut = bench.cuts().first().copied().expect("a cut");
    let after = cut.since(settled).expect("after").as_millis();
    assert!(
        (CUT_AFTER.as_millis()..=CUT_AFTER.as_millis() + 1_100).contains(&after),
        "cut {after} ms after the module came up"
    );
}
#[test]
fn l_033_heartbeats_alone_do_not_bring_the_link_up_and_a_statement_does() {
    // Capabilities: statement withheld.
    let mut bench = Bench::new(Capabilities {
        statement: Statement::Withheld,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(10_000));
    assert!(
        !bench.link.is_up(),
        "beats were answered but nobody stated itself"
    );
    let acks = bench
        .comms
        .heard
        .iter()
        .filter(|h| matches!(h, Heard::HeartbeatAck { .. }))
        .count();
    assert!(acks >= 4, "the peer's beats were answered anyway: {acks}");
    // And a connection announced before the exchange is refused as such.
    let bytes = bench
        .comms
        .announce_connection(1, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.comms.heard.iter().any(|h| matches!(
        h,
        Heard::Other {
            opcode: 0xE2,
            outcome: Some(4),
            ..
        }
    )));
    bench.comms.capabilities().statement = Statement::Given;
    let bytes = bench.comms.boot(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.link.is_up());
}

#[test]
fn l_041_a_link_up_with_a_new_comms_boot_id_drops_every_connection() {
    // Capabilities: none; the peer reboots.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    let first = bench.comms.boot_id();
    // The same statement again changes nothing (L-030).
    let same = bench.comms.restate(bench.now).expect("the peer builds it");
    bench.feed(&same);
    assert!(bench.drops().is_empty(), "the same boot_id drops nothing");
    assert!(bench.link.is_up());
    let bytes = bench.comms.boot(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    assert_ne!(bench.comms.boot_id(), first);
    assert_eq!(
        bench
            .drops()
            .iter()
            .map(|(_, why)| *why)
            .collect::<Vec<_>>(),
        vec![DropReason::CommsRebooted]
    );
    assert!(bench.link.is_up());
    assert_eq!(
        bench.link.peer().expect("a peer").boot_id,
        bench.comms.boot_id()
    );
}

#[test]
fn l_050_a_major_mismatch_keeps_link_up_and_heartbeats_and_refuses_the_rest_with_261() {
    // Capabilities: version 2.0.
    let mut bench = Bench::new(Capabilities {
        version: Version { major: 2, minor: 0 },
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(5_000));
    assert!(bench.link.is_up());
    assert_eq!(
        bench.link.compat(),
        Some(Compat::MajorMismatch {
            theirs: Version { major: 2, minor: 0 }
        })
    );
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::HeartbeatAck { .. }))
    );
    let bytes = bench
        .comms
        .announce_connection(1, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.comms.heard.iter().any(|h| matches!(
        h,
        Heard::Refusal {
            code: 261,
            session: 0,
            ..
        }
    )));
}

#[test]
fn l_051_a_minor_mismatch_proceeds_at_the_lower_minor() {
    // Capabilities: version 1.4.
    let mut bench = Bench::new(Capabilities {
        version: Version { major: 1, minor: 4 },
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert_eq!(
        bench.link.compat(),
        Some(Compat::Agreed(Version { major: 1, minor: 0 }))
    );
    assert_eq!(
        bench.link.peer().expect("a peer").version,
        Version { major: 1, minor: 4 }
    );
}

#[test]
fn l_100_a_heartbeat_goes_out_every_two_seconds_and_the_peers_is_answered_at_once() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(10_500));
    let beats = bench.sent(is_heartbeat);
    assert!(
        (4..=6).contains(&beats.len()),
        "beats in ten seconds: {}",
        beats.len()
    );
    for pair in beats.windows(2) {
        let gap = pair[1].0.since(pair[0].0).expect("in order").as_millis();
        assert!((1_990..=2_010).contains(&gap), "gap {gap} ms");
    }
    let theirs = bench
        .comms
        .sent
        .iter()
        .filter(|kind| **kind == LinkMessageType::Heartbeat)
        .count();
    let answered = bench
        .comms
        .heard
        .iter()
        .filter(|h| matches!(h, Heard::HeartbeatAck { .. }))
        .count();
    assert!(theirs >= 4);
    assert_eq!(
        answered, theirs,
        "every beat of theirs answered in the same tick"
    );
    assert!(bench.link.is_up());
}

#[test]
fn l_110_six_seconds_of_silence_is_link_down_with_the_record_and_no_cut() {
    // Capabilities: answers nothing, from the moment the link is up.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::Nothing;
    let quiet_from = bench.link.last_heard().expect("something was heard");
    bench.run_for(Millis::from_millis(7_000));
    assert!(!bench.link.is_up());
    let (at, why) = bench.drops().first().copied().expect("a drop");
    assert_eq!(why, DropReason::LinkLost);
    let silence = at.since(quiet_from).expect("after").as_millis();
    assert!(
        (DEAD_AFTER.as_millis()..=DEAD_AFTER.as_millis() + 20).contains(&silence),
        "dropped after {silence} ms"
    );
    assert_eq!(
        bench.events().iter().map(|(_, e)| *e).collect::<Vec<_>>(),
        vec![LinkEvent::LinkLost]
    );
    assert!(bench.cuts().is_empty(), "no cut inside the first minute");
}
#[test]
fn l_111_sixty_seconds_of_silence_cuts_the_rail_and_logs_the_cycle_with_its_count() {
    // Capabilities: answers nothing, from the moment the link is up.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::Nothing;
    let quiet_from = bench.link.last_heard().expect("something was heard");
    bench.run_for(Millis::from_millis(70_000));
    let cut = bench.cuts().first().copied().expect("a cut");
    let silence = cut.since(quiet_from).expect("after").as_millis();
    assert!(
        (CUT_AFTER.as_millis()..=CUT_AFTER.as_millis() + 20).contains(&silence),
        "cut after {silence} ms"
    );
    assert!(
        bench
            .events()
            .iter()
            .any(|(_, e)| *e == LinkEvent::PowerCycled { count: 1 })
    );
    // The rail came back and the module was given its boot.
    assert_eq!(bench.rail.lines().rail, RailLine::On);
    assert!(bench.module_booted);
}
#[test]
fn l_112_the_third_cycle_in_an_hour_leaves_the_rail_on_and_raises_unrecoverable_once_on_revision_a()
{
    // Capabilities: answers nothing, from boot: a module that never speaks.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::Nothing,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(15 * 60 * 1_000));
    let cycles: Vec<u8> = bench
        .events()
        .iter()
        .filter_map(|(_, e)| match e {
            LinkEvent::PowerCycled { count } => Some(*count),
            LinkEvent::LinkLost | LinkEvent::Unrecoverable => None,
        })
        .collect();
    assert_eq!(cycles, vec![1, 2, 3], "three cycles, each counted");
    let raised = bench
        .events()
        .iter()
        .filter(|(_, e)| *e == LinkEvent::Unrecoverable)
        .count();
    assert_eq!(raised, 1, "the third rung raised once, not every minute");
    assert_eq!(
        bench.rail.lines().rail,
        RailLine::On,
        "revision A leaves the rail on"
    );
    assert!(!bench.link.is_up());
}

#[test]
fn l_113_the_ladder_is_suspended_while_an_install_is_in_flight() {
    // Capabilities: answers nothing, from boot.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::Nothing,
        ..Capabilities::default()
    });
    bench.install_in_flight = true;
    bench.run_for(Millis::from_millis(180_000));
    assert!(
        bench.cuts().is_empty(),
        "no cut while a release is being written"
    );
    bench.install_in_flight = false;
    bench.run_for(Millis::from_millis(200));
    assert_eq!(
        bench.cuts().len(),
        1,
        "the cut the moment the window is over"
    );
}

#[test]
fn l_113_an_install_in_flight_suspends_the_first_rung_too() {
    // Capabilities: answers nothing once the link is up, while a release
    // is being written.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(3_000));
    assert!(bench.link.is_up());
    bench.comms.capabilities().answers = Answers::Nothing;
    bench.install_in_flight = true;
    bench.run_for(Millis::from_millis(30_000));
    assert!(
        bench.link.is_up(),
        "no link loss while a release is written"
    );
    assert!(bench.drops().is_empty());
    assert!(bench.events().is_empty(), "nothing recorded");
    bench.install_in_flight = false;
    bench.run_for(Millis::from_millis(200));
    assert_eq!(
        bench.drops().first().map(|(_, why)| *why),
        Some(DropReason::LinkLost),
        "the first rung the moment the install is over"
    );
}

#[test]
fn l_015_a_link_up_unanswered_goes_again_with_the_same_id_three_times_then_is_given_up() {
    // Capabilities: answers nothing, from boot.
    let mut bench = Bench::new(Capabilities {
        answers: Answers::Nothing,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(3_000));
    let statements: Vec<(u64, Outgoing)> = bench
        .sent(is_link_up)
        .into_iter()
        .map(|(at, out)| (since_boot(at), out))
        .collect();
    let ids: Vec<u32> = statements
        .iter()
        .filter_map(|(_, out)| match out {
            Outgoing::LinkUp { req_id } => Some(req_id.0),
            _ => None,
        })
        .collect();
    assert!(
        ids.len() >= 4,
        "three attempts and a fresh statement: {ids:?}"
    );
    assert_eq!(ids[0], ids[1]);
    assert_eq!(ids[1], ids[2]);
    assert_ne!(ids[2], ids[3], "given up, then a new request");
    let gap = statements[1].0 - statements[0].0;
    assert!((500..=520).contains(&gap), "retried after {gap} ms");
    assert!(
        bench
            .notes()
            .contains(&Note::RequestFailed(LinkMessageType::LinkUp))
    );
    // The first statement went out as the module was powered, before it
    // could hear; the attempts are what reached it, under one id, and then
    // the fresh request.
    let heard: Vec<u32> = bench
        .comms
        .heard
        .iter()
        .filter_map(|h| match h {
            Heard::LinkUp { req_id, .. } => Some(req_id.0),
            _ => None,
        })
        .collect();
    assert!(heard.len() >= 3, "{heard:?}");
    assert_eq!(heard[0], ids[0]);
    assert_eq!(heard[1], ids[0]);
    assert_eq!(*heard.last().expect("one"), ids[3]);
}
#[test]
fn l_013_request_ids_come_from_our_own_counter_and_climb() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(6_500));
    let ids: Vec<u32> = bench
        .asked
        .iter()
        .filter_map(|(_, action)| match action {
            Action::Send(Outgoing::LinkUp { req_id } | Outgoing::Heartbeat { req_id }) => {
                Some(req_id.0)
            }
            _ => None,
        })
        .collect();
    assert!(ids.len() >= 3);
    // A retry keeps its id (L-015); every new request takes the next.
    for pair in ids.windows(2) {
        assert!(pair[1] >= pair[0], "ids never fall back: {ids:?}");
    }
    let distinct: std::collections::BTreeSet<u32> = ids.iter().copied().collect();
    assert!(distinct.len() >= 3, "{ids:?}");
    // Their ids are theirs: the peer started at 1 too, and nothing collided
    // because nothing matches on the other side's counter.
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::HeartbeatAck { .. }))
    );
}
#[test]
fn f_031_bytes_that_are_not_frames_are_counted_per_module_boot_and_noted_at_link_up() {
    // Capabilities: rom_text.
    let mut bench = Bench::new(Capabilities {
        rom_text: 200,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.link.is_up());
    assert!(bench.noise > 0, "the ROM's text refused as frames");
    let noted: Vec<u32> = bench
        .notes()
        .iter()
        .filter_map(|note| match note {
            Note::RomText { count } => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(noted, vec![bench.noise], "counted once, at the statement");
    // A quiet link adds nothing to the next boot's count.
    bench.comms.capabilities().rom_text = 0;
    let bytes = bench.comms.boot(bench.now).expect("the peer builds it");
    bench.feed(&bytes);
    let noted_again: Vec<u32> = bench
        .notes()
        .iter()
        .filter_map(|note| match note {
            Note::RomText { count } => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(noted_again.len(), 1, "nothing to note on a clean boot");
}

#[test]
fn l_001_a_frame_from_the_wrong_side_is_refused_with_256_on_session_zero_and_request_zero() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    let bytes = bench
        .comms
        .send_from_the_wrong_side(bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    let refusal = bench
        .comms
        .heard
        .iter()
        .find_map(|h| match h {
            Heard::Refusal {
                code,
                session,
                req_id,
            } => Some((*code, *session, req_id.0)),
            _ => None,
        })
        .expect("a refusal");
    // L-181: session and request both zero.
    assert_eq!(refusal, (256, 0, 0));
    assert!(bench.link.is_up(), "a refused frame is not a dead link");
}

#[test]
fn l_012_a_link_local_frame_on_a_session_is_refused_with_263() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    let bytes = bench
        .comms
        .beat_on_a_session(3, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.comms.heard.iter().any(|h| matches!(
        h,
        Heard::Refusal {
            code: 263,
            session: 0,
            ..
        }
    )));
}

#[test]
fn a_connection_before_the_session_layer_is_refused_as_a_full_table() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    let bytes = bench
        .comms
        .announce_connection(1, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.comms.heard.iter().any(|h| matches!(
        h,
        Heard::Other {
            opcode: 0xE2,
            outcome: Some(2),
            ..
        }
    )));
}

#[test]
fn a_time_offer_before_the_clock_exists_is_refused_as_implausible() {
    // Capabilities: none.
    let mut bench = Bench::new(Capabilities::default());
    bench.run_for(Millis::from_millis(1_000));
    let bytes = bench
        .comms
        .offer_time(1_800_000_000_000, bench.now)
        .expect("the peer builds it");
    bench.feed(&bytes);
    assert!(bench.comms.heard.iter().any(|h| matches!(
        h,
        Heard::Other {
            opcode: 0xE6,
            outcome: Some(2),
            ..
        }
    )));
}

#[test]
fn p_031_a_request_whose_body_does_not_decode_is_neither_heard_nor_answered() {
    // Capabilities: none.
    for (kind, ack) in [
        (LinkMessageType::ClientConnected, 0xE2),
        (LinkMessageType::ClientDisconnected, 0xE3),
        (LinkMessageType::TimeOffer, 0xE6),
    ] {
        let mut bench = Bench::new(Capabilities::default());
        bench.run_for(Millis::from_millis(1_000));
        assert!(bench.link.is_up());
        // One step of silence, so the last thing heard is behind the clock
        // and a frame counted as heard would move it.
        bench.now = bench.now.after(STEP).expect("the clock has room");
        let before = bench.link.last_heard();
        assert_ne!(before, Some(bench.now));
        let bytes = bench
            .comms
            .request_with_no_body(kind, bench.now)
            .expect("the peer builds it");
        bench.feed(&bytes);
        assert_eq!(
            bench.link.last_heard(),
            before,
            "{kind:?}: a body that is not the message keeps no link alive"
        );
        assert!(
            !bench
                .comms
                .heard
                .iter()
                .any(|h| matches!(h, Heard::Other { opcode, .. } if *opcode == ack)),
            "{kind:?}: nothing is answered"
        );
        assert!(
            bench
                .notes()
                .iter()
                .any(|note| matches!(note, Note::Malformed(noted) if *noted == kind)),
            "{kind:?}: noted on the probe, never answered"
        );
    }
}

#[test]
fn a_statement_claiming_to_be_a_controller_is_refused_and_brings_nothing_up() {
    // Capabilities: claims to be a controller.
    let mut bench = Bench::new(Capabilities {
        claims: Claims::Controller,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert!(!bench.link.is_up());
    assert!(bench.notes().contains(&Note::WrongRole));
    assert!(
        bench
            .comms
            .heard
            .iter()
            .any(|h| matches!(h, Heard::Refusal { code: 256, .. }))
    );
}

#[test]
fn a_late_peer_is_still_a_peer_inside_the_timeout() {
    // Capabilities: delay 300 ms.
    let mut bench = Bench::new(Capabilities {
        delay: Some(Millis::from_millis(300)),
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(10_000));
    assert!(bench.link.is_up());
    assert!(bench.drops().is_empty());
    assert!(
        !bench
            .notes()
            .contains(&Note::RequestFailed(LinkMessageType::LinkUp))
    );
}

#[test]
fn the_resynchroniser_recovers_inside_one_delimiter_after_a_thousand_cut_frames() {
    // Capabilities: a cut frame before each.
    let mut bench = Bench::new(Capabilities {
        frames: Frames::CutBeforeEach,
        ..Capabilities::default()
    });
    bench.run_for(Millis::from_millis(1_000));
    assert!(bench.link.is_up(), "up through a cut statement");
    let before = bench.noise;
    let sent_before = bench.comms.sent.len();
    for _ in 0..1_000 {
        let bytes = bench
            .comms
            .heartbeat(bench.now)
            .expect("the peer builds it");
        bench.feed(&bytes);
        bench.run_for(Millis::from_millis(10));
    }
    // One refusal per frame the peer sent: the thousand, and the beats and
    // acknowledgements of its own it sent meanwhile. Recovered inside one
    // delimiter every time, or the count would run ahead of the frames.
    let sent = bench.comms.sent.len() - sent_before;
    assert!(sent >= 1_000);
    assert_eq!(
        bench.noise - before,
        u32::try_from(sent).expect("fits"),
        "every cut frame refused, once"
    );
    let answered = bench
        .comms
        .heard
        .iter()
        .filter(|h| matches!(h, Heard::HeartbeatAck { .. }))
        .count();
    assert!(
        answered >= 1_000,
        "every whole beat behind a cut one was answered: {answered}"
    );
    assert!(bench.link.is_up());
}
