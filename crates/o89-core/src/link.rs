//! The link to the comms processor, as the controller keeps it.
//!
//! A state machine that takes decoded frames and ticks and answers typed
//! actions the adapter performs: send this, drop every connection, cut the
//! rail, write this record. The bytes, the UART and the rail pin are the
//! adapter's; nothing here names one. What it holds is the whole of the
//! link-local rulebook on this side: linked once its own `LinkUp` is
//! answered and not before (L-030, L-033), the peer's identity and a
//! changed `boot_id` dropping every connection (L-040, L-041), version
//! agreement (L-050, L-051), a heartbeat every two seconds answered at once
//! (L-100), the ladder measured on the tick from the peer's last answer to
//! a request of ours, never from what it says of its own accord (L-110,
//! L-111, L-112 through the rail sequencer, L-113 while an install is in
//! flight), the request counter with its four outstanding and its three
//! attempts (L-013, L-014, L-015), and the ROM's boot text counted per
//! module boot (F-031).
//!
//! **Before the session layer exists**, a connection the comms processor
//! announces is refused as a full table, which a table of no rows is, a
//! handle it releases is unknown, and a time offer is refused as
//! implausible, because a controller that cannot yet take a time cannot
//! find one plausible; the policies those answers stand in for arrive with
//! M4 and replace the arms below, which is what the exhaustive match on the
//! message type is for.
//!
//! cites: F-031, F-039

use km43::{
    ClientConnected, ClientDisconnected, ClientDown, ClientDownAck, ClientUp, ClientUpAck,
    ClockOffer, EventKind, FrameWriter, Heartbeat, Intake, LinkEnvelope, LinkError, LinkErrorCode,
    LinkMessageType, LinkUp, MAX_INFLIGHT, MAX_LINK_TEXT, ReqId, Side, TimeOffer, TimeVerdict,
    Version, arriving,
};
use sha2::{Digest, Sha256};

use crate::BootCount;
use crate::rail::Recovery;
use crate::text::Text;
use crate::tick::{Millis, Tick};
use o89_link::{
    Beats, LINK_ENVELOPE, Overdue, Requests, crosses_mismatch, frame_refusal, is_peer_refusal,
    link_header, refused_before_link,
};

pub use o89_link::{
    ATTEMPTS, DEAD_AFTER, EncodeError, HEARTBEAT_PERIOD, LINKUP_PERIOD, OURS, RESPONSE_TIMEOUT,
};

/// Sixty seconds of silence: the rail is cut (L-111).
pub const CUT_AFTER: Millis = Millis::from_millis(60_000);

/// A text field on this link: 32 bytes (`fw`, `hw`).
pub type LinkText = Text<MAX_LINK_TEXT>;

/// L-040's `boot_id`, on a part with no RNG.
///
/// SHA-256 over the part's unique id and the boot count, truncated to the
/// width the field has. The rule's property is that the number rests on
/// nothing that survives a reboot; the boot count climbs on the FRAM at
/// every boot, the unique id keeps two units apart, and the hash keeps it
/// from reading as a counter to a peer that would be tempted to predict
/// it. Two boots share a value with the chance two random draws would,
/// one in 2^32, which is the bound the field's width gives any scheme.
/// Nothing on this link rests on its secrecy (L-020), so no secret goes
/// into it: a unit without one still boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BootId(u32);

impl BootId {
    /// The id for this boot, from what makes it unique. A count is
    /// required by the signature: a boot without a written one, a part
    /// whose FRAM did not answer or whose new count did not land, has no
    /// id to state and no link (F-039).
    #[must_use]
    pub fn derive(unique: &[u8], boot: BootCount) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(unique);
        hasher.update(boot.get().to_le_bytes());
        let digest = hasher.finalize();
        let head: [u8; 4] = digest
            .get(..4)
            .and_then(|four| four.try_into().ok())
            .unwrap_or([0; 4]);
        Self(u32::from_le_bytes(head))
    }

    /// The number, as it goes out in key 5.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// What this side says about itself in every `LinkUp` it sends or answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Identity {
    /// Key 4: this firmware's version.
    pub fw: LinkText,
    /// Key 6: the board revision.
    pub hw: LinkText,
    /// Key 5.
    pub boot_id: BootId,
}

/// The peer, as its last `LinkUp` or acknowledgement stated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// Keys 1 and 2, as the peer speaks it.
    pub version: Version,
    /// Key 4, which the controller reports as `fw_comms` (L-031).
    pub fw: LinkText,
    /// Key 6.
    pub hw: LinkText,
    /// Key 5.
    pub boot_id: u32,
    /// Key 7: the credential version it has cached, 0 if none.
    pub net_version: Option<u32>,
}

/// How far the two versions agree (L-050, L-051).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compat {
    /// The lower of the two minors, under one major.
    Agreed(Version),
    /// Different majors: `LinkUp`, `Heartbeat` and a release's
    /// acknowledgement only, everything else refused with 261.
    MajorMismatch {
        /// What the peer speaks.
        theirs: Version,
    },
}

/// Why every connection is being dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DropReason {
    /// Six seconds without a heartbeat (L-110).
    LinkLost,
    /// The comms processor came back with another `boot_id` (L-041).
    CommsRebooted,
    /// The bench took the module into its ROM (F-038).
    ModuleTaken,
}

/// A record the ring gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LinkEvent {
    /// Comms link lost, `0x0801`.
    LinkLost,
    /// Comms power cycled, `0x0802`, with the cycles in the last hour.
    PowerCycled {
        /// This cycle included.
        count: u8,
    },
    /// Comms unrecoverable, `0x0803`: the third rung, executed or not.
    Unrecoverable,
}

impl LinkEvent {
    /// The registry's kind.
    #[must_use]
    pub const fn kind(self) -> EventKind {
        match self {
            Self::LinkLost => EventKind::COMMS_LINK_LOST,
            Self::PowerCycled { .. } => EventKind::COMMS_POWER_CYCLED,
            Self::Unrecoverable => EventKind::COMMS_UNRECOVERABLE,
        }
    }
}

/// Something for the log on the probe, never for the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// Bytes that were not frames since the module last booted (F-031):
    /// the ROM's text at its own baud, or a link that is wrong.
    RomText {
        /// Refusals and abandoned runs, counted.
        count: u32,
    },
    /// A frame refused back to the peer with this code.
    Refused(LinkErrorCode),
    /// A request of ours unanswered after every attempt (L-015).
    RequestFailed(LinkMessageType),
    /// An acknowledgement nothing of ours is waiting for.
    UnexpectedAck(LinkMessageType),
    /// A body that did not decode; nothing is answered (P-031).
    Malformed(LinkMessageType),
    /// The peer refused a frame of ours with this code, or with a body that
    /// did not read; nothing is answered (L-181).
    PeerRefused(Option<u16>),
    /// A `LinkUp` claiming to be a controller.
    WrongRole,
}

/// A frame to put on the wire, described rather than encoded so the
/// adapter and the simulator share one [`Link::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outgoing {
    /// Our statement.
    LinkUp {
        /// From our counter.
        req_id: ReqId,
    },
    /// Our statement, answering theirs.
    LinkUpAck {
        /// Theirs, echoed.
        req_id: ReqId,
    },
    /// Still here.
    Heartbeat {
        /// From our counter.
        req_id: ReqId,
    },
    /// Answering theirs, at once.
    HeartbeatAck {
        /// Theirs, echoed.
        req_id: ReqId,
    },
    /// Answering a connection they announced.
    ClientUpAck {
        /// Theirs, echoed.
        req_id: ReqId,
        /// What became of it.
        outcome: ClientConnected,
    },
    /// Answering a connection they released.
    ClientDownAck {
        /// Theirs, echoed.
        req_id: ReqId,
        /// What became of it.
        outcome: ClientDisconnected,
    },
    /// Answering a time offer.
    TimeVerdict {
        /// Theirs, echoed.
        req_id: ReqId,
        /// What became of it.
        outcome: TimeOffer,
    },
    /// A refusal, with session and request both zero (L-181).
    Refuse {
        /// Why.
        code: LinkErrorCode,
    },
}

/// What the adapter is to do, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an action nobody performs is a rule nothing did"]
pub enum Action {
    /// Put this frame on the wire.
    Send(Outgoing),
    /// Every connection and every session bound to one goes.
    DropConnections(DropReason),
    /// Ask the rail sequencer to recover, and report what it said
    /// through [`Link::rail`].
    CutRail,
    /// A record for the ring.
    Log(LinkEvent),
    /// A line for the probe.
    Note(Note),
}

/// How many actions one call can hand out. The most is a comms `LinkUp`
/// with a new `boot_id` arriving on a dead link: the ROM-text note, the
/// drop, the acknowledgement; a tick can add a cut and a `LinkUp` of its
/// own. Eight is room for every combination and a dropped action is a
/// bug, counted rather than hidden.
pub const ACTIONS: usize = 8;

/// The actions of one call, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "actions nobody performs are rules nothing did"]
pub struct Actions {
    items: [Option<Action>; ACTIONS],
    len: usize,
    dropped: u8,
}

impl Actions {
    /// Nothing to do.
    pub const NONE: Self = Self {
        items: [None; ACTIONS],
        len: 0,
        dropped: 0,
    };

    fn push(&mut self, action: Action) {
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = Some(action);
            self.len = self.len.saturating_add(1);
        } else {
            debug_assert!(false, "more than {ACTIONS} actions in one call");
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// The actions, in the order they are to be performed.
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.items.iter().take(self.len).flatten()
    }

    /// How many.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Nothing to do.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Actions that did not fit, which a build with the assertion on
    /// would have stopped at.
    #[must_use]
    pub const fn dropped(&self) -> u8 {
        self.dropped
    }
}

impl<'a> IntoIterator for &'a Actions {
    type Item = &'a Action;
    type IntoIter = core::iter::Flatten<core::iter::Take<core::slice::Iter<'a, Option<Action>>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter().take(self.len).flatten()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing exchanged, or the link fell: `LinkUp` goes out on its
    /// cadence once the module has been powered, and not before, because
    /// there is no UART before the rail has settled (F-006) and nothing to
    /// hear a statement before then.
    Down { next_linkup: Option<Tick> },
    /// Both sides have stated themselves.
    Up {
        peer: Peer,
        compat: Compat,
        next_beat: Tick,
    },
}

/// The link, on the controller's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    identity: Identity,
    boot: Tick,
    phase: Phase,
    /// When the peer last answered a request of ours, a `LinkUp` or a
    /// heartbeat (L-100): the ladder counts silence from this or from the
    /// module's last power-up, whichever is later. What the peer says of its
    /// own accord does not count: its statements and heartbeats prove it can
    /// talk, not that it can hear, and a comms processor whose receiver has
    /// hung keeps talking.
    last_heard: Option<Tick>,
    /// The peer as its last accepted statement described it, kept through
    /// a drop: field 4 is `fw_comms` in every `Hello` answer (L-031), and a
    /// module that is off still has a firmware.
    last_peer: Option<Peer>,
    /// When the module's rail last settled: silence is measured from
    /// whichever of this and `last_heard` is later, so a module that was
    /// just powered gets its sixty seconds to boot and speak.
    module_up_since: Tick,
    /// The earliest moment the ladder may ask for a cut.
    earliest_cut: Tick,
    /// A cut was asked for and the rail has not settled since.
    cut_pending: bool,
    /// The third rung was raised and not yet cleared by the link coming up.
    raised: bool,
    /// Our requests in flight (L-014, L-015).
    requests: Requests<MAX_INFLIGHT>,
    /// Our last heartbeats: only the first answer to one of these is the
    /// peer heard (L-100).
    beats: Beats,
    next_req_id: u32,
    /// Refusals and abandoned runs since the module last booted (F-031).
    noise: u32,
    /// Allocated connection rows, for the heartbeat (L-101): none until M4.
    conns: u8,
}

impl Link {
    /// A link at boot: down, saying nothing until [`Link::module_settled`]
    /// says the module is powered. On a board whose rail is already up at
    /// boot the adapter says so at once.
    #[must_use]
    pub fn new(identity: Identity, now: Tick) -> Self {
        Self {
            identity,
            boot: now,
            phase: Phase::Down { next_linkup: None },
            last_heard: None,
            last_peer: None,
            module_up_since: now,
            earliest_cut: now.after(CUT_AFTER).unwrap_or(now),
            cut_pending: false,
            raised: false,
            requests: Requests::NONE,
            beats: Beats::NONE,
            next_req_id: 1,
            noise: 0,
            conns: 0,
        }
    }

    /// Whether `LinkUp` has crossed in both directions (L-033).
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up { .. })
    }

    /// The peer, while the link is up.
    #[must_use]
    pub const fn peer(&self) -> Option<&Peer> {
        self.last_peer.as_ref()
    }

    /// How far the versions agree, while the link is up.
    #[must_use]
    pub const fn compat(&self) -> Option<Compat> {
        match self.phase {
            Phase::Up { compat, .. } => Some(compat),
            Phase::Down { .. } => None,
        }
    }

    /// What this side says about itself.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The adapter saw bytes between delimiters that were not a frame, or a
    /// run nothing finished: counted per module boot (F-031).
    pub fn noise(&mut self) {
        self.noise = self.noise.saturating_add(1);
    }

    /// The rail is up and `EN` released: the module is booting. The ladder's
    /// clock restarts, what the ROM said since the last boot is noted, and
    /// this side states itself (L-030): the module may not hear it yet,
    /// which is what the attempts are for.
    pub fn module_settled(&mut self, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        self.note_rom_text(&mut actions);
        self.cut_pending = false;
        self.module_up_since = now;
        self.earliest_cut = now.after(CUT_AFTER).unwrap_or(now);
        if let Phase::Down { .. } = self.phase {
            self.announce(now, &mut actions);
        }
        actions
    }

    /// The last valid frame from the peer, from which silence is measured.
    #[must_use]
    pub const fn last_heard(&self) -> Option<Tick> {
        self.last_heard
    }

    /// The bench took the module into its ROM (F-038). Whatever the link
    /// was, it is down and every connection goes, and nothing is recorded
    /// as lost, because the controller did it on purpose; nothing is said
    /// and no silence is measured until [`Link::module_settled`] reports the
    /// module reset normally.
    pub fn module_taken(&mut self) -> Actions {
        let mut actions = Actions::NONE;
        if let Phase::Up { .. } = self.phase {
            actions.push(Action::DropConnections(DropReason::ModuleTaken));
        }
        self.phase = Phase::Down { next_linkup: None };
        // A request to a module in its ROM will never be answered, and no
        // answer to a beat before it counts.
        self.requests.forget();
        self.beats.forget();
        self.cut_pending = false;
        actions
    }

    /// What the rail sequencer answered a [`Action::CutRail`] with.
    pub fn rail(&mut self, recovery: Recovery, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        self.earliest_cut = now.after(CUT_AFTER).unwrap_or(now);
        match recovery {
            Recovery::Cycling { count, .. } => {
                actions.push(Action::Log(LinkEvent::PowerCycled { count }));
            }
            Recovery::LeftOnAndRaised => {
                self.cut_pending = false;
                if !self.raised {
                    self.raised = true;
                    actions.push(Action::Log(LinkEvent::Unrecoverable));
                }
            }
            Recovery::Busy => {}
        }
        actions
    }

    /// A frame from the peer, decoded by the adapter.
    pub fn received(&mut self, envelope: LinkEnvelope<'_>, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        if is_peer_refusal(&envelope) {
            // The peer refused something of ours. It stays on the UART and is
            // never answered with another error (L-181); it carries no
            // request id to match, so nothing waits on it. An error with a
            // session or a request id is a client's frame, and goes to the
            // intake like one.
            actions.push(Action::Note(Note::PeerRefused(Self::error_code(envelope))));
            return actions;
        }
        let kind = match arriving(envelope.opcode(), Side::Controller, envelope.session()) {
            Intake::Act(kind) => kind,
            Intake::Refuse(code) => {
                Self::refuse(code, &mut actions);
                return actions;
            }
        };
        let req_id = envelope.req_id();
        if let Phase::Up {
            compat: Compat::MajorMismatch { .. },
            ..
        } = self.phase
            && !crosses_mismatch(Side::Controller, kind)
        {
            Self::refuse(LinkErrorCode::LinkMajorMismatch, &mut actions);
            return actions;
        }
        match kind {
            LinkMessageType::LinkUp => match LinkUp::decode(envelope) {
                Ok(theirs) => {
                    if let Some((peer, compat)) = Self::accept(&theirs, &mut actions) {
                        actions.push(Action::Send(Outgoing::LinkUpAck { req_id }));
                        self.stated(peer, compat, now, &mut actions);
                    }
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            },
            LinkMessageType::LinkUpAck => {
                if !self.requests.awaits(req_id, LinkMessageType::LinkUp) {
                    actions.push(Action::Note(Note::UnexpectedAck(kind)));
                    return actions;
                }
                // The request is consumed only by an acknowledgement that
                // validates: a malformed one, or one claiming the wrong
                // role, leaves it to its retries (L-015).
                match LinkUp::decode(envelope) {
                    Ok(theirs) => {
                        if let Some((peer, compat)) = Self::accept(&theirs, &mut actions) {
                            let _ = self.requests.answered(req_id, LinkMessageType::LinkUp);
                            self.linked(peer, compat, now, &mut actions);
                        }
                    }
                    Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
                }
            }
            LinkMessageType::Heartbeat => match Heartbeat::decode(envelope) {
                Ok(_) => {
                    // Answered at once, and not heard: it proves the peer can
                    // talk, not that it can hear (L-100).
                    actions.push(Action::Send(Outgoing::HeartbeatAck { req_id }));
                    if let Phase::Down { next_linkup } = &mut self.phase {
                        // A peer that beats is a peer to state ourselves to.
                        *next_linkup = Some(now);
                    }
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            },
            LinkMessageType::HeartbeatAck => match Heartbeat::decode(envelope) {
                // Heard only as the first answer to a beat of ours, which it
                // uses up: an answer to nothing, or one replayed, proves
                // nothing about whether the peer hears.
                Ok(_) => {
                    if self.beats.answered(req_id) {
                        self.heard(now);
                    } else {
                        actions.push(Action::Note(Note::UnexpectedAck(kind)));
                    }
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            },
            LinkMessageType::ClientConnected
            | LinkMessageType::ClientDisconnected
            | LinkMessageType::TimeOffer => self.answer(kind, envelope, &mut actions),
            LinkMessageType::CloseConnectionAck
            | LinkMessageType::NetConfigAck
            | LinkMessageType::CommsReleaseAck
            | LinkMessageType::EnterDownloadAck => {
                // Requests this firmware does not send yet, so nothing
                // waits; the download request is the bench tool's, through
                // its own path, and an acknowledgement nobody asked for is
                // not a heartbeat.
                actions.push(Action::Note(Note::UnexpectedAck(kind)));
            }
            LinkMessageType::ClientConnectedAck
            | LinkMessageType::ClientDisconnectedAck
            | LinkMessageType::CloseConnection
            | LinkMessageType::NetConfig
            | LinkMessageType::TimeOfferAck
            | LinkMessageType::CommsRelease
            | LinkMessageType::EnterDownload => {
                // `arriving` refuses these at this side; an arm so that a
                // change to the direction table lands here and not in a
                // wildcard.
                Self::refuse(LinkErrorCode::WrongSide, &mut actions);
            }
        }
        actions
    }

    /// The three requests the peer makes, each body read before it is
    /// answered: a frame that is not the message it claims gets no
    /// acknowledgement the peer could act on (P-031), and none of them is a
    /// heartbeat. Before the link is up only the handshake is admitted
    /// (L-033): `ClientConnected` has an outcome for that, the others are
    /// refused with 258. Until the session layer and the clock exist every
    /// answer is a refusal the peer can act on, never silence.
    fn answer(&mut self, kind: LinkMessageType, envelope: LinkEnvelope<'_>, actions: &mut Actions) {
        if !self.is_up() && refused_before_link(Side::Controller, kind) {
            Self::refuse(LinkErrorCode::BeforeLinkUp, actions);
            return;
        }
        let req_id = envelope.req_id();
        let outgoing = match kind {
            LinkMessageType::ClientConnected => ClientUp::decode(envelope).map(|_| {
                let outcome = if self.is_up() {
                    ClientConnected::RefusedTableFull
                } else {
                    ClientConnected::RefusedLinkNotUp
                };
                Outgoing::ClientUpAck { req_id, outcome }
            }),
            LinkMessageType::ClientDisconnected => {
                ClientDown::decode(envelope).map(|_| Outgoing::ClientDownAck {
                    req_id,
                    outcome: ClientDisconnected::UnknownHandle,
                })
            }
            LinkMessageType::TimeOffer => {
                ClockOffer::decode(envelope).map(|_| Outgoing::TimeVerdict {
                    req_id,
                    outcome: TimeOffer::RefusedImplausible,
                })
            }
            LinkMessageType::LinkUp
            | LinkMessageType::LinkUpAck
            | LinkMessageType::Heartbeat
            | LinkMessageType::HeartbeatAck
            | LinkMessageType::ClientConnectedAck
            | LinkMessageType::ClientDisconnectedAck
            | LinkMessageType::CloseConnection
            | LinkMessageType::CloseConnectionAck
            | LinkMessageType::NetConfig
            | LinkMessageType::NetConfigAck
            | LinkMessageType::TimeOfferAck
            | LinkMessageType::CommsRelease
            | LinkMessageType::CommsReleaseAck
            | LinkMessageType::EnterDownload
            | LinkMessageType::EnterDownloadAck => {
                // Not a request of the peer's; `received` never sends these
                // here, and an arm keeps a new opcode from landing in a
                // wildcard.
                actions.push(Action::Note(Note::UnexpectedAck(kind)));
                return;
            }
        };
        match outgoing {
            Ok(outgoing) => actions.push(Action::Send(outgoing)),
            Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
        }
    }

    /// Time passed. `install_in_flight` is L-113: a release being written
    /// suspends the ladder.
    pub fn tick(&mut self, now: Tick, install_in_flight: bool) -> Actions {
        let mut actions = Actions::NONE;
        if self.cut_pending {
            // The rail task is cycling the module: nothing sent now reaches
            // a peer, and a request retried into the dark only burns its
            // attempts. The ladder resumes when the rail reports.
            return actions;
        }
        if self.cut_due(now, install_in_flight) {
            // The cut goes alone: the module is about to lose its power, and
            // any frame queued with it, a statement or a retry, would only
            // hold it back behind the transmitter.
            self.cut_pending = true;
            actions.push(Action::CutRail);
            return actions;
        }
        self.retry(now, &mut actions);
        match self.phase {
            Phase::Up { next_beat, .. } => {
                let silent = self
                    .last_heard
                    .and_then(|heard| now.since(heard))
                    .is_some_and(|silence| silence.as_millis() >= DEAD_AFTER.as_millis());
                // L-113 suspends the whole ladder, its first rung included.
                if silent && !install_in_flight {
                    self.down(DropReason::LinkLost, now, &mut actions);
                    actions.push(Action::Log(LinkEvent::LinkLost));
                } else if now.since(next_beat).is_some() {
                    self.beat(now, &mut actions);
                }
            }
            Phase::Down { next_linkup } => {
                // No `next_linkup` is a module not yet powered: nothing to
                // say to it.
                if next_linkup.is_some_and(|at| now.since(at).is_some()) {
                    self.announce(now, &mut actions);
                }
            }
        }
        actions
    }

    /// Whether the ladder's cut is due (L-111): unlinked with the module
    /// powered, sixty seconds since the peer last answered or the module
    /// last came up, past the earliest cut, and no install in flight
    /// (L-113).
    fn cut_due(&self, now: Tick, install_in_flight: bool) -> bool {
        let Phase::Down {
            next_linkup: Some(_),
        } = self.phase
        else {
            return false;
        };
        now.since(self.silence_since())
            .is_some_and(|silence| silence.as_millis() >= CUT_AFTER.as_millis())
            && !install_in_flight
            && now.since(self.earliest_cut).is_some()
    }

    /// Encode an outgoing frame, delimiter included, into `dst`.
    pub fn encode(
        &self,
        outgoing: Outgoing,
        now: Tick,
        writer: &mut FrameWriter,
        dst: &mut [u8],
    ) -> Result<usize, EncodeError> {
        let mut envelope = [0u8; LINK_ENVELOPE];
        let len = match outgoing {
            Outgoing::LinkUp { req_id } => {
                self.link_up(LinkMessageType::LinkUp, req_id, &mut envelope)
            }
            Outgoing::LinkUpAck { req_id } => {
                self.link_up(LinkMessageType::LinkUpAck, req_id, &mut envelope)
            }
            Outgoing::Heartbeat { req_id } => {
                self.heartbeat(LinkMessageType::Heartbeat, req_id, now, &mut envelope)
            }
            Outgoing::HeartbeatAck { req_id } => {
                self.heartbeat(LinkMessageType::HeartbeatAck, req_id, now, &mut envelope)
            }
            Outgoing::ClientUpAck { req_id, outcome } => ClientUpAck { outcome }.write(
                link_header(LinkMessageType::ClientConnectedAck, req_id),
                &mut envelope,
            ),
            Outgoing::ClientDownAck { req_id, outcome } => ClientDownAck { outcome }.write(
                link_header(LinkMessageType::ClientDisconnectedAck, req_id),
                &mut envelope,
            ),
            Outgoing::TimeVerdict { req_id, outcome } => TimeVerdict { outcome }.write(
                link_header(LinkMessageType::TimeOfferAck, req_id),
                &mut envelope,
            ),
            Outgoing::Refuse { code } => {
                return frame_refusal(code, writer, dst);
            }
        }
        .map_err(|_: LinkError| EncodeError::Body)?;
        let payload = envelope.get(..len).ok_or(EncodeError::Body)?;
        writer.write(payload, dst).map_err(EncodeError::Frame)
    }

    fn link_up(
        &self,
        kind: LinkMessageType,
        req_id: ReqId,
        dst: &mut [u8],
    ) -> Result<usize, LinkError> {
        LinkUp {
            version: OURS,
            role: Side::Controller,
            fw: self.identity.fw.as_str(),
            boot_id: self.identity.boot_id.get(),
            hw: self.identity.hw.as_str(),
            net_version: None,
        }
        .write(link_header(kind, req_id), dst)
    }

    fn heartbeat(
        &self,
        kind: LinkMessageType,
        req_id: ReqId,
        now: Tick,
        dst: &mut [u8],
    ) -> Result<usize, LinkError> {
        Heartbeat {
            uptime_s: self.uptime_s(now),
            conns: self.conns,
        }
        .write(link_header(kind, req_id), dst)
    }

    /// Seconds since boot, saturating (key 1 of a heartbeat).
    fn uptime_s(&self, now: Tick) -> u32 {
        now.since(self.boot)
            .map_or(0, Millis::as_secs)
            .try_into()
            .unwrap_or(u32::MAX)
    }

    /// The peer stated itself, in a request or in an answer. Whether the
    /// link is to acknowledge, which it is not when the statement is refused.
    /// A statement read for what it claims: the role this side expects and
    /// texts that fit. What it describes, if it is one this side can take.
    fn accept(theirs: &LinkUp<'_>, actions: &mut Actions) -> Option<(Peer, Compat)> {
        if theirs.role != Side::Comms {
            actions.push(Action::Note(Note::WrongRole));
            Self::refuse(LinkErrorCode::WrongSide, actions);
            return None;
        }
        let (Ok(fw), Ok(hw)) = (LinkText::new(theirs.fw), LinkText::new(theirs.hw)) else {
            actions.push(Action::Note(Note::Malformed(LinkMessageType::LinkUp)));
            return None;
        };
        let peer = Peer {
            version: theirs.version,
            fw,
            hw,
            boot_id: theirs.boot_id,
            net_version: theirs.net_version,
        };
        let compat = match OURS.agreed(theirs.version) {
            Ok(agreed) => Compat::Agreed(agreed),
            Err(_) => Compat::MajorMismatch {
                theirs: theirs.version,
            },
        };
        Some((peer, compat))
    }

    /// The peer stated itself of its own accord (L-030): recorded and
    /// answered, and never a link (L-033). A changed `boot_id` is a peer that
    /// rebooted: every connection goes (L-041), and the link with them,
    /// because the new boot has answered nothing of ours. Unlinked, this side
    /// states itself at once.
    fn stated(&mut self, peer: Peer, compat: Compat, now: Tick, actions: &mut Actions) {
        let rebooted = self
            .last_peer
            .is_some_and(|known| known.boot_id != peer.boot_id);
        self.last_peer = Some(peer);
        if rebooted && self.is_up() {
            // The common way down: every connection drops, and no answer to
            // a beat of the old boot counts (L-041, L-100).
            self.down(DropReason::CommsRebooted, now, actions);
        } else if let Phase::Up {
            peer: known,
            compat: agreed,
            ..
        } = &mut self.phase
        {
            // The same boot again changes nothing (L-030).
            *known = peer;
            *agreed = compat;
        }
        if let Phase::Down { .. } = self.phase {
            self.announce(now, actions);
        }
    }

    /// Our statement was answered (L-033): the answer carries the peer's,
    /// and answering proves it holds ours. That is the link, and it is a
    /// round trip, so the peer is heard (L-100).
    fn linked(&mut self, peer: Peer, compat: Compat, now: Tick, actions: &mut Actions) {
        if let Phase::Up { peer: known, .. } = self.phase
            && known.boot_id != peer.boot_id
        {
            self.beats.forget();
            actions.push(Action::DropConnections(DropReason::CommsRebooted));
        }
        self.note_rom_text(actions);
        self.last_peer = Some(peer);
        self.heard(now);
        self.raised = false;
        self.cut_pending = false;
        let next_beat = match self.phase {
            Phase::Up { next_beat, .. } => next_beat,
            Phase::Down { .. } => now.after(HEARTBEAT_PERIOD).unwrap_or(now),
        };
        self.phase = Phase::Up {
            peer,
            compat,
            next_beat,
        };
    }

    fn heard(&mut self, now: Tick) {
        self.last_heard = Some(now);
    }

    fn silence_since(&self) -> Tick {
        match self.last_heard {
            Some(heard) if heard.since(self.module_up_since).is_some() => heard,
            Some(_) | None => self.module_up_since,
        }
    }

    fn note_rom_text(&mut self, actions: &mut Actions) {
        if self.noise > 0 {
            actions.push(Action::Note(Note::RomText { count: self.noise }));
            self.noise = 0;
        }
    }

    fn down(&mut self, why: DropReason, now: Tick, actions: &mut Actions) {
        // A beat of the link that fell is answered by nothing that counts.
        self.beats.forget();
        self.phase = Phase::Down {
            next_linkup: Some(now),
        };
        actions.push(Action::DropConnections(why));
    }

    fn beat(&mut self, now: Tick, actions: &mut Actions) {
        if let Phase::Up { next_beat, .. } = &mut self.phase {
            *next_beat = now.after(HEARTBEAT_PERIOD).unwrap_or(now);
        }
        // Not tracked as outstanding: a heartbeat unanswered is a beat
        // missed, and three of those are the dead link (L-100), not a
        // request to retry (L-015).
        let req_id = self.take_req_id();
        self.beats.sent(req_id);
        actions.push(Action::Send(Outgoing::Heartbeat { req_id }));
    }

    fn announce(&mut self, now: Tick, actions: &mut Actions) {
        if let Phase::Down { next_linkup } = &mut self.phase {
            *next_linkup = Some(now.after(LINKUP_PERIOD).unwrap_or(now));
        }
        // One `LinkUp` outstanding at a time: a second before the first is
        // answered or given up would be two statements in flight for one
        // answer.
        if self.requests.in_flight(LinkMessageType::LinkUp) {
            return;
        }
        if let Some(req_id) = self.request(LinkMessageType::LinkUp, now) {
            actions.push(Action::Send(Outgoing::LinkUp { req_id }));
        }
    }

    /// Issue a request, or nothing when four are outstanding (L-014).
    fn request(&mut self, kind: LinkMessageType, now: Tick) -> Option<ReqId> {
        if self.requests.is_full() {
            return None;
        }
        let req_id = self.take_req_id();
        self.requests.issue(kind, req_id, now).then_some(req_id)
    }

    fn take_req_id(&mut self) -> ReqId {
        let req_id = ReqId(self.next_req_id);
        // Wraps, and may recur: nothing here carries a MAC (L-013).
        self.next_req_id = self.next_req_id.wrapping_add(1);
        req_id
    }

    /// The code an error frame carries, if its body reads.
    fn error_code(envelope: LinkEnvelope<'_>) -> Option<u16> {
        if envelope.keys() == 0 {
            return None;
        }
        let mut body = envelope.into_body();
        if body.key().ok()? != 1 {
            return None;
        }
        body.u16().ok()
    }

    /// Requests unanswered for the timeout go again with the same id, up to
    /// the attempts; past that they are given up (L-015).
    fn retry(&mut self, now: Tick, actions: &mut Actions) {
        // Bounded: each call moves one request on, and no more than
        // `MAX_INFLIGHT` are in flight to move.
        for _ in 0..MAX_INFLIGHT {
            match self.requests.overdue(now) {
                None => return,
                Some(Overdue::GivenUp { kind, .. }) => {
                    // The only request tracked before M4 is a `LinkUp`, which
                    // goes out only while unlinked, so there is no link for
                    // L-015 to take down; the first request sent while linked
                    // brings that arm, and heartbeats unanswered take a link
                    // down at six seconds meanwhile (L-100).
                    actions.push(Action::Note(Note::RequestFailed(kind)));
                }
                Some(Overdue::Resend { kind, req_id }) => match kind {
                    LinkMessageType::LinkUp => {
                        actions.push(Action::Send(Outgoing::LinkUp { req_id }));
                    }
                    LinkMessageType::LinkUpAck
                    | LinkMessageType::Heartbeat
                    | LinkMessageType::HeartbeatAck
                    | LinkMessageType::ClientConnected
                    | LinkMessageType::ClientConnectedAck
                    | LinkMessageType::ClientDisconnected
                    | LinkMessageType::ClientDisconnectedAck
                    | LinkMessageType::CloseConnection
                    | LinkMessageType::CloseConnectionAck
                    | LinkMessageType::NetConfig
                    | LinkMessageType::NetConfigAck
                    | LinkMessageType::TimeOffer
                    | LinkMessageType::TimeOfferAck
                    | LinkMessageType::CommsRelease
                    | LinkMessageType::CommsReleaseAck
                    | LinkMessageType::EnterDownload
                    | LinkMessageType::EnterDownloadAck => {
                        // Nothing else is issued as a request yet; the arm
                        // lands here when one is.
                        let _ = self.requests.answered(req_id, kind);
                    }
                },
            }
        }
    }

    fn refuse(code: LinkErrorCode, actions: &mut Actions) {
        actions.push(Action::Note(Note::Refused(code)));
        actions.push(Action::Send(Outgoing::Refuse { code }));
    }
}

#[cfg(test)]
mod tests {
    use km43::{
        Envelope, ErrorBody, FrameReader, Incoming, LinkEnvelope, MAX_FRAME, MessageType, Received,
        SessionId,
    };

    use super::*;
    use crate::{BOOT_COUNT_BYTES, Body};

    fn boot(n: u32) -> BootCount {
        let mut bytes = [0u8; BOOT_COUNT_BYTES];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        BootCount::decode(&bytes).expect("a count decodes")
    }

    fn identity() -> Identity {
        Identity {
            fw: LinkText::new("ctrl 0.0.0").expect("fits"),
            hw: LinkText::new("A rev A").expect("fits"),
            boot_id: BootId::derive(b"unit", boot(3)),
        }
    }

    /// Encode one outgoing frame and hand back its envelope's bytes and
    /// their length, through the same reader the adapter uses.
    fn envelope_of(link: &Link, outgoing: Outgoing, now: Tick) -> ([u8; MAX_FRAME], usize) {
        let mut writer = FrameWriter::new();
        let mut dst = [0u8; MAX_FRAME];
        let len = link
            .encode(outgoing, now, &mut writer, &mut dst)
            .expect("encodes");
        let mut reader = FrameReader::new();
        let mut out = [0u8; MAX_FRAME];
        let mut found = 0;
        for byte in &dst[..len] {
            if let Received::Frame(envelope) = reader.push(*byte) {
                out[..envelope.len()].copy_from_slice(envelope);
                found = envelope.len();
            }
        }
        assert!(found > 0, "a whole frame");
        (out, found)
    }

    #[test]
    fn f_039_the_boot_id_changes_with_the_boot_count_and_with_the_unit_and_never_with_ram() {
        let unit = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
        let first = BootId::derive(unit, boot(1));
        let second = BootId::derive(unit, boot(2));
        assert_ne!(first, second, "a boot later is another id");
        assert_eq!(
            first,
            BootId::derive(unit, boot(1)),
            "the same boot is the same id"
        );
        let other = BootId::derive(b"another unit", boot(1));
        assert_ne!(first, other, "another unit at the same count is another id");
    }

    #[test]
    fn l_040_a_boot_id_is_redrawn_at_every_boot_without_a_counter_showing_through() {
        let unit = b"unit";
        let mut ids = [0u32; 8];
        for (slot, n) in ids.iter_mut().zip(1..) {
            *slot = BootId::derive(unit, boot(n)).get();
        }
        for pair in ids.windows(2) {
            assert_ne!(pair[0], pair[1]);
            assert_ne!(pair[1], pair[0].wrapping_add(1), "not a counter");
        }
    }

    #[test]
    fn l_012_every_frame_this_side_writes_carries_session_zero() {
        let link = Link::new(identity(), Tick::from_millis(5_000));
        let outgoings = [
            Outgoing::LinkUp { req_id: ReqId(1) },
            Outgoing::LinkUpAck { req_id: ReqId(2) },
            Outgoing::Heartbeat { req_id: ReqId(3) },
            Outgoing::HeartbeatAck { req_id: ReqId(4) },
            Outgoing::ClientUpAck {
                req_id: ReqId(5),
                outcome: ClientConnected::RefusedTableFull,
            },
            Outgoing::ClientDownAck {
                req_id: ReqId(6),
                outcome: ClientDisconnected::UnknownHandle,
            },
            Outgoing::TimeVerdict {
                req_id: ReqId(7),
                outcome: TimeOffer::RefusedImplausible,
            },
        ];
        for outgoing in outgoings {
            let (bytes, len) = envelope_of(&link, outgoing, Tick::from_millis(9_000));
            let envelope = LinkEnvelope::decode(&bytes[..len]).expect("decodes");
            assert_eq!(envelope.session(), SessionId::None, "{outgoing:?}");
        }
    }

    #[test]
    fn l_181_a_refusal_carries_session_zero_and_request_zero() {
        let link = Link::new(identity(), Tick::ZERO);
        let (bytes, len) = envelope_of(
            &link,
            Outgoing::Refuse {
                code: LinkErrorCode::WrongSide,
            },
            Tick::ZERO,
        );
        let envelope = Envelope::decode(&bytes[..len]).expect("decodes");
        let header = envelope.header();
        assert_eq!(header.kind, MessageType::ErrorResponse);
        assert_eq!(header.session, SessionId::None);
        assert_eq!(header.req_id, ReqId(0));
        let hint = ErrorBody::from_envelope(envelope).expect("an error body");
        assert_eq!(hint.code(), Incoming::LinkLocal(LinkErrorCode::WrongSide));
    }

    #[test]
    fn a_heartbeat_reports_seconds_since_boot_saturating() {
        let boot = Tick::from_millis(1_000);
        let link = Link::new(identity(), boot);
        assert_eq!(link.uptime_s(Tick::from_millis(1_999)), 0);
        assert_eq!(link.uptime_s(Tick::from_millis(2_000)), 1);
        assert_eq!(link.uptime_s(Tick::from_millis(u64::MAX)), u32::MAX);
        assert_eq!(link.uptime_s(Tick::ZERO), 0, "before boot is not negative");
    }

    #[test]
    fn nothing_is_said_and_no_silence_is_measured_before_the_module_is_powered() {
        let mut link = Link::new(identity(), Tick::ZERO);
        let actions = link.tick(Tick::from_millis(120_000), false);
        assert!(actions.is_empty(), "{actions:?}");
        let actions = link.module_settled(Tick::from_millis(120_000));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Send(Outgoing::LinkUp { .. }))),
            "the statement goes out the moment the module is powered"
        );
    }
}

// `km43`'s types carry no `defmt::Format` yet (origin89hq/km43#38), so the
// types here that hold one say it by its number, which is what the wire
// carries anyway.
#[cfg(feature = "defmt")]
impl defmt::Format for Peer {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "Peer {{ version: {=u8}.{=u8}, fw: {}, hw: {}, boot_id: {=u32:#x}, net_version: {} }}",
            self.version.major,
            self.version.minor,
            self.fw,
            self.hw,
            self.boot_id,
            self.net_version
        );
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Compat {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::Agreed(version) => {
                defmt::write!(f, "Agreed({=u8}.{=u8})", version.major, version.minor);
            }
            Self::MajorMismatch { theirs } => {
                defmt::write!(
                    f,
                    "MajorMismatch {{ theirs: {=u8}.{=u8} }}",
                    theirs.major,
                    theirs.minor
                );
            }
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Note {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::RomText { count } => defmt::write!(f, "RomText {{ count: {=u32} }}", count),
            Self::Refused(code) => defmt::write!(f, "Refused({=u16})", *code as u16),
            Self::RequestFailed(kind) => {
                defmt::write!(f, "RequestFailed({=u8:#x})", *kind as u8);
            }
            Self::UnexpectedAck(kind) => {
                defmt::write!(f, "UnexpectedAck({=u8:#x})", *kind as u8);
            }
            Self::Malformed(kind) => defmt::write!(f, "Malformed({=u8:#x})", *kind as u8),
            Self::PeerRefused(Some(code)) => defmt::write!(f, "PeerRefused({=u16})", code),
            Self::PeerRefused(None) => defmt::write!(f, "PeerRefused(unread)"),
            Self::WrongRole => defmt::write!(f, "WrongRole"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Outgoing {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::LinkUp { req_id } => defmt::write!(f, "LinkUp({=u32})", req_id.0),
            Self::LinkUpAck { req_id } => defmt::write!(f, "LinkUpAck({=u32})", req_id.0),
            Self::Heartbeat { req_id } => defmt::write!(f, "Heartbeat({=u32})", req_id.0),
            Self::HeartbeatAck { req_id } => {
                defmt::write!(f, "HeartbeatAck({=u32})", req_id.0);
            }
            Self::ClientUpAck { req_id, outcome } => {
                defmt::write!(f, "ClientUpAck({=u32}, {=u8})", req_id.0, *outcome as u8);
            }
            Self::ClientDownAck { req_id, outcome } => {
                defmt::write!(f, "ClientDownAck({=u32}, {=u8})", req_id.0, *outcome as u8);
            }
            Self::TimeVerdict { req_id, outcome } => {
                defmt::write!(f, "TimeVerdict({=u32}, {=u8})", req_id.0, *outcome as u8);
            }
            Self::Refuse { code } => defmt::write!(f, "Refuse({=u16})", *code as u16),
        }
    }
}
