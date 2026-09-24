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
//! attempts (L-013, L-014, L-015), and the ROM's boot text counted in bytes
//! and recorded once per boot attempt, zero included (F-031).
//!
//! The connection rows are the session layer's ([`Rows`]): a connection the
//! comms processor announces is admitted or refused by it, a release frees
//! its row, and every row goes with the link (L-041). A connection the
//! session layer wants closed goes to the comms processor as a
//! `CloseConnection` request, tracked and retried like any other, and its
//! row is freed when the answer says the transport is gone (L-090).
//!
//! Each answer to a heartbeat of ours carries the comms processor's count
//! of connections, which is compared with ours (L-101). Three answers in a
//! row that disagree under an agreed version (L-050) and the comms
//! processor's count is taken as the truth: every connection is closed with
//! one `CloseConnection` naming handle 0, and when its answer arrives every
//! row goes with it, so a release lost on the wire leaks a row for six
//! seconds rather than until the next reboot (L-102). The clients
//! reconnect and are announced again.
//!
//! Time offers are decoded here and handed to the recorder, which owns the
//! floor and RTC. Its verdict returns through `time_verdict`; a pending
//! offer never stalls heartbeat processing.
//!
//! The pairing window is the panel's; the link reports its state to the
//! comms processor as a `PairingWindow` request after every link-up, on the
//! opening and on every closure (L-195), each report a fresh revision of
//! this boot and each retry the same one, a newer report superseding the
//! one in flight. The adapter hands the panel's deadline in every tick, and
//! a report owed goes out on the tick; an enrolment's `Pair` answer, sent
//! as its frame is handled, is on the wire before the tick that sees the
//! window closed. When the revisions of a boot run out the link falls and
//! stays down until the controller reboots.
//!
//! cites: F-031, F-039

use core::num::NonZeroU32;
use km43::{
    ClientConnected, ClientDisconnected, ClientDown, ClientDownAck, ClientUp, ClientUpAck,
    ClockOffer, CloseConnections, CloseReason, CloseReport, Conn, ControllerRecord, EventKind,
    FrameWriter, Heartbeat, Intake, LinkEnvelope, LinkError, LinkErrorCode, LinkMessageType,
    LinkUp, MAX_INFLIGHT, MAX_LINK_TEXT, MAX_SESSIONS, PairingWindowAck, PairingWindowNotice,
    ReqId, Side, TimeOffer, TimeVerdict, Version, arriving,
};

use sha2::{Digest, Sha256};

use crate::BootCount;
use crate::pairing_report::{PairingReports, Unbuilt};
use crate::rail::{CUT, Recovery};
use crate::text::Text;
use crate::tick::{Millis, Tick};
use o89_link::{
    Beats, LINK_ENVELOPE, Overdue, Requests, crosses_mismatch, frame_refusal, is_peer_refusal,
    link_header, refused_before_link,
};

pub use o89_link::{
    ATTEMPTS, DEAD_AFTER, EncodeError, HEARTBEAT_PERIOD, LINKUP_PERIOD, OURS, RESPONSE_TIMEOUT,
};

/// The connection rows the link admits into and frees, which the session
/// layer holds. The link decides when; the rows decide whether.
pub trait Rows {
    /// A transport the comms processor announced (L-060, L-061, L-080).
    fn admit(&mut self, conn: Conn) -> ClientConnected;
    /// A transport that went, by the comms processor's word or by the
    /// answer to a close the controller asked for.
    fn release(&mut self, conn: Conn) -> ClientDisconnected;
    /// Every row goes (L-041).
    fn drop_all(&mut self);
    /// Rows allocated, bound or not, for the heartbeat (L-101).
    fn allocated(&self) -> u8;
}

/// Closes that can be outstanding: one per row.
const CLOSING: usize = MAX_SESSIONS;

/// Heartbeat answers in a row whose `conns` disagrees with ours before the
/// table is resynchronised (L-102). One is a `ClientConnected` crossing a
/// beat in flight; three is a leak.
pub const RESYNC_AFTER: u8 = 3;

/// The resynchronisation of every connection (L-102).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resync {
    /// The counts agree, or disagree on fewer than [`RESYNC_AFTER`]
    /// answers in a row.
    Watching { disagreed: u8 },
    /// Due, and not sent: four requests are in flight (L-014).
    Owed,
    /// Sent under this request, and not answered.
    Sent(ReqId),
}

impl Resync {
    const AGREED: Self = Self::Watching { disagreed: 0 };
}

/// A close asked for and not yet answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Closing {
    conn: Conn,
    reason: CloseReason,
    /// Its request, once one was issued; none while four others are in
    /// flight (L-014).
    req_id: Option<ReqId>,
}

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
    /// Key 8, from the device secret (L-035). A unit without one has
    /// nothing to state: it keeps the link down for the boot, sends no
    /// `LinkUp` and answers none, and its silence is no reason to cut the
    /// rail (origin89hq/km43#127).
    pub device_id: Option<[u8; crate::secret::DEVICE_ID_BYTES]>,
}

/// The peer, as its last `LinkUp` or acknowledgement stated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

impl Compat {
    /// Whether the two versions agree, so that more than the handshake and
    /// heartbeats may cross (L-050).
    #[must_use]
    pub const fn is_agreed(self) -> bool {
        match self {
            Self::Agreed(_) => true,
            Self::MajorMismatch { .. } => false,
        }
    }
}

/// Why every connection is being dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DropReason {
    /// Six seconds without a heartbeat (L-110).
    LinkLost,
    /// The comms processor came back with another `boot_id` (L-041).
    CommsRebooted,
    /// The two connection counts disagreed on three heartbeats in a row,
    /// and the comms processor answered the close of every connection
    /// (L-102).
    Resync,
    /// The bench took the module into its ROM (F-038).
    ModuleTaken,
    /// Every pairing-report revision of this boot was used: the link falls
    /// and stays down until the controller reboots (L-195).
    RevisionsSpent,
}

/// A record the ring gets, each with the body KM43 gives it (P-215).
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
    /// Comms unrecoverable, `0x0803`: the third rung, and which of its two
    /// branches the board took (L-112).
    Unrecoverable {
        /// Left on and uncycled, on a board that cannot switch the rail
        /// back on after that long; otherwise off for the pause.
        rail_on: bool,
    },
    /// Comms boot noise, `0x0805`: the bytes the controller read as
    /// non-frames in one boot attempt of the module, zero included (F-031).
    BootNoise {
        /// Bytes, saturating.
        count: u32,
    },
}

impl LinkEvent {
    /// The registry's kind.
    #[must_use]
    pub fn kind(self) -> EventKind {
        self.record().kind()
    }

    /// The record's body. A cycle count is at least one, since the cycle
    /// it is logged for is counted in it.
    #[must_use]
    pub fn record(self) -> ControllerRecord {
        match self {
            Self::LinkLost => ControllerRecord::CommsLinkLost,
            Self::PowerCycled { count } => ControllerRecord::CommsPowerCycled {
                count: NonZeroU32::new(u32::from(count)).unwrap_or(NonZeroU32::MIN),
            },
            Self::Unrecoverable { rail_on } => ControllerRecord::CommsUnrecoverable { rail_on },
            Self::BootNoise { count } => ControllerRecord::CommsBootNoise { count },
        }
    }
}

/// The operation alone, with no credential or radio metadata values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkOperation {
    /// Join the configured network.
    Set,
    /// Forget a written network's credentials.
    Clear,
    /// Forget a foreign cache for a never-written master.
    ClearUnwritten,
}

/// Safe metadata for the adapter to log after a successful UART write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkPush {
    /// The request, unchanged across retries.
    pub req_id: ReqId,
    /// The immutable snapshot's version.
    pub version: u32,
    /// Only the operation; never an SSID, passphrase, country or hostname value.
    pub operation: NetworkOperation,
}

/// Something for the log on the probe, never for the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Note {
    /// A network push handed to the adapter; not proof of a completed UART write.
    NetworkSent {
        /// The request, unchanged across retries.
        req_id: ReqId,
        /// The immutable snapshot's version.
        version: u32,
        /// Only the operation; no network field values.
        operation: NetworkOperation,
    },
    /// An unanswered network push scheduled again under the same request.
    NetworkRetry {
        /// The request, unchanged across retries.
        req_id: ReqId,
        /// The immutable snapshot's version.
        version: u32,
        /// Only the operation; no network field values.
        operation: NetworkOperation,
    },
    /// A network push exhausted its bounded attempts.
    NetworkGaveUp {
        /// The request, unchanged across retries.
        req_id: ReqId,
        /// The immutable snapshot's version.
        version: u32,
        /// Only the operation; no network field values.
        operation: NetworkOperation,
    },
    /// A matching, decoded answer to the network push.
    NetworkAnswered {
        /// The request answered.
        req_id: ReqId,
        /// The module's verdict.
        outcome: km43::NetConfig,
        /// The version reported by the module, even on refusal.
        version: u32,
    },
    /// The module holds a network but the controller master is damaged or unencodable.
    NetworkWithoutMaster,
    /// The module refused the authoritative network update.
    NetworkRefused(km43::NetConfig),
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
    /// A `LinkUp` left unanswered: without a `device_id` this side has no
    /// statement to answer with (L-035).
    NoDeviceId,
}

/// A frame to put on the wire, described rather than encoded so the
/// adapter and the simulator share one [`Link::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outgoing {
    /// The sole scan order; its number is fixed through retries.
    WifiScan {
        /// Request identifier.
        req_id: ReqId,
        /// Fixed scan number.
        order: km43::ScanOrder,
    },
    /// Every valid result is acknowledged, including a late number.
    WifiScanResultAck {
        /// Echoed request identifier.
        req_id: ReqId,
        /// Echoed scan number.
        scan: NonZeroU32,
    },
    /// A decoded radio report has been held.
    WifiStateAck {
        /// Echoed request identifier.
        req_id: ReqId,
    },
    /// Push the fixed network snapshot tracked under this request.
    NetConfig {
        /// The request id, unchanged on retry.
        req_id: ReqId,
    },
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
    /// Close a transport.
    CloseConnection {
        /// From our counter.
        req_id: ReqId,
        /// Which.
        conn: Conn,
        /// Why.
        reason: CloseReason,
    },
    /// Close every transport: `CloseConnection` naming handle 0, with the
    /// reason `resync` (L-102).
    Resync {
        /// From our counter; a retry keeps it.
        req_id: ReqId,
    },
    /// The pairing window's state, reported (L-195).
    PairingWindow {
        /// From our counter; a retry keeps it.
        req_id: ReqId,
        /// Its revision and remaining time, fixed when first sent.
        notice: PairingWindowNotice,
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
    /// A rate-limited class A diagnostic for the recorder (P-220).
    RecordWifi(km43::WifiStatusChanged),
    /// Submit a decoded offer to the recorder, which owns the RTC and floor.
    OfferTime {
        /// Request to acknowledge after processing.
        req_id: ReqId,
        /// Offered wall-clock value; peer provenance never crosses this seam.
        unix_ms: u64,
    },
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

/// How many actions one call can hand out. A tick is the most: a request
/// slot given up and its note, resent or newly issued, four in all because
/// four is every slot (L-014), each given-up slot then reissued as a close
/// (four more), the link falling with its drop and its record, or a beat,
/// and a pairing report. Network diagnostics add at most two notes: the one
/// pending network request retried/given up, and a newly issued push. Sixteen
/// still holds every combination; a dropped action is a bug, counted rather
/// than hidden.
pub const ACTIONS: usize = 16;

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

    pub(crate) fn push(&mut self, action: Action) {
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

/// Why the network snapshot is owed; a local write must reach the module
/// even if its previously reported version happens to equal the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkDue {
    None,
    Compare,
    Changed,
}

/// The link, on the controller's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Diagnostic state shared with the wrapped-read endpoint.
    pub wifi: crate::Wifi,
    wifi_request: Option<ReqId>,
    network: Option<crate::Network>,
    network_sent: Option<(ReqId, crate::Network)>,
    network_due: NetworkDue,
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
    /// Bytes read as non-frames in the module's boot attempt (F-031).
    noise: u32,
    /// A boot attempt of the module is open: started when it settled, and
    /// closed at the first `LinkUp` or when the next one starts, with one
    /// boot-noise record either way.
    attempt: bool,
    /// Allocated connection rows, for the heartbeat (L-101), as the rows
    /// last said.
    conns: u8,
    /// Closes asked for and not yet answered.
    closing: [Option<Closing>; CLOSING],
    /// Whether the counts disagree, and the close of every connection that
    /// heals it (L-102).
    resync: Resync,
    /// What the comms processor has been told of the pairing window, and
    /// whether the link fell for want of a revision (L-195).
    pairing: PairingReports,
}

impl Link {
    /// A link at boot: down, saying nothing until [`Link::module_settled`]
    /// says the module is powered. On a board whose rail is already up at
    /// boot the adapter says so at once.
    #[must_use]
    pub fn new(identity: Identity, now: Tick) -> Self {
        Self {
            wifi: crate::Wifi::EMPTY,
            wifi_request: None,
            network: None,
            network_sent: None,
            network_due: NetworkDue::None,
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
            attempt: false,
            conns: 0,
            closing: [None; CLOSING],
            resync: Resync::AGREED,
            pairing: PairingReports::new(),
        }
    }

    /// Refresh the transport snapshot from the controller's persisted master.
    pub fn set_network(&mut self, network: Option<crate::Network>) {
        if self.network != network {
            self.forget_network();
            self.network_due = if self.is_up() {
                NetworkDue::Changed
            } else {
                NetworkDue::Compare
            };
            self.network = network;
        }
    }

    /// Metadata for a pending push, only while this exact request is current.
    /// Never exposes an SSID, passphrase, country or hostname value.
    #[must_use]
    pub fn network_push(&self, req_id: ReqId) -> Option<NetworkPush> {
        let (_, network) = self
            .network_sent
            .as_ref()
            .filter(|(sent, _)| *sent == req_id)?;
        let operation = match network.change()? {
            km43::NetChange::Set { .. } => NetworkOperation::Set,
            km43::NetChange::Clear { .. } => NetworkOperation::Clear,
            km43::NetChange::ClearUnwritten => NetworkOperation::ClearUnwritten,
        };
        Some(NetworkPush {
            req_id,
            version: network.version(),
            operation,
        })
    }

    fn forget_network(&mut self) {
        if let Some((req_id, _)) = self.network_sent.take() {
            let _ = self.requests.answered(req_id, LinkMessageType::NetConfig);
        }
    }

    fn report_network(&mut self, now: Tick, actions: &mut Actions) {
        if self.network_due == NetworkDue::None || self.network_sent.is_some() {
            return;
        }
        let Phase::Up {
            peer,
            compat: Compat::Agreed(_),
            ..
        } = self.phase
        else {
            return;
        };
        let Some(network) = self.network else {
            if peer.net_version.is_some_and(|version| version != 0) {
                actions.push(Action::Note(Note::NetworkWithoutMaster));
            }
            self.network_due = NetworkDue::None;
            return;
        };
        if peer.net_version == Some(network.version())
            && (network.version() == 0 || self.network_due != NetworkDue::Changed)
        {
            self.network_due = NetworkDue::None;
            return;
        }
        if network.change().is_none() {
            actions.push(Action::Note(Note::NetworkWithoutMaster));
            self.network_due = NetworkDue::None;
            return;
        }
        let Some(req_id) = self.request(LinkMessageType::NetConfig, now) else {
            return;
        };
        self.network_sent = Some((req_id, network));
        self.network_due = NetworkDue::None;
        if let Some(NetworkPush {
            version, operation, ..
        }) = self.network_push(req_id)
        {
            actions.push(Action::Note(Note::NetworkSent {
                req_id,
                version,
                operation,
            }));
        }
        actions.push(Action::Send(Outgoing::NetConfig { req_id }));
    }

    fn network_answered(&mut self, envelope: LinkEnvelope<'_>, actions: &mut Actions) {
        let req_id = envelope.req_id();
        let Ok(verdict) = km43::NetVerdict::decode(envelope) else {
            actions.push(Action::Note(Note::Malformed(LinkMessageType::NetConfigAck)));
            return;
        };
        if self.network_sent.is_none_or(|(sent, _)| sent != req_id) {
            actions.push(Action::Note(Note::UnexpectedAck(
                LinkMessageType::NetConfigAck,
            )));
            return;
        }
        actions.push(Action::Note(Note::NetworkAnswered {
            req_id,
            outcome: verdict.outcome,
            version: verdict.version,
        }));
        self.forget_network();
        if let Phase::Up { peer, .. } = &mut self.phase {
            peer.net_version = Some(verdict.version);
        }
        if let Some(peer) = &mut self.last_peer {
            peer.net_version = Some(verdict.version);
        }
        if verdict.outcome != km43::NetConfig::Stored {
            actions.push(Action::Note(Note::NetworkRefused(verdict.outcome)));
        }
    }

    /// Whether `LinkUp` has crossed in both directions (L-033).
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up { .. })
    }

    /// Whether the link is up under an agreed version (L-050).
    const fn agreed(&self) -> bool {
        match self.compat() {
            Some(compat) => compat.is_agreed(),
            None => false,
        }
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

    /// The adapter read `bytes` that were not a frame: a run between
    /// delimiters whose CRC did not hold, or one nothing finished. Counted
    /// while a boot attempt is open, which is the interval the record
    /// covers (F-031); a frame whose CRC held and whose body did not read is
    /// a malformed frame and is not counted here.
    pub fn noise(&mut self, bytes: u32) {
        if self.attempt {
            self.noise = self.noise.saturating_add(bytes);
        }
    }

    /// The rail is up and `EN` released: the module is booting. An attempt
    /// still open is abandoned and recorded, a new one opens, the ladder's
    /// clock restarts, and this side states itself (L-030): the module may
    /// not hear it yet, which is what the attempts are for.
    pub fn module_settled(&mut self, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        self.close_attempt(&mut actions);
        self.attempt = true;
        self.cut_pending = false;
        self.module_up_since = now;
        self.earliest_cut = now.after(CUT_AFTER).unwrap_or(now);
        if let Phase::Down { .. } = self.phase {
            self.announce(now, &mut actions);
        }
        actions
    }

    /// The panel's pairing window at `now`: its deadline while open, `None`
    /// while closed. A change from what was last reported, and the first
    /// state after a link-up, is reported on the next tick (L-195).
    pub fn pairing_window(&mut self, deadline: Option<Tick>, now: Tick) {
        self.pairing.observe(deadline, now);
    }

    /// Whether every pairing-report revision of this boot is used, which
    /// keeps the link down until the controller reboots (L-195).
    #[must_use]
    pub const fn revisions_spent(&self) -> bool {
        self.pairing.retired()
    }

    /// Whether the link is down on purpose for the rest of the boot: every
    /// pairing-report revision spent (L-195), or no `device_id` to state
    /// (L-035). Neither is anything a cycle of the module would cure.
    const fn held_down(&self) -> bool {
        self.pairing.retired() || self.identity.device_id.is_none()
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
    pub fn module_taken(&mut self, rows: &mut impl Rows) -> Actions {
        let mut actions = Actions::NONE;
        // The bench took the module in the middle of an attempt, which the
        // controller abandons.
        self.close_attempt(&mut actions);
        if let Phase::Up { .. } = self.phase {
            self.drop_rows(DropReason::ModuleTaken, rows, &mut actions);
        }
        self.phase = Phase::Down { next_linkup: None };
        // A request to a module in its ROM will never be answered, and no
        // answer to a beat before it counts.
        self.requests.forget();
        self.beats.forget();
        let _ = self.pairing.forget();
        self.cut_pending = false;
        actions
    }

    /// What the rail sequencer answered a [`Action::CutRail`] with.
    pub fn rail(&mut self, recovery: Recovery, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        self.earliest_cut = now.after(CUT_AFTER).unwrap_or(now);
        match recovery {
            Recovery::Cycling { count, off_for } => {
                actions.push(Action::Log(LinkEvent::PowerCycled { count }));
                // A cut longer than the ladder's own is the third rung
                // executed: the rail off for its pause, raised as the rung
                // it is (L-112).
                if off_for.as_millis() > CUT.as_millis() && !self.raised {
                    self.raised = true;
                    actions.push(Action::Log(LinkEvent::Unrecoverable { rail_on: false }));
                }
            }
            Recovery::LeftOnAndRaised => {
                self.cut_pending = false;
                if !self.raised {
                    self.raised = true;
                    actions.push(Action::Log(LinkEvent::Unrecoverable { rail_on: true }));
                }
            }
            Recovery::Busy => {}
            Recovery::Deferred => {
                // Nothing moved and nothing will settle: the ladder is
                // back, and asks again once the cut is due again.
                self.cut_pending = false;
            }
        }
        actions
    }

    /// A frame from the peer, decoded by the adapter.
    pub fn received(
        &mut self,
        envelope: LinkEnvelope<'_>,
        now: Tick,
        rows: &mut impl Rows,
    ) -> Actions {
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
            LinkMessageType::WifiScanAck
            | LinkMessageType::WifiScanResult
            | LinkMessageType::WifiState => self.wifi_received(kind, envelope, now, &mut actions),
            LinkMessageType::LinkUp => {
                self.statement_received(envelope, now, rows, &mut actions);
            }
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
                            self.linked(peer, compat, now, rows, &mut actions);
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
                Ok(beat) => {
                    if self.beats.answered(req_id) {
                        self.heard(now);
                        self.compare(beat.conns, rows, now, &mut actions);
                    } else {
                        actions.push(Action::Note(Note::UnexpectedAck(kind)));
                    }
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            },
            LinkMessageType::ClientConnected
            | LinkMessageType::ClientDisconnected
            | LinkMessageType::TimeOffer => self.answer(kind, envelope, rows, &mut actions),
            LinkMessageType::CloseConnectionAck => {
                self.close_answered(envelope, rows, &mut actions);
            }
            LinkMessageType::PairingWindowAck => self.pairing_answered(envelope, &mut actions),
            LinkMessageType::NetConfigAck => self.network_answered(envelope, &mut actions),
            LinkMessageType::CommsReleaseAck | LinkMessageType::EnterDownloadAck => {
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
            | LinkMessageType::PairingWindow
            | LinkMessageType::TimeOfferAck
            | LinkMessageType::CommsRelease
            | LinkMessageType::WifiScan
            | LinkMessageType::WifiScanResultAck
            | LinkMessageType::WifiStateAck
            | LinkMessageType::EnterDownload => {
                // `arriving` refuses these at this side; an arm so that a
                // change to the direction table lands here and not in a
                // wildcard.
                Self::refuse(LinkErrorCode::WrongSide, &mut actions);
            }
        }
        self.report_network(now, &mut actions);
        self.wifi_tick(now, &mut actions);
        actions
    }

    /// A verdict from the recorder, sent only while the link remains up.
    pub fn time_verdict(&self, req_id: ReqId, outcome: TimeOffer) -> Actions {
        let mut actions = Actions::NONE;
        if self.is_up() {
            actions.push(Action::Send(Outgoing::TimeVerdict { req_id, outcome }));
        }
        actions
    }

    /// The three requests the peer makes, each body read before it is
    /// answered: a frame that is not the message it claims gets no
    /// acknowledgement the peer could act on (P-031), and none of them is a
    /// heartbeat. Before the link is up only the handshake is admitted
    /// (L-033): `ClientConnected` has an outcome for that, the others are
    /// refused with 258. The rows decide a connection; time offers go to
    /// the recorder so their floor and calendar share an owner.
    fn answer(
        &mut self,
        kind: LinkMessageType,
        envelope: LinkEnvelope<'_>,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        if !self.is_up() && refused_before_link(Side::Controller, kind) {
            Self::refuse(LinkErrorCode::BeforeLinkUp, actions);
            return;
        }
        let req_id = envelope.req_id();
        let outgoing = match kind {
            // Neither `transport` nor `peer` is read past the decode: both are
            // the untrusted chip's assertions (L-072).
            LinkMessageType::ClientConnected => ClientUp::decode(envelope).map(|up| {
                let outcome = match (self.is_up(), Conn::new(up.conn)) {
                    (true, Some(conn)) => rows.admit(conn),
                    // The decode refuses handle 0; an arm rather than a
                    // guess if it ever did not.
                    (true, None) => ClientConnected::RefusedHandleInUse,
                    (false, _) => ClientConnected::RefusedLinkNotUp,
                };
                Outgoing::ClientUpAck { req_id, outcome }
            }),
            LinkMessageType::ClientDisconnected => ClientDown::decode(envelope).map(|down| {
                let outcome =
                    Conn::new(down.conn).map_or(ClientDisconnected::UnknownHandle, |conn| {
                        // The transport is gone, and the answer lets its handle
                        // go to the next one (L-080): a close still owed for it
                        // would close, or its late answer free, the next owner.
                        self.forget_close(conn);
                        rows.release(conn)
                    });
                Outgoing::ClientDownAck { req_id, outcome }
            }),
            LinkMessageType::TimeOffer => {
                match ClockOffer::decode(envelope) {
                    Ok(offer) => actions.push(Action::OfferTime {
                        req_id,
                        unix_ms: offer.unix_ms,
                    }),
                    Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
                }
                return;
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
            | LinkMessageType::PairingWindow
            | LinkMessageType::PairingWindowAck
            | LinkMessageType::TimeOfferAck
            | LinkMessageType::CommsRelease
            | LinkMessageType::CommsReleaseAck
            | LinkMessageType::EnterDownload
            | LinkMessageType::WifiScan
            | LinkMessageType::WifiScanAck
            | LinkMessageType::WifiScanResult
            | LinkMessageType::WifiScanResultAck
            | LinkMessageType::WifiState
            | LinkMessageType::WifiStateAck
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
        self.conns = rows.allocated();
    }

    /// The session layer wants `conn` closed (P-051, P-077). Asked once:
    /// a close already outstanding for it stands. Sent now when the link is
    /// up and a request slot is free, else on a later tick; a link that
    /// falls meanwhile takes every row with it, and the close with them.
    pub fn close(&mut self, conn: Conn, reason: CloseReason, now: Tick) -> Actions {
        let mut actions = Actions::NONE;
        self.close_into(conn, reason, now, &mut actions);
        actions
    }

    /// [`Link::close`], into actions already being gathered.
    pub(crate) fn close_into(
        &mut self,
        conn: Conn,
        reason: CloseReason,
        now: Tick,
        actions: &mut Actions,
    ) {
        if self
            .closing
            .iter()
            .flatten()
            .any(|closing| closing.conn == conn)
        {
            return;
        }
        let Some(free) = self.closing.iter_mut().find(|slot| slot.is_none()) else {
            // One per row, and a row is closed once: full is a bug.
            debug_assert!(false, "more closes outstanding than rows");
            actions.push(Action::Note(Note::RequestFailed(
                LinkMessageType::CloseConnection,
            )));
            return;
        };
        *free = Some(Closing {
            conn,
            reason,
            req_id: None,
        });
        self.issue_closes(now, actions);
    }

    /// Issue every close not yet in flight, while the link is up and a
    /// request slot is free (L-014).
    fn issue_closes(&mut self, now: Tick, actions: &mut Actions) {
        if !self.is_up() {
            return;
        }
        for index in 0..CLOSING {
            let waiting = self
                .closing
                .get(index)
                .copied()
                .flatten()
                .filter(|closing| closing.req_id.is_none());
            let Some(closing) = waiting else {
                continue;
            };
            let Some(req_id) = self.request(LinkMessageType::CloseConnection, now) else {
                return;
            };
            if let Some(Some(slot)) = self.closing.get_mut(index) {
                slot.req_id = Some(req_id);
            }
            actions.push(Action::Send(Outgoing::CloseConnection {
                req_id,
                conn: closing.conn,
                reason: closing.reason,
            }));
        }
    }

    /// The answer to a close: the transport is gone, closed now or unknown
    /// already, and its row goes with it. An answer nothing waits for, or
    /// one that does not read, leaves the request to its retries (L-015).
    fn close_answered(
        &mut self,
        envelope: LinkEnvelope<'_>,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        let req_id = envelope.req_id();
        if self.resync == Resync::Sent(req_id) {
            self.resynced(envelope, rows, actions);
            return;
        }
        if !self
            .requests
            .awaits(req_id, LinkMessageType::CloseConnection)
        {
            actions.push(Action::Note(Note::UnexpectedAck(
                LinkMessageType::CloseConnectionAck,
            )));
            return;
        }
        if CloseReport::decode(envelope).is_err() {
            actions.push(Action::Note(Note::Malformed(
                LinkMessageType::CloseConnectionAck,
            )));
            return;
        }
        let _ = self
            .requests
            .answered(req_id, LinkMessageType::CloseConnection);
        if let Some(closing) = self.take_closing(req_id) {
            let _ = rows.release(closing.conn);
        }
        self.conns = rows.allocated();
    }

    /// The comms processor's `conns`, from an answer to a beat of ours,
    /// against the rows (L-101). Three disagreements in a row and every
    /// connection is closed (L-102); an agreement starts the count again.
    /// Nothing is counted while that close is owed or in flight, or under a
    /// major mismatch, where the peer would refuse it (L-050).
    fn compare(&mut self, theirs: u8, rows: &impl Rows, now: Tick, actions: &mut Actions) {
        self.conns = rows.allocated();
        if !self.agreed() {
            return;
        }
        let Resync::Watching { disagreed } = self.resync else {
            return;
        };
        if theirs == self.conns {
            self.resync = Resync::AGREED;
            return;
        }
        let disagreed = disagreed.saturating_add(1);
        self.resync = if disagreed >= RESYNC_AFTER {
            Resync::Owed
        } else {
            Resync::Watching { disagreed }
        };
        self.issue_resync(now, actions);
    }

    /// Send the close of every connection that is owed, while the link is
    /// up under an agreed version and a request slot is free (L-014). Under
    /// a major mismatch it stays owed, as the pairing report does (L-050);
    /// one already in flight runs out its retries, and no answer after it
    /// counts towards another.
    fn issue_resync(&mut self, now: Tick, actions: &mut Actions) {
        if self.resync != Resync::Owed || !self.agreed() {
            return;
        }
        if let Some(req_id) = self.request(LinkMessageType::CloseConnection, now) {
            self.resync = Resync::Sent(req_id);
            actions.push(Action::Send(Outgoing::Resync { req_id }));
        }
    }

    /// The answer to the close of every connection: the comms processor's
    /// count was the true one and it has closed them all, so every row
    /// goes, with every session on it and every close still owed (L-102).
    /// One that does not read leaves the request to its retries (L-015).
    fn resynced(
        &mut self,
        envelope: LinkEnvelope<'_>,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        if CloseReport::decode(envelope).is_err() {
            actions.push(Action::Note(Note::Malformed(
                LinkMessageType::CloseConnectionAck,
            )));
            return;
        }
        rows.drop_all();
        self.conns = rows.allocated();
        self.forget_resync();
        for closing in self.closing.iter_mut().filter_map(Option::take) {
            if let Some(req_id) = closing.req_id {
                let _ = self
                    .requests
                    .answered(req_id, LinkMessageType::CloseConnection);
            }
        }
        actions.push(Action::DropConnections(DropReason::Resync));
    }

    /// Back to watching, with the close in flight retired.
    fn forget_resync(&mut self) {
        if let Resync::Sent(req_id) = self.resync {
            let _ = self
                .requests
                .answered(req_id, LinkMessageType::CloseConnection);
        }
        self.resync = Resync::AGREED;
    }

    /// The answer to a pairing report: it consumes the report only when it
    /// reads and echoes the revision in flight under that request (L-193).
    /// Anything else is an acknowledgement nobody waits for, or a malformed
    /// one, and leaves the report to its retries (L-015).
    fn pairing_answered(&mut self, envelope: LinkEnvelope<'_>, actions: &mut Actions) {
        let kind = LinkMessageType::PairingWindowAck;
        let req_id = envelope.req_id();
        if !self.requests.awaits(req_id, LinkMessageType::PairingWindow) {
            actions.push(Action::Note(Note::UnexpectedAck(kind)));
            return;
        }
        let Ok(ack) = PairingWindowAck::decode(envelope) else {
            actions.push(Action::Note(Note::Malformed(kind)));
            return;
        };
        if self.pairing.acknowledged(req_id, ack.revision) {
            let _ = self
                .requests
                .answered(req_id, LinkMessageType::PairingWindow);
        } else {
            actions.push(Action::Note(Note::UnexpectedAck(kind)));
        }
    }

    /// The pairing report owed, if the link is up under an agreed version
    /// and a request slot is free (L-014): the one in flight superseded,
    /// the new one built now. With every revision used, the link falls
    /// instead and stays down (L-195).
    fn report(&mut self, now: Tick, rows: &mut impl Rows, actions: &mut Actions) {
        if !self.pairing.owed() {
            return;
        }
        let Phase::Up {
            compat: Compat::Agreed(_),
            ..
        } = self.phase
        else {
            // Down, the next link-up owes the state again; under a major
            // mismatch the peer would refuse it (L-050).
            return;
        };
        if let Some(superseded) = self.pairing.supersede() {
            let _ = self
                .requests
                .answered(superseded, LinkMessageType::PairingWindow);
        }
        let notice = match self.pairing.prepare(now) {
            Ok(notice) => notice,
            Err(Unbuilt::Spent) => {
                self.pairing.retire();
                self.down(DropReason::RevisionsSpent, now, rows, actions);
                return;
            }
            Err(Unbuilt::Refused) => {
                debug_assert!(false, "a clamped pairing report was refused");
                actions.push(Action::Note(Note::RequestFailed(
                    LinkMessageType::PairingWindow,
                )));
                return;
            }
        };
        let Some(req_id) = self.request(LinkMessageType::PairingWindow, now) else {
            // Four in flight: still owed, and built afresh when a slot frees.
            return;
        };
        self.pairing.sent(req_id, notice);
        actions.push(Action::Send(Outgoing::PairingWindow { req_id, notice }));
    }

    /// Forget the close owed for `conn`, and retire the request carrying
    /// it, so neither a retry nor a late answer reaches the handle's next
    /// owner.
    fn forget_close(&mut self, conn: Conn) {
        let owed = self
            .closing
            .iter_mut()
            .find(|slot| slot.is_some_and(|closing| closing.conn == conn))
            .and_then(Option::take);
        if let Some(Closing {
            req_id: Some(req_id),
            ..
        }) = owed
        {
            let _ = self
                .requests
                .answered(req_id, LinkMessageType::CloseConnection);
        }
    }

    fn take_closing(&mut self, req_id: ReqId) -> Option<Closing> {
        self.closing
            .iter_mut()
            .find(|slot| slot.is_some_and(|closing| closing.req_id == Some(req_id)))
            .and_then(Option::take)
    }

    /// Time passed. `install_in_flight` is L-113: a release being written
    /// suspends the ladder.
    pub fn tick(&mut self, now: Tick, install_in_flight: bool, rows: &mut impl Rows) -> Actions {
        let mut actions = Actions::NONE;
        self.conns = rows.allocated();
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
        self.issue_closes(now, &mut actions);
        self.issue_resync(now, &mut actions);
        match self.phase {
            Phase::Up { next_beat, .. } => {
                let silent = self
                    .last_heard
                    .and_then(|heard| now.since(heard))
                    .is_some_and(|silence| silence.as_millis() >= DEAD_AFTER.as_millis());
                // L-113 suspends the whole ladder, its first rung included.
                if silent && !install_in_flight {
                    self.down(DropReason::LinkLost, now, rows, &mut actions);
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
        self.report(now, rows, &mut actions);
        self.report_network(now, &mut actions);
        self.wifi_tick(now, &mut actions);
        actions
    }

    /// Whether the ladder's cut is due (L-111): unlinked with the module
    /// powered, sixty seconds since the peer last answered or the module
    /// last came up, past the earliest cut, and no install in flight
    /// (L-113).
    fn cut_due(&self, now: Tick, install_in_flight: bool) -> bool {
        if self.held_down() {
            // Down on purpose for the rest of the boot: its silence is
            // nothing a cycle of the module would cure.
            return false;
        }
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
            Outgoing::WifiScan { req_id, order } => order.write(
                link_header(LinkMessageType::WifiScan, req_id),
                &mut envelope,
            ),
            Outgoing::WifiScanResultAck { req_id, scan } => km43::ScanResultAck { scan }.write(
                link_header(LinkMessageType::WifiScanResultAck, req_id),
                &mut envelope,
            ),
            Outgoing::WifiStateAck { req_id } => km43::RadioReportAck.write(
                link_header(LinkMessageType::WifiStateAck, req_id),
                &mut envelope,
            ),
            Outgoing::NetConfig { req_id } => {
                let (_, network) = self
                    .network_sent
                    .as_ref()
                    .filter(|(sent, _)| *sent == req_id)
                    .ok_or(EncodeError::Body)?;
                network.change().ok_or(EncodeError::Body)?.write(
                    link_header(LinkMessageType::NetConfig, req_id),
                    &mut envelope,
                )
            }
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
            Outgoing::CloseConnection {
                req_id,
                conn,
                reason,
            } => CloseConnections {
                conn: conn.get(),
                reason,
            }
            .write(
                link_header(LinkMessageType::CloseConnection, req_id),
                &mut envelope,
            ),
            Outgoing::Resync { req_id } => CloseConnections {
                conn: 0,
                reason: CloseReason::Resync,
            }
            .write(
                link_header(LinkMessageType::CloseConnection, req_id),
                &mut envelope,
            ),
            Outgoing::PairingWindow { req_id, notice } => notice.write(
                link_header(LinkMessageType::PairingWindow, req_id),
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
            device_id: self.identity.device_id,
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

    /// A `LinkUp` from the peer: answered with ours and recorded, or, with
    /// no `device_id` to state, left unanswered, because an acknowledgement
    /// is a statement and one without key 8 is one the module must refuse
    /// (L-035).
    fn statement_received(
        &mut self,
        envelope: LinkEnvelope<'_>,
        now: Tick,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        if self.identity.device_id.is_none() {
            actions.push(Action::Note(Note::NoDeviceId));
            return;
        }
        let req_id = envelope.req_id();
        match LinkUp::decode(envelope) {
            Ok(theirs) => {
                if let Some((peer, compat)) = Self::accept(&theirs, actions) {
                    actions.push(Action::Send(Outgoing::LinkUpAck { req_id }));
                    self.stated(peer, compat, now, rows, actions);
                }
            }
            Err(_) => actions.push(Action::Note(Note::Malformed(LinkMessageType::LinkUp))),
        }
    }

    /// The peer stated itself of its own accord (L-030): recorded and
    /// answered, and never a link (L-033). A changed `boot_id` is a peer that
    /// rebooted: every connection goes (L-041), and the link with them,
    /// because the new boot has answered nothing of ours. Unlinked, this side
    /// states itself at once.
    fn stated(
        &mut self,
        peer: Peer,
        compat: Compat,
        now: Tick,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        let rebooted = self
            .last_peer
            .is_some_and(|known| known.boot_id != peer.boot_id);
        self.last_peer = Some(peer);
        if rebooted && self.is_up() {
            // The common way down: every connection drops, and no answer to
            // a beat of the old boot counts (L-041, L-100).
            self.down(DropReason::CommsRebooted, now, rows, actions);
        } else if let Phase::Up {
            peer: known,
            compat: agreed,
            ..
        } = &mut self.phase
        {
            // The same boot preserves sessions (L-030), but compares the cache
            // again so a failed network write is retried (L-133, L-137).
            if self.network_due == NetworkDue::None {
                self.network_due = NetworkDue::Compare;
            }
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
    fn linked(
        &mut self,
        peer: Peer,
        compat: Compat,
        now: Tick,
        rows: &mut impl Rows,
        actions: &mut Actions,
    ) {
        if let Phase::Up { peer: known, .. } = self.phase
            && known.boot_id != peer.boot_id
        {
            self.beats.forget();
            self.drop_rows(DropReason::CommsRebooted, rows, actions);
        }
        self.forget_network();
        self.network_due = NetworkDue::Compare;
        self.close_attempt(actions);
        self.last_peer = Some(peer);
        self.heard(now);
        // Every link-up owes the window's state under a fresh revision,
        // unchanged or not (L-195).
        self.pairing.linked();
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

    /// Record the open attempt's noise, zero included, once (F-031).
    fn close_attempt(&mut self, actions: &mut Actions) {
        if self.attempt {
            actions.push(Action::Log(LinkEvent::BootNoise { count: self.noise }));
        }
        self.attempt = false;
        self.noise = 0;
    }

    fn down(&mut self, why: DropReason, now: Tick, rows: &mut impl Rows, actions: &mut Actions) {
        // A beat of the link that fell is answered by nothing that counts.
        self.beats.forget();
        self.phase = Phase::Down {
            next_linkup: Some(now),
        };
        self.drop_rows(why, rows, actions);
    }

    /// Every connection goes, and every close asked for with it: there is
    /// no transport left to close, and a close retried into the next link
    /// would name a handle the comms processor may have given to somebody
    /// else (L-041, L-080).
    fn drop_rows(&mut self, why: DropReason, rows: &mut impl Rows, actions: &mut Actions) {
        self.wifi.lost();
        self.forget_wifi_request();
        self.forget_network();
        self.network_due = NetworkDue::Compare;
        rows.drop_all();
        self.conns = rows.allocated();
        self.forget_resync();
        for closing in self.closing.iter_mut().filter_map(Option::take) {
            if let Some(req_id) = closing.req_id {
                let _ = self
                    .requests
                    .answered(req_id, LinkMessageType::CloseConnection);
            }
        }
        // The report in flight goes too: the peer that would acknowledge it
        // drops what it learned with the link, and the next link-up owes a
        // fresh revision (L-195).
        if let Some(req_id) = self.pairing.forget() {
            let _ = self
                .requests
                .answered(req_id, LinkMessageType::PairingWindow);
        }
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
        if self.held_down() {
            // Only a controller reboot links again (L-195), and only with a
            // device secret written (L-035).
            return;
        }
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
    fn request_given_up(&mut self, kind: LinkMessageType, req_id: ReqId, actions: &mut Actions) {
        if kind == LinkMessageType::WifiScan {
            self.wifi_request = None;
            self.wifi.failed();
        }
        // Failed to whatever asked, and nothing more: whether
        // the link is down is L-100's timer alone (L-015). A
        // close given up leaves its row to the transport's own
        // release, or to the link falling.
        if kind == LinkMessageType::CloseConnection {
            let _ = self.take_closing(req_id);
            if self.resync == Resync::Sent(req_id) {
                // Back to watching: the counts still disagree,
                // and three more answers send it again.
                self.resync = Resync::AGREED;
            }
        }
        if kind == LinkMessageType::NetConfig {
            if let Some(NetworkPush {
                version, operation, ..
            }) = self.network_push(req_id)
            {
                actions.push(Action::Note(Note::NetworkGaveUp {
                    req_id,
                    version,
                    operation,
                }));
            }
            self.network_sent = None;
        }
        if kind == LinkMessageType::PairingWindow {
            self.pairing.given_up(req_id);
        }
        actions.push(Action::Note(Note::RequestFailed(kind)));
    }

    fn retry(&mut self, now: Tick, actions: &mut Actions) {
        // Bounded: each call moves one request on, and no more than
        // `MAX_INFLIGHT` are in flight to move.
        for _ in 0..MAX_INFLIGHT {
            match self.requests.overdue(now) {
                None => return,
                Some(Overdue::GivenUp { kind, req_id }) => {
                    self.request_given_up(kind, req_id, actions);
                }
                Some(Overdue::Resend { kind, req_id }) => match kind {
                    LinkMessageType::WifiScan => {
                        if let Some(order) = self.wifi.order() {
                            actions.push(Action::Send(Outgoing::WifiScan { req_id, order }));
                        }
                    }
                    LinkMessageType::LinkUp => {
                        actions.push(Action::Send(Outgoing::LinkUp { req_id }));
                    }
                    LinkMessageType::CloseConnection => {
                        match self
                            .closing
                            .iter()
                            .flatten()
                            .find(|closing| closing.req_id == Some(req_id))
                        {
                            None if self.resync == Resync::Sent(req_id) => {
                                actions.push(Action::Send(Outgoing::Resync { req_id }));
                            }
                            Some(closing) => {
                                actions.push(Action::Send(Outgoing::CloseConnection {
                                    req_id,
                                    conn: closing.conn,
                                    reason: closing.reason,
                                }));
                            }
                            None => {
                                let _ = self.requests.answered(req_id, kind);
                            }
                        }
                    }
                    // The same revision and body, under the same id: a
                    // report superseded meanwhile is not sent again.
                    LinkMessageType::PairingWindow => match self.pairing.resend(req_id) {
                        Some(notice) => {
                            actions.push(Action::Send(Outgoing::PairingWindow { req_id, notice }));
                        }
                        None => {
                            let _ = self.requests.answered(req_id, kind);
                        }
                    },
                    LinkMessageType::NetConfig => {
                        if self.network_sent.is_some_and(|(sent, _)| sent == req_id) {
                            if let Some(NetworkPush {
                                version, operation, ..
                            }) = self.network_push(req_id)
                            {
                                actions.push(Action::Note(Note::NetworkRetry {
                                    req_id,
                                    version,
                                    operation,
                                }));
                            }
                            actions.push(Action::Send(Outgoing::NetConfig { req_id }));
                        }
                    }
                    LinkMessageType::LinkUpAck
                    | LinkMessageType::Heartbeat
                    | LinkMessageType::HeartbeatAck
                    | LinkMessageType::ClientConnected
                    | LinkMessageType::ClientConnectedAck
                    | LinkMessageType::ClientDisconnected
                    | LinkMessageType::ClientDisconnectedAck
                    | LinkMessageType::CloseConnectionAck
                    | LinkMessageType::NetConfigAck
                    | LinkMessageType::PairingWindowAck
                    | LinkMessageType::TimeOffer
                    | LinkMessageType::TimeOfferAck
                    | LinkMessageType::CommsRelease
                    | LinkMessageType::CommsReleaseAck
                    | LinkMessageType::EnterDownload
                    | LinkMessageType::WifiScanAck
                    | LinkMessageType::WifiScanResult
                    | LinkMessageType::WifiScanResultAck
                    | LinkMessageType::WifiState
                    | LinkMessageType::WifiStateAck
                    | LinkMessageType::EnterDownloadAck => {
                        // Nothing else is issued as a request yet; the arm
                        // lands here when one is.
                        let _ = self.requests.answered(req_id, kind);
                    }
                },
            }
        }
    }

    fn forget_wifi_request(&mut self) {
        if let Some(req_id) = self.wifi_request.take() {
            let _ = self.requests.answered(req_id, LinkMessageType::WifiScan);
        }
    }

    fn wifi_tick(&mut self, now: Tick, actions: &mut Actions) {
        self.wifi.tick(now);
        // The peer refuses a scan order under a major mismatch (L-050).
        if !self.agreed() {
            self.wifi.lost();
            self.forget_wifi_request();
            return;
        }
        if self.wifi.order().is_none() {
            self.forget_wifi_request();
        }
        if let Some(order) = self.wifi.order()
            && self.wifi_request.is_none()
            && !self.wifi.started_already()
            && let Some(req_id) = self.request(LinkMessageType::WifiScan, now)
        {
            self.wifi_request = Some(req_id);
            actions.push(Action::Send(Outgoing::WifiScan { req_id, order }));
        }
        let section = self.network.map_or(0, |network| network.version());
        if let Some(record) = self.wifi.record(section, now) {
            actions.push(Action::RecordWifi(record));
        }
    }

    fn wifi_received(
        &mut self,
        kind: LinkMessageType,
        envelope: LinkEnvelope<'_>,
        now: Tick,
        actions: &mut Actions,
    ) {
        if !self.is_up() {
            Self::refuse(LinkErrorCode::BeforeLinkUp, actions);
            return;
        }
        let req_id = envelope.req_id();
        if kind == LinkMessageType::WifiScanAck {
            match km43::ScanOrderVerdict::decode(envelope) {
                Ok(verdict) if self.wifi_request == Some(req_id) => {
                    self.forget_wifi_request();
                    match verdict.outcome {
                        km43::WifiScan::Started => self.wifi.started(now),
                        km43::WifiScan::RefusedBusy | km43::WifiScan::RefusedRadioOff => {
                            self.wifi.failed();
                        }
                    }
                }
                Ok(_) => actions.push(Action::Note(Note::UnexpectedAck(kind))),
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            }
        } else if kind == LinkMessageType::WifiScanResult {
            match km43::ScanResult::decode(envelope) {
                Ok(result) => {
                    self.wifi.result(result, now);
                    actions.push(Action::Send(Outgoing::WifiScanResultAck {
                        req_id,
                        scan: result.scan,
                    }));
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
            }
        } else {
            match km43::RadioReport::decode(envelope) {
                Ok(report) => {
                    self.wifi.reported(report);
                    actions.push(Action::Send(Outgoing::WifiStateAck { req_id }));
                }
                Err(_) => actions.push(Action::Note(Note::Malformed(kind))),
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

    #[test]
    fn l_015_l_203_scan_without_ack_is_failed_after_three_transmissions() {
        let mut link = Link::new(identity(), Tick::ZERO);
        assert_eq!(link.wifi.refresh(true, true, true, Tick::ZERO), None);
        let req_id = ReqId(123);
        assert!(
            link.requests
                .issue(LinkMessageType::WifiScan, req_id, Tick::ZERO)
        );
        link.wifi_request = Some(req_id);
        for millis in [500, 1000] {
            let mut actions = Actions::NONE;
            link.retry(Tick::from_millis(millis), &mut actions);
            assert!(link.wifi.order().is_some());
            assert!(actions.iter().any(|action| matches!(
                action,
                Action::Send(Outgoing::WifiScan {
                    req_id: ReqId(123),
                    ..
                })
            )));
        }
        let mut actions = Actions::NONE;
        link.retry(Tick::from_millis(1500), &mut actions);
        assert_eq!(link.wifi.order(), None);
        assert_eq!(link.wifi_request, None);
        let mut body = [0; km43::MAX_PAYLOAD];
        let len = link
            .wifi
            .answer(None, Tick::from_millis(1500), &mut body)
            .expect("answer");
        assert_eq!(
            km43::ScanAnswer::decode(&body[..len]).expect("body").scan(),
            km43::ScanState::Failed
        );
    }

    /// Every event goes to the ring as the body KM43 defines for its kind,
    /// and reads back the same.
    #[test]
    fn l_112_every_link_event_is_the_record_km43_defines_for_its_kind() {
        let events = [
            (LinkEvent::LinkLost, EventKind::COMMS_LINK_LOST),
            (
                LinkEvent::PowerCycled { count: 3 },
                EventKind::COMMS_POWER_CYCLED,
            ),
            (
                LinkEvent::Unrecoverable { rail_on: true },
                EventKind::COMMS_UNRECOVERABLE,
            ),
            (
                LinkEvent::Unrecoverable { rail_on: false },
                EventKind::COMMS_UNRECOVERABLE,
            ),
            (
                LinkEvent::BootNoise { count: 0 },
                EventKind::COMMS_BOOT_NOISE,
            ),
            (
                LinkEvent::BootNoise { count: u32::MAX },
                EventKind::COMMS_BOOT_NOISE,
            ),
        ];
        for (event, kind) in events {
            assert_eq!(event.kind(), kind, "{event:?}");
            let record = event.record();
            let mut body = [0u8; km43::CONTROLLER_RECORD_MAX_BYTES];
            let len = record.encode(&mut body).expect("encodes");
            assert_eq!(
                ControllerRecord::decode(kind, &body[..len]),
                Ok(record),
                "{event:?}"
            );
        }
        assert_eq!(
            LinkEvent::Unrecoverable { rail_on: false }.record(),
            ControllerRecord::CommsUnrecoverable { rail_on: false },
            "the branch taken, not a default"
        );
    }

    /// A cycle is counted in its own record, so its count is never zero;
    /// the widest a `u8` holds carries whole.
    #[test]
    fn a_power_cycle_counts_itself_and_its_count_carries_whole() {
        let one = NonZeroU32::new(1).expect("one");
        assert_eq!(
            LinkEvent::PowerCycled { count: 0 }.record(),
            ControllerRecord::CommsPowerCycled { count: one },
            "a zero that cannot happen reads as the one cycle that did"
        );
        assert_eq!(
            LinkEvent::PowerCycled { count: u8::MAX }.record(),
            ControllerRecord::CommsPowerCycled {
                count: NonZeroU32::new(255).expect("nonzero")
            }
        );
    }
    use crate::{BOOT_COUNT_BYTES, Body};

    /// A table of no rows.
    struct NoRows;

    impl Rows for NoRows {
        fn admit(&mut self, _: Conn) -> ClientConnected {
            ClientConnected::RefusedTableFull
        }

        fn release(&mut self, _: Conn) -> ClientDisconnected {
            ClientDisconnected::UnknownHandle
        }

        fn drop_all(&mut self) {}

        fn allocated(&self) -> u8 {
            0
        }
    }

    fn boot(n: u32) -> BootCount {
        let mut bytes = [0u8; BOOT_COUNT_BYTES];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        BootCount::decode(&bytes).expect("a count decodes")
    }

    /// The device secret's id the fixture unit states in key 8.
    const DEVICE_ID: [u8; crate::secret::DEVICE_ID_BYTES] = [0x4f; crate::secret::DEVICE_ID_BYTES];

    fn identity() -> Identity {
        Identity {
            fw: LinkText::new("0.0.0+g0123abcd").expect("fits"),
            hw: LinkText::new("controller-a rev A").expect("fits"),
            boot_id: BootId::derive(b"unit", boot(3)),
            device_id: Some(DEVICE_ID),
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

    fn push_after_link_up(network: crate::Network) -> (Link, Actions, NetworkPush) {
        let mut link = up(at(0));
        link.set_network(Some(network));
        let mut body = [0; 256];
        let len = LinkUp {
            version: OURS,
            role: Side::Comms,
            fw: "0.1.0+g89abcdef",
            boot_id: link.peer().expect("peer").boot_id,
            hw: "comms",
            net_version: Some(99),
            device_id: None,
        }
        .write(link_header(LinkMessageType::LinkUp, ReqId(100)), &mut body)
        .expect("statement");
        let actions = link.received(
            LinkEnvelope::decode(&body[..len]).expect("envelope"),
            at(0),
            &mut NoRows,
        );
        let req_id = link.network_sent.expect("push").0;
        let push = link.network_push(req_id).expect("metadata");
        (link, actions, push)
    }

    fn network_ack(
        link: &mut Link,
        req_id: ReqId,
        outcome: km43::NetConfig,
        version: u32,
    ) -> Actions {
        let mut body = [0; 64];
        let len = km43::NetVerdict { outcome, version }
            .write(
                link_header(LinkMessageType::NetConfigAck, req_id),
                &mut body,
            )
            .expect("ack");
        link.received(
            LinkEnvelope::decode(&body[..len]).expect("envelope"),
            at(1),
            &mut NoRows,
        )
    }

    fn network_cases() -> [(crate::Network, u32, NetworkOperation); 3] {
        let set = network_fixture();
        let mut clear = set;
        clear.clear().expect("clear");
        [
            (set, 1, NetworkOperation::Set),
            (clear, 2, NetworkOperation::Clear),
            (crate::Network::NONE, 0, NetworkOperation::ClearUnwritten),
        ]
    }

    #[test]
    fn l_133_network_sent_note_follows_a_differing_link_up() {
        for (network, version, operation) in network_cases() {
            let (link, actions, push) = push_after_link_up(network);
            let req_id = push.req_id;
            assert_eq!(
                push,
                NetworkPush {
                    req_id,
                    version,
                    operation
                }
            );
            assert!(
                actions
                    .iter()
                    .any(|action| *action == Action::Send(Outgoing::NetConfig { req_id }))
            );
            assert!(actions.iter().any(|action| *action
                == Action::Note(Note::NetworkSent {
                    req_id,
                    version,
                    operation
                })));
            assert_eq!(link.network_push(ReqId(req_id.0 + 1)), None);
            assert_eq!(actions.dropped(), 0);
        }
    }

    #[test]
    fn l_137_network_answered_note_preserves_the_verdict_and_reported_version() {
        for outcome in [
            km43::NetConfig::Stored,
            km43::NetConfig::RejectedInvalid,
            km43::NetConfig::NvsWriteFailed,
        ] {
            let (mut link, _, push) = push_after_link_up(network_fixture());
            let req_id = push.req_id;
            let unexpected = network_ack(&mut link, ReqId(req_id.0 + 1), outcome, 17);
            assert!(
                !unexpected
                    .iter()
                    .any(|action| matches!(action, Action::Note(Note::NetworkAnswered { .. })))
            );
            assert_eq!(link.network_push(req_id), Some(push));
            let actions = network_ack(&mut link, req_id, outcome, 17);
            assert!(actions.iter().any(|action| *action
                == Action::Note(Note::NetworkAnswered {
                    req_id,
                    outcome,
                    version: 17
                })));
            assert_eq!(link.network_push(req_id), None);
            let duplicate = network_ack(&mut link, req_id, outcome, 17);
            assert!(
                !duplicate
                    .iter()
                    .any(|action| matches!(action, Action::Note(Note::NetworkAnswered { .. })))
            );
        }
    }

    #[test]
    fn l_015_network_retry_note_keeps_the_snapshot_and_waits_for_the_deadline() {
        for (network, version, operation) in network_cases() {
            let (mut link, _, push) = push_after_link_up(network);
            let req_id = push.req_id;
            let early = link.tick(at(499), false, &mut NoRows);
            assert!(
                !early
                    .iter()
                    .any(|action| matches!(action, Action::Note(Note::NetworkRetry { .. })))
            );
            for now in [500, 1000] {
                let actions = link.tick(at(now), false, &mut NoRows);
                assert!(actions.iter().any(|action| *action
                    == Action::Note(Note::NetworkRetry {
                        req_id,
                        version,
                        operation
                    })));
                assert!(
                    actions
                        .iter()
                        .any(|action| *action == Action::Send(Outgoing::NetConfig { req_id }))
                );
                assert_eq!(link.network_push(req_id), Some(push));
                assert_eq!(actions.dropped(), 0);
            }
        }
    }

    #[test]
    fn l_015_network_give_up_note_keeps_the_last_snapshot_without_resending() {
        for (network, version, operation) in network_cases() {
            let (mut link, _, push) = push_after_link_up(network);
            let req_id = push.req_id;
            for now in [500, 1000] {
                let actions = link.tick(at(now), false, &mut NoRows);
                assert!(
                    !actions
                        .iter()
                        .any(|action| matches!(action, Action::Note(Note::NetworkGaveUp { .. })))
                );
            }
            let actions = link.tick(at(1500), false, &mut NoRows);
            assert!(actions.iter().any(|action| *action
                == Action::Note(Note::NetworkGaveUp {
                    req_id,
                    version,
                    operation
                })));
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, Action::Send(Outgoing::NetConfig { .. })))
            );
            assert_eq!(link.network_push(req_id), None);
            assert_eq!(actions.dropped(), 0);
            let later = link.tick(at(1501), false, &mut NoRows);
            assert!(
                !later
                    .iter()
                    .any(|action| matches!(action, Action::Note(Note::NetworkGaveUp { .. })))
            );
        }
    }

    // Fixed-capacity formatting for domain tests too: overflowing is a test failure.
    struct DebugText {
        bytes: [u8; 512],
        len: usize,
    }

    impl core::fmt::Write for DebugText {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    fn debug_text(value: impl core::fmt::Debug) -> DebugText {
        use core::fmt::Write as _;
        let mut text = DebugText {
            bytes: [0; 512],
            len: 0,
        };
        write!(&mut text, "{value:?}").expect("bounded debug text");
        text
    }

    #[test]
    fn network_notes_debug_never_contains_network_values_as_text_or_decimal_bytes() {
        for (network, version, operation) in network_cases() {
            let (mut link, sent, push) = push_after_link_up(network);
            let retried = link.tick(at(500), false, &mut NoRows);
            let _ = link.tick(at(1000), false, &mut NoRows);
            let gave_up = link.tick(at(1500), false, &mut NoRows);
            let (mut other, _, other_push) = push_after_link_up(network);
            let answered = network_ack(
                &mut other,
                other_push.req_id,
                km43::NetConfig::Stored,
                version,
            );
            let expected = [
                Note::NetworkSent {
                    req_id: push.req_id,
                    version,
                    operation,
                },
                Note::NetworkRetry {
                    req_id: push.req_id,
                    version,
                    operation,
                },
                Note::NetworkGaveUp {
                    req_id: push.req_id,
                    version,
                    operation,
                },
                Note::NetworkAnswered {
                    req_id: other_push.req_id,
                    outcome: km43::NetConfig::Stored,
                    version,
                },
            ];
            for (actions, expected) in [sent, retried, gave_up, answered].iter().zip(expected) {
                let note = actions
                    .iter()
                    .find_map(|action| {
                        if let Action::Note(note) = action {
                            (*note == expected).then_some(*note)
                        } else {
                            None
                        }
                    })
                    .expect("each new note was emitted");
                let formatted = debug_text(note);
                let text = core::str::from_utf8(&formatted.bytes[..formatted.len]).expect("UTF-8");
                for value in ["cabin", "correct horse", "CA", "origin89"] {
                    let decimal = debug_text(value.as_bytes());
                    let decimal = core::str::from_utf8(&decimal.bytes[..decimal.len])
                        .expect("UTF-8")
                        .trim_matches(['[', ']']);
                    assert!(!text.contains(value), "{note:?} contains {value}");
                    assert!(!text.contains(decimal), "{note:?} contains {decimal}");
                }
            }
        }
    }

    fn network_fixture() -> crate::Network {
        let mut network = crate::Network::NONE;
        network
            .set(crate::Credentials {
                ssid: Text::new("cabin").expect("ssid"),
                psk: crate::Psk::new("correct horse").expect("psk"),
                country: crate::Country::new(*b"CA").expect("country"),
                hostname: Text::new("origin89").expect("host"),
            })
            .expect("network");
        network
    }

    #[test]
    fn l_133_repeated_link_up_preserves_an_owed_local_network_write() {
        let mut link = up(at(0));
        let mut peer = *link.peer().expect("peer");
        peer.net_version = Some(1);
        link.set_network(Some(network_fixture()));
        let mut actions = Actions::NONE;
        link.stated(
            peer,
            link.compat().expect("compat"),
            at(1),
            &mut NoRows,
            &mut actions,
        );
        link.report_network(at(1), &mut actions);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Send(Outgoing::NetConfig { .. })))
        );
    }

    #[test]
    fn l_133_net_config_retries_the_same_snapshot_and_rejects_an_unmatched_ack() {
        let mut link = up(at(0));
        link.set_network(Some(network_fixture()));
        let mut actions = Actions::NONE;
        link.report_network(at(0), &mut actions);
        let (req_id, _) = link.network_sent.expect("sent");
        let (before, len) = envelope_of(&link, Outgoing::NetConfig { req_id }, at(0));
        let mut body = [0; 64];
        let ack_len = km43::NetVerdict {
            outcome: km43::NetConfig::Stored,
            version: 1,
        }
        .write(
            link_header(LinkMessageType::NetConfigAck, ReqId(req_id.0 + 1)),
            &mut body,
        )
        .expect("ack");
        link.network_answered(
            LinkEnvelope::decode(&body[..ack_len]).expect("envelope"),
            &mut actions,
        );
        assert!(link.network_sent.is_some());
        link.retry(at(2000), &mut actions);
        assert!(actions.iter().filter(|action| matches!(action, Action::Send(Outgoing::NetConfig { req_id: sent }) if *sent == req_id)).count() >= 2);
        let (after, after_len) = envelope_of(&link, Outgoing::NetConfig { req_id }, at(2000));
        assert_eq!(&before[..len], &after[..after_len]);
        let ack_len = km43::NetVerdict {
            outcome: km43::NetConfig::Stored,
            version: 1,
        }
        .write(
            link_header(LinkMessageType::NetConfigAck, req_id),
            &mut body,
        )
        .expect("ack");
        link.network_answered(
            LinkEnvelope::decode(&body[..ack_len]).expect("envelope"),
            &mut actions,
        );
        assert!(link.network_sent.is_none());
        assert_eq!(link.peer().expect("peer").net_version, Some(1));
    }

    #[test]
    fn l_135_a_clear_supersedes_an_inflight_set_even_if_the_peer_claimed_its_version() {
        let mut link = up(at(0));
        let mut network = network_fixture();
        link.set_network(Some(network));
        let mut actions = Actions::NONE;
        link.report_network(at(0), &mut actions);
        let (old, _) = link.network_sent.expect("set");
        if let Phase::Up { peer, .. } = &mut link.phase {
            peer.net_version = Some(2);
        }
        network.clear().expect("clear");
        link.set_network(Some(network));
        link.report_network(at(1), &mut actions);
        let (new, sent) = link.network_sent.expect("clear");
        assert_ne!(old, new);
        assert!(!link.requests.awaits(old, LinkMessageType::NetConfig));
        assert!(matches!(
            sent.change(),
            Some(km43::NetChange::Clear { version: 2, .. })
        ));
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
    fn l_034_a_statement_is_written_only_with_a_version_and_its_commit() {
        let link = Link::new(identity(), Tick::from_millis(0));
        let (bytes, len) = envelope_of(
            &link,
            Outgoing::LinkUp { req_id: ReqId(1) },
            Tick::from_millis(0),
        );
        let envelope = LinkEnvelope::decode(&bytes[..len]).expect("decodes");
        let stated = LinkUp::decode(envelope).expect("a statement");
        assert_eq!(stated.fw, "0.0.0+g0123abcd");
        assert_eq!(stated.hw, "controller-a rev A");
        // A text in another shape is refused where it is written, and the
        // statement never leaves.
        let mut unversioned = identity();
        unversioned.fw = LinkText::new("o89-controller 0.0.0").expect("fits");
        let link = Link::new(unversioned, Tick::from_millis(0));
        let mut writer = FrameWriter::new();
        let mut dst = [0u8; MAX_FRAME];
        assert_eq!(
            link.encode(
                Outgoing::LinkUp { req_id: ReqId(1) },
                Tick::from_millis(0),
                &mut writer,
                &mut dst
            ),
            Err(EncodeError::Body)
        );
        // No text at all is refused the same way.
        let mut empty = identity();
        empty.fw = LinkText::EMPTY;
        let link = Link::new(empty, Tick::from_millis(0));
        assert_eq!(
            link.encode(
                Outgoing::LinkUp { req_id: ReqId(1) },
                Tick::from_millis(0),
                &mut writer,
                &mut dst
            ),
            Err(EncodeError::Body)
        );
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
    fn l_071_the_answer_to_a_connection_carries_its_outcome_and_no_challenge() {
        let link = Link::new(identity(), Tick::ZERO);
        for outcome in [
            ClientConnected::Accepted,
            ClientConnected::RefusedTableFull,
            ClientConnected::RefusedHandleInUse,
            ClientConnected::RefusedLinkNotUp,
        ] {
            let (bytes, len) = envelope_of(
                &link,
                Outgoing::ClientUpAck {
                    req_id: ReqId(4),
                    outcome,
                },
                Tick::ZERO,
            );
            let envelope = LinkEnvelope::decode(&bytes[..len]).expect("decodes");
            assert_eq!(
                envelope.keys(),
                1,
                "{outcome:?}: the outcome and nothing else"
            );
            let ack = ClientUpAck::decode(envelope).expect("an ack");
            assert_eq!(ack.outcome, outcome);
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

    /// A link the comms processor brought up at `now` by answering its
    /// statement, speaking `version`.
    fn up_with(now: Tick, version: Version) -> Link {
        let mut link = Link::new(identity(), Tick::ZERO);
        let settled = link.module_settled(now);
        let req_id = settled
            .iter()
            .find_map(|action| {
                if let Action::Send(Outgoing::LinkUp { req_id }) = action {
                    Some(*req_id)
                } else {
                    None
                }
            })
            .expect("a statement");
        let mut buf = [0u8; 256];
        let len = LinkUp {
            version,
            role: Side::Comms,
            fw: "0.1.0+g89abcdef",
            boot_id: 0x5EED,
            hw: "comms",
            net_version: Some(0),
            device_id: None,
        }
        .write(link_header(LinkMessageType::LinkUpAck, req_id), &mut buf)
        .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        let _ = link.received(envelope, now, &mut NoRows);
        assert!(link.is_up());
        link
    }

    fn up(now: Tick) -> Link {
        up_with(now, OURS)
    }

    /// The one pairing report among `actions`, if one; two is a failure.
    fn report(actions: &Actions) -> Option<(ReqId, PairingWindowNotice)> {
        let mut found = None;
        for action in actions {
            if let Action::Send(Outgoing::PairingWindow { req_id, notice }) = action {
                assert_eq!(found, None, "two reports in one call: {actions:?}");
                found = Some((*req_id, *notice));
            }
        }
        found
    }

    /// The one action in `actions`, if exactly one.
    fn only(actions: &Actions) -> Option<Action> {
        (actions.len() == 1)
            .then(|| actions.iter().next().copied())
            .flatten()
    }

    /// The comms processor's acknowledgement of `revision` under `req_id`.
    fn acknowledge(link: &mut Link, req_id: ReqId, revision: u64, now: Tick) -> Actions {
        let mut buf = [0u8; 64];
        let len = PairingWindowAck {
            revision: core::num::NonZeroU64::new(revision).expect("non-zero"),
        }
        .write(
            link_header(LinkMessageType::PairingWindowAck, req_id),
            &mut buf,
        )
        .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        link.received(envelope, now, &mut NoRows)
    }

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    #[test]
    fn l_195_the_first_tick_after_linking_reports_the_window_and_the_report_reads_back() {
        let mut link = up(at(1_000));
        link.pairing_window(Some(at(61_000)), at(1_000));
        let (req_id, notice) = report(&link.tick(at(1_010), false, &mut NoRows)).expect("a report");
        assert_eq!(notice.revision().get(), 1);
        assert_eq!(notice.remaining_ms(), 59_990);
        let (bytes, len) =
            envelope_of(&link, Outgoing::PairingWindow { req_id, notice }, at(1_010));
        let envelope = LinkEnvelope::decode(&bytes[..len]).expect("decodes");
        assert_eq!(envelope.opcode(), LinkMessageType::PairingWindow as u8);
        assert_eq!(envelope.session(), SessionId::None, "L-194");
        assert_eq!(envelope.req_id(), req_id);
        assert_eq!(PairingWindowNotice::decode(envelope), Ok(notice));
        // Nothing more while nothing changes.
        assert_eq!(report(&link.tick(at(1_020), false, &mut NoRows)), None);
    }

    #[test]
    fn l_195_only_an_ack_echoing_the_revision_in_flight_consumes_the_report() {
        let mut link = up(at(0));
        let (req_id, notice) = report(&link.tick(at(10), false, &mut NoRows)).expect("a report");
        let unexpected = Action::Note(Note::UnexpectedAck(LinkMessageType::PairingWindowAck));
        // Another request's id, then this one's with another revision.
        let stray = acknowledge(&mut link, ReqId(req_id.0.wrapping_add(50)), 1, at(20));
        assert_eq!(only(&stray), Some(unexpected));
        let wrong = acknowledge(&mut link, req_id, 2, at(30));
        assert_eq!(only(&wrong), Some(unexpected));
        // A body that does not read.
        let mut buf = [0u8; 64];
        let cbor = link_header(LinkMessageType::PairingWindowAck, req_id)
            .write(0, &mut buf)
            .expect("fits");
        let len = cbor.finish().expect("fits");
        let malformed = link.received(
            LinkEnvelope::decode(&buf[..len]).expect("an envelope"),
            at(40),
            &mut NoRows,
        );
        assert_eq!(
            only(&malformed),
            Some(Action::Note(Note::Malformed(
                LinkMessageType::PairingWindowAck
            )))
        );
        // None of those consumed it: it goes again, the same.
        let again = report(&link.tick(at(510), false, &mut NoRows));
        assert_eq!(again, Some((req_id, notice)));
        // The right one does, and nothing more goes.
        let right = acknowledge(&mut link, req_id, 1, at(520));
        assert!(right.is_empty(), "{right:?}");
        assert_eq!(report(&link.tick(at(1_100), false, &mut NoRows)), None);
        let late = acknowledge(&mut link, req_id, 1, at(1_200));
        assert_eq!(only(&late), Some(unexpected));
    }

    #[test]
    fn l_195_no_report_goes_under_a_major_mismatch() {
        let mut link = up_with(at(0), Version { major: 2, minor: 0 });
        assert!(matches!(link.compat(), Some(Compat::MajorMismatch { .. })));
        link.pairing_window(Some(at(120_000)), at(0));
        for now in [10, 500, 1_000, 5_000] {
            assert_eq!(report(&link.tick(at(now), false, &mut NoRows)), None);
        }
    }

    #[test]
    fn l_195_a_report_held_back_by_four_requests_says_what_is_left_when_it_leaves() {
        let mut link = up(at(0));
        let (req_id, _) = report(&link.tick(at(10), false, &mut NoRows)).expect("a report");
        assert!(acknowledge(&mut link, req_id, 1, at(20)).is_empty());
        // Four closes fill every request slot (L-014) and are never answered.
        for handle in 1..=4 {
            let conn = Conn::new(handle).expect("a handle");
            let _ = link.close(conn, CloseReason::Shedding, at(100));
        }
        link.pairing_window(Some(at(120_100)), at(100));
        for now in [110, 600, 1_100] {
            assert_eq!(
                report(&link.tick(at(now), false, &mut NoRows)),
                None,
                "no slot at {now}"
            );
        }
        // The closes are given up at 1 600 ms and the report leaves then,
        // built from the deadline, not the duration observed.
        let (_, sent) = report(&link.tick(at(1_600), false, &mut NoRows)).expect("a report");
        assert_eq!(sent.revision().get(), 2);
        assert_eq!(sent.remaining_ms(), 118_500);
    }

    #[test]
    fn l_195_a_closure_takes_the_slot_of_the_open_report_it_supersedes_at_once() {
        let mut link = up(at(0));
        let (req_id, _) = report(&link.tick(at(10), false, &mut NoRows)).expect("a report");
        assert!(acknowledge(&mut link, req_id, 1, at(20)).is_empty());
        // Three closes unanswered and the opening make four in flight.
        for handle in 1..=3 {
            let conn = Conn::new(handle).expect("a handle");
            let _ = link.close(conn, CloseReason::Shedding, at(100));
        }
        link.pairing_window(Some(at(120_100)), at(100));
        let (open_id, open) = report(&link.tick(at(110), false, &mut NoRows)).expect("the opening");
        assert_eq!(open.revision().get(), 2);
        // Closed before anything was answered: the closure goes in the same
        // tick, in the open report's slot, and the opening is never retried.
        link.pairing_window(None, at(200));
        let (closed_id, closed) =
            report(&link.tick(at(210), false, &mut NoRows)).expect("the closure at once");
        assert_eq!(closed.revision().get(), 3);
        assert_eq!(closed.remaining_ms(), 0);
        for now in [610, 710, 1_110, 1_210] {
            let resent = report(&link.tick(at(now), false, &mut NoRows));
            assert!(
                resent.is_none_or(|(id, notice)| id == closed_id && notice == closed),
                "{resent:?} at {now}"
            );
        }
        let late = acknowledge(&mut link, open_id, 2, at(1_300));
        assert_eq!(
            only(&late),
            Some(Action::Note(Note::UnexpectedAck(
                LinkMessageType::PairingWindowAck
            )))
        );
    }

    #[test]
    fn l_195_a_report_in_flight_goes_with_the_link_and_is_never_retried_after_it() {
        let mut link = up(at(0));
        let (req_id, _) = report(&link.tick(at(10), false, &mut NoRows)).expect("a report");
        assert!(acknowledge(&mut link, req_id, 1, at(20)).is_empty());
        link.pairing_window(Some(at(120_100)), at(100));
        let (_, open) = report(&link.tick(at(110), false, &mut NoRows)).expect("the opening");
        // The comms processor states itself under another boot: the link
        // falls with the report unanswered.
        let mut buf = [0u8; 256];
        let len = LinkUp {
            version: OURS,
            role: Side::Comms,
            fw: "0.1.0+g89abcdef",
            boot_id: 0xB007,
            hw: "comms",
            net_version: Some(0),
            device_id: None,
        }
        .write(link_header(LinkMessageType::LinkUp, ReqId(90)), &mut buf)
        .expect("fits");
        let rebooted = link.received(
            LinkEnvelope::decode(&buf[..len]).expect("an envelope"),
            at(200),
            &mut NoRows,
        );
        assert!(
            rebooted
                .iter()
                .any(|a| *a == Action::DropConnections(DropReason::CommsRebooted))
        );
        assert!(!link.is_up());
        // Its retry time comes and goes with nothing sent to the new boot.
        for now in (210..2_000).step_by(100) {
            let ticked = link.tick(at(now), false, &mut NoRows);
            assert_eq!(report(&ticked), None, "{open:?} retried at {now}");
        }
    }

    #[test]
    fn l_195_when_the_revisions_run_out_the_link_falls_and_stays_down_until_a_reboot() {
        let mut link = up(at(0));
        link.pairing.skip_to(core::num::NonZeroU64::MAX);
        let (req_id, last) = report(&link.tick(at(10), false, &mut NoRows)).expect("a report");
        assert_eq!(
            last.revision(),
            core::num::NonZeroU64::MAX,
            "the last is used"
        );
        assert!(acknowledge(&mut link, req_id, u64::MAX, at(20)).is_empty());
        assert!(link.is_up() && !link.revisions_spent());
        // The next report owed has no revision: the link falls, nothing wraps.
        link.pairing_window(Some(at(120_100)), at(100));
        let fell = link.tick(at(110), false, &mut NoRows);
        assert_eq!(report(&fell), None);
        assert!(
            fell.iter()
                .any(|a| *a == Action::DropConnections(DropReason::RevisionsSpent))
        );
        assert!(!link.is_up());
        assert!(link.revisions_spent());
        // Nothing states this side again, and the silence is never cut.
        let settled = link.module_settled(at(200));
        assert!(settled.iter().all(|a| !matches!(a, Action::Send(_))));
        for now in (300..200_000).step_by(100) {
            let ticked = link.tick(at(now), false, &mut NoRows);
            assert!(
                ticked
                    .iter()
                    .all(|a| !matches!(a, Action::Send(_) | Action::CutRail)),
                "{ticked:?} at {now}"
            );
        }
    }

    #[test]
    fn nothing_is_said_and_no_silence_is_measured_before_the_module_is_powered() {
        let mut link = Link::new(identity(), Tick::ZERO);
        let actions = link.tick(Tick::from_millis(120_000), false, &mut NoRows);
        assert!(actions.is_empty(), "{actions:?}");
        let actions = link.module_settled(Tick::from_millis(120_000));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Send(Outgoing::LinkUp { .. }))),
            "the statement goes out the moment the module is powered"
        );
    }
    /// Rows that hold a count of connections.
    struct Held(u8);

    impl Rows for Held {
        fn admit(&mut self, _: Conn) -> ClientConnected {
            self.0 = self.0.saturating_add(1);
            ClientConnected::Accepted
        }

        fn release(&mut self, _: Conn) -> ClientDisconnected {
            self.0 = self.0.saturating_sub(1);
            ClientDisconnected::Released
        }

        fn drop_all(&mut self) {
            self.0 = 0;
        }

        fn allocated(&self) -> u8 {
            self.0
        }
    }

    /// The `n`th beat after linking at one second, answered with `conns`:
    /// what the answer asked for.
    fn answer_beat(link: &mut Link, rows: &mut Held, n: u64, conns: u8) -> Actions {
        let now = at(2_000u64.saturating_mul(n).saturating_add(1_010));
        let ticked = link.tick(now, false, rows);
        let req_id = ticked
            .iter()
            .find_map(|action| {
                if let Action::Send(Outgoing::Heartbeat { req_id }) = action {
                    Some(*req_id)
                } else {
                    None
                }
            })
            .expect("a beat");
        let mut buf = [0u8; 64];
        let len = Heartbeat { uptime_s: 1, conns }
            .write(link_header(LinkMessageType::HeartbeatAck, req_id), &mut buf)
            .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        link.received(envelope, now, rows)
    }

    /// The close of every connection among `actions`, if one.
    fn resync(actions: &Actions) -> Option<ReqId> {
        actions.iter().find_map(|action| {
            if let Action::Send(Outgoing::Resync { req_id }) = action {
                Some(*req_id)
            } else {
                None
            }
        })
    }

    /// The comms processor's report of a close, under `req_id`.
    fn close_report(link: &mut Link, rows: &mut Held, req_id: ReqId, now: Tick) -> Actions {
        let mut buf = [0u8; 64];
        let len = CloseReport {
            outcome: km43::CloseConnection::Closed,
            closed: 1,
        }
        .write(
            link_header(LinkMessageType::CloseConnectionAck, req_id),
            &mut buf,
        )
        .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        link.received(envelope, now, rows)
    }

    /// The comms processor stating itself again under the same boot,
    /// speaking `version`.
    fn restate(link: &mut Link, version: Version, req_id: u32, now: Tick) -> Actions {
        let mut buf = [0u8; 256];
        let len = LinkUp {
            version,
            role: Side::Comms,
            fw: "0.1.0+g89abcdef",
            boot_id: 0x5EED,
            hw: "comms",
            net_version: Some(0),
            device_id: None,
        }
        .write(
            link_header(LinkMessageType::LinkUp, ReqId(req_id)),
            &mut buf,
        )
        .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        link.received(envelope, now, &mut NoRows)
    }

    #[test]
    fn l_102_three_disagreeing_answers_in_a_row_close_every_connection_once() {
        let mut link = up(at(1_000));
        let mut rows = Held(2);
        assert_eq!(resync(&answer_beat(&mut link, &mut rows, 1, 1)), None);
        assert_eq!(resync(&answer_beat(&mut link, &mut rows, 2, 1)), None);
        let req_id = resync(&answer_beat(&mut link, &mut rows, 3, 1)).expect("the third");
        // Asked once: the counts still disagree while it is in flight.
        assert_eq!(resync(&answer_beat(&mut link, &mut rows, 4, 1)), None);
        assert_eq!(rows.0, 2, "no row goes before the answer");
        // On the wire it is a close of handle 0, for a resync.
        let (frame, len) = envelope_of(&link, Outgoing::Resync { req_id }, at(7_100));
        let envelope = LinkEnvelope::decode(&frame[..len]).expect("an envelope");
        assert_eq!(envelope.opcode(), LinkMessageType::CloseConnection as u8);
        let close = CloseConnections::decode(envelope).expect("a close");
        assert!(close.is_every_connection());
        assert_eq!(close.reason, CloseReason::Resync);
    }

    #[test]
    fn l_102_an_agreeing_answer_starts_the_count_again() {
        let mut link = up(at(1_000));
        let mut rows = Held(1);
        for (n, theirs) in [(1, 0), (2, 0), (3, 1), (4, 0), (5, 0)] {
            let actions = answer_beat(&mut link, &mut rows, n, theirs);
            assert_eq!(resync(&actions), None, "beat {n}");
        }
        assert!(resync(&answer_beat(&mut link, &mut rows, 6, 0)).is_some());
    }

    #[test]
    fn l_102_no_resync_goes_under_a_major_mismatch_however_long_the_counts_disagree() {
        let mut link = up_with(at(1_000), Version { major: 2, minor: 0 });
        assert!(matches!(link.compat(), Some(Compat::MajorMismatch { .. })));
        let mut rows = Held(2);
        // The peer would refuse the close (L-050): sent, it would be given up
        // and owed again three answers later, for as long as the link lasts.
        for n in 1..=30 {
            let actions = answer_beat(&mut link, &mut rows, n, 0);
            assert_eq!(resync(&actions), None, "beat {n}");
        }
        assert_eq!(rows.0, 2, "no row goes without the peer's answer");
        // Nor did those answers count: agreed again, nothing is owed.
        let _ = restate(&mut link, OURS, 90, at(62_000));
        assert!(matches!(link.compat(), Some(Compat::Agreed(_))));
        assert_eq!(resync(&link.tick(at(62_100), false, &mut rows)), None);
    }

    #[test]
    fn l_102_a_resync_owed_when_the_version_turns_mismatched_is_held_until_it_agrees() {
        let mut link = up(at(1_000));
        let mut rows = Held(2);
        // Owed and held back: as four requests in flight would leave it.
        link.resync = Resync::Owed;
        // The same boot states another major: still up, and mismatched,
        // for less than the silence that would fall the link (L-100).
        let _ = restate(&mut link, Version { major: 2, minor: 0 }, 90, at(1_100));
        assert!(matches!(link.compat(), Some(Compat::MajorMismatch { .. })));
        for now in (1_200..5_000).step_by(100) {
            let ticked = link.tick(at(now), false, &mut rows);
            assert_eq!(resync(&ticked), None, "sent at {now}");
        }
        // Agreed again, the close owed goes.
        let _ = restate(&mut link, OURS, 91, at(5_000));
        assert!(matches!(link.compat(), Some(Compat::Agreed(_))));
        assert!(resync(&link.tick(at(5_100), false, &mut rows)).is_some());
    }

    #[test]
    fn l_102_the_answer_to_the_resync_frees_every_row_and_the_counts_agree_after() {
        let mut link = up(at(1_000));
        let mut rows = Held(3);
        for n in 1..=2 {
            let _ = answer_beat(&mut link, &mut rows, n, 1);
        }
        let req_id = resync(&answer_beat(&mut link, &mut rows, 3, 1)).expect("sent");
        let answered = close_report(&mut link, &mut rows, req_id, at(7_050));
        assert!(
            answered
                .iter()
                .any(|a| *a == Action::DropConnections(DropReason::Resync)),
            "{answered:?}"
        );
        assert_eq!(rows.0, 0);
        // The same answer again is one nothing waits for.
        let again = close_report(&mut link, &mut rows, req_id, at(7_060));
        assert_eq!(
            only(&again),
            Some(Action::Note(Note::UnexpectedAck(
                LinkMessageType::CloseConnectionAck
            )))
        );
        // Both sides count none now, and nothing is sent again.
        for n in 4..=10 {
            let actions = answer_beat(&mut link, &mut rows, n, 0);
            assert_eq!(resync(&actions), None, "beat {n}");
        }
    }

    #[test]
    fn l_102_an_answer_to_the_resync_that_does_not_read_frees_nothing_and_it_goes_again() {
        let mut link = up(at(1_000));
        let mut rows = Held(1);
        for n in 1..=2 {
            let _ = answer_beat(&mut link, &mut rows, n, 0);
        }
        let req_id = resync(&answer_beat(&mut link, &mut rows, 3, 0)).expect("sent");
        let mut buf = [0u8; 16];
        let cbor = link_header(LinkMessageType::CloseConnectionAck, req_id)
            .write(0, &mut buf)
            .expect("fits");
        let len = cbor.finish().expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        let malformed = link.received(envelope, at(7_050), &mut rows);
        assert_eq!(
            only(&malformed),
            Some(Action::Note(Note::Malformed(
                LinkMessageType::CloseConnectionAck
            )))
        );
        assert_eq!(rows.0, 1);
        // Retried under the same request, as any request is (L-015).
        let retried = link.tick(at(7_600), false, &mut rows);
        assert_eq!(resync(&retried), Some(req_id));
        let _ = close_report(&mut link, &mut rows, req_id, at(7_650));
        assert_eq!(rows.0, 0);
    }

    /// A unit whose device secret is absent this boot.
    fn without_device_id() -> Link {
        Link::new(
            Identity {
                device_id: None,
                ..identity()
            },
            Tick::ZERO,
        )
    }

    /// Whether `actions` holds anything said to the module or a cut.
    fn speaks_or_cuts(actions: &Actions) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::Send(_) | Action::CutRail))
    }

    #[test]
    fn l_035_every_statement_the_controller_writes_carries_its_device_id() {
        let link = Link::new(identity(), Tick::ZERO);
        for outgoing in [
            Outgoing::LinkUp { req_id: ReqId(1) },
            Outgoing::LinkUpAck { req_id: ReqId(2) },
        ] {
            let (bytes, len) = envelope_of(&link, outgoing, Tick::ZERO);
            let envelope = LinkEnvelope::decode(&bytes[..len]).expect("decodes");
            let ours = LinkUp::decode(envelope).expect("a statement");
            assert_eq!(ours.device_id, Some(DEVICE_ID), "{outgoing:?}");
        }
    }

    #[test]
    fn l_035_without_a_device_id_the_controller_states_nothing_and_never_cuts() {
        let mut link = without_device_id();
        let settled = link.module_settled(at(0));
        assert!(!speaks_or_cuts(&settled), "{settled:?}");
        // Well past the sixty seconds L-111 would count from the rail.
        for now in (100..200_000).step_by(100) {
            let ticked = link.tick(at(now), false, &mut NoRows);
            assert!(!speaks_or_cuts(&ticked), "{ticked:?} at {now}");
        }
        assert!(!link.is_up());
    }

    #[test]
    fn l_035_without_a_device_id_a_comms_statement_is_left_unanswered() {
        let mut link = without_device_id();
        let _ = link.module_settled(at(0));
        let mut buf = [0u8; 256];
        let len = LinkUp {
            version: OURS,
            role: Side::Comms,
            fw: "0.1.0+g89abcdef",
            boot_id: 0x5EED,
            hw: "comms",
            net_version: Some(0),
            device_id: None,
        }
        .write(link_header(LinkMessageType::LinkUp, ReqId(40)), &mut buf)
        .expect("fits");
        let envelope = LinkEnvelope::decode(&buf[..len]).expect("an envelope");
        let answered = link.received(envelope, at(10), &mut NoRows);
        assert_eq!(only(&answered), Some(Action::Note(Note::NoDeviceId)));
        assert!(!link.is_up());
    }

    /// The other side of the two tests above: a unit with its id, whose
    /// module never answers, is cut once the ladder's sixty seconds pass.
    #[test]
    fn l_111_a_unit_with_its_device_id_still_cuts_a_silent_module() {
        let mut link = Link::new(identity(), Tick::ZERO);
        let settled = link.module_settled(at(0));
        assert!(
            settled
                .iter()
                .any(|a| matches!(a, Action::Send(Outgoing::LinkUp { .. })))
        );
        let cut = (100..=CUT_AFTER.as_millis())
            .step_by(100)
            .map(|now| link.tick(at(now), false, &mut NoRows))
            .any(|ticked| ticked.iter().any(|a| *a == Action::CutRail));
        assert!(cut, "no cut by sixty seconds of silence");
    }
}
