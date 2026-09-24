//! The connection rows, the challenge each one holds, and the session a
//! `Hello` binds onto it.
//!
//! **A row is allocated before it is bound** (P-076, L-062). The comms
//! processor announces a transport and the controller gives it a row, and
//! the row holds the connection's challenge from that moment (L-070); a
//! `Hello` whose proof verifies binds a session onto it; `Goodbye` clears
//! the binding and leaves the row to the transport that is still open;
//! only the transport going, or the comms processor rebooting, frees the
//! row (L-041). Eight rows, and a ninth announcement is refused rather than
//! evicting one (L-061). The session's id is the row's handle: one number
//! on the wire, and no mapping to disagree about.
//!
//! **A challenge is derived, never drawn** (P-063): the part has no RNG, so
//! each one is the device secret's PRF over a counter the part has already
//! written ([`Minted`]). One per row at most, single use, and dead at 120
//! seconds or with its connection (P-060, P-061, P-062). A `Discover` is
//! answered with the row's live one or a fresh one, never a dead one.
//!
//! **Only a frame that proved itself refreshes a session** (P-077): a
//! wrapper whose MAC verified. What the controller sends, and what arrives
//! and fails, do not; a failure counts against the connection, eight inside
//! a minute sheds it, and a new `Hello` does not reset the count (P-051).
//!
//! **A verified request is then held to the session's `req_id` window**
//! (P-022), before its counter is read or its body acted on: one the
//! session accepted already, or one below the highest less `MAX_INFLIGHT`,
//! is dropped without an answer or a refresh. It proved itself, so it is
//! not a failure against the connection.
//!
//! Every answer is addressed to the frame it answers: the handle in
//! `session_id`, the request's `req_id` echoed (P-026, L-182). Before a
//! session exists, and whenever the controller holds no key for the one
//! named, an error goes bare; once one exists, an answer to a frame that
//! verified goes under its key (P-142). An unverified frame is never
//! answered under a key: a tag over a `req_id` the comms processor chose
//! is a response it could hold back and play against the client's real
//! request later.
//!
//! **A `Command` goes through [`admit`]**, in P-080's order, under the
//! session's key and the client it was bound to (P-084). No command kind
//! has an argument schema yet (km43's DEFERRED entry 8), so what is
//! permitted is answered `rejected` and nothing reaches an output: its
//! counter is spent and its dedup entry discarded, as P-120 has for a
//! command that did not run. A retry meeting an entry a reset left in
//! flight runs again for the same reason: no output can already be where
//! a command asked.
//!
//! **A `Pair` enrols only inside the pairing window** the selector opens
//! (P-066), read when the frame is handled. Every answer to one is MAC'd
//! under the pair key, refusals included, so the comms processor cannot
//! forge a `window_closed` that sends somebody back to the panel (P-064).
//! A row lands on the part before the answer says so, and an enrolment or
//! a reclaim closes the window behind it (L-195).
//!
//! What this slice does not serve yet is refused with error 2, bare or
//! under the key by the rule above: the three other signed requests,
//! whose handlers call [`admit`] when they land, and the wrapped reads
//! (theirs). Each is an arm of the exhaustive match below, which is where
//! those slices land.
//!
//! cites: P-021, P-022, P-026, P-051, P-058, P-060, P-061, P-062, P-063, P-064,
//! P-066, P-067, P-073, P-076, P-077, P-078, P-079, P-080, P-084, P-086,
//! P-143, L-061, L-062, L-070, L-071, L-072, L-080, L-180, L-182, L-195

use km43::{
    CapabilityBit, Caps, ClientConnected, ClientDisconnected, ClientId, CloseReason, CommandAck,
    Conn, EmptyBody, Envelope, EnvelopeError, Epoch, ErrorBody, ErrorCode, Handshake,
    HandshakeError, Header, HelloClaim, HelloReport, Incoming, LinkEnvelope, LinkErrorCode, LogSeq,
    MAX_AUTH_FAILURES, MAX_COMMAND_ACK_BYTES, MAX_HELLO_REPORT, MAX_SESSIONS, MAX_TIME_ACK_BYTES,
    MessageType, Outcome, PairClaim, PairRequest, PairResponse, Refusal as Code, ReqId, SessionId,
    SessionKey, SignedClaim, SignedError, StateSeq, Tagged, TimeAck, TimeOperation, Topology,
    Version, Wrapper, WrapperError, WrapperKey,
};

use crate::body::Kept;
use crate::challenge::{CHALLENGE_BYTES, CHALLENGE_COUNTER_BYTES, ChallengeCounter};
use crate::clients::{CLIENT_TABLE_BYTES, ClientTable, Label, Paired, TableFull};
use crate::epoch::{EPOCH_BYTES, ResetFailed, reset_clients};
use crate::fram::Fram;
use crate::link::Rows;
use crate::req_window::{OutOfWindow, ReqWindow};
use crate::request::{Admission, Executed, Permit, Refusal, admit};
use crate::secret::Secret;
use crate::tick::{Millis, Tick};

/// Connection rows: one per session the protocol permits, so a row that
/// exists can always be bound and error 8 never fires over this link
/// (L-061).
pub const CONNECTIONS: usize = MAX_SESSIONS;

/// A challenge dies this long after it was minted (P-062).
pub const CHALLENGE_LIFE: Millis = Millis::from_millis(120_000);

/// A session dies this long after the last frame that proved itself
/// (P-077).
pub const SESSION_IDLE: Millis = Millis::from_millis(15 * 60 * 1_000);

/// The window `MAX_AUTH_FAILURES` is counted over (P-051).
pub const FAILURE_WINDOW: Millis = Millis::from_millis(60_000);

/// What a permitted command is told while no kind has an argument schema.
pub const UNSPECIFIED: &str = "no command kind has an argument schema yet";

/// Failures a connection may accumulate inside the window; the one that
/// reaches it sheds the connection.
const FAILURES: usize = MAX_AUTH_FAILURES as usize;

/// What the controller keeps for the client protocol, as the boot read it:
/// the secret every key descends from, the epoch keys derive under and its
/// record, the enrolled clients and the challenge counter. The records move
/// only once the part has moved.
pub struct Keys {
    /// Versioned identity and behaviour sections.
    pub configuration: crate::Configuration,
    /// The authoritative network section.
    pub network: Kept<crate::Network, { crate::NETWORK_BYTES }>,
    /// No secret is a unit that derives nothing: no challenge, no key.
    pub secret: Option<Secret>,
    /// No epoch is a boot that could not establish one, and derives nothing
    /// (P-085). The boot's answer, which is not always what the record
    /// holds: a record behind the table that could not be raised holds an
    /// epoch nothing may derive under.
    pub epoch: Option<Epoch>,
    /// The epoch's record, which a factory reset advances.
    pub epoch_record: Kept<Epoch, EPOCH_BYTES>,
    /// The enrolled clients and their counters.
    pub clients: Kept<ClientTable, CLIENT_TABLE_BYTES>,
    /// The counter every challenge is derived from.
    pub challenges: Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES>,
}

/// What a `Discover` or a `Hello` reports that the rows do not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts<'a> {
    /// `Discover` key 4.
    pub model: &'a str,
    /// `Hello` key 4.
    pub fw_controller: &'a str,
    /// `Hello` key 5: what the comms processor says of itself, which a
    /// client does not decide on.
    pub fw_comms: &'a str,
    /// `Hello` keys 7 and 8.
    pub log: LogSpan,
    /// `Hello` key 10.
    pub time_known: bool,
    /// `Discover` key 6, and whether a `Pair` may enrol: the pairing window,
    /// read as this frame is handled and never cached (P-066).
    pub pairing_open: bool,
    /// Whether the link-local handshake is done: a client frame before it
    /// is refused with 258 (L-033, L-180).
    pub link_up: bool,
}

/// The oldest and newest sequence the log holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LogSpan {
    /// `Hello` key 7.
    pub oldest: LogSeq,
    /// `Hello` key 8.
    pub newest: LogSeq,
}

/// A connection the comms processor is to close, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Close {
    /// Which.
    pub conn: Conn,
    /// Why, as the ack's reason carries it.
    pub reason: CloseReason,
}

/// Something for the probe about a client frame, never for the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionNote {
    /// A frame whose four elements did not read, refused with error 1 at
    /// `0, 0` before any element was read (P-025, P-028): no handle to
    /// answer on.
    Unreadable,
    /// A client frame carrying handle 0, which the comms processor stamps
    /// over on every frame it relays (P-021). Its bug; nothing to answer.
    NoHandle,
    /// Refused with this code.
    Refused(u16),
    /// A session was bound on this handle.
    Bound(Conn),
    /// A `Pair` enrolled or reclaimed this client: the window that allowed it
    /// closes now (L-195).
    Paired(ClientId),
    /// A client's `Time`, for the recorder to decide and answer.
    TimeAsked(TimeAsked),
    /// The client said goodbye on this handle.
    Unbound(Conn),
    /// A challenge could not be minted: the counter did not land, is at its
    /// ceiling, is unreadable, or there is no secret to derive from.
    NoChallenge,
    /// An `Error` from a client, which is never answered.
    ClientError,
    /// A signed request's record did not land: its counter, refused with
    /// error 7 and nothing run, which P-079 raises as `counter write
    /// failed`; or a command's outcome, whose entry is left for the state
    /// store.
    NotKept,
    /// The answer did not fit the buffer: a bug in a cap.
    TooLarge,
    /// A request that verified under the session's key and was dropped
    /// unanswered for its `req_id` (P-022): nothing acted, the counter was
    /// not read, and the session was not refreshed. P-022 says it is not
    /// answered, and an answer under the key would be a second genuine
    /// response to a `(session_id, req_id)` already answered.
    OutOfWindow(OutOfWindow),
}

/// What the adapter does with one client frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an answer nobody sends is a client waiting on a timeout"]
pub struct Reply {
    /// The answer's envelope, this many bytes at the head of the buffer.
    pub answer: Option<usize>,
    /// A connection to close once the answer is out.
    pub close: Option<Close>,
    /// For the probe.
    pub note: Option<SessionNote>,
}

impl Reply {
    const NOTHING: Self = Self {
        answer: None,
        close: None,
        note: None,
    };

    const fn noted(note: SessionNote) -> Self {
        Self {
            answer: None,
            close: None,
            note: Some(note),
        }
    }
}

/// The connections a tick found expired, to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a session expired and nobody closed its transport"]
pub struct Expired([Option<Conn>; CONNECTIONS]);

impl Expired {
    /// Each connection whose session expired.
    pub fn iter(&self) -> impl Iterator<Item = Close> + '_ {
        self.0.iter().flatten().map(|conn| Close {
            conn: *conn,
            reason: CloseReason::SessionExpired,
        })
    }
}

/// The challenge a row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Challenge {
    /// Accepted and not minted yet; the next [`Sessions::settle`] or
    /// `Discover` mints it (L-070).
    Owed,
    /// Live until [`CHALLENGE_LIFE`] after `minted`.
    Live {
        bytes: [u8; CHALLENGE_BYTES],
        minted: Tick,
    },
    /// Consumed or expired: a `Discover` mints another (P-060).
    Spent,
}

/// Whether a session is bound on a row, and whether one ever was.
enum Bound {
    /// No `Hello` has succeeded here: a session request is error 4.
    Never,
    /// Running.
    Session(Binding),
    /// One was, and is gone: a session request is error 9 (P-143).
    Ended,
}

struct Binding {
    /// The client that proved.
    client: ClientId,
    key: SessionKey,
    /// The last frame that proved itself (P-077).
    heard: Tick,
    /// Which binding this is, so an answer that took its time goes to the
    /// session that asked and to no later one on the same handle.
    serial: u32,
    /// The `req_id`s this session accepted (P-022), gone with it.
    window: ReqWindow,
}

/// A client's `Time` the recorder is deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AskedTime {
    ticket: u32,
    to: Addressed,
    serial: u32,
    asked: Tick,
}

/// How long a client's `Time` waits for the recorder before it is
/// forgotten: past the floor scan's thirty seconds, so a slow answer still
/// lands, and short enough that a lost one does not refuse every later
/// `Time` with 7.
pub const TIME_ANSWER_LIMIT: Millis = Millis::from_millis(60_000);

/// Whether a client `Time` handed on at `asked` has waited out
/// [`TIME_ANSWER_LIMIT`] by `now`, or the tick gives it no age to trust. The
/// session forgets it then, and the recorder must not act on it after: the
/// client that asked is no longer waiting for the answer.
#[must_use]
pub fn time_expired(asked: Tick, now: Tick) -> bool {
    now.since(asked)
        .is_none_or(|waited| waited.as_millis() >= TIME_ANSWER_LIMIT.as_millis())
}

/// What a client's `Time` asks the recorder, which owns the calendar, the
/// log the floor comes from, and the record the set is written into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeAsked {
    /// What the answer is handed back with.
    pub ticket: u32,
    /// The operation's `at`, milliseconds since the epoch.
    pub at: u64,
    /// Whether the client's mask lets it set the clock; answered
    /// `unauthorised` otherwise, with the clock the controller keeps (P-105).
    pub authorised: bool,
}

/// The recorder's answer to a client's `Time`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeAnswer {
    /// Its `TimeAck`.
    Ack(TimeAck),
    /// Inside fifteen minutes of the last one accepted, or another change
    /// is still owed to the log: error 7, and nothing executed (P-118).
    Busy,
}

struct Row {
    conn: Conn,
    challenge: Challenge,
    bound: Bound,
    /// When each failure inside the window happened (P-051).
    failures: [Option<Tick>; FAILURES],
}

impl Row {
    const fn new(conn: Conn) -> Self {
        Self {
            conn,
            challenge: Challenge::Owed,
            bound: Bound::Never,
            failures: [None; FAILURES],
        }
    }

    /// Count a failure at `now`: the ones older than the window are
    /// forgotten first. Whether it reaches the threshold.
    fn failed(&mut self, now: Tick) -> bool {
        for slot in &mut self.failures {
            if slot.is_some_and(|at| {
                now.since(at)
                    .is_some_and(|age| age.as_millis() >= FAILURE_WINDOW.as_millis())
            }) {
                *slot = None;
            }
        }
        if let Some(free) = self.failures.iter_mut().find(|slot| slot.is_none()) {
            *free = Some(now);
        }
        self.failures.iter().flatten().count() >= FAILURES
    }

    /// Take the live challenge: consumed on presentation, whatever the
    /// proof turns out to be (P-061). None when it is spent, owed or dead.
    fn take_challenge(&mut self, now: Tick) -> Option<[u8; CHALLENGE_BYTES]> {
        let taken = match self.challenge {
            Challenge::Live { bytes, minted } if alive(minted, now) => Some(bytes),
            Challenge::Live { .. } | Challenge::Owed | Challenge::Spent => None,
        };
        if let Challenge::Live { .. } = self.challenge {
            self.challenge = Challenge::Spent;
        }
        taken
    }
}

fn alive(minted: Tick, now: Tick) -> bool {
    now.since(minted)
        .is_none_or(|age| age.as_millis() < CHALLENGE_LIFE.as_millis())
}

/// The rows and what the controller keeps for the client protocol.
pub struct Sessions {
    rows: [Option<Row>; CONNECTIONS],
    keys: Keys,
    /// The last binding's serial.
    bindings: u32,
    /// The one client `Time` in the recorder's hands; a second waits its
    /// turn as error 7, which P-118's one-a-quarter-hour makes rare.
    time: Option<AskedTime>,
    /// The last ticket handed to the recorder.
    tickets: u32,
}

impl Sessions {
    /// No connections, and the keys the boot read.
    #[must_use]
    pub const fn new(keys: Keys) -> Self {
        Self {
            rows: [const { None }; CONNECTIONS],
            keys,
            bindings: 0,
            time: None,
            tickets: 0,
        }
    }

    /// What the rows are kept under.
    #[must_use]
    pub const fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Allocated rows, bound or not: the heartbeat's `conns` (L-101).
    #[must_use]
    pub fn allocated(&self) -> u8 {
        u8::try_from(self.rows.iter().flatten().count()).unwrap_or(u8::MAX)
    }

    /// Sessions bound onto those rows.
    #[must_use]
    pub fn bound(&self) -> usize {
        self.rows
            .iter()
            .flatten()
            .filter(|row| matches!(row.bound, Bound::Session(_)))
            .count()
    }

    /// Whether a session is bound on `conn`.
    #[must_use]
    pub fn is_bound(&self, conn: Conn) -> bool {
        self.row(conn)
            .is_some_and(|row| matches!(row.bound, Bound::Session(_)))
    }

    /// The client whose proof bound the session on `conn`, if one is bound.
    #[must_use]
    pub fn proven(&self, conn: Conn) -> Option<ClientId> {
        match self.row(conn).map(|row| &row.bound) {
            Some(Bound::Session(binding)) => Some(binding.client),
            Some(Bound::Never | Bound::Ended) | None => None,
        }
    }

    /// The comms processor announced a transport (L-060). A handle already
    /// allocated is refused, since the comms processor must not reuse one
    /// before its release is answered (L-080); a full table is refused and
    /// nothing is evicted (L-061). An accepted row owes a challenge, which
    /// [`Sessions::settle`] mints before the next frame is read (L-070).
    /// Nothing about the transport or the peer enters the decision (L-072).
    pub fn admit(&mut self, conn: Conn) -> ClientConnected {
        if self.row(conn).is_some() {
            return ClientConnected::RefusedHandleInUse;
        }
        match self.rows.iter_mut().find(|row| row.is_none()) {
            Some(free) => {
                *free = Some(Row::new(conn));
                ClientConnected::Accepted
            }
            None => ClientConnected::RefusedTableFull,
        }
    }

    /// The transport went: the row, its challenge and any session on it go
    /// with it (P-062, P-076).
    pub fn release(&mut self, conn: Conn) -> ClientDisconnected {
        match self
            .rows
            .iter_mut()
            .find(|row| row.as_ref().is_some_and(|row| row.conn == conn))
        {
            Some(row) => {
                *row = None;
                ClientDisconnected::Released
            }
            None => ClientDisconnected::UnknownHandle,
        }
    }

    /// Every row goes: the comms processor rebooted, the link fell, or the
    /// bench took the module (L-041).
    pub fn drop_all(&mut self) {
        self.rows = [const { None }; CONNECTIONS];
    }

    /// The physical factory reset (P-085): the epoch advanced and verified,
    /// then the table cleared under it. The network clear and old-slot scrub land before the
    /// epoch can advance. Every session ends first, whatever
    /// comes of the writes, because each was keyed under the epoch this
    /// retires; the rows stay with their transports, and a client that
    /// pairs again under the new epoch `Hello`s on the same one. Keys derive
    /// afterwards under what the record holds, which after a failure may be
    /// nothing at all: that is the failure closed.
    pub async fn factory_reset<F: Fram>(
        &mut self,
        fram: &mut F,
    ) -> Result<(), ResetFailed<F::Error>> {
        for row in self.rows.iter_mut().flatten() {
            if let Bound::Session(_) = row.bound {
                row.bound = Bound::Ended;
            }
        }
        match self.keys.network.held() {
            crate::Held::Present(held) => {
                let mut cleared = *held;
                cleared
                    .clear()
                    .map_err(|_| ResetFailed::Network(crate::Refused::AtTheCeiling))?;
                self.keys
                    .network
                    .write(fram, cleared)
                    .await
                    .map_err(ResetFailed::Network)?;
                self.keys
                    .network
                    .erase_previous(fram)
                    .await
                    .map_err(ResetFailed::Network)?;
            }
            // An interrupted erase can read absent with residue in the other slot.
            crate::Held::Absent | crate::Held::Corrupt | crate::Held::Malformed(_) => {
                self.keys
                    .network
                    .erase(fram)
                    .await
                    .map_err(ResetFailed::Network)?;
            }
        }
        let reset = reset_clients(&mut self.keys.epoch_record, &mut self.keys.clients, fram).await;
        self.keys.epoch = self.keys.epoch_record.present().copied();
        reset
    }

    /// Mint every challenge an accepted row owes, each written before it
    /// exists (L-070, P-063). A mint that fails leaves the row owing, and
    /// the connection's first `Discover` tries again.
    pub async fn settle<F: Fram>(&mut self, now: Tick, fram: &mut F) {
        for index in 0..CONNECTIONS {
            let owed = self
                .rows
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|row| row.challenge == Challenge::Owed);
            if !owed {
                continue;
            }
            let minted = self.mint(fram).await;
            if let (Some(bytes), Some(Some(row))) = (minted, self.rows.get_mut(index)) {
                row.challenge = Challenge::Live { bytes, minted: now };
            }
        }
    }

    /// Sessions whose last proven frame is fifteen minutes old are
    /// unbound, their keys destroyed, and their transports to be closed
    /// (P-077). The row stays allocated until the transport goes.
    pub fn tick(&mut self, now: Tick) -> Expired {
        if self
            .time
            .is_some_and(|asked| time_expired(asked.asked, now))
        {
            self.time = None;
        }
        let mut expired = [None; CONNECTIONS];
        for (row, out) in self.rows.iter_mut().flatten().zip(expired.iter_mut()) {
            let idle = match &row.bound {
                Bound::Session(binding) => now
                    .since(binding.heard)
                    .is_some_and(|idle| idle.as_millis() >= SESSION_IDLE.as_millis()),
                Bound::Never | Bound::Ended => false,
            };
            if idle {
                row.bound = Bound::Ended;
                *out = Some(row.conn);
            }
        }
        Expired(expired)
    }

    /// A client's frame, relayed by the comms processor with the handle
    /// stamped into `session_id` (P-021). The answer is written into `dst`.
    pub async fn frame<F: Fram>(
        &mut self,
        frame: &[u8],
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let Ok(scalars) = LinkEnvelope::decode(frame) else {
            return unreadable(dst);
        };
        let req_id = scalars.req_id();
        let SessionId::Assigned(handle) = scalars.session() else {
            return Reply::noted(SessionNote::NoHandle);
        };
        let Some(conn) = Conn::new(handle.get()) else {
            return Reply::noted(SessionNote::NoHandle);
        };
        let to = Addressed { conn, req_id };
        if !facts.link_up {
            return bare(to, Incoming::LinkLocal(LinkErrorCode::BeforeLinkUp), dst);
        }
        if self.row(conn).is_none() {
            // A handle the controller was never told about is what its
            // reboot looks like from outside: reconnect (L-062).
            return bare(to, Incoming::LinkLocal(LinkErrorCode::UnknownHandle), dst);
        }
        let envelope = match Envelope::decode(frame) {
            Ok(envelope) => envelope,
            Err(EnvelopeError::LinkLocalType(_)) => {
                return bare(
                    to,
                    Incoming::LinkLocal(LinkErrorCode::LinkTypeOnClientTransport),
                    dst,
                );
            }
            Err(EnvelopeError::UnknownType(_)) => {
                return bare(to, Incoming::Client(ErrorCode::UnknownMessageType), dst);
            }
            Err(EnvelopeError::WrongLength | EnvelopeError::Cbor(_)) => {
                return bare(to, Incoming::Client(ErrorCode::MalformedFrame), dst);
            }
        };
        match envelope.header().kind {
            MessageType::Discover => self.discover(to, now, facts, fram, dst).await,
            MessageType::Hello => self.hello(to, envelope, now, facts, dst),
            MessageType::Pair => self.pair(to, envelope, now, facts, fram, dst).await,
            // Wrapped: verified before anything is read (P-051).
            MessageType::Goodbye
            | MessageType::Inventory
            | MessageType::Readings
            | MessageType::Concerns
            | MessageType::History
            | MessageType::Subscribe
            | MessageType::ReadLog
            | MessageType::GetConfig => self.wrapped_request(to, envelope, now, dst),
            // Signed: its own MAC and counter, in P-080's order.
            MessageType::Command => self.command(to, envelope, now, fram, dst).await,
            MessageType::Time => self.time(to, envelope, now, fram, dst).await,
            MessageType::SetConfig => self.set_config(to, envelope, now, fram, dst).await,
            // Firmware remains unserved and spends no counter (P-143).
            MessageType::Firmware => match self.bound_on(to, dst) {
                Ok(()) => bare(to, Incoming::Client(ErrorCode::UnknownMessageType), dst),
                Err(refused) => refused,
            },
            // An error is never answered with another (P-031).
            MessageType::ErrorResponse => Reply::noted(SessionNote::ClientError),
            // What only the controller sends is not a request.
            MessageType::DiscoverResponse
            | MessageType::HelloResponse
            | MessageType::InventoryResponse
            | MessageType::ReadingsResponse
            | MessageType::ConcernsResponse
            | MessageType::HistoryResponse
            | MessageType::SubscribeResponse
            | MessageType::EventResponse
            | MessageType::ReadLogResponse
            | MessageType::GetConfigResponse
            | MessageType::SetConfigResponse
            | MessageType::CommandResponse
            | MessageType::FirmwareResponse
            | MessageType::TimeResponse
            | MessageType::PairResponse
            | MessageType::GoodbyeResponse => {
                bare(to, Incoming::Client(ErrorCode::MalformedFrame), dst)
            }
        }
    }

    /// `Discover 0x80` with the row's live challenge, minted now if it has
    /// none (P-060). No challenge to give is error 7: the counter did not
    /// land, and an answer without one would send the client to prove
    /// against nothing.
    async fn discover<F: Fram>(
        &mut self,
        to: Addressed,
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        // Nothing derives without both: a unit with no secret, or a boot
        // that could not establish an epoch (P-085).
        let (Some(secret), Some(epoch)) = (self.keys.secret, self.keys.epoch) else {
            let mut reply = bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
            reply.note = Some(SessionNote::NoChallenge);
            return reply;
        };
        let live = match self.row(to.conn).map(|row| row.challenge) {
            Some(Challenge::Live { bytes, minted }) if alive(minted, now) => Some(bytes),
            Some(Challenge::Live { .. } | Challenge::Owed | Challenge::Spent) | None => None,
        };
        let challenge = if let Some(bytes) = live {
            bytes
        } else {
            let Some(bytes) = self.mint(fram).await else {
                let mut reply = bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
                reply.note = Some(SessionNote::NoChallenge);
                return reply;
            };
            // The old one is discarded with the write: one per row (P-060).
            if let Some(row) = self.row_mut(to.conn) {
                row.challenge = Challenge::Live { bytes, minted: now };
            }
            bytes
        };
        let provisioned = self
            .keys
            .clients
            .present()
            .is_some_and(|table| table.is_under(epoch) && table.enrolled() > 0);
        let written = km43::Discovery {
            version: Version::V1_0,
            device_id: secret.device_id_bytes(),
            model: facts.model,
            provisioned,
            pairing_open: facts.pairing_open,
            challenge,
            epoch,
        }
        .write(to.header(MessageType::DiscoverResponse), dst);
        answered(written.ok())
    }

    /// `Pair 0x0B`: the challenge consumed on presentation whatever the
    /// answer (P-061), a new one minted to go back in `next_challenge`
    /// (P-058), and every outcome MAC'd under the pair key so a refusal the
    /// comms processor forges does not read (P-064, P-066). Enrolment needs
    /// the window open when this frame is handled (P-066) and a proof that
    /// checks out, and lands its row on the part before the answer says so:
    /// reclaim by label first, then the lowest free slot, then `table_full`
    /// (P-067, P-078, P-086). A proof that fails counts against the
    /// connection like any other (P-051); a closed window or a full table,
    /// which cost no proof, does not.
    async fn pair<F: Fram>(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let claim = match PairClaim::decode(envelope) {
            Ok(claim) => claim,
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let Some(challenge) = self
            .row_mut(to.conn)
            .and_then(|row| row.take_challenge(now))
        else {
            return bare(
                to,
                Incoming::Client(ErrorCode::StaleChallengeReconnectAndRetry),
                dst,
            );
        };
        // Nothing derives without both, so nothing can be MAC'd.
        let (Some(secret), Some(epoch)) = (self.keys.secret, self.keys.epoch) else {
            let mut reply = bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
            reply.note = Some(SessionNote::NoChallenge);
            return reply;
        };
        let Some(next_challenge) = self.mint(fram).await else {
            let mut reply = bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
            reply.note = Some(SessionNote::NoChallenge);
            return reply;
        };
        if let Some(row) = self.row_mut(to.conn) {
            row.challenge = Challenge::Live {
                bytes: next_challenge,
                minted: now,
            };
        }
        let key = secret.device_secret().pair_key();
        let attempt = claim.attempt(secret.device_id_bytes(), challenge);
        let outcome = if facts.pairing_open {
            match claim.verify(&key, &attempt) {
                // A verified `Pair` that could not be recorded has no outcome
                // to say so (origin89hq/km43#91), and a bare 7 needs a MAC a
                // client will not find: it times out and tries again.
                Ok(request) => match self.enrol(request, epoch, fram).await {
                    Ok(outcome) => outcome,
                    Err(Unenrolled::NotKept) => {
                        let mut reply = bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
                        reply.note = Some(SessionNote::NotKept);
                        return reply;
                    }
                    Err(Unenrolled::OtherEpoch) => {
                        return bare(to, Incoming::Client(ErrorCode::BusyRetry), dst);
                    }
                    Err(Unenrolled::Label) => {
                        return bare(to, Incoming::Client(ErrorCode::MalformedFrame), dst);
                    }
                },
                Err(bad) => bad.outcome(),
            }
        } else {
            Outcome::WindowClosed
        };
        let shed = outcome.failed_a_proof() && self.count_failure(to.conn, now);
        let written = PairResponse {
            outcome,
            epoch,
            next_challenge,
        }
        .write(&key, &attempt, to.header(MessageType::PairResponse), dst);
        let mut reply = answered(written.ok());
        if let Some(client) = outcome.slot() {
            reply.note = Some(SessionNote::Paired(client));
        }
        if shed {
            reply.close = Some(Close {
                conn: to.conn,
                reason: CloseReason::AuthenticationFailures,
            });
        }
        reply
    }

    /// A verified `Pair` into the client table under `epoch`: the row on the
    /// part, or why nothing was enrolled.
    async fn enrol<F: Fram>(
        &mut self,
        request: PairRequest<'_>,
        epoch: Epoch,
        fram: &mut F,
    ) -> Result<Outcome, Unenrolled> {
        let label = Label::new(request.label).map_err(|_| Unenrolled::Label)?;
        let Some(table) = self
            .keys
            .clients
            .present()
            .filter(|table| table.is_under(epoch))
        else {
            return Err(Unenrolled::OtherEpoch);
        };
        // A reclaim keeps the client's id and key and sets its counter to
        // zero, so a session still bound to it would read a captured frame
        // as fresh. Every one goes first, whether or not the row then lands
        // (P-078).
        if let Some(client) = table.holder(&label) {
            self.unbind(client);
        }
        let paired = self
            .keys
            .clients
            .update(fram, |table| table.pair(label, request.client_kind))
            .await
            .map_err(|_| Unenrolled::NotKept)?;
        Ok(match paired {
            Ok(Paired::Enrolled(client)) => Outcome::Enrolled(client),
            Ok(Paired::Reclaimed(client)) => Outcome::Reclaimed(client),
            Err(TableFull) => Outcome::TableFull,
        })
    }

    /// `Hello 0x01`: the challenge consumed on presentation (P-061), the
    /// proof checked under the key the enrolment derives under this epoch,
    /// and on success a session bound on the row, replacing any bound
    /// there (P-076), and answered under its new key.
    fn hello(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        facts: &Facts<'_>,
        dst: &mut [u8],
    ) -> Reply {
        let claim = match HelloClaim::decode(envelope) {
            Ok(claim) => claim,
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let Some(challenge) = self
            .row_mut(to.conn)
            .and_then(|row| row.take_challenge(now))
        else {
            return bare(
                to,
                Incoming::Client(ErrorCode::StaleChallengeReconnectAndRetry),
                dst,
            );
        };
        let client = claim.client_id();
        let (Some(secret), Some(epoch)) = (self.keys.secret, self.keys.epoch) else {
            return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst);
        };
        let Some(table) = self
            .keys
            .clients
            .present()
            .filter(|table| table.is_under(epoch))
        else {
            return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst);
        };
        if table.row(client).is_none() {
            return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst);
        }
        let counter = table.accepted(client).map_or(0, |counter| counter.0);
        let enrolment = secret.device_secret().enrolment(epoch, client);
        let client_nonce = claim.client_nonce();
        let agreed = match claim.verify(&enrolment.client_key(), &challenge, Version::V1_0) {
            Ok(accepted) => accepted.agreed,
            Err(HandshakeError::MajorMismatch { .. }) => {
                return bare(to, Incoming::Client(ErrorCode::ProtocolMajorMismatch), dst);
            }
            Err(HandshakeError::Proof(_)) => return self.failed(to, now, dst),
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let session = SessionId::from(to.conn.get());
        let key = enrolment.session_key(
            &Handshake {
                challenge,
                client_nonce,
            },
            session,
        );
        let mut inner = [0u8; MAX_HELLO_REPORT];
        let report = HelloReport {
            version: agreed,
            session,
            fw_controller: facts.fw_controller,
            fw_comms: facts.fw_comms,
            capabilities: 0,
            log_oldest_seq: facts.log.oldest,
            log_newest_seq: facts.log.newest,
            // The state store does not exist yet; its counter starts here.
            state_seq: StateSeq(0),
            time_known: facts.time_known,
            counter,
            caps: Caps::THIS_CONTROLLER,
            topology: Topology::THIS_CONTROLLER,
        };
        let Ok(len) = report.encode(&mut inner) else {
            return Reply::noted(SessionNote::TooLarge);
        };
        let written = Tagged::over(
            to.header(MessageType::HelloResponse),
            inner.get(..len).unwrap_or(&[]),
            &key,
        )
        .and_then(|tagged| tagged.write(dst));
        let Ok(written) = written else {
            return Reply::noted(SessionNote::TooLarge);
        };
        // Bound only once the answer exists: a session nobody can be told
        // about is a row held for fifteen minutes for nothing.
        self.bindings = self.bindings.wrapping_add(1);
        let serial = self.bindings;
        if let Some(row) = self.row_mut(to.conn) {
            row.bound = Bound::Session(Binding {
                client,
                key,
                heard: now,
                serial,
                window: ReqWindow::opened_by(to.req_id),
            });
        }
        Reply {
            answer: Some(written),
            close: None,
            note: Some(SessionNote::Bound(to.conn)),
        }
    }

    /// Whether a session is bound on the row: none ever bound here is
    /// error 4, one that ended is error 9 (P-143).
    fn bound_on(&self, to: Addressed, dst: &mut [u8]) -> Result<(), Reply> {
        match self.row(to.conn).map(|row| &row.bound) {
            Some(Bound::Session(_)) => Ok(()),
            Some(Bound::Never) => Err(bare(
                to,
                Incoming::Client(ErrorCode::HelloRequiredFirst),
                dst,
            )),
            Some(Bound::Ended) | None => {
                Err(bare(to, Incoming::Client(ErrorCode::SessionExpired), dst))
            }
        }
    }

    /// A wrapped request on a session: verified before anything is read,
    /// and only one that verifies refreshes the session (P-077); a failure
    /// counts against the connection (P-051). `Goodbye` clears the binding
    /// and leaves the row (P-076); the reads are the later slices'.
    fn wrapped_request(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        dst: &mut [u8],
    ) -> Reply {
        if let Err(refused) = self.bound_on(to, dst) {
            return refused;
        }
        let kind = envelope.header().kind;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = self.row(to.conn)
        else {
            return Reply::NOTHING;
        };
        let verified = Wrapper::decode(envelope).and_then(|wrapper| wrapper.verify(&binding.key));
        let payload = match verified {
            Ok(verified) => verified.payload(),
            Err(WrapperError::Mac(_) | WrapperError::Missing(WrapperKey::Mac)) => {
                return self.failed(to, now, dst);
            }
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let goodbye = kind == MessageType::Goodbye
            && EmptyBody::decode(MessageType::Goodbye, payload).is_ok();
        let Self { rows, keys, .. } = self;
        let Some(Row {
            bound: bound @ Bound::Session(_),
            ..
        }) = rows.iter_mut().flatten().find(|row| row.conn == to.conn)
        else {
            return Reply::NOTHING;
        };
        if let Bound::Session(binding) = bound {
            // After the MAC and before anything reads the body or refreshes
            // the session (P-022, P-077); no wire answer, per the note.
            if let Err(why) = binding.window.accept(to.req_id) {
                return Reply::noted(SessionNote::OutOfWindow(why));
            }
            binding.heard = now;
        }
        if kind == MessageType::GetConfig {
            let Bound::Session(binding) = bound else {
                return Reply::NOTHING;
            };
            let request = match km43::GetConfigRequest::decode(payload) {
                Ok(request) => request,
                Err(why) => return refused_under(to, &binding.key, why.refusal(), dst),
            };
            let mut body = [0; km43::CONFIG_HEADER_BYTES + km43::MAX_NETWORK_READ_BYTES];
            let len = match keys
                .configuration
                .answer(request.section, &keys.network, &mut body)
            {
                Ok(len) => len,
                Err(code) => return wrapped(to, &binding.key, code, dst),
            };
            let written = body
                .get(..len)
                .and_then(|body| {
                    Tagged::over(
                        to.header(MessageType::GetConfigResponse),
                        body,
                        &binding.key,
                    )
                    .ok()
                })
                .and_then(|tagged| tagged.write(dst).ok());
            return answered(written);
        }
        if kind != MessageType::Goodbye || !goodbye {
            let code = if kind == MessageType::Goodbye {
                ErrorCode::MalformedFrame
            } else {
                // Proven, and not served by this slice: error 2 under the
                // key, which a verified request has earned.
                ErrorCode::UnknownMessageType
            };
            return match bound {
                Bound::Session(binding) => wrapped(to, &binding.key, code, dst),
                Bound::Never | Bound::Ended => Reply::NOTHING,
            };
        }
        let mut body = [0u8; 1];
        let answer = match bound {
            Bound::Session(binding) => EmptyBody
                .encode(MessageType::GoodbyeResponse, &mut body)
                .ok()
                .and_then(|len| {
                    Tagged::over(
                        to.header(MessageType::GoodbyeResponse),
                        body.get(..len).unwrap_or(&[]),
                        &binding.key,
                    )
                    .ok()
                })
                .and_then(|tagged| tagged.write(dst).ok()),
            Bound::Never | Bound::Ended => None,
        };
        // The binding goes and the key with it; the row stays with its
        // transport (P-076).
        *bound = Bound::Ended;
        Reply {
            answer,
            close: None,
            note: Some(SessionNote::Unbound(to.conn)),
        }
    }

    /// `Command 0x08` on a session, through [`admit`] under the session's key
    /// and the client it was bound to. A signed body that does not read is
    /// answered bare, like any frame nothing verified; a MAC that fails
    /// counts against the connection (P-051); everything past the MAC is
    /// answered under the key. It refreshes the session (P-077) only when it
    /// spent its counter, which is when a permit came back: a replay
    /// verifies too, and so does a command refused before its counter
    /// landed, whose bytes stay fresh for as long as the comms processor
    /// cares to replay them and would keep an idle session alive.
    async fn command<F: Fram>(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        if let Err(refused) = self.bound_on(to, dst) {
            return refused;
        }
        let claim = match SignedClaim::decode(envelope) {
            Ok(claim) => claim,
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let Self { rows, keys, .. } = self;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = rows.iter_mut().flatten().find(|row| row.conn == to.conn)
        else {
            return Reply::NOTHING;
        };
        let mut admission = admit(
            claim,
            &binding.key,
            binding.client,
            &mut binding.window,
            &mut keys.clients,
            fram,
            now,
        )
        .await;
        if let Admission::InFlight(retry) = admission {
            // No output has authority yet, so none can already be where the
            // command asked: the state store's answer is always to run it.
            admission = retry.again(&mut keys.clients, fram, now).await;
        }
        let spent = matches!(admission, Admission::Execute(_));
        let reply = match admission {
            Admission::OutOfWindow(why) => Some(Reply::noted(SessionNote::OutOfWindow(why))),
            Admission::Refused(Refusal::Signed(SignedError::Mac(_))) => None,
            Admission::Refused(why) => {
                let mut reply = refused_under(to, &binding.key, why.code(), dst);
                if why.raises().is_some() {
                    reply.note = Some(SessionNote::NotKept);
                }
                Some(reply)
            }
            Admission::Answered(ack) => Some(acked(to, &binding.key, ack, dst)),
            Admission::Execute(Permit::Command(reservation)) => {
                let finished = reservation
                    .finished(&mut keys.clients, fram, Executed::Rejected, UNSPECIFIED)
                    .await;
                let mut reply = acked(to, &binding.key, finished.ack, dst);
                if finished.recorded.is_err() {
                    reply.note = Some(SessionNote::NotKept);
                }
                Some(reply)
            }
            // Only the three other signed types are written; a `Command` is
            // never one.
            Admission::Execute(Permit::Write(_)) => Some(wrapped(
                to,
                &binding.key,
                ErrorCode::UnknownMessageType,
                dst,
            )),
            // Settled by another retry between the two, and neither running
            // nor recorded now: this one goes again.
            Admission::InFlight(_) => Some(wrapped(to, &binding.key, ErrorCode::BusyRetry, dst)),
        };
        match reply {
            Some(reply) => {
                if spent {
                    binding.heard = now;
                }
                reply
            }
            None => self.failed(to, now, dst),
        }
    }

    /// Admit the signed write before its version or section body is examined.
    async fn set_config<F: Fram>(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        if let Err(refused) = self.bound_on(to, dst) {
            return refused;
        }
        let claim = match SignedClaim::decode(envelope) {
            Ok(claim) => claim,
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let Self { rows, keys, .. } = self;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = rows.iter_mut().flatten().find(|row| row.conn == to.conn)
        else {
            return Reply::NOTHING;
        };
        let admission = admit(
            claim,
            &binding.key,
            binding.client,
            &mut binding.window,
            &mut keys.clients,
            fram,
            now,
        )
        .await;
        let write = match admission {
            Admission::Execute(Permit::Write(write)) => write,
            Admission::OutOfWindow(why) => return Reply::noted(SessionNote::OutOfWindow(why)),
            Admission::Refused(Refusal::Signed(SignedError::Mac(_))) => {
                return self.failed(to, now, dst);
            }
            Admission::Refused(why) => {
                let mut reply = refused_under(to, &binding.key, why.code(), dst);
                if why.raises().is_some() {
                    reply.note = Some(SessionNote::NotKept);
                }
                return reply;
            }
            // Only a `Command` is reserved, answered from the table or left
            // in flight; a `SetConfig` never is.
            Admission::Execute(Permit::Command(_))
            | Admission::Answered(_)
            | Admission::InFlight(_) => {
                return wrapped(to, &binding.key, ErrorCode::UnknownMessageType, dst);
            }
        };
        binding.heard = now;
        let operation = match km43::SetConfigOperation::decode(write.operation()) {
            Ok(operation) => operation,
            Err(why) => return refused_under(to, &binding.key, why.refusal(), dst),
        };
        // Like Time, spend the admitted counter before checking the row's mask.
        let required = km43::ClientCapability::WRITE_CONFIG.0
            | if matches!(
                operation.section,
                km43::ConfigSection::Network | km43::ConfigSection::Cloud
            ) {
                km43::ClientCapability::WRITE_NETWORK_AND_CLOUD.0
            } else {
                0
            };
        let authorised = keys
            .clients
            .present()
            .and_then(|table| table.row(binding.client))
            .is_some_and(|row| row.mask().0 & required == required);
        let ack = if authorised {
            match keys
                .configuration
                .set(operation, &mut keys.network, fram)
                .await
            {
                Ok(ack) => ack,
                Err(code) => return wrapped(to, &binding.key, code, dst),
            }
        } else {
            km43::SetConfigAck {
                section: operation.section,
                version: keys.configuration.version(operation.section, &keys.network),
                outcome: km43::SetConfig::Unauthorised,
            }
        };
        let mut body = [0; km43::MAX_SET_CONFIG_ACK_BYTES];
        let written = ack
            .encode(&mut body)
            .ok()
            .and_then(|len| {
                Tagged::over(
                    to.header(MessageType::SetConfigResponse),
                    body.get(..len)?,
                    &binding.key,
                )
                .ok()
            })
            .and_then(|tagged| tagged.write(dst).ok());
        answered(written)
    }

    /// `Time 0x0A` on a session, through [`admit`]: the counter spent before
    /// anything else (P-080), then the operation handed to the recorder,
    /// which owns the calendar and the floor, with a ticket. The answer
    /// comes back through [`Sessions::time_answered`]. Refusals before the
    /// recorder are answered as a `Command`'s are.
    async fn time<F: Fram>(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        if let Err(refused) = self.bound_on(to, dst) {
            return refused;
        }
        let claim = match SignedClaim::decode(envelope) {
            Ok(claim) => claim,
            Err(why) => return bare(to, Incoming::from(why.refusal().code()), dst),
        };
        let Self {
            rows,
            keys,
            time,
            tickets,
            ..
        } = self;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = rows.iter_mut().flatten().find(|row| row.conn == to.conn)
        else {
            return Reply::NOTHING;
        };
        let admission = admit(
            claim,
            &binding.key,
            binding.client,
            &mut binding.window,
            &mut keys.clients,
            fram,
            now,
        )
        .await;
        let write = match admission {
            Admission::Execute(Permit::Write(write)) => write,
            Admission::OutOfWindow(why) => return Reply::noted(SessionNote::OutOfWindow(why)),
            Admission::Refused(Refusal::Signed(SignedError::Mac(_))) => {
                return self.failed(to, now, dst);
            }
            Admission::Refused(why) => {
                let mut reply = refused_under(to, &binding.key, why.code(), dst);
                if why.raises().is_some() {
                    reply.note = Some(SessionNote::NotKept);
                }
                return reply;
            }
            // Only a `Command` is reserved, answered from the table or left
            // in flight; a `Time` never is.
            Admission::Execute(Permit::Command(_))
            | Admission::Answered(_)
            | Admission::InFlight(_) => {
                return wrapped(to, &binding.key, ErrorCode::UnknownMessageType, dst);
            }
        };
        // The counter is spent: this frame proved itself and is fresh.
        binding.heard = now;
        let operation = match TimeOperation::decode(write.operation()) {
            Ok(operation) => operation,
            Err(why) => return refused_under(to, &binding.key, why.refusal(), dst),
        };
        if time.is_some() {
            return wrapped(to, &binding.key, ErrorCode::BusyRetry, dst);
        }
        let authorised = keys
            .clients
            .present()
            .and_then(|table| table.row(binding.client))
            .is_some_and(|row| {
                row.mask().0 & (1 << CapabilityBit::ClockSettableByClient as u16) != 0
            });
        *tickets = tickets.wrapping_add(1);
        *time = Some(AskedTime {
            ticket: *tickets,
            to,
            serial: binding.serial,
            asked: now,
        });
        Reply::noted(SessionNote::TimeAsked(TimeAsked {
            ticket: *tickets,
            at: operation.at,
            authorised,
        }))
    }

    /// The recorder's answer to the `Time` it was handed as `ticket`,
    /// written under the key of the session that asked. Nothing is written
    /// for a ticket that is not the one waiting, or when that session has
    /// ended or been bound again since: its client is not listening.
    pub fn time_answered(&mut self, ticket: u32, answer: TimeAnswer, dst: &mut [u8]) -> Reply {
        let Some(asked) = self.time.filter(|asked| asked.ticket == ticket) else {
            return Reply::NOTHING;
        };
        self.time = None;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = self.row(asked.to.conn)
        else {
            return Reply::NOTHING;
        };
        if binding.serial != asked.serial {
            return Reply::NOTHING;
        }
        let ack = match answer {
            TimeAnswer::Ack(ack) => ack,
            TimeAnswer::Busy => return wrapped(asked.to, &binding.key, ErrorCode::BusyRetry, dst),
        };
        let mut body = [0u8; MAX_TIME_ACK_BYTES];
        let written = ack
            .encode(&mut body)
            .ok()
            .and_then(|len| {
                Tagged::over(
                    asked.to.header(MessageType::TimeResponse),
                    body.get(..len).unwrap_or(&[]),
                    &binding.key,
                )
                .ok()
            })
            .and_then(|tagged| tagged.write(dst).ok());
        answered(written)
    }

    /// A proof or a MAC that did not verify: error 10, bare, and one more
    /// failure against the connection; the one that reaches the threshold
    /// ends any session on it and closes it (P-051).
    fn failed(&mut self, to: Addressed, now: Tick, dst: &mut [u8]) -> Reply {
        let shed = self.count_failure(to.conn, now);
        let mut reply = bare(to, Incoming::Client(ErrorCode::BadMAC), dst);
        if shed {
            reply.close = Some(Close {
                conn: to.conn,
                reason: CloseReason::AuthenticationFailures,
            });
        }
        reply
    }

    /// End every session bound to `client`, leaving the rows to their
    /// transports (P-076).
    fn unbind(&mut self, client: ClientId) {
        for row in self.rows.iter_mut().flatten() {
            if matches!(&row.bound, Bound::Session(binding) if binding.client == client) {
                row.bound = Bound::Ended;
            }
        }
    }

    /// One more failure against `conn`; whether it reached the threshold,
    /// which ends any session on it (P-051).
    fn count_failure(&mut self, conn: Conn, now: Tick) -> bool {
        self.row_mut(conn).is_some_and(|row| {
            let shed = row.failed(now);
            if shed {
                row.bound = Bound::Ended;
            }
            shed
        })
    }

    /// The next challenge, its counter on the part before it exists. None
    /// without a secret and an epoch: a challenge nobody can prove against
    /// would spend a counter for nothing.
    async fn mint<F: Fram>(&mut self, fram: &mut F) -> Option<[u8; CHALLENGE_BYTES]> {
        let secret = self.keys.secret?;
        self.keys.epoch?;
        let minted = self.keys.challenges.mint(fram).await.ok()?;
        Some(minted.challenge(&secret.device_secret()))
    }

    fn row(&self, conn: Conn) -> Option<&Row> {
        self.rows.iter().flatten().find(|row| row.conn == conn)
    }

    fn row_mut(&mut self, conn: Conn) -> Option<&mut Row> {
        self.rows.iter_mut().flatten().find(|row| row.conn == conn)
    }
}

impl Rows for Sessions {
    fn admit(&mut self, conn: Conn) -> ClientConnected {
        Self::admit(self, conn)
    }

    fn release(&mut self, conn: Conn) -> ClientDisconnected {
        Self::release(self, conn)
    }

    fn drop_all(&mut self) {
        Self::drop_all(self);
    }

    fn allocated(&self) -> u8 {
        Self::allocated(self)
    }
}

/// Why a verified `Pair` enrolled nothing. Each is answered differently and
/// only one is a part that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unenrolled {
    /// The row did not land: the FRAM refused the write.
    NotKept,
    /// The table is not one this epoch's keys derive for: a factory reset
    /// the boot has not finished, and no write was tried.
    OtherEpoch,
    /// A label the table cannot hold, which km43's decoder refuses first.
    Label,
}

/// Where an answer goes: the handle in `session_id`, the request echoed
/// (P-026, L-182).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Addressed {
    conn: Conn,
    req_id: ReqId,
}

impl Addressed {
    fn header(self, kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(self.conn.get()),
            req_id: self.req_id,
        }
    }
}

const fn answered(len: Option<usize>) -> Reply {
    match len {
        Some(len) => Reply {
            answer: Some(len),
            close: None,
            note: None,
        },
        None => Reply::noted(SessionNote::TooLarge),
    }
}

/// A bare `Error 0xFF`: no key for this session, or none earned by the
/// frame (P-142).
fn bare(to: Addressed, code: Incoming, dst: &mut [u8]) -> Reply {
    let written = ErrorBody { code, detail: "" }
        .write(to.header(MessageType::ErrorResponse), dst)
        .ok();
    let mut reply = answered(written);
    reply.note = Some(SessionNote::Refused(wire(code)));
    reply
}

/// Error 1 at `0, 0` for a frame whose four elements did not read
/// (P-025, P-028). It names no connection, so it stays on the UART as a
/// refusal of the comms processor's frame (L-181); an honest one never
/// relays such a frame, and answers its client itself.
fn unreadable(dst: &mut [u8]) -> Reply {
    let written = ErrorBody {
        code: Incoming::Client(ErrorCode::MalformedFrame),
        detail: "",
    }
    .write(
        Header {
            kind: MessageType::ErrorResponse,
            session: SessionId::None,
            req_id: ReqId(0),
        },
        dst,
    )
    .ok();
    let mut reply = answered(written);
    if reply.answer.is_some() {
        reply.note = Some(SessionNote::Unreadable);
    }
    reply
}

/// A refusal of a request that verified: under the key, as P-142 has for
/// every client code; a link-local one, which none of these is, bare.
fn refused_under(to: Addressed, key: &SessionKey, code: Code, dst: &mut [u8]) -> Reply {
    match code {
        Code::Client(code) => wrapped(to, key, code, dst),
        Code::LinkLocal(code) => bare(to, Incoming::LinkLocal(code), dst),
    }
}

/// `Ack 0x88` under the session's key.
fn acked(to: Addressed, key: &SessionKey, ack: CommandAck<'_>, dst: &mut [u8]) -> Reply {
    let mut body = [0u8; MAX_COMMAND_ACK_BYTES];
    let written = ack
        .encode(&mut body)
        .ok()
        .and_then(|len| {
            Tagged::over(
                to.header(MessageType::CommandResponse),
                body.get(..len).unwrap_or(&[]),
                key,
            )
            .ok()
        })
        .and_then(|tagged| tagged.write(dst).ok());
    answered(written)
}

/// An `Error 0xFF` under the session's key, for a request that verified.
fn wrapped(to: Addressed, key: &SessionKey, code: ErrorCode, dst: &mut [u8]) -> Reply {
    let mut body = [0u8; 16];
    let written = ErrorBody {
        code: Incoming::Client(code),
        detail: "",
    }
    .encode(&mut body)
    .ok()
    .and_then(|len| {
        Tagged::over(
            to.header(MessageType::ErrorResponse),
            body.get(..len).unwrap_or(&[]),
            key,
        )
        .ok()
    })
    .and_then(|tagged| tagged.write(dst).ok());
    let mut reply = answered(written);
    reply.note = Some(SessionNote::Refused(code as u16));
    reply
}

const fn wire(code: Incoming) -> u16 {
    match code {
        Incoming::Client(code) => code as u16,
        Incoming::LinkLocal(code) => code as u16,
        Incoming::Unknown(raw) => raw,
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{
        Attempt, ClientKind, CommandKind, CommandOperation, Counter, DeviceId, DeviceSecret,
        ErrorBody as Body, HelloInner, Hint, MAX_PAYLOAD, PairAckClaim, PrintedSecret, Session,
        Signed,
    };

    use super::*;
    use crate::clients::Label;
    use crate::epoch::Clearing;
    use crate::fram::{Address, FRAM_BYTES, Refused};
    use crate::map::{CHALLENGE_COUNTER, CLIENT_TABLE, EPOCH};

    const DEVICE: [u8; 16] = [7; 16];
    const PRINTED: [u8; 32] = [9; 32];

    /// Up to the end of the client table, which is as far as this reaches.
    const PART_BYTES: usize = crate::map::END.0 as usize;
    const _: () = assert!(PART_BYTES <= FRAM_BYTES);

    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        /// Refuse writes to the client table's record only, as a part that
        /// failed mid-way through an enrolment would.
        table_refused: bool,
    }

    /// Where the client table's record starts: its two slots end the part.
    const TABLE_STARTS: usize =
        CLIENT_TABLE.end().0 as usize - 2 * crate::fram::slot_bytes(CLIENT_TABLE_BYTES);

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            into.copy_from_slice(&self.bytes[start..][..into.len()]);
            core::future::ready(Ok(()))
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            let outcome =
                if self.falling || (self.table_refused && usize::from(at.0) >= TABLE_STARTS) {
                    Err(Refused::SupplyFalling)
                } else {
                    let start = usize::from(at.0);
                    self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                    Ok(())
                };
            core::future::ready(outcome)
        }
    }

    /// A frame, without an allocator.
    struct Bytes {
        buf: [u8; MAX_PAYLOAD],
        len: usize,
    }

    impl Bytes {
        const EMPTY: Self = Self {
            buf: [0; MAX_PAYLOAD],
            len: 0,
        };

        fn of(bytes: &[u8]) -> Self {
            let mut out = Self::EMPTY;
            out.buf[..bytes.len()].copy_from_slice(bytes);
            out.len = bytes.len();
            out
        }
    }

    impl core::ops::Deref for Bytes {
        type Target = [u8];

        fn deref(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    fn conn(n: u16) -> Conn {
        Conn::new(n).expect("a nonzero handle")
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    fn device() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new(PRINTED))
    }

    const FACTS: Facts<'static> = Facts {
        model: "origin89 controller",
        fw_controller: "0.1.0+gabcdef01",
        fw_comms: "0.1.0-sim+g89abcdef",
        log: LogSpan {
            oldest: LogSeq(3),
            newest: LogSeq(41),
        },
        time_known: false,
        pairing_open: false,
        link_up: true,
    };

    /// A unit under epoch `under` with one client enrolled at slot 1 under
    /// epoch 1, its counter at `counter`, and a part to write to.
    struct Rig {
        part: Part,
        sessions: Sessions,
        now: Tick,
        req: u32,
    }

    impl Rig {
        fn new() -> Self {
            Self::under(epoch(1))
        }

        fn under(current: Epoch) -> Self {
            let mut part = Part {
                bytes: [0; PART_BYTES],
                falling: false,
                table_refused: false,
            };
            let mut table = ClientTable::cleared(&Clearing::found_at_boot(epoch(1)));
            let _ = table.pair(Label::new("phone").expect("fits"), ClientKind::App);
            let mut clients = block_on(Kept::read(CLIENT_TABLE, &mut part)).expect("reads");
            block_on(clients.write(&mut part, table)).expect("lands");
            let challenges = block_on(Kept::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
            let mut epoch_record = block_on(Kept::read(EPOCH, &mut part)).expect("reads");
            block_on(epoch_record.write(&mut part, current)).expect("lands");
            let keys = Keys {
                configuration: block_on(crate::Configuration::read(&mut part))
                    .expect("read config"),
                network: block_on(Kept::read(crate::map::NETWORK, &mut part))
                    .expect("read network"),
                secret: Some(Secret::new(DEVICE, PRINTED).expect("entropy")),
                epoch: Some(current),
                epoch_record,
                clients,
                challenges,
            };
            Self {
                part,
                sessions: Sessions::new(keys),
                now: Tick::from_millis(10_000),
                req: 0,
            }
        }

        fn at(&mut self, millis: u64) {
            self.now = self.now.after(Millis::from_millis(millis)).expect("fits");
        }

        fn counter(&self) -> u64 {
            self.sessions
                .keys()
                .challenges
                .present()
                .map_or(0, ChallengeCounter::last)
        }

        fn connect(&mut self, handle: u16) -> ClientConnected {
            let outcome = self.sessions.admit(conn(handle));
            block_on(self.sessions.settle(self.now, &mut self.part));
            outcome
        }

        fn next_req(&mut self) -> ReqId {
            self.req = self.req.checked_add(1).expect("fewer than 2^32 requests");
            ReqId(self.req)
        }

        /// Send `frame` and hand back the reply and the answer's bytes.
        fn send(&mut self, frame: &[u8]) -> (Reply, Bytes) {
            self.send_with(frame, &FACTS)
        }

        fn send_with(&mut self, frame: &[u8], facts: &Facts<'_>) -> (Reply, Bytes) {
            let mut dst = [0u8; MAX_PAYLOAD];
            let reply =
                block_on(
                    self.sessions
                        .frame(frame, self.now, facts, &mut self.part, &mut dst),
                );
            let bytes = reply
                .answer
                .map_or(Bytes::EMPTY, |len| Bytes::of(&dst[..len]));
            (reply, bytes)
        }

        /// A request of `kind` with an empty body on `handle`.
        fn empty(&mut self, handle: u16, kind: MessageType) -> Bytes {
            let req_id = self.next_req();
            let mut dst = [0u8; 64];
            let cbor = Header {
                kind,
                session: SessionId::from(handle),
                req_id,
            }
            .write(0, &mut dst)
            .expect("fits");
            let len = cbor.finish().expect("fits");
            Bytes::of(&dst[..len])
        }

        /// `Discover` on `handle`, and the challenge it answered with.
        fn discover(&mut self, handle: u16) -> [u8; 16] {
            let frame = self.empty(handle, MessageType::Discover);
            let (_, answer) = self.send(&frame);
            let envelope = Envelope::decode(&answer).expect("an envelope");
            assert_eq!(envelope.header().session, SessionId::from(handle), "P-026");
            let discovery = km43::Discovery::decode(envelope).expect("a Discover answer");
            discovery.challenge
        }

        /// A `Hello` from `client` proving over `challenge` with `secret`
        /// under `under`, speaking `version`.
        #[expect(clippy::too_many_arguments, reason = "a test fixture")]
        fn hello_frame(
            &mut self,
            handle: u16,
            client: u32,
            challenge: [u8; 16],
            secret: &DeviceSecret,
            under: Epoch,
            version: Version,
            nonce: [u8; 16],
        ) -> Bytes {
            let req_id = self.next_req();
            let id = ClientId::new(client).expect("a slot");
            let enrolment = secret.enrolment(under, id);
            let mut inner = [0u8; 128];
            let request = HelloInner {
                version,
                client_id: id,
                client_version: "sim/1",
                client_nonce: nonce,
            }
            .prove(&enrolment.client_key(), &challenge, &mut inner)
            .expect("proves");
            let mut dst = [0u8; 256];
            let len = request
                .write(
                    Header {
                        kind: MessageType::Hello,
                        session: SessionId::from(handle),
                        req_id,
                    },
                    &mut dst,
                )
                .expect("fits");
            Bytes::of(&dst[..len])
        }

        /// A proper `Hello` from client 1 on `handle`, over its live
        /// challenge; the session key the client derives.
        fn hello(&mut self, handle: u16) -> (Reply, Bytes, SessionKey) {
            let challenge = self.discover(handle);
            let nonce = [handle.to_le_bytes()[0]; 16];
            let frame = self.hello_frame(
                handle,
                1,
                challenge,
                &device(),
                epoch(1),
                Version::V1_0,
                nonce,
            );
            let (reply, answer) = self.send(&frame);
            let key = device()
                .enrolment(epoch(1), ClientId::new(1).expect("a slot"))
                .session_key(
                    &Handshake {
                        challenge,
                        client_nonce: nonce,
                    },
                    SessionId::from(handle),
                );
            (reply, answer, key)
        }

        /// A wrapped request of `kind` under `key`, empty inner body.
        fn wrapped(&mut self, handle: u16, kind: MessageType, key: &SessionKey) -> Bytes {
            let req_id = self.next_req();
            let mut dst = [0u8; 128];
            let len = Tagged::over(
                Header {
                    kind,
                    session: SessionId::from(handle),
                    req_id,
                },
                &[0xa0],
                key,
            )
            .expect("wraps")
            .write(&mut dst)
            .expect("fits");
            Bytes::of(&dst[..len])
        }
    }

    impl Rig {
        /// A `Command` on `handle` claiming `client`, carrying `counter` and
        /// the operation `cmd_id`/`kind`, signed under `key`.
        fn command(
            &mut self,
            handle: u16,
            client: u32,
            counter: u64,
            (cmd_id, kind): (u32, CommandKind),
            key: &SessionKey,
        ) -> Bytes {
            let req_id = self.next_req();
            let mut op = [0u8; 16];
            let len = CommandOperation {
                cmd_id,
                kind,
                args: &[0xa0],
            }
            .encode(&mut op)
            .expect("fits");
            let mut dst = [0u8; 128];
            let len = Signed::over(
                Header {
                    kind: MessageType::Command,
                    session: SessionId::from(handle),
                    req_id,
                },
                ClientId::new(client).expect("a slot"),
                Counter(counter),
                &op[..len],
                key,
            )
            .expect("signs")
            .write(&mut dst)
            .expect("fits");
            Bytes::of(&dst[..len])
        }

        /// The highest counter the table holds for client 1.
        fn accepted(&self) -> Option<Counter> {
            self.sessions
                .keys()
                .clients
                .present()
                .and_then(|table| table.accepted(ClientId::new(1).expect("a slot")))
        }
    }

    const START: (u32, CommandKind) = (42, CommandKind::StartGenerator);

    /// The payload of an answer under `key`, and its header.
    fn under(answer: &[u8], key: &SessionKey) -> (Header, Bytes) {
        let envelope = Envelope::decode(answer).expect("an envelope");
        let header = envelope.header();
        let verified = Wrapper::decode(envelope)
            .and_then(|wrapper| wrapper.verify(key))
            .expect("under the session's key");
        (header, Bytes::of(verified.payload()))
    }

    /// The code of an error under `key`.
    fn code_under(answer: &[u8], key: &SessionKey) -> Incoming {
        let (header, payload) = under(answer, key);
        assert_eq!(header.kind, MessageType::ErrorResponse);
        ErrorBody::authenticated(&payload)
            .expect("an error body")
            .code
    }

    /// The code of a bare error, read as a client reads one: a code the
    /// registry marks MAC'd does not read.
    fn hint(answer: &[u8]) -> Option<u16> {
        let envelope = Envelope::decode(answer).ok()?;
        let hint: Hint<'_> = Body::from_envelope(envelope).ok()?;
        Some(wire(hint.code()))
    }

    /// The code key 1 of a bare error carries, whatever a client makes of it.
    fn raw_code(answer: &[u8]) -> Option<u16> {
        let envelope = Envelope::decode(answer).ok()?;
        if envelope.header().kind != MessageType::ErrorResponse {
            return None;
        }
        let mut body = envelope.into_body();
        (body.key().ok()? == 1).then_some(())?;
        body.u16().ok()
    }

    fn header(answer: &[u8]) -> Header {
        Envelope::decode(answer).expect("an envelope").header()
    }

    fn other_key() -> SessionKey {
        DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]))
            .enrolment(epoch(1), ClientId::new(1).expect("a slot"))
            .session_key(
                &Handshake {
                    challenge: [0; 16],
                    client_nonce: [0; 16],
                },
                SessionId::from(1),
            )
    }

    #[test]
    fn p_080_a_command_is_verified_counted_and_answered_rejected_under_the_key() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.command(1, 1, 1, START, &key);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.close, None);
        assert_eq!(reply.note, None);
        let (header, payload) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::CommandResponse);
        assert_eq!(header.req_id, ReqId(rig.req), "P-026");
        assert_eq!(
            CommandAck::decode(&payload),
            Ok(CommandAck {
                cmd_id: 42,
                outcome: km43::Command::Rejected,
                detail: UNSPECIFIED,
            })
        );
        // The counter is spent on the part, and no entry stays behind for
        // a command that did not run (P-120).
        assert_eq!(rig.accepted(), Some(Counter(1)));
        let reread = block_on(Kept::<ClientTable, CLIENT_TABLE_BYTES>::read(
            CLIENT_TABLE,
            &mut rig.part,
        ))
        .expect("reads");
        let table = reread.present().expect("a table");
        assert_eq!(
            table.accepted(ClientId::new(1).expect("a slot")),
            Some(Counter(1))
        );
        assert_eq!(table.dedup().live(rig.now), 0);
        // So a retry, with the next counter, is not a duplicate of anything.
        let frame = rig.command(1, 1, 2, START, &key);
        let (_, answer) = rig.send(&frame);
        let (_, payload) = under(&answer, &key);
        assert_eq!(
            CommandAck::decode(&payload).map(|ack| ack.outcome),
            Ok(km43::Command::Rejected)
        );
    }

    /// Conformance 8 at the session: the same bytes again are refused by the
    /// counter, under the key, and do not keep the session alive.
    #[test]
    fn p_080_a_command_reusing_its_counter_is_11_under_the_key_and_refreshes_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.command(1, 1, 1, START, &key);
        let _ = rig.send(&frame);
        rig.at(SESSION_IDLE.as_millis() - 1_000);
        // Signed again under a new req_id, with the counter already spent:
        // past the window, and refused at the counter.
        let again = rig.command(1, 1, 1, START, &key);
        let (reply, answer) = rig.send(&again);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::CounterNotFresh)
        );
        assert_eq!(reply.close, None);
        assert_eq!(rig.accepted(), Some(Counter(1)));
        // The replay was the last frame, and the session still ends on the
        // time the genuine one set.
        rig.at(1_000);
        let expired = rig.sessions.tick(rig.now);
        assert_eq!(expired.iter().map(|close| close.conn).next(), Some(conn(1)));
    }

    #[test]
    fn p_022_a_verified_command_replayed_on_its_session_is_dropped_unanswered() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.command(1, 1, 1, START, &key);
        let (_, answer) = rig.send(&frame);
        assert!(!answer.is_empty(), "the genuine one is answered");
        let part = rig.part.bytes;
        rig.at(SESSION_IDLE.as_millis() - 1_000);
        // Eight replays: no answer to play against the client, nothing
        // written, no failure counted, and no refresh.
        for n in 1..=8 {
            let (reply, answer) = rig.send(&frame);
            assert_eq!(
                reply.note,
                Some(SessionNote::OutOfWindow(OutOfWindow::Replayed)),
                "{n}"
            );
            assert!(answer.is_empty(), "{n}");
            assert_eq!(reply.close, None, "{n}");
        }
        assert!(rig.part.bytes == part, "nothing written");
        assert_eq!(rig.accepted(), Some(Counter(1)));
        rig.at(1_000);
        let expired = rig.sessions.tick(rig.now);
        assert_eq!(expired.iter().map(|close| close.conn).next(), Some(conn(1)));
    }

    #[test]
    fn p_022_a_wrapped_request_replayed_or_below_the_window_is_dropped_unanswered() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        // Signed first and held back while the client moves on five.
        let withheld = rig.wrapped(1, MessageType::Readings, &key);
        let sent: [Bytes; 5] =
            core::array::from_fn(|_| rig.wrapped(1, MessageType::Readings, &key));
        for frame in &sent {
            let (_, answer) = rig.send(frame);
            assert_eq!(
                code_under(&answer, &key),
                Incoming::Client(ErrorCode::UnknownMessageType)
            );
        }
        let (reply, answer) = rig.send(&withheld);
        assert_eq!(
            reply.note,
            Some(SessionNote::OutOfWindow(OutOfWindow::BelowWindow))
        );
        assert!(answer.is_empty());
        let (reply, answer) = rig.send(&sent[4]);
        assert_eq!(
            reply.note,
            Some(SessionNote::OutOfWindow(OutOfWindow::Replayed))
        );
        assert!(answer.is_empty());
        assert!(rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_022_wrapped_requests_reordered_inside_the_window_are_each_answered_once() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frames: [Bytes; 4] =
            core::array::from_fn(|_| rig.wrapped(1, MessageType::Readings, &key));
        for at in [3, 0, 2, 1] {
            let (_, answer) = rig.send(&frames[at]);
            assert_eq!(
                code_under(&answer, &key),
                Incoming::Client(ErrorCode::UnknownMessageType),
                "{at}"
            );
        }
        for frame in &frames {
            let (reply, answer) = rig.send(frame);
            assert_eq!(
                reply.note,
                Some(SessionNote::OutOfWindow(OutOfWindow::Replayed))
            );
            assert!(answer.is_empty());
        }
    }

    #[test]
    fn p_022_the_window_goes_with_the_binding_and_a_new_session_starts_its_own() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.wrapped(1, MessageType::Readings, &key);
        let _ = rig.send(&frame);
        let goodbye = rig.wrapped(1, MessageType::Goodbye, &key);
        let _ = rig.send(&goodbye);
        // A frame of the ended session is refused by the session check,
        // never read against a window that no longer exists.
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(9));
        let (_, _, key) = rig.hello(1);
        let frame = rig.wrapped(1, MessageType::Readings, &key);
        let (_, answer) = rig.send(&frame);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::UnknownMessageType)
        );
    }

    /// A command refused before its counter lands leaves the counter where it
    /// was, so the same bytes stay fresh and the comms processor can replay
    /// them as often as it likes. None of those refresh the session.
    #[test]
    fn p_077_a_command_refused_before_its_counter_lands_refreshes_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let req_id = rig.next_req();
        let mut dst = [0u8; 128];
        let len = Signed::over(
            Header {
                kind: MessageType::Command,
                session: SessionId::from(1),
                req_id,
            },
            ClientId::new(1).expect("a slot"),
            Counter(1),
            &[0x07],
            &key,
        )
        .expect("signs")
        .write(&mut dst)
        .expect("fits");
        let unreadable = Bytes::of(&dst[..len]);
        let naming_another = rig.command(1, 2, 1, START, &key);
        rig.at(SESSION_IDLE.as_millis() - 2_000);
        for frame in [&unreadable, &naming_another] {
            let (_, answer) = rig.send(frame);
            assert!(matches!(code_under(&answer, &key), Incoming::Client(_)));
            rig.at(500);
        }
        assert_eq!(rig.accepted(), Some(Counter(0)), "nothing was spent");
        rig.at(1_000);
        let expired = rig.sessions.tick(rig.now);
        assert_eq!(expired.iter().map(|close| close.conn).next(), Some(conn(1)));
    }

    #[test]
    fn p_077_a_command_that_verified_refreshes_the_session() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        rig.at(SESSION_IDLE.as_millis() - 1_000);
        let frame = rig.command(1, 1, 1, START, &key);
        let _ = rig.send(&frame);
        rig.at(1_000);
        assert_eq!(rig.sessions.tick(rig.now).iter().next(), None);
        assert!(rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_051_a_command_under_another_key_is_10_bare_and_counts_against_the_connection() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, _) = rig.hello(1);
        for n in 1..FAILURES {
            let frame = rig.command(1, 1, 1, START, &other_key());
            let (reply, answer) = rig.send(&frame);
            assert_eq!(hint(&answer), Some(10), "failure {n}");
            assert_eq!(reply.close, None, "failure {n}");
        }
        let frame = rig.command(1, 1, 1, START, &other_key());
        let (reply, _) = rig.send(&frame);
        assert_eq!(
            reply.close,
            Some(Close {
                conn: conn(1),
                reason: CloseReason::AuthenticationFailures
            })
        );
        assert_eq!(rig.accepted(), Some(Counter(0)), "no forged frame moved it");
    }

    #[test]
    fn p_084_a_command_naming_another_client_is_12_under_the_key_and_moves_no_counter() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.command(1, 2, u64::MAX, START, &key);
        let (_, answer) = rig.send(&frame);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::UnknownClient)
        );
        assert_eq!(rig.accepted(), Some(Counter(0)));
    }

    #[test]
    fn p_079_a_command_whose_counter_does_not_land_is_7_under_the_key_and_noted() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        rig.part.falling = true;
        let frame = rig.command(1, 1, 1, START, &key);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::BusyRetry)
        );
        assert_eq!(reply.note, Some(SessionNote::NotKept));
        assert_eq!(rig.accepted(), Some(Counter(0)), "RAM is where the part is");
        // The supply recovers and the client's retry runs, with the next
        // counter.
        rig.part.falling = false;
        let frame = rig.command(1, 1, 2, START, &key);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, None);
        let (header, _) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::CommandResponse);
        assert_eq!(rig.accepted(), Some(Counter(2)));
    }

    /// A reset between reserving and finishing: the entry says only that the
    /// command started. No output has authority, so the state store's answer
    /// is to run it again, and it is answered as a fresh command would be.
    #[test]
    fn p_080_a_retry_meeting_an_entry_a_reset_left_in_flight_runs_again() {
        let mut rig = Rig::new();
        let (op, len) = {
            let mut op = [0u8; 16];
            let len = CommandOperation {
                cmd_id: START.0,
                kind: START.1,
                args: &[0xa0],
            }
            .encode(&mut op)
            .expect("fits");
            (op, len)
        };
        let client = ClientId::new(1).expect("a slot");
        let reserved = block_on(rig.sessions.keys.clients.update(&mut rig.part, |table| {
            table.admit(
                client,
                Counter(1),
                START.0,
                crate::dedup::Fingerprint::of(&op[..len]),
                Tick::ZERO,
            )
        }));
        assert!(matches!(reserved, Ok(crate::clients::Admitted::Fresh(_))));
        let mut clients = block_on(Kept::read(CLIENT_TABLE, &mut rig.part)).expect("reads");
        let _ = block_on(clients.booted(&mut rig.part, epoch(1)));
        rig.sessions.keys.clients = clients;
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.command(1, 1, 2, START, &key);
        let (_, answer) = rig.send(&frame);
        let (header, payload) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::CommandResponse);
        assert_eq!(
            CommandAck::decode(&payload).map(|ack| ack.outcome),
            Ok(km43::Command::Rejected)
        );
        assert_eq!(rig.accepted(), Some(Counter(2)));
        let table = rig.sessions.keys().clients.present().expect("a table");
        assert_eq!(table.dedup().live(rig.now), 0, "the entry is settled");
    }

    impl Rig {
        /// A signed `Time` on `handle` from `client` setting `at`.
        fn time_frame(
            &mut self,
            handle: u16,
            client: u32,
            counter: u64,
            at: u64,
            key: &SessionKey,
        ) -> Bytes {
            let req_id = self.next_req();
            let mut op = [0u8; 16];
            let len = km43::TimeOperation { at }.encode(&mut op).expect("fits");
            let mut dst = [0u8; 128];
            let len = Signed::over(
                Header {
                    kind: MessageType::Time,
                    session: SessionId::from(handle),
                    req_id,
                },
                ClientId::new(client).expect("a slot"),
                Counter(counter),
                &op[..len],
                key,
            )
            .expect("signs")
            .write(&mut dst)
            .expect("fits");
            Bytes::of(&dst[..len])
        }

        /// Hand `answer` back for `ticket`, and the bytes it wrote.
        fn answer_time(&mut self, ticket: u32, answer: TimeAnswer) -> (Reply, Bytes) {
            let mut dst = [0u8; MAX_PAYLOAD];
            let reply = self.sessions.time_answered(ticket, answer, &mut dst);
            let bytes = reply
                .answer
                .map_or(Bytes::EMPTY, |len| Bytes::of(&dst[..len]));
            (reply, bytes)
        }
    }

    const SET_AT: u64 = 1_800_000_000_000;

    fn asked(reply: &Reply) -> TimeAsked {
        match reply.note {
            Some(SessionNote::TimeAsked(asked)) => asked,
            other => panic!("handed to the recorder, not {other:?}"),
        }
    }

    #[test]
    fn p_110_a_client_time_spends_its_counter_and_is_handed_to_the_recorder() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, answer) = rig.send(&frame);
        assert!(answer.is_empty(), "answered later, by the recorder");
        let asked = asked(&reply);
        assert_eq!(asked.at, SET_AT);
        assert!(asked.authorised, "an app may set the clock");
        assert_eq!(
            rig.accepted(),
            Some(Counter(1)),
            "spent before anything else"
        );
        let req_id = ReqId(rig.req);
        let ack = TimeAck::new(km43::Time::Accepted, Some(SET_AT)).expect("an ack");
        let (_, answer) = rig.answer_time(asked.ticket, TimeAnswer::Ack(ack));
        let (header, payload) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::TimeResponse);
        assert_eq!(header.req_id, req_id, "P-026");
        assert_eq!(TimeAck::decode(&payload), Ok(ack));
        // Answered once: the same ticket again writes nothing.
        let (_, again) = rig.answer_time(asked.ticket, TimeAnswer::Ack(ack));
        assert!(again.is_empty());
    }

    #[test]
    fn p_118_a_second_time_while_one_is_decided_is_7_and_a_busy_answer_is_7_under_the_key() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let first = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, _) = rig.send(&first);
        let ticket = asked(&reply).ticket;
        let second = rig.time_frame(1, 1, 2, SET_AT, &key);
        let (reply, answer) = rig.send(&second);
        assert_eq!(reply.note, Some(SessionNote::Refused(7)));
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::BusyRetry)
        );
        let (_, answer) = rig.answer_time(ticket, TimeAnswer::Busy);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::BusyRetry)
        );
        // The slot is free again.
        let third = rig.time_frame(1, 1, 3, SET_AT, &key);
        let (reply, _) = rig.send(&third);
        assert_ne!(asked(&reply).ticket, ticket);
    }

    /// The answer takes its time; the client that asked may be gone. It goes
    /// to the session that asked and to no later one on the same handle.
    #[test]
    fn a_time_answer_reaches_only_the_session_that_asked() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        let ticket = asked(&reply).ticket;
        let ack = TimeAck::new(km43::Time::Rejected, None).expect("an ack");
        // A wrong ticket is nobody's.
        let (_, answer) = rig.answer_time(ticket.wrapping_add(1), TimeAnswer::Ack(ack));
        assert!(answer.is_empty());
        // The client says goodbye and hellos again on the same handle.
        let bye = rig.wrapped(1, MessageType::Goodbye, &key);
        let _ = rig.send(&bye);
        let _ = rig.hello(1);
        let (_, answer) = rig.answer_time(ticket, TimeAnswer::Ack(ack));
        assert!(answer.is_empty(), "the new session did not ask");
    }

    /// One definition of when a waiting `Time` is forgotten, used by the
    /// session to free its slot and by the recorder to never act on it after.
    #[test]
    fn a_time_is_expired_from_the_limit_on_and_on_a_tick_that_went_backwards() {
        let asked = Tick::from_millis(5_000);
        assert!(!time_expired(asked, asked));
        let limit = asked.after(TIME_ANSWER_LIMIT).expect("fits");
        assert!(!time_expired(
            asked,
            Tick::from_millis(limit.as_millis() - 1)
        ));
        assert!(time_expired(asked, limit));
        assert!(
            time_expired(asked, Tick::from_millis(4_999)),
            "no age to trust"
        );
    }

    #[test]
    fn a_time_the_recorder_never_answers_is_forgotten_and_the_next_is_taken() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        let lost = asked(&reply).ticket;
        rig.at(TIME_ANSWER_LIMIT.as_millis() - 1);
        let _ = rig.sessions.tick(rig.now);
        let frame = rig.time_frame(1, 1, 2, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Refused(7)), "still waiting");
        rig.at(1);
        let _ = rig.sessions.tick(rig.now);
        let frame = rig.time_frame(1, 1, 3, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        let taken = asked(&reply).ticket;
        assert_ne!(taken, lost);
        let ack = TimeAck::new(km43::Time::Rejected, None).expect("an ack");
        let (_, answer) = rig.answer_time(lost, TimeAnswer::Ack(ack));
        assert!(answer.is_empty(), "the forgotten one answers nothing");
    }

    /// The cloud's mask does not reach the clock (P-105): handed on as
    /// unauthorised, so the answer can carry the clock the controller keeps.
    #[test]
    fn p_105_a_client_whose_mask_does_not_reach_the_clock_is_asked_as_unauthorised() {
        let mut rig = Rig::new();
        let cloud = Label::new("cloud").expect("fits");
        let paired = block_on(
            rig.sessions
                .keys
                .clients
                .update(&mut rig.part, |table| table.pair(cloud, ClientKind::Cloud)),
        );
        assert!(matches!(paired, Ok(Ok(Paired::Enrolled(_)))));
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let frame = rig.hello_frame(1, 2, challenge, &device(), epoch(1), Version::V1_0, [4; 16]);
        let _ = rig.send(&frame);
        let key = device()
            .enrolment(epoch(1), ClientId::new(2).expect("a slot"))
            .session_key(
                &Handshake {
                    challenge,
                    client_nonce: [4; 16],
                },
                SessionId::from(1),
            );
        let frame = rig.time_frame(1, 2, 1, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        assert!(!asked(&reply).authorised);
    }

    #[test]
    fn a_client_time_under_another_key_is_10_and_one_reusing_its_counter_is_11() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let forged = rig.time_frame(1, 1, 1, SET_AT, &other_key());
        let (reply, answer) = rig.send(&forged);
        assert_eq!(hint(&answer), Some(10));
        assert_eq!(reply.close, None);
        let frame = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, _) = rig.send(&frame);
        let ack = TimeAck::new(km43::Time::Accepted, Some(SET_AT)).expect("an ack");
        let _ = rig.answer_time(asked(&reply).ticket, TimeAnswer::Ack(ack));
        let again = rig.time_frame(1, 1, 1, SET_AT, &key);
        let (reply, answer) = rig.send(&again);
        assert_eq!(reply.note, Some(SessionNote::Refused(11)));
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::CounterNotFresh)
        );
    }

    impl Rig {
        fn config_frame(
            &mut self,
            counter: u64,
            expected: u32,
            body: &[u8],
            key: &SessionKey,
        ) -> Bytes {
            let mut operation = [0; 128];
            let len = km43::SetConfigOperation {
                section: km43::ConfigSection::IdentityAndSite,
                expected_version: expected,
                body,
            }
            .encode(&mut operation)
            .expect("operation");
            let mut frame = [0; 256];
            let len = Signed::over(
                Header {
                    kind: MessageType::SetConfig,
                    session: SessionId::from(1),
                    req_id: self.next_req(),
                },
                ClientId::new(1).expect("client"),
                Counter(counter),
                &operation[..len],
                key,
            )
            .expect("signed")
            .write(&mut frame)
            .expect("frame");
            Bytes::of(&frame[..len])
        }
        fn get_config(&mut self, key: &SessionKey) -> (Reply, Bytes) {
            let mut body = [0; km43::MAX_GET_CONFIG_BYTES];
            let len = km43::GetConfigRequest {
                section: km43::ConfigSection::IdentityAndSite,
            }
            .encode(&mut body)
            .expect("body");
            let mut frame = [0; 128];
            let len = Tagged::over(
                Header {
                    kind: MessageType::GetConfig,
                    session: SessionId::from(1),
                    req_id: self.next_req(),
                },
                &body[..len],
                key,
            )
            .expect("wrapper")
            .write(&mut frame)
            .expect("frame");
            self.send(&Bytes::of(&frame[..len]))
        }
    }

    fn config_client(kind: ClientKind, mask: Option<u16>) -> (Rig, SessionKey) {
        use crate::Body;
        let mut rig = Rig::new();
        let _ = block_on(rig.sessions.keys.clients.update(&mut rig.part, |table| {
            table.pair(Label::new("phone").expect("label"), kind)
        }))
        .expect("persist")
        .expect("pair");
        if let Some(mask) = mask {
            let mut bytes = rig.sessions.keys.clients.present().expect("table").encode();
            let offset = 4 + 1 + 1 + km43::MAX_LABEL;
            bytes[offset..offset + 2].copy_from_slice(&mask.to_le_bytes());
            let table = ClientTable::decode(&bytes).expect("table");
            block_on(rig.sessions.keys.clients.write(&mut rig.part, table)).expect("persist mask");
        }
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        (rig, key)
    }

    fn config_section_frame(
        rig: &mut Rig,
        section: km43::ConfigSection,
        body: &[u8],
        key: &SessionKey,
    ) -> Bytes {
        let mut operation = [0; 192];
        let len = km43::SetConfigOperation {
            section,
            expected_version: 0,
            body,
        }
        .encode(&mut operation)
        .expect("operation");
        let mut frame = [0; 256];
        let len = Signed::over(
            Header {
                kind: MessageType::SetConfig,
                session: SessionId::from(1),
                req_id: rig.next_req(),
            },
            ClientId::new(1).expect("client"),
            Counter(1),
            &operation[..len],
            key,
        )
        .expect("signed")
        .write(&mut frame)
        .expect("frame");
        Bytes::of(&frame[..len])
    }

    fn network_write_body() -> Bytes {
        let mut bytes = [0; 192];
        let len = km43::NetworkWrite {
            join: Some(km43::JoinWrite {
                ssid: km43::Ssid::new("cabin").expect("ssid"),
                psk: Some(km43::Passphrase::new("correct horse").expect("psk")),
            }),
            country: km43::Country::new("CA").expect("country"),
            hostname: km43::Hostname::new("origin89").expect("hostname"),
        }
        .encode(&mut bytes)
        .expect("network");
        Bytes::of(&bytes[..len])
    }

    #[test]
    fn p_105_cloud_network_and_cloud_writes_are_refused_under_the_session_key() {
        for section in [km43::ConfigSection::Network, km43::ConfigSection::Cloud] {
            let (mut rig, key) = config_client(ClientKind::Cloud, None);
            let before = rig.part.bytes;
            let frame = config_section_frame(&mut rig, section, &network_write_body(), &key);
            let (_, answer) = rig.send(&frame);
            let (header, body) = under(&answer, &key);
            assert_eq!(header.kind, MessageType::SetConfigResponse);
            assert_eq!(
                km43::SetConfigAck::decode(&body).expect("ack").outcome,
                km43::SetConfig::Unauthorised
            );
            assert_eq!(
                rig.accepted(),
                Some(Counter(1)),
                "refusal still spends the counter"
            );
            let start = usize::from(crate::map::COMMS_RELEASE.end().0);
            let end = usize::from(crate::map::NETWORK.end().0);
            assert_eq!(&rig.part.bytes[start..end], &before[start..end]);
        }
    }

    #[test]
    fn p_105_cloud_identity_and_behaviour_writes_succeed() {
        for (section, body) in [
            (
                km43::ConfigSection::IdentityAndSite,
                &[0xa1, 1, 0x61, b'a'][..],
            ),
            (
                km43::ConfigSection::GeneratorBehaviour,
                &[0xa1, 1, 0xf5][..],
            ),
        ] {
            let (mut rig, key) = config_client(ClientKind::Cloud, None);
            let frame = config_section_frame(&mut rig, section, body, &key);
            let (_, answer) = rig.send(&frame);
            let (_, body) = under(&answer, &key);
            assert_eq!(
                km43::SetConfigAck::decode(&body).expect("ack").outcome,
                km43::SetConfig::Accepted
            );
        }
    }

    #[test]
    fn p_105_without_write_config_every_section_is_refused() {
        for section in [
            km43::ConfigSection::IdentityAndSite,
            km43::ConfigSection::Channels,
            km43::ConfigSection::BusesAndDevices,
            km43::ConfigSection::GeneratorBehaviour,
            km43::ConfigSection::FrostBehaviour,
            km43::ConfigSection::ScheduleBehaviour,
            km43::ConfigSection::LoadShedBehaviour,
            km43::ConfigSection::Network,
            km43::ConfigSection::Cloud,
        ] {
            let (mut rig, key) = config_client(
                ClientKind::App,
                Some(km43::ClientCapability::WRITE_NETWORK_AND_CLOUD.0),
            );
            let frame = config_section_frame(&mut rig, section, &[0xa1, 1, 0x61, b'a'], &key);
            let (_, answer) = rig.send(&frame);
            let (header, body) = under(&answer, &key);
            assert_eq!(header.kind, MessageType::SetConfigResponse);
            assert_eq!(
                km43::SetConfigAck::decode(&body).expect("ack").outcome,
                km43::SetConfig::Unauthorised
            );
        }
    }

    #[test]
    fn p_105_app_network_write_succeeds() {
        let (mut rig, key) = config_client(ClientKind::App, None);
        let frame = config_section_frame(
            &mut rig,
            km43::ConfigSection::Network,
            &network_write_body(),
            &key,
        );
        let (_, answer) = rig.send(&frame);
        let (_, body) = under(&answer, &key);
        assert_eq!(
            km43::SetConfigAck::decode(&body).expect("ack").outcome,
            km43::SetConfig::Accepted
        );
        assert_eq!(
            rig.sessions
                .keys
                .network
                .present()
                .expect("network")
                .version(),
            1
        );
    }

    #[test]
    fn p_108_get_config_is_wrapped_and_tracks_the_committed_section() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let (_, answer) = rig.get_config(&key);
        let (header, body) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::GetConfigResponse);
        assert_eq!(
            km43::ConfigAnswer::decode(&body).expect("answer").version(),
            0
        );
        let frame = rig.config_frame(1, 0, &[0xa1, 1, 0x61, b'a'], &key);
        let (_, answer) = rig.send(&frame);
        let (_, body) = under(&answer, &key);
        assert_eq!(
            km43::SetConfigAck::decode(&body).expect("ack").outcome,
            km43::SetConfig::Accepted
        );
        let (_, answer) = rig.get_config(&key);
        let (_, body) = under(&answer, &key);
        let answer = km43::ConfigAnswer::decode(&body).expect("config");
        assert_eq!(answer.version(), 1);
        assert_eq!(answer.body(), Some(&[0xa1, 1, 0x61, b'a'][..]));
    }

    #[test]
    fn p_101_config_reports_structure_and_value_errors_after_the_counter() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let malformed = rig.config_frame(1, 0, &[0xa0], &key);
        let (_, answer) = rig.send(&malformed);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::MalformedFrame)
        );
        assert_eq!(rig.accepted(), Some(Counter(1)));
        let invalid = rig.config_frame(2, 0, &[0xa1, 1, 0x60], &key);
        let (_, answer) = rig.send(&invalid);
        let (_, body) = under(&answer, &key);
        assert_eq!(
            km43::SetConfigAck::decode(&body).expect("ack").outcome,
            km43::SetConfig::Invalid
        );
        assert_eq!(rig.accepted(), Some(Counter(2)));
    }

    #[test]
    fn p_079_config_with_bad_mac_or_refused_counter_cannot_write_a_section() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let forged = rig.config_frame(1, 0, &[0xa1, 1, 0x61, b'a'], &other_key());
        let (_, answer) = rig.send(&forged);
        assert_eq!(hint(&answer), Some(10));
        assert_eq!(rig.accepted(), Some(Counter(0)));
        rig.part.table_refused = true;
        let write = rig.config_frame(1, 0, &[0xa1, 1, 0x61, b'a'], &key);
        let (_, answer) = rig.send(&write);
        assert_eq!(
            code_under(&answer, &key),
            Incoming::Client(ErrorCode::BusyRetry)
        );
        assert_eq!(rig.accepted(), Some(Counter(0)));
        let (_, answer) = rig.get_config(&key);
        let (_, body) = under(&answer, &key);
        assert_eq!(
            km43::ConfigAnswer::decode(&body).expect("config").body(),
            None
        );
    }

    #[test]
    fn p_100_signed_config_spends_counter_before_version_and_validation() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let mut operation = [0; 64];
        let len = km43::SetConfigOperation {
            section: km43::ConfigSection::IdentityAndSite,
            expected_version: 1,
            body: &[0xa0],
        }
        .encode(&mut operation)
        .expect("operation");
        let mut frame = [0; 256];
        let len = Signed::over(
            Header {
                kind: MessageType::SetConfig,
                session: SessionId::from(1),
                req_id: rig.next_req(),
            },
            ClientId::new(1).expect("client"),
            Counter(1),
            &operation[..len],
            &key,
        )
        .expect("signed")
        .write(&mut frame)
        .expect("frame");
        let (_, answer) = rig.send(&Bytes::of(&frame[..len]));
        assert_eq!(rig.accepted(), Some(Counter(1)));
        let (header, body) = under(&answer, &key);
        assert_eq!(header.kind, MessageType::SetConfigResponse);
        assert_eq!(
            km43::SetConfigAck::decode(&body).expect("ack").outcome,
            km43::SetConfig::StaleVersion
        );
    }

    #[test]
    fn a_signed_request_not_served_yet_is_2_and_spends_no_counter() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, _) = rig.hello(1);
        let frame = rig.empty(1, MessageType::Firmware);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(2));
        assert_eq!(rig.accepted(), Some(Counter(0)));
    }

    const OPEN: Facts<'static> = Facts {
        pairing_open: true,
        ..FACTS
    };

    fn pair_key() -> km43::PairKey {
        device().pair_key()
    }

    impl Rig {
        /// A `Pair` from `label` of `kind` on `handle`, proved under `key`
        /// over `challenge`, and the attempt its answer is MAC'd over.
        fn pair_frame(
            &mut self,
            handle: u16,
            (label, kind): (&str, ClientKind),
            challenge: [u8; 16],
            key: &km43::PairKey,
        ) -> (Bytes, Attempt) {
            let req_id = self.next_req();
            let attempt = Attempt {
                device_id: DEVICE,
                challenge,
                client_nonce: [handle.to_le_bytes()[0] ^ 0x5a; 16],
            };
            let mut dst = [0u8; 256];
            let len = PairRequest {
                client_kind: kind,
                label,
            }
            .write(
                key,
                &attempt,
                Header {
                    kind: MessageType::Pair,
                    session: SessionId::from(handle),
                    req_id,
                },
                &mut dst,
            )
            .expect("fits");
            (Bytes::of(&dst[..len]), attempt)
        }

        /// The labels enrolled, by slot.
        fn enrolled(&self) -> usize {
            self.sessions
                .keys()
                .clients
                .present()
                .map_or(0, ClientTable::enrolled)
        }
    }

    /// The `Pair 0x8B` in `answer`, verified as the client verifies it.
    fn pair_ack(answer: &[u8], attempt: &Attempt) -> PairResponse {
        let envelope = Envelope::decode(answer).expect("an envelope");
        assert_eq!(envelope.header().kind, MessageType::PairResponse);
        PairAckClaim::decode(envelope)
            .expect("a pair ack")
            .verify(&pair_key(), attempt, epoch(1))
            .expect("MAC'd under the pair key, refusals included (P-064)")
    }

    const LAPTOP: (&str, ClientKind) = ("laptop", ClientKind::Cli);

    #[test]
    fn p_066_a_pair_with_no_window_open_is_window_closed_under_the_mac_and_enrols_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        for _ in 0..=FAILURES {
            let challenge = rig.discover(1);
            let (frame, attempt) = rig.pair_frame(1, LAPTOP, challenge, &pair_key());
            let (reply, answer) = rig.send(&frame);
            assert_eq!(pair_ack(&answer, &attempt).outcome, Outcome::WindowClosed);
            assert_eq!(reply.note, None);
            // Refusing to look at a proof costs nothing and counts nothing.
            assert_eq!(reply.close, None);
        }
        assert_eq!(rig.enrolled(), 1);
    }

    #[test]
    fn p_086_inside_the_window_a_new_label_is_enrolled_at_the_lowest_free_slot_and_closes_it() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let (frame, attempt) = rig.pair_frame(1, LAPTOP, challenge, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        let two = ClientId::new(2).expect("a slot");
        assert_eq!(pair_ack(&answer, &attempt).outcome, Outcome::Enrolled(two));
        assert_eq!(reply.note, Some(SessionNote::Paired(two)), "L-195");
        // On the part, at counter zero (P-065), before the answer said so.
        let reread = block_on(Kept::<ClientTable, CLIENT_TABLE_BYTES>::read(
            CLIENT_TABLE,
            &mut rig.part,
        ))
        .expect("reads");
        let table = reread.present().expect("a table");
        let row = table.row(two).expect("the laptop's row");
        assert_eq!(row.label().as_bytes(), b"laptop");
        assert_eq!(row.kind(), ClientKind::Cli);
        assert_eq!(row.counter(), Counter(0));
        // And it can say hello under the key its slot derives.
        let challenge = rig.discover(1);
        let frame = rig.hello_frame(1, 2, challenge, &device(), epoch(1), Version::V1_0, [3; 16]);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Bound(conn(1))));
    }

    #[test]
    fn p_078_the_same_label_reclaims_its_row_with_the_counter_back_to_zero() {
        let mut rig = Rig::new();
        let one = ClientId::new(1).expect("a slot");
        let moved = block_on(
            rig.sessions
                .keys
                .clients
                .update(&mut rig.part, |table| table.accept(one, Counter(340))),
        );
        assert!(matches!(moved, Ok(crate::clients::Check::Ahead)));
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let (frame, attempt) =
            rig.pair_frame(1, ("phone", ClientKind::App), challenge, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        assert_eq!(pair_ack(&answer, &attempt).outcome, Outcome::Reclaimed(one));
        assert_eq!(reply.note, Some(SessionNote::Paired(one)));
        assert_eq!(rig.accepted(), Some(Counter(0)));
        assert_eq!(rig.enrolled(), 1);
    }

    /// Without unbinding, the reset counter is a replay hole: a command the
    /// comms processor captured on a live session verifies under that
    /// session's key and is ahead of a counter just set to zero.
    #[test]
    fn p_078_a_reclaim_unbinds_every_session_of_that_client_before_the_row_is_rewritten() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let captured = rig.command(1, 1, 5, START, &key);
        let (_, answer) = rig.send(&captured);
        assert_eq!(header(&answer).kind, MessageType::CommandResponse);
        assert_eq!(rig.accepted(), Some(Counter(5)));
        // The phone is reinstalled and pairs again, on another connection.
        let _ = rig.connect(2);
        let challenge = rig.discover(2);
        let (frame, attempt) =
            rig.pair_frame(2, ("phone", ClientKind::App), challenge, &pair_key());
        let (_, answer) = rig.send_with(&frame, &OPEN);
        assert!(matches!(
            pair_ack(&answer, &attempt).outcome,
            Outcome::Reclaimed(_)
        ));
        assert_eq!(rig.accepted(), Some(Counter(0)));
        assert!(
            !rig.sessions.is_bound(conn(1)),
            "unbound before the rewrite"
        );
        // The captured command, replayed on the old session: refused as a
        // session that ended, and the counter stays where the reclaim put it.
        let (_, answer) = rig.send(&captured);
        assert_eq!(hint(&answer), Some(9));
        assert_eq!(rig.accepted(), Some(Counter(0)));
    }

    #[test]
    fn p_067_a_full_table_is_table_full_unless_the_label_reclaims() {
        let mut rig = Rig::new();
        for n in 2..=8u8 {
            let label = [b'c', b'0' + n];
            let label = Label::new(core::str::from_utf8(&label).expect("ascii")).expect("fits");
            let paired = block_on(
                rig.sessions
                    .keys
                    .clients
                    .update(&mut rig.part, |table| table.pair(label, ClientKind::App)),
            );
            assert!(matches!(paired, Ok(Ok(Paired::Enrolled(_)))));
        }
        assert_eq!(rig.enrolled(), 8);
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let (frame, attempt) = rig.pair_frame(1, LAPTOP, challenge, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        assert_eq!(pair_ack(&answer, &attempt).outcome, Outcome::TableFull);
        assert_eq!(reply.note, None);
        assert_eq!(reply.close, None);
        let challenge = rig.discover(1);
        let (frame, attempt) =
            rig.pair_frame(1, ("phone", ClientKind::App), challenge, &pair_key());
        let (_, answer) = rig.send_with(&frame, &OPEN);
        assert!(matches!(
            pair_ack(&answer, &attempt).outcome,
            Outcome::Reclaimed(_)
        ));
    }

    #[test]
    fn p_051_a_pair_proof_that_fails_is_bad_proof_under_the_mac_and_counts_against_the_connection()
    {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let wrong =
            DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32])).pair_key();
        for n in 1..=FAILURES {
            let challenge = rig.discover(1);
            let (frame, attempt) = rig.pair_frame(1, LAPTOP, challenge, &wrong);
            let (reply, answer) = rig.send_with(&frame, &OPEN);
            assert_eq!(
                pair_ack(&answer, &attempt).outcome,
                Outcome::BadProof,
                "{n}"
            );
            assert_eq!(reply.note, None);
            let shed = n == FAILURES;
            assert_eq!(reply.close.is_some(), shed, "failure {n}");
        }
        assert_eq!(rig.enrolled(), 1);
    }

    /// The challenge is spent on presentation, whatever the answer, and the
    /// one handed back in `next_challenge` is the row's live one: a retry
    /// proves over it without another `Discover` (P-058), and a proof over
    /// the spent one fails against the live one (P-061).
    #[test]
    fn p_061_a_pair_spends_its_challenge_and_answers_with_the_next() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let first = rig.discover(1);
        let (frame, attempt) = rig.pair_frame(1, LAPTOP, first, &pair_key());
        let (_, answer) = rig.send(&frame);
        let next = pair_ack(&answer, &attempt).next_challenge;
        assert_ne!(next, first);
        // Over the one handed back, with no Discover between: enrolled.
        let (frame, attempt) = rig.pair_frame(1, LAPTOP, next, &pair_key());
        let (_, answer) = rig.send_with(&frame, &OPEN);
        let enrolled = pair_ack(&answer, &attempt);
        assert!(matches!(enrolled.outcome, Outcome::Enrolled(_)));
        // Over the first, long spent: the controller proves it against its
        // live challenge, and the proof fails.
        let (frame, attempt) = rig.pair_frame(1, ("tablet", ClientKind::App), first, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        let as_the_controller_saw_it = Attempt {
            challenge: enrolled.next_challenge,
            ..attempt
        };
        assert_eq!(
            pair_ack(&answer, &as_the_controller_saw_it).outcome,
            Outcome::BadProof
        );
        assert_eq!(reply.note, None);
        assert_eq!(rig.enrolled(), 2);
    }

    /// A table under an earlier epoch is one a factory reset left behind and
    /// the boot has not cleared: nothing is enrolled into it, and the refusal
    /// does not read as a FRAM that failed, because none did.
    #[test]
    fn a_pair_into_a_table_under_another_epoch_enrols_nothing_and_blames_no_write() {
        let mut rig = Rig::under(epoch(2));
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let (frame, _) = rig.pair_frame(1, LAPTOP, challenge, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        assert_eq!(raw_code(&answer), Some(7));
        assert_eq!(reply.note, Some(SessionNote::Refused(7)));
        assert_eq!(rig.enrolled(), 1);
    }

    #[test]
    fn p_066_discover_says_whether_the_window_is_open() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        for facts in [FACTS, OPEN] {
            let frame = rig.empty(1, MessageType::Discover);
            let (_, answer) = rig.send_with(&frame, &facts);
            let discovery =
                km43::Discovery::decode(Envelope::decode(&answer).expect("an envelope"))
                    .expect("a Discover answer");
            assert_eq!(discovery.pairing_open, facts.pairing_open);
        }
    }

    #[test]
    fn a_pair_whose_row_does_not_land_enrols_nothing_and_is_busy() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        rig.part.table_refused = true;
        let (frame, _) = rig.pair_frame(1, LAPTOP, challenge, &pair_key());
        let (reply, answer) = rig.send_with(&frame, &OPEN);
        assert_eq!(raw_code(&answer), Some(7));
        assert_eq!(reply.note, Some(SessionNote::NotKept));
        assert_eq!(rig.enrolled(), 1, "RAM is where the part is");
        // A falling supply stops the challenge's mint before anything else.
        rig.part.table_refused = false;
        rig.part.falling = true;
        let (frame, _) = rig.pair_frame(1, LAPTOP, [0; 16], &pair_key());
        let (_, answer) = rig.send_with(&frame, &OPEN);
        assert!(raw_code(&answer).is_some());
        assert_eq!(rig.enrolled(), 1);
    }

    #[test]
    fn l_061_a_ninth_connection_is_refused_and_no_row_is_evicted() {
        let mut rig = Rig::new();
        for handle in 1..=8 {
            assert_eq!(rig.connect(handle), ClientConnected::Accepted);
        }
        assert_eq!(rig.connect(9), ClientConnected::RefusedTableFull);
        assert_eq!(rig.sessions.allocated(), 8);
        // Every one of the eight still answers on its own handle.
        for handle in 1..=8 {
            let _ = rig.discover(handle);
        }
        // Freed, a row takes the next transport.
        assert_eq!(rig.sessions.release(conn(3)), ClientDisconnected::Released);
        assert_eq!(rig.connect(9), ClientConnected::Accepted);
    }

    #[test]
    fn l_080_a_handle_in_use_is_refused_and_taken_again_only_once_released() {
        let mut rig = Rig::new();
        assert_eq!(rig.connect(5), ClientConnected::Accepted);
        let (_, _, _) = rig.hello(5);
        assert_eq!(rig.connect(5), ClientConnected::RefusedHandleInUse);
        assert!(rig.sessions.is_bound(conn(5)), "the refusal left the row");
        assert_eq!(rig.sessions.release(conn(5)), ClientDisconnected::Released);
        assert_eq!(
            rig.sessions.release(conn(5)),
            ClientDisconnected::UnknownHandle
        );
        // Taken again, it is a new row: no session and no old challenge.
        assert_eq!(rig.connect(5), ClientConnected::Accepted);
        assert!(!rig.sessions.is_bound(conn(5)));
    }

    #[test]
    fn p_026_a_pre_session_answer_carries_the_handle_it_arrived_on() {
        let mut rig = Rig::new();
        let _ = rig.connect(0x0102);
        let frame = rig.empty(0x0102, MessageType::Discover);
        let (_, answer) = rig.send(&frame);
        let header = header(&answer);
        assert_eq!(header.kind, MessageType::DiscoverResponse);
        assert_eq!(header.session, SessionId::from(0x0102));
        assert_eq!(header.req_id, ReqId(rig.req));
        // A refusal before any session is addressed the same way.
        let frame = rig.hello_frame(
            0x0102,
            5,
            [0; 16],
            &device(),
            epoch(1),
            Version::V1_0,
            [1; 16],
        );
        let (_, answer) = rig.send(&frame);
        assert_eq!(
            header_of(&answer),
            (SessionId::from(0x0102), ReqId(rig.req))
        );
    }

    fn header_of(answer: &[u8]) -> (SessionId, ReqId) {
        let header = header(answer);
        (header.session, header.req_id)
    }

    #[test]
    fn l_062_a_frame_on_a_handle_never_announced_is_259_with_its_pair_echoed() {
        let mut rig = Rig::new();
        let frame = rig.empty(42, MessageType::Discover);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(0x103));
        assert_eq!(header(&answer).session, SessionId::from(42));
        assert_eq!(header(&answer).req_id, ReqId(rig.req));
        assert_eq!(reply.close, None);
        assert_eq!(rig.counter(), 0, "nothing was minted for it");
    }

    #[test]
    fn l_070_an_accepted_connection_holds_a_challenge_its_counter_on_the_part() {
        let mut rig = Rig::new();
        assert_eq!(rig.connect(1), ClientConnected::Accepted);
        assert_eq!(rig.counter(), 1, "minted at accept, before any Discover");
        let challenge = rig.discover(1);
        assert_eq!(challenge, device().challenge(1));
        assert_eq!(rig.counter(), 1, "the Discover took the one already held");
        // A refused announcement mints nothing.
        for handle in 2..=9 {
            let _ = rig.connect(handle);
        }
        assert_eq!(rig.counter(), 8);
    }

    #[test]
    fn p_060_each_connection_has_its_own_challenge_and_discover_repeats_the_live_one() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let _ = rig.connect(2);
        let one = rig.discover(1);
        let two = rig.discover(2);
        assert_ne!(one, two);
        rig.at(119_000);
        assert_eq!(rig.discover(1), one, "still live at 119 s");
        assert_eq!(rig.counter(), 2);
    }

    #[test]
    fn p_062_a_challenge_is_dead_at_120_seconds_and_discover_mints_another() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let first = rig.discover(1);
        rig.at(120_000);
        // A Hello over the dead one is 14, never a proof checked against it.
        let frame = rig.hello_frame(1, 1, first, &device(), epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(14));
        assert!(!rig.sessions.is_bound(conn(1)));
        let second = rig.discover(1);
        assert_ne!(first, second);
        assert_eq!(rig.counter(), 2);
    }

    #[test]
    fn p_062_a_challenge_goes_with_its_connection() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let held = rig.discover(1);
        let _ = rig.sessions.release(conn(1));
        // The handle again, after its release: a new row and a new
        // challenge, which a proof over the old one does not verify against.
        let _ = rig.connect(1);
        let frame = rig.hello_frame(1, 1, held, &device(), epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10));
        assert!(!rig.sessions.is_bound(conn(1)));
        assert_ne!(rig.discover(1), held);
    }

    #[test]
    fn p_061_a_challenge_is_consumed_by_the_first_hello_even_one_that_fails() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let wrong = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
        let frame = rig.hello_frame(1, 1, challenge, &wrong, epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10));
        // The right proof over the same challenge, now spent.
        let frame = rig.hello_frame(1, 1, challenge, &device(), epoch(1), Version::V1_0, [2; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(14));
        assert!(!rig.sessions.is_bound(conn(1)));
        // Discover hands out a fresh one, and that one works.
        let (reply, _, _) = rig.hello(1);
        assert_eq!(reply.note, Some(SessionNote::Bound(conn(1))));
    }

    #[test]
    fn p_063_a_challenge_leaves_only_once_its_counter_is_on_the_part() {
        let mut rig = Rig::new();
        rig.part.falling = true;
        assert_eq!(rig.connect(1), ClientConnected::Accepted);
        assert_eq!(rig.counter(), 0);
        let frame = rig.empty(1, MessageType::Discover);
        let (reply, answer) = rig.send(&frame);
        // Busy, with no challenge in it. Error 7 is MAC'd, so a client
        // discards this bare one and times out: the one refusal the
        // capacities table names, and km43's gap (km43#82), not this code's.
        assert_eq!(raw_code(&answer), Some(7));
        assert_eq!(hint(&answer), None);
        assert_eq!(reply.note, Some(SessionNote::NoChallenge));
        rig.part.falling = false;
        assert_eq!(rig.discover(1), device().challenge(1));
        assert_eq!(rig.counter(), 1);
    }

    #[test]
    fn p_063_a_unit_with_no_epoch_derives_no_challenge() {
        let mut rig = Rig::new();
        rig.sessions.keys.epoch = None;
        let _ = rig.connect(1);
        let frame = rig.empty(1, MessageType::Discover);
        let (_, answer) = rig.send(&frame);
        assert_eq!(raw_code(&answer), Some(7));
        assert_eq!(
            rig.counter(),
            0,
            "no counter spent on a challenge nobody can use"
        );
        let frame = rig.hello_frame(1, 1, [0; 16], &device(), epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(14));
    }

    #[test]
    fn p_076_a_verified_hello_binds_a_session_the_client_opens_under_the_same_key() {
        let mut rig = Rig::new();
        let _ = rig.connect(3);
        let challenge = rig.discover(3);
        let nonce = [5; 16];
        let frame = rig.hello_frame(3, 1, challenge, &device(), epoch(1), Version::V1_0, nonce);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Bound(conn(3))));
        let enrolment = device().enrolment(epoch(1), ClientId::new(1).expect("a slot"));
        let session = Session::open(
            Envelope::decode(&answer).expect("an envelope"),
            &enrolment,
            &Handshake {
                challenge,
                client_nonce: nonce,
            },
            Version::V1_0,
        )
        .expect("the client opens it");
        let report = session.report();
        assert_eq!(
            report.session,
            SessionId::from(3),
            "the handle is the session"
        );
        assert_eq!(report.caps, Caps::THIS_CONTROLLER, "P-005");
        assert_eq!(report.fw_comms, FACTS.fw_comms);
        assert_eq!(report.log_newest_seq, LogSeq(41));
        assert_eq!(report.counter, 0);
        assert_eq!(rig.sessions.proven(conn(3)), ClientId::new(1));
    }

    #[test]
    fn p_076_a_verified_hello_on_a_bound_row_replaces_the_binding_and_its_key() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, old) = rig.hello(1);
        let (reply, _, new) = rig.hello(1);
        assert_eq!(reply.note, Some(SessionNote::Bound(conn(1))), "not error 8");
        assert_eq!(rig.sessions.bound(), 1);
        let frame = rig.wrapped(1, MessageType::Goodbye, &old);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10), "the old key is gone");
        let frame = rig.wrapped(1, MessageType::Goodbye, &new);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Unbound(conn(1))));
    }

    #[test]
    fn p_076_goodbye_clears_the_binding_and_leaves_the_row_for_another_hello() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.wrapped(1, MessageType::Goodbye, &key);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Unbound(conn(1))));
        // The answer is a Goodbye 0x8C under the key it ended.
        let envelope = Envelope::decode(&answer).expect("an envelope");
        assert_eq!(envelope.header().kind, MessageType::GoodbyeResponse);
        let verified = Wrapper::decode(envelope)
            .and_then(|wrapper| wrapper.verify(&key))
            .expect("under the session's key");
        assert!(EmptyBody::decode(MessageType::GoodbyeResponse, verified.payload()).is_ok());
        assert_eq!(rig.sessions.allocated(), 1, "the row stays");
        assert_eq!(rig.sessions.bound(), 0);
        let frame = rig.wrapped(1, MessageType::Readings, &key);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(9));
        let (reply, _, _) = rig.hello(1);
        assert_eq!(reply.note, Some(SessionNote::Bound(conn(1))));
    }

    #[test]
    fn p_143_a_session_request_before_any_hello_is_4_and_after_one_ended_is_9() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        for kind in [
            MessageType::Readings,
            MessageType::Command,
            MessageType::Goodbye,
        ] {
            let frame = rig.empty(1, kind);
            let (_, answer) = rig.send(&frame);
            assert_eq!(hint(&answer), Some(4), "{kind:?}");
        }
        let (_, _, key) = rig.hello(1);
        let frame = rig.wrapped(1, MessageType::Goodbye, &key);
        let _ = rig.send(&frame);
        for kind in [MessageType::Readings, MessageType::Command] {
            let frame = rig.empty(1, kind);
            let (_, answer) = rig.send(&frame);
            assert_eq!(hint(&answer), Some(9), "{kind:?}");
        }
    }

    #[test]
    fn p_057_a_hello_under_a_wrong_secret_or_a_stale_epoch_binds_nothing() {
        // Under a secret this unit was not born with.
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let wrong = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
        let frame = rig.hello_frame(1, 1, challenge, &wrong, epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10));
        assert!(!rig.sessions.is_bound(conn(1)));
        // A client keyed under epoch 1 at a unit reset to epoch 2, whose
        // table the reset re-stamped with the row still in it.
        let mut rig = Rig::under(epoch(2));
        let mut table = ClientTable::cleared(&Clearing::found_at_boot(epoch(2)));
        let _ = table.pair(Label::new("phone").expect("fits"), ClientKind::App);
        block_on(rig.sessions.keys.clients.write(&mut rig.part, table)).expect("lands");
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let frame = rig.hello_frame(1, 1, challenge, &device(), epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10));
        assert!(!rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_085_a_table_left_under_an_earlier_epoch_enrols_nobody() {
        let mut rig = Rig::under(epoch(2));
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let frame = rig.hello_frame(1, 1, challenge, &device(), epoch(2), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(12));
    }

    #[test]
    fn p_085_a_factory_reset_ends_every_session_and_no_key_from_before_it_verifies() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let _ = rig.connect(2);
        let (_, _, key) = rig.hello(1);
        block_on(rig.sessions.factory_reset(&mut rig.part)).expect("both writes land");
        assert_eq!(rig.sessions.keys().epoch, Some(epoch(2)));
        assert_eq!(rig.sessions.bound(), 0);
        assert_eq!(rig.sessions.allocated(), 2, "the transports stay");
        let frame = rig.wrapped(1, MessageType::Readings, &key);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(9), "the old session is gone");
        // The phone's enrolment is gone with the table: its Hello, keyed
        // under either epoch, names a slot nobody holds.
        for under in [epoch(1), epoch(2)] {
            let challenge = rig.discover(2);
            let frame = rig.hello_frame(2, 1, challenge, &device(), under, Version::V1_0, [3; 16]);
            let (_, answer) = rig.send(&frame);
            assert_eq!(hint(&answer), Some(12), "{under:?}");
        }
    }

    #[test]
    fn p_085_a_reset_whose_network_erase_is_refused_ends_every_session_and_derives_nothing_new() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, _) = rig.hello(1);
        rig.part.falling = true;
        assert!(matches!(
            block_on(rig.sessions.factory_reset(&mut rig.part)),
            Err(ResetFailed::Network(crate::Refused::SupplyFalling))
        ));
        assert_eq!(
            rig.sessions.bound(),
            0,
            "ended before the write, whatever it did"
        );
        assert_eq!(
            rig.sessions.keys().epoch,
            Some(epoch(1)),
            "the record never moved"
        );
    }

    #[test]
    fn a_hello_naming_a_slot_nobody_holds_is_12() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let frame = rig.hello_frame(1, 2, challenge, &device(), epoch(1), Version::V1_0, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(12));
    }

    #[test]
    fn p_073_a_major_mismatch_is_3_and_binds_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let challenge = rig.discover(1);
        let two = Version { major: 2, minor: 0 };
        let frame = rig.hello_frame(1, 1, challenge, &device(), epoch(1), two, [1; 16]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(3));
        assert!(!rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_051_eight_failures_inside_a_minute_shed_the_connection_and_a_hello_resets_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        for _ in 0..4 {
            let frame = rig.wrapped(1, MessageType::Goodbye, &other_key());
            let _ = rig.send(&frame);
        }
        // No session yet: those were error 4, not failures. Bind one.
        let (_, _, _) = rig.hello(1);
        for n in 1..=7 {
            rig.at(1_000);
            let frame = rig.wrapped(1, MessageType::Readings, &other_key());
            let (reply, answer) = rig.send(&frame);
            assert_eq!(hint(&answer), Some(10));
            assert_eq!(reply.close, None, "failure {n}");
            if n == 4 {
                // A fresh Hello in the middle resets nothing.
                let (reply, _, _) = rig.hello(1);
                assert_eq!(reply.note, Some(SessionNote::Bound(conn(1))));
            }
        }
        let frame = rig.wrapped(1, MessageType::Readings, &other_key());
        let (reply, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(10));
        assert_eq!(
            reply.close,
            Some(Close {
                conn: conn(1),
                reason: CloseReason::AuthenticationFailures
            })
        );
        assert!(!rig.sessions.is_bound(conn(1)), "the session went with it");
    }

    #[test]
    fn p_051_failures_older_than_a_minute_are_forgotten() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, _) = rig.hello(1);
        // Nine seconds apart: seven inside any minute, never eight.
        for _ in 0..20 {
            rig.at(9_000);
            let frame = rig.wrapped(1, MessageType::Readings, &other_key());
            let (reply, _) = rig.send(&frame);
            assert_eq!(reply.close, None, "never eight inside a minute");
        }
    }

    #[test]
    fn p_057_a_hello_proof_that_fails_counts_against_the_connection() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let wrong = DeviceSecret::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
        let mut last = None;
        for _ in 0..8 {
            let challenge = rig.discover(1);
            let frame = rig.hello_frame(1, 1, challenge, &wrong, epoch(1), Version::V1_0, [1; 16]);
            last = rig.send(&frame).0.close;
        }
        assert_eq!(
            last.map(|close| close.reason),
            Some(CloseReason::AuthenticationFailures)
        );
    }

    #[test]
    fn p_077_only_a_verified_inbound_frame_refreshes_a_session() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let _ = rig.connect(2);
        let (_, _, one) = rig.hello(1);
        let (_, _, _) = rig.hello(2);
        rig.at(14 * 60 * 1_000);
        // One proves itself; two only receives a failure of somebody else's.
        let frame = rig.wrapped(1, MessageType::Readings, &one);
        let (_, answer) = rig.send(&frame);
        assert_eq!(header(&answer).kind, MessageType::ErrorResponse);
        let frame = rig.wrapped(2, MessageType::Readings, &other_key());
        let _ = rig.send(&frame);
        rig.at(60 * 1_000);
        let expired = rig.sessions.tick(rig.now);
        let mut closes = expired.iter();
        assert_eq!(
            closes.next(),
            Some(Close {
                conn: conn(2),
                reason: CloseReason::SessionExpired
            })
        );
        assert_eq!(closes.next(), None);
        assert!(rig.sessions.is_bound(conn(1)));
        assert_eq!(
            rig.sessions.allocated(),
            2,
            "the row waits for its transport"
        );
        let frame = rig.empty(2, MessageType::Readings);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(9));
        // Expired once, closed once.
        assert_eq!(rig.sessions.tick(rig.now).iter().count(), 0);
    }

    #[test]
    fn p_142_a_verified_request_not_served_is_refused_under_the_key_and_an_unverified_one_bare() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, key) = rig.hello(1);
        let frame = rig.wrapped(1, MessageType::Inventory, &key);
        let (_, answer) = rig.send(&frame);
        let envelope = Envelope::decode(&answer).expect("an envelope");
        let verified = Wrapper::decode(envelope)
            .and_then(|wrapper| wrapper.verify(&key))
            .expect("under the key");
        let body = ErrorBody::authenticated(verified.payload()).expect("an error body");
        assert_eq!(body.code, Incoming::Client(ErrorCode::UnknownMessageType));
        // A signed request whose body does not read is answered bare.
        let frame = rig.empty(1, MessageType::Command);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(1));
    }

    #[test]
    fn l_041_every_row_goes_with_the_comms_processor() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let _ = rig.connect(2);
        let (_, _, key) = rig.hello(1);
        rig.sessions.drop_all();
        assert_eq!(rig.sessions.allocated(), 0);
        let frame = rig.wrapped(1, MessageType::Goodbye, &key);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(0x103));
    }

    #[test]
    fn l_101_the_count_is_rows_bound_or_not() {
        let mut rig = Rig::new();
        assert_eq!(rig.sessions.allocated(), 0);
        let _ = rig.connect(1);
        let _ = rig.connect(2);
        let (_, _, _) = rig.hello(1);
        assert_eq!((rig.sessions.allocated(), rig.sessions.bound()), (2, 1));
    }

    #[test]
    fn l_180_a_client_frame_before_the_link_is_up_is_258_to_its_client() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let frame = rig.empty(1, MessageType::Discover);
        let facts = Facts {
            link_up: false,
            ..FACTS
        };
        let (_, answer) = rig.send_with(&frame, &facts);
        assert_eq!(hint(&answer), Some(0x102));
        assert_eq!(header(&answer).session, SessionId::from(1));
    }

    #[test]
    fn p_021_a_client_frame_with_no_handle_is_not_answered() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let frame = rig.empty(0, MessageType::Discover);
        let (reply, answer) = rig.send(&frame);
        assert!(answer.is_empty());
        assert_eq!(reply.note, Some(SessionNote::NoHandle));
    }

    /// Error 1 at `0, 0`, noted as unreadable.
    fn assert_unreadable(reply: &Reply, answer: &[u8]) {
        assert_eq!(reply.note, Some(SessionNote::Unreadable));
        assert_eq!(reply.close, None);
        assert_eq!(hint(answer), Some(ErrorCode::MalformedFrame as u16));
        let header = header(answer);
        assert_eq!(header.kind, MessageType::ErrorResponse);
        assert_eq!((header.session, header.req_id), (SessionId::None, ReqId(0)));
    }

    #[test]
    fn p_028_a_five_element_goodbye_is_refused_with_error_1_at_zero_zero_and_unbinds_nothing() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let (_, _, _) = rig.hello(1);
        let goodbye = rig.empty(1, MessageType::Goodbye);
        let mut five = [0u8; 64];
        five[..goodbye.len()].copy_from_slice(&goodbye);
        assert_eq!(five[0], 0x84);
        five[0] = 0x85;
        let (reply, answer) = rig.send(&five[..=goodbye.len()]);
        assert_unreadable(&reply, &answer);
        assert!(rig.sessions.is_bound(conn(1)));
        assert_eq!((rig.sessions.allocated(), rig.sessions.bound()), (1, 1));
    }

    #[test]
    fn p_025_a_frame_that_is_no_envelope_is_refused_with_error_1_at_zero_zero() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let counter = rig.counter();
        // Three elements, an array of four cut short, a map, nothing.
        for frame in [&[0x83, 0x00, 0x01, 0x01][..], &[0x84, 0x00], &[0xa0], &[]] {
            let (reply, answer) = rig.send(frame);
            assert_unreadable(&reply, &answer);
        }
        assert_eq!(rig.counter(), counter);
        assert_eq!(rig.sessions.allocated(), 1);
    }

    #[test]
    fn p_028_an_unreadable_frame_is_refused_before_the_link_or_any_row_is_asked() {
        let mut rig = Rig::new();
        let facts = Facts {
            link_up: false,
            ..FACTS
        };
        let (reply, answer) = rig.send_with(&[0x85, 0x00, 0x01, 0x01, 0xa0, 0x00], &facts);
        assert_unreadable(&reply, &answer);
        assert_eq!(rig.sessions.allocated(), 0);
    }

    #[test]
    fn p_031_an_error_from_a_client_is_never_answered() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let mut dst = [0u8; 64];
        let len = ErrorBody {
            code: Incoming::Client(ErrorCode::BusyRetry),
            detail: "",
        }
        .write(
            Header {
                kind: MessageType::ErrorResponse,
                session: SessionId::from(1),
                req_id: ReqId(9),
            },
            &mut dst,
        )
        .expect("fits");
        let (reply, answer) = rig.send(&dst[..len]);
        assert!(answer.is_empty());
        assert_eq!(reply.note, Some(SessionNote::ClientError));
    }

    #[test]
    fn p_143_a_type_nobody_allocated_is_2_and_a_response_type_is_1() {
        let mut rig = Rig::new();
        let _ = rig.connect(1);
        let mut dst = [0u8; 16];
        // [0x3f, 1, 7, {}]: a request opcode nobody allocated.
        dst[..5].copy_from_slice(&[0x84, 0x18, 0x3f, 0x01, 0x07]);
        dst[5] = 0xa0;
        let (_, answer) = rig.send(&dst[..6]);
        assert_eq!(hint(&answer), Some(2));
        assert_eq!(header(&answer).req_id, ReqId(7));
        let frame = rig.empty(1, MessageType::ReadingsResponse);
        let (_, answer) = rig.send(&frame);
        assert_eq!(hint(&answer), Some(1));
    }
}
