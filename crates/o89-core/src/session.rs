//! The connection rows, the challenge each one holds, the pairing handshake
//! it may be in, and the session a `Hello` binds onto it.
//!
//! **A row is allocated before it is bound** (P-076, L-062). The comms
//! processor announces a transport and the controller gives it a row, and
//! the row holds the connection's challenge from that moment (L-070); a
//! `Hello` that proves its slot's key binds a session onto it; `Goodbye`
//! clears the binding and leaves the row to the transport that is still
//! open; only the transport going, or the comms processor rebooting, frees
//! the row (L-041). Eight rows, and a ninth announcement is refused rather
//! than evicting one (L-061). The session's id is the row's handle.
//!
//! **A challenge is a draw** from the generator (P-063, P-237), one per row
//! at most, single use, and dead at 120 seconds or with its connection
//! (P-060, P-061, P-062). A `Discover` is answered with the row's live one
//! or a fresh one, never a dead one, and error 18 when there is none to
//! give.
//!
//! **Nothing here computes a key agreement** (P-243). What is cheap is done
//! as the frame arrives, in the order P-226 gives: the body, the suite, the
//! challenge consumed, the label's tag on pairing message 1 or the slot's
//! admission tag on a `Hello` (P-238), the window and the table, the draw.
//! What is left is queued as an [`agreement::Job`](crate::Job), one per row,
//! handed out one at a time and in turn, and its answer is sent when the
//! [`Done`](crate::Done) comes back. A handshake is abandoned on any failure,
//! on a second one on the same row, when the row goes, 120 seconds after
//! pairing message 1, and on a factory reset (P-229); a result for one that
//! was abandoned is discarded.
//!
//! **Pairing enrols inside the window only**, the one the selector opens
//! (P-066), read at message 1 and again at message 3 (P-064). Refusals after
//! message 1 carry the label's refusal tag, so the comms processor cannot
//! forge one (P-241). At message 3 the slot P-240 picks is written as P-239
//! says before the answer names it; one that does not land is outcome 7, the
//! window left open (P-064).
//!
//! **Every request after a `Hello` is sealed** (P-231). It is opened under
//! the session's keys, whose window drops a replayed or stale `req_id`
//! unanswered and uncounted (P-022); only a request that opened refreshes the
//! session (P-077), and a tag that fails counts against the connection
//! (P-051). A write then goes through [`admit`], in P-080's order, under the
//! client the session was bound to. No command kind has an argument schema
//! yet (km43's DEFERRED entry 8), so a permitted command is answered
//! `rejected`, its dedup entry discarded, and nothing reaches an output.
//!
//! **A `Vouch` is a job like a handshake** (P-243, P-244): read where it
//! opened, queued on the row with the epoch and the slot of the session that
//! asked, computed by the worker, and sealed for that session when it comes
//! back, or for nobody if it has ended since. A row already holding a
//! handshake or a job refuses it with error 7 rather than drop either.
//!
//! Every answer is addressed to the frame it answers: the handle in
//! `session_id`, the request's `req_id` echoed (P-026, L-182). Before a
//! session exists, and whenever the controller holds no key for the one
//! named, an error goes bare; once one exists, an answer to a frame that
//! opened goes sealed (P-142).
//!
//! cites: P-021, P-022, P-026, P-051, P-058, P-060, P-061, P-062, P-063,
//! P-064, P-066, P-076, P-077, P-080, P-105, P-143, P-226, P-229, P-231,
//! P-237, P-238, P-240, P-241, P-242, P-243, P-244, P-245, L-061, L-062, L-070, L-071,
//! L-072, L-080, L-180, L-182, L-195

use km43::{
    ClientConnected, ClientDisconnected, ClientId, ClientKind, CloseReason, CommandAck, Conn,
    ControllerChannel, DeviceId, EmptyBody, EnrolAnswer, EnrolAwaiting, Envelope, EnvelopeError,
    Epoch, ErrorBody, ErrorCode, Generation, Header, HelloArrival, Incoming, LinkEnvelope,
    LinkErrorCode, LogSeq, MAX_AUTH_FAILURES, MAX_COMMAND_ACK_BYTES, MAX_PAYLOAD, MAX_SESSIONS,
    MAX_TIME_ACK_BYTES, MessageType, Outcome, PairArrival, PairRefusal, Prologue, PrologueFields,
    PublicKey, Refusal as Code, ReqId, Sealed, SessionId, SignedWrite, TimeAck, TimeOperation,
    Version, VouchAnswer, VouchRequest,
};

use crate::agreement::{Bytes, Computed, Done, Job, Report, ReportText, Task, Ticket};
use crate::body::Kept;
use crate::clients::{ClientLabel, Clients, Enrolment, Place};
use crate::drbg::{CHALLENGE_BYTES, Generator};
use crate::epoch::{EPOCH_BYTES, ResetFailed, reset_clients};
use crate::fram::Fram;
use crate::link::{Compat, Rows};
use crate::request::{Admission, Executed, Permit, admit};
use crate::secret::Secret;
use crate::tick::{Millis, Tick};

/// Connection rows: one per session the protocol permits, so a row that
/// exists can always be bound and error 8 never fires over this link
/// (L-061).
pub const CONNECTIONS: usize = MAX_SESSIONS;

/// A challenge dies this long after it was minted (P-062).
pub const CHALLENGE_LIFE: Millis = Millis::from_millis(120_000);

/// A pairing handshake is abandoned this long after message 1 was read
/// (P-229).
pub const PAIRING_LIFE: Millis = Millis::from_millis(120_000);

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

/// The only suite there is (P-226), and so the one every slot holds.
const SUITE: km43::Suite = km43::Suite::X25519ChachapolySha256;

/// What the controller keeps for the client protocol, as the boot read it.
/// The records move only once the part has moved.
pub struct Keys {
    /// Versioned identity and behaviour sections.
    pub configuration: crate::Configuration,
    /// The authoritative network section.
    pub network: Kept<crate::Network, { crate::NETWORK_BYTES }>,
    /// The device id and the printed secret. None is a unit nobody
    /// manufactured: nothing pairs and no challenge is given.
    pub secret: Option<Secret>,
    /// The controller key's public half, `CS`. None is a unit with no
    /// controller key, which pairs nobody and admits nobody (P-235).
    pub controller: Option<PublicKey>,
    /// No epoch is a boot that could not establish one, and nothing enrols
    /// or binds (P-085). The boot's answer, which is not always what the
    /// record holds.
    pub epoch: Option<Epoch>,
    /// The epoch's record, which a factory reset advances.
    pub epoch_record: Kept<Epoch, EPOCH_BYTES>,
    /// The slots and the dedup table.
    pub clients: Clients,
    /// Every challenge and every ephemeral key (P-237).
    pub generator: Generator,
}

impl Keys {
    /// The mask of the enrolment a session is bound to, while it is still
    /// the slot's: a slot re-keyed since grants its old session nothing.
    fn mask(&self, binding: &Binding) -> Option<km43::ClientCapability> {
        self.clients
            .occupant(binding.client, self.epoch?)
            .filter(|occupant| occupant.generation() == binding.generation)
            .map(crate::clients::Occupant::mask)
    }
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
    /// `Discover` key 6, and whether a pairing may enrol: the pairing window,
    /// read as this frame is handled and never cached (P-066).
    pub pairing_open: bool,
    /// The link as the handshake left it: `None` before it is done, when a
    /// client frame is refused with 258 (L-033, L-180); up under a major
    /// mismatch, a refresh is refused as the link down (L-050, P-218).
    pub link: Option<Compat>,
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
    /// Key agreement for this connection is queued; the answer goes when it
    /// is done (P-243).
    Queued(Conn),
    /// A session was bound on this handle.
    Bound(Conn),
    /// A pairing enrolled or reclaimed this client: the window that allowed
    /// it closes now (L-195).
    Paired(ClientId),
    /// A client's `Time`, for the recorder to decide and answer.
    TimeAsked(TimeAsked),
    /// The client said goodbye on this handle.
    Unbound(Conn),
    /// No challenge could be given: the unit is not provisioned, or has no
    /// epoch.
    NoChallenge,
    /// The generator's state did not read back: every `Pair` and `Hello` is
    /// refused, and P-237 raises condition 22 `entropy unavailable`.
    EntropyUnavailable,
    /// A slot did not land: `Enrol` answered outcome 7, the window left
    /// open, and P-064 raises condition 23 `client table write failed`.
    TableNotStored,
    /// An `Error` from a client, which is never answered.
    ClientError,
    /// A command's dedup entry did not land: refused with error 7 and
    /// nothing run, which P-079 raises as condition 24 `dedup write
    /// failed`; or a command's outcome, whose entry is left for the state
    /// store.
    NotKept,
    /// The answer did not fit the buffer: a bug in a cap.
    TooLarge,
    /// A sealed request dropped unanswered for its `req_id`, replayed or
    /// below the window (P-022): nothing acted, nothing was counted, and the
    /// session was not refreshed.
    Dropped,
    /// A handshake result for one that was abandoned since (P-229).
    Stale,
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

    const fn with(mut self, note: SessionNote) -> Self {
        self.note = Some(note);
        self
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
    /// The slot that proved, and which enrolment of it.
    client: ClientId,
    generation: Generation,
    /// The session's keys, and P-022's window on what it accepted.
    channel: ControllerChannel,
    /// The last frame that proved itself (P-077).
    heard: Tick,
    /// Which binding this is, so an answer that took its time goes to the
    /// session that asked and to no later one on the same handle.
    serial: u32,
}

/// What `PairOffer` said, kept from message 1 to the slot it is written
/// into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Offer {
    kind: ClientKind,
    label: ClientLabel,
}

/// Where a row's pairing handshake is (P-229).
enum Pairing {
    /// None held.
    None,
    /// Message 1 opened; message 2 is being computed.
    Replying { offer: Offer, since: Tick },
    /// Message 2 sent; message 3 awaited.
    Awaiting {
        awaiting: EnrolAwaiting,
        offer: Offer,
        since: Tick,
    },
    /// Message 3 arrived and is being computed.
    Enrolling { offer: Offer, since: Tick },
}

impl Pairing {
    const fn since(&self) -> Option<Tick> {
        match self {
            Self::None => None,
            Self::Replying { since, .. }
            | Self::Awaiting { since, .. }
            | Self::Enrolling { since, .. } => Some(*since),
        }
    }
}

/// A row's key agreement: waiting its turn, or being computed.
#[expect(
    clippy::large_enum_variant,
    reason = "no allocator: each of the eight rows holds its one job inline, a fixed and named cost"
)]
enum Work {
    Idle,
    Queued(Job),
    Computing,
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
    pairing: Pairing,
    work: Work,
    /// Moves on every abandoned handshake, so a result that comes back for
    /// one is recognised and discarded.
    attempt: u32,
}

impl Row {
    const fn new(conn: Conn) -> Self {
        Self {
            conn,
            challenge: Challenge::Owed,
            bound: Bound::Never,
            failures: [None; FAILURES],
            pairing: Pairing::None,
            work: Work::Idle,
            attempt: 0,
        }
    }

    const fn ticket(&self, req_id: ReqId) -> Ticket {
        Ticket {
            conn: self.conn,
            attempt: self.attempt,
            req_id,
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
    /// handshake turns out to be (P-061). None when it is spent, owed or
    /// dead.
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

    /// `Vouch 0x14`, opened on the session bound here: queued for the
    /// worker with the epoch and the session's slot, since the request names
    /// neither (P-244). A body that does not read is error 1; a row whose one
    /// job is taken, by a handshake or by another `Vouch`, is error 7, and
    /// neither is evicted.
    fn vouch(
        &mut self,
        to: Addressed,
        epoch: Option<Epoch>,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Reply {
        let ticket = self.ticket(to.req_id);
        let Self {
            bound: Bound::Session(binding),
            pairing,
            work,
            ..
        } = self
        else {
            return Reply::NOTHING;
        };
        let request = match VouchRequest::decode(payload) {
            Ok(request) => request,
            Err(why) => return refused_under(to, binding, why.refusal(), dst),
        };
        if !matches!(pairing, Pairing::None) || !matches!(work, Work::Idle) {
            return sealed_error(to, binding, ErrorCode::BusyRetry, dst);
        }
        // A factory reset ends every session before the epoch can go, so a
        // bound session with none is a bug: nothing to vouch for.
        let Some(epoch) = epoch else {
            return sealed_error(to, binding, ErrorCode::UnknownClient, dst);
        };
        *work = Work::Queued(Job::new(
            ticket,
            Task::Vouch {
                request,
                epoch,
                bound: (binding.client, binding.generation),
                serial: binding.serial,
            },
        ));
        Reply::noted(SessionNote::Queued(to.conn))
    }

    /// Abandon whatever handshake the row holds or is computing (P-229): a
    /// result that comes back for it is discarded.
    fn abandon(&mut self) {
        self.attempt = self.attempt.wrapping_add(1);
        self.pairing = Pairing::None;
        self.work = Work::Idle;
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
    /// The job out at the worker, if one is: at most one at a time (P-243).
    computing: Option<Ticket>,
    /// The row the last job came from; the next is looked for after it.
    served: usize,
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
            computing: None,
            served: 0,
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

    /// The transport went: the row, its challenge, any handshake and any
    /// session on it go with it (P-062, P-076, P-229).
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

    /// The physical factory reset (P-085): every session unbound and every
    /// handshake abandoned first, whatever comes of the writes, then the
    /// network cleared, then the epoch advanced and verified, then the slots
    /// freed under it. The rows stay with their transports. After a
    /// failure the epoch may be none at all, which is the failure closed.
    pub async fn factory_reset<F: Fram>(
        &mut self,
        fram: &mut F,
    ) -> Result<(), ResetFailed<F::Error>> {
        for row in self.rows.iter_mut().flatten() {
            if let Bound::Session(_) = row.bound {
                row.bound = Bound::Ended;
            }
            row.abandon();
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
        reset.map(|_| ())
    }

    /// Mint every challenge an accepted row owes, each a draw whose
    /// successor is on the part (L-070, P-063). A mint that fails leaves the
    /// row owing, and the connection's first `Discover` tries again.
    pub async fn settle<F: Fram>(&mut self, now: Tick, fram: &mut F) {
        if !self.provisioned() {
            return;
        }
        let Self { rows, keys, .. } = self;
        for row in rows.iter_mut().flatten() {
            if row.challenge != Challenge::Owed {
                continue;
            }
            if let Ok(bytes) = keys.generator.challenge(fram).await {
                row.challenge = Challenge::Live { bytes, minted: now };
            }
        }
    }

    /// Sessions whose last proven frame is fifteen minutes old are
    /// unbound, their keys destroyed, and their transports to be closed
    /// (P-077). Pairing handshakes 120 seconds past message 1 are
    /// abandoned (P-229). The row stays allocated until the transport goes.
    pub fn tick(&mut self, now: Tick) -> Expired {
        if self
            .time
            .is_some_and(|asked| time_expired(asked.asked, now))
        {
            self.time = None;
        }
        let mut expired = [None; CONNECTIONS];
        for (row, out) in self.rows.iter_mut().flatten().zip(expired.iter_mut()) {
            if row.pairing.since().is_some_and(|since| {
                now.since(since)
                    .is_none_or(|age| age.as_millis() >= PAIRING_LIFE.as_millis())
            }) {
                row.abandon();
            }
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

    /// The next key agreement to compute, if none is out and one waits: the
    /// first queued after the row served last, so connections take turns
    /// (P-243). Hand it to the worker and bring its [`Done`] back to
    /// [`Sessions::completed`].
    pub fn next_job(&mut self) -> Option<Job> {
        if self.computing.is_some() {
            return None;
        }
        let start = self.served.saturating_add(1);
        let order = (0..CONNECTIONS).map(|step| start.saturating_add(step) % CONNECTIONS);
        for index in order {
            let Some(Some(row)) = self.rows.get_mut(index) else {
                continue;
            };
            if !matches!(row.work, Work::Queued(_)) {
                continue;
            }
            let Work::Queued(job) = core::mem::replace(&mut row.work, Work::Computing) else {
                continue;
            };
            self.served = index;
            self.computing = Some(job.ticket());
            return Some(job);
        }
        None
    }

    /// A job the adapter could not hand to the worker: back on its row to be
    /// handed out again, and the worker counted free.
    pub fn unsent(&mut self, job: Job) {
        let ticket = job.ticket();
        if self.computing == Some(ticket) {
            self.computing = None;
        }
        if let Some(row) = self.row_mut(ticket.conn)
            && row.attempt == ticket.attempt
            && matches!(row.work, Work::Computing)
        {
            row.work = Work::Queued(job);
        }
    }

    /// Whether a job is out at the worker.
    #[must_use]
    pub const fn is_computing(&self) -> bool {
        self.computing.is_some()
    }

    /// A client's frame, relayed by the comms processor with the handle
    /// stamped into `session_id` (P-021). The answer is written into `dst`.
    pub async fn frame<F: Fram>(
        &mut self,
        frame: &[u8],
        now: Tick,
        context: (&Facts<'_>, &mut crate::Wifi),
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let (facts, wifi) = context;
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
        if facts.link.is_none() {
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
            MessageType::Pair => self.pair(to, frame, now, facts, fram, dst).await,
            MessageType::Enrol => self.enrol(to, frame, now, dst),
            MessageType::Hello => self.hello(to, frame, now, facts, fram, dst).await,
            MessageType::Goodbye
            | MessageType::Inventory
            | MessageType::Readings
            | MessageType::Concerns
            | MessageType::History
            | MessageType::Subscribe
            | MessageType::ReadLog
            | MessageType::WifiScan
            | MessageType::WifiStatus
            | MessageType::GetConfig
            | MessageType::Command
            | MessageType::Time
            | MessageType::SetConfig
            | MessageType::Firmware
            | MessageType::Vouch
            | MessageType::Clients
            | MessageType::Invite
            | MessageType::Approve
            | MessageType::Remove => {
                let agreed = facts.link.is_some_and(Compat::is_agreed);
                self.sealed(to, envelope, now, (wifi, agreed), fram, dst)
                    .await
            }
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
            | MessageType::EnrolResponse
            | MessageType::WifiScanResponse
            | MessageType::WifiStatusResponse
            | MessageType::VouchResponse
            | MessageType::ClientsResponse
            | MessageType::InviteResponse
            | MessageType::ApproveResponse
            | MessageType::RemoveResponse
            | MessageType::GoodbyeResponse => {
                bare(to, Incoming::Client(ErrorCode::MalformedFrame), dst)
            }
        }
    }

    /// A job came back from the worker. Its answer goes out only if the
    /// handshake it belongs to is still the one its row is in; a slot is
    /// written, and a challenge drawn, before an `Enrol 0x93` says so.
    pub async fn completed<F: Fram>(
        &mut self,
        done: Done,
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let ticket = done.ticket();
        if self.computing == Some(ticket) {
            self.computing = None;
        }
        let current = self.row(ticket.conn).is_some_and(|row| {
            row.attempt == ticket.attempt && matches!(row.work, Work::Computing)
        });
        if !current {
            return Reply::noted(SessionNote::Stale);
        }
        let Some(row) = self.row_mut(ticket.conn) else {
            return Reply::noted(SessionNote::Stale);
        };
        row.work = Work::Idle;
        let to = Addressed {
            conn: ticket.conn,
            req_id: ticket.req_id,
        };
        match done.result {
            Computed::Proceeded { awaiting, answer } => {
                let Pairing::Replying { offer, since } = row.pairing else {
                    row.abandon();
                    return Reply::noted(SessionNote::Stale);
                };
                row.pairing = Pairing::Awaiting {
                    awaiting,
                    offer,
                    since,
                };
                copied(answer.as_slice(), dst)
            }
            Computed::Enrolled { enrolling, admit } => {
                let Pairing::Enrolling { offer, .. } = row.pairing else {
                    row.abandon();
                    return Reply::noted(SessionNote::Stale);
                };
                row.abandon();
                self.enrolled(to, (enrolling, admit, offer), now, facts, fram, dst)
                    .await
            }
            Computed::Bound {
                channel,
                answer,
                client_id,
                generation,
            } => {
                let still = self.keys.epoch.and_then(|epoch| {
                    self.keys
                        .clients
                        .occupant(client_id, epoch)
                        .filter(|occupant| occupant.generation() == generation)
                });
                if still.is_none() {
                    // Re-keyed or reset while the `Hello` was computed: the
                    // key it proved is no longer this slot's.
                    return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst);
                }
                self.bindings = self.bindings.wrapping_add(1);
                let serial = self.bindings;
                let Some(row) = self.row_mut(ticket.conn) else {
                    return Reply::noted(SessionNote::Stale);
                };
                row.bound = Bound::Session(Binding {
                    client: client_id,
                    generation,
                    channel,
                    heard: now,
                    serial,
                });
                copied(answer.as_slice(), dst).with(SessionNote::Bound(ticket.conn))
            }
            Computed::PairFailed(why) => {
                row.abandon();
                let counted = why.counts();
                match why.refusal() {
                    Some(code) => self.refused(to, code, counted, now, dst),
                    None => Reply::noted(SessionNote::Dropped),
                }
            }
            Computed::HelloFailed(why) => self.refused(to, why.refusal(), why.counts(), now, dst),
            Computed::Vouched { answer, serial } => match &mut row.bound {
                Bound::Session(binding) if binding.serial == serial => {
                    vouched(to, binding, &answer, dst)
                }
                // Ended or bound again since: the client that asked holds
                // no keys to open it with.
                Bound::Session(_) | Bound::Never | Bound::Ended => Reply::noted(SessionNote::Stale),
            },
            Computed::Unwritable => {
                row.abandon();
                Reply::noted(SessionNote::TooLarge)
            }
        }
    }

    /// `Discover 0x80` with the row's live challenge, minted now if it has
    /// none (P-060). No challenge to give is error 18: a unit not
    /// provisioned, or a generator that did not read back.
    async fn discover<F: Fram>(
        &mut self,
        to: Addressed,
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let (Some(secret), Some(epoch), true) = (
            self.keys.secret,
            self.keys.epoch,
            self.keys.controller.is_some(),
        ) else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::NoChallenge);
        };
        let live = match self.row(to.conn).map(|row| row.challenge) {
            Some(Challenge::Live { bytes, minted }) if alive(minted, now) => Some(bytes),
            Some(Challenge::Live { .. } | Challenge::Owed | Challenge::Spent) | None => None,
        };
        let challenge = if let Some(bytes) = live {
            bytes
        } else {
            let Ok(bytes) = self.keys.generator.challenge(fram).await else {
                return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                    .with(SessionNote::EntropyUnavailable);
            };
            // The old one is discarded with the draw: one per row (P-060).
            if let Some(row) = self.row_mut(to.conn) {
                row.challenge = Challenge::Live { bytes, minted: now };
            }
            bytes
        };
        let written = km43::Discovery {
            version: Version::V1_0,
            device_id: secret.device_id_bytes(),
            model: facts.model,
            provisioned: self.keys.clients.enrolled(epoch) > 0,
            pairing_open: facts.pairing_open,
            challenge,
            epoch,
        }
        .write(to.header(MessageType::DiscoverResponse), dst);
        answered(written.ok())
    }

    /// `Pair 0x0B`, message 1, in P-226's order: the body and its suite, the
    /// challenge consumed, then the label's tag. A tag that fails is bare
    /// error 10, counted (P-066). One that opens into a closed window, or a
    /// table P-240 could not allocate from, is refused under the label's
    /// refusal key, uncounted (P-241). Otherwise message 2 is queued (P-243).
    async fn pair<F: Fram>(
        &mut self,
        to: Addressed,
        frame: &[u8],
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let arrival = match Envelope::decode(frame)
            .map_err(km43::PairError::from)
            .and_then(PairArrival::decode)
        {
            Ok(arrival) => arrival,
            Err(why) => return self.pair_refused(to, why, now, dst),
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
        // A new `Pair` abandons the handshake the row held (P-229).
        if let Some(row) = self.row_mut(to.conn) {
            row.abandon();
        }
        let Some((secret, epoch)) = self.ready() else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::NoChallenge);
        };
        let label = secret.label();
        let prologue = prologue(secret.device_id(), epoch, &challenge, to.conn);
        let mut plain = [0u8; km43::MAX_PAIR_OFFER];
        let offered = match arrival.open(&prologue, &label.pair_psk(), &mut plain) {
            Ok(offered) => offered,
            Err(why) => return self.pair_refused(to, why, now, dst),
        };
        let offer = offered.offer();
        let Ok(client_label) = ClientLabel::new(offer.label) else {
            return bare(to, Incoming::Client(ErrorCode::MalformedFrame), dst);
        };
        let refusal = if !facts.pairing_open {
            Some(PairRefusal::WindowClosed)
        } else if self.keys.clients.place(epoch, None, offer.label) == Place::Full {
            Some(PairRefusal::TableFull)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return answered(offered.refuse(refusal, &label.refusal_key(), dst).ok());
        }
        let kind = offer.client_kind;
        let Ok(ephemeral) = self.keys.generator.draw(fram).await else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::EntropyUnavailable);
        };
        let Some(frame) = Bytes::copied(frame) else {
            return bare(to, Incoming::Client(ErrorCode::PayloadTooLarge), dst);
        };
        let Some(row) = self.row_mut(to.conn) else {
            return Reply::NOTHING;
        };
        row.pairing = Pairing::Replying {
            offer: Offer {
                kind,
                label: client_label,
            },
            since: now,
        };
        row.work = Work::Queued(Job::new(
            row.ticket(to.req_id),
            Task::Proceed {
                frame,
                prologue,
                ephemeral,
            },
        ));
        Reply::noted(SessionNote::Queued(to.conn))
    }

    /// `Enrol 0x13`, message 3: queued if the row holds a handshake waiting
    /// for it (P-243). On a row that holds none it is error 10, uncounted,
    /// because nothing was computed to refuse it (P-229).
    fn enrol(&mut self, to: Addressed, frame: &[u8], now: Tick, dst: &mut [u8]) -> Reply {
        let Some(row) = self.row_mut(to.conn) else {
            return Reply::NOTHING;
        };
        let pairing = core::mem::replace(&mut row.pairing, Pairing::None);
        let Pairing::Awaiting {
            awaiting,
            offer,
            since,
        } = pairing
        else {
            row.abandon();
            return bare(to, Incoming::Client(ErrorCode::AuthenticationFailed), dst);
        };
        let expired = now
            .since(since)
            .is_none_or(|age| age.as_millis() >= PAIRING_LIFE.as_millis());
        let copy = Bytes::copied(frame);
        let (false, Some(frame)) = (expired, copy) else {
            row.abandon();
            return bare(to, Incoming::Client(ErrorCode::AuthenticationFailed), dst);
        };
        row.pairing = Pairing::Enrolling { offer, since };
        row.work = Work::Queued(Job::new(
            row.ticket(to.req_id),
            Task::Enrol { frame, awaiting },
        ));
        Reply::noted(SessionNote::Queued(to.conn))
    }

    /// Message 3 opened: the window read again, P-240 run again with the
    /// client key, and the slot written as P-239 says before the answer
    /// names it (P-064). The next challenge is drawn first, because every
    /// outcome carries one (P-058).
    async fn enrolled<F: Fram>(
        &mut self,
        to: Addressed,
        opened: (km43::Enrolling, [u8; km43::KEY_BYTES], Offer),
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let (enrolling, admit, offer) = opened;
        let Some((_, epoch)) = self.ready() else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::NoChallenge);
        };
        let Ok(next_challenge) = self.keys.generator.challenge(fram).await else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::EntropyUnavailable);
        };
        if let Some(row) = self.row_mut(to.conn) {
            row.challenge = Challenge::Live {
                bytes: next_challenge,
                minted: now,
            };
        }
        let client = enrolling.client();
        let place = self
            .keys
            .clients
            .place(epoch, Some(&client), offer.label.as_str());
        let (outcome, note) = if facts.pairing_open {
            match place.slot() {
                Some((id, role)) => {
                    // Every session on the slot goes before it is rewritten
                    // (P-240), whether or not the write then lands.
                    self.unbind(id);
                    let enrolment = Enrolment {
                        client,
                        admit,
                        suite: SUITE,
                        role,
                        kind: offer.kind,
                        label: offer.label,
                    };
                    match self.keys.clients.enrol(id, enrolment, epoch, fram).await {
                        Ok(generation) => (
                            match place {
                                Place::Free(..) => Outcome::Enrolled(id, generation),
                                Place::SameKey(..) | Place::Reclaim(_) | Place::Full => {
                                    Outcome::Reclaimed(id, generation)
                                }
                            },
                            Some(SessionNote::Paired(id)),
                        ),
                        Err(_) => (Outcome::NotStored, Some(SessionNote::TableNotStored)),
                    }
                }
                None => (Outcome::TableFull, None),
            }
        } else {
            (Outcome::WindowClosed, None)
        };
        let written = enrolling.answer(
            &EnrolAnswer {
                outcome,
                next_challenge,
            },
            dst,
        );
        let reply = answered(written.ok());
        match note {
            Some(note) => reply.with(note),
            None => reply,
        }
    }

    /// `Hello 0x01`, in P-226's order and then P-238's: the body and its
    /// suite, the challenge consumed, then the admission tag against every
    /// occupied slot before any DH. No match is bare error 12, counted. A
    /// match is queued for the proof and the answer (P-243).
    async fn hello<F: Fram>(
        &mut self,
        to: Addressed,
        frame: &[u8],
        now: Tick,
        facts: &Facts<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        let arrival = match Envelope::decode(frame)
            .map_err(km43::HelloError::from)
            .and_then(HelloArrival::decode)
        {
            Ok(arrival) => arrival,
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
        // One handshake computed per row: a new one supersedes the last.
        if let Some(row) = self.row_mut(to.conn) {
            row.abandon();
        }
        let Some((secret, epoch)) = self.ready() else {
            return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst)
                .with(SessionNote::NoChallenge);
        };
        let prologue = prologue(secret.device_id(), epoch, &challenge, to.conn);
        let occupied = self
            .keys
            .clients
            .occupied(epoch)
            .map(|(id, occupant)| (id, occupant.admit_key()));
        let mut keys: [Option<(ClientId, km43::AdmitKey)>; crate::clients::SLOTS] =
            [const { None }; crate::clients::SLOTS];
        for (slot, key) in keys.iter_mut().zip(occupied) {
            *slot = Some(key);
        }
        let admitted = arrival.admit(&prologue, keys.iter().flatten().map(|(id, key)| (*id, key)));
        let slot = match admitted {
            Ok(admitted) => admitted.slot(),
            Err(why) => return self.refused(to, why.refusal(), why.counts(), now, dst),
        };
        let Some(occupant) = self.keys.clients.occupant(slot, epoch).copied() else {
            return bare(to, Incoming::Client(ErrorCode::UnknownClient), dst);
        };
        let Ok(ephemeral) = self.keys.generator.draw(fram).await else {
            return bare(to, Incoming::Client(ErrorCode::ChallengeUnavailable), dst)
                .with(SessionNote::EntropyUnavailable);
        };
        let Some(frame) = Bytes::copied(frame) else {
            return bare(to, Incoming::Client(ErrorCode::PayloadTooLarge), dst);
        };
        let report = Report {
            session: SessionId::from(to.conn.get()),
            fw_controller: report_text(facts.fw_controller),
            fw_comms: report_text(facts.fw_comms),
            log: facts.log,
            time_known: facts.time_known,
            client_id: slot,
            generation: occupant.generation(),
        };
        let admit = *occupant.admit_key().to_stored();
        let Some(row) = self.row_mut(to.conn) else {
            return Reply::NOTHING;
        };
        row.work = Work::Queued(Job::new(
            row.ticket(to.req_id),
            Task::Hello {
                frame,
                prologue,
                admit,
                enrolled: occupant.client(),
                suite: occupant.suite(),
                ephemeral,
                report,
            },
        ));
        Reply::noted(SessionNote::Queued(to.conn))
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

    /// A sealed request on a session: opened under the session's keys before
    /// anything is read, P-022's window applied by the opener, and only one
    /// that opens refreshes the session (P-077). A tag that fails counts
    /// against the connection (P-051); a `req_id` the window refuses is
    /// dropped, unanswered and uncounted.
    async fn sealed<F: Fram>(
        &mut self,
        to: Addressed,
        envelope: Envelope<'_>,
        now: Tick,
        link: (&mut crate::Wifi, bool),
        fram: &mut F,
        dst: &mut [u8],
    ) -> Reply {
        if let Err(refused) = self.bound_on(to, dst) {
            return refused;
        }
        let kind = envelope.header().kind;
        let mut plain = [0u8; MAX_PAYLOAD];
        let Self {
            rows,
            keys,
            time,
            tickets,
            ..
        } = self;
        let Some(row) = rows.iter_mut().flatten().find(|row| row.conn == to.conn) else {
            return Reply::NOTHING;
        };
        let Bound::Session(binding) = &mut row.bound else {
            return Reply::NOTHING;
        };
        let opened = Sealed::decode(envelope)
            .and_then(|sealed| sealed.open(&mut binding.channel.rx, &mut plain));
        let opened = match opened {
            Ok(opened) => opened,
            Err(why) => return self.unopened(to, &why, now, dst),
        };
        binding.heard = now;
        let payload = opened.inner();
        let mask = keys.mask(binding);
        let reply = match kind {
            MessageType::Goodbye => goodbye(to, binding, payload, dst),
            MessageType::WifiScan | MessageType::WifiStatus => {
                wifi_answer(to, binding, (keys, mask), link, (kind, payload, now), dst)
            }
            MessageType::GetConfig => config_answer(to, binding, (keys, mask), payload, dst),
            MessageType::Command => match signed(to, binding, &opened, dst) {
                Ok(write) => command(to, binding, keys, write, fram, now, dst).await,
                Err(refused) => refused,
            },
            MessageType::SetConfig => match signed(to, binding, &opened, dst) {
                Ok(write) => set_config(to, binding, (keys, mask), write, fram, dst).await,
                Err(refused) => refused,
            },
            MessageType::Time => match signed(to, binding, &opened, dst) {
                Ok(write) => time_asked(to, binding, (time, tickets), mask, &write, now, dst),
                Err(refused) => refused,
            },
            MessageType::Vouch => row.vouch(to, keys.epoch, payload, dst),
            // Opened, and not served by this slice: error 2 under the
            // session's keys, which an opened request has earned. Firmware
            // is unserved (P-143); the reads are the later slices'.
            MessageType::Inventory
            | MessageType::Readings
            | MessageType::Concerns
            | MessageType::History
            | MessageType::Subscribe
            | MessageType::ReadLog
            | MessageType::Firmware
            // The client list, invites and removal are #180's.
            | MessageType::Clients
            | MessageType::Invite
            | MessageType::Approve
            | MessageType::Remove => sealed_error(to, binding, ErrorCode::UnknownMessageType, dst),
            // `frame` routes only the types above here.
            MessageType::Discover
            | MessageType::DiscoverResponse
            | MessageType::Hello
            | MessageType::HelloResponse
            | MessageType::InventoryResponse
            | MessageType::ReadingsResponse
            | MessageType::ConcernsResponse
            | MessageType::HistoryResponse
            | MessageType::SubscribeResponse
            | MessageType::EventResponse
            | MessageType::ReadLogResponse
            | MessageType::WifiScanResponse
            | MessageType::WifiStatusResponse
            | MessageType::GetConfigResponse
            | MessageType::SetConfigResponse
            | MessageType::CommandResponse
            | MessageType::FirmwareResponse
            | MessageType::TimeResponse
            | MessageType::Pair
            | MessageType::PairResponse
            | MessageType::Enrol
            | MessageType::EnrolResponse
            | MessageType::GoodbyeResponse
            | MessageType::VouchResponse
            | MessageType::ClientsResponse
            | MessageType::InviteResponse
            | MessageType::ApproveResponse
            | MessageType::RemoveResponse
            | MessageType::ErrorResponse => {
                sealed_error(to, binding, ErrorCode::MalformedFrame, dst)
            }
        };
        // Only a `Goodbye` whose body read unbinds: the binding goes and the
        // keys with it, and the row stays with its transport (P-076).
        if matches!(reply.note, Some(SessionNote::Unbound(_))) {
            row.bound = Bound::Ended;
        }
        reply
    }

    /// The recorder's answer to the `Time` it was handed as `ticket`,
    /// sealed for the session that asked. Nothing is written for a ticket
    /// that is not the one waiting, or when that session has ended or been
    /// bound again since: its client is not listening.
    pub fn time_answered(&mut self, ticket: u32, answer: TimeAnswer, dst: &mut [u8]) -> Reply {
        let Some(asked) = self.time.filter(|asked| asked.ticket == ticket) else {
            return Reply::NOTHING;
        };
        self.time = None;
        let Some(Row {
            bound: Bound::Session(binding),
            ..
        }) = self
            .rows
            .iter_mut()
            .flatten()
            .find(|row| row.conn == asked.to.conn)
        else {
            return Reply::NOTHING;
        };
        if binding.serial != asked.serial {
            return Reply::NOTHING;
        }
        let ack = match answer {
            TimeAnswer::Ack(ack) => ack,
            TimeAnswer::Busy => {
                return sealed_error(asked.to, binding, ErrorCode::BusyRetry, dst);
            }
        };
        let mut body = [0u8; MAX_TIME_ACK_BYTES];
        let written = ack.encode(&mut body).ok().and_then(|len| {
            let body = body.get(..len)?;
            binding
                .channel
                .tx
                .seal(asked.to.header(MessageType::TimeResponse), body, dst)
                .ok()
        });
        answered(written)
    }

    /// A refusal answered bare, counted against the connection when the
    /// peer failed a check it should have passed (P-051); the one that
    /// reaches the threshold ends any session on it and closes it.
    /// A sealed request that did not open: refused and counted as the
    /// opener says, or dropped unanswered (P-022, P-051).
    fn unopened(
        &mut self,
        to: Addressed,
        why: &km43::SealError,
        now: Tick,
        dst: &mut [u8],
    ) -> Reply {
        match why.refusal() {
            Some(code) => self.refused(to, code, why.counts(), now, dst),
            None => Reply::noted(SessionNote::Dropped),
        }
    }

    fn refused(
        &mut self,
        to: Addressed,
        code: Code,
        counted: bool,
        now: Tick,
        dst: &mut [u8],
    ) -> Reply {
        let shed = counted && self.count_failure(to.conn, now);
        let mut reply = bare(to, Incoming::from(code.code()), dst);
        if shed {
            reply.close = Some(Close {
                conn: to.conn,
                reason: CloseReason::AuthenticationFailures,
            });
        }
        reply
    }

    /// A pairing message that did not read or did not open: its handshake
    /// abandoned (P-229), and answered as km43 says, counted when it says.
    fn pair_refused(
        &mut self,
        to: Addressed,
        why: km43::PairError,
        now: Tick,
        dst: &mut [u8],
    ) -> Reply {
        if let Some(row) = self.row_mut(to.conn) {
            row.abandon();
        }
        match why.refusal() {
            Some(code) => self.refused(to, code, why.counts(), now, dst),
            None => Reply::noted(SessionNote::Dropped),
        }
    }

    /// The secret and the epoch, when the unit can pair and admit at all: a
    /// controller key and a generator to draw from as well (P-235, P-237).
    fn ready(&self) -> Option<(Secret, Epoch)> {
        self.keys.controller?;
        Some((self.keys.secret?, self.keys.epoch?))
    }

    /// Whether the unit has what a challenge is given for.
    const fn provisioned(&self) -> bool {
        self.keys.secret.is_some() && self.keys.epoch.is_some() && self.keys.controller.is_some()
    }

    /// End every session bound to `client`, leaving the rows to their
    /// transports (P-076, P-240).
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
                row.abandon();
            }
            shed
        })
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

/// P-227's prologue as the controller builds it for this connection.
fn prologue(
    device_id: DeviceId,
    epoch: Epoch,
    challenge: &[u8; CHALLENGE_BYTES],
    conn: Conn,
) -> Prologue {
    Prologue::new(&PrologueFields {
        suite: SUITE,
        version: Version::V1_0,
        device_id,
        epoch,
        challenge,
        handle: SessionId::from(conn.get()),
    })
}

/// P-241's condition for message 2: P-240's step 2 or 3 would allocate. At
/// message 1 there is no client key, so step 1 cannot be run.
fn report_text(text: &str) -> ReportText {
    // `Facts` carries link texts, which are already within the cap; one that
    // is not is reported as nothing rather than cut mid-character.
    ReportText::new(text).unwrap_or(ReportText::EMPTY)
}

/// An answer the worker wrote, copied into the adapter's buffer.
fn copied(answer: &[u8], dst: &mut [u8]) -> Reply {
    let written = dst.get_mut(..answer.len()).map(|room| {
        room.copy_from_slice(answer);
        answer.len()
    });
    answered(written)
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
    answered(written).with(SessionNote::Refused(wire(code)))
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
    let reply = answered(written);
    if reply.answer.is_some() {
        reply.with(SessionNote::Unreadable)
    } else {
        reply
    }
}

/// A refusal of a request that opened: sealed, as P-142 has for every
/// client code; a link-local one, which none of these is, bare.
fn refused_under(to: Addressed, binding: &mut Binding, code: Code, dst: &mut [u8]) -> Reply {
    match code {
        Code::Client(code) => sealed_error(to, binding, code, dst),
        Code::LinkLocal(code) => bare(to, Incoming::LinkLocal(code), dst),
    }
}

/// A write that opened and did not read as one: its refusal sealed, or
/// nothing where km43 says silence.
fn signed_refused(
    to: Addressed,
    binding: &mut Binding,
    code: Option<Code>,
    dst: &mut [u8],
) -> Reply {
    match code {
        Some(code) => refused_under(to, binding, code, dst),
        None => Reply::noted(SessionNote::Dropped),
    }
}

/// `Ack 0x88`, sealed.
fn acked(to: Addressed, binding: &mut Binding, ack: CommandAck<'_>, dst: &mut [u8]) -> Reply {
    let mut body = [0u8; MAX_COMMAND_ACK_BYTES];
    let written = ack.encode(&mut body).ok().and_then(|len| {
        let body = body.get(..len)?;
        binding
            .channel
            .tx
            .seal(to.header(MessageType::CommandResponse), body, dst)
            .ok()
    });
    answered(written)
}

/// The widest `Vouch 0x94` body: a five-pair map, the outcome, three `u32`
/// at five bytes each, and P-041's sixteen-byte tag behind its one-byte
/// head. The tag's width is spelled out because `km43::TAG_BYTES` is two
/// constants to a glob import, and naming it is refused.
const VOUCH_ANSWER_BYTES: usize = 1 + (1 + 1) + 3 * (1 + 5) + (1 + 1 + 16);

/// `Vouch 0x94`, sealed for the session that asked.
fn vouched(to: Addressed, binding: &mut Binding, answer: &VouchAnswer, dst: &mut [u8]) -> Reply {
    let mut body = [0u8; VOUCH_ANSWER_BYTES];
    let written = answer.encode(&mut body).ok().and_then(|len| {
        let body = body.get(..len)?;
        binding
            .channel
            .tx
            .seal(to.header(MessageType::VouchResponse), body, dst)
            .ok()
    });
    answered(written)
}

/// An `Error 0xFF`, sealed, for a request that opened.
fn sealed_error(to: Addressed, binding: &mut Binding, code: ErrorCode, dst: &mut [u8]) -> Reply {
    let mut body = [0u8; 16];
    let written = ErrorBody {
        code: Incoming::Client(code),
        detail: "",
    }
    .encode(&mut body)
    .ok()
    .and_then(|len| {
        let body = body.get(..len)?;
        binding
            .channel
            .tx
            .seal(to.header(MessageType::ErrorResponse), body, dst)
            .ok()
    });
    answered(written).with(SessionNote::Refused(code as u16))
}

const fn wire(code: Incoming) -> u16 {
    match code {
        Incoming::Client(code) => code as u16,
        Incoming::LinkLocal(code) => code as u16,
        Incoming::Unknown(raw) => raw,
    }
}

/// `Command 0x08` that opened, through [`admit`] under the client the
/// session was bound to.
async fn command<F: Fram>(
    to: Addressed,
    binding: &mut Binding,
    keys: &mut Keys,
    write: SignedWrite<'_>,
    fram: &mut F,
    now: Tick,
    dst: &mut [u8],
) -> Reply {
    let dedups = keys.clients.commands_mut();
    let mut admission = admit(write, binding.client, dedups, fram, now).await;
    if let Admission::InFlight(retry) = admission {
        // No output has authority yet, so none can already be where the
        // command asked: the state store's answer is always to run it.
        admission = retry.again(keys.clients.commands_mut(), fram, now).await;
    }
    match admission {
        Admission::Refused(why) => {
            let reply = refused_under(to, binding, why.code(), dst);
            if why.raises().is_some() {
                reply.with(SessionNote::NotKept)
            } else {
                reply
            }
        }
        Admission::Answered(ack) => acked(to, binding, ack, dst),
        Admission::Execute(Permit::Command(reservation)) => {
            let finished = reservation
                .finished(
                    keys.clients.commands_mut(),
                    fram,
                    Executed::Rejected,
                    UNSPECIFIED,
                )
                .await;
            let reply = acked(to, binding, finished.ack, dst);
            if finished.recorded.is_err() {
                reply.with(SessionNote::NotKept)
            } else {
                reply
            }
        }
        // `admit` hands a `Command` a reservation, never a plain write.
        Admission::Execute(Permit::Write(_)) => {
            sealed_error(to, binding, ErrorCode::UnknownMessageType, dst)
        }
        // Settled by another retry between the two, and neither running
        // nor recorded now: this one goes again.
        Admission::InFlight(_) => sealed_error(to, binding, ErrorCode::BusyRetry, dst),
    }
}

/// A write out of a request that opened, or its refusal (P-053).
fn signed<'a>(
    to: Addressed,
    binding: &mut Binding,
    opened: &km43::Opened<'a>,
    dst: &mut [u8],
) -> Result<SignedWrite<'a>, Reply> {
    SignedWrite::read(opened).map_err(|why| signed_refused(to, binding, why.refusal(), dst))
}

/// `Goodbye 0x0C` that opened: answered, and the caller unbinds.
fn goodbye(to: Addressed, binding: &mut Binding, payload: &[u8], dst: &mut [u8]) -> Reply {
    if EmptyBody::decode(MessageType::Goodbye, payload).is_err() {
        return sealed_error(to, binding, ErrorCode::MalformedFrame, dst);
    }
    let mut body = [0u8; 1];
    let answer = EmptyBody
        .encode(MessageType::GoodbyeResponse, &mut body)
        .ok()
        .and_then(|len| {
            let body = body.get(..len)?;
            binding
                .channel
                .tx
                .seal(to.header(MessageType::GoodbyeResponse), body, dst)
                .ok()
        });
    Reply {
        answer,
        close: None,
        note: Some(SessionNote::Unbound(to.conn)),
    }
}

/// `Time 0x0A` that opened: handed to the recorder, which owns the
/// calendar and the floor, with a ticket; the answer comes back through
/// [`Sessions::time_answered`]. One at a time (P-118).
fn time_asked(
    to: Addressed,
    binding: &mut Binding,
    asking: (&mut Option<AskedTime>, &mut u32),
    mask: Option<km43::ClientCapability>,
    write: &SignedWrite<'_>,
    now: Tick,
    dst: &mut [u8],
) -> Reply {
    let (time, tickets) = asking;
    let operation = match TimeOperation::decode(write.operation()) {
        Ok(operation) => operation,
        Err(why) => return refused_under(to, binding, why.refusal(), dst),
    };
    if time.is_some() {
        return sealed_error(to, binding, ErrorCode::BusyRetry, dst);
    }
    let authorised = allows(mask, km43::ClientCapability::SET_CLOCK);
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

/// `SetConfig 0x07` that opened: the mask, then the version, then the
/// section (P-100, P-105).
async fn set_config<F: Fram>(
    to: Addressed,
    binding: &mut Binding,
    keys: (&mut Keys, Option<km43::ClientCapability>),
    write: SignedWrite<'_>,
    fram: &mut F,
    dst: &mut [u8],
) -> Reply {
    let (keys, mask) = keys;
    let operation = match km43::SetConfigOperation::decode(write.operation()) {
        Ok(operation) => operation,
        Err(why) => return refused_under(to, binding, why.refusal(), dst),
    };
    let required = km43::ClientCapability(
        km43::ClientCapability::WRITE_CONFIG.0
            | if private(operation.section) {
                km43::ClientCapability::WRITE_NETWORK_AND_CLOUD.0
            } else {
                0
            },
    );
    let authorised = allows(mask, required);
    let ack = if authorised {
        match keys
            .configuration
            .set(operation, &mut keys.network, fram)
            .await
        {
            Ok(ack) => ack,
            Err(code) => return sealed_error(to, binding, code, dst),
        }
    } else {
        km43::SetConfigAck {
            section: operation.section,
            version: keys.configuration.version(operation.section, &keys.network),
            outcome: km43::SetConfig::Unauthorised,
        }
    };
    let mut body = [0; km43::MAX_SET_CONFIG_ACK_BYTES];
    let written = ack.encode(&mut body).ok().and_then(|len| {
        let body = body.get(..len)?;
        binding
            .channel
            .tx
            .seal(to.header(MessageType::SetConfigResponse), body, dst)
            .ok()
    });
    answered(written)
}

/// Whether a section is the network's or the cloud's: written with bit 1,
/// read with bit 5 (P-105, P-251).
const fn private(section: km43::ConfigSection) -> bool {
    matches!(
        section,
        km43::ConfigSection::Network | km43::ConfigSection::Cloud
    )
}

/// Whether the mask of a session's enrolment reaches every bit of
/// `required`. A session whose slot was re-keyed has no mask, and is
/// allowed nothing.
fn allows(mask: Option<km43::ClientCapability>, required: km43::ClientCapability) -> bool {
    mask.is_some_and(|mask| mask.allows(required))
}

/// `GetConfig 0x06`. The network and cloud sections need bit 5, and a slot
/// without it is sealed error 20 before the section is read (P-251).
fn config_answer(
    to: Addressed,
    binding: &mut Binding,
    keys: (&Keys, Option<km43::ClientCapability>),
    payload: &[u8],
    dst: &mut [u8],
) -> Reply {
    let (keys, mask) = keys;
    let request = match km43::GetConfigRequest::decode(payload) {
        Ok(request) => request,
        Err(why) => return refused_under(to, binding, why.refusal(), dst),
    };
    if private(request.section) && !allows(mask, km43::ClientCapability::READ_PRIVATE) {
        return sealed_error(to, binding, ErrorCode::RoleNotPermitted, dst);
    }
    let mut body = [0; km43::CONFIG_HEADER_BYTES + km43::MAX_NETWORK_READ_BYTES];
    let len = match keys
        .configuration
        .answer(request.section, &keys.network, &mut body)
    {
        Ok(len) => len,
        Err(code) => return sealed_error(to, binding, code, dst),
    };
    let written = body.get(..len).and_then(|body| {
        binding
            .channel
            .tx
            .seal(to.header(MessageType::GetConfigResponse), body, dst)
            .ok()
    });
    answered(written)
}

fn wifi_answer(
    to: Addressed,
    binding: &mut Binding,
    keys: (&Keys, Option<km43::ClientCapability>),
    link: (&mut crate::Wifi, bool),
    request: (MessageType, &[u8], Tick),
    dst: &mut [u8],
) -> Reply {
    let (keys, mask) = keys;
    let (wifi, agreed) = link;
    let (kind, payload, now) = request;
    let section = match keys.network.held() {
        crate::Held::Present(network) => network.version(),
        crate::Held::Absent | crate::Held::Corrupt | crate::Held::Malformed(_) => 0,
    };
    let mut body = [0; MAX_PAYLOAD];
    let (response, encoded) = if kind == MessageType::WifiScan {
        let asked = match km43::ScanRequest::decode(payload) {
            Ok(asked) => asked,
            Err(why) => return refused_under(to, binding, why.refusal(), dst),
        };
        // The list is private (P-251); a refresh also moves the radio off
        // the network, which is bit 1's (P-105).
        if !allows(mask, km43::ClientCapability::READ_PRIVATE) {
            return sealed_error(to, binding, ErrorCode::RoleNotPermitted, dst);
        }
        let authorised = allows(mask, km43::ClientCapability::WRITE_NETWORK_AND_CLOUD);
        let refused = if asked.refresh {
            wifi.refresh(authorised, section != 0, agreed, now)
        } else {
            None
        };
        (
            MessageType::WifiScanResponse,
            wifi.answer(refused, now, &mut body),
        )
    } else {
        if let Err(why) = EmptyBody::decode(MessageType::WifiStatus, payload) {
            return refused_under(to, binding, why.refusal(), dst);
        }
        (
            MessageType::WifiStatusResponse,
            wifi.status(section).encode(&mut body),
        )
    };
    let len = match encoded {
        Ok(len) => len,
        Err(why) => return refused_under(to, binding, why.refusal(), dst),
    };
    answered(
        body.get(..len)
            .and_then(|body| binding.channel.tx.seal(to.header(response), body, dst).ok()),
    )
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{
        ClientChannel, CommandKind, CommandOperation, EnrolPending, Entropy, Fingerprint,
        HelloOffer, HelloPending, Label, MAX_FRAME, PairOffer, PairPending, PairReply,
        PrintedSecret, Role, Signed, StaticKey,
    };

    use super::*;
    use crate::agreement::Agreement;
    use crate::body::Kept;
    use crate::clients::Occupant;
    use crate::drbg::DrbgState;
    use crate::fram::{Address, FRAM_BYTES, Refused};
    use crate::map;
    use crate::secret::ControllerKey;

    const DEVICE: [u8; 16] = [7; 16];
    const PRINTED: [u8; 32] = [9; 32];
    const CONTROLLER: [u8; 32] = [5; 32];
    const SEED: [u8; 32] = [3; 32];

    const PART_BYTES: usize = map::END.0 as usize;
    const _: () = assert!(PART_BYTES <= FRAM_BYTES);

    /// The part in an array: a supply that can fall, and the generator's
    /// record alone made to lose its writes.
    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        drbg_lost: bool,
        /// Refuse writes to the slots and their marks only, as a part that
        /// failed mid-way through an enrolment would.
        table_refused: bool,
    }

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
            let start = usize::from(at.0);
            // The generator's record starts where the epoch's ends.
            let drbg = usize::from(map::EPOCH.end().0);
            let in_drbg = (drbg..usize::from(map::DRBG.end().0)).contains(&start);
            let table = usize::from(map::NETWORK.end().0)..usize::from(map::COMMANDS.end().0);
            let outcome = if self.falling || (self.table_refused && table.contains(&start)) {
                Err(Refused::SupplyFalling)
            } else {
                if !(self.drbg_lost && in_drbg) {
                    self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                }
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    /// A frame, without an allocator.
    #[derive(Clone, Copy)]
    struct Frame {
        buf: [u8; MAX_FRAME],
        len: usize,
    }

    impl Frame {
        const EMPTY: Self = Self {
            buf: [0; MAX_FRAME],
            len: 0,
        };

        fn of(bytes: &[u8]) -> Self {
            let mut out = Self::EMPTY;
            out.buf[..bytes.len()].copy_from_slice(bytes);
            out.len = bytes.len();
            out
        }
    }

    impl core::fmt::Debug for Frame {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Frame({} bytes)", self.len)
        }
    }

    impl core::ops::Deref for Frame {
        type Target = [u8];

        fn deref(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    fn conn(n: u16) -> Conn {
        Conn::new(n).expect("a nonzero handle")
    }

    fn label() -> Label {
        Label::new(DeviceId::new(DEVICE), PrintedSecret::new(PRINTED))
    }

    fn fingerprint() -> Fingerprint {
        ControllerKey::new(CONTROLLER)
            .expect("entropy")
            .fingerprint()
    }

    /// A manufactured unit: secret, controller key and generator on the
    /// part, and the sessions over what a boot would read.
    struct Rig {
        part: Part,
        sessions: Sessions,
        agreement: Agreement,
        wifi: crate::Wifi,
        now: Tick,
        pairing_open: bool,
    }

    impl Rig {
        fn new() -> Self {
            Self::built(true)
        }

        fn unprovisioned() -> Self {
            Self::built(false)
        }

        #[expect(
            clippy::large_stack_arrays,
            reason = "the whole map, as the boot reads it; a test thread's stack holds it"
        )]
        fn built(provisioned: bool) -> Self {
            let mut part = Part {
                bytes: [0xFF; PART_BYTES],
                falling: false,
                drbg_lost: false,
                table_refused: false,
            };
            let secret = Secret::new(DEVICE, PRINTED).expect("entropy");
            let controller = ControllerKey::new(CONTROLLER).expect("entropy");
            if provisioned {
                let mut kept = block_on(Kept::read(map::DEVICE_SECRET, &mut part)).expect("reads");
                block_on(kept.write(&mut part, secret)).expect("secret");
                let mut kept = block_on(Kept::read(map::CONTROLLER_KEY, &mut part)).expect("reads");
                block_on(kept.write(&mut part, controller)).expect("key");
                let mut kept = block_on(Kept::read(map::DRBG, &mut part)).expect("reads");
                block_on(kept.write(&mut part, DrbgState::new(SEED).expect("entropy")))
                    .expect("seed");
            }
            let mut epoch_record =
                block_on(Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, &mut part)).expect("reads");
            block_on(epoch_record.write(&mut part, Epoch::FIRST)).expect("epoch");
            let mut clients = block_on(Clients::read(&mut part)).expect("reads");
            let _ = block_on(clients.booted(&mut epoch_record, &mut part)).expect("repairs");
            let keys = Keys {
                configuration: block_on(crate::Configuration::read(&mut part)).expect("reads"),
                network: block_on(Kept::read(map::NETWORK, &mut part)).expect("reads"),
                secret: provisioned.then_some(secret),
                controller: provisioned.then(|| controller.public()),
                epoch: Some(Epoch::FIRST),
                epoch_record,
                clients,
                generator: Generator::new(
                    block_on(Kept::read(map::DRBG, &mut part)).expect("reads"),
                ),
            };
            Self {
                part,
                sessions: Sessions::new(keys),
                agreement: Agreement::new(&secret, &controller),
                wifi: crate::Wifi::EMPTY,
                now: Tick::ZERO,
                pairing_open: true,
            }
        }

        fn facts(&self) -> Facts<'static> {
            Facts {
                model: "test",
                fw_controller: "0.1.0",
                fw_comms: "0.1.0",
                log: LogSpan {
                    oldest: LogSeq(0),
                    newest: LogSeq(0),
                },
                time_known: false,
                pairing_open: self.pairing_open,
                link: Some(Compat::Agreed(Version::V1_0)),
            }
        }

        fn at(&mut self, millis: u64) {
            self.now = Tick::from_millis(millis);
        }

        fn connect(&mut self, handle: u16) {
            assert_eq!(self.sessions.admit(conn(handle)), ClientConnected::Accepted);
            block_on(self.sessions.settle(self.now, &mut self.part));
        }

        fn send(&mut self, frame: &[u8]) -> (Reply, Frame) {
            let facts = self.facts();
            let mut dst = [0u8; MAX_FRAME];
            let reply = block_on(self.sessions.frame(
                frame,
                self.now,
                (&facts, &mut self.wifi),
                &mut self.part,
                &mut dst,
            ));
            (reply, Frame::of(&dst[..reply.answer.unwrap_or(0)]))
        }

        /// Run the next queued key agreement, as the worker would.
        fn compute(&mut self) -> Option<(Reply, Frame)> {
            let job = self.sessions.next_job()?;
            let done = self.agreement.run(job);
            let facts = self.facts();
            let mut dst = [0u8; MAX_FRAME];
            let reply =
                block_on(
                    self.sessions
                        .completed(done, self.now, &facts, &mut self.part, &mut dst),
                );
            Some((reply, Frame::of(&dst[..reply.answer.unwrap_or(0)])))
        }

        /// Send a handshake frame and compute what it queued.
        fn exchange(&mut self, frame: &[u8]) -> (Reply, Frame) {
            let (reply, answer) = self.send(frame);
            if reply.note
                != Some(SessionNote::Queued(conn(u16::from(
                    Envelope::decode(frame)
                        .map_or(SessionId::None, |envelope| envelope.header().session),
                ))))
            {
                return (reply, answer);
            }
            self.compute().expect("a job was queued")
        }
    }

    /// A client on one connection, built from `km43`'s client half.
    struct Phone {
        handle: u16,
        req: u32,
        draws: u8,
        challenge: Option<[u8; CHALLENGE_BYTES]>,
        epoch: Epoch,
        enrolment: Option<km43::Enrolment>,
        channel: Option<ClientChannel>,
    }

    impl Phone {
        fn on(handle: u16) -> Self {
            Self {
                handle,
                req: 0,
                draws: 0,
                challenge: None,
                epoch: Epoch::FIRST,
                enrolment: None,
                channel: None,
            }
        }

        fn header(&mut self, kind: MessageType) -> Header {
            self.req = self.req.wrapping_add(1);
            Header {
                kind,
                session: SessionId::from(self.handle),
                req_id: ReqId(self.req),
            }
        }

        fn entropy(&mut self) -> Entropy {
            self.draws = self.draws.wrapping_add(1);
            let mut bytes = [0u8; 32];
            bytes[0] = u8::try_from(self.handle).expect("a small handle");
            bytes[1] = self.draws;
            bytes[31] = 0x40;
            Entropy::new(bytes)
        }

        fn prologue(&self) -> Prologue {
            prologue(
                DeviceId::new(DEVICE),
                self.epoch,
                self.challenge.as_ref().expect("a challenge to present"),
                conn(self.handle),
            )
        }

        fn discover(&mut self, rig: &mut Rig) -> Reply {
            let mut dst = [0u8; 64];
            let len = self
                .header(MessageType::Discover)
                .write(0, &mut dst)
                .expect("fits")
                .finish()
                .expect("fits");
            let (reply, answer) = rig.send(&dst[..len]);
            if let Ok(discovery) = Envelope::decode(&answer).and_then(|envelope| {
                km43::Discovery::decode(envelope).map_err(|_| EnvelopeError::WrongLength)
            }) {
                self.challenge = Some(discovery.challenge);
                self.epoch = discovery.epoch;
            }
            reply
        }

        /// Discover as setup: the unit answers with a challenge and notes
        /// nothing, or the test stops here rather than later and elsewhere.
        fn challenged(&mut self, rig: &mut Rig) {
            let reply = self.discover(rig);
            assert!(reply.answer.is_some(), "Discover was answered");
            assert_eq!(reply.note, None);
            assert!(self.challenge.is_some(), "the answer carried a challenge");
        }

        /// Pairing message 1 under `label`, as a client holding it writes it.
        fn pair_frame(
            &mut self,
            under: &Label,
            name: &str,
            kind: ClientKind,
        ) -> (PairPending, Frame) {
            let mut dst = [0u8; MAX_FRAME];
            let entropy = self.entropy();
            let header = self.header(MessageType::Pair);
            let (pending, len) = PairPending::start(
                &self.prologue(),
                SUITE,
                under,
                entropy,
                &PairOffer {
                    version: Version::V1_0,
                    client_version: "test",
                    client_kind: kind,
                    label: name,
                },
                header,
                &mut dst,
            )
            .expect("message 1");
            (pending, Frame::of(&dst[..len]))
        }

        /// A whole pairing: message 1, message 2 checked against the label's
        /// fingerprint, message 3 under `key`, and the answer read. The
        /// enrolment is kept before message 3 goes, as P-064 requires.
        fn pair(
            &mut self,
            rig: &mut Rig,
            name: &str,
            kind: ClientKind,
            key: StaticKey,
        ) -> Result<EnrolAnswer, PairRefusal> {
            self.challenged(rig);
            let (pending, frame) = self.pair_frame(&label(), name, kind);
            let (_, answer) = rig.exchange(&frame);
            let envelope = Envelope::decode(&answer).expect("Pair 0x8B");
            let reply = pending
                .read(envelope, &label(), &fingerprint())
                .expect("a reply the label vouches for");
            let proceeding = match reply {
                PairReply::Proceed(proceeding) => proceeding,
                PairReply::Refused(refusal) => return Err(refusal),
            };
            let mut dst = [0u8; MAX_FRAME];
            let header = self.header(MessageType::Enrol);
            let (enrol, len) = proceeding
                .finish(&key, header, &mut dst)
                .expect("message 3");
            self.enrolment = Some(km43::Enrolment::new(
                DeviceId::new(DEVICE),
                proceeding_controller(),
                key,
                SUITE,
                self.epoch,
            ));
            let (_, answer) = rig.exchange(&dst[..len]);
            let answer = read_enrol(enrol, &answer);
            self.challenge = Some(answer.next_challenge);
            Ok(answer)
        }

        /// A `Hello` against the kept enrolment and the live challenge.
        fn hello_frame(&mut self) -> (HelloPending, Frame) {
            let mut dst = [0u8; MAX_FRAME];
            let entropy = self.entropy();
            let header = self.header(MessageType::Hello);
            let (pending, len) = HelloPending::start(
                &self.prologue(),
                self.enrolment.as_ref().expect("enrolled"),
                entropy,
                &HelloOffer {
                    version: Version::V1_0,
                    client_version: "test",
                },
                header,
                &mut dst,
            )
            .expect("message 1");
            (pending, Frame::of(&dst[..len]))
        }

        #[expect(
            clippy::result_large_err,
            reason = "a test helper: the refusal's whole frame is what the caller reads"
        )]
        fn hello(&mut self, rig: &mut Rig) -> Result<km43::HelloReport<'static>, Frame> {
            let (pending, frame) = self.hello_frame();
            let (_, answer) = rig.exchange(&frame);
            let Ok(envelope) = Envelope::decode(&answer) else {
                return Err(answer);
            };
            if envelope.header().kind != MessageType::HelloResponse {
                return Err(answer);
            }
            let mut plain = [0u8; MAX_PAYLOAD];
            let session = pending
                .finish(
                    self.enrolment.as_ref().expect("enrolled"),
                    envelope,
                    &mut plain,
                )
                .expect("message 2 opens");
            let report = *session.report();
            let (client_id, generation) = (report.client_id, report.generation);
            self.channel = Some(session.into_channel());
            Ok(km43::HelloReport {
                fw_controller: "",
                fw_comms: "",
                client_id,
                generation,
                ..report_shape(report)
            })
        }

        /// A sealed request under the session.
        fn sealed(&mut self, kind: MessageType, inner: &[u8]) -> Frame {
            let mut dst = [0u8; MAX_FRAME];
            let channel = self.channel.as_mut().expect("a session");
            let (req, len) = channel
                .tx
                .seal(kind, SessionId::from(self.handle), inner, &mut dst)
                .expect("sealed");
            self.req = req.0;
            Frame::of(&dst[..len])
        }

        fn signed(&mut self, kind: MessageType, operation: &[u8]) -> Frame {
            let mut dst = [0u8; MAX_FRAME];
            let channel = self.channel.as_mut().expect("a session");
            let (_, len) = Signed::new(kind, operation)
                .expect("a write")
                .seal(&mut channel.tx, SessionId::from(self.handle), &mut dst)
                .expect("sealed");
            Frame::of(&dst[..len])
        }

        /// Open an answer under the session: its type and inner body.
        fn open(&mut self, answer: &[u8]) -> (MessageType, Frame) {
            let channel = self.channel.as_mut().expect("a session");
            let envelope = Envelope::decode(answer).expect("an envelope");
            let kind = envelope.header().kind;
            let mut plain = [0u8; MAX_PAYLOAD];
            let opened = Sealed::decode(envelope)
                .and_then(|sealed| sealed.open(&mut channel.rx, &mut plain))
                .expect("opens under the session");
            (kind, Frame::of(opened.inner()))
        }
    }

    /// Message 2, read and checked against the label as a client does.
    fn proceeds(pending: PairPending, answer: &[u8]) -> km43::PairProceeding {
        let read = pending.read(
            Envelope::decode(answer).expect("0x8B"),
            &label(),
            &fingerprint(),
        );
        match read {
            Ok(PairReply::Proceed(proceeding)) => proceeding,
            Ok(PairReply::Refused(refusal)) => panic!("refused: {refusal:?}"),
            Err(why) => panic!("message 2 did not read: {why:?}"),
        }
    }

    fn proceeding_controller() -> PublicKey {
        ControllerKey::new(CONTROLLER).expect("entropy").public()
    }

    fn report_shape(report: km43::HelloReport<'_>) -> km43::HelloReport<'static> {
        km43::HelloReport {
            fw_controller: "",
            fw_comms: "",
            ..report
        }
    }

    fn read_enrol(pending: EnrolPending, answer: &[u8]) -> EnrolAnswer {
        let mut plain = [0u8; MAX_PAYLOAD];
        pending
            .read(Envelope::decode(answer).expect("Enrol 0x93"), &mut plain)
            .expect("sealed under the pairing's keys")
    }

    fn client_key(n: u8) -> StaticKey {
        let mut bytes = [n; 32];
        bytes[31] = 0x41;
        StaticKey::generate(Entropy::new(bytes))
    }

    /// The code key 1 of a bare `Error 0xFF` carries.
    fn bare_code(answer: &[u8]) -> u16 {
        let envelope = Envelope::decode(answer).expect("an envelope");
        assert_eq!(envelope.header().kind, MessageType::ErrorResponse);
        let mut body = envelope.into_body();
        assert_eq!(body.key().expect("a key"), 1);
        body.u16().expect("a code")
    }

    fn enrolled_phone(rig: &mut Rig, handle: u16, name: &str, key: u8) -> Phone {
        rig.connect(handle);
        let mut phone = Phone::on(handle);
        let answer = phone
            .pair(rig, name, ClientKind::App, client_key(key))
            .expect("proceeds");
        assert!(matches!(
            answer.outcome,
            Outcome::Enrolled(..) | Outcome::Reclaimed(..)
        ));
        phone
    }

    #[test]
    fn p_060_discover_answers_with_the_rows_live_challenge_and_the_same_one_again() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        assert_eq!(phone.discover(&mut rig).note, None);
        let first = phone.challenge;
        phone.challenged(&mut rig);
        assert_eq!(phone.challenge, first);
        assert!(first.is_some());
    }

    #[test]
    fn p_060_p_235_a_unit_nobody_manufactured_answers_discover_with_18() {
        let mut rig = Rig::unprovisioned();
        rig.connect(1);
        let mut phone = Phone::on(1);
        let mut dst = [0u8; 64];
        let len = phone
            .header(MessageType::Discover)
            .write(0, &mut dst)
            .expect("fits")
            .finish()
            .expect("fits");
        let (reply, answer) = rig.send(&dst[..len]);
        assert_eq!(bare_code(&answer), ErrorCode::ChallengeUnavailable as u16);
        assert_eq!(reply.note, Some(SessionNote::NoChallenge));
    }

    #[test]
    fn p_237_a_generator_that_does_not_read_back_gives_no_challenge_and_no_ephemeral() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        // The challenge was a draw; the next draw's successor will not land.
        rig.part.drbg_lost = true;
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(bare_code(&answer), ErrorCode::ChallengeUnavailable as u16);
        assert_eq!(reply.note, Some(SessionNote::EntropyUnavailable));
        assert!(rig.sessions.next_job().is_none(), "nothing was queued");
        let reply = phone.discover(&mut rig);
        assert_eq!(reply.note, Some(SessionNote::EntropyUnavailable));
    }

    #[test]
    fn p_064_p_240_a_label_holder_in_the_window_is_enrolled_at_the_lowest_free_slot() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        let answer = phone
            .pair(&mut rig, "phone", ClientKind::App, client_key(1))
            .expect("proceeds");
        let first = ClientId::new(1).expect("a slot");
        assert_eq!(answer.outcome, Outcome::Enrolled(first, Generation::FIRST));
        let occupant = rig
            .sessions
            .keys
            .clients
            .occupant(first, Epoch::FIRST)
            .expect("written before the answer named it");
        assert!(occupant.client().matches(&client_key(1).public()));
        assert_eq!(occupant.label().as_str(), "phone");
        assert_eq!(occupant.role(), Role::Owner);
    }

    #[test]
    fn p_064_p_222_the_next_challenge_opens_a_hello_on_the_same_transport() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        let report = phone.hello(&mut rig).expect("a session");
        assert_eq!(report.client_id, ClientId::new(1).expect("a slot"));
        assert_eq!(report.generation, Generation::FIRST);
        assert!(rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_241_a_closed_window_is_refused_under_the_refusal_key_and_not_counted() {
        let mut rig = Rig::new();
        rig.pairing_open = false;
        rig.connect(1);
        let mut phone = Phone::on(1);
        let refused = phone
            .pair(&mut rig, "phone", ClientKind::App, client_key(1))
            .err();
        assert_eq!(refused, Some(PairRefusal::WindowClosed));
        assert!(rig.sessions.next_job().is_none(), "no DH was queued");
        let row = rig.sessions.row(conn(1)).expect("a row");
        assert_eq!(row.failures.iter().flatten().count(), 0);
    }

    #[test]
    fn p_241_p_067_a_full_table_with_no_such_label_is_refused_before_any_dh() {
        let mut rig = Rig::new();
        for n in 1..=8u8 {
            let id = ClientId::new(u32::from(n)).expect("a slot");
            let mut name = [b'a'; 1];
            name[0] = b'a' + n;
            // A table P-258 permits: an owner, six admins and the viewer.
            let role = match n {
                1 => Role::Owner,
                8 => Role::Viewer,
                _ => Role::Admin,
            };
            let enrolment = Enrolment {
                client: client_key(n).public(),
                admit: [n; 32],
                suite: SUITE,
                role,
                kind: ClientKind::App,
                label: ClientLabel::new(core::str::from_utf8(&name).expect("ascii"))
                    .expect("short"),
            };
            block_on(
                rig.sessions
                    .keys
                    .clients
                    .enrol(id, enrolment, Epoch::FIRST, &mut rig.part),
            )
            .expect("lands");
        }
        rig.connect(1);
        let mut phone = Phone::on(1);
        let refused = phone
            .pair(&mut rig, "stranger", ClientKind::App, client_key(20))
            .err();
        assert_eq!(refused, Some(PairRefusal::TableFull));
        // The same label reclaims instead, through message 2.
        rig.connect(2);
        let mut owner = Phone::on(2);
        let answer = owner
            .pair(&mut rig, "c", ClientKind::App, client_key(21))
            .expect("proceeds");
        let slot = ClientId::new(2).expect("a slot");
        assert_eq!(
            answer.outcome,
            Outcome::Reclaimed(slot, Generation::new(2).expect("nonzero"))
        );
    }

    #[test]
    fn p_066_a_wrong_label_is_bare_10_counted_and_queues_nothing() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let wrong = Label::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
        let (_, frame) = phone.pair_frame(&wrong, "phone", ClientKind::App);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(bare_code(&answer), ErrorCode::AuthenticationFailed as u16);
        assert_eq!(reply.note, Some(SessionNote::Refused(0x0a)));
        assert!(rig.sessions.next_job().is_none());
        let row = rig.sessions.row(conn(1)).expect("a row");
        assert_eq!(row.failures.iter().flatten().count(), 1);
    }

    #[test]
    fn p_061_the_challenge_is_consumed_even_by_a_pair_that_fails() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let wrong = Label::new(DeviceId::new(DEVICE), PrintedSecret::new([1; 32]));
        let (_, frame) = phone.pair_frame(&wrong, "phone", ClientKind::App);
        let _ = rig.send(&frame);
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (_, answer) = rig.send(&frame);
        assert_eq!(
            bare_code(&answer),
            ErrorCode::StaleChallengeReconnectAndRetry as u16
        );
    }

    #[test]
    fn p_229_an_enrol_on_a_row_holding_no_handshake_is_10_and_uncounted() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        let mut dst = [0u8; 128];
        let header = phone.header(MessageType::Enrol);
        let mut cbor = header.write(1, &mut dst).expect("fits");
        cbor.key(1).expect("fits");
        cbor.bytes(&[0u8; 64]).expect("fits");
        let len = cbor.finish().expect("fits");
        let (_, answer) = rig.send(&dst[..len]);
        assert_eq!(bare_code(&answer), ErrorCode::AuthenticationFailed as u16);
        let row = rig.sessions.row(conn(1)).expect("a row");
        assert_eq!(row.failures.iter().flatten().count(), 0);
    }

    #[test]
    fn p_229_a_second_pair_abandons_the_first_and_its_result_is_discarded() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let first = rig.sessions.next_job().expect("queued");
        // A second attempt on the same connection before the first is done.
        phone.challenged(&mut rig);
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let done = rig.agreement.run(first);
        let facts = rig.facts();
        let mut dst = [0u8; MAX_FRAME];
        let stale =
            block_on(
                rig.sessions
                    .completed(done, rig.now, &facts, &mut rig.part, &mut dst),
            );
        assert_eq!(stale.answer, None);
        assert_eq!(stale.note, Some(SessionNote::Stale));
        let (reply, _) = rig.compute().expect("the second one is next");
        assert!(reply.answer.is_some());
    }

    #[test]
    fn p_229_a_pairing_is_abandoned_120_seconds_after_message_1() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let (pending, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (_, answer) = rig.exchange(&frame);
        let proceeding = proceeds(pending, &answer);
        rig.at(120_000);
        let _ = rig.sessions.tick(rig.now);
        let mut dst = [0u8; MAX_FRAME];
        let header = phone.header(MessageType::Enrol);
        let (_, len) = proceeding
            .finish(&client_key(1), header, &mut dst)
            .expect("message 3");
        let (_, answer) = rig.send(&dst[..len]);
        assert_eq!(bare_code(&answer), ErrorCode::AuthenticationFailed as u16);
        assert_eq!(rig.sessions.keys.clients.enrolled(Epoch::FIRST), 0);
    }

    #[test]
    fn p_229_a_result_for_a_connection_that_dropped_is_discarded() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let _ = rig.send(&frame);
        let job = rig.sessions.next_job().expect("queued");
        assert_eq!(rig.sessions.release(conn(1)), ClientDisconnected::Released);
        let done = rig.agreement.run(job);
        let facts = rig.facts();
        let mut dst = [0u8; MAX_FRAME];
        let reply =
            block_on(
                rig.sessions
                    .completed(done, rig.now, &facts, &mut rig.part, &mut dst),
            );
        assert_eq!(reply.note, Some(SessionNote::Stale));
        assert!(!rig.sessions.is_computing(), "the worker is free again");
    }

    #[test]
    fn p_240_the_same_key_pairing_again_takes_its_own_slot_back_under_a_new_generation() {
        let mut rig = Rig::new();
        let _first = enrolled_phone(&mut rig, 1, "phone", 1);
        let _other = enrolled_phone(&mut rig, 2, "tablet", 2);
        rig.connect(3);
        let mut again = Phone::on(3);
        let answer = again
            .pair(&mut rig, "renamed", ClientKind::App, client_key(1))
            .expect("proceeds");
        assert_eq!(
            answer.outcome,
            Outcome::Reclaimed(
                ClientId::new(1).expect("a slot"),
                Generation::new(2).expect("nonzero")
            )
        );
        assert_eq!(rig.sessions.keys.clients.enrolled(Epoch::FIRST), 2);
    }

    #[test]
    fn p_240_a_reclaim_by_label_revokes_the_old_install_and_unbinds_it() {
        let mut rig = Rig::new();
        let _owner = enrolled_phone(&mut rig, 3, "owner", 9);
        let mut old = enrolled_phone(&mut rig, 1, "phone", 1);
        old.hello(&mut rig).expect("a session");
        // Five more admins, so the same label is reclaimed: slot 8 is free,
        // and past the admin ceiling (P-258).
        for n in 3..=7u8 {
            let id = ClientId::new(u32::from(n)).expect("a slot");
            let enrolment = Enrolment {
                client: client_key(n).public(),
                admit: [n; 32],
                suite: SUITE,
                role: Role::Admin,
                kind: ClientKind::App,
                label: ClientLabel::new("other").expect("short"),
            };
            block_on(
                rig.sessions
                    .keys
                    .clients
                    .enrol(id, enrolment, Epoch::FIRST, &mut rig.part),
            )
            .expect("lands");
        }
        rig.connect(2);
        let mut new = Phone::on(2);
        let answer = new
            .pair(&mut rig, "phone", ClientKind::App, client_key(30))
            .expect("proceeds");
        let slot = ClientId::new(2).expect("a slot");
        assert!(matches!(answer.outcome, Outcome::Reclaimed(id, _) if id == slot));
        assert_eq!(
            rig.sessions
                .keys
                .clients
                .occupant(slot, Epoch::FIRST)
                .map(Occupant::role),
            Some(Role::Admin)
        );
        assert!(
            !rig.sessions.is_bound(conn(1)),
            "the old session went first"
        );
        old.challenged(&mut rig);
        let refused = old.hello(&mut rig).expect_err("refused");
        assert_eq!(bare_code(&refused), ErrorCode::UnknownClient as u16);
    }

    #[test]
    fn p_064_a_slot_that_does_not_land_is_not_stored_and_the_window_stays_open() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let (pending, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (_, answer) = rig.exchange(&frame);
        let proceeding = proceeds(pending, &answer);
        let mut dst = [0u8; MAX_FRAME];
        let header = phone.header(MessageType::Enrol);
        let (enrol, len) = proceeding
            .finish(&client_key(1), header, &mut dst)
            .expect("message 3");
        rig.part.table_refused = true;
        let (reply, answer) = rig.exchange(&dst[..len]);
        rig.part.table_refused = false;
        assert_eq!(reply.note, Some(SessionNote::TableNotStored));
        let answer = read_enrol(enrol, &answer);
        assert_eq!(answer.outcome, Outcome::NotStored);
        assert_eq!(rig.sessions.keys.clients.enrolled(Epoch::FIRST), 0);
        // Not `Paired`: the adapter leaves the window open, and the client
        // pairs again from the challenge the answer carried.
        phone.challenge = Some(answer.next_challenge);
        let (_, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
    }

    #[test]
    fn p_238_a_hello_whose_tag_matches_no_slot_is_12_counted_and_queues_nothing() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut stranger = Phone::on(1);
        stranger.challenged(&mut rig);
        stranger.enrolment = Some(km43::Enrolment::new(
            DeviceId::new(DEVICE),
            proceeding_controller(),
            client_key(9),
            SUITE,
            Epoch::FIRST,
        ));
        let (_, frame) = stranger.hello_frame();
        let (reply, answer) = rig.send(&frame);
        assert_eq!(bare_code(&answer), ErrorCode::UnknownClient as u16);
        assert_eq!(reply.note, Some(SessionNote::Refused(0x0c)));
        assert!(rig.sessions.next_job().is_none(), "no DH for a stranger");
        let row = rig.sessions.row(conn(1)).expect("a row");
        assert_eq!(row.failures.iter().flatten().count(), 1);
    }

    #[test]
    fn p_242_an_enrol_answer_the_relay_dropped_still_leaves_a_hello_that_names_the_slot() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let (pending, frame) = phone.pair_frame(&label(), "phone", ClientKind::App);
        let (_, answer) = rig.exchange(&frame);
        let proceeding = proceeds(pending, &answer);
        let mut dst = [0u8; MAX_FRAME];
        let header = phone.header(MessageType::Enrol);
        let key = client_key(4);
        let (_, len) = proceeding
            .finish(&key, header, &mut dst)
            .expect("message 3");
        phone.enrolment = Some(km43::Enrolment::new(
            DeviceId::new(DEVICE),
            proceeding_controller(),
            key,
            SUITE,
            Epoch::FIRST,
        ));
        let _dropped = rig.exchange(&dst[..len]);
        phone.challenged(&mut rig);
        let report = phone.hello(&mut rig).expect("the slot was written");
        assert_eq!(report.client_id, ClientId::new(1).expect("a slot"));
    }

    #[test]
    fn p_239_a_hello_computed_while_its_slot_was_re_keyed_binds_nothing() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        let (_, frame) = phone.hello_frame();
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        // Another install takes the slot while the `Hello` waits its turn.
        let enrolment = Enrolment {
            client: client_key(2).public(),
            admit: [2; 32],
            suite: SUITE,
            role: Role::Admin,
            kind: ClientKind::App,
            label: ClientLabel::new("phone").expect("short"),
        };
        let slot = ClientId::new(1).expect("a slot");
        block_on(
            rig.sessions
                .keys
                .clients
                .enrol(slot, enrolment, Epoch::FIRST, &mut rig.part),
        )
        .expect("lands");
        let (_, answer) = rig.compute().expect("computed");
        assert_eq!(bare_code(&answer), ErrorCode::UnknownClient as u16);
        assert!(!rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_243_one_key_agreement_at_a_time_and_connections_take_turns() {
        let mut rig = Rig::new();
        let mut phones = [
            enrolled_phone(&mut rig, 1, "one", 1),
            enrolled_phone(&mut rig, 2, "two", 2),
            enrolled_phone(&mut rig, 3, "three", 3),
        ];
        for phone in &mut phones {
            let (_, frame) = phone.hello_frame();
            let (reply, answer) = rig.send(&frame);
            assert_eq!(answer.len, 0, "nothing is computed where the frame arrived");
            assert_eq!(reply.note, Some(SessionNote::Queued(conn(phone.handle))));
        }
        let first = rig.sessions.next_job().expect("one is handed out");
        assert!(rig.sessions.next_job().is_none(), "never two at once");
        let served = first.ticket().conn;
        let done = rig.agreement.run(first);
        let facts = rig.facts();
        let mut dst = [0u8; MAX_FRAME];
        let _ = block_on(
            rig.sessions
                .completed(done, rig.now, &facts, &mut rig.part, &mut dst),
        );
        let second = rig.sessions.next_job().expect("the next one").ticket().conn;
        assert_ne!(second, served);
    }

    const NONCE: km43::VouchNonce = km43::VouchNonce::new([0xB0; 16]);
    const BINDING: km43::AccountBinding = km43::AccountBinding::new([0xD0; 32]);

    fn verifier() -> StaticKey {
        let mut bytes = [0xA5; 32];
        bytes[31] = 0x42;
        StaticKey::generate(Entropy::new(bytes))
    }

    /// `Vouch 0x14`'s body for `verifier`, the nonce and the binding.
    fn vouch_body(verifier: PublicKey) -> ([u8; 96], usize) {
        let mut body = [0u8; 96];
        let len = km43::VouchRequest {
            verifier,
            nonce: NONCE,
            binding: BINDING,
        }
        .encode(&mut body)
        .expect("fits");
        (body, len)
    }

    /// A `Vouch` for [`verifier`] on the phone's session.
    fn vouch_frame(phone: &mut Phone) -> Frame {
        let (body, len) = vouch_body(verifier().public());
        phone.sealed(MessageType::Vouch, &body[..len])
    }

    /// `Vouch 0x94`, opened under the phone's session.
    fn vouch_answer(phone: &mut Phone, answer: &[u8]) -> km43::VouchAnswer {
        let (kind, body) = phone.open(answer);
        assert_eq!(kind, MessageType::VouchResponse);
        km43::VouchAnswer::decode(&body).expect("a vouch body")
    }

    /// The code key 1 of a sealed `Error 0xFF` carries.
    fn sealed_code(phone: &mut Phone, answer: &[u8]) -> u8 {
        let (kind, payload) = phone.open(answer);
        assert_eq!(kind, MessageType::ErrorResponse);
        assert_eq!(payload.get(1), Some(&0x01), "key 1 first");
        *payload.get(2).expect("a code under 24")
    }

    #[test]
    fn p_244_p_243_a_vouch_is_computed_by_the_worker_and_verifies_for_the_verifier() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        let report = phone.hello(&mut rig).expect("a session");
        // P-246 is retired in km43 0.8.0: bit 9 announces nothing.
        assert_eq!(report.capabilities & (1 << 9), 0);
        let frame = vouch_frame(&mut phone);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        assert_eq!(answer.len, 0, "no DH where the frame arrived");
        let (reply, answer) = rig.compute().expect("the vouch was queued");
        assert!(reply.answer.is_some());
        let km43::VouchAnswer::Vouched {
            epoch,
            client_id,
            generation,
            tag,
        } = vouch_answer(&mut phone, &answer)
        else {
            panic!("refused a contributory verifier key");
        };
        assert_eq!(epoch, Epoch::FIRST);
        assert_eq!(
            (client_id, generation),
            (report.client_id, report.generation)
        );
        let issued = km43::VouchIssue {
            device_id: DeviceId::new(DEVICE),
            epoch: Epoch::FIRST,
            nonce: NONCE,
            binding: BINDING,
        };
        let claim = km43::VouchClaim {
            controller: proceeding_controller(),
            client_id,
            generation,
            tag,
        };
        let vouched = issued
            .verify(&verifier(), Some(&fingerprint()), &claim)
            .expect("the verifier accepts it");
        assert_eq!(vouched.statement().client_id, report.client_id);
        // Another account's binding does not verify under the same tag.
        let other = km43::VouchIssue {
            binding: km43::AccountBinding::new([0xD1; 32]),
            ..issued
        };
        assert_eq!(
            other
                .verify(&verifier(), Some(&fingerprint()), &claim)
                .err(),
            Some(km43::VouchRefusal::TagMismatch)
        );
        assert!(rig.sessions.is_bound(conn(1)));
        assert!(!rig.sessions.is_computing());
    }

    #[test]
    fn p_245_a_low_order_verifier_key_is_answered_bad_verifier_under_the_session() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let (body, len) = vouch_body(PublicKey::from_bytes([0; 32]));
        let frame = phone.sealed(MessageType::Vouch, &body[..len]);
        let (reply, _) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let (_, answer) = rig.compute().expect("queued");
        assert!(matches!(
            vouch_answer(&mut phone, &answer),
            km43::VouchAnswer::BadVerifier
        ));
        assert!(rig.sessions.is_bound(conn(1)), "a refusal ends nothing");
    }

    #[test]
    fn p_244_a_vouch_body_that_does_not_read_is_sealed_1_and_queues_nothing() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let frame = phone.sealed(MessageType::Vouch, &[0xa0]);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Refused(1)));
        assert_eq!(sealed_code(&mut phone, &answer), 1);
        assert!(rig.sessions.next_job().is_none());
        assert!(rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_243_a_second_vouch_on_a_row_whose_job_is_taken_is_sealed_7_and_evicts_nothing() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let first = vouch_frame(&mut phone);
        let (reply, _) = rig.send(&first);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let second = vouch_frame(&mut phone);
        let (reply, answer) = rig.send(&second);
        assert_eq!(reply.note, Some(SessionNote::Refused(7)));
        assert_eq!(sealed_code(&mut phone, &answer), 7);
        let (_, answer) = rig.compute().expect("the first is still queued");
        assert!(matches!(
            vouch_answer(&mut phone, &answer),
            km43::VouchAnswer::Vouched { .. }
        ));
        // Out at the worker counts too.
        let (reply, _) = rig.send(&vouch_frame(&mut phone));
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let job = rig.sessions.next_job().expect("handed out");
        let (reply, _) = rig.send(&vouch_frame(&mut phone));
        assert_eq!(reply.note, Some(SessionNote::Refused(7)));
        assert_eq!(job.ticket().conn, conn(1));
    }

    #[test]
    fn p_243_a_vouch_takes_its_turn_with_the_handshakes_of_other_connections() {
        let mut rig = Rig::new();
        let mut vouching = enrolled_phone(&mut rig, 1, "one", 1);
        vouching.hello(&mut rig).expect("a session");
        let mut greeting = enrolled_phone(&mut rig, 2, "two", 2);
        let (reply, _) = rig.send(&vouch_frame(&mut vouching));
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let (_, hello) = greeting.hello_frame();
        let (reply, _) = rig.send(&hello);
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(2))));
        let first = rig.sessions.next_job().expect("one is handed out");
        assert!(rig.sessions.next_job().is_none(), "never two at once");
        let served = first.ticket().conn;
        let done = rig.agreement.run(first);
        let facts = rig.facts();
        let mut dst = [0u8; MAX_FRAME];
        let _ = block_on(
            rig.sessions
                .completed(done, rig.now, &facts, &mut rig.part, &mut dst),
        );
        let second = rig.sessions.next_job().expect("the other one");
        assert_ne!(second.ticket().conn, served);
        assert!([conn(1), conn(2)].contains(&served));
    }

    #[test]
    fn p_244_a_vouch_whose_session_ended_while_it_computed_is_sent_to_nobody() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let (reply, _) = rig.send(&vouch_frame(&mut phone));
        assert_eq!(reply.note, Some(SessionNote::Queued(conn(1))));
        let job = rig.sessions.next_job().expect("out at the worker");
        let goodbye = phone.sealed(MessageType::Goodbye, &[0xa0]);
        let (reply, _) = rig.send(&goodbye);
        assert_eq!(reply.note, Some(SessionNote::Unbound(conn(1))));
        let done = rig.agreement.run(job);
        let facts = rig.facts();
        let mut dst = [0u8; MAX_FRAME];
        let reply =
            block_on(
                rig.sessions
                    .completed(done, rig.now, &facts, &mut rig.part, &mut dst),
            );
        assert_eq!(reply.answer, None);
        assert_eq!(reply.note, Some(SessionNote::Stale));
        assert!(!rig.sessions.is_computing(), "the worker is free again");
    }

    #[test]
    fn p_076_a_hello_binds_and_a_sealed_goodbye_ends_the_session_and_keeps_the_row() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let frame = phone.sealed(MessageType::Goodbye, &[0xa0]);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Unbound(conn(1))));
        let (kind, _) = phone.open(&answer);
        assert_eq!(kind, MessageType::GoodbyeResponse);
        assert!(!rig.sessions.is_bound(conn(1)));
        assert_eq!(rig.sessions.allocated(), 1);
    }

    #[test]
    fn p_022_p_077_a_replayed_request_is_dropped_unanswered_uncounted_and_refreshes_nothing() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let frame = phone.sealed(MessageType::WifiStatus, &[0xa0]);
        let (reply, _) = rig.send(&frame);
        assert!(reply.answer.is_some());
        rig.at(60_000);
        let (reply, answer) = rig.send(&frame);
        assert_eq!(reply.note, Some(SessionNote::Dropped));
        assert_eq!(answer.len, 0);
        let row = rig.sessions.row(conn(1)).expect("a row");
        assert_eq!(row.failures.iter().flatten().count(), 0);
        let Bound::Session(binding) = &row.bound else {
            panic!("still bound");
        };
        assert_eq!(binding.heard, Tick::ZERO, "the replay refreshed nothing");
    }

    #[test]
    fn p_051_a_tag_that_fails_is_bare_10_counted_and_eight_shed_the_connection() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let mut last = Reply::NOTHING;
        for _ in 0..FAILURES {
            let mut frame = phone.sealed(MessageType::WifiStatus, &[0xa0]);
            let tail = frame.len - 1;
            frame.buf[tail] ^= 1;
            let (reply, answer) = rig.send(&frame);
            assert_eq!(bare_code(&answer), ErrorCode::AuthenticationFailed as u16);
            last = reply;
        }
        assert_eq!(
            last.close,
            Some(Close {
                conn: conn(1),
                reason: CloseReason::AuthenticationFailures,
            })
        );
        assert!(!rig.sessions.is_bound(conn(1)));
    }

    #[test]
    fn p_143_a_session_request_before_any_hello_is_4_and_after_one_ended_is_9() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        let mut dst = [0u8; 64];
        let len = phone
            .header(MessageType::WifiStatus)
            .write(0, &mut dst)
            .expect("fits")
            .finish()
            .expect("fits");
        let (_, answer) = rig.send(&dst[..len]);
        assert_eq!(bare_code(&answer), ErrorCode::HelloRequiredFirst as u16);
        phone.hello(&mut rig).expect("a session");
        let frame = phone.sealed(MessageType::Goodbye, &[0xa0]);
        let _ = rig.send(&frame);
        let frame = phone.sealed(MessageType::WifiStatus, &[0xa0]);
        let (_, answer) = rig.send(&frame);
        assert_eq!(bare_code(&answer), ErrorCode::SessionExpired as u16);
    }

    #[test]
    fn p_080_a_permitted_command_is_answered_rejected_sealed_and_remembers_nothing() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let mut op = [0u8; 64];
        let len = CommandOperation {
            cmd_id: 7,
            kind: CommandKind::StartGenerator,
            args: &[0xa0],
        }
        .encode(&mut op)
        .expect("fits");
        let frame = phone.signed(MessageType::Command, &op[..len]);
        let (_, answer) = rig.send(&frame);
        let (kind, body) = phone.open(&answer);
        assert_eq!(kind, MessageType::CommandResponse);
        let ack = CommandAck::decode(&body).expect("an ack");
        assert_eq!(ack.outcome, km43::Command::Rejected);
        assert_eq!(ack.detail, UNSPECIFIED);
        let dedup = rig
            .sessions
            .keys
            .clients
            .commands()
            .present()
            .expect("held");
        assert!(!dedup.dedup().holds(ClientId::new(1).expect("a slot")));
    }

    /// A `SetConfig` of the network section with a body no section takes:
    /// the ack's outcome, or `None` for the sealed error the section
    /// answers once the mask has let it through.
    fn network_write(rig: &mut Rig, phone: &mut Phone) -> Option<km43::SetConfig> {
        let mut operation = [0u8; 64];
        let len = km43::SetConfigOperation {
            section: km43::ConfigSection::Network,
            expected_version: 0,
            body: &[0xa0],
        }
        .encode(&mut operation)
        .expect("fits");
        let frame = phone.signed(MessageType::SetConfig, &operation[..len]);
        let (_, answer) = rig.send(&frame);
        let (kind, body) = phone.open(&answer);
        (kind == MessageType::SetConfigResponse)
            .then(|| km43::SetConfigAck::decode(&body).expect("ack").outcome)
    }

    /// The role slot `n` holds now.
    fn role_of(rig: &Rig, n: u32) -> Option<Role> {
        rig.sessions
            .keys
            .clients
            .occupant(ClientId::new(n).expect("a slot"), Epoch::FIRST)
            .map(Occupant::role)
    }

    /// Slot `n` written straight to the table with `role`, as nothing but a
    /// test writes it.
    fn seat(rig: &mut Rig, n: u8, role: Role, label: &str) {
        let enrolment = Enrolment {
            client: client_key(n).public(),
            admit: [n; 32],
            suite: SUITE,
            role,
            kind: ClientKind::App,
            label: ClientLabel::new(label).expect("short"),
        };
        let id = ClientId::new(u32::from(n)).expect("a slot");
        block_on(
            rig.sessions
                .keys
                .clients
                .enrol(id, enrolment, Epoch::FIRST, &mut rig.part),
        )
        .expect("lands");
    }

    #[test]
    fn p_105_p_250_a_cloud_kind_paired_first_is_the_owner_and_may_write_the_network() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut relay = Phone::on(1);
        relay
            .pair(&mut rig, "relay", ClientKind::Cloud, client_key(1))
            .expect("proceeds");
        // The kind decides nothing: the first pairing at the panel is the
        // owner, whatever it said it was.
        assert_eq!(role_of(&rig, 1), Some(Role::Owner));
        relay.hello(&mut rig).expect("a session");
        assert_eq!(network_write(&mut rig, &mut relay), None);
    }

    #[test]
    fn p_105_p_250_a_later_label_pairing_is_an_admin_refused_a_network_write_sealed() {
        let mut rig = Rig::new();
        let _owner = enrolled_phone(&mut rig, 1, "owner", 1);
        let mut phone = enrolled_phone(&mut rig, 2, "phone", 2);
        assert_eq!(role_of(&rig, 2), Some(Role::Admin));
        phone.hello(&mut rig).expect("a session");
        assert_eq!(
            network_write(&mut rig, &mut phone),
            Some(km43::SetConfig::Unauthorised)
        );
    }

    #[test]
    fn p_240_p_250_the_same_key_pairing_again_keeps_the_owner_role() {
        let mut rig = Rig::new();
        let _owner = enrolled_phone(&mut rig, 1, "owner", 1);
        let _admin = enrolled_phone(&mut rig, 2, "admin", 2);
        rig.connect(3);
        let mut again = Phone::on(3);
        let answer = again
            .pair(&mut rig, "renamed", ClientKind::App, client_key(1))
            .expect("proceeds");
        assert!(matches!(answer.outcome, Outcome::Reclaimed(..)));
        // An owner exists, and it is this one: still the owner.
        assert_eq!(role_of(&rig, 1), Some(Role::Owner));
        assert_eq!(role_of(&rig, 2), Some(Role::Admin));
    }

    #[test]
    fn p_258_the_sixth_admin_is_enrolled_and_a_seventh_refused_table_full_at_message_1() {
        let mut rig = Rig::new();
        seat(&mut rig, 1, Role::Owner, "owner");
        for n in 2..=6 {
            seat(&mut rig, n, Role::Admin, "admin");
        }
        // Five admins: the sixth takes slot 7.
        rig.connect(1);
        let mut sixth = Phone::on(1);
        let answer = sixth
            .pair(&mut rig, "sixth", ClientKind::App, client_key(20))
            .expect("proceeds");
        let slot = ClientId::new(7).expect("a slot");
        assert_eq!(answer.outcome, Outcome::Enrolled(slot, Generation::FIRST));
        assert_eq!(role_of(&rig, 7), Some(Role::Admin));
        // Six: slot 8 is free and no admin may take it. Refused under the
        // refusal key before any DH (P-241).
        rig.connect(2);
        let mut seventh = Phone::on(2);
        let refused = seventh
            .pair(&mut rig, "seventh", ClientKind::App, client_key(21))
            .err();
        assert_eq!(refused, Some(PairRefusal::TableFull));
        assert!(rig.sessions.next_job().is_none(), "no DH was queued");
        assert_eq!(role_of(&rig, 8), None);
    }

    #[test]
    fn p_250_the_role_is_decided_again_at_message_3() {
        let mut rig = Rig::new();
        // Two phones pass message 1 against an empty table, each as its
        // owner.
        rig.connect(1);
        let mut late = Phone::on(1);
        late.challenged(&mut rig);
        let (pending, frame) = late.pair_frame(&label(), "late", ClientKind::App);
        let (_, answer) = rig.exchange(&frame);
        let proceeding = proceeds(pending, &answer);
        rig.connect(2);
        let mut first = Phone::on(2);
        first
            .pair(&mut rig, "first", ClientKind::App, client_key(2))
            .expect("proceeds");
        assert_eq!(role_of(&rig, 1), Some(Role::Owner));
        // The late one finishes after an owner exists: an admin.
        let mut dst = [0u8; MAX_FRAME];
        let header = late.header(MessageType::Enrol);
        let (enrol, len) = proceeding
            .finish(&client_key(1), header, &mut dst)
            .expect("message 3");
        let (_, answer) = rig.exchange(&dst[..len]);
        let answer = read_enrol(enrol, &answer);
        let slot = ClientId::new(2).expect("a slot");
        assert_eq!(answer.outcome, Outcome::Enrolled(slot, Generation::FIRST));
        assert_eq!(role_of(&rig, 2), Some(Role::Admin));
    }

    /// A sealed read, and the code of the sealed error it was answered
    /// with, if it was one.
    fn read_refused(
        rig: &mut Rig,
        phone: &mut Phone,
        kind: MessageType,
        inner: &[u8],
    ) -> Option<Incoming> {
        let frame = phone.sealed(kind, inner);
        let (_, answer) = rig.send(&frame);
        let (answered, body) = phone.open(&answer);
        (answered == MessageType::ErrorResponse)
            .then(|| ErrorBody::authenticated(&body).expect("an error body").code)
    }

    fn get_config(section: km43::ConfigSection) -> ([u8; 16], usize) {
        let mut inner = [0u8; 16];
        let len = km43::GetConfigRequest { section }
            .encode(&mut inner)
            .expect("fits");
        (inner, len)
    }

    #[test]
    fn p_105_p_251_a_viewer_is_sealed_error_20_for_the_network_section_and_the_scan_list() {
        let mut rig = Rig::new();
        let _owner = enrolled_phone(&mut rig, 1, "owner", 1);
        let mut relay = enrolled_phone(&mut rig, 2, "relay", 2);
        // Written again as the viewer an owner's invite would make it.
        let slot = ClientId::new(2).expect("a slot");
        let mut enrolment = rig
            .sessions
            .keys
            .clients
            .occupant(slot, Epoch::FIRST)
            .expect("occupied")
            .enrolment();
        enrolment.role = Role::Viewer;
        block_on(
            rig.sessions
                .keys
                .clients
                .enrol(slot, enrolment, Epoch::FIRST, &mut rig.part),
        )
        .expect("lands");
        relay.challenged(&mut rig);
        relay.hello(&mut rig).expect("a session");
        let refused = Some(Incoming::Client(ErrorCode::RoleNotPermitted));
        for section in [km43::ConfigSection::Network, km43::ConfigSection::Cloud] {
            let (inner, len) = get_config(section);
            assert_eq!(
                read_refused(&mut rig, &mut relay, MessageType::GetConfig, &inner[..len]),
                refused,
                "{section:?}"
            );
        }
        let mut scan = [0u8; 8];
        let len = km43::ScanRequest { refresh: false }
            .encode(&mut scan)
            .expect("fits");
        assert_eq!(
            read_refused(&mut rig, &mut relay, MessageType::WifiScan, &scan[..len]),
            refused
        );
        // What is not private is still read.
        let (inner, len) = get_config(km43::ConfigSection::IdentityAndSite);
        assert_ne!(
            read_refused(&mut rig, &mut relay, MessageType::GetConfig, &inner[..len]),
            refused
        );
    }

    #[test]
    fn p_105_p_251_an_admin_reads_the_network_section_and_the_scan_list() {
        let mut rig = Rig::new();
        let _owner = enrolled_phone(&mut rig, 1, "owner", 1);
        let mut admin = enrolled_phone(&mut rig, 2, "admin", 2);
        admin.hello(&mut rig).expect("a session");
        let (inner, len) = get_config(km43::ConfigSection::Network);
        assert_eq!(
            read_refused(&mut rig, &mut admin, MessageType::GetConfig, &inner[..len]),
            None
        );
        let mut scan = [0u8; 8];
        let len = km43::ScanRequest { refresh: false }
            .encode(&mut scan)
            .expect("fits");
        assert_eq!(
            read_refused(&mut rig, &mut admin, MessageType::WifiScan, &scan[..len]),
            None
        );
    }

    #[test]
    fn p_110_a_client_time_is_handed_to_the_recorder_and_answered_sealed() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        let mut op = [0u8; 32];
        let len = km43::TimeOperation {
            at: 1_700_000_000_000,
        }
        .encode(&mut op)
        .expect("fits");
        let frame = phone.signed(MessageType::Time, &op[..len]);
        let (reply, _) = rig.send(&frame);
        let Some(SessionNote::TimeAsked(asked)) = reply.note else {
            panic!("handed to the recorder");
        };
        assert!(asked.authorised);
        let mut dst = [0u8; MAX_FRAME];
        let reply = rig
            .sessions
            .time_answered(asked.ticket, TimeAnswer::Busy, &mut dst);
        let (kind, _) = phone.open(&dst[..reply.answer.expect("answered")]);
        assert_eq!(kind, MessageType::ErrorResponse);
    }

    #[test]
    fn p_085_p_229_a_factory_reset_unbinds_abandons_and_leaves_every_slot_free() {
        let mut rig = Rig::new();
        let mut phone = enrolled_phone(&mut rig, 1, "phone", 1);
        phone.hello(&mut rig).expect("a session");
        rig.connect(2);
        let mut pairing = Phone::on(2);
        pairing.challenged(&mut rig);
        let (_, frame) = pairing.pair_frame(&label(), "tablet", ClientKind::App);
        let _ = rig.send(&frame);
        block_on(rig.sessions.factory_reset(&mut rig.part)).expect("resets");
        assert!(!rig.sessions.is_bound(conn(1)));
        assert!(
            rig.sessions.next_job().is_none(),
            "the handshake was abandoned"
        );
        let epoch = rig.sessions.keys.epoch.expect("advanced");
        assert_eq!(epoch.get(), 2);
        assert_eq!(rig.sessions.keys.clients.enrolled(epoch), 0);
        phone.challenged(&mut rig);
        let refused = phone.hello(&mut rig).expect_err("refused");
        assert_eq!(bare_code(&refused), ErrorCode::UnknownClient as u16);
    }

    #[test]
    fn l_061_a_ninth_connection_is_refused_and_no_row_is_evicted() {
        let mut rig = Rig::new();
        for handle in 1..=8 {
            rig.connect(handle);
        }
        assert_eq!(
            rig.sessions.admit(conn(9)),
            ClientConnected::RefusedTableFull
        );
        assert_eq!(rig.sessions.allocated(), 8);
    }

    #[test]
    fn l_062_a_frame_on_a_handle_never_announced_is_259() {
        let mut rig = Rig::new();
        let mut phone = Phone::on(5);
        let mut dst = [0u8; 64];
        let len = phone
            .header(MessageType::Discover)
            .write(0, &mut dst)
            .expect("fits")
            .finish()
            .expect("fits");
        let (_, answer) = rig.send(&dst[..len]);
        assert_eq!(bare_code(&answer), LinkErrorCode::UnknownHandle as u16);
    }

    #[test]
    fn p_062_a_challenge_is_dead_at_120_seconds_and_discover_draws_another() {
        let mut rig = Rig::new();
        rig.connect(1);
        let mut phone = Phone::on(1);
        phone.challenged(&mut rig);
        let first = phone.challenge;
        rig.at(120_000);
        phone.challenged(&mut rig);
        assert_ne!(phone.challenge, first);
    }
}
