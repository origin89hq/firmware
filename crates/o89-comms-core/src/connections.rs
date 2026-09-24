//! The connection table: eight rows every client transport shares.
//!
//! One table for the comms processor, whatever carries the client:
//! WebSocket now, BLE when #96 lands, each row a transport that exists. A
//! transport asks for a row and is refused when all eight are taken or the
//! link is down (L-120); there is no second allowance per transport. The
//! handle comes from a counter from 1 to 0xFFFF that skips handles in use
//! and never yields 0 (L-060), and a handle stays in use until the
//! controller has answered its release (L-080).
//!
//! A row is announced with `ClientConnected` and released with
//! `ClientDisconnected`, each retried under its own id and given up after
//! three attempts (L-015), at most three in flight so that, with the time
//! offer's one, this side never has more than four (L-014); a row waiting
//! for a request slot goes out when one frees. What the controller answers
//! decides the row: accepted, it carries frames; refused, for a full table
//! or any other reason, it is dropped from the table and its transport is
//! told to close with the reason (L-061). An announcement never answered
//! closes the transport and is released, since the controller may hold the
//! row; a release never answered is sent again under a new id, because the
//! handle cannot be reused until it is answered, and the link falling is
//! what ends it.
//!
//! What the controller closes, one handle or every one (L-090), closes the
//! transports and is counted: the count is how many transports existed. A
//! link that falls or a controller that reboots closes every transport and
//! forgets every row (L-042, L-120). The heartbeat's `conns` is the rows a
//! transport holds, announced or open, bound or not (L-101). After a resync
//! close every transport is gone, and each client that reconnects is
//! announced afresh under a new handle: that is the re-announcement L-102
//! asks for, since this side keeps no connection without its transport.
//!
//! Full, a new transport is refused; nothing is evicted.

use core::fmt::{self, Write as _};

use km43::{
    ClientConnected, CloseConnection, CloseReason, Conn, DisconnectReason, LinkMessageType,
    LinkTransport, MAX_INFLIGHT, MAX_SESSIONS, ReqId,
};
use o89_link::{Overdue, Requests, Tick};

/// Rows in the table, shared by every transport: the controller's own
/// count of connection rows, so a table this side accepts is one the
/// controller can hold.
pub const ROWS: usize = MAX_SESSIONS;

/// Connection requests in flight at once: L-014's four, less the time
/// offer's one. A row due while all three are out waits for one to free.
pub const CLIENT_REQUESTS: usize = MAX_INFLIGHT - 1;

const _: () = assert!(ROWS <= u8::MAX as usize, "`conns` is a u8 on the wire");
const _: () = assert!(CLIENT_REQUESTS >= 1);

/// Where a client says it is, as its transport reports it: shown to a
/// person and decided on by nothing (L-072).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// An IPv4 address and port, for a WebSocket.
    Ipv4 {
        /// The address.
        addr: [u8; 4],
        /// The port.
        port: u16,
    },
}

/// The longest peer text: `255.255.255.255:65535`.
const PEER_TEXT: usize = 21;

/// A peer written out for `ClientConnected` key 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerText {
    bytes: [u8; PEER_TEXT],
    len: usize,
}

impl PeerText {
    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.bytes
            .get(..self.len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

impl fmt::Write for PeerText {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl Peer {
    /// The peer as text. Every address fits, so nothing is cut short.
    #[must_use]
    pub fn text(self) -> PeerText {
        let mut text = PeerText {
            bytes: [0; PEER_TEXT],
            len: 0,
        };
        let written = match self {
            Self::Ipv4 {
                addr: [a, b, c, d],
                port,
            } => write!(text, "{a}.{b}.{c}.{d}:{port}"),
        };
        debug_assert!(written.is_ok(), "every address fits");
        text
    }
}

/// Why a transport may not have a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused transport is one to close"]
pub enum Refused {
    /// The link is down, or the versions disagree: new connections are
    /// refused until the controller answers (L-120, L-050).
    NotLinked,
    /// All eight rows are taken. Nothing is evicted.
    TableFull,
}

/// Why the table wants a transport closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// The controller's rows are full (L-061).
    TableFull,
    /// The controller holds this handle already.
    HandleInUse,
    /// The controller's side of the link is not up.
    ControllerNotLinked,
    /// The announcement went unanswered three times (L-015).
    Unanswered,
    /// The controller closed it (L-090).
    ByController(CloseReason),
    /// This side lost the link, or the controller rebooted (L-120, L-042).
    LinkLost,
    /// The client did not take its frames as fast as the controller sent
    /// them: its queue was full, and the frame was not dropped for it.
    Overrun,
}

/// What a transport reads of its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a row asking for its transport closed is a rule nothing performed"]
pub enum Status {
    /// Announced, not yet answered: the client's frames wait.
    Announcing,
    /// Accepted: frames cross both ways.
    Open,
    /// Close the transport, for this reason, then report it gone.
    Close(Closed),
}

/// A request of the table's, to put on the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a request the table issued and nobody sent is one the controller never hears"]
pub enum Request {
    /// `ClientConnected`.
    Connected {
        /// The request.
        req_id: ReqId,
        /// The handle.
        conn: Conn,
        /// What carries it.
        transport: LinkTransport,
        /// Where the client says it is.
        peer: Peer,
    },
    /// `ClientDisconnected`.
    Disconnected {
        /// The request.
        req_id: ReqId,
        /// The handle.
        conn: Conn,
        /// Why the transport went.
        reason: DisconnectReason,
    },
}

/// A request of a row's: waiting for a slot, or in flight under an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Due,
    Sent(ReqId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A transport exists and its `ClientConnected` is due or in flight.
    Announcing(Pending),
    /// Accepted by the controller.
    Open,
    /// The transport is to close; the row is held until it has. `release`
    /// when the controller may hold the row and must be told.
    Closing { why: Closed, release: bool },
    /// The transport is gone, and the handle is held until the controller
    /// answers its release (L-080).
    Releasing {
        reason: DisconnectReason,
        pending: Pending,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    conn: Conn,
    transport: LinkTransport,
    peer: Peer,
    state: State,
}

impl Row {
    /// A transport exists and the controller may be counting it (L-101).
    const fn allocated(&self) -> bool {
        match self.state {
            State::Announcing(_) | State::Open => true,
            State::Closing { .. } | State::Releasing { .. } => false,
        }
    }
}

/// The table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connections {
    rows: [Option<Row>; ROWS],
    /// The next handle to try (L-060); never 0.
    next: u16,
    requests: Requests<CLIENT_REQUESTS>,
}

/// What a close did: its outcome and how many transports it closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a close nobody reports is one the controller retries"]
pub struct CloseOutcome {
    /// `closed` or `unknown_handle`.
    pub outcome: CloseConnection,
    /// Transports closed (L-090).
    pub closed: u8,
}

impl Default for Connections {
    fn default() -> Self {
        Self::new()
    }
}

impl Connections {
    /// No rows, and the counter at 1.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rows: [None; ROWS],
            next: 1,
            requests: Requests::NONE,
        }
    }

    /// A row for a transport that exists, announced at the next turn.
    /// Refused when every row is taken, including rows still waiting for
    /// the controller to answer their release (L-080).
    pub(crate) fn allocate(
        &mut self,
        transport: LinkTransport,
        peer: Peer,
    ) -> Result<Conn, Refused> {
        let conn = self.take_handle().ok_or(Refused::TableFull)?;
        let free = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(Refused::TableFull)?;
        *free = Some(Row {
            conn,
            transport,
            peer,
            state: State::Announcing(Pending::Due),
        });
        Ok(conn)
    }

    /// The next handle from the counter, skipping every one a row holds
    /// (L-060). With eight rows, nine candidates hold one that is free.
    fn take_handle(&mut self) -> Option<Conn> {
        // Bounded: `ROWS + 1` candidates, of which at most `ROWS` are held.
        for _ in 0..=ROWS {
            let candidate = Conn::new(self.next);
            self.next = self.next.checked_add(1).unwrap_or(1);
            if let Some(conn) = candidate
                && self.find(conn).is_none()
            {
                return Some(conn);
            }
        }
        None
    }

    /// Rows whose transport exists, announced or open, bound or not
    /// (L-101).
    #[must_use]
    pub fn allocated(&self) -> u8 {
        let count = self
            .rows
            .iter()
            .flatten()
            .filter(|row| row.allocated())
            .count();
        u8::try_from(count).unwrap_or(u8::MAX)
    }

    /// What the transport holding `conn` is to do; `None` for a handle
    /// that holds no transport.
    #[must_use]
    pub fn status(&self, conn: Conn) -> Option<Status> {
        match self.find(conn)?.state {
            State::Announcing(_) => Some(Status::Announcing),
            State::Open => Some(Status::Open),
            State::Closing { why, .. } => Some(Status::Close(why)),
            State::Releasing { .. } => None,
        }
    }

    /// Whether `conn` carries frames.
    #[must_use]
    pub fn is_open(&self, conn: Conn) -> bool {
        self.find(conn).is_some_and(|row| row.state == State::Open)
    }

    /// The transport holding `conn` has gone. A row the controller may
    /// hold is released, and its handle held until that is answered; a row
    /// the controller refused or closed is simply freed.
    pub(crate) fn gone(&mut self, conn: Conn, reason: DisconnectReason) {
        let Some(slot) = self
            .rows
            .iter_mut()
            .find(|slot| slot.is_some_and(|row| row.conn == conn))
        else {
            return;
        };
        let Some(row) = slot.as_mut() else {
            return;
        };
        let releasing = State::Releasing {
            reason,
            pending: Pending::Due,
        };
        match row.state {
            State::Announcing(pending) => {
                forget(
                    &mut self.requests,
                    pending,
                    LinkMessageType::ClientConnected,
                );
                row.state = releasing;
            }
            State::Open => row.state = releasing,
            State::Closing { release: true, .. } => {
                row.state = State::Releasing {
                    reason: DisconnectReason::ClosedByComms,
                    pending: Pending::Due,
                };
            }
            State::Closing { release: false, .. } => *slot = None,
            State::Releasing { .. } => {}
        }
    }

    /// The client could not take its frames: its transport is closed, and
    /// the row released once it has.
    pub(crate) fn overrun(&mut self, conn: Conn) {
        if let Some(row) = self.row_mut(conn)
            && row.state == State::Open
        {
            row.state = State::Closing {
                why: Closed::Overrun,
                release: true,
            };
        }
    }

    /// The controller answered an announcement; `false` when `req_id`
    /// answers none in flight.
    pub(crate) fn connected(&mut self, req_id: ReqId, outcome: ClientConnected) -> bool {
        if !self
            .requests
            .answered(req_id, LinkMessageType::ClientConnected)
        {
            return false;
        }
        let Some(row) = self
            .rows
            .iter_mut()
            .flatten()
            .find(|row| row.state == State::Announcing(Pending::Sent(req_id)))
        else {
            return true;
        };
        let refused = match outcome {
            ClientConnected::Accepted => {
                row.state = State::Open;
                return true;
            }
            ClientConnected::RefusedTableFull => Closed::TableFull,
            ClientConnected::RefusedHandleInUse => Closed::HandleInUse,
            ClientConnected::RefusedLinkNotUp => Closed::ControllerNotLinked,
        };
        // Refused: the controller holds no row, so there is nothing to
        // release; the transport closes with the reason (L-061).
        row.state = State::Closing {
            why: refused,
            release: false,
        };
        true
    }

    /// The controller answered a release, `released` or `unknown_handle`:
    /// either way it holds no row, and the handle may be reused (L-080).
    pub(crate) fn disconnected(&mut self, req_id: ReqId) -> bool {
        if !self
            .requests
            .answered(req_id, LinkMessageType::ClientDisconnected)
        {
            return false;
        }
        for slot in &mut self.rows {
            if slot.is_some_and(|row| {
                matches!(
                    row.state,
                    State::Releasing { pending: Pending::Sent(sent), .. } if sent == req_id
                )
            }) {
                *slot = None;
            }
        }
        true
    }

    /// The controller's `CloseConnection`: handle 0 is every connection
    /// (L-090). Every transport it names closes, and is counted; a row
    /// waiting on its release is freed by a close of every one, whose
    /// answer frees every row on the controller's side too.
    pub(crate) fn close(&mut self, conn: u16, reason: CloseReason) -> CloseOutcome {
        let Some(named) = Conn::new(conn) else {
            let mut closed = 0u8;
            for slot in &mut self.rows {
                let Some(row) = slot.as_mut() else {
                    continue;
                };
                match row.state {
                    State::Announcing(pending) => {
                        forget(
                            &mut self.requests,
                            pending,
                            LinkMessageType::ClientConnected,
                        );
                        row.state = by_controller(reason);
                        closed = closed.saturating_add(1);
                    }
                    State::Open => {
                        row.state = by_controller(reason);
                        closed = closed.saturating_add(1);
                    }
                    State::Closing { why, .. } => {
                        row.state = State::Closing {
                            why,
                            release: false,
                        };
                    }
                    State::Releasing { pending, .. } => {
                        forget(
                            &mut self.requests,
                            pending,
                            LinkMessageType::ClientDisconnected,
                        );
                        *slot = None;
                    }
                }
            }
            return CloseOutcome {
                outcome: CloseConnection::Closed,
                closed,
            };
        };
        let unknown = CloseOutcome {
            outcome: CloseConnection::UnknownHandle,
            closed: 0,
        };
        let Some(row) = self.row_mut(named) else {
            return unknown;
        };
        match row.state {
            State::Announcing(pending) => {
                row.state = by_controller(reason);
                forget(
                    &mut self.requests,
                    pending,
                    LinkMessageType::ClientConnected,
                );
            }
            State::Open => row.state = by_controller(reason),
            State::Closing { why, .. } => {
                // Already closing: the controller will hold no row once it
                // has this answer, so there is nothing left to release.
                row.state = State::Closing {
                    why,
                    release: false,
                };
                return unknown;
            }
            State::Releasing { .. } => return unknown,
        }
        CloseOutcome {
            outcome: CloseConnection::Closed,
            closed: 1,
        }
    }

    /// The link fell or the controller rebooted: the controller holds no
    /// row any more, so every transport closes, every release is moot, and
    /// every request in flight is forgotten (L-042, L-120).
    pub(crate) fn drop_all(&mut self) {
        for slot in &mut self.rows {
            let Some(row) = slot.as_mut() else {
                continue;
            };
            match row.state {
                State::Announcing(_) | State::Open => {
                    row.state = State::Closing {
                        why: Closed::LinkLost,
                        release: false,
                    };
                }
                State::Closing { why, .. } => {
                    row.state = State::Closing {
                        why,
                        release: false,
                    };
                }
                State::Releasing { .. } => *slot = None,
            }
        }
        self.requests.forget();
    }

    /// The next request to send at `now`: a retry of one in flight (L-015),
    /// or a row's request once a slot is free (L-014). At most one per
    /// call; `take_req` numbers a new one.
    pub(crate) fn due(
        &mut self,
        now: Tick,
        mut take_req: impl FnMut() -> ReqId,
    ) -> Option<Request> {
        // Bounded: each call moves one request in flight on (`Requests`).
        for _ in 0..CLIENT_REQUESTS {
            let Some(overdue) = self.requests.overdue(now) else {
                break;
            };
            match overdue {
                Overdue::Resend { req_id, .. } => {
                    if let Some(request) = self.request_for(req_id) {
                        return Some(request);
                    }
                }
                Overdue::GivenUp { req_id, .. } => self.given_up(req_id),
            }
        }
        if self.requests.is_full() {
            return None;
        }
        let row = self.rows.iter_mut().flatten().find(|row| {
            matches!(
                row.state,
                State::Announcing(Pending::Due)
                    | State::Releasing {
                        pending: Pending::Due,
                        ..
                    }
            )
        })?;
        let req_id = take_req();
        let (kind, request) = match row.state {
            State::Announcing(_) => {
                row.state = State::Announcing(Pending::Sent(req_id));
                (
                    LinkMessageType::ClientConnected,
                    Request::Connected {
                        req_id,
                        conn: row.conn,
                        transport: row.transport,
                        peer: row.peer,
                    },
                )
            }
            State::Releasing { reason, .. } => {
                row.state = State::Releasing {
                    reason,
                    pending: Pending::Sent(req_id),
                };
                (
                    LinkMessageType::ClientDisconnected,
                    Request::Disconnected {
                        req_id,
                        conn: row.conn,
                        reason,
                    },
                )
            }
            State::Open | State::Closing { .. } => return None,
        };
        let issued = self.requests.issue(kind, req_id, now);
        debug_assert!(issued, "a slot was free");
        Some(request)
    }

    /// The request in flight under `req_id`, to send again.
    fn request_for(&self, req_id: ReqId) -> Option<Request> {
        self.rows.iter().flatten().find_map(|row| match row.state {
            State::Announcing(Pending::Sent(sent)) if sent == req_id => Some(Request::Connected {
                req_id,
                conn: row.conn,
                transport: row.transport,
                peer: row.peer,
            }),
            State::Releasing {
                reason,
                pending: Pending::Sent(sent),
            } if sent == req_id => Some(Request::Disconnected {
                req_id,
                conn: row.conn,
                reason,
            }),
            State::Announcing(_)
            | State::Open
            | State::Closing { .. }
            | State::Releasing { .. } => None,
        })
    }

    /// A request answered three times by silence (L-015). An announcement
    /// closes its transport and is released after, since the controller
    /// may hold the row; a release is due again under a new id, because
    /// the handle stays held until one is answered (L-080).
    fn given_up(&mut self, req_id: ReqId) {
        for row in self.rows.iter_mut().flatten() {
            match row.state {
                State::Announcing(Pending::Sent(sent)) if sent == req_id => {
                    row.state = State::Closing {
                        why: Closed::Unanswered,
                        release: true,
                    };
                }
                State::Releasing {
                    reason,
                    pending: Pending::Sent(sent),
                } if sent == req_id => {
                    row.state = State::Releasing {
                        reason,
                        pending: Pending::Due,
                    };
                }
                State::Announcing(_)
                | State::Open
                | State::Closing { .. }
                | State::Releasing { .. } => {}
            }
        }
    }

    /// The open row whose handle is `session`: where a frame the controller
    /// addressed to that session goes.
    #[must_use]
    pub fn open_row(&self, session: u16) -> Option<Conn> {
        let conn = Conn::new(session)?;
        self.is_open(conn).then_some(conn)
    }

    fn find(&self, conn: Conn) -> Option<&Row> {
        self.rows.iter().flatten().find(|row| row.conn == conn)
    }

    fn row_mut(&mut self, conn: Conn) -> Option<&mut Row> {
        self.rows.iter_mut().flatten().find(|row| row.conn == conn)
    }
}

const fn by_controller(reason: CloseReason) -> State {
    State::Closing {
        why: Closed::ByController(reason),
        release: false,
    }
}

/// Take a row's request out of flight, so its late answer matches nothing.
fn forget(requests: &mut Requests<CLIENT_REQUESTS>, pending: Pending, kind: LinkMessageType) {
    if let Pending::Sent(req_id) = pending {
        let _ = requests.answered(req_id, kind);
    }
}

#[cfg(test)]
mod tests {
    use km43::ClientConnected;

    use super::*;

    const PEER: Peer = Peer::Ipv4 {
        addr: [192, 168, 4, 2],
        port: 50_123,
    };

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    fn conn(handle: u16) -> Conn {
        Conn::new(handle).expect("a handle")
    }

    /// Request ids from 100 up, as a link would number them.
    fn numbering() -> impl FnMut() -> ReqId {
        let mut next: u32 = 100;
        move || {
            next = next.wrapping_add(1);
            ReqId(next)
        }
    }

    fn open(table: &mut Connections) -> Conn {
        let conn = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        let Some(Request::Connected { req_id, .. }) = table.due(at(0), numbering()) else {
            panic!("its announcement is due");
        };
        assert!(table.connected(req_id, ClientConnected::Accepted));
        conn
    }

    /// Release `conn` and have the controller answer it.
    fn release(table: &mut Connections, conn: Conn) {
        table.gone(conn, DisconnectReason::ClosedByClient);
        let Some(Request::Disconnected { req_id, .. }) = table.due(at(0), numbering()) else {
            panic!("its release is due");
        };
        assert!(table.disconnected(req_id));
    }

    #[test]
    fn l_060_handles_count_up_from_one_and_skip_every_one_in_use() {
        let mut table = Connections::new();
        let first = open(&mut table);
        let second = open(&mut table);
        assert_eq!((first.get(), second.get()), (1, 2));
        // The counter on its way round: 0xFFFF, then 1 is held, so 0 is
        // never a candidate and 1 is skipped.
        table.next = 0xFFFF;
        let top = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        let wrapped = table.allocate(LinkTransport::Ble, PEER).expect("a row");
        assert_eq!((top.get(), wrapped.get()), (0xFFFF, 3));
    }

    #[test]
    fn l_060_a_ninth_transport_is_refused_and_no_row_is_evicted() {
        let mut table = Connections::new();
        // Every transport shares the eight rows: a BLE row fills one too.
        for i in 0..ROWS {
            let transport = if i % 2 == 0 {
                LinkTransport::WifiLocal
            } else {
                LinkTransport::Ble
            };
            assert!(table.allocate(transport, PEER).is_ok(), "row {i}");
        }
        assert_eq!(
            table.allocate(LinkTransport::WifiLocal, PEER),
            Err(Refused::TableFull)
        );
        assert_eq!(usize::from(table.allocated()), ROWS);
        for handle in 1..=8 {
            assert_eq!(table.status(conn(handle)), Some(Status::Announcing));
        }
    }

    #[test]
    fn l_080_a_released_handle_is_held_until_the_controller_answers() {
        let mut table = Connections::new();
        let held = open(&mut table);
        table.gone(held, DisconnectReason::ClosedByClient);
        // The transport is gone and not counted, but its handle is in use.
        assert_eq!(table.allocated(), 0);
        assert_eq!(table.status(held), None);
        table.next = held.get();
        let next = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        assert_ne!(next, held, "skipped while its release waits");
        // A release still waiting holds a row: seven more fill the table.
        for _ in 2..ROWS {
            assert!(table.allocate(LinkTransport::WifiLocal, PEER).is_ok());
        }
        assert_eq!(
            table.allocate(LinkTransport::WifiLocal, PEER),
            Err(Refused::TableFull)
        );
    }

    #[test]
    fn l_080_a_handle_is_reused_once_its_release_is_answered() {
        let mut table = Connections::new();
        let first = open(&mut table);
        release(&mut table, first);
        table.next = first.get();
        let again = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        assert_eq!(again, first);
    }

    #[test]
    fn l_080_an_answer_to_no_release_in_flight_frees_nothing() {
        let mut table = Connections::new();
        let held = open(&mut table);
        table.gone(held, DisconnectReason::TransportError);
        assert!(!table.disconnected(ReqId(9)), "never sent");
        let Some(Request::Disconnected { req_id, reason, .. }) = table.due(at(0), numbering())
        else {
            panic!("its release is due");
        };
        assert_eq!(reason, DisconnectReason::TransportError);
        assert!(!table.disconnected(ReqId(req_id.0 + 1)));
        table.next = held.get();
        assert_ne!(
            table.allocate(LinkTransport::WifiLocal, PEER),
            Ok(held),
            "still held"
        );
    }

    #[test]
    fn l_061_an_announcement_refused_for_a_full_table_leaves_the_table_and_closes() {
        for (outcome, why) in [
            (ClientConnected::RefusedTableFull, Closed::TableFull),
            (ClientConnected::RefusedHandleInUse, Closed::HandleInUse),
            (
                ClientConnected::RefusedLinkNotUp,
                Closed::ControllerNotLinked,
            ),
        ] {
            let mut table = Connections::new();
            let refused = table
                .allocate(LinkTransport::WifiLocal, PEER)
                .expect("a row");
            let Some(Request::Connected { req_id, .. }) = table.due(at(0), numbering()) else {
                panic!("its announcement is due");
            };
            assert_eq!(table.allocated(), 1, "counted while announced");
            assert!(table.connected(req_id, outcome));
            assert_eq!(table.status(refused), Some(Status::Close(why)));
            assert_eq!(table.allocated(), 0, "{outcome:?}: dropped from the count");
            // The controller holds no row: nothing to release.
            table.gone(refused, DisconnectReason::ClosedByComms);
            assert_eq!(table.status(refused), None);
            assert_eq!(table.due(at(0), numbering()), None, "{outcome:?}");
            assert!(table.rows.iter().all(Option::is_none), "{outcome:?}");
        }
    }

    #[test]
    fn l_101_conns_counts_rows_with_a_transport_and_nothing_else() {
        let mut table = Connections::new();
        assert_eq!(table.allocated(), 0);
        let open_one = open(&mut table);
        let _announcing = table.allocate(LinkTransport::Ble, PEER).expect("a row");
        let closing = open(&mut table);
        let releasing = open(&mut table);
        assert_eq!(table.allocated(), 4);
        let _ = table.close(closing.get(), CloseReason::SessionExpired);
        table.gone(releasing, DisconnectReason::IdleTimeout);
        assert_eq!(table.allocated(), 2, "announced and open, bound or not");
        assert_eq!(table.status(open_one), Some(Status::Open));
    }

    #[test]
    fn l_090_a_close_of_every_connection_closes_every_transport_and_counts_them() {
        let mut table = Connections::new();
        let a = open(&mut table);
        let b = open(&mut table);
        let announcing = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        let releasing = open(&mut table);
        table.gone(releasing, DisconnectReason::ClosedByClient);
        let done = table.close(0, CloseReason::Resync);
        assert_eq!(
            done,
            CloseOutcome {
                outcome: CloseConnection::Closed,
                closed: 3
            }
        );
        for closed in [a, b, announcing] {
            assert_eq!(
                table.status(closed),
                Some(Status::Close(Closed::ByController(CloseReason::Resync)))
            );
        }
        assert_eq!(table.allocated(), 0);
        // The release waiting on its answer is moot: the controller frees
        // every row with this close's answer.
        assert_eq!(table.due(at(0), numbering()), None);
        for closed in [a, b, announcing] {
            table.gone(closed, DisconnectReason::ClosedByComms);
        }
        assert!(table.rows.iter().all(Option::is_none));
    }

    #[test]
    fn l_090_a_close_of_nothing_reports_closed_with_none() {
        let mut table = Connections::new();
        assert_eq!(
            table.close(0, CloseReason::Resync),
            CloseOutcome {
                outcome: CloseConnection::Closed,
                closed: 0
            }
        );
    }

    #[test]
    fn l_090_a_close_of_one_handle_reports_closed_or_unknown_truthfully() {
        let mut table = Connections::new();
        let a = open(&mut table);
        let b = open(&mut table);
        assert_eq!(
            table.close(b.get(), CloseReason::AuthenticationFailures),
            CloseOutcome {
                outcome: CloseConnection::Closed,
                closed: 1
            }
        );
        assert_eq!(table.status(a), Some(Status::Open), "only the one named");
        // Already closing, never held, and waiting on its release: none of
        // those is a transport this close closed.
        let unknown = CloseOutcome {
            outcome: CloseConnection::UnknownHandle,
            closed: 0,
        };
        assert_eq!(table.close(b.get(), CloseReason::Shedding), unknown);
        assert_eq!(table.close(77, CloseReason::Shedding), unknown);
        table.gone(a, DisconnectReason::ClosedByClient);
        assert_eq!(table.close(a.get(), CloseReason::Shedding), unknown);
    }

    #[test]
    fn l_015_an_unanswered_announcement_closes_its_transport_and_is_released() {
        let mut table = Connections::new();
        let conn = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        let mut ids = numbering();
        let Some(Request::Connected { req_id, .. }) = table.due(at(0), &mut ids) else {
            panic!("its announcement is due");
        };
        assert_eq!(table.due(at(499), &mut ids), None);
        for resent_at in [500, 1_000] {
            assert_eq!(
                table.due(at(resent_at), &mut ids),
                Some(Request::Connected {
                    req_id,
                    conn,
                    transport: LinkTransport::WifiLocal,
                    peer: PEER
                }),
                "under its own id"
            );
        }
        // Given up: the transport closes, and nothing else is due yet.
        assert_eq!(table.due(at(1_500), &mut ids), None);
        assert_eq!(table.status(conn), Some(Status::Close(Closed::Unanswered)));
        // The controller may hold the row, so it is released once closed.
        table.gone(conn, DisconnectReason::ClosedByComms);
        assert!(matches!(
            table.due(at(1_500), &mut ids),
            Some(Request::Disconnected {
                reason: DisconnectReason::ClosedByComms,
                ..
            })
        ));
    }

    #[test]
    fn l_080_an_unanswered_release_goes_again_under_a_new_id_and_keeps_its_handle() {
        let mut table = Connections::new();
        let held = open(&mut table);
        table.gone(held, DisconnectReason::ClosedByClient);
        let mut ids = numbering();
        let Some(Request::Disconnected { req_id: first, .. }) = table.due(at(0), &mut ids) else {
            panic!("its release is due");
        };
        let _ = table.due(at(500), &mut ids);
        let _ = table.due(at(1_000), &mut ids);
        let Some(Request::Disconnected { req_id: again, .. }) = table.due(at(1_500), &mut ids)
        else {
            panic!("released again");
        };
        assert_ne!(again, first);
        assert!(!table.disconnected(first), "the old id answers nothing");
        assert!(table.disconnected(again));
        assert!(table.rows.iter().all(Option::is_none));
    }

    #[test]
    fn l_014_at_most_three_connection_requests_are_in_flight() {
        let mut table = Connections::new();
        for _ in 0..5 {
            let _ = table
                .allocate(LinkTransport::WifiLocal, PEER)
                .expect("a row");
        }
        let mut ids = numbering();
        let Some(Request::Connected { req_id, .. }) = table.due(at(0), &mut ids) else {
            panic!("an announcement");
        };
        let mut sent = 1;
        while table.due(at(0), &mut ids).is_some() {
            sent += 1;
        }
        assert_eq!(sent, CLIENT_REQUESTS);
        // One answered frees a slot for the next row waiting.
        assert!(table.connected(req_id, ClientConnected::Accepted));
        assert!(matches!(
            table.due(at(10), &mut ids),
            Some(Request::Connected { conn, .. }) if conn.get() == 4
        ));
        assert_eq!(table.due(at(10), &mut ids), None);
    }

    #[test]
    fn l_120_link_loss_closes_every_transport_and_forgets_every_request() {
        let mut table = Connections::new();
        let a = open(&mut table);
        let releasing = open(&mut table);
        table.gone(releasing, DisconnectReason::ClosedByClient);
        let announcing = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        let _ = table.due(at(0), numbering());
        table.drop_all();
        for closed in [a, announcing] {
            assert_eq!(table.status(closed), Some(Status::Close(Closed::LinkLost)));
            table.gone(closed, DisconnectReason::ClosedByComms);
        }
        assert_eq!(table.due(at(5_000), numbering()), None, "nothing to retry");
        assert!(table.rows.iter().all(Option::is_none));
    }

    #[test]
    fn an_overrun_client_is_closed_then_released() {
        let mut table = Connections::new();
        let slow = open(&mut table);
        table.overrun(slow);
        assert_eq!(table.status(slow), Some(Status::Close(Closed::Overrun)));
        table.gone(slow, DisconnectReason::ClosedByComms);
        assert!(matches!(
            table.due(at(0), numbering()),
            Some(Request::Disconnected { conn, .. }) if conn == slow
        ));
        // A row not open cannot overrun.
        let announcing = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        table.overrun(announcing);
        assert_eq!(table.status(announcing), Some(Status::Announcing));
    }

    #[test]
    fn a_frame_routes_only_to_an_open_row() {
        let mut table = Connections::new();
        let open_one = open(&mut table);
        let announcing = table
            .allocate(LinkTransport::WifiLocal, PEER)
            .expect("a row");
        assert_eq!(table.open_row(open_one.get()), Some(open_one));
        assert_eq!(table.open_row(announcing.get()), None);
        assert_eq!(table.open_row(0), None);
        assert_eq!(table.open_row(99), None);
    }

    #[test]
    fn a_peer_is_written_whole() {
        let widest = Peer::Ipv4 {
            addr: [255; 4],
            port: u16::MAX,
        };
        assert_eq!(widest.text().as_str(), "255.255.255.255:65535");
        assert_eq!(PEER.text().as_str(), "192.168.4.2:50123");
    }
}
