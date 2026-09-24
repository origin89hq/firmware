//! WebSocket clients: one TCP connection per client, one protocol message
//! per binary frame (P-034), each connection a row of the link's table.
//!
//! A worker listens on port 80, takes the opening handshake, and asks the
//! link for a row. Refused, because the link is down or every row is
//! taken, it closes with the reason (L-120, L-060). Given one, it waits for
//! the controller's answer to the announcement, then carries frames both
//! ways: a client's frame is stamped with its handle and forwarded, or
//! refused on its connection, by `o89-comms-core` ([`Link::from_client`]);
//! a frame the controller addresses to the handle arrives in the worker's
//! mailbox and goes out as one binary frame. What the table asks, a close
//! for a reason, closes the connection with that reason (L-061, L-090).
//! When the connection ends for any reason, including the worker being
//! dropped with its network, the row is released.
//!
//! Every buffer is fixed. A worker holds its socket's two buffers and one
//! envelope in each direction; a mailbox holds two frames. A mailbox that
//! is full when the controller sends a third closes that client rather than
//! drop a frame or evict one (`Closed::Overrun`). With one worker per row,
//! a ninth client finds no listening socket and is reset by the stack; a
//! row taken by another transport refuses a worker's client with a close.
//!
//! Waits: a listening worker waits for a client with no deadline, holding
//! no row and no lock. Once connected, the read half waits for the client
//! with no deadline of its own; the write half turns every 100 ms, reads
//! the table and ends the connection when it says so, and the socket's
//! timeout and keep-alive end one whose peer vanished. Every write has a
//! deadline.

use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_futures::join::join_array;
use embassy_futures::select::{Either, select};
use embassy_net::tcp::{TcpReader, TcpSocket, TcpWriter};
use embassy_net::{IpAddress, IpEndpoint, Stack};
use embassy_sync::blocking_mutex::Mutex as Blocking;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::{Read, Write};
use km43::{Conn, DisconnectReason, LinkTransport, MAX_PAYLOAD};
use o89_comms_core::{
    CONTROL_PAYLOAD, Closed, Goodbye, HEAD_BYTES, Inbound, Incoming, Link, Outgoing, Peer,
    REQUEST_BYTES, RESPONSE_BYTES, Status, accept, close_payload, head_len, read_head, request_end,
    unmask, write_head,
};

use crate::link::LINK;

/// The port a client connects to, KM43's (P-223).
const PORT: u16 = km43::WS_PORT;
/// Workers on the station's network: one per row.
pub const STATION_WORKERS: usize = o89_comms_core::sockets::STATION_WORKERS;
/// BLE workers follow the station and access-point workers in the shared mailboxes.
pub const BLE_FIRST: usize = STATION_WORKERS + crate::access_point::WORKERS;
const WORKERS: usize = BLE_FIRST + o89_comms_core::BLE_CONNECTIONS;
/// Frames the controller may send a client before it has taken one.
const MAILBOX: usize = 2;
/// The socket's receive buffer: an envelope and its frame head.
const TCP_RX: usize = 1_536;
/// The socket's transmit buffer: an envelope and its head, with room.
const TCP_TX: usize = 2_048;
/// How long an opening handshake may take to arrive.
const HANDSHAKE: Duration = Duration::from_secs(5);
/// How long the controller may take to answer an announcement: past the
/// three attempts its table gives up after (L-015).
const ANNOUNCED: Duration = Duration::from_secs(3);
/// How often a connection reads its row.
const STATUS: Duration = Duration::from_millis(100);
/// How long one frame may take to leave.
const WRITE: Duration = Duration::from_secs(1);
/// A connection that has carried nothing this long is gone.
const IDLE: Duration = Duration::from_secs(60);
/// A connection is probed after this long quiet.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// The access point's drain (L-196), and how often it looks.
const DRAIN: Duration = Duration::from_millis(o89_comms_core::DRAIN.as_millis());
const DRAIN_POLL: Duration = Duration::from_millis(50);

const _: () = assert!(
    REQUEST_BYTES <= MAX_PAYLOAD,
    "the request is read into an envelope's buffer"
);
const _: () = assert!(TCP_TX >= MAX_PAYLOAD + HEAD_BYTES);

/// Stamped client frames waiting for the link's turn at the UART.
const UPSTREAM_DEPTH: usize = 2;

/// One envelope, between the link task and a worker.
pub struct Envelope {
    len: usize,
    bytes: [u8; MAX_PAYLOAD],
}

impl Envelope {
    /// A copy of `bytes`; `None` for more than an envelope.
    fn of(bytes: &[u8]) -> Option<Self> {
        let mut envelope = Self {
            len: bytes.len(),
            bytes: [0; MAX_PAYLOAD],
        };
        envelope
            .bytes
            .get_mut(..bytes.len())?
            .copy_from_slice(bytes);
        Some(envelope)
    }

    /// The envelope's bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// Each worker's frames from the controller.
static MAILBOXES: [Channel<CriticalSectionRawMutex, Envelope, MAILBOX>; WORKERS] =
    [const { Channel::new() }; WORKERS];

/// Clients' stamped frames for the link task to put on the UART, which it
/// alone owns. Full, a worker waits one write deadline: WebSocket relies on
/// client retry; BLE closes and clears its codecs. Nothing is evicted.
pub static UPSTREAM: Channel<CriticalSectionRawMutex, Upstream, UPSTREAM_DEPTH> = Channel::new();

/// The handle each worker holds, if any.
static OWNERS: Blocking<CriticalSectionRawMutex, RefCell<[Option<Conn>; WORKERS]>> =
    Blocking::new(RefCell::new([None; WORKERS]));

/// The access point is going: its workers take no new client (L-196).
static DRAINING: AtomicBool = AtomicBool::new(false);

/// The access point is up: its workers take clients.
pub fn open_access_point() {
    DRAINING.store(false, Ordering::Relaxed);
}

/// The pairing window closed: the access point's workers take no new
/// client, and the ones they have get at most [`DRAIN`] to take the frames
/// already queued for them before the access point goes (L-196).
pub async fn drain_access_point() {
    DRAINING.store(true, Ordering::Relaxed);
    let drained = MAILBOXES.get(STATION_WORKERS..BLE_FIRST).unwrap_or(&[]);
    let _drained = with_timeout(DRAIN, async {
        // Bounded by the deadline.
        while drained.iter().any(|mailbox| !mailbox.is_empty()) {
            Timer::after(DRAIN_POLL).await;
        }
    })
    .await;
}

/// A frame the controller addressed to `conn`, into its worker's mailbox.
/// A full mailbox closes the client: the frame is neither dropped quietly
/// nor put in place of an older one.
pub fn deliver(link: &mut Link, conn: Conn, frame: &[u8]) {
    let worker = OWNERS.lock(|owners| {
        owners
            .borrow()
            .iter()
            .position(|owner| *owner == Some(conn))
    });
    let Some(mailbox) = worker.and_then(|worker| MAILBOXES.get(worker)) else {
        return;
    };
    let Some(envelope) = Envelope::of(frame) else {
        link.overrun(conn);
        return;
    };
    if mailbox.try_send(envelope).is_err() {
        link.overrun(conn);
    }
}

/// Serve a worker per buffer on `stack`, numbered from `first`, until
/// dropped.
pub async fn serve<const N: usize>(stack: Stack<'_>, first: usize, buffers: &mut [Buffers; N]) {
    let mut index = first;
    let workers = buffers.each_mut().map(|buffers| {
        let at = index;
        index = index.saturating_add(1);
        worker(stack, at, buffers)
    });
    join_array(workers).await;
}

/// What a worker holds for its connection: the socket's two buffers, a
/// client's envelope, and its stamped copy or the refusal it is owed.
pub struct Buffers {
    rx: [u8; TCP_RX],
    tx: [u8; TCP_TX],
    envelopes: Envelopes,
    to_client: [u8; MAX_PAYLOAD],
}

impl Buffers {
    /// Every buffer zeroed.
    pub const EMPTY: Self = Self {
        rx: [0; TCP_RX],
        tx: [0; TCP_TX],
        envelopes: Envelopes {
            from_client: [0; MAX_PAYLOAD],
            stamped: [0; MAX_PAYLOAD],
        },
        to_client: [0; MAX_PAYLOAD],
    };
}

struct Envelopes {
    from_client: [u8; MAX_PAYLOAD],
    stamped: [u8; MAX_PAYLOAD],
}

async fn worker(stack: Stack<'_>, index: usize, buffers: &mut Buffers) {
    let Buffers {
        rx,
        tx,
        envelopes,
        to_client,
    } = buffers;
    // Bounded per turn: one client, then its socket is closed.
    loop {
        let mut socket = TcpSocket::new(stack, rx, tx);
        socket.set_timeout(Some(IDLE));
        socket.set_keep_alive(Some(KEEP_ALIVE));
        if socket.accept(PORT).await.is_err() {
            Timer::after(STATUS).await;
            continue;
        }
        if index >= STATION_WORKERS && DRAINING.load(Ordering::Relaxed) {
            // The access point is going: no new client on it.
            socket.abort();
            continue;
        }
        let peer = peer(socket.remote_endpoint());
        if let Some(goodbye) = client(&mut socket, index, peer, envelopes, to_client).await {
            let mut close = [0u8; CONTROL_PAYLOAD];
            let len = close_payload(goodbye, &mut close);
            let _sent = frame(
                &mut socket,
                Outgoing::Close,
                close.get(..len).unwrap_or(&[]),
            )
            .await;
        }
        socket.close();
        let _flushed = with_timeout(WRITE, socket.flush()).await;
        socket.abort();
    }
}

/// What the client says it is, for `ClientConnected` (L-072).
fn peer(endpoint: Option<IpEndpoint>) -> Peer {
    match endpoint {
        Some(IpEndpoint {
            addr: IpAddress::Ipv4(addr),
            port,
        }) => Peer::Ipv4 {
            addr: addr.octets(),
            port,
        },
        None => Peer::Ipv4 {
            addr: [0; 4],
            port: 0,
        },
    }
}

/// A row held by a worker: registered for its mailbox, and released when
/// the connection ends however it ends. The link is never locked across an
/// await, so the release on drop finds it free.
pub struct Row {
    index: usize,
    conn: Conn,
    reason: Cell<DisconnectReason>,
}

impl Row {
    pub fn hold(index: usize, conn: Conn) -> Self {
        OWNERS.lock(|owners| {
            if let Some(owner) = owners.borrow_mut().get_mut(index) {
                *owner = Some(conn);
            }
        });
        if let Some(mailbox) = MAILBOXES.get(index) {
            // Bounded by the mailbox's two frames: a previous client's.
            while mailbox.try_receive().is_ok() {}
        }
        Self {
            index,
            conn,
            reason: Cell::new(DisconnectReason::ClosedByComms),
        }
    }
}

impl Drop for Row {
    fn drop(&mut self) {
        OWNERS.lock(|owners| {
            if let Some(owner) = owners.borrow_mut().get_mut(self.index) {
                *owner = None;
            }
        });
        // Free unless a task holds it across an await, which none does. Were
        // it held, the row would leak until the controller's resync (L-102).
        if let Ok(mut link) = LINK.try_lock() {
            link.gone(self.conn, self.reason.get());
        }
    }
}

/// How a connection ended.
enum Ended {
    /// This side closes it, and says why.
    Goodbye(Goodbye),
    /// The client closed it; its close is answered.
    ClientClosed,
    /// The transport failed: nothing more to write.
    Transport,
}

/// One client, from its handshake to the end of its connection; the close
/// this side owes it, if any.
async fn client(
    socket: &mut TcpSocket<'_>,
    index: usize,
    peer: Peer,
    envelopes: &mut Envelopes,
    to_client: &mut [u8; MAX_PAYLOAD],
) -> Option<Goodbye> {
    let request = &mut envelopes.from_client;
    let end = with_timeout(HANDSHAKE, handshake(socket, request))
        .await
        .ok()??;
    let mut response = [0u8; RESPONSE_BYTES];
    let answer = request
        .get(..end)
        .map(|request| accept(request, &mut response));
    let Some(Ok(len)) = answer else {
        let refusal = answer.and_then(Result::err)?;
        let _sent = with_timeout(WRITE, socket.write_all(refusal.response())).await;
        return None;
    };
    let written = with_timeout(WRITE, socket.write_all(response.get(..len)?)).await;
    if !matches!(written, Ok(Ok(()))) {
        return None;
    }
    let conn = match LINK.lock().await.connect(LinkTransport::WifiLocal, peer) {
        Ok(conn) => conn,
        Err(refused) => return Some(Goodbye::Refused(refused)),
    };
    let row = Row::hold(index, conn);
    match with_timeout(ANNOUNCED, announced(conn)).await {
        Ok(Ok(())) => {}
        Ok(Err(goodbye)) => return goodbye,
        Err(_) => return Some(Goodbye::Table(Closed::Unanswered)),
    }
    let (mut reader, writer) = socket.split();
    let writer = Mutex::<NoopRawMutex, _>::new(writer);
    let ended = match select(
        read_half(&mut reader, &writer, conn, envelopes),
        write_half(&writer, index, conn, to_client),
    )
    .await
    {
        Either::First(ended) | Either::Second(ended) => ended,
    };
    match ended {
        Ended::Goodbye(goodbye) => Some(goodbye),
        Ended::ClientClosed => {
            row.reason.set(DisconnectReason::ClosedByClient);
            Some(Goodbye::Answered)
        }
        Ended::Transport => {
            row.reason.set(DisconnectReason::TransportError);
            None
        }
    }
}

/// Read the opening handshake into `request` until its blank line; its
/// length, or `None` when the client went or sent more than a handshake.
async fn handshake(socket: &mut TcpSocket<'_>, request: &mut [u8; MAX_PAYLOAD]) -> Option<usize> {
    let mut have = 0usize;
    // Bounded: every turn reads at least one byte into a fixed buffer.
    loop {
        let free = request.get_mut(have..REQUEST_BYTES)?;
        if free.is_empty() {
            // Full with no blank line: `accept` refuses it as too long.
            return Some(REQUEST_BYTES);
        }
        let read = socket.read(free).await.ok().filter(|read| *read > 0)?;
        have = have.checked_add(read)?;
        if let Some(end) = request.get(..have).and_then(request_end) {
            return Some(end);
        }
    }
}

/// Wait for the controller to answer the announcement of `conn`.
async fn announced(conn: Conn) -> Result<(), Option<Goodbye>> {
    // Bounded by the caller's deadline.
    loop {
        match LINK.lock().await.status(conn) {
            Some(Status::Open) => return Ok(()),
            Some(Status::Announcing) => {}
            Some(Status::Close(why)) => return Err(Some(Goodbye::Table(why))),
            None => return Err(None),
        }
        Timer::after(STATUS).await;
    }
}

/// The client's frames, until it closes, breaks the protocol or goes.
async fn read_half(
    reader: &mut TcpReader<'_>,
    writer: &Mutex<NoopRawMutex, TcpWriter<'_>>,
    conn: Conn,
    envelopes: &mut Envelopes,
) -> Ended {
    // One frame a turn; each turn waits on the client (see the module).
    loop {
        let mut head = [0u8; HEAD_BYTES];
        let Some(first) = head.first_chunk_mut::<2>() else {
            return Ended::Transport;
        };
        if reader.read_exact(first).await.is_err() {
            return Ended::Transport;
        }
        let len = head_len(*first);
        let Some(rest) = head.get_mut(2..len) else {
            return Ended::Transport;
        };
        if reader.read_exact(rest).await.is_err() {
            return Ended::Transport;
        }
        let head = match read_head(head.get(..len).unwrap_or(&[])) {
            Ok(head) => head,
            Err(violation) => return Ended::Goodbye(Goodbye::Violation(violation)),
        };
        let (Incoming::Message(len)
        | Incoming::Ping(len)
        | Incoming::Pong(len)
        | Incoming::Close(len)) = head.incoming;
        let Some(payload) = envelopes.from_client.get_mut(..len) else {
            return Ended::Transport;
        };
        if reader.read_exact(payload).await.is_err() {
            return Ended::Transport;
        }
        unmask(head.mask, payload);
        match head.incoming {
            Incoming::Message(_) => {
                let payload = &*payload;
                let stamped = LINK
                    .lock()
                    .await
                    .from_client(conn, payload, &mut envelopes.stamped);
                match stamped {
                    Some(Ok(Inbound::Forward(len))) => {
                        let _queued =
                            forward(conn, envelopes.stamped.get(..len).unwrap_or(&[])).await;
                    }
                    Some(Ok(Inbound::Answer(len))) => {
                        let answer = envelopes.stamped.get(..len).unwrap_or(&[]);
                        if !frame(&mut *writer.lock().await, Outgoing::Binary, answer).await {
                            return Ended::Transport;
                        }
                    }
                    // A refusal that would not encode: nothing to send.
                    Some(Err(_)) => {}
                    // The row is closing: the write half reads why within
                    // `STATUS` and ends the connection with it.
                    None => return core::future::pending().await,
                }
            }
            Incoming::Ping(_) => {
                if !frame(&mut *writer.lock().await, Outgoing::Pong, payload).await {
                    return Ended::Transport;
                }
            }
            Incoming::Pong(_) => {}
            Incoming::Close(_) => return Ended::ClientClosed,
        }
    }
}

/// A stamped frame to the controller. One that does not leave within the
/// deadline returns false; the transport decides whether to close or rely on retry.
pub async fn forward(conn: Conn, stamped: &[u8]) -> bool {
    let queued = with_timeout(WRITE, async {
        // Bounded by the deadline. The copy is made only when there is
        // room, so the wait holds none.
        loop {
            let Some(envelope) = Envelope::of(stamped) else {
                return false;
            };
            if UPSTREAM.try_send(Upstream { conn, envelope }).is_ok() {
                return true;
            }
            poll_fn(|cx| UPSTREAM.poll_ready_to_send(cx)).await;
        }
    })
    .await;
    matches!(queued, Ok(true))
}

/// The controller's frames for this client, and the table's word on it.
async fn write_half(
    writer: &Mutex<NoopRawMutex, TcpWriter<'_>>,
    index: usize,
    conn: Conn,
    to_client: &mut [u8; MAX_PAYLOAD],
) -> Ended {
    let Some(mailbox) = MAILBOXES.get(index) else {
        return Ended::Transport;
    };
    // Every turn ends within `STATUS` or one frame's deadline.
    loop {
        // Copied out of the mailbox at once, so the wait below holds none.
        let len = match select(mailbox.receive(), Timer::after(STATUS)).await {
            Either::First(out) => {
                let bytes = out.bytes();
                to_client
                    .get_mut(..bytes.len())
                    .map(|dst| dst.copy_from_slice(bytes))
                    .map(|()| bytes.len())
            }
            Either::Second(()) => None,
        };
        if let Some(len) = len
            && !frame(
                &mut *writer.lock().await,
                Outgoing::Binary,
                to_client.get(..len).unwrap_or(&[]),
            )
            .await
        {
            return Ended::Transport;
        }
        match LINK.lock().await.status(conn) {
            Some(Status::Open) => {}
            Some(Status::Close(why)) => return Ended::Goodbye(Goodbye::Table(why)),
            Some(Status::Announcing) | None => return Ended::Transport,
        }
    }
}

/// One frame of `kind` out within the deadline; whether it left.
async fn frame(writer: &mut impl Write, kind: Outgoing, payload: &[u8]) -> bool {
    let mut head = [0u8; HEAD_BYTES];
    let Ok(len) = write_head(kind, payload.len(), &mut head) else {
        return false;
    };
    let sent = with_timeout(WRITE, async {
        writer.write_all(head.get(..len).unwrap_or(&[])).await?;
        writer.write_all(payload).await?;
        writer.flush().await
    })
    .await;
    matches!(sent, Ok(Ok(())))
}

/// BLE shares the same bounded per-worker delivery mailboxes as WebSocket.
pub async fn receive(index: usize) -> Option<Envelope> {
    Some(MAILBOXES.get(index)?.receive().await)
}

/// A queued client frame retains its owner so teardown cancels it before UART transmission.
pub struct Upstream {
    pub conn: Conn,
    envelope: Envelope,
}
impl Upstream {
    pub fn bytes(&self) -> &[u8] {
        self.envelope.bytes()
    }
}
