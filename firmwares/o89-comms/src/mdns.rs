//! The station's mDNS responder on its socket (KM43 P-224): what it
//! decides is `o89_comms_core::mdns`'s, and this carries its packets.
//!
//! One UDP socket on 5353, in the station's socket budget, joined to
//! 224.0.0.251. Each turn reads the station's address and the `device_id`
//! from the controller's latest statement (L-035), sends what is due, and
//! waits at most a second for a packet, the next probe or announcement, or
//! the station leaving. Leaving is [`leave`]: the goodbye goes out on the
//! network being left, before it is left, and the station waits for it no
//! longer than [`GOODBYE`].
//!
//! Every await is bounded or is the parked end of a responder that could
//! not start, which still answers [`leave`] at once.

use embassy_futures::select::{Either3, select3};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_hal::rng::Rng;
use o89_comms_core::Tick;
use o89_comms_core::mdns::{
    Destination, MDNS_GROUP, MDNS_PORT, Outgoing, RECEIVE_BYTES, Responder, SEND_BYTES, Source,
};

/// The station is leaving its network.
static LEAVE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The goodbye is handed to the stack, or there was none to say.
static LEFT: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// How long the station waits for the goodbye before it leaves anyway.
pub const GOODBYE: Duration = Duration::from_millis(500);
/// How long one send may wait for room in the socket.
const SEND: Duration = Duration::from_millis(200);
/// The longest wait for a packet: the address and the `device_id` are
/// read at least this often.
const TURN: Duration = Duration::from_secs(1);
/// Messages sent from one turn's timers: a probe finishing into an
/// announcement is two.
const DUE_PER_TURN: usize = 2;
/// RFC 6762 §11: every packet leaves with TTL 255.
const HOP_LIMIT: u8 = 255;
/// Packets the socket holds each way.
const PACKETS: usize = 2;

/// The responder's socket buffers and its answer, held for the part's
/// life and lent to each station session, so no session's future carries
/// them.
pub struct Buffers {
    rx_meta: [PacketMetadata; PACKETS],
    tx_meta: [PacketMetadata; PACKETS],
    rx: [u8; RECEIVE_BYTES],
    tx: [u8; SEND_BYTES],
    out: [u8; SEND_BYTES],
}

impl Buffers {
    pub const EMPTY: Self = Self {
        rx_meta: [PacketMetadata::EMPTY; PACKETS],
        tx_meta: [PacketMetadata::EMPTY; PACKETS],
        rx: [0; RECEIVE_BYTES],
        tx: [0; SEND_BYTES],
        out: [0; SEND_BYTES],
    };
}

/// Say goodbye before leaving the network (RFC 6762 §10.1): asks the
/// responder and waits for it, at most [`GOODBYE`].
pub async fn leave() {
    LEAVE.signal(());
    let _said = with_timeout(GOODBYE, LEFT.wait()).await;
}

/// Answer for `hostname` on `stack` for the life of the station session.
/// Never returns: the session ends it by dropping it.
pub async fn respond(stack: Stack<'_>, hostname: &str, buffers: &mut Buffers) {
    LEAVE.reset();
    LEFT.reset();
    let seed = Rng::new().random();
    let Ok(mut responder) = Responder::new(hostname, seed) else {
        return park().await;
    };
    let [a, b, c, d] = MDNS_GROUP;
    if stack
        .join_multicast_group(Ipv4Address::new(a, b, c, d))
        .is_err()
    {
        return park().await;
    }
    let Buffers {
        rx_meta,
        tx_meta,
        rx,
        tx,
        out,
    } = buffers;
    let mut socket = UdpSocket::new(stack, rx_meta, rx, tx_meta, tx);
    socket.set_hop_limit(Some(HOP_LIMIT));
    if socket.bind(MDNS_PORT).is_err() {
        return park().await;
    }
    loop {
        let address = stack
            .config_v4()
            .map(|config| config.address.address().octets());
        let device_id = crate::radio::diagnostics().await.controller_device_id();
        responder.observe(address, device_id, now());
        for _ in 0..DUE_PER_TURN {
            let Some(message) = responder.poll(now(), out) else {
                break;
            };
            send(&socket, out, message).await;
        }
        // Until the next probe or announcement, zero if it is already due.
        let wait = responder.due().map_or(TURN, |due| {
            let millis = due.as_millis().saturating_sub(now().as_millis());
            Duration::from_millis(millis).min(TURN)
        });
        // The packet is read where the socket holds it.
        let read = socket.recv_from_with(|packet, meta| {
            let IpAddress::Ipv4(addr) = meta.endpoint.addr;
            let from = Source {
                addr: addr.octets(),
                port: meta.endpoint.port,
            };
            responder.received(packet, from, now(), out)
        });
        match select3(read, Timer::after(wait), LEAVE.wait()).await {
            Either3::First(Some(message)) => send(&socket, out, message).await,
            Either3::First(None) | Either3::Second(()) => {}
            Either3::Third(()) => {
                if let Some(message) = responder.goodbye(out) {
                    send(&socket, out, message).await;
                    // Out of the socket and into the driver before the
                    // session drops the stack.
                    let _flushed = with_timeout(SEND, socket.flush()).await;
                }
                LEFT.signal(());
                return park().await;
            }
        }
    }
}

/// A responder with nothing to answer: every [`leave`] is told at once.
async fn park() {
    loop {
        LEAVE.wait().await;
        LEFT.signal(());
    }
}

async fn send(socket: &UdpSocket<'_>, out: &[u8; SEND_BYTES], message: Outgoing) {
    let Some(bytes) = out.get(..message.len) else {
        return;
    };
    let to = match message.to {
        Destination::Multicast => {
            let [a, b, c, d] = MDNS_GROUP;
            IpEndpoint::new(IpAddress::v4(a, b, c, d), MDNS_PORT)
        }
        Destination::Unicast {
            addr: [a, b, c, d],
            port,
        } => IpEndpoint::new(IpAddress::v4(a, b, c, d), port),
    };
    // A message the socket has no room for is lost like any datagram;
    // the next query or announcement says it again.
    let _sent = with_timeout(SEND, socket.send_to(bytes, to)).await;
}

fn now() -> Tick {
    Tick::from_millis(Instant::now().as_millis())
}
