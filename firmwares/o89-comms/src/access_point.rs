//! The provisioning access point: an open network named after the module,
//! an address for each phone that joins it, and the WebSocket workers
//! behind it.
//!
//! When it runs is `o89_comms_core::Plan`'s: no network cached, or the
//! controller's pairing window open, and never without a regulatory
//! country from the controller's record. It is open: the comms processor
//! holds no key, and every client proves itself end to end to the
//! controller, whose physical act still gates enrolment (P-066). Its
//! clients take rows from the one connection table.
//!
//! Bounds: at most [`STATIONS`] phones associate, the radio refusing the
//! next. The lease table holds [`LEASES`] addresses, as many as the range
//! offers, for [`LEASE_SECS`] each; with all eight leased, a ninth phone is
//! refused an address until one expires, and nothing is evicted. Two
//! WebSocket workers serve it.

use core::fmt::Write as _;
use core::net::Ipv4Addr;

use edge_dhcp::server::{Server, ServerOptions};
use edge_dhcp::{Options, Packet};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Cidr, Stack, StaticConfigV4};
use embassy_time::{Duration, Instant, with_timeout};
use esp_radio::wifi::ap::AccessPointConfig;
use esp_radio::wifi::{AuthenticationMethodConfig, Ssid};

/// Phones that may associate at once.
pub const STATIONS: u16 = 8;
/// WebSocket workers behind the access point.
pub const WORKERS: usize = 2;
/// Addresses leased at once: the whole range, so an expired lease is
/// reused rather than a full table refusing forever.
const LEASES: usize = 8;
/// How long a lease lasts; a phone renews at half of it.
const LEASE_SECS: u32 = 300;
/// The access point's own address, and its network.
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
/// The first and last hosts leased: [`LEASES`] of them.
const FIRST_HOST: u8 = 50;
const LAST_HOST: u8 = 57;
/// A DHCP message, with room past the 576 bytes every client accepts.
const DHCP_BYTES: usize = 768;
/// How long a DHCP answer may take to leave.
const SEND: Duration = Duration::from_secs(1);

const _: () = assert!(LAST_HOST - FIRST_HOST + 1 == 8 && LEASES == 8);

/// The access point's network: its address, and no gateway, so a phone
/// keeps its own route to anywhere else.
pub fn network() -> Config {
    Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(ADDRESS, 24),
        gateway: None,
        dns_servers: core::iter::empty().collect(),
    })
}

/// The access point's radio configuration, named `origin89-` and the last
/// two bytes of its address.
pub fn config(mac: [u8; 6]) -> Option<AccessPointConfig> {
    let [.., high, low] = mac;
    let mut name = Name::default();
    write!(name, "origin89-{high:02x}{low:02x}").ok()?;
    let ssid = Ssid::try_from(name.as_str()).ok()?;
    Some(
        AccessPointConfig::default()
            .with_ssid(ssid)
            .with_authentication(AuthenticationMethodConfig::Open)
            .with_max_connections(STATIONS),
    )
}

/// An address for each phone that asks, until dropped.
pub async fn dhcp(stack: Stack<'_>) {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx = [0u8; DHCP_BYTES];
    let mut tx = [0u8; DHCP_BYTES];
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    if socket.bind(67).is_err() {
        return;
    }
    let mut options = ServerOptions::new(ADDRESS, None);
    options.lease_duration_secs = LEASE_SECS;
    let mut server = Server::<_, LEASES>::new(|| Instant::now().as_secs(), ADDRESS);
    let [a, b, c, _] = ADDRESS.octets();
    server.range_start = Ipv4Addr::new(a, b, c, FIRST_HOST);
    server.range_end = Ipv4Addr::new(a, b, c, LAST_HOST);
    let mut request = [0u8; DHCP_BYTES];
    let mut reply = [0u8; DHCP_BYTES];
    // One request a turn. Waiting for one has no deadline: a quiet access
    // point holds no row and no lock, and its session ends it.
    loop {
        let Ok((len, _from)) = socket.recv_from(&mut request).await else {
            continue;
        };
        let Some(Ok(packet)) = request.get(..len).map(Packet::decode) else {
            continue;
        };
        let mut buffer = Options::buf();
        let Some(answer) = server.handle_request(&mut buffer, &options, &packet) else {
            continue;
        };
        let Ok(bytes) = answer.encode(&mut reply) else {
            continue;
        };
        // RFC 2131 §4.1: to a client that has an address and did not ask
        // for broadcast, at that address; otherwise to everyone.
        let to = if !packet.ciaddr.is_unspecified() && !packet.broadcast {
            packet.ciaddr
        } else {
            Ipv4Addr::BROADCAST
        };
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(to), 68);
        let _sent = with_timeout(SEND, socket.send_to(bytes, endpoint)).await;
    }
}

/// Room for `origin89-` and four hex digits.
#[derive(Default)]
struct Name {
    bytes: [u8; 16],
    len: usize,
}

impl Name {
    fn as_str(&self) -> &str {
        self.bytes
            .get(..self.len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

impl core::fmt::Write for Name {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(core::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
