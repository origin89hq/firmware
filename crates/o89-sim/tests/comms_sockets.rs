//! The comms processor's socket budgets, against `embassy-net`'s own stack.
//!
//! Each stack is built as the firmware builds it, with the release and
//! features `firmwares/o89-comms` uses, and every socket its session opens
//! is held open at once. A socket past the budget panics in smoltcp, which
//! on the part resets the module; here it fails the test. The budget one
//! slot short must panic too, so a budget that counts a socket nothing
//! opens is caught as well as one that misses a socket.

use core::task::Context;

use embassy_net::driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{
    Config, DhcpConfig, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4,
};
use o89_comms_core::sockets::{ACCESS_POINT, ACCESS_POINT_WORKERS, STATION, STATION_WORKERS};

/// A link that never comes up: the stack is built and holds sockets, and
/// no frame moves.
struct Unplugged;

struct Never;

impl RxToken for Never {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        f(&mut [])
    }
}

impl TxToken for Never {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, _len: usize, f: F) -> R {
        f(&mut [])
    }
}

impl Driver for Unplugged {
    type RxToken<'a> = Never;
    type TxToken<'a> = Never;

    fn receive(&mut self, _cx: &mut Context) -> Option<(Never, Never)> {
        None
    }

    fn transmit(&mut self, _cx: &mut Context) -> Option<Never> {
        None
    }

    fn link_state(&mut self, _cx: &mut Context) -> LinkState {
        LinkState::Down
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = 1_514;
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet([0x02, 0, 0, 0, 0, 0x01])
    }
}

/// The access point's configuration: a static address, as
/// `access_point::network` gives it.
fn access_point_config() -> Config {
    Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 4, 1), 24),
        gateway: None,
        dns_servers: core::iter::empty().collect(),
    })
}

/// The station's configuration: DHCP, as a network record gives it.
fn station_config() -> Config {
    Config::dhcpv4(DhcpConfig::default())
}

/// One UDP socket bound to `port`, held while `hold` runs.
fn with_udp(stack: Stack<'_>, port: u16, hold: impl FnOnce()) {
    let mut rx_meta = [PacketMetadata::EMPTY; 1];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut rx = [0u8; 64];
    let mut tx = [0u8; 64];
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    assert!(socket.bind(port).is_ok(), "the port is free");
    hold();
}

/// `N` workers' TCP sockets, each listening, all held at once.
fn workers<const N: usize>(stack: Stack<'_>) {
    let mut buffers = [([0u8; 64], [0u8; 64]); N];
    let _sockets = buffers
        .each_mut()
        .map(|(rx, tx)| TcpSocket::new(stack, rx, tx));
}

/// The access point's session: embassy-net's DNS, the DHCP server, and
/// every worker.
fn access_point_session<const SOCK: usize>() {
    let mut resources = StackResources::<SOCK>::new();
    let (stack, _runner) = embassy_net::new(Unplugged, access_point_config(), &mut resources, 1);
    with_udp(stack, 67, || workers::<ACCESS_POINT_WORKERS>(stack));
}

/// The station's session: embassy-net's DNS and DHCP client, an NTP query,
/// and every worker.
fn station_session<const SOCK: usize>() {
    let mut resources = StackResources::<SOCK>::new();
    let (stack, _runner) = embassy_net::new(Unplugged, station_config(), &mut resources, 1);
    with_udp(stack, 0, || workers::<STATION_WORKERS>(stack));
}

const ACCESS_POINT_SHORT: usize = ACCESS_POINT.saturating_sub(1);
const STATION_SHORT: usize = STATION.saturating_sub(1);

#[test]
fn the_access_point_stack_holds_embassy_dns_its_dhcp_server_and_every_worker() {
    access_point_session::<ACCESS_POINT>();
}

#[test]
#[should_panic(expected = "adding a socket to a full SocketSet")]
fn an_access_point_budget_one_slot_short_panics_on_its_last_worker() {
    access_point_session::<ACCESS_POINT_SHORT>();
}

#[test]
fn the_station_stack_holds_embassy_dns_and_dhcp_ntp_and_every_worker() {
    station_session::<STATION>();
}

#[test]
#[should_panic(expected = "adding a socket to a full SocketSet")]
fn a_station_budget_one_slot_short_panics_on_its_last_worker() {
    station_session::<STATION_SHORT>();
}
