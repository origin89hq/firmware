//! What each of the comms processor's network stacks holds at once, one
//! named slot per socket that anything opens on it.
//!
//! The stack's socket set is fixed, and adding a socket to a full one is a
//! panic in smoltcp, which resets the module. So a budget is the sum of
//! the slots below and never a hand count: a socket the firmware opens, or
//! one `embassy-net` opens for itself, is a constant here first. The host
//! test `o89-sim/tests/comms_sockets.rs` builds both stacks with
//! `embassy-net`'s own code, the same release and features as the
//! firmware's, holds every socket open at once, and shows one slot fewer
//! panics; `cargo xtask check` refuses the two feature lists drifting apart.

use crate::ROWS;

/// `embassy-net`'s DNS socket, which `embassy_net::new` adds to every stack
/// while its `dns` feature is on. The station's NTP lookup needs that
/// feature, so the access point's stack, built by the same crate, has one
/// too.
pub const EMBASSY_DNS: usize = 1;
/// `embassy-net`'s DHCP client, added when a stack is configured by DHCP:
/// the station's, never the access point's static address.
pub const EMBASSY_DHCP_CLIENT: usize = 1;
/// The station's NTP query: one UDP socket, open for one query at a time.
pub const NTP: usize = 1;
/// The access point's DHCP server: one UDP socket for the session.
pub const DHCP_SERVER: usize = 1;
/// WebSocket workers on the station's network, each holding one TCP
/// socket at a time: one per row.
pub const STATION_WORKERS: usize = ROWS;
/// WebSocket workers behind the access point, each holding one TCP socket
/// at a time.
pub const ACCESS_POINT_WORKERS: usize = 2;

/// The station's stack: `embassy-net`'s DNS and DHCP client, NTP, and its
/// workers.
pub const STATION: usize = EMBASSY_DNS + EMBASSY_DHCP_CLIENT + NTP + STATION_WORKERS;
/// The access point's stack: `embassy-net`'s DNS, the DHCP server, and its
/// workers.
pub const ACCESS_POINT: usize = EMBASSY_DNS + DHCP_SERVER + ACCESS_POINT_WORKERS;

const _: () = assert!(
    ACCESS_POINT_WORKERS >= 1,
    "a phone on the access point needs a worker"
);
const _: () = assert!(
    STATION == 11 && ACCESS_POINT == 4,
    "the architecture states both budgets"
);
