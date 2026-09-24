//! What the comms processor's network stack holds at once, one named slot
//! per socket that anything opens on it.
//!
//! The stack's socket set is fixed, and adding a socket to a full one is a
//! panic in smoltcp, which resets the module. So the budget is the sum of
//! the slots below and never a hand count: a socket the firmware opens, or
//! one `embassy-net` opens for itself, is a constant here first. The host
//! test `o89-sim/tests/comms_sockets.rs` builds the stack with
//! `embassy-net`'s own code, the same release and features as the
//! firmware's, holds every socket open at once, and shows one slot fewer
//! panics; `cargo xtask check` refuses the two feature lists drifting apart.

use crate::ROWS;

/// `embassy-net`'s DNS socket, which `embassy_net::new` adds to every stack
/// while its `dns` feature is on, as the station's NTP lookup needs.
pub const EMBASSY_DNS: usize = 1;
/// `embassy-net`'s DHCP client, added when a stack is configured by DHCP.
pub const EMBASSY_DHCP_CLIENT: usize = 1;
/// The station's NTP query: one UDP socket, open for one query at a time.
pub const NTP: usize = 1;
/// The station's mDNS responder (KM43 P-224): one UDP socket on 5353 for
/// the session.
pub const MDNS: usize = 1;
/// WebSocket workers on the station's network, each holding one TCP
/// socket at a time: one per row.
pub const STATION_WORKERS: usize = ROWS;

/// The station's stack: `embassy-net`'s DNS and DHCP client, NTP, the mDNS
/// responder, and its workers.
pub const STATION: usize = EMBASSY_DNS + EMBASSY_DHCP_CLIENT + NTP + MDNS + STATION_WORKERS;

const _: () = assert!(STATION == 12, "the architecture states the budget");
