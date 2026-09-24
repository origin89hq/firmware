//! The comms processor's decisions, and nothing about the UART it runs on.
//!
//! The comms firmware builds for the ESP32-C6 alone, so what it decides
//! lives here, where the host can drive it: the download window's intake,
//! which reads the controller UART for `EnterDownload` and for nothing else
//! (F-033, L-190), and the link-local state machine, which states this side,
//! beats, answers the controller and drops the link when the controller
//! stops answering (L-033, L-100, L-120). The firmware reads its timer and
//! its UART, hands the bytes and the [`Tick`] in, and puts the frames that
//! come back on the wire.
//!
//! The counterpart of `o89-core`, and never reaching it: the comms processor
//! forwards client bytes it cannot read, and what it keeps of its own is the
//! link. The mechanics the two sides share, the tick, the requests and
//! beats in flight and the rules every link-local frame meets, are
//! `o89-link`'s. `no_std` and no `alloc`.

#![no_std]

mod access_point;
mod ble;
mod connections;
#[cfg(any(test, feature = "frames"))]
mod frame_bench;
mod link;
mod network;
mod ntp;
mod relay;
pub mod sockets;
mod websocket;
mod window;

pub use access_point::*;
pub use ble::*;
pub use connections::*;
#[cfg(any(test, feature = "frames"))]
pub use frame_bench::FrameBenchStart;
pub use link::*;
pub use network::*;
pub use ntp::*;
pub use o89_link::{Country, EncodeError, Millis, Tick};
pub use relay::*;
pub use websocket::*;
pub use window::*;

mod credential_store;
pub use credential_store::*;
