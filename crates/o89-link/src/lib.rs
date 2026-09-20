//! The link's mechanics, which both processors run and neither decides by.
//!
//! The controller's link-local state machine lives in `o89-core` and the
//! comms processor's in `o89-comms-core`. The comms processor must never
//! reach the crate that decides, so what the two share lives here, below
//! both: the monotonic [`Tick`] every duration is measured on; the
//! [`Requests`] a side has in flight, with their retries (L-014, L-015); the
//! [`Beats`] whose answers still count (L-100); and the rules every
//! link-local frame meets whichever side reads it, a peer's refusal never
//! answered (L-181) and only the link's own frames crossing a major
//! mismatch (L-050).
//!
//! `no_std`, no `alloc`, and nothing here names a peripheral.

#![no_std]

mod beats;
mod requests;
mod rules;
mod tick;
mod wire;

pub use beats::*;
pub use requests::*;
pub use rules::*;
pub use tick::*;
pub use wire::*;
