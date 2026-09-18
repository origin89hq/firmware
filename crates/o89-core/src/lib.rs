//! The controller's decisions, and nothing about how they reach a pin.
//!
//! `no_std` and no `alloc`, which is the proof rather than the claim: with no
//! allocator crate in scope there is no `Vec` and no `Box` to reach for, so
//! every collection has a named capacity and a written behaviour when full.
//! Nothing here names a peripheral either. Time arrives as a [`Tick`] the
//! caller reads, which is what lets a whole winter run on a laptop and what
//! lets a test move a probe from −5 °C to unknown between two calls.
//!
//! What exists today is the first seam, the monotonic tick and the clock
//! that reads it, and the safety floor's decisions: the fail state every
//! line declares, the board [`Revision`] and the policies read from it, the
//! reset cause and the boot record, the last words a run leaves for the next
//! boot, the [`Rollcall`] that earns the watchdog its feed, the lamp's
//! [`Pattern`], the module rail's [`RailSequencer`], the contract
//! [`Feedback`] is read under, and the FRAM [`Record`] with the [`map`] that
//! places every one of them in the part. The tables,
//! the behaviours and the link-local state machines arrive with the
//! milestones that name them.

#![no_std]

mod fail_state;
mod feedback;
mod fram;
mod lamp;
mod last_words;
pub mod map;
mod rail;
mod reset;
mod revision;
mod rollcall;
mod tick;

pub use fail_state::*;
pub use feedback::*;
pub use fram::*;
pub use lamp::*;
pub use last_words::*;
pub use rail::*;
pub use reset::*;
pub use revision::*;
pub use rollcall::*;
pub use tick::*;
