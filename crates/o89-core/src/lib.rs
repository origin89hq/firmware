//! The controller's decisions, and nothing about how they reach a pin.
//!
//! `no_std` and no `alloc`, which is the proof rather than the claim: with no
//! allocator crate in scope there is no `Vec` and no `Box` to reach for, so
//! every collection has a named capacity and a written behaviour when full.
//! Nothing here names a peripheral either. Time arrives as a [`Tick`] the
//! caller reads, which is what lets a whole winter run on a laptop and what
//! lets a test move a probe from −5 °C to unknown between two calls.
//!
//! What exists today is the first seam: the monotonic tick and the clock that
//! reads it. The tables, the behaviours and the link-local state machines
//! arrive with the milestones that name them.

#![no_std]

mod tick;

pub use tick::*;
