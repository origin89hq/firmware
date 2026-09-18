//! The simulated site: the seams `o89-core` leaves, filled with faults.
//!
//! `o89-core` decides and touches nothing; every peripheral it needs arrives
//! through a trait. This crate fills those traits on a laptop with parts
//! that can be told to fail: a supply that falls, a power that is cut at
//! the k-th byte, and, as the milestones add them, a winter, a hostile comms
//! processor and a bus that answers with the same number for a week. A
//! fault found on the bench becomes a fault here first, so it is a test
//! that runs on every commit rather than a night somebody remembers.
//!
//! What exists today is the storage seam: a simulated FRAM with a step
//! counter, the harness that runs a write path crashing at every step and
//! asserts the recovery invariant after each (VERIFICATION §6, F-025), and
//! the tables' write paths run through it. This crate is host-only: it is
//! never cross-compiled, so it may hold a whole part's bytes on the heap;
//! the rules that bind the domain crates bind what it tests, not itself.

mod fram;
#[cfg(test)]
mod tables;

pub use fram::*;
