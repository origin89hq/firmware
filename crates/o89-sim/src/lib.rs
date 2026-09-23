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
//! What exists today: the storage seam, a simulated FRAM and a simulated
//! NOR, each with a step counter, and the harness that runs a write path
//! crashing at every step and asserts the recovery invariant after each
//! (VERIFICATION §6, F-025). The paths run through it: on the FRAM, one
//! record's A/B write, a factory reset's epoch and table, a command's
//! counter and in-flight entry, a signed command from its MAC to its finished entry, a pairing, a challenge's mint, a boot's
//! count and panic record, the ladder's cuts, and a run reason's start and
//! stop; on the NOR, an append, a page turn and its erase ahead, and the
//! boot that erases a block a torn record closed, itself cut, and a head a
//! torn write closed moving into a block the erase ahead missed, and the
//! bench's drop of the oldest block; and the hostile comms processor, the comms processor's own
//! link from `o89-comms-core` with a named set of capabilities on top that
//! every test using it declares, driving the link's state machine and the
//! sessions over it through what a real one can do to it, with a client
//! from `km43`'s own client half on the far side. This crate is host-only:
//! it is never cross-compiled, so it may hold a whole part's bytes on the
//! heap; the rules that bind the domain crates bind what it tests, not
//! itself.

mod comms;
mod fram;
#[cfg(test)]
mod link;
mod nor;
#[cfg(test)]
mod pairing;
#[cfg(test)]
mod sessions;
#[cfg(test)]
mod tables;

pub use comms::*;
pub use fram::*;
pub use nor::*;

#[cfg(test)]
mod configuration;
