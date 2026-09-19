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
//! [`Feedback`] is read under, the FRAM [`Record`] with the [`map`] that
//! places every one of them in the part, and the [`Store`] of what the
//! part holds: the epoch with the [`Clearing`] a factory reset has to
//! earn, the [`ClientTable`] with its counters and the [`Dedup`] table
//! beside them, the challenge counter with the [`Minted`] a challenge
//! cannot leave without, the run reason with the [`Declared`] an output
//! cannot move without, the secret, the panic record, the boot count, the
//! log's byte budget, the authorised comms release and the network master
//! copy. The behaviours and the link-local state machines arrive with the
//! milestones that name them.

#![no_std]

mod body;
mod boot_count;
mod challenge;
mod clients;
mod dedup;
mod epoch;
mod fail_state;
mod feedback;
mod fram;
mod lamp;
mod last_words;
mod link;
pub mod mailbox;
pub mod map;
mod network;
mod panic_record;
mod rail;
mod readout;
mod record;
mod release;
mod reset;
mod revision;
mod ring;
mod rollcall;
mod run_reason;
mod secret;
mod store;
mod text;
mod tick;
mod write_volume;

pub use body::*;
pub use boot_count::*;
pub use challenge::*;
pub use clients::*;
pub use dedup::*;
pub use epoch::*;
pub use fail_state::*;
pub use feedback::*;
pub use fram::*;
pub use lamp::*;
pub use last_words::*;
pub use link::*;
pub use network::*;
pub use panic_record::*;
pub use rail::*;
pub use readout::*;
pub use record::*;
pub use release::*;
pub use reset::*;
pub use revision::*;
pub use ring::*;
pub use rollcall::*;
pub use run_reason::*;
pub use secret::*;
pub use store::*;
pub use text::*;
pub use tick::*;
pub use write_volume::*;
