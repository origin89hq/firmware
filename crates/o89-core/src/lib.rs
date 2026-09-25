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
//! earn, the [`Clients`] slots with the [`Dedup`] table beside them, the
//! [`Generator`] every challenge and ephemeral key is drawn from, the run
//! reason with the [`Declared`] an output cannot move without, the secret
//! and the controller key, the panic record, the boot count, the log's byte
//! budget, the authorised comms release and the network master copy. Then
//! the link to the comms processor, the connection rows and the
//! [`Sessions`] bound onto them, with the [`Job`]s of key agreement an
//! [`Agreement`] runs off the control loop, and the [`Endpoint`] that sends
//! each frame to one or the other; and the signed-request path, whose
//! [`Permit`] is the only way an operation reaches a handler. The behaviours
//! arrive with the milestones that name them.

#![no_std]

mod agreement;
mod body;
mod boot_count;
mod calendar;
mod clients;
mod clock_journal;
mod configuration;
mod dedup;
mod drbg;
mod endpoint;
mod epoch;
mod fail_state;
mod feedback;
mod fram;
mod gesture;
mod knock;
mod lamp;
mod last_words;
mod link;
pub mod mailbox;
pub mod map;
mod network;
mod pairing_report;
mod panic_record;
mod provision;
mod rail;
mod rail_turn;
mod readout;
mod record;
mod release;
mod request;
mod reset;
mod revision;
mod ring;
mod rollcall;
mod run_reason;
mod secret;
mod session;
mod store;
mod text;
mod tick;
mod wall_clock;
mod write_volume;

pub use agreement::{Agreement, Done, HANDSHAKE_ANSWER, HANDSHAKE_FRAME, Job, ReportText, Ticket};
pub use body::*;
pub use boot_count::*;
pub use calendar::*;
pub use clients::*;
pub use clock_journal::*;
pub use configuration::*;
pub use dedup::*;
pub use drbg::*;
pub use endpoint::*;
pub use epoch::*;
pub use fail_state::*;
pub use feedback::*;
pub use fram::*;
pub use gesture::*;
pub use knock::*;
pub use lamp::*;
pub use last_words::*;
pub use link::*;
pub use network::*;
pub use panic_record::*;
pub use provision::*;
pub use rail::*;
pub use rail_turn::*;
pub use readout::*;
pub use record::*;
pub use release::*;
pub use request::*;
pub use reset::*;
pub use revision::*;
pub use ring::*;
pub use rollcall::*;
pub use run_reason::*;
pub use secret::*;
pub use session::*;
pub use store::*;
pub use text::*;
pub use tick::*;
pub use wall_clock::*;
pub use write_volume::*;

mod wifi;
pub use wifi::*;
