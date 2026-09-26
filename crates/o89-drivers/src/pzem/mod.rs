//! Peacefair's PZEM meters. The DC and AC halves share a vendor, a baud
//! rate and an alarm encoding, and nothing else: framing, resolutions and
//! register layout all differ, so each is its own dialect.
//!
//! Each meter's poll here is whole; the `Device` variant that dispatches to
//! it, and the check that no two devices' signals overlap, belong to the
//! configuration of buses and devices (#196).

pub mod ac;
pub mod dc;
