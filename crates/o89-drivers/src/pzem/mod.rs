//! Peacefair's PZEM meters. The DC and AC halves share a vendor, a baud
//! rate and an alarm encoding, and nothing else: framing, resolutions and
//! register layout all differ, so each is its own dialect.

pub mod ac;
pub mod dc;
