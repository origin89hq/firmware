//! The bench tool's mailbox: a few words of RAM the host writes over SWD
//! and the recorder answers, so a laptop can read and write the FRAM and
//! the NOR through the firmware that owns them.
//!
//! The firmware side moves bytes and nothing else: read this range, write
//! these bytes, erase this block, reboot. Every write reaches the part
//! through the same seam the store uses, so the voltage detector's refusal
//! and the bus's answer are the ones the store would get. What the bytes
//! mean is the host's business, and the host uses this crate's own
//! [`Record`](crate::Record) and [`Kept`](crate::Kept) to mean it, so an
//! epoch written from the bench lands the way the firmware would land it.
//!
//! The protocol is a sequence pair. The host fills the request and lands
//! its sequence last; the firmware sees a request whose sequence is not the
//! one it answered, serves it, fills the answer and lands the same sequence
//! as its response last. Nothing is read by either side while the other is
//! writing it, because each waits for the other's sequence to move.
//!
//! This is the layout both sides share; the address is where the
//! controller's linker puts it, stated here so the two cannot disagree.

/// Where the mailbox sits in the controller's RAM: the last 4 KiB, which
/// `memory.x` keeps out of the stack and the runtime never zeroes.
pub const MAILBOX_ADDRESS: u32 = 0x2002_3000;

/// The bytes the mailbox takes.
pub const MAILBOX_BYTES: usize = 4096;

/// The word at offset zero when a mailbox is there: `O89M`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"O89M");

/// The protocol's version, at offset four.
pub const VERSION: u32 = 1;

/// Bytes of data a request or an answer carries: enough for the client
/// table's record in one write.
pub const DATA_BYTES: usize = 2048;

/// The offsets of every field, in bytes from the mailbox's start.
pub mod offset {
    /// `MAGIC`.
    pub const MAGIC: u32 = 0;
    /// `VERSION`.
    pub const VERSION: u32 = 4;
    /// The host's sequence, landed last when a request is ready.
    pub const REQUEST_SEQ: u32 = 8;
    /// The firmware's sequence, landed last when an answer is ready.
    pub const RESPONSE_SEQ: u32 = 12;
    /// The operation.
    pub const OP: u32 = 16;
    /// The first argument: an address or a block.
    pub const ARG0: u32 = 20;
    /// The second argument: a length.
    pub const ARG1: u32 = 24;
    /// The status of the answer.
    pub const STATUS: u32 = 28;
    /// The bytes of data in the answer.
    pub const LENGTH: u32 = 32;
    /// The data.
    pub const DATA: u32 = 36;
}

const _: () = assert!(offset::DATA as usize + DATA_BYTES <= MAILBOX_BYTES);

/// What the host asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Op {
    /// Nothing but an answer, carrying the boot count.
    Ping,
    /// `ARG1` bytes of the FRAM from `ARG0`.
    ReadFram,
    /// The data, `ARG1` bytes, into the FRAM at `ARG0`, through the seam.
    WriteFram,
    /// `ARG1` bytes of the NOR from `ARG0`.
    ReadNor,
    /// Erase the NOR block `ARG0`.
    EraseNorBlock,
    /// Answer, then reset the part.
    Reboot,
}

impl Op {
    /// The word in the mailbox.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Ping => 1,
            Self::ReadFram => 2,
            Self::WriteFram => 3,
            Self::ReadNor => 4,
            Self::EraseNorBlock => 5,
            Self::Reboot => 6,
        }
    }

    /// The operation a word names, or nothing.
    #[must_use]
    pub const fn of(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Ping),
            2 => Some(Self::ReadFram),
            3 => Some(Self::WriteFram),
            4 => Some(Self::ReadNor),
            5 => Some(Self::EraseNorBlock),
            6 => Some(Self::Reboot),
            _ => None,
        }
    }
}

/// What the firmware answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Status {
    /// Done; the data, if any, is in the mailbox.
    Ok,
    /// A word that names no operation.
    UnknownOp,
    /// An address or a length past the part, or past the data.
    OutOfRange,
    /// The write did not start: the supply was falling.
    SupplyFalling,
    /// The bus refused.
    Bus,
    /// The NOR is not there: the ring never opened.
    NoNor,
}

impl Status {
    /// The word in the mailbox.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::UnknownOp => 1,
            Self::OutOfRange => 2,
            Self::SupplyFalling => 3,
            Self::Bus => 4,
            Self::NoNor => 5,
        }
    }

    /// The status a word names, or nothing.
    #[must_use]
    pub const fn of(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::UnknownOp),
            2 => Some(Self::OutOfRange),
            3 => Some(Self::SupplyFalling),
            4 => Some(Self::Bus),
            5 => Some(Self::NoNor),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_and_status_round_trips_through_its_word() {
        for op in [
            Op::Ping,
            Op::ReadFram,
            Op::WriteFram,
            Op::ReadNor,
            Op::EraseNorBlock,
            Op::Reboot,
        ] {
            assert_eq!(Op::of(op.code()), Some(op));
        }
        for status in [
            Status::Ok,
            Status::UnknownOp,
            Status::OutOfRange,
            Status::SupplyFalling,
            Status::Bus,
            Status::NoNor,
        ] {
            assert_eq!(Status::of(status.code()), Some(status));
        }
        assert_eq!(Op::of(0), None);
        assert_eq!(Op::of(7), None);
        assert_eq!(Status::of(6), None);
    }

    #[test]
    fn the_layout_fits_the_region_and_the_magic_reads() {
        assert_eq!(MAGIC.to_le_bytes(), *b"O89M");
        assert!(offset::DATA as usize + DATA_BYTES <= MAILBOX_BYTES);
        assert_eq!(MAILBOX_ADDRESS % 4, 0);
    }
}
