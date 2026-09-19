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

/// Where the mailbox sits in the controller's RAM: the last 8 KiB, which
/// `memory.x` keeps out of the stack and the runtime never zeroes.
pub const MAILBOX_ADDRESS: u32 = 0x2002_2000;

/// The bytes the mailbox takes: the request and its data, then the two
/// rings the bridge to the module runs on.
pub const MAILBOX_BYTES: usize = 8192;

/// The word at offset zero when a mailbox is there: `O89M`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"O89M");

/// The protocol's version, at offset four.
pub const VERSION: u32 = 2;

/// Bytes of data a request or an answer carries: enough for the client
/// table's record in one write.
pub const DATA_BYTES: usize = 2048;

/// Bytes each bridge ring holds. One byte of each is never used, which is
/// how a full ring and an empty one are told apart.
pub const RING_BYTES: usize = 2048;

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
    /// The bridge, host to module: the host's write index.
    pub const TO_MODULE_WRITE: u32 = 2084;
    /// The bridge, host to module: the firmware's read index.
    pub const TO_MODULE_READ: u32 = 2088;
    /// The bridge, host to module: the bytes.
    pub const TO_MODULE_DATA: u32 = 2092;
    /// The bridge, module to host: the firmware's write index.
    pub const FROM_MODULE_WRITE: u32 = 4140;
    /// The bridge, module to host: the host's read index.
    pub const FROM_MODULE_READ: u32 = 4144;
    /// The bridge, module to host: the bytes.
    pub const FROM_MODULE_DATA: u32 = 4148;
    /// The host's lease on the bridge: a number the host changes about
    /// once a second while it holds the bridge. The firmware closes a
    /// bridge whose lease has not changed for a minute, so a host that
    /// died, lost power or lost its probe does not hold the module in its
    /// ROM; the module's own bytes are no sign of a host.
    pub const BRIDGE_LEASE: u32 = 6196;
    /// The first byte past the mailbox.
    pub const END: u32 = 6200;
}

// The offsets above are literals so that both sides read them as numbers;
// these say they are the layout the sizes describe.
const _: () = {
    assert!(offset::TO_MODULE_WRITE as usize == offset::DATA as usize + DATA_BYTES);
    assert!(offset::FROM_MODULE_WRITE as usize == offset::TO_MODULE_DATA as usize + RING_BYTES);
    assert!(offset::BRIDGE_LEASE as usize == offset::FROM_MODULE_DATA as usize + RING_BYTES);
    assert!(offset::END as usize == offset::BRIDGE_LEASE as usize + 4);
};
const _: () = assert!(offset::END as usize <= MAILBOX_BYTES);

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
    /// Put the module into its ROM's serial download mode and bridge its
    /// UART to the rings. `ARG0` is the reason, as the registry numbers
    /// it; `ARG1` is the [`DownloadEntry`], the route in. A number either
    /// does not name is refused as out of range.
    Download,
    /// End the bridge: reset the module normally and give the link back.
    Normal,
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
            Self::Download => 7,
            Self::Normal => 8,
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
            7 => Some(Self::Download),
            8 => Some(Self::Normal),
            _ => None,
        }
    }
}

/// The route into the module's ROM a download request takes. The ROM never
/// waits in its loader by itself: a module with no bootable app reboots
/// through its second-stage bootloader forever, and one with no bootloader
/// loops on an invalid header, so a plain reset only listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DownloadEntry {
    /// Reset the module normally and bridge whatever it says: a listen.
    Reset,
    /// Knock at the window the comms firmware opens (KM43 L-190 to L-192).
    Knock,
    /// Hold IO9 low across the reset: the ROM's strapping route, reached as
    /// the board's [`crate::StrapRoute`] says.
    Strap,
}

impl DownloadEntry {
    /// The number `ARG1` carries.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Reset => 0,
            Self::Knock => 1,
            Self::Strap => 2,
        }
    }

    /// The entry a number names, if any.
    #[must_use]
    pub const fn of(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Reset),
            1 => Some(Self::Knock),
            2 => Some(Self::Strap),
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
    /// The module did not answer `EnterDownload` inside the window.
    NoModuleAnswer,
    /// The link task did not answer the request in time.
    LinkBusy,
    /// The controller booted without its store: no `boot_id` and no link
    /// (F-039). Nothing on the link is served.
    NoStore,
    /// USART1 refused the ROM's configuration: the module was reset
    /// normally and nothing was bridged.
    BridgeRefused,
    /// The module answered `refused_outside_window` (L-191): it is running
    /// an image whose window had closed when the knock arrived.
    ModuleRefused,
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
            Self::NoModuleAnswer => 6,
            Self::LinkBusy => 7,
            Self::NoStore => 8,
            Self::BridgeRefused => 9,
            Self::ModuleRefused => 10,
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
            6 => Some(Self::NoModuleAnswer),
            7 => Some(Self::LinkBusy),
            8 => Some(Self::NoStore),
            9 => Some(Self::BridgeRefused),
            10 => Some(Self::ModuleRefused),
            _ => None,
        }
    }
}

/// One bridge ring's arithmetic, shared by the firmware over its atomics
/// and the host over the probe: a single writer and a single reader, each
/// owning one index, the ring full when the write index is one behind the
/// read index. Refuses rather than overwrites: a writer with no room writes
/// nothing, and a reader with nothing reads nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ring;

impl Ring {
    /// Bytes waiting to be read.
    #[must_use]
    pub fn available(write: u32, read: u32) -> usize {
        let (write, read) = (Self::index(write), Self::index(read));
        write
            .wrapping_sub(read)
            .wrapping_add(RING_BYTES)
            .checked_rem(RING_BYTES)
            .unwrap_or(0)
    }

    /// Bytes a writer may add before the ring is full.
    #[must_use]
    pub fn room(write: u32, read: u32) -> usize {
        RING_BYTES
            .saturating_sub(1)
            .saturating_sub(Self::available(write, read))
    }

    /// An index advanced by `count`, wrapping at the ring's end.
    #[must_use]
    pub fn advanced(index: u32, count: usize) -> u32 {
        let next = Self::index(index)
            .wrapping_add(count)
            .checked_rem(RING_BYTES)
            .unwrap_or(0);
        u32::try_from(next).unwrap_or(0)
    }

    /// The bytes from `index` a writer or reader may touch in one go before
    /// the ring's end, bounded by `count`.
    #[must_use]
    pub fn contiguous(index: u32, count: usize) -> usize {
        let to_end = RING_BYTES.saturating_sub(Self::index(index));
        count.min(to_end)
    }

    /// An index as the ring holds it, whatever the word said.
    #[must_use]
    pub fn index(raw: u32) -> usize {
        usize::try_from(raw)
            .unwrap_or(0)
            .checked_rem(RING_BYTES)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_counts_its_bytes_and_its_room_on_both_sides_of_the_wrap() {
        assert_eq!(Ring::available(0, 0), 0);
        assert_eq!(Ring::room(0, 0), RING_BYTES - 1);
        assert_eq!(Ring::available(10, 0), 10);
        assert_eq!(Ring::available(5, 2040), RING_BYTES - 2040 + 5);
        assert_eq!(Ring::room(5, 6), 0, "one behind the reader is full");
        assert_eq!(Ring::advanced(2046, 4), 2);
        assert_eq!(Ring::contiguous(2040, 100), 8);
        assert_eq!(Ring::contiguous(0, 100), 100);
    }

    #[test]
    fn an_index_past_the_ring_is_read_modulo_the_ring() {
        let raw = u32::try_from(RING_BYTES).expect("fits") + 7;
        assert_eq!(Ring::index(raw), 7);
        assert_eq!(Ring::available(raw, 0), 7);
    }

    #[test]
    fn the_rings_sit_inside_the_region_after_the_data() {
        assert!(offset::TO_MODULE_WRITE as usize >= offset::DATA as usize + DATA_BYTES);
        assert_eq!(
            offset::END as usize,
            MAILBOX_BYTES - (MAILBOX_BYTES - offset::END as usize)
        );
        assert!(offset::END as usize <= MAILBOX_BYTES);
        assert_eq!(MAILBOX_ADDRESS % 4, 0);
    }

    #[test]
    fn every_operation_and_status_round_trips_through_its_word() {
        for op in [
            Op::Ping,
            Op::ReadFram,
            Op::WriteFram,
            Op::ReadNor,
            Op::EraseNorBlock,
            Op::Reboot,
            Op::Download,
            Op::Normal,
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
            Status::NoModuleAnswer,
            Status::LinkBusy,
            Status::NoStore,
            Status::BridgeRefused,
            Status::ModuleRefused,
        ] {
            assert_eq!(Status::of(status.code()), Some(status));
        }
        assert_eq!(Op::of(0), None);
        assert_eq!(Op::of(9), None);
        assert_eq!(Status::of(11), None);
        for entry in [
            DownloadEntry::Reset,
            DownloadEntry::Knock,
            DownloadEntry::Strap,
        ] {
            assert_eq!(DownloadEntry::of(entry.code()), Some(entry));
        }
        assert_eq!(DownloadEntry::of(3), None);
    }

    #[test]
    fn the_layout_fits_the_region_and_the_magic_reads() {
        assert_eq!(MAGIC.to_le_bytes(), *b"O89M");
        assert!(offset::DATA as usize + DATA_BYTES <= MAILBOX_BYTES);
        assert!(offset::END as usize <= MAILBOX_BYTES);
        assert_eq!(
            offset::BRIDGE_LEASE % 4,
            0,
            "the lease is a word the probe writes whole"
        );
        assert_eq!(MAILBOX_ADDRESS % 4, 0);
    }
}
