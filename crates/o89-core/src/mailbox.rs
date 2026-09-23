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
//! One operation reads records rather than bytes: [`Op::ReadRing`] walks the
//! event ring with the ring's own reader, because the ring is the one thing
//! that knows where it starts and ends, and a host walking 3712 blocks a
//! request at a time would take minutes to find a head the firmware already
//! holds. What the records say is still the host's business.
//!
//! This is the layout both sides share; the address is where the
//! controller's linker puts it, stated here so the two cannot disagree.

use crate::record::{Class, MAX_PAYLOAD};
use crate::ring::Dropped;

/// Where the mailbox sits in the controller's RAM: the last 8 KiB, which
/// `memory.x` keeps out of the stack and the runtime never zeroes.
pub const MAILBOX_ADDRESS: u32 = 0x2002_2000;

/// The bytes the mailbox takes: the request and its data, then the two
/// rings the bridge to the module runs on.
pub const MAILBOX_BYTES: usize = 8192;

/// The word at offset zero when a mailbox is there: `O89M`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"O89M");

/// The protocol's version, at offset four. A host that reads another
/// refuses the part, because an operation's meaning can change under the
/// same number: 3 is where `EraseNorBlock` stopped erasing the ring's own
/// blocks (#78), and a newer host that took a version 2 part's erase for
/// a refusing one would recreate the hole it exists to prevent.
pub const VERSION: u32 = 3;

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
    /// Erase the NOR block `ARG0`, which has to lie outside the ring:
    /// the ring's own are refused with [`Status::InsideTheRing`] (#78).
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
    /// The ring's records from the sequence `ARG1 << 32 | ARG0`, oldest
    /// first, as many as the data holds, laid out as a [`RingPage`].
    ReadRing,
    /// Erase the ring's oldest block, answered as a [`DropAnswer`].
    DropOldest,
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
            Self::ReadRing => 9,
            Self::DropOldest => 10,
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
            9 => Some(Self::ReadRing),
            10 => Some(Self::DropOldest),
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
    /// A block of the ring's own, which only [`Op::DropOldest`] erases.
    InsideTheRing,
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
            Self::InsideTheRing => 11,
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
            11 => Some(Self::InsideTheRing),
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

/// The answer to [`Op::ReadRing`]: a header, then the records.
///
/// ```text
/// [ ring_next: u64 | oldest: u64, 0 for none | next: u64 ]
/// [ seq: u64 | class: u8 | len: u16 | payload ] ...
/// ```
///
/// `ring_next` is the sequence the ring hands out next, so a host asking
/// for the newest records knows where they end; `oldest` is the first it
/// still holds; `next` is what to ask for to continue. Zero is never a
/// sequence, so it can say *none* for `oldest`. Every integer is
/// little-endian. The firmware writes an entry only while one more at its
/// largest still fits, so a page never cuts a record short and the ring's
/// `next` never skips one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingPage {
    /// The sequence the ring hands out next.
    pub ring_next: u64,
    /// The first sequence the ring still holds, if any.
    pub oldest: Option<u64>,
    /// The sequence to ask for next.
    pub next: u64,
}

/// One record in a [`RingPage`], as the ring verified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingEntry<'a> {
    /// The record's sequence.
    pub seq: u64,
    /// Its class.
    pub class: Class,
    /// Its payload: an encoded KM43 event.
    pub payload: &'a [u8],
}

/// Why a [`RingPage`] could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageError {
    /// Fewer bytes than the header.
    Short,
    /// An entry cut short, at this offset.
    Truncated(usize),
    /// A class byte no build allocated, at this offset.
    Class(usize),
    /// A payload longer than the ring allows, at this offset.
    TooLong(usize),
}

impl RingPage {
    /// A sequence as the two argument words carry it: `ARG0` the low half,
    /// `ARG1` the high.
    #[must_use]
    pub fn args(from: u64) -> (u32, u32) {
        let lo = u32::try_from(from & 0xFFFF_FFFF).unwrap_or(0);
        let hi = u32::try_from(from.checked_shr(32).unwrap_or(0)).unwrap_or(0);
        (lo, hi)
    }

    /// The sequence two argument words carry.
    #[must_use]
    pub fn from_args(lo: u32, hi: u32) -> u64 {
        u64::from(hi).checked_shl(32).unwrap_or(0) | u64::from(lo)
    }

    /// The header's bytes.
    pub const HEADER: usize = 24;
    /// The bytes in front of each payload.
    pub const ENTRY_HEAD: usize = 11;

    /// The header as it sits at the start of the data.
    #[must_use]
    pub fn header(self) -> [u8; Self::HEADER] {
        let mut out = [0u8; Self::HEADER];
        let words = [self.ring_next, self.oldest.unwrap_or(0), self.next];
        for (slot, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *slot = word.to_le_bytes();
        }
        out
    }

    /// The bytes in front of one entry's payload, or nothing for a payload
    /// longer than a record may carry.
    #[must_use]
    pub fn entry_head(seq: u64, class: Class, len: usize) -> Option<[u8; Self::ENTRY_HEAD]> {
        if len > MAX_PAYLOAD {
            return None;
        }
        let len = u16::try_from(len).ok()?;
        let mut out = [0u8; Self::ENTRY_HEAD];
        let (seq_room, rest) = out.split_at_mut(8);
        seq_room.copy_from_slice(&seq.to_le_bytes());
        let (class_room, len_room) = rest.split_at_mut(1);
        class_room.copy_from_slice(&[class.byte()]);
        len_room.copy_from_slice(&len.to_le_bytes());
        Some(out)
    }

    /// Whether another entry, at its largest, fits after `used` bytes.
    #[must_use]
    pub const fn room_after(used: usize) -> bool {
        used.saturating_add(Self::ENTRY_HEAD)
            .saturating_add(MAX_PAYLOAD)
            <= DATA_BYTES
    }

    /// Read a page: the header, and the entries after it, each checked as
    /// it is read.
    pub fn read(
        data: &[u8],
    ) -> Result<(Self, impl Iterator<Item = Result<RingEntry<'_>, PageError>>), PageError> {
        let word = |at: usize| -> Result<u64, PageError> {
            let bytes: [u8; 8] = data
                .get(at..at.saturating_add(8))
                .and_then(|b| b.try_into().ok())
                .ok_or(PageError::Short)?;
            Ok(u64::from_le_bytes(bytes))
        };
        let page = Self {
            ring_next: word(0)?,
            oldest: Some(word(8)?).filter(|oldest| *oldest != 0),
            next: word(16)?,
        };
        let mut at = Self::HEADER;
        let mut failed = false;
        let entries = core::iter::from_fn(move || {
            if failed || at >= data.len() {
                return None;
            }
            let entry = Self::entry(data, at);
            match entry {
                Ok((found, end)) => {
                    at = end;
                    Some(Ok(found))
                }
                Err(why) => {
                    failed = true;
                    Some(Err(why))
                }
            }
        });
        Ok((page, entries))
    }

    fn entry(data: &[u8], at: usize) -> Result<(RingEntry<'_>, usize), PageError> {
        let head = data
            .get(at..at.saturating_add(Self::ENTRY_HEAD))
            .ok_or(PageError::Truncated(at))?;
        let (seq, rest) = head.split_at(8);
        let (class, len) = rest.split_at(1);
        let seq = u64::from_le_bytes(seq.try_into().map_err(|_| PageError::Truncated(at))?);
        let class = class
            .first()
            .and_then(|byte| Class::of(*byte))
            .ok_or(PageError::Class(at))?;
        let len = usize::from(u16::from_le_bytes(
            len.try_into().map_err(|_| PageError::Truncated(at))?,
        ));
        if len > MAX_PAYLOAD {
            return Err(PageError::TooLong(at));
        }
        let from = at.saturating_add(Self::ENTRY_HEAD);
        let end = from.saturating_add(len);
        let payload = data.get(from..end).ok_or(PageError::Truncated(at))?;
        Ok((
            RingEntry {
                seq,
                class,
                payload,
            },
            end,
        ))
    }
}

/// The answer to [`Op::DropOldest`]: nothing when the ring held no
/// records, else the block erased, counted within the ring, and the oldest
/// sequence left, zero for none, both little-endian.
///
/// ```text
/// [ block: u32 | oldest: u64 ]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropAnswer;

impl DropAnswer {
    /// The bytes of an answer that dropped a block.
    pub const BYTES: usize = 12;

    /// What the firmware lands in the data: nothing for
    /// [`Dropped::Nothing`], twelve bytes for a block.
    #[must_use]
    pub fn encode(dropped: Dropped) -> Option<[u8; Self::BYTES]> {
        match dropped {
            Dropped::Nothing => None,
            Dropped::Block { block, oldest } => {
                let mut out = [0u8; Self::BYTES];
                let (block_room, oldest_room) = out.split_at_mut(4);
                block_room.copy_from_slice(&block.to_le_bytes());
                oldest_room.copy_from_slice(&oldest.unwrap_or(0).to_le_bytes());
                Some(out)
            }
        }
    }

    /// What the host reads back, or nothing for an answer of any length
    /// but zero or twelve.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Dropped> {
        if data.is_empty() {
            return Some(Dropped::Nothing);
        }
        let bytes: &[u8; Self::BYTES] = data.try_into().ok()?;
        let (block, oldest) = bytes.split_at(4);
        let block = u32::from_le_bytes(block.try_into().ok()?);
        let oldest = u64::from_le_bytes(oldest.try_into().ok()?);
        Some(Dropped::Block {
            block,
            oldest: Some(oldest).filter(|oldest| *oldest != 0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drop_answer_reads_back_whatever_the_drop_did_and_refuses_any_other_length() {
        let cases = [
            Dropped::Nothing,
            Dropped::Block {
                block: 3,
                oldest: Some(1_216),
            },
            Dropped::Block {
                block: 0,
                oldest: None,
            },
            Dropped::Block {
                block: u32::MAX,
                oldest: Some(u64::MAX),
            },
        ];
        for dropped in cases {
            let bytes = DropAnswer::encode(dropped);
            let data: &[u8] = bytes.as_ref().map_or(&[], |b| b.as_slice());
            assert_eq!(DropAnswer::decode(data), Some(dropped), "{dropped:?}");
        }
        assert_eq!(DropAnswer::decode(&[0; 11]), None);
        assert_eq!(DropAnswer::decode(&[0; 13]), None);
    }

    /// A page as the firmware lays it out, from `(seq, class, payload)`.
    fn page(header: RingPage, entries: &[(u64, Class, &[u8])], out: &mut [u8]) -> usize {
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            let end = at.saturating_add(bytes.len());
            out[at..end].copy_from_slice(bytes);
            at = end;
        };
        put(&header.header());
        for (seq, class, payload) in entries {
            put(&RingPage::entry_head(*seq, *class, payload.len()).expect("a record's length"));
            put(payload);
        }
        at
    }

    #[test]
    fn a_ring_page_reads_back_its_header_and_every_entry_in_order() {
        let header = RingPage {
            ring_next: 1219,
            oldest: Some(1),
            next: 1219,
        };
        let big = [0x5A; MAX_PAYLOAD];
        let mut data = [0u8; DATA_BYTES];
        let len = page(
            header,
            &[(1216, Class::A, b"boot"), (1218, Class::B, &big)],
            &mut data,
        );
        let (read, entries) = RingPage::read(&data[..len]).expect("a header");
        assert_eq!(read, header);
        let entries: [Result<RingEntry<'_>, PageError>; 2] = {
            let mut it = entries;
            [it.next().expect("one"), it.next().expect("two")]
        };
        assert_eq!(
            entries[0],
            Ok(RingEntry {
                seq: 1216,
                class: Class::A,
                payload: b"boot"
            })
        );
        let second = entries[1].expect("the largest record");
        assert_eq!((second.seq, second.class), (1218, Class::B));
        assert_eq!(
            second.payload.len(),
            MAX_PAYLOAD,
            "a hole in seq is not a hole in the page"
        );
    }

    #[test]
    fn an_empty_ring_is_a_header_with_no_oldest_and_no_entries() {
        let header = RingPage {
            ring_next: 1,
            oldest: None,
            next: 1,
        };
        let bytes = header.header();
        assert_eq!(
            &bytes[8..16],
            &[0; 8],
            "none is zero, which is never a sequence"
        );
        let (read, mut entries) = RingPage::read(&bytes).expect("a header");
        assert_eq!(read, header);
        assert!(entries.next().is_none());
        assert_eq!(
            RingPage::read(&bytes[..23]).map(|(p, _)| p),
            Err(PageError::Short)
        );
    }

    #[test]
    fn a_page_cut_short_or_carrying_a_class_nobody_allocated_stops_at_the_entry() {
        let header = RingPage {
            ring_next: 3,
            oldest: Some(1),
            next: 3,
        };
        let mut data = [0u8; 128];
        let len = page(
            header,
            &[(1, Class::A, b"one"), (2, Class::A, b"two")],
            &mut data,
        );
        // Every cut inside the second entry is refused, and the first survives.
        let second = RingPage::HEADER + RingPage::ENTRY_HEAD + 3;
        for cut in second + 1..len {
            let (_, mut entries) = RingPage::read(&data[..cut]).expect("a header");
            assert!(entries.next().expect("the first").is_ok());
            assert_eq!(
                entries.next(),
                Some(Err(PageError::Truncated(second))),
                "cut at {cut}"
            );
            assert!(entries.next().is_none(), "reading past a refusal");
        }
        let mut damaged = data;
        damaged[second + 8] = 0x01;
        let (_, mut entries) = RingPage::read(&damaged[..len]).expect("a header");
        assert!(entries.next().expect("the first").is_ok());
        assert_eq!(entries.next(), Some(Err(PageError::Class(second))));
        let mut long = data;
        long[second + 9..second + 11].copy_from_slice(&300u16.to_le_bytes());
        let (_, mut entries) = RingPage::read(&long[..len]).expect("a header");
        assert!(entries.next().expect("the first").is_ok());
        assert_eq!(entries.next(), Some(Err(PageError::TooLong(second))));
    }

    #[test]
    fn a_sequence_crosses_the_two_argument_words_whole() {
        for seq in [
            0,
            1,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0x0123_4567_89AB_CDEF,
            u64::MAX,
        ] {
            let (lo, hi) = RingPage::args(seq);
            assert_eq!(RingPage::from_args(lo, hi), seq);
        }
        assert_eq!(
            RingPage::args(0x0000_0002_0000_0001),
            (1, 2),
            "low half first"
        );
    }

    #[test]
    fn a_page_holds_another_record_only_while_the_largest_still_fits() {
        assert!(RingPage::room_after(RingPage::HEADER));
        let last = DATA_BYTES - RingPage::ENTRY_HEAD - MAX_PAYLOAD;
        assert!(RingPage::room_after(last));
        assert!(!RingPage::room_after(last + 1));
        assert!(!RingPage::room_after(usize::MAX));
        assert_eq!(RingPage::entry_head(1, Class::A, MAX_PAYLOAD + 1), None);
        assert!(RingPage::entry_head(1, Class::A, MAX_PAYLOAD).is_some());
    }

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
            Op::ReadRing,
            Op::DropOldest,
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
            Status::InsideTheRing,
        ] {
            assert_eq!(Status::of(status.code()), Some(status));
        }
        assert_eq!(Op::of(0), None);
        assert_eq!(Op::of(11), None);
        assert_eq!(Status::of(12), None);
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
