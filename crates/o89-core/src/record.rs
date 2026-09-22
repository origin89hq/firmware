//! One record on NOR: the seventeen bytes around a payload, and the two
//! rules that stop a damaged log lying.
//!
//! ```text
//! [ magic: u16 | len: u16 | seq: u64 | class: u8 | payload | crc32 ]
//!   ^ programmed LAST
//! ```
//!
//! **The magic is programmed last.** NOR programs 1→0 over a block erased
//! to `0xFF`, so a record is written body-first and becomes findable only
//! when its magic lands. A write torn by a power cut leaves a record with
//! no magic, which the scan reads as the tail. No half-record is ever
//! readable, and that is a property of the write order rather than of a
//! flag somebody has to remember to set. The CRC covers everything after
//! the magic, because the magic is not there when the CRC is computed.
//!
//! **A damaged record is not stepped over by its own length.** The length
//! is inside the CRC, so it can only be checked after it has been trusted;
//! a scan that resynchronised by it would turn one flipped bit into the
//! loss of every record after it in the block. The scan hunts forward for
//! the next magic and verifies each candidate. This cost the old firmware
//! a defect.
//!
//! Nothing here touches a part. This frames a record into a buffer and
//! reads one back out of bytes; [`Ring`](crate::Ring) is what moves them.
//!
//! cites: F-023

use crc::{CRC_32_ISO_HDLC, Crc};

/// What a record's header says it is.
///
/// Not `0xFFFF`, which is what an erased block reads as: a magic
/// indistinguishable from erasure would make every empty block look like
/// a record. Not `0x0000` either: a block that failed to erase reads as
/// zeroes.
pub const MAGIC: u16 = 0x8901;

/// The two bytes of the magic, as they sit on the part.
pub const MAGIC_BYTES: [u8; 2] = MAGIC.to_le_bytes();

/// Bytes a record costs beyond its payload: the magic, the length, the
/// sequence number, the class byte and the CRC.
pub const OVERHEAD: usize = 2 + 2 + 8 + 1 + 4;

/// The bytes before the payload.
pub const HEADER: usize = 2 + 2 + 8 + 1;

/// The largest payload one record may carry.
///
/// A record is one log entry, and an entry a client cannot fit in a page is
/// one no client can read. Kept well under the page cap so a page always
/// holds more than one.
pub const MAX_PAYLOAD: usize = 256;

/// The bytes the largest record takes, which is the scratch a scan needs.
pub const MAX_RECORD: usize = OVERHEAD + MAX_PAYLOAD;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Whether a record may be shed when the ring is under pressure.
///
/// The byte on the part, so a scan can decide what to keep without knowing
/// what kind the record is: the kind is in the payload, and the whole point
/// of the class byte is that shedding must not require parsing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Class {
    /// Never dropped: state changes, commands and their outcomes, alarms,
    /// configuration changes, boot records, faults.
    A,
    /// Dropped first, with a marker recording how many: aggregates,
    /// diagnostics, telemetry.
    B,
}

impl Class {
    /// Two values far apart rather than 0 and 1, so a byte that failed to
    /// program cleanly is a record this build refuses rather than one it
    /// reads as the wrong class and sheds.
    const A_BYTE: u8 = 0xA0;
    const B_BYTE: u8 = 0xB0;

    /// The byte on the part.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::A => Self::A_BYTE,
            Self::B => Self::B_BYTE,
        }
    }

    /// The class a byte names, or nothing for one no build allocated.
    #[must_use]
    pub const fn of(byte: u8) -> Option<Self> {
        match byte {
            Self::A_BYTE => Some(Self::A),
            Self::B_BYTE => Some(Self::B),
            _ => None,
        }
    }
}

/// Why a record could not be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Unframed {
    /// A payload longer than [`MAX_PAYLOAD`].
    PayloadTooLong(usize),
    /// The buffer offered is smaller than the record.
    NoRoom {
        /// What the record needs.
        needs: usize,
        /// What was offered.
        has: usize,
    },
    /// Sequence numbers are positions, and zero is not one.
    ZeroIsNotAPosition,
}

/// The bytes a record takes for a payload of `payload` bytes.
#[must_use]
pub const fn framed_len(payload: usize) -> usize {
    OVERHEAD.saturating_add(payload)
}

/// A record framed into a buffer: the body ready to land, the magic held
/// back until it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a record framed and not written is an event the log never saw"]
pub struct Framed {
    len: usize,
}

impl Framed {
    /// The whole record's length, magic included.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Never: a record is at least its overhead.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// The body: everything after the magic, which is what lands first.
    #[must_use]
    pub fn body(self, buffer: &[u8]) -> &[u8] {
        buffer.get(2..self.len).unwrap_or(&[])
    }
}

/// Frame `payload` as record `seq` of `class` into `buffer`: the length,
/// the sequence, the class, the payload and the CRC over all of them, with
/// the magic in place at the front for the writer to land last.
pub fn frame(
    buffer: &mut [u8],
    seq: u64,
    class: Class,
    payload: &[u8],
) -> Result<Framed, Unframed> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Unframed::PayloadTooLong(payload.len()));
    }
    if seq == 0 {
        return Err(Unframed::ZeroIsNotAPosition);
    }
    let needs = framed_len(payload.len());
    let has = buffer.len();
    let room = buffer
        .get_mut(..needs)
        .ok_or(Unframed::NoRoom { needs, has })?;
    let len = u16::try_from(payload.len()).map_err(|_| Unframed::PayloadTooLong(payload.len()))?;
    let (head, rest) = room.split_at_mut(HEADER);
    let (payload_room, crc_room) = rest.split_at_mut(payload.len());
    // The magic in front, then the bytes the CRC covers, in order.
    let mut fields = [0u8; HEADER];
    fields[..2].copy_from_slice(&MAGIC_BYTES);
    fields[2..4].copy_from_slice(&len.to_le_bytes());
    fields[4..12].copy_from_slice(&seq.to_le_bytes());
    fields[12] = class.byte();
    head.copy_from_slice(&fields);
    payload_room.copy_from_slice(payload);
    let mut digest = CRC32.digest();
    digest.update(fields.get(2..).unwrap_or(&[]));
    digest.update(payload);
    crc_room.copy_from_slice(&digest.finalize().to_le_bytes());
    Ok(Framed { len: needs })
}

/// What the header of a candidate record says, before its CRC is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The payload's length.
    pub len: usize,
    /// The sequence number.
    pub seq: u64,
    /// The class byte, decoded.
    pub class: Option<Class>,
}

impl Header {
    /// Read a header out of the first [`HEADER`] bytes, or nothing when the
    /// magic is not there.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let head: [u8; HEADER] = bytes.get(..HEADER)?.try_into().ok()?;
        if head[..2] != MAGIC_BYTES {
            return None;
        }
        let len = usize::from(u16::from_le_bytes([head[2], head[3]]));
        let seq = u64::from_le_bytes([
            head[4], head[5], head[6], head[7], head[8], head[9], head[10], head[11],
        ]);
        Some(Self {
            len,
            seq,
            class: Class::of(head[12]),
        })
    }

    /// The whole record's length, if the header is plausible: a payload
    /// under the cap and a class this build can read.
    #[must_use]
    pub const fn record_len(&self) -> Option<usize> {
        if self.len > MAX_PAYLOAD || self.class.is_none() || self.seq == 0 {
            return None;
        }
        Some(framed_len(self.len))
    }
}

/// A record read back whole and verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found<'a> {
    /// The sequence number.
    pub seq: u64,
    /// The class.
    pub class: Class,
    /// The payload.
    pub payload: &'a [u8],
}

/// Verify the record at the start of `bytes` and hand it back, or nothing
/// when the magic, the header or the CRC does not hold.
#[must_use]
pub fn verify(bytes: &[u8]) -> Option<Found<'_>> {
    let header = Header::parse(bytes)?;
    let len = header.record_len()?;
    let record = bytes.get(..len)?;
    let class = header.class?;
    let covered = record.get(2..len.saturating_sub(4))?;
    let crc = u32::from_le_bytes(record.get(len.saturating_sub(4)..)?.try_into().ok()?);
    if CRC32.checksum(covered) != crc {
        return None;
    }
    Some(Found {
        seq: header.seq,
        class,
        payload: record.get(HEADER..len.saturating_sub(4))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_023_a_record_costs_seventeen_bytes_and_reads_back_whole() {
        let mut buffer = [0u8; MAX_RECORD];
        let framed = frame(&mut buffer, 7, Class::A, b"boot").expect("frames");
        assert_eq!(framed.len(), 17 + 4);
        assert_eq!(OVERHEAD, 17);
        assert_eq!(
            verify(&buffer),
            Some(Found {
                seq: 7,
                class: Class::A,
                payload: b"boot"
            })
        );
        // The body is what lands first: everything after the magic.
        assert_eq!(framed.body(&buffer).len(), 19);
        assert_eq!(&buffer[..2], &MAGIC_BYTES);
    }

    #[test]
    fn f_023_a_record_without_its_magic_is_not_a_record() {
        let mut buffer = [0u8; MAX_RECORD];
        let _ = frame(&mut buffer, 7, Class::B, b"aggregate").expect("frames");
        buffer[..2].copy_from_slice(&[0xFF, 0xFF]);
        assert_eq!(verify(&buffer), None);
        assert_eq!(Header::parse(&buffer), None);
    }

    #[test]
    fn f_023_a_flipped_bit_anywhere_after_the_magic_fails_the_crc() {
        let mut buffer = [0u8; MAX_RECORD];
        let framed = frame(&mut buffer, 9, Class::A, b"state").expect("frames");
        for bit in 16..framed.len() * 8 {
            let mut damaged = buffer;
            damaged[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&damaged), None, "bit {bit}");
        }
    }

    #[test]
    fn a_payload_past_the_cap_a_zero_sequence_or_a_short_buffer_is_refused() {
        let mut buffer = [0u8; MAX_RECORD];
        let long = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            frame(&mut buffer, 1, Class::A, &long),
            Err(Unframed::PayloadTooLong(MAX_PAYLOAD + 1))
        );
        assert_eq!(
            frame(&mut buffer, 0, Class::A, b"x"),
            Err(Unframed::ZeroIsNotAPosition)
        );
        assert_eq!(
            frame(&mut buffer[..10], 1, Class::A, b"x"),
            Err(Unframed::NoRoom { needs: 18, has: 10 })
        );
        // The largest payload frames and reads back.
        let full = [0x5Au8; MAX_PAYLOAD];
        let framed = frame(&mut buffer, u64::MAX, Class::B, &full).expect("frames");
        assert_eq!(framed.len(), MAX_RECORD);
        assert_eq!(verify(&buffer).map(|f| f.payload.len()), Some(MAX_PAYLOAD));
    }

    #[test]
    fn a_class_byte_nobody_allocated_is_a_record_this_build_refuses() {
        let mut buffer = [0u8; MAX_RECORD];
        let _ = frame(&mut buffer, 3, Class::A, b"x").expect("frames");
        buffer[12] = 0x01;
        let header = Header::parse(&buffer).expect("the magic is there");
        assert_eq!(header.class, None);
        assert_eq!(header.record_len(), None);
        assert_eq!(verify(&buffer), None);
    }
}
