//! The DNS message format as multicast DNS uses it (RFC 1035 §4, RFC 6762
//! §18): a header, then questions and records whose names may point back
//! into the message.
//!
//! Nothing here allocates. A reader walks a packet in place and refuses
//! one that runs past its end, points forward or loops; a writer fills a
//! fixed buffer and refuses what does not fit. Names this side writes are
//! never compressed: every message it sends fits its buffer without it.

/// A record or question type, as the wire numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Type(pub(super) u16);

impl Type {
    pub(super) const A: Self = Self(1);
    pub(super) const PTR: Self = Self(12);
    pub(super) const TXT: Self = Self(16);
    pub(super) const SRV: Self = Self(33);
    pub(super) const ANY: Self = Self(255);
}

/// The internet class, the only one multicast DNS carries.
pub(super) const CLASS_IN: u16 = 1;
/// The top bit of a record's class: the cache-flush bit (RFC 6762 §10.2).
pub(super) const CACHE_FLUSH: u16 = 0x8000;
/// The top bit of a question's class: a unicast response is asked for
/// (RFC 6762 §5.4).
pub(super) const UNICAST_RESPONSE: u16 = 0x8000;
/// The header's response bit.
pub(super) const QR: u16 = 0x8000;
/// A response from the authority for its names (RFC 6762 §18.4).
pub(super) const AUTHORITATIVE: u16 = 0x0400;
/// The header: id, flags and four counts.
pub(super) const HEADER_BYTES: usize = 12;

/// Pointers followed in one name before it is refused as a loop.
const JUMPS: usize = 16;
/// Labels read in one name, pointers included: a name is at most 255
/// bytes, so at most 127 labels of one byte.
const LABELS: usize = 128;
/// A pointer's two high bits.
const POINTER: u8 = 0xC0;

/// A packet that does not read as a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed;

/// A message that does not fit its buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Full;

/// A name as this side knows it: its labels, most specific first.
pub(super) type Name<'a> = [&'a [u8]];

/// The header of a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) id: u16,
    pub(super) flags: u16,
    pub(super) questions: u16,
    pub(super) answers: u16,
    pub(super) authorities: u16,
    pub(super) additionals: u16,
}

impl Header {
    pub(super) fn read(packet: &[u8]) -> Result<Self, Malformed> {
        Ok(Self {
            id: u16_at(packet, 0)?,
            flags: u16_at(packet, 2)?,
            questions: u16_at(packet, 4)?,
            answers: u16_at(packet, 6)?,
            authorities: u16_at(packet, 8)?,
            additionals: u16_at(packet, 10)?,
        })
    }

    pub(super) const fn is_response(&self) -> bool {
        self.flags & QR != 0
    }
}

/// A question in a received message, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Question {
    /// Where its name starts.
    pub(super) name: usize,
    pub(super) kind: Type,
    /// The class without the unicast-response bit.
    pub(super) class: u16,
    pub(super) unicast: bool,
}

/// A record in a received message, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Record {
    /// Where its name starts.
    pub(super) name: usize,
    pub(super) kind: Type,
    /// The class without the cache-flush bit.
    pub(super) class: u16,
    /// Whether the cache-flush bit was set.
    pub(super) flush: bool,
    pub(super) ttl: u32,
    /// Where its data starts, and how long it is.
    pub(super) rdata: usize,
    pub(super) rdlen: usize,
}

/// Read the question at `at`, and where the next item starts.
pub(super) fn question_at(packet: &[u8], at: usize) -> Result<(Question, usize), Malformed> {
    let fixed = skip_name(packet, at)?;
    let class = u16_at(packet, fixed.checked_add(2).ok_or(Malformed)?)?;
    let question = Question {
        name: at,
        kind: Type(u16_at(packet, fixed)?),
        class: class & !UNICAST_RESPONSE,
        unicast: class & UNICAST_RESPONSE != 0,
    };
    Ok((question, fixed.checked_add(4).ok_or(Malformed)?))
}

/// Read the record at `at`, and where the next item starts.
pub(super) fn record_at(packet: &[u8], at: usize) -> Result<(Record, usize), Malformed> {
    let fixed = skip_name(packet, at)?;
    let offset = |by: usize| fixed.checked_add(by).ok_or(Malformed);
    let rdlen = usize::from(u16_at(packet, offset(8)?)?);
    let rdata = offset(10)?;
    let next = rdata.checked_add(rdlen).ok_or(Malformed)?;
    if next > packet.len() {
        return Err(Malformed);
    }
    let class = u16_at(packet, offset(2)?)?;
    let record = Record {
        name: at,
        kind: Type(u16_at(packet, fixed)?),
        class: class & !CACHE_FLUSH,
        flush: class & CACHE_FLUSH != 0,
        ttl: u32_at(packet, offset(4)?)?,
        rdata,
        rdlen,
    };
    Ok((record, next))
}

/// Where the name at `at` ends in place: past its root label, or past the
/// pointer that finishes it.
fn skip_name(packet: &[u8], mut at: usize) -> Result<usize, Malformed> {
    for _ in 0..LABELS {
        let len = *packet.get(at).ok_or(Malformed)?;
        if len == 0 {
            return at.checked_add(1).ok_or(Malformed);
        }
        if len & POINTER == POINTER {
            return at.checked_add(2).ok_or(Malformed);
        }
        if len & POINTER != 0 {
            return Err(Malformed);
        }
        at = at
            .checked_add(1)
            .and_then(|at| at.checked_add(usize::from(len)))
            .ok_or(Malformed)?;
    }
    Err(Malformed)
}

/// Each label of the name at `at`, following pointers, handed to `label`
/// until it answers `false`. Whether every label was taken.
fn walk(
    packet: &[u8],
    mut at: usize,
    mut label: impl FnMut(&[u8]) -> bool,
) -> Result<bool, Malformed> {
    let mut jumps = 0usize;
    for _ in 0..LABELS {
        let len = *packet.get(at).ok_or(Malformed)?;
        if len == 0 {
            return Ok(true);
        }
        if len & POINTER == POINTER {
            let low = *packet
                .get(at.checked_add(1).ok_or(Malformed)?)
                .ok_or(Malformed)?;
            let target = usize::from(u16::from_be_bytes([len & !POINTER, low]));
            // A pointer only reaches back: forward is how a loop is built.
            if target >= at || jumps >= JUMPS {
                return Err(Malformed);
            }
            jumps = jumps.saturating_add(1);
            at = target;
            continue;
        }
        if len & POINTER != 0 {
            return Err(Malformed);
        }
        let start = at.checked_add(1).ok_or(Malformed)?;
        let end = start.checked_add(usize::from(len)).ok_or(Malformed)?;
        if !label(packet.get(start..end).ok_or(Malformed)?) {
            return Ok(false);
        }
        at = end;
    }
    Err(Malformed)
}

/// Whether the name at `at` is `name`, ignoring ASCII case (RFC 6762 §16).
pub(super) fn name_is(packet: &[u8], at: usize, name: &Name<'_>) -> Result<bool, Malformed> {
    let mut expected = name.iter();
    let mut differ = false;
    let whole = walk(packet, at, |label| {
        let same = expected
            .next()
            .is_some_and(|want| want.eq_ignore_ascii_case(label));
        differ |= !same;
        same
    })?;
    Ok(whole && !differ && expected.next().is_none())
}

/// Write the name at `at` uncompressed, as it would read with every
/// pointer followed.
pub(super) fn expand_name(packet: &[u8], at: usize, out: &mut Writer<'_>) -> Result<(), Malformed> {
    let mut full = false;
    walk(packet, at, |label| {
        let written = u8::try_from(label.len())
            .map_err(|_| Full)
            .and_then(|len| out.put(&[len]))
            .and_then(|()| out.put(label));
        full |= written.is_err();
        written.is_ok()
    })?;
    if full || out.put(&[0]).is_err() {
        return Err(Malformed);
    }
    Ok(())
}

/// The data of `record` with any name in it written out in full, as
/// RFC 6762 §8.2 compares it.
pub(super) fn canonical_rdata(
    packet: &[u8],
    record: &Record,
    out: &mut Writer<'_>,
) -> Result<(), Malformed> {
    let rdata = packet
        .get(record.rdata..record.rdata.checked_add(record.rdlen).ok_or(Malformed)?)
        .ok_or(Malformed)?;
    match record.kind {
        Type::PTR => expand_name(packet, record.rdata, out),
        Type::SRV => {
            // Priority, weight and port, then the target.
            let fixed = rdata.get(..6).ok_or(Malformed)?;
            out.put(fixed).map_err(|Full| Malformed)?;
            expand_name(packet, record.rdata.checked_add(6).ok_or(Malformed)?, out)
        }
        Type(_) => out.put(rdata).map_err(|Full| Malformed),
    }
}

fn u16_at(packet: &[u8], at: usize) -> Result<u16, Malformed> {
    let bytes = packet
        .get(at..at.checked_add(2).ok_or(Malformed)?)
        .ok_or(Malformed)?;
    let [high, low] = <[u8; 2]>::try_from(bytes).map_err(|_| Malformed)?;
    Ok(u16::from_be_bytes([high, low]))
}

fn u32_at(packet: &[u8], at: usize) -> Result<u32, Malformed> {
    let bytes = packet
        .get(at..at.checked_add(4).ok_or(Malformed)?)
        .ok_or(Malformed)?;
    Ok(u32::from_be_bytes(
        <[u8; 4]>::try_from(bytes).map_err(|_| Malformed)?,
    ))
}

/// A message written into a fixed buffer.
pub(super) struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub(super) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// What has been written.
    pub(super) fn written(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    pub(super) fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self.len.checked_add(bytes.len()).ok_or(Full)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(Full)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    pub(super) fn u16(&mut self, value: u16) -> Result<(), Full> {
        self.put(&value.to_be_bytes())
    }

    pub(super) fn u32(&mut self, value: u32) -> Result<(), Full> {
        self.put(&value.to_be_bytes())
    }

    /// Overwrite two bytes already written at `at`.
    pub(super) fn patch_u16(&mut self, at: usize, value: u16) -> Result<(), Full> {
        self.buf
            .get_mut(at..at.checked_add(2).ok_or(Full)?)
            .filter(|_| at.checked_add(2).is_some_and(|end| end <= self.len))
            .ok_or(Full)?
            .copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// `name` uncompressed.
    pub(super) fn name(&mut self, name: &Name<'_>) -> Result<(), Full> {
        for label in name {
            self.put(&[u8::try_from(label.len()).map_err(|_| Full)?])?;
            self.put(label)?;
        }
        self.put(&[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `origin89.local` at 12, and `x.local` pointing into it at 28.
    fn packet() -> [u8; 64] {
        let mut p = [0u8; 64];
        let name = b"\x08origin89\x05local\x00";
        p[12..28].copy_from_slice(name);
        // At 28: "x" then a pointer to "local" at 21.
        p[28..32].copy_from_slice(b"\x01x\xC0\x15");
        p
    }

    #[test]
    fn a_name_reads_in_place_and_through_a_pointer_ignoring_case() {
        let p = packet();
        assert_eq!(name_is(&p, 12, &[b"ORIGIN89", b"local"]), Ok(true));
        assert_eq!(name_is(&p, 12, &[b"origin89"]), Ok(false));
        assert_eq!(name_is(&p, 12, &[b"origin89", b"local", b"x"]), Ok(false));
        assert_eq!(name_is(&p, 28, &[b"x", b"local"]), Ok(true));
        assert_eq!(skip_name(&p, 28), Ok(32));
        assert_eq!(skip_name(&p, 12), Ok(28));
    }

    #[test]
    fn a_pointer_forward_or_a_loop_is_malformed() {
        let mut p = [0u8; 32];
        // A pointer to itself.
        p[12..14].copy_from_slice(&[0xC0, 12]);
        assert_eq!(name_is(&p, 12, &[b"a"]), Err(Malformed));
        // A pointer forward.
        p[12..14].copy_from_slice(&[0xC0, 20]);
        assert_eq!(name_is(&p, 12, &[b"a"]), Err(Malformed));
        // A label running past the end.
        p[30] = 9;
        assert_eq!(skip_name(&p, 30), Err(Malformed));
        // The reserved label kinds.
        p[12] = 0x40;
        assert_eq!(skip_name(&p, 12), Err(Malformed));
        // A name never ended, in a buffer of one-byte labels.
        let endless = [1u8; 300];
        assert_eq!(skip_name(&endless, 0), Err(Malformed));
        assert_eq!(name_is(&endless, 0, &[b"a"]), Ok(false));
    }

    #[test]
    fn a_record_past_the_packet_is_malformed() {
        let mut p = [0u8; 23];
        p[..11].copy_from_slice(b"\x01a\x00\x00\x01\x00\x01\x00\x00\x00\x78");
        // rdlength 4 with only 10 bytes of the record fixed part left.
        p[11..13].copy_from_slice(&[0, 4]);
        p[13..17].copy_from_slice(&[10, 0, 0, 1]);
        let (record, next) = record_at(&p[..17], 0).expect("whole");
        assert_eq!(
            (record.kind, record.ttl, record.rdlen, next),
            (Type::A, 120, 4, 17)
        );
        assert_eq!(record_at(&p[..16], 0), Err(Malformed));
    }

    #[test]
    fn a_writer_refuses_what_does_not_fit_and_keeps_what_did() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.name(&[b"ab"]), Ok(()));
        assert_eq!(w.written(), b"\x02ab\x00");
        assert_eq!(w.u32(1), Ok(()));
        assert_eq!(w.put(&[1]), Err(Full));
        assert_eq!(w.len(), 8);
        assert_eq!(w.patch_u16(0, 0x0102), Ok(()));
        assert_eq!(w.patch_u16(7, 1), Err(Full));
        assert_eq!(w.written()[..2], [1, 2]);
    }

    #[test]
    fn rdata_is_compared_with_its_names_written_out() {
        let mut p = packet();
        // An SRV whose target points at `origin89.local`.
        let srv = [0, 0, 0, 0, 0, 80, 0xC0, 12];
        p[40..48].copy_from_slice(&srv);
        let record = Record {
            name: 12,
            kind: Type::SRV,
            class: CLASS_IN,
            flush: false,
            ttl: 120,
            rdata: 40,
            rdlen: 8,
        };
        let mut buf = [0u8; 64];
        let mut out = Writer::new(&mut buf);
        canonical_rdata(&p, &record, &mut out).expect("reads");
        assert_eq!(
            out.written(),
            b"\x00\x00\x00\x00\x00\x50\x08origin89\x05local\x00"
        );
    }
}
