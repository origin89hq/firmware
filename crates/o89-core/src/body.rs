//! A typed record: the body a record encodes, and the handle that keeps the
//! RAM copy honest about what the part holds.
//!
//! [`Record`] moves bytes; this is where they mean something. A [`Body`]
//! encodes into exactly the bytes its record budgets and refuses to decode
//! what it cannot read, and a [`Kept`] pairs a decoded value with the
//! record's position on the part, so that a write always goes to the right
//! slot and the value in RAM never runs ahead of the value in FRAM. That
//! last property is P-079 made structural: a counter the part did not keep
//! is a counter the controller does not know it accepted, so an update that
//! is refused leaves the RAM copy exactly where the part is, and the caller
//! answers `busy` rather than executing on a promise.
//!
//! cites: F-020, P-079

use crate::fram::{Current, Fram, Position, Record, Refused};

/// What a record's body encodes to and decodes from: exactly `N` bytes.
///
/// Decoding refuses rather than defaults. A row whose kind byte names no
/// client kind is not a vacant row; it is a table this image cannot read,
/// and saying so is the difference between a boot that reports damage and
/// a boot that silently enrols nobody.
pub trait Body<const N: usize>: Sized {
    /// The bytes, all `N` of them; what the budget leaves over is zero.
    fn encode(&self) -> [u8; N];

    /// The value the bytes hold, or the first offset that did not decode.
    fn decode(bytes: &[u8; N]) -> Result<Self, Malformed>;
}

/// A valid record whose body this image cannot read: the CRC held, the
/// bytes did not decode. A map that moved, a kind nobody defined, a length
/// past its field. Carries the offset so the dump reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Malformed {
    /// The offset into the body of the first byte that did not decode.
    pub at: usize,
}

/// What a typed record holds after a read. Four things, because they are
/// four different situations and a boot reports each one differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Held<T> {
    /// A record, decoded.
    Present(T),
    /// Never written: a fresh part, or a record this image added.
    Absent,
    /// Both slots written and neither holds: damage, which the boot raises.
    Corrupt,
    /// A record that holds and does not decode.
    Malformed(Malformed),
}

impl<T> Held<T> {
    /// The value, if there is one.
    #[must_use]
    pub const fn present(&self) -> Option<&T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Absent | Self::Corrupt | Self::Malformed(_) => None,
        }
    }
}

/// Why an update did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an update that did not land is a change the controller must not act on"]
pub enum Unchanged<E> {
    /// Nothing is held, so there is nothing to change; write a value first.
    NothingHeld,
    /// The write did not happen; the value in RAM is the value on the part.
    Refused(Refused<E>),
}

/// A record and its decoded value, kept together so the one in RAM is
/// always the one on the part.
///
/// A [`Kept`] is made by reading; it is changed by [`write`](Self::write),
/// which replaces the value, or [`update`](Self::update), which changes a
/// copy and keeps it only once the part has it. There is no way to change
/// the value without the part agreeing first.
#[derive(Debug)]
pub struct Kept<T, const N: usize> {
    record: Record<N>,
    position: Position,
    held: Held<T>,
}

impl<T: Body<N>, const N: usize> Kept<T, N> {
    /// Read `record` and decode what it holds.
    pub async fn read<F: Fram>(record: Record<N>, fram: &mut F) -> Result<Self, F::Error> {
        let current = record.read(fram).await?;
        let position = current.position();
        let held = match current {
            Current::Valid { body, .. } => match T::decode(&body) {
                Ok(value) => Held::Present(value),
                Err(malformed) => Held::Malformed(malformed),
            },
            Current::Empty => Held::Absent,
            Current::Corrupt => Held::Corrupt,
        };
        Ok(Self {
            record,
            position,
            held,
        })
    }

    /// The record this keeps.
    #[must_use]
    pub const fn record(&self) -> Record<N> {
        self.record
    }

    /// What the last read or write left.
    #[must_use]
    pub const fn held(&self) -> &Held<T> {
        &self.held
    }

    /// The value, if the record holds one.
    #[must_use]
    pub const fn present(&self) -> Option<&T> {
        self.held.present()
    }

    /// Write `value` as the next record. On success it is what this holds;
    /// on refusal it is dropped and this holds what it held.
    pub async fn write<F: Fram>(
        &mut self,
        fram: &mut F,
        value: T,
    ) -> Result<(), Refused<F::Error>> {
        let body = value.encode();
        let written = self.record.write(fram, self.position, &body).await?;
        self.position = written.position;
        self.held = Held::Present(value);
        Ok(())
    }

    /// Replace the value in RAM without writing: for a change every boot
    /// makes again from what the part holds, so the part need not hold it.
    /// Crate-private, because it is the one way the RAM copy may differ
    /// from the part and each use has to say why.
    pub(crate) fn rebase(&mut self, value: T) {
        self.held = Held::Present(value);
    }

    /// Apply `change` to a copy of the value and write the copy, keeping it
    /// only once the part has it. What `change` returns comes back on
    /// success and is never seen on refusal, so a decision made inside it
    /// cannot be acted on unless the part kept the state it was made on.
    ///
    /// A change that leaves the value equal writes nothing: a stale counter
    /// costs no transaction.
    pub async fn update<F: Fram, R>(
        &mut self,
        fram: &mut F,
        change: impl FnOnce(&mut T) -> R,
    ) -> Result<R, Unchanged<F::Error>>
    where
        T: Clone + PartialEq,
    {
        let Held::Present(value) = &self.held else {
            return Err(Unchanged::NothingHeld);
        };
        let mut candidate = value.clone();
        let outcome = change(&mut candidate);
        if candidate == *value {
            return Ok(outcome);
        }
        let body = candidate.encode();
        let written = self
            .record
            .write(fram, self.position, &body)
            .await
            .map_err(Unchanged::Refused)?;
        self.position = written.position;
        self.held = Held::Present(candidate);
        Ok(outcome)
    }
}

/// Writes fields into a body in order. A field past the end is a layout
/// the constants beside each body assert cannot happen, so it is a debug
/// assertion and not a branch.
pub(crate) struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub(crate) const fn over(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let end = self.at.saturating_add(bytes.len());
        match self.out.get_mut(self.at..end) {
            Some(room) => room.copy_from_slice(bytes),
            None => debug_assert!(false, "a field past the body's end"),
        }
        self.at = end;
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.put(&[value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.put(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.put(&value.to_le_bytes());
    }

    /// Skip `bytes`, leaving them as they are: zero, in a fresh body.
    pub(crate) fn skip(&mut self, bytes: usize) {
        self.at = self.at.saturating_add(bytes);
    }
}

/// Reads fields out of a body in order, naming the offset of the first
/// one that is not there.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn over(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The offset the next field starts at.
    pub(crate) const fn at(&self) -> usize {
        self.at
    }

    /// The offset of the field just taken, for a value that did not
    /// decode.
    pub(crate) fn malformed(&self, width: usize) -> Malformed {
        Malformed {
            at: self.at.saturating_sub(width),
        }
    }

    pub(crate) fn take<const K: usize>(&mut self) -> Result<[u8; K], Malformed> {
        let end = self.at.saturating_add(K);
        let field = self
            .bytes
            .get(self.at..end)
            .and_then(|field| <[u8; K]>::try_from(field).ok())
            .ok_or(Malformed { at: self.at })?;
        self.at = end;
        Ok(field)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Malformed> {
        self.take::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Malformed> {
        self.take::<2>().map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Malformed> {
        self.take::<4>().map(u32::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Malformed> {
        self.take::<8>().map(u64::from_le_bytes)
    }

    pub(crate) fn skip(&mut self, bytes: usize) {
        self.at = self.at.saturating_add(bytes);
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::fram::{Address, Slot};

    /// A part in an array whose supply can be made to fall.
    struct Part {
        bytes: [u8; 128],
        falling: bool,
        writes: usize,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0; 128],
                falling: false,
                writes: 0,
            }
        }
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            into.copy_from_slice(&self.bytes[start..][..into.len()]);
            core::future::ready(Ok(()))
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            let outcome = if self.falling {
                Err(Refused::SupplyFalling)
            } else {
                self.writes = self.writes.saturating_add(1);
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    /// A count whose body refuses the top bit, so a test can write bytes
    /// that hold and do not decode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Count(u32);

    impl Body<4> for Count {
        fn encode(&self) -> [u8; 4] {
            self.0.to_le_bytes()
        }

        fn decode(bytes: &[u8; 4]) -> Result<Self, Malformed> {
            let value = u32::from_le_bytes(*bytes);
            if value & 0x8000_0000 != 0 {
                return Err(Malformed { at: 3 });
            }
            Ok(Self(value))
        }
    }

    const COUNT: Record<4> = Record::at(0x544E_5543, Address(0));

    #[test]
    fn f_020_a_kept_record_tells_absent_present_corrupt_and_malformed_apart() {
        let mut part = Part::fresh();
        let kept = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(kept.held(), &Held::Absent);
        assert_eq!(kept.present(), None);

        let mut kept = kept;
        block_on(kept.write(&mut part, Count(7))).expect("the supply is fine");
        assert_eq!(kept.present(), Some(&Count(7)));
        let again = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(again.held(), &Held::Present(Count(7)));

        // Bytes that hold and do not decode: the top bit set, written as
        // the next record so the CRC is right.
        let at = Position::At {
            seq: 1,
            slot: Slot::A,
        };
        let _bad = block_on(COUNT.write(&mut part, at, &0x8000_0001u32.to_le_bytes()));
        let malformed = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(malformed.held(), &Held::Malformed(Malformed { at: 3 }));

        // One body byte flipped in each slot: both written, neither holds.
        part.bytes[8] ^= 0x01;
        part.bytes[16 + 8] ^= 0x01;
        let corrupt = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(corrupt.held(), &Held::Corrupt);
    }

    #[test]
    fn p_079_a_refused_update_leaves_the_ram_copy_where_the_part_is() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        block_on(kept.write(&mut part, Count(1))).expect("the supply is fine");
        part.falling = true;
        let refused = block_on(kept.update(&mut part, |count| {
            count.0 = 2;
            "moved"
        }));
        assert_eq!(refused, Err(Unchanged::Refused(Refused::SupplyFalling)));
        assert_eq!(kept.present(), Some(&Count(1)));
        part.falling = false;
        let found = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(found.present(), Some(&Count(1)));
    }

    #[test]
    fn p_079_an_update_the_part_kept_is_the_value_in_ram() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        block_on(kept.write(&mut part, Count(1))).expect("the supply is fine");
        let moved = block_on(kept.update(&mut part, |count| {
            count.0 = 2;
            "moved"
        }));
        assert_eq!(moved, Ok("moved"));
        assert_eq!(kept.present(), Some(&Count(2)));
        let found = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        assert_eq!(found.present(), Some(&Count(2)));
    }

    #[test]
    fn an_update_that_changes_nothing_writes_nothing() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        block_on(kept.write(&mut part, Count(1))).expect("the supply is fine");
        let before = part.writes;
        let same = block_on(kept.update(&mut part, |_| "stale"));
        assert_eq!(same, Ok("stale"));
        assert_eq!(part.writes, before);
    }

    #[test]
    fn an_update_on_nothing_held_is_refused() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Count, 4>::read(COUNT, &mut part)).expect("reads");
        let nothing = block_on(kept.update(&mut part, |count| count.0 = 5));
        assert_eq!(nothing, Err(Unchanged::NothingHeld));
        assert_eq!(kept.held(), &Held::Absent);
    }
}
