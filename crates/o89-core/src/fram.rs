//! The FRAM record: two slots, and the CRC that makes one of them current.
//!
//! FRAM has no erase cycle and no write latency, so a single word survives a
//! power cut by itself; what it cannot do is make several words land
//! together. Every record here is therefore an A/B pair of slots, each
//! `[magic | seq | body | crc32]`. A write goes to the slot that is not
//! current, and the reader takes the slot whose magic and CRC hold with the
//! higher sequence. The magic lands last, in a transaction of its own, and
//! is cleared first: whatever the slot held stops being a record before a
//! byte of the new one lands, and nothing in between is one. A write cut
//! at any byte before the magic leaves a slot no CRC can make a record of
//! and the previous record in effect, and there is no third word to flip
//! and no third thing to tear (P-102, F-020). The CRC alone was not enough
//! here: a slot being reused still holds the old record's CRC while the
//! new sequence and body land over it, and a CRC is thirty-two bits, so an
//! image that collides with it exists and the review built one.
//!
//! The seven brown-outs of 2026-09-16 destroyed both counter slots at once
//! because one transaction wrote into both. The order above is the half of
//! the answer that lives here; the other half, no transaction starting on a
//! falling supply, is the adapter's, and reaches this code as a write
//! refused, which the store answers by doing nothing at all (P-079, F-021).
//!
//! Nothing here touches a bus. [`Fram`] is the seam the controller fills with
//! its I2C driver and the simulator fakes with a step counter that cuts the
//! power at every byte.
//!
//! cites: F-020, F-021

use core::future::Future;

use crc::{CRC_32_ISO_HDLC, Crc};

/// The part: an FM24W256, 32 KiB, byte-addressed.
pub const FRAM_BYTES: usize = 32 * 1024;

/// A byte address in the part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Address(pub u16);

impl Address {
    /// The address `bytes` past this one.
    ///
    /// # Panics
    ///
    /// Past the end of the part. The map is laid out at compile time, so a
    /// sum that leaves the part is a map that does not build.
    #[must_use]
    pub const fn plus(self, bytes: usize) -> Self {
        let at = (self.0 as usize).saturating_add(bytes);
        assert!(at < FRAM_BYTES, "an address past the end of the FRAM");
        // Bounded just above, so the narrowing cannot lose a bit.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "asserted below FRAM_BYTES, which fits a u16"
        )]
        Self(at as u16)
    }
}

/// Why a write did not happen. Every variant is the write not having
/// happened at all: the store never has to wonder which half landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a write that did not happen is a record the controller no longer knows it accepted"]
pub enum Refused<E> {
    /// The supply is falling and the adapter would not start a transaction.
    SupplyFalling,
    /// The record's sequence is at the top of its `u32`. Refused rather than
    /// wrapped: a sequence back at one would make an old slot the newer one.
    AtTheCeiling,
    /// The bus said no, before or during the write; what landed is unknown,
    /// possibly a prefix of the bytes, and the magic and the CRC are what
    /// tell the next reader.
    Bus(E),
}

/// The bytes of the part, as the adapter and the simulator provide them.
pub trait Fram {
    /// What the bus reports.
    type Error;

    /// Read `into.len()` bytes starting at `at`.
    fn read(
        &mut self,
        at: Address,
        into: &mut [u8],
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Write `bytes` starting at `at`, as one transaction, or refuse to
    /// start one on a falling supply. A transaction the bus starts is one
    /// the part is expected to finish on its own energy, which is why the
    /// discipline is about starting; a `Bus` error is the bus failing
    /// before or during it, and what landed is then unknown. The
    /// simulator cuts the power inside a transaction on purpose and
    /// reports that as `Bus`, so that every prefix a cut can leave is
    /// read back and judged by the magic and the CRC, never by trust.
    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<Self::Error>>>;
}

/// The CRC every slot carries: CRC-32 as ISO HDLC and zlib use it.
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// The bytes before the body: the magic and the sequence.
const HEAD: usize = 8;
/// The bytes of the magic, at the front of a slot.
const MAGIC_BYTES: usize = 4;
/// What a slot's magic is cleared to before a new record lands over it.
/// Zero, which no record's magic is, and which is what a fresh part reads
/// as blank when the rest is zero too.
const NO_MAGIC: [u8; MAGIC_BYTES] = [0; MAGIC_BYTES];
/// The bytes after it: the CRC.
const TAIL: usize = 4;

/// The bytes one slot of a record with an `N`-byte body takes.
#[must_use]
pub const fn slot_bytes(body: usize) -> usize {
    HEAD.saturating_add(body).saturating_add(TAIL)
}

/// Which of the two slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Slot {
    /// The first.
    A,
    /// The second.
    B,
}

impl Slot {
    const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// What one slot's bytes decode to. The body stays in the buffer it was
/// read into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    /// The magic, the CRC and the sequence all hold.
    Valid { seq: u32 },
    /// Every byte erased or zero: never written, or a fresh part.
    Blank,
    /// Written and wrong: a torn write, or damage.
    Corrupt,
}

/// Which slot holds the record, if either does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Newest {
    Valid { seq: u32, slot: Slot },
    Empty,
    Corrupt,
}

/// What a record holds right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Current<const N: usize> {
    /// The newer of the valid slots.
    Valid {
        /// Its sequence.
        seq: u32,
        /// Its body.
        body: [u8; N],
        /// Which slot holds it, which is the one the next write avoids.
        slot: Slot,
    },
    /// Neither slot was ever written: a fresh part, or a record added by
    /// this image. The next write goes to `A` at sequence one.
    Empty,
    /// Both slots are written and neither holds: two torn writes cannot do
    /// this, so it is damage, and the reader does not guess. The next
    /// write starts the record over at `A`, and the adapter raises it.
    Corrupt,
}

impl<const N: usize> Current<N> {
    /// Where the next write goes, which is all a writer needs from a read.
    #[must_use]
    pub const fn position(&self) -> Position {
        match *self {
            Self::Valid { seq, slot, .. } => Position::At { seq, slot },
            Self::Empty | Self::Corrupt => Position::Start,
        }
    }
}

/// Where a record's next write goes: the sequence and slot the last read
/// found, and nothing else. The bytes are the reader's to decode and keep
/// or drop; a two-kilobyte record is not held twice in RAM so that its
/// slot is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Position {
    /// A valid record at `seq` in `slot`: the next write is `seq + 1` in
    /// the other slot.
    At {
        /// The current record's sequence.
        seq: u32,
        /// The slot it sits in.
        slot: Slot,
    },
    /// No valid record: the next write is sequence one in `A`.
    Start,
}

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "where the record now sits is what the next write needs; discarding it writes over the wrong slot"]
pub struct Written {
    /// Where the record sits now, for the next write.
    pub position: Position,
}

/// One A/B record in the map: its magic and where its two slots sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<const N: usize> {
    magic: u32,
    a: Address,
}

impl<const N: usize> Record<N> {
    /// A record whose slot `A` starts at `at`; `B` follows it.
    ///
    /// The magic is never zero: zero is what a slot's magic is cleared to
    /// while a new record lands over it, and a record whose magic were
    /// zero would read as current with its sequence, body and CRC in
    /// place and its magic not yet written. Every record is a `const`, so
    /// a zero here is a build that fails, not a boot that does:
    ///
    /// ```compile_fail
    /// use o89_core::{Address, Record};
    ///
    /// const ZERO: Record<4> = Record::at(0, Address(0));
    /// ```
    ///
    /// # Panics
    ///
    /// On a zero magic, which every record being a `const` makes a build
    /// error rather than a panic at runtime.
    #[must_use]
    pub const fn at(magic: u32, at: Address) -> Self {
        assert!(
            magic != 0,
            "a record's magic is never zero: zero is a slot being written"
        );
        Self { magic, a: at }
    }

    /// The first address past both slots: where the next record may start.
    #[must_use]
    pub const fn end(self) -> Address {
        self.a.plus(slot_bytes(N).saturating_mul(2))
    }

    const fn slots(self) -> Slots {
        Slots {
            magic: self.magic,
            a: self.a,
            body: N,
        }
    }

    /// The bytes a slot holds for `seq` and `body`, CRC included.
    #[cfg(test)]
    fn encode(self, seq: u32, body: &[u8; N]) -> ([u8; HEAD], u32) {
        self.slots().encode(seq, body)
    }

    /// What the record holds: the newer valid slot, or that there is none.
    pub async fn read<F: Fram>(self, fram: &mut F) -> Result<Current<N>, F::Error> {
        let mut a = [0u8; N];
        let mut b = [0u8; N];
        Ok(match self.slots().read(fram, &mut a, &mut b).await? {
            Newest::Valid { seq, slot } => Current::Valid {
                seq,
                body: match slot {
                    Slot::A => a,
                    Slot::B => b,
                },
                slot,
            },
            Newest::Empty => Current::Empty,
            Newest::Corrupt => Current::Corrupt,
        })
    }

    /// Write `body` as the next record, into the slot that is not current:
    /// the magic cleared first, so whatever the slot held stops being a
    /// record; then the sequence, the body and the CRC; then the magic, in
    /// a transaction of its own, which is the switch. `at` is where the
    /// last read or write left the record; a stale one writes over the
    /// wrong slot, so the caller reads, then writes, then keeps what this
    /// returns.
    pub async fn write<F: Fram>(
        self,
        fram: &mut F,
        at: Position,
        body: &[u8; N],
    ) -> Result<Written, Refused<F::Error>> {
        self.slots().write(fram, at, body).await
    }
}

/// A record with its body's length known at run time rather than in the
/// type: the code every record shares. Typed, each of a dozen body sizes
/// carried its own copy of the reads, the check and the five-step write,
/// about 450 bytes apiece of a 248 KB slot; here there is one, and
/// [`Record`] only lends it buffers of the right length.
#[derive(Debug, Clone, Copy)]
struct Slots {
    magic: u32,
    a: Address,
    /// The body's length in bytes: `N` of the record this came from.
    body: usize,
}

impl Slots {
    const fn address(self, slot: Slot) -> Address {
        match slot {
            Slot::A => self.a,
            Slot::B => self.a.plus(slot_bytes(self.body)),
        }
    }

    /// The bytes a slot holds for `seq` and `body`, CRC included.
    fn encode(self, seq: u32, body: &[u8]) -> ([u8; HEAD], u32) {
        debug_assert_eq!(body.len(), self.body);
        let mut head = [0u8; HEAD];
        head[..4].copy_from_slice(&self.magic.to_le_bytes());
        head[4..].copy_from_slice(&seq.to_le_bytes());
        let mut digest = CRC32.digest();
        digest.update(&head);
        digest.update(body);
        (head, digest.finalize())
    }

    fn decode(self, head: [u8; HEAD], body: &[u8], tail: [u8; TAIL]) -> Decoded {
        let blank = |byte: &u8| *byte == 0x00 || *byte == 0xFF;
        if head.iter().all(blank) && body.iter().all(blank) && tail.iter().all(blank) {
            return Decoded::Blank;
        }
        let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let seq = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        let crc = u32::from_le_bytes(tail);
        let mut digest = CRC32.digest();
        digest.update(&head);
        digest.update(body);
        if magic == self.magic && digest.finalize() == crc && seq != 0 {
            Decoded::Valid { seq }
        } else {
            Decoded::Corrupt
        }
    }

    /// Read `slot` into `body`, which is exactly the body's length.
    async fn read_slot<F: Fram>(
        self,
        fram: &mut F,
        slot: Slot,
        body: &mut [u8],
    ) -> Result<Decoded, F::Error> {
        debug_assert_eq!(body.len(), self.body);
        let at = self.address(slot);
        let mut head = [0u8; HEAD];
        let mut tail = [0u8; TAIL];
        fram.read(at, &mut head).await?;
        fram.read(at.plus(HEAD), body).await?;
        fram.read(at.plus(HEAD.saturating_add(self.body)), &mut tail)
            .await?;
        Ok(self.decode(head, body, tail))
    }

    /// Read both slots, `A` into `a` and `B` into `b`, and say which holds
    /// the record.
    async fn read<F: Fram>(
        self,
        fram: &mut F,
        a: &mut [u8],
        b: &mut [u8],
    ) -> Result<Newest, F::Error> {
        let in_a = self.read_slot(fram, Slot::A, a).await?;
        let in_b = self.read_slot(fram, Slot::B, b).await?;
        Ok(match (in_a, in_b) {
            (Decoded::Valid { seq: sa }, Decoded::Valid { seq: sb }) => {
                if sa >= sb {
                    Newest::Valid {
                        seq: sa,
                        slot: Slot::A,
                    }
                } else {
                    Newest::Valid {
                        seq: sb,
                        slot: Slot::B,
                    }
                }
            }
            (Decoded::Valid { seq }, Decoded::Blank | Decoded::Corrupt) => {
                Newest::Valid { seq, slot: Slot::A }
            }
            (Decoded::Blank | Decoded::Corrupt, Decoded::Valid { seq }) => {
                Newest::Valid { seq, slot: Slot::B }
            }
            (Decoded::Blank, Decoded::Blank | Decoded::Corrupt)
            | (Decoded::Corrupt, Decoded::Blank) => Newest::Empty,
            (Decoded::Corrupt, Decoded::Corrupt) => Newest::Corrupt,
        })
    }

    /// [`Record::write`], for a body of this length.
    async fn write<F: Fram>(
        self,
        fram: &mut F,
        at: Position,
        body: &[u8],
    ) -> Result<Written, Refused<F::Error>> {
        debug_assert_eq!(body.len(), self.body);
        let (seq, slot) = match at {
            Position::At { seq, slot } => match seq.checked_add(1) {
                Some(next) => (next, slot.other()),
                None => return Err(Refused::AtTheCeiling),
            },
            Position::Start => (1, Slot::A),
        };
        let at = self.address(slot);
        let (_, crc) = self.encode(seq, body);
        // 1. Whatever the slot held is no longer a record.
        fram.write(at, &NO_MAGIC).await?;
        // 2. Everything after the magic. None of it is a record without one.
        fram.write(at.plus(MAGIC_BYTES), &seq.to_le_bytes()).await?;
        fram.write(at.plus(HEAD), body).await?;
        fram.write(at.plus(HEAD.saturating_add(self.body)), &crc.to_le_bytes())
            .await?;
        // 3. The magic, last: the switch.
        fram.write(at, &self.magic.to_le_bytes()).await?;
        Ok(Written {
            position: Position::At { seq, slot },
        })
    }
}

#[cfg(test)]
mod tests {
    use embassy_futures::block_on;

    use super::*;

    /// A part in an array, with a supply that can be made to fall, a count
    /// of every transaction, and a power that can be cut before any byte,
    /// so a test reads what a write did and what a cut left.
    struct Part {
        bytes: [u8; 256],
        falling: bool,
        transactions: usize,
        /// Bytes landed since the last power-up.
        landed: usize,
        /// The byte the power is cut before, if a cut is scheduled.
        cut_at: Option<usize>,
        dead: bool,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0xFF; 256],
                falling: false,
                transactions: 0,
                landed: 0,
                cut_at: None,
                dead: false,
            }
        }

        /// The same bytes, powered up, with the power cut before byte `at`
        /// of what is written next.
        fn cut_before(&self, at: usize) -> Self {
            Self {
                bytes: self.bytes,
                falling: false,
                transactions: 0,
                landed: 0,
                cut_at: Some(at),
                dead: false,
            }
        }

        /// Power back on: the bytes stay.
        fn rebooted(&self) -> Self {
            Self {
                bytes: self.bytes,
                falling: false,
                transactions: 0,
                landed: 0,
                cut_at: None,
                dead: false,
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
            let outcome = if self.dead {
                Err(Refused::Bus(()))
            } else if self.falling {
                Err(Refused::SupplyFalling)
            } else {
                self.transactions = self.transactions.saturating_add(1);
                let start = usize::from(at.0);
                let mut outcome = Ok(());
                for (i, byte) in bytes.iter().enumerate() {
                    if self.cut_at == Some(self.landed) {
                        self.dead = true;
                        outcome = Err(Refused::Bus(()));
                        break;
                    }
                    self.bytes[start.saturating_add(i)] = *byte;
                    self.landed = self.landed.saturating_add(1);
                }
                outcome
            };
            core::future::ready(outcome)
        }
    }

    const COUNTER: Record<4> = Record::at(0x4E54_5243, Address(16));

    #[test]
    fn f_020_a_fresh_part_is_empty_and_the_first_write_lands_in_a_at_one() {
        let mut part = Part::fresh();
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(Current::Empty));
        let written = block_on(COUNTER.write(&mut part, Position::Start, &7u32.to_le_bytes()))
            .expect("the supply is fine");
        assert_eq!(
            written.position,
            Position::At {
                seq: 1,
                slot: Slot::A
            }
        );
        let found = block_on(COUNTER.read(&mut part)).expect("reads");
        assert_eq!(
            found,
            Current::Valid {
                seq: 1,
                body: 7u32.to_le_bytes(),
                slot: Slot::A
            }
        );
        assert_eq!(found.position(), written.position);
    }

    #[test]
    fn f_020_writes_alternate_slots_and_the_higher_sequence_is_current() {
        let mut part = Part::fresh();
        let mut at = Position::Start;
        for value in 1..=5u32 {
            at = block_on(COUNTER.write(&mut part, at, &value.to_le_bytes()))
                .expect("the supply is fine")
                .position;
        }
        assert_eq!(
            at,
            Position::At {
                seq: 5,
                slot: Slot::A
            }
        );
        // Both slots hold a valid record now; the newer one wins whichever
        // slot it sits in.
        assert_eq!(
            block_on(COUNTER.read(&mut part)),
            Ok(Current::Valid {
                seq: 5,
                body: 5u32.to_le_bytes(),
                slot: Slot::A
            })
        );
    }

    #[test]
    fn f_020_a_write_cut_at_any_byte_leaves_the_previous_record_in_effect() {
        // Write once for real, then replay the second write with the power
        // cut before every byte it lands, and read what a boot would find.
        let mut part = Part::fresh();
        let at = block_on(COUNTER.write(&mut part, Position::Start, &1u32.to_le_bytes()))
            .expect("the supply is fine")
            .position;
        let first = block_on(COUNTER.read(&mut part)).expect("reads");
        let mut whole = part.rebooted();
        let _second = block_on(COUNTER.write(&mut whole, at, &2u32.to_le_bytes()))
            .expect("the supply is fine");
        // Four bytes cleared, four of sequence, four of body, four of CRC,
        // four of magic: twenty bytes, and a cut before any of them keeps
        // the first record.
        assert_eq!(whole.landed, 20);
        for cut in 0..whole.landed {
            let mut torn = part.cut_before(cut);
            let refused = block_on(COUNTER.write(&mut torn, at, &2u32.to_le_bytes()));
            assert_eq!(refused, Err(Refused::Bus(())), "cut before byte {cut}");
            let mut booted = torn.rebooted();
            assert_eq!(
                block_on(COUNTER.read(&mut booted)),
                Ok(first),
                "cut before byte {cut}"
            );
        }
        // Every byte landed: the new record is current.
        assert_eq!(
            block_on(COUNTER.read(&mut whole)),
            Ok(Current::Valid {
                seq: 2,
                body: 2u32.to_le_bytes(),
                slot: Slot::B
            })
        );
    }

    #[test]
    fn f_020_the_magic_lands_last_and_on_its_own_and_is_cleared_first() {
        let mut part = Part::fresh();
        let _nine = block_on(COUNTER.write(&mut part, Position::Start, &9u32.to_le_bytes()))
            .expect("the supply is fine");
        // The clearing, the sequence, the body, the CRC, the magic.
        assert_eq!(part.transactions, 5);
        // With the magic blanked the slot is not a record, whatever its CRC.
        let mut no_magic = Part::fresh();
        no_magic.bytes = part.bytes;
        no_magic.bytes[16..20].copy_from_slice(&[0xFF; 4]);
        assert_eq!(block_on(COUNTER.read(&mut no_magic)), Ok(Current::Empty));
        // The first bytes a write lands clear the old magic: a reused slot
        // stops being a record before anything else in it changes.
        let mut reused = part.rebooted();
        let first = block_on(COUNTER.read(&mut reused)).expect("reads");
        let _ = block_on(COUNTER.write(&mut reused, first.position(), &10u32.to_le_bytes()));
        let mut again = reused.rebooted();
        let second = block_on(COUNTER.read(&mut again)).expect("reads");
        let mut cut = again.cut_before(4);
        let _ = block_on(COUNTER.write(&mut cut, second.position(), &11u32.to_le_bytes()));
        assert_eq!(&cut.bytes[16..20], &[0, 0, 0, 0]);
        assert_eq!(&cut.bytes[20..32], &part.bytes[20..32]);
    }

    #[test]
    fn f_020_a_reused_slot_cannot_present_the_old_crcs_collision_as_a_record() {
        // Sequence 1 with body 01 00 00 00 and sequence 3 with body
        // 8a c8 09 aa have the same CRC under this magic: a collision the
        // review constructed. Writing the third record over the first, a
        // cut right before its magic leaves the new sequence and body over
        // the old CRC, which matches; without the magic it is no record.
        let colliding = [0x8a, 0xc8, 0x09, 0xaa];
        assert_eq!(
            COUNTER.encode(1, &1u32.to_le_bytes()).1,
            COUNTER.encode(3, &colliding).1
        );
        let mut part = Part::fresh();
        let at = block_on(COUNTER.write(&mut part, Position::Start, &1u32.to_le_bytes()))
            .expect("the supply is fine")
            .position;
        let at = block_on(COUNTER.write(&mut part, at, &2u32.to_le_bytes()))
            .expect("the supply is fine")
            .position;
        let second = block_on(COUNTER.read(&mut part)).expect("reads");
        for cut in 0..20 {
            let mut torn = part.cut_before(cut);
            let _ = block_on(COUNTER.write(&mut torn, at, &colliding));
            let mut booted = torn.rebooted();
            assert_eq!(
                block_on(COUNTER.read(&mut booted)),
                Ok(second),
                "cut before byte {cut}"
            );
        }
        // Landed whole, it is the record.
        let mut whole = part.rebooted();
        let _third =
            block_on(COUNTER.write(&mut whole, at, &colliding)).expect("the supply is fine");
        assert_eq!(
            block_on(COUNTER.read(&mut whole)),
            Ok(Current::Valid {
                seq: 3,
                body: colliding,
                slot: Slot::A
            })
        );
    }

    #[test]
    fn f_020_two_corrupt_slots_are_damage_and_a_stray_magic_is_not_a_record() {
        let mut part = Part::fresh();
        let mut at = Position::Start;
        for value in 1..=2u32 {
            at = block_on(COUNTER.write(&mut part, at, &value.to_le_bytes()))
                .expect("the supply is fine")
                .position;
        }
        // Flip one body byte in each slot.
        part.bytes[16 + 8] ^= 0x01;
        part.bytes[16 + 16 + 8] ^= 0x01;
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(Current::Corrupt));
        // A magic with a zero sequence is not a record either.
        let mut zero = Part::fresh();
        zero.bytes[16..20].copy_from_slice(&0x4E54_5243u32.to_le_bytes());
        zero.bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
        let (_, crc) = COUNTER.encode(0, &[0; 4]);
        zero.bytes[24..28].copy_from_slice(&[0; 4]);
        zero.bytes[28..32].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(block_on(COUNTER.read(&mut zero)), Ok(Current::Empty));
    }

    #[test]
    fn f_021_a_write_refused_on_a_falling_supply_changes_nothing() {
        let mut part = Part::fresh();
        let at = block_on(COUNTER.write(&mut part, Position::Start, &1u32.to_le_bytes()))
            .expect("the supply is fine")
            .position;
        let current = block_on(COUNTER.read(&mut part)).expect("reads");
        let before = part.bytes;
        part.falling = true;
        let refused = block_on(COUNTER.write(&mut part, at, &2u32.to_le_bytes()));
        assert_eq!(refused, Err(Refused::SupplyFalling));
        assert_eq!(part.bytes, before);
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(current));
    }

    #[test]
    fn a_record_at_the_ceiling_refuses_rather_than_wraps() {
        let mut part = Part::fresh();
        let at_top = Position::At {
            seq: u32::MAX,
            slot: Slot::A,
        };
        assert_eq!(
            block_on(COUNTER.write(&mut part, at_top, &[1; 4])),
            Err(Refused::AtTheCeiling)
        );
        assert!(part.bytes.iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn slots_and_records_lay_out_end_to_end() {
        assert_eq!(slot_bytes(4), 16);
        assert_eq!(COUNTER.end(), Address(16 + 32));
        assert_eq!(COUNTER.slots().address(Slot::B), Address(32));
    }
}
