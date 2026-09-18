//! The FRAM record: two slots, and the CRC that makes one of them current.
//!
//! FRAM has no erase cycle and no write latency, so a single word survives a
//! power cut by itself; what it cannot do is make several words land
//! together. Every record here is therefore an A/B pair of slots, each
//! `[magic | seq | body | crc32]`. A write goes to the slot that is not
//! current, its CRC last and in a transaction of its own, and the reader
//! takes the slot whose CRC holds with the higher sequence. The CRC landing
//! is what makes a slot current: a write cut at any byte before it leaves a
//! slot whose CRC does not match and the previous record in effect, and
//! there is no third word to flip and no third thing to tear (P-102, F-020).
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
    /// The bus said no, before or during the write; what landed is unknown
    /// and the CRC is what tells the next reader.
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
    /// the part finishes: the discipline is about starting.
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

/// What one slot's bytes decode to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded<const N: usize> {
    /// The magic, the CRC and the sequence all hold.
    Valid { seq: u32, body: [u8; N] },
    /// Every byte erased or zero: never written, or a fresh part.
    Blank,
    /// Written and wrong: a torn write, or damage.
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

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "what landed is what the next read returns; discarding it is guessing"]
pub struct Written<const N: usize> {
    /// The record as the next read will find it.
    pub current: Current<N>,
}

/// One A/B record in the map: its magic and where its two slots sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<const N: usize> {
    magic: u32,
    a: Address,
}

impl<const N: usize> Record<N> {
    /// A record whose slot `A` starts at `at`; `B` follows it.
    #[must_use]
    pub const fn at(magic: u32, at: Address) -> Self {
        Self { magic, a: at }
    }

    /// The first address past both slots: where the next record may start.
    #[must_use]
    pub const fn end(self) -> Address {
        self.a.plus(slot_bytes(N).saturating_mul(2))
    }

    const fn address(self, slot: Slot) -> Address {
        match slot {
            Slot::A => self.a,
            Slot::B => self.a.plus(slot_bytes(N)),
        }
    }

    /// The bytes a slot holds for `seq` and `body`, CRC included.
    fn encode(self, seq: u32, body: &[u8; N]) -> ([u8; HEAD], u32) {
        let mut head = [0u8; HEAD];
        head[..4].copy_from_slice(&self.magic.to_le_bytes());
        head[4..].copy_from_slice(&seq.to_le_bytes());
        let mut digest = CRC32.digest();
        digest.update(&head);
        digest.update(body);
        (head, digest.finalize())
    }

    fn decode(self, head: [u8; HEAD], body: &[u8; N], tail: [u8; TAIL]) -> Decoded<N> {
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
            Decoded::Valid { seq, body: *body }
        } else {
            Decoded::Corrupt
        }
    }

    async fn read_slot<F: Fram>(self, fram: &mut F, slot: Slot) -> Result<Decoded<N>, F::Error> {
        let at = self.address(slot);
        let mut head = [0u8; HEAD];
        let mut body = [0u8; N];
        let mut tail = [0u8; TAIL];
        fram.read(at, &mut head).await?;
        fram.read(at.plus(HEAD), &mut body).await?;
        fram.read(at.plus(HEAD.saturating_add(N)), &mut tail)
            .await?;
        Ok(self.decode(head, &body, tail))
    }

    /// What the record holds: the newer valid slot, or that there is none.
    pub async fn read<F: Fram>(self, fram: &mut F) -> Result<Current<N>, F::Error> {
        let a = self.read_slot(fram, Slot::A).await?;
        let b = self.read_slot(fram, Slot::B).await?;
        Ok(match (a, b) {
            (Decoded::Valid { seq: sa, body: ba }, Decoded::Valid { seq: sb, body: bb }) => {
                if sa >= sb {
                    Current::Valid {
                        seq: sa,
                        body: ba,
                        slot: Slot::A,
                    }
                } else {
                    Current::Valid {
                        seq: sb,
                        body: bb,
                        slot: Slot::B,
                    }
                }
            }
            (Decoded::Valid { seq, body }, Decoded::Blank | Decoded::Corrupt) => Current::Valid {
                seq,
                body,
                slot: Slot::A,
            },
            (Decoded::Blank | Decoded::Corrupt, Decoded::Valid { seq, body }) => Current::Valid {
                seq,
                body,
                slot: Slot::B,
            },
            (Decoded::Blank, Decoded::Blank | Decoded::Corrupt)
            | (Decoded::Corrupt, Decoded::Blank) => Current::Empty,
            (Decoded::Corrupt, Decoded::Corrupt) => Current::Corrupt,
        })
    }

    /// Write `body` as the next record, into the slot that is not current,
    /// the CRC last in a transaction of its own. `current` is what the last
    /// read returned; passing a stale one writes over the wrong slot, so the
    /// caller reads, then writes, then keeps what this returns.
    pub async fn write<F: Fram>(
        self,
        fram: &mut F,
        current: &Current<N>,
        body: &[u8; N],
    ) -> Result<Written<N>, Refused<F::Error>> {
        let (seq, slot) = match *current {
            Current::Valid { seq, slot, .. } => match seq.checked_add(1) {
                Some(next) => (next, slot.other()),
                None => return Err(Refused::AtTheCeiling),
            },
            Current::Empty | Current::Corrupt => (1, Slot::A),
        };
        let at = self.address(slot);
        let (head, crc) = self.encode(seq, body);
        let mut first = [0u8; HEAD];
        first.copy_from_slice(&head);
        fram.write(at, &first).await?;
        fram.write(at.plus(HEAD), body).await?;
        fram.write(at.plus(HEAD.saturating_add(N)), &crc.to_le_bytes())
            .await?;
        Ok(Written {
            current: Current::Valid {
                seq,
                body: *body,
                slot,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use embassy_futures::block_on;

    use super::*;

    /// A part in an array, with a supply that can be made to fall and a
    /// count of every transaction, so a test reads what a write did.
    struct Part {
        bytes: [u8; 256],
        falling: bool,
        transactions: usize,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0xFF; 256],
                falling: false,
                transactions: 0,
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
                self.transactions = self.transactions.saturating_add(1);
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    const COUNTER: Record<4> = Record::at(0x4E54_5243, Address(16));

    #[test]
    fn f_020_a_fresh_part_is_empty_and_the_first_write_lands_in_a_at_one() {
        let mut part = Part::fresh();
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(Current::Empty));
        let written = block_on(COUNTER.write(&mut part, &Current::Empty, &7u32.to_le_bytes()))
            .expect("the supply is fine");
        assert_eq!(
            written.current,
            Current::Valid {
                seq: 1,
                body: 7u32.to_le_bytes(),
                slot: Slot::A
            }
        );
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(written.current));
    }

    #[test]
    fn f_020_writes_alternate_slots_and_the_higher_sequence_is_current() {
        let mut part = Part::fresh();
        let mut current = Current::Empty;
        for value in 1..=5u32 {
            current = block_on(COUNTER.write(&mut part, &current, &value.to_le_bytes()))
                .expect("the supply is fine")
                .current;
        }
        assert_eq!(
            current,
            Current::Valid {
                seq: 5,
                body: 5u32.to_le_bytes(),
                slot: Slot::A
            }
        );
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(current));
        // Both slots hold a valid record now; the newer one wins whichever
        // slot it sits in.
        let stale = Current::Valid {
            seq: 4,
            body: 4u32.to_le_bytes(),
            slot: Slot::B,
        };
        let _ = stale;
    }

    #[test]
    fn f_020_a_write_cut_at_any_byte_leaves_the_previous_record_in_effect() {
        // Write once for real, then replay the second write cut after every
        // byte it would have landed, and read what a boot would find.
        let mut part = Part::fresh();
        let first = block_on(COUNTER.write(&mut part, &Current::Empty, &1u32.to_le_bytes()))
            .expect("the supply is fine")
            .current;
        let before = part.bytes;
        let mut whole = Part::fresh();
        whole.bytes = before;
        let _second = block_on(COUNTER.write(&mut whole, &first, &2u32.to_le_bytes()))
            .expect("the supply is fine");
        let after = whole.bytes;
        // The bytes land in address order, head then body then CRC, so a
        // cut after any prefix of the image is a cut after that many bytes
        // of the transaction; the last byte to change is the CRC's.
        let last_changed = (0..256)
            .rev()
            .find(|i| before[*i] != after[*i])
            .expect("the write changed something");
        for cut in 0..=last_changed {
            let mut torn = Part::fresh();
            torn.bytes = before;
            torn.bytes[..cut].copy_from_slice(&after[..cut]);
            let found = block_on(COUNTER.read(&mut torn)).expect("reads");
            assert_eq!(found, first, "cut after {cut} bytes");
        }
        // Every byte landed: the new record is current.
        let mut done = Part::fresh();
        done.bytes = after;
        assert_eq!(
            block_on(COUNTER.read(&mut done)),
            Ok(Current::Valid {
                seq: 2,
                body: 2u32.to_le_bytes(),
                slot: Slot::B
            })
        );
    }

    #[test]
    fn f_020_the_crc_lands_last_and_on_its_own() {
        let mut part = Part::fresh();
        let _nine = block_on(COUNTER.write(&mut part, &Current::Empty, &9u32.to_le_bytes()))
            .expect("the supply is fine");
        assert_eq!(part.transactions, 3);
        // With the CRC blanked the slot is corrupt and the record empty; with
        // the CRC alone in place and the body blank it is corrupt too.
        let mut no_crc = Part::fresh();
        no_crc.bytes = part.bytes;
        no_crc.bytes[16 + 8 + 4..16 + 8 + 4 + 4].copy_from_slice(&[0xFF; 4]);
        assert_eq!(block_on(COUNTER.read(&mut no_crc)), Ok(Current::Empty));
    }

    #[test]
    fn f_020_two_corrupt_slots_are_damage_and_a_stray_magic_is_not_a_record() {
        let mut part = Part::fresh();
        let mut current = Current::Empty;
        for value in 1..=2u32 {
            current = block_on(COUNTER.write(&mut part, &current, &value.to_le_bytes()))
                .expect("the supply is fine")
                .current;
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
        let current = block_on(COUNTER.write(&mut part, &Current::Empty, &1u32.to_le_bytes()))
            .expect("the supply is fine")
            .current;
        let before = part.bytes;
        part.falling = true;
        let refused = block_on(COUNTER.write(&mut part, &current, &2u32.to_le_bytes()));
        assert_eq!(refused, Err(Refused::SupplyFalling));
        assert_eq!(part.bytes, before);
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(current));
    }

    #[test]
    fn a_record_at_the_ceiling_refuses_rather_than_wraps() {
        let mut part = Part::fresh();
        let at_top = Current::Valid {
            seq: u32::MAX,
            body: [0; 4],
            slot: Slot::A,
        };
        assert_eq!(
            block_on(COUNTER.write(&mut part, &at_top, &[1; 4])),
            Err(Refused::AtTheCeiling)
        );
        assert!(part.bytes.iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn slots_and_records_lay_out_end_to_end() {
        assert_eq!(slot_bytes(4), 16);
        assert_eq!(COUNTER.end(), Address(16 + 32));
        assert_eq!(COUNTER.address(Slot::B), Address(32));
    }
}
