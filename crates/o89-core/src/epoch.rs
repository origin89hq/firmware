//! The epoch: the one number on this device that can invalidate key
//! material, and the order a factory reset moves it in.
//!
//! Every client key derives from the epoch and the slot, so an epoch that
//! moves makes every key under the old one useless (P-085). A factory reset
//! increments it, persists it, reads it back and verifies it, and only then
//! clears the client table — the order is the load-bearing half. A power cut
//! between the two steps leaves an epoch that is too high, which only
//! over-invalidates: the worst case is a phone that has to be paired again.
//! The reverse order leaves a cleared table at a stale epoch, and the next
//! enrolment mints `client_id 1` under the same key a stolen phone holds.
//!
//! The order is a type here. [`Clearing`] is what the client table's
//! `cleared` constructor takes, and the only way to hold one is to have
//! written the new epoch and read it back, or to be a boot that found the
//! table stamped with an epoch the part no longer holds — a reset that was
//! cut, being finished.
//!
//! cites: P-085

use km43::Epoch;

use crate::body::{Body, Kept, Malformed};
use crate::fram::{Fram, Refused};

/// The bytes the epoch takes in its record: one `u32`.
pub const EPOCH_BYTES: usize = 4;

impl Body<EPOCH_BYTES> for Epoch {
    fn encode(&self) -> [u8; EPOCH_BYTES] {
        self.get().to_le_bytes()
    }

    /// Zero is not an epoch: it starts at one and only ever climbs, so a
    /// zero is bytes nobody wrote.
    fn decode(bytes: &[u8; EPOCH_BYTES]) -> Result<Self, Malformed> {
        Self::new(u32::from_le_bytes(*bytes)).ok_or(Malformed { at: 0 })
    }
}

/// Permission to clear the client table under an epoch the part holds.
///
/// There is no public constructor. One comes out of [`Kept::advance`] after
/// the new epoch was written, read back and agreed, and one comes out of a
/// boot that found the table stamped with another epoch than the record
/// holds, which is a factory reset cut between its two writes and is
/// finished by clearing the table under the epoch that landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a clearing nobody performs leaves eight rows enrolled under an epoch that no longer derives their keys"]
pub struct Clearing {
    epoch: Epoch,
}

impl Clearing {
    /// The epoch the cleared table is stamped with.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// A boot found the table under another epoch than the part holds:
    /// the reset that moved the epoch was cut before it cleared the table,
    /// and the boot finishes it. Crate-private because only the boot's
    /// comparison of the two records can honestly say this.
    pub(crate) const fn found_at_boot(epoch: Epoch) -> Self {
        Self { epoch }
    }
}

/// Why the epoch did not advance. Every variant is P-085's *the reset MUST
/// NOT proceed*: the caller raises `concern raised` at condition `epoch
/// write failed` and refuses every `Pair` until a later attempt succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a reset that did not advance the epoch must not clear anything"]
pub enum EpochFailed<E> {
    /// The record holds no epoch to increment from: absent, corrupt or
    /// malformed. The boot establishes one before anything can reset.
    Unknown,
    /// The epoch is at the top of its `u32`. Refused rather than wrapped:
    /// an epoch back at one re-derives the first keys this unit ever had.
    AtTheCeiling,
    /// The write did not happen.
    Write(Refused<E>),
    /// The read-back failed on the bus.
    ReadBack(E),
    /// The read-back found something other than what was written. What
    /// it found is what the handle now holds.
    Disagreed,
}

impl Kept<Epoch, EPOCH_BYTES> {
    /// Increment the epoch, persist it, read it back and verify it, in that
    /// order, and hand out the permission to clear the tables only once
    /// the read-back agrees (P-085).
    ///
    /// After this returns, whatever it returns, the handle holds what the
    /// part holds: the read-back is a read.
    pub async fn advance<F: Fram>(
        &mut self,
        fram: &mut F,
    ) -> Result<Clearing, EpochFailed<F::Error>> {
        let Some(current) = self.present() else {
            return Err(EpochFailed::Unknown);
        };
        let next = current
            .get()
            .checked_add(1)
            .and_then(Epoch::new)
            .ok_or(EpochFailed::AtTheCeiling)?;
        self.write(fram, next).await.map_err(EpochFailed::Write)?;
        *self = Self::read(self.record(), fram)
            .await
            .map_err(EpochFailed::ReadBack)?;
        if self.present() == Some(&next) {
            Ok(Clearing { epoch: next })
        } else {
            Err(EpochFailed::Disagreed)
        }
    }
}

/// Why the physical reset did not finish. Both failures forbid pairing
/// until a later successful reset; the caller retains that latch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ResetFailed<E> {
    /// Epoch advance or verification failed; nothing else was cleared.
    Epoch(EpochFailed<E>),
    /// The epoch advanced, but the table did not clear. Boot finishes it.
    Clients(Refused<E>),
}

/// Advance and verify the epoch, then clear clients, counters and dedup in
/// their single record. Session owners must drop their bindings before
/// permitting another request after this operation.
pub async fn reset_clients<F: Fram>(
    epoch: &mut Kept<Epoch, EPOCH_BYTES>,
    clients: &mut Kept<crate::ClientTable, { crate::CLIENT_TABLE_BYTES }>,
    fram: &mut F,
) -> Result<(), ResetFailed<F::Error>> {
    let clearing = epoch.advance(fram).await.map_err(ResetFailed::Epoch)?;
    clients
        .write(fram, crate::ClientTable::cleared(&clearing))
        .await
        .map_err(ResetFailed::Clients)
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::body::Held;
    use crate::fram::{Address, Position, Slot};
    use crate::map::EPOCH;

    /// A part whose supply can fall, and whose bytes a test can damage
    /// between a write and its read-back.
    struct Part {
        bytes: [u8; 64],
        falling: bool,
        writes: usize,
        /// After the n-th write, flip the byte at that offset, so the
        /// read-back disagrees.
        flip: Option<(usize, usize)>,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0; 64],
                falling: false,
                writes: 0,
                flip: None,
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
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                self.writes = self.writes.saturating_add(1);
                if let Some((after, at)) = self.flip
                    && self.writes == after
                {
                    self.bytes[at] ^= 0x01;
                }
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    fn with_first(part: &mut Part) -> Kept<Epoch, EPOCH_BYTES> {
        let mut kept = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, part)).expect("reads");
        block_on(kept.write(part, Epoch::FIRST)).expect("the supply is fine");
        kept
    }

    #[test]
    fn p_085_the_epoch_starts_at_one_and_a_zero_is_bytes_nobody_wrote() {
        assert_eq!(Epoch::FIRST.encode(), [1, 0, 0, 0]);
        assert_eq!(Epoch::decode(&[1, 0, 0, 0]), Ok(Epoch::FIRST));
        assert_eq!(Epoch::decode(&[0, 0, 0, 0]), Err(Malformed { at: 0 }));
        assert_eq!(Epoch::decode(&[0xFF; 4]), Ok(epoch(u32::MAX)));
    }

    #[test]
    fn p_085_advancing_writes_reads_back_and_only_then_hands_out_a_clearing() {
        let mut part = Part::fresh();
        let mut kept = with_first(&mut part);
        let clearing = block_on(kept.advance(&mut part)).expect("the supply is fine");
        assert_eq!(clearing.epoch(), epoch(2));
        assert_eq!(kept.present(), Some(&epoch(2)));
        // What the part holds is what the clearing names.
        let found = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, &mut part)).expect("reads");
        assert_eq!(found.present(), Some(&epoch(2)));
        // And again: the epoch only climbs.
        let again = block_on(kept.advance(&mut part)).expect("the supply is fine");
        assert_eq!(again.epoch(), epoch(3));
    }

    #[test]
    fn p_085_a_write_that_fails_hands_out_no_clearing_and_moves_nothing() {
        let mut part = Part::fresh();
        let mut kept = with_first(&mut part);
        part.falling = true;
        assert_eq!(
            block_on(kept.advance(&mut part)),
            Err(EpochFailed::Write(Refused::SupplyFalling))
        );
        assert_eq!(kept.present(), Some(&Epoch::FIRST));
        part.falling = false;
        let found = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, &mut part)).expect("reads");
        assert_eq!(found.present(), Some(&Epoch::FIRST));
    }

    #[test]
    fn p_085_a_read_back_that_disagrees_hands_out_no_clearing_and_holds_what_it_found() {
        let mut part = Part::fresh();
        let mut kept = with_first(&mut part);
        // Slot B starts at 16; its body at 24. The first record took five
        // writes; flip a body byte after the tenth, the magic of the second,
        // so the record the write landed is not the record read back.
        part.flip = Some((10, 24));
        assert_eq!(
            block_on(kept.advance(&mut part)),
            Err(EpochFailed::Disagreed)
        );
        // The read-back found slot B corrupt and slot A still at one.
        assert_eq!(kept.present(), Some(&Epoch::FIRST));
        assert_eq!(
            block_on(EPOCH.read(&mut part)).map(|c| c.position()),
            Ok(Position::At {
                seq: 1,
                slot: Slot::A
            })
        );
    }

    #[test]
    fn p_085_an_epoch_at_its_ceiling_refuses_rather_than_wraps() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, &mut part)).expect("reads");
        block_on(kept.write(&mut part, epoch(u32::MAX))).expect("the supply is fine");
        assert_eq!(
            block_on(kept.advance(&mut part)),
            Err(EpochFailed::AtTheCeiling)
        );
        assert_eq!(kept.present(), Some(&epoch(u32::MAX)));
    }

    #[test]
    fn p_085_an_unknown_epoch_cannot_be_advanced() {
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, &mut part)).expect("reads");
        assert_eq!(kept.held(), &Held::Absent);
        assert_eq!(block_on(kept.advance(&mut part)), Err(EpochFailed::Unknown));
        // A zero written raw is malformed, and cannot be advanced either.
        let _zero = block_on(EPOCH.write(&mut part, Position::Start, &[0; 4]));
        let mut zero = block_on(Kept::<Epoch, EPOCH_BYTES>::read(EPOCH, &mut part)).expect("reads");
        assert_eq!(zero.held(), &Held::Malformed(Malformed { at: 0 }));
        assert_eq!(block_on(zero.advance(&mut part)), Err(EpochFailed::Unknown));
    }
}
