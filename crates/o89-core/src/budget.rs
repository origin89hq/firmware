//! Each admin slot's proposal budget, as P-254 keeps it: a FRAM record of
//! its own beside the slot's key record, never inside it.
//!
//! **A budget belongs to one enrolment.** The record names the epoch and
//! generation it was spent under, and a record naming any other enrolment
//! reads as a full budget: that is P-254's restore when the slot is written
//! for a new enrolment (P-239), and it needs no write of its own, so a re-key
//! cut between its steps cannot leave a new enrolment holding the old one's
//! spend.
//!
//! **A spend lands before anything it pays for.** It is written to the older
//! copy and read back; a cut leaves the budget as it was, and the proposal it
//! was for is refused with nothing stored. A record with no copy that reads
//! is an exhausted budget, never a full one: only an owner's approval or a
//! new enrolment restores a budget, and damage is neither.
//!
//! `owner` slots have no budget and never reach this table; a `viewer` may
//! not propose at all (P-251).
//!
//! cites: P-254

use km43::{ClientId, Epoch, Generation, INVITE_BUDGET};

use crate::body::{Body, Held, Kept, Malformed, Reader, Unverified, Writer};
use crate::clients::SLOTS;
use crate::fram::Fram;
use crate::map;

/// The bytes a budget record takes: the epoch, the generation, what is left.
pub const BUDGET_BYTES: usize = 4 + 4 + 1;

/// What one enrolment has left to propose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProposalBudget {
    epoch: Epoch,
    generation: Generation,
    left: u8,
}

impl ProposalBudget {
    /// Whether this record is `epoch` and `generation`'s.
    fn names(&self, epoch: Epoch, generation: Generation) -> bool {
        self.epoch == epoch && self.generation == generation
    }
}

impl Body<BUDGET_BYTES> for ProposalBudget {
    fn encode(&self) -> [u8; BUDGET_BYTES] {
        let mut out = [0; BUDGET_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.u32(self.epoch.get());
        writer.u32(self.generation.get());
        writer.u8(self.left);
        out
    }

    fn decode(bytes: &[u8; BUDGET_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let epoch = Epoch::new(reader.u32()?).ok_or(Malformed { at: 0 })?;
        let generation = Generation::new(reader.u32()?).ok_or(Malformed { at: 4 })?;
        let left = reader.u8()?;
        if left > INVITE_BUDGET {
            return Err(Malformed { at: 8 });
        }
        Ok(Self {
            epoch,
            generation,
            left,
        })
    }
}

/// Why a proposal was not paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an unpaid proposal must not be stored or answered"]
pub enum Unspent<E> {
    /// Nothing left: `Invite` outcome 6 `no_budget`.
    Exhausted,
    /// No slot has that number.
    NoSuchSlot,
    /// The spend did not read back: error 7 `busy`, and the caller raises a
    /// class A concern at condition `client table write failed`.
    Write(Unverified<E>),
}

impl<E> From<Unverified<E>> for Unspent<E> {
    fn from(why: Unverified<E>) -> Self {
        Self::Write(why)
    }
}

/// Why a budget was not restored. The enrolment it was restored for stands;
/// the budget stays where it was, which is the safe side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a restore that did not land is a concern to raise"]
pub enum Unrestored<E> {
    /// No slot has that number.
    NoSuchSlot,
    /// The write did not read back.
    Write(Unverified<E>),
}

impl<E> From<Unverified<E>> for Unrestored<E> {
    fn from(why: Unverified<E>) -> Self {
        Self::Write(why)
    }
}

/// The eight budgets, as the part holds them.
#[derive(Debug)]
pub struct ProposalBudgets {
    records: [Kept<ProposalBudget, BUDGET_BYTES>; SLOTS],
}

impl ProposalBudgets {
    /// Read every budget record.
    ///
    /// # Errors
    ///
    /// The part's error, if a read failed on the bus.
    pub async fn read<F: Fram>(fram: &mut F) -> Result<Self, F::Error> {
        let mut records = map::BUDGETS.map(Kept::unread);
        for record in &mut records {
            *record = Kept::read(record.record(), fram).await?;
        }
        Ok(Self { records })
    }

    /// What slot `id`'s enrolment, `epoch` and `generation`, has left.
    /// Zero for a slot with no such number, or a record that does not read.
    #[must_use]
    pub fn left(&self, id: ClientId, epoch: Epoch, generation: Generation) -> u8 {
        match self.record(id).map(Kept::held) {
            Some(Held::Present(budget)) if budget.names(epoch, generation) => budget.left,
            Some(Held::Present(_) | Held::Absent) => INVITE_BUDGET,
            Some(Held::Corrupt | Held::Malformed(_)) | None => 0,
        }
    }

    /// Spend one of slot `id`'s proposals, written and read back before the
    /// caller stores the invite (P-254). Answers what is left.
    ///
    /// # Errors
    ///
    /// [`Unspent`]: nothing left, no such slot, or a write that did not land.
    pub async fn spend<F: Fram>(
        &mut self,
        id: ClientId,
        epoch: Epoch,
        generation: Generation,
        fram: &mut F,
    ) -> Result<u8, Unspent<F::Error>> {
        let left = self
            .left(id, epoch, generation)
            .checked_sub(1)
            .ok_or(Unspent::Exhausted)?;
        let record = self.record_mut(id).ok_or(Unspent::NoSuchSlot)?;
        record
            .write_verified(
                fram,
                ProposalBudget {
                    epoch,
                    generation,
                    left,
                },
            )
            .await?;
        Ok(left)
    }

    /// Restore slot `id`'s budget to `INVITE_BUDGET`: an owner approved an
    /// invite it proposed (P-254). A budget already full is not written.
    ///
    /// # Errors
    ///
    /// [`Unrestored`]: no such slot, or a write that did not land.
    pub async fn restore<F: Fram>(
        &mut self,
        id: ClientId,
        epoch: Epoch,
        generation: Generation,
        fram: &mut F,
    ) -> Result<(), Unrestored<F::Error>> {
        if self.left(id, epoch, generation) == INVITE_BUDGET {
            return Ok(());
        }
        let record = self.record_mut(id).ok_or(Unrestored::NoSuchSlot)?;
        record
            .write_verified(
                fram,
                ProposalBudget {
                    epoch,
                    generation,
                    left: INVITE_BUDGET,
                },
            )
            .await?;
        Ok(())
    }

    /// The record at `id`, for the bench and the tests.
    #[must_use]
    pub fn record(&self, id: ClientId) -> Option<&Kept<ProposalBudget, BUDGET_BYTES>> {
        id.slot().and_then(|index| self.records.get(index))
    }

    fn record_mut(&mut self, id: ClientId) -> Option<&mut Kept<ProposalBudget, BUDGET_BYTES>> {
        id.slot().and_then(|index| self.records.get_mut(index))
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::fram::{Address, Refused};

    const PART_BYTES: usize = map::END.0 as usize;

    struct Part {
        bytes: [u8; PART_BYTES],
        /// Every write refused from here on, as a falling supply refuses it.
        falling: bool,
    }

    impl Part {
        #[expect(
            clippy::large_stack_arrays,
            reason = "the whole map, as the boot reads it; a test thread's stack holds it"
        )]
        fn fresh() -> Self {
            Self {
                bytes: [0xFF; PART_BYTES],
                falling: false,
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
            if self.falling {
                return core::future::ready(Err(Refused::SupplyFalling));
            }
            let start = usize::from(at.0);
            self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
            core::future::ready(Ok(()))
        }
    }

    fn id(n: u32) -> ClientId {
        ClientId::new(n).expect("a slot number")
    }

    fn epoch(n: u32) -> Epoch {
        Epoch::new(n).expect("an epoch")
    }

    fn generation(n: u32) -> Generation {
        Generation::new(n).expect("a generation")
    }

    fn budgets(part: &mut Part) -> ProposalBudgets {
        block_on(ProposalBudgets::read(part)).expect("reads")
    }

    #[test]
    fn p_254_an_admin_proposes_three_times_and_is_refused_the_fourth() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        let (slot, e, g) = (id(2), epoch(1), generation(1));
        assert_eq!(table.left(slot, e, g), INVITE_BUDGET);
        for left in (0..INVITE_BUDGET).rev() {
            assert_eq!(block_on(table.spend(slot, e, g, &mut part)), Ok(left));
        }
        assert_eq!(
            block_on(table.spend(slot, e, g, &mut part)),
            Err(Unspent::Exhausted)
        );
    }

    #[test]
    fn p_254_a_reboot_restores_nothing() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        let (slot, e, g) = (id(2), epoch(1), generation(1));
        for _ in 0..INVITE_BUDGET {
            let _ = block_on(table.spend(slot, e, g, &mut part)).expect("spent");
        }
        let rebooted = budgets(&mut part);
        assert_eq!(rebooted.left(slot, e, g), 0);
    }

    #[test]
    fn p_254_a_new_enrolment_on_the_slot_starts_with_a_full_budget() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        let slot = id(3);
        for _ in 0..INVITE_BUDGET {
            let _ = block_on(table.spend(slot, epoch(1), generation(4), &mut part)).expect("spent");
        }
        assert_eq!(table.left(slot, epoch(1), generation(5)), INVITE_BUDGET);
        assert_eq!(table.left(slot, epoch(2), generation(4)), INVITE_BUDGET);
        assert_eq!(table.left(slot, epoch(1), generation(4)), 0);
    }

    #[test]
    fn p_254_an_owners_approval_restores_the_inviters_budget() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        let (slot, e, g) = (id(2), epoch(1), generation(1));
        for _ in 0..INVITE_BUDGET {
            let _ = block_on(table.spend(slot, e, g, &mut part)).expect("spent");
        }
        assert_eq!(block_on(table.restore(slot, e, g, &mut part)), Ok(()));
        assert_eq!(budgets(&mut part).left(slot, e, g), INVITE_BUDGET);
    }

    #[test]
    fn p_254_a_spend_that_does_not_land_leaves_the_budget_as_it_was() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        let (slot, e, g) = (id(2), epoch(1), generation(1));
        let _ = block_on(table.spend(slot, e, g, &mut part)).expect("spent");
        part.falling = true;
        assert!(matches!(
            block_on(table.spend(slot, e, g, &mut part)),
            Err(Unspent::Write(_))
        ));
        part.falling = false;
        assert_eq!(budgets(&mut part).left(slot, e, g), INVITE_BUDGET - 1);
    }

    #[test]
    fn p_254_a_record_that_does_not_read_is_an_exhausted_budget() {
        let mut part = Part::fresh();
        let slot = id(2);
        let record = map::BUDGETS[1];
        // Both copies written with garbage: the CRC holds in neither.
        let end = usize::from(record.end().0);
        let start = end - 2 * crate::fram::slot_bytes(BUDGET_BYTES);
        part.bytes[start..end].fill(0x5A);
        let table = budgets(&mut part);
        assert_eq!(table.record(slot).map(Kept::held), Some(&Held::Corrupt));
        assert_eq!(table.left(slot, epoch(1), generation(1)), 0);
    }

    #[test]
    fn p_254_a_budget_above_the_limit_does_not_decode() {
        let mut bytes = ProposalBudget {
            epoch: epoch(1),
            generation: generation(1),
            left: INVITE_BUDGET,
        }
        .encode();
        assert!(ProposalBudget::decode(&bytes).is_ok());
        bytes[8] = INVITE_BUDGET + 1;
        assert_eq!(ProposalBudget::decode(&bytes), Err(Malformed { at: 8 }));
        bytes[..4].fill(0);
        assert_eq!(ProposalBudget::decode(&bytes), Err(Malformed { at: 0 }));
    }

    #[test]
    fn p_254_a_full_budget_is_not_rewritten_and_no_slot_nine_exists() {
        let mut part = Part::fresh();
        let mut table = budgets(&mut part);
        part.falling = true;
        assert_eq!(
            block_on(table.restore(id(2), epoch(1), generation(1), &mut part)),
            Ok(())
        );
        part.falling = false;
        assert_eq!(table.left(id(9), epoch(1), generation(1)), 0);
        assert_eq!(
            block_on(table.spend(id(9), epoch(1), generation(1), &mut part)),
            Err(Unspent::Exhausted)
        );
    }
}
