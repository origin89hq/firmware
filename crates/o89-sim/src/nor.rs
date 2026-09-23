//! A simulated NOR part whose power can be cut at any byte, and the
//! harness that cuts it at every one.
//!
//! The part programs a byte at a time, clearing bits only, and erases a
//! block a byte at a time too, so a power cut mid-erase leaves a block
//! that is neither erased nor holding records, which is exactly the block
//! the ring has to be able to boot past. The step counter counts bytes
//! programmed or erased since the last power-up; a cut at step k lands k
//! of them and then every operation fails until the part is rebooted.
//!
//! cites: F-025

use core::future::Future;

use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};

/// What the simulated part reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NorError {
    /// The power was cut; nothing answers until the part is rebooted.
    PowerLost,
    /// An address past the end of the part.
    OutOfRange,
}

impl NorFlashError for NorError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            Self::PowerLost => NorFlashErrorKind::Other,
            Self::OutOfRange => NorFlashErrorKind::OutOfBounds,
        }
    }
}

/// The simulated part: `ERASE` bytes a block, any number of blocks.
#[derive(Debug, Clone)]
pub struct SimNor<const ERASE: usize> {
    bytes: Vec<u8>,
    /// Bytes programmed or erased since the last power-up.
    steps: usize,
    cut_at: Option<usize>,
    dead: bool,
    /// Bytes ever programmed, which is what the ring's budget is about.
    programmed: u64,
}

impl<const ERASE: usize> SimNor<ERASE> {
    /// A part out of its bag: every byte erased.
    #[must_use]
    pub fn fresh(blocks: usize) -> Self {
        Self {
            bytes: vec![0xFF; ERASE.saturating_mul(blocks)],
            steps: 0,
            cut_at: None,
            dead: false,
            programmed: 0,
        }
    }

    /// Cut the power after `step` more bytes land. Zero cuts it before the
    /// next byte.
    pub fn cut_after(&mut self, step: usize) {
        self.cut_at = Some(step);
        self.steps = 0;
    }

    /// Power back on: the bytes stay, the part answers again.
    pub fn reboot(&mut self) {
        self.dead = false;
        self.steps = 0;
        self.cut_at = None;
    }

    /// Whether the power is out.
    #[must_use]
    pub const fn is_dead(&self) -> bool {
        self.dead
    }

    /// Bytes programmed or erased since the last power-up.
    #[must_use]
    pub const fn steps(&self) -> usize {
        self.steps
    }

    /// Bytes ever programmed.
    #[must_use]
    pub const fn programmed(&self) -> u64 {
        self.programmed
    }

    /// The part's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn range(&self, at: u32, len: usize) -> Result<core::ops::Range<usize>, NorError> {
        let start = usize::try_from(at).map_err(|_| NorError::OutOfRange)?;
        let end = start.checked_add(len).ok_or(NorError::OutOfRange)?;
        if end > self.bytes.len() {
            return Err(NorError::OutOfRange);
        }
        Ok(start..end)
    }

    /// Land one byte, or die at the scheduled step.
    fn step(&mut self) -> Result<(), NorError> {
        if self.cut_at == Some(self.steps) {
            self.dead = true;
            return Err(NorError::PowerLost);
        }
        self.steps = self.steps.saturating_add(1);
        Ok(())
    }
}

impl<const ERASE: usize> ErrorType for SimNor<ERASE> {
    type Error = NorError;
}

impl<const ERASE: usize> ReadNorFlash for SimNor<ERASE> {
    const READ_SIZE: usize = 1;

    fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.read_now(offset, bytes))
    }

    fn capacity(&self) -> usize {
        self.bytes.len()
    }
}

impl<const ERASE: usize> NorFlash for SimNor<ERASE> {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = ERASE;

    fn erase(&mut self, from: u32, to: u32) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.erase_now(from, to))
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.write_now(offset, bytes))
    }
}

impl<const ERASE: usize> SimNor<ERASE> {
    fn read_now(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), NorError> {
        if self.dead {
            return Err(NorError::PowerLost);
        }
        let range = self.range(offset, bytes.len())?;
        bytes.copy_from_slice(self.bytes.get(range).ok_or(NorError::OutOfRange)?);
        Ok(())
    }

    /// Erase a byte at a time, so a cut leaves a block half erased.
    fn erase_now(&mut self, from: u32, to: u32) -> Result<(), NorError> {
        if self.dead {
            return Err(NorError::PowerLost);
        }
        let len = usize::try_from(to.saturating_sub(from)).map_err(|_| NorError::OutOfRange)?;
        let range = self.range(from, len)?;
        for index in range {
            self.step()?;
            if let Some(byte) = self.bytes.get_mut(index) {
                *byte = 0xFF;
            }
        }
        Ok(())
    }

    /// Program a byte at a time, clearing bits only.
    fn write_now(&mut self, offset: u32, bytes: &[u8]) -> Result<(), NorError> {
        if self.dead {
            return Err(NorError::PowerLost);
        }
        let range = self.range(offset, bytes.len())?;
        for (index, byte) in range.zip(bytes) {
            self.step()?;
            if let Some(slot) = self.bytes.get_mut(index) {
                *slot &= *byte;
            }
            self.programmed = self.programmed.saturating_add(1);
        }
        Ok(())
    }
}

impl<const ERASE: usize> MultiwriteNorFlash for SimNor<ERASE> {}

/// The part lent to a ring rather than given to it.
///
/// [`Ring::open`](o89_core::Ring::open) takes its part by value, and an
/// open that fails hands nothing back. A boot the power cuts is exactly
/// that open, and what it left on the part is what the next boot reads, so
/// a test of a cut boot opens the ring on this and keeps the part.
pub struct Lent<'a, const ERASE: usize>(pub &'a mut SimNor<ERASE>);

impl<const ERASE: usize> ErrorType for Lent<'_, ERASE> {
    type Error = NorError;
}

impl<const ERASE: usize> ReadNorFlash for Lent<'_, ERASE> {
    const READ_SIZE: usize = 1;

    fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.0.read_now(offset, bytes))
    }

    fn capacity(&self) -> usize {
        self.0.bytes.len()
    }
}

impl<const ERASE: usize> NorFlash for Lent<'_, ERASE> {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = ERASE;

    fn erase(&mut self, from: u32, to: u32) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.0.erase_now(from, to))
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> impl Future<Output = Result<(), NorError>> {
        core::future::ready(self.0.write_now(offset, bytes))
    }
}

impl<const ERASE: usize> MultiwriteNorFlash for Lent<'_, ERASE> {}

/// What the harness found: how many steps the path takes uncut, and so
/// how many cuts it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a harness whose count nobody reads may have cut nothing"]
pub struct NorCrashes {
    /// The bytes the path lands when nothing cuts it.
    pub steps: usize,
}

/// Why the harness could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NorUncut {
    /// The path failed with no cut scheduled.
    PathFailed,
    /// The path landed nothing.
    NothingWritten,
}

/// Run `path` on a copy of `start` with nothing cut, to count its steps;
/// then, for every step, on a fresh copy with the power cut there, reboot
/// the part and hand it to `invariant` with the step it was cut at.
pub fn crash_nor_at_every_step<const ERASE: usize, P, I>(
    start: &SimNor<ERASE>,
    mut path: P,
    mut invariant: I,
) -> Result<NorCrashes, NorUncut>
where
    P: FnMut(&mut SimNor<ERASE>) -> Result<(), ()>,
    I: FnMut(&mut SimNor<ERASE>, usize),
{
    let mut whole = start.clone();
    whole.reboot();
    path(&mut whole).map_err(|()| NorUncut::PathFailed)?;
    let steps = whole.steps();
    if steps == 0 {
        return Err(NorUncut::NothingWritten);
    }
    for step in 0..steps {
        let mut cut = start.clone();
        cut.reboot();
        cut.cut_after(step);
        let _ = path(&mut cut);
        cut.reboot();
        invariant(&mut cut, step);
    }
    Ok(NorCrashes { steps })
}

#[cfg(test)]
mod tests {
    use embassy_futures::block_on;
    use km43::{Event, EventKind, LogSeq};
    use o89_core::{Class, Ring, SCRATCH, Wants};

    use super::*;

    const ERASE: usize = 512;
    const BLOCKS: u32 = 4;

    type Part = SimNor<ERASE>;

    fn event(seq: u64, into: &mut [u8]) -> usize {
        Event::new(
            LogSeq(seq),
            Some(1_790_000_000_000u64.saturating_add(seq)),
            EventKind::BOOT,
            &[0xA0],
        )
        .expect("an empty map is a body")
        .encode(into)
        .expect("fits")
    }

    /// Boot: take the part into a ring; `close` hands it back.
    fn open(part: &mut Part) -> Ring<Part> {
        let taken = core::mem::replace(part, Part::fresh(0));
        let mut scratch = [0u8; SCRATCH];
        block_on(Ring::open(taken, 0, BLOCKS, &mut scratch)).expect("opens")
    }

    fn close(part: &mut Part, ring: Ring<Part>) {
        *part = ring.release();
    }

    fn append(ring: &mut Ring<Part>) -> Result<u64, ()> {
        let mut payload = [0u8; 64];
        let len = event(ring.next_seq(), &mut payload);
        let mut scratch = [0u8; SCRATCH];
        block_on(ring.append(Class::A, &payload[..len], &mut scratch)).map_err(|_| ())
    }

    fn seqs(ring: &mut Ring<Part>) -> Vec<u64> {
        let mut found = Vec::new();
        let mut scratch = [0u8; SCRATCH];
        let _ = block_on(ring.read_from(1, &mut scratch, |record| {
            found.push(record.seq);
            Wants::More
        }))
        .expect("reads");
        found
    }

    /// A part with `n` records on it.
    fn with(n: u64) -> Part {
        let mut part = Part::fresh(BLOCKS as usize);
        let mut ring = open(&mut part);
        for _ in 0..n {
            append(&mut ring).expect("appends");
        }
        close(&mut part, ring);
        part
    }

    #[test]
    fn f_023_an_append_cut_at_any_byte_leaves_every_earlier_record_and_the_new_one_whole_or_absent()
    {
        let start = with(5);
        let expected: Vec<u64> = (1..=5).collect();
        let mut landed = 0;
        let crashes = crash_nor_at_every_step(
            &start,
            |part| {
                let mut ring = open(part);
                let outcome = append(&mut ring).map(|_| ());
                close(part, ring);
                outcome
            },
            |part, step| {
                let mut ring = open(part);
                let found = seqs(&mut ring);
                assert_eq!(&found[..5], &expected[..], "cut at {step}");
                match found.len() {
                    5 => {}
                    6 => {
                        assert_eq!(found[5], 6, "cut at {step}");
                        landed += 1;
                    }
                    n => panic!("cut at {step}: {n} records"),
                }
                // A torn write is never damage, and the ring appends again.
                assert_eq!(ring.damage().failed_crc, 0, "cut at {step}");
                let next = append(&mut ring).expect("appends after any cut");
                assert_eq!(next, found.len() as u64 + 1, "cut at {step}");
                close(part, ring);
            },
        )
        .expect("the path runs uncut");
        // The body, then two magic bytes: only the very last byte lands the
        // record, and it is not in the loop.
        assert_eq!(landed, 0);
        assert!(crashes.steps > 17);
    }

    /// A ring filled to the end of its last block, so the next append
    /// turns into block zero and erases block one, which holds records.
    struct Full {
        part: Part,
        /// The last sequence on it.
        total: u64,
        /// The first sequence of block one, the oldest the ring holds.
        block_one: u64,
        /// The first sequence of block two, the oldest once block one is gone.
        block_two: u64,
        /// The bytes the turn's own record takes.
        record: usize,
    }

    fn full() -> Full {
        let mut part = Part::fresh(BLOCKS as usize);
        let mut ring = open(&mut part);
        let mut payload = [0u8; 64];
        let len = o89_core::framed_len(event(1, &mut payload));
        let per_block = u64::try_from(ERASE.checked_div(len).expect("a record")).expect("fits");
        let fits = |at: u32| usize::try_from(at).expect("fits").saturating_add(len) <= ERASE;
        while ring.head().block < BLOCKS.saturating_sub(1) || fits(ring.head().at) {
            append(&mut ring).expect("appends");
        }
        let next = ring.next_seq();
        let record = o89_core::framed_len(event(next, &mut payload));
        let block_one = per_block.saturating_add(1);
        assert_eq!(ring.head().oldest, Some(block_one));
        close(&mut part, ring);
        Full {
            part,
            total: next.saturating_sub(1),
            block_one,
            block_two: per_block.saturating_mul(2).saturating_add(1),
            record,
        }
    }

    /// The append that turns the page.
    fn turn(part: &mut Part) -> Result<(), ()> {
        let mut ring = open(part);
        let outcome = append(&mut ring).map(|_| ());
        close(part, ring);
        outcome
    }

    /// What a boot after any cut of the page turn owes: the records
    /// contiguous, ending at the last one or the new one, starting in block
    /// one or at block two; no damage; an append that lands; and the block
    /// after the head erased.
    fn usable_after_the_turn(full: &Full, part: &mut Part, cut: &str) {
        let mut ring = open(part);
        let found = seqs(&mut ring);
        assert!(
            found.windows(2).all(|w| w[1] == w[0].saturating_add(1)),
            "{cut}"
        );
        let last = *found.last().expect("records");
        assert!(
            last == full.total || last == full.total.saturating_add(1),
            "{cut}: {last}"
        );
        let first = found[0];
        assert!(
            (full.block_one..=full.block_two).contains(&first),
            "{cut}: {first}"
        );
        // A cut inside an erase is not damage.
        assert_eq!(ring.damage().failed_crc, 0, "{cut}");
        append(&mut ring).expect("appends after any cut");
        let head = ring.head();
        close(part, ring);
        let ahead = head
            .block
            .saturating_add(1)
            .checked_rem(BLOCKS)
            .expect("blocks");
        let from = usize::try_from(ahead).expect("fits").saturating_mul(ERASE);
        assert!(
            part.bytes()[from..from.saturating_add(ERASE)]
                .iter()
                .all(|b| *b == 0xFF),
            "{cut}"
        );
    }

    #[test]
    fn f_023_a_page_turn_cut_at_any_byte_of_the_erase_ahead_leaves_a_ring_the_boot_can_use() {
        let full = full();
        let crashes = crash_nor_at_every_step(&full.part, turn, |part, step| {
            usable_after_the_turn(&full, part, &format!("cut at {step}"));
        })
        .expect("the path runs uncut");
        // The erase of block one and the record: the erase is most of it.
        assert!(crashes.steps > ERASE, "{} steps", crashes.steps);
    }

    /// A cut in the page turn's record, once the block ahead is erased,
    /// leaves a torn first record in a fresh block. The next boot finds that
    /// block closed and erases it again before it appends, and that erase
    /// can be cut too: the boot after it still finds the same records and a
    /// ring it can append to. Every first cut across the turn, and every
    /// second cut across the recovering boot's own erase.
    ///
    /// A first cut inside the erase of block one leaves the boot nothing to
    /// erase: the half-erased block is the oldest, which a boot probes and
    /// never erases, and the page-turn test above covers it.
    #[test]
    fn f_023_a_boot_cut_while_it_erases_a_block_a_torn_record_closed_leaves_a_ring_the_next_boot_can_use()
     {
        let full = full();
        let mut uncut = full.part.clone();
        uncut.reboot();
        turn(&mut uncut).expect("the turn runs uncut");
        let turn_steps = uncut.steps();
        let record = full.record;
        assert_eq!(
            turn_steps,
            ERASE + record,
            "the erase ahead, then the record"
        );
        let mut erasing = Vec::new();
        for first in 0..turn_steps {
            let mut after_first = full.part.clone();
            after_first.reboot();
            after_first.cut_after(first);
            let _ = turn(&mut after_first);
            after_first.reboot();
            let boot = |part: &mut Part| {
                let mut scratch = [0u8; SCRATCH];
                block_on(Ring::open(Lent(part), 0, BLOCKS, &mut scratch))
                    .map(|_| ())
                    .map_err(|_| ())
            };
            match crash_nor_at_every_step(&after_first, boot, |part, second| {
                usable_after_the_turn(
                    &full,
                    part,
                    &format!("turn cut at {first}, boot cut at {second}"),
                );
            }) {
                Ok(crashes) => erasing.push((first, crashes.steps)),
                Err(NorUncut::NothingWritten) => {}
                Err(NorUncut::PathFailed) => panic!("turn cut at {first}: the boot failed uncut"),
            }
        }
        // Every cut after the record's first byte and before its last leaves
        // residue, and each has the boot erase one whole block.
        let expected: Vec<(usize, usize)> = (ERASE + 1..ERASE + record)
            .map(|first| (first, ERASE))
            .collect();
        assert_eq!(erasing, expected);
    }

    /// Two faults at once: a torn write closes the head's block, and the
    /// block after it still holds the oldest records because the erase
    /// ahead of them never landed. The boot moves the head into that block
    /// and has to erase it first, or the next append programs over records
    /// and reads back as damage.
    #[test]
    fn f_023_a_closed_head_moves_into_a_block_the_erase_ahead_missed_only_once_it_is_erased() {
        let full = full();
        let before_the_turn = full.part.clone();
        let mut part = full.part.clone();
        turn(&mut part).expect("the turn runs uncut");
        // The erase ahead never landed: block one's old records are back.
        part.bytes[ERASE..2 * ERASE].copy_from_slice(&before_the_turn.bytes[ERASE..2 * ERASE]);
        // A torn write closed block zero: body bytes after the turn's
        // record, with no magic in front of them.
        let residue = full.record;
        part.bytes[residue..residue + 3].copy_from_slice(&[0x12, 0x00, 0x34]);
        let new = full.total + 1;

        let mut ring = open(&mut part);
        assert_eq!(ring.head().block, 1, "past the closed block");
        assert_eq!(ring.head().at, 0);
        assert_eq!(ring.next_seq(), new + 1);
        let appended = append(&mut ring).expect("appends");
        assert_eq!(appended, new + 1);
        let found = seqs(&mut ring);
        assert_eq!(ring.damage().failed_crc, 0);
        close(&mut part, ring);
        // The records are contiguous up to the new one, and none of block
        // one's old records came back: they were older than the oldest.
        assert!(found.windows(2).all(|w| w[1] == w[0] + 1), "{found:?}");
        assert_eq!(found.last(), Some(&(new + 1)));
        assert!(found.iter().all(|seq| *seq > full.block_two), "{found:?}");
        // And a boot after it reads the same ring.
        let mut again = open(&mut part);
        assert_eq!(seqs(&mut again), found);
        assert_eq!(again.damage().failed_crc, 0);
    }

    /// The bench's drop of the ring's oldest block, the power cut at every
    /// byte of it (#78): the next boot opens with no damage, reads records
    /// that stay contiguous up to the last one, never hands out a sequence
    /// it already used, and the drop can be asked again.
    #[test]
    fn f_023_a_drop_of_the_oldest_block_cut_at_any_byte_never_reuses_a_sequence() {
        let full = full();
        let crashes = crash_nor_at_every_step(
            &full.part,
            |part| {
                let mut scratch = [0u8; SCRATCH];
                let mut ring = open(part);
                let outcome = block_on(ring.drop_oldest(&mut scratch))
                    .map(|_| ())
                    .map_err(|_| ());
                close(part, ring);
                outcome
            },
            |part, step| {
                let mut ring = open(part);
                let found = seqs(&mut ring);
                assert!(
                    found.windows(2).all(|w| w[1] == w[0].saturating_add(1)),
                    "cut at {step}"
                );
                assert_eq!(found.last(), Some(&full.total), "cut at {step}");
                assert!(
                    (full.block_one..=full.block_two).contains(&found[0]),
                    "cut at {step}: {}",
                    found[0]
                );
                assert_eq!(ring.damage().failed_crc, 0, "cut at {step}");
                let next = append(&mut ring).expect("appends after any cut");
                assert_eq!(next, full.total.saturating_add(1), "cut at {step}");
                let mut scratch = [0u8; SCRATCH];
                let again = block_on(ring.drop_oldest(&mut scratch)).expect("drops again");
                assert!(
                    matches!(
                        again,
                        o89_core::Dropped::Block {
                            oldest: Some(_),
                            ..
                        }
                    ),
                    "cut at {step}: {again:?}"
                );
                close(part, ring);
            },
        )
        .expect("the path runs uncut");
        assert_eq!(crashes.steps, ERASE, "one block, a byte at a time");
    }
}
