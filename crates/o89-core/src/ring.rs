//! The event log on NOR: where it continues after a reboot, how a record
//! lands, and how a client reads from a sequence number.
//!
//! Append-only records over a ring of erase blocks. Nothing here is a
//! filesystem, and nothing here is allowed to stop the site: a corrupted
//! log must never be able to imply that a relay is open when the hardware
//! says closed. The state store is authoritative; this is the durable
//! change and audit record, read by sequence number from arbitrary
//! positions by several clients months apart.
//!
//! **A torn write closes its block.** The residue cannot be written over,
//! since NOR only clears bits, and cannot be skipped past, since the scan
//! stops at it. So the block is finished, its records stay readable, and
//! the log continues in the next one. A power cut costs the rest of one
//! block. **A torn write is not damage**: a block that is neither erased
//! nor holding records is a first record cut short, which on a new part is
//! an ordinary first boot; a block holding records that failed their CRC is
//! a chip somebody has to look at, and the two are counted apart.
//!
//! **The oldest block is erased one ahead of the write head**, so an append
//! never waits on an erase. **No wear levelling**: a pass takes the better
//! part of six months against an endurance of 100,000 cycles.
//!
//! **Nothing is held per block.** The part is megabytes and the controller
//! has 144 KB, so the boot finds the head by binary search over the first
//! record of each block, scans the head block alone, and streams every
//! read through one record's worth of scratch. The time floor a clock
//! offer is checked against is found the first time it is asked for, not
//! at boot, because the walk back to the newest timestamped record is
//! instant on a unit whose clock was ever set and the whole ring on one
//! whose clock never was.
//!
//! `sequential-storage` was read before this was designed and is not
//! adopted, for shape rather than quality: its queue is a FIFO, and this
//! log is read from arbitrary positions and nothing ever pops. What is
//! taken is the trait.
//!
//! cites: F-023, P-096, P-099, L-140

use embedded_storage_async::nor_flash::MultiwriteNorFlash;
use km43::Event;

use crate::record::{self, Class, Found, HEADER, Header, MAGIC_BYTES, MAX_RECORD, Unframed};

/// The scratch every operation wants: one record at its largest.
pub const SCRATCH: usize = MAX_RECORD;

/// Bytes read at a time while hunting for a magic or checking for erasure.
const WINDOW: usize = 64;
const _: () = assert!(WINDOW <= SCRATCH);
const _: () = assert!(WINDOW > 2);

/// How far into a block a probe hunts for its first record: past one
/// record at its largest, so a first record that failed its CRC does not
/// hide the valid one after it, and no further, so a part full of
/// somebody else's bytes costs a bounded read per block rather than the
/// whole block. The boot on a fresh part probes every block once.
const PROBE_REACH: usize = 2 * MAX_RECORD;

/// Hand the executor a turn between blocks, so a walk over thousands of
/// them is not a task that never checks in.
async fn yield_now() {
    let mut yielded = false;
    core::future::poll_fn(|cx| {
        if yielded {
            core::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await;
}

/// Where the log continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Head {
    /// The block the next record goes into.
    pub block: u32,
    /// The offset within it.
    pub at: u32,
    /// The sequence number the next record gets.
    pub next_seq: u64,
    /// The oldest sequence a client can still be given, if any. Below it
    /// the answer is *that is gone*, which is a different sentence from
    /// *there is nothing* (P-099).
    pub oldest: Option<u64>,
}

/// What the boot's scan had to step over, kept so it can be logged once the
/// log is open enough to log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Damage {
    /// Records whose CRC did not hold: a chip somebody has to look at.
    pub failed_crc: u32,
    /// Blocks closed by a torn write: ordinary, and counted so a rate is
    /// visible.
    pub closed: u32,
}

/// Why the ring could not be opened, appended to or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RingError<E> {
    /// Fewer than two blocks: the one being written and the one erased
    /// ahead of it cannot be the same block.
    TooFewBlocks(u32),
    /// A block too small for one record at its largest.
    BlockTooSmall(usize),
    /// The part programs more than a byte at a time. The magic is written
    /// after the body over the same two bytes the body write left erased,
    /// and that is a byte-granular program.
    WriteSizeNotOne(usize),
    /// The scratch offered is smaller than [`SCRATCH`].
    ScratchTooSmall(usize),
    /// An address past the part.
    OutOfRange,
    /// The record could not be framed.
    Unframed(Unframed),
    /// The payload is not an event, or names another sequence than the
    /// one the ring hands out next.
    NotTheNextEvent,
    /// A block of the ring's own, which only
    /// [`Ring::drop_oldest`] erases (#78).
    InsideTheRing(u32),
    /// The part refused.
    Flash(E),
}

impl<E> From<Unframed> for RingError<E> {
    fn from(unframed: Unframed) -> Self {
        Self::Unframed(unframed)
    }
}

/// What [`Ring::drop_oldest`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a drop nobody reports is a log that shrank without a word"]
pub enum Dropped {
    /// The ring held no records.
    Nothing,
    /// The block erased, counted within the ring, and the oldest sequence
    /// the ring holds after it, if any.
    Block {
        /// The block, counted from the ring's first.
        block: u32,
        /// The oldest sequence left.
        oldest: Option<u64>,
    },
}

/// Whether a reader wants more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Wants {
    /// Keep going.
    More,
    /// Stop here. The page is full, and the sequence the walk answers is
    /// what the client asks for next, which is not the same as the log
    /// ending.
    Enough,
}

/// What a probe of a block's first bytes found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Every byte still erased.
    Erased,
    /// Written and holding no readable record: a first record cut short,
    /// or damage.
    Closed,
    /// Holding records, the first at this sequence.
    Records { first: u64 },
}

/// The newest wall-clock timestamp the log holds, once looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Floor {
    /// Not looked for yet.
    Unknown,
    /// Looked for: the newest, or none in the whole ring.
    Found(Option<u64>),
}

/// What a scan of one block found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Scanned {
    first: Option<u64>,
    last: Option<u64>,
    /// The end of the last verified record: where an append would go.
    tail: u32,
    /// Something is written past the last verified record with no record
    /// after it: the block is finished.
    closed: bool,
    failed_crc: u32,
}

/// The ring on a part.
pub struct Ring<N> {
    flash: N,
    from: u32,
    blocks: u32,
    head: Head,
    damage: Damage,
    floor: Floor,
}

impl<N: MultiwriteNorFlash> Ring<N> {
    /// Open the ring spanning `blocks` erase blocks from address `from`,
    /// finding where the log continues.
    pub async fn open(
        flash: N,
        from: u32,
        blocks: u32,
        scratch: &mut [u8],
    ) -> Result<Self, RingError<N::Error>> {
        if N::WRITE_SIZE != 1 {
            return Err(RingError::WriteSizeNotOne(N::WRITE_SIZE));
        }
        if N::ERASE_SIZE < MAX_RECORD {
            return Err(RingError::BlockTooSmall(N::ERASE_SIZE));
        }
        if blocks < 2 {
            return Err(RingError::TooFewBlocks(blocks));
        }
        if scratch.len() < SCRATCH {
            return Err(RingError::ScratchTooSmall(scratch.len()));
        }
        let mut ring = Self {
            flash,
            from,
            blocks,
            head: Head {
                block: 0,
                at: 0,
                next_seq: 1,
                oldest: None,
            },
            damage: Damage::default(),
            floor: Floor::Unknown,
        };
        ring.find_the_head(scratch).await?;
        Ok(ring)
    }

    /// Where the next record goes.
    #[must_use]
    pub const fn head(&self) -> Head {
        self.head
    }

    /// The sequence the next record gets, which is what its payload must
    /// name.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.head.next_seq
    }

    /// What the boot's scan stepped over.
    #[must_use]
    pub const fn damage(&self) -> Damage {
        self.damage
    }

    /// The bytes an append of `payload` costs, for the budget.
    #[must_use]
    pub const fn cost(payload: usize) -> usize {
        record::framed_len(payload)
    }

    /// Hand the part back.
    pub fn release(self) -> N {
        self.flash
    }

    /// The part's bytes at `at`, as they are: for the bench tool, which
    /// wants what is on the part and not the records the ring makes of it.
    /// A read moves nothing.
    pub async fn read_raw(&mut self, at: u32, into: &mut [u8]) -> Result<(), RingError<N::Error>> {
        let end = usize::try_from(at)
            .ok()
            .and_then(|at| at.checked_add(into.len()))
            .ok_or(RingError::OutOfRange)?;
        if end > self.flash.capacity() {
            return Err(RingError::OutOfRange);
        }
        self.flash.read(at, into).await.map_err(RingError::Flash)
    }

    /// Erase one erase block of the part outside the ring, counted from the
    /// part's start: the bench tool's way to clear what the ring does not
    /// own, one block per request so that whoever feeds the watchdog gets a
    /// turn between two. A block of the ring's own is refused (#78): an
    /// erase anywhere but the oldest leaves a hole the head search reads
    /// as the end of the log, and the next record reuses a sequence. The
    /// ring's blocks go through [`drop_oldest`](Self::drop_oldest).
    pub async fn erase_block(&mut self, block: u32) -> Result<(), RingError<N::Error>> {
        let first = self.from.checked_div(Self::block_len()).unwrap_or(0);
        let ours = block
            .checked_sub(first)
            .is_some_and(|index| index < self.blocks);
        if ours {
            return Err(RingError::InsideTheRing(block));
        }
        let from = block
            .checked_mul(Self::block_len())
            .ok_or(RingError::OutOfRange)?;
        let to = from
            .checked_add(Self::block_len())
            .ok_or(RingError::OutOfRange)?;
        if usize::try_from(to).map_or(true, |to| to > self.flash.capacity()) {
            return Err(RingError::OutOfRange);
        }
        self.flash.erase(from, to).await.map_err(RingError::Flash)
    }

    /// Erase the block holding the oldest records, which is the block the
    /// ring would erase next anyway, and find the head again from the bytes
    /// as a boot would: the bench tool's way to shed the log, one block per
    /// request. The order of the ring is kept, so a sequence never comes
    /// back. When the oldest block is the head's, the ring held one block
    /// of records and is empty after it, and the next record is one again.
    ///
    /// The scratch is checked before the erase: a search that cannot run
    /// after the bytes are gone would leave a head describing bytes that
    /// are no longer there.
    pub async fn drop_oldest(
        &mut self,
        scratch: &mut [u8],
    ) -> Result<Dropped, RingError<N::Error>> {
        if scratch.len() < SCRATCH {
            return Err(RingError::ScratchTooSmall(scratch.len()));
        }
        if self.head.oldest.is_none() {
            return Ok(Dropped::Nothing);
        }
        let (block, _) = self.run(scratch).await?;
        self.erase(block).await?;
        self.damage = Damage::default();
        self.floor = Floor::Unknown;
        self.find_the_head(scratch).await?;
        Ok(Dropped::Block {
            block,
            oldest: self.head.oldest,
        })
    }

    /// Append one event and answer the sequence it got.
    ///
    /// `payload` is an encoded `Event` naming [`next_seq`](Self::next_seq),
    /// which is checked: the frame's sequence is the ring's, and a payload
    /// that disagrees with it would hand a client two numbers for one
    /// record. The body lands first, then the magic in a program of its
    /// own; a cut between the two leaves a record the scan reads as the
    /// tail.
    pub async fn append(
        &mut self,
        class: Class,
        payload: &[u8],
        scratch: &mut [u8],
    ) -> Result<u64, RingError<N::Error>> {
        let needs = record::framed_len(payload.len());
        if needs > N::ERASE_SIZE {
            return Err(RingError::Unframed(Unframed::PayloadTooLong(payload.len())));
        }
        if scratch.len() < SCRATCH {
            return Err(RingError::ScratchTooSmall(scratch.len()));
        }
        let seq = self.head.next_seq;
        let event = Event::decode(payload).map_err(|_| RingError::NotTheNextEvent)?;
        if event.seq.0 != seq {
            return Err(RingError::NotTheNextEvent);
        }
        // The page turns before the record is framed: turning it probes
        // the part through the same scratch the frame would sit in.
        if self.head.at.saturating_add(Self::len_u32(needs)?) > Self::block_len() {
            self.turn_the_page(scratch).await?;
        }
        let framed = record::frame(scratch, seq, class, payload)?;
        let at = self.address(self.head.block, self.head.at)?;
        self.flash
            .write(at.saturating_add(2), framed.body(scratch))
            .await
            .map_err(RingError::Flash)?;
        self.flash
            .write(at, &MAGIC_BYTES)
            .await
            .map_err(RingError::Flash)?;

        self.head.at = self.head.at.saturating_add(Self::len_u32(needs)?);
        self.head.next_seq = seq.saturating_add(1);
        if self.head.oldest.is_none() {
            self.head.oldest = Some(seq);
        }
        if let Some(at) = event.at {
            self.floor = Floor::Found(Some(at));
        }
        Ok(seq)
    }

    /// Visit records from `from` onward, oldest first, and answer the
    /// sequence a client should ask for next. A `from` below the oldest
    /// sequence held is answered from the oldest, so the client can see it
    /// lost data (P-099); a hole is a record that failed its CRC (P-096).
    pub async fn read_from(
        &mut self,
        from: u64,
        scratch: &mut [u8],
        mut visit: impl FnMut(&Found<'_>) -> Wants,
    ) -> Result<u64, RingError<N::Error>> {
        if scratch.len() < SCRATCH {
            return Err(RingError::ScratchTooSmall(scratch.len()));
        }
        let Some(oldest) = self.head.oldest else {
            return Ok(from.max(1));
        };
        let start = from.max(oldest).max(1);
        let (first_block, run) = self.run(scratch).await?;
        // The last block of the run whose first record is at or before
        // `start`, by binary search over the run.
        let mut lo = 0u32;
        let mut hi = run;
        while hi.saturating_sub(lo) > 1 {
            yield_now().await;
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            let first = self.first_in_run(first_block, run, mid, scratch).await?;
            if first.is_some_and(|first| first <= start) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let mut next = start;
        for k in lo..run {
            yield_now().await;
            let block = self.in_run(first_block, k);
            let (_, wants) = self
                .scan_block(block, Self::block_len(), scratch, &mut |found| {
                    if found.seq < start {
                        return Wants::More;
                    }
                    next = found.seq.saturating_add(1);
                    visit(found)
                })
                .await?;
            if wants == Wants::Enough {
                break;
            }
        }
        Ok(next)
    }

    /// The newest wall-clock timestamp the log holds, or `None` when no
    /// record carries one: the floor the first clock offer after boot is
    /// checked against (L-140), and the case the build timestamp is for
    /// (L-142). Found on the first call and remembered.
    pub async fn floor(&mut self, scratch: &mut [u8]) -> Result<Option<u64>, RingError<N::Error>> {
        if let Floor::Found(found) = self.floor {
            return Ok(found);
        }
        if scratch.len() < SCRATCH {
            return Err(RingError::ScratchTooSmall(scratch.len()));
        }
        let (first_block, run) = self.run(scratch).await?;
        let mut newest = None;
        for k in (0..run).rev() {
            yield_now().await;
            let block = self.in_run(first_block, k);
            let mut in_block = None;
            let _ = self
                .scan_block(block, Self::block_len(), scratch, &mut |found| {
                    if let Ok(event) = Event::decode(found.payload)
                        && let Some(at) = event.at
                    {
                        in_block = Some(at);
                    }
                    Wants::More
                })
                .await?;
            if in_block.is_some() {
                newest = in_block;
                break;
            }
        }
        self.floor = Floor::Found(newest);
        Ok(newest)
    }

    /// The blocks the log occupies, in ring order: the first, and how many.
    async fn run(&mut self, scratch: &mut [u8]) -> Result<(u32, u32), RingError<N::Error>> {
        // Post-wrap the run starts two past the head, after the erased
        // block; pre-wrap it starts at zero. Either way the first block of
        // the run is the first holding records from two past the head.
        let mut block = self.next_block(self.next_block(self.head.block));
        for _ in 0..self.blocks {
            yield_now().await;
            match self.probe(block, scratch).await? {
                Probe::Records { .. } => break,
                Probe::Erased | Probe::Closed => block = self.next_block(block),
            }
        }
        // The distance in the ring, not modulo two to the thirty-two: a
        // wrapping subtraction only comes out right when the block count
        // is a power of two, and 232 blocks of 64 KB is not.
        let run = self
            .head
            .block
            .saturating_add(self.blocks)
            .saturating_sub(block)
            .checked_rem(self.blocks)
            .unwrap_or(0)
            .saturating_add(1);
        Ok((block, run))
    }

    /// The k-th block of the run.
    fn in_run(&self, first_block: u32, k: u32) -> u32 {
        first_block
            .saturating_add(k)
            .checked_rem(self.blocks)
            .unwrap_or(0)
    }

    /// The first sequence at or after the k-th block of the run, skipping
    /// closed blocks; `None` past the head.
    async fn first_in_run(
        &mut self,
        first_block: u32,
        run: u32,
        k: u32,
        scratch: &mut [u8],
    ) -> Result<Option<u64>, RingError<N::Error>> {
        for j in k..run {
            yield_now().await;
            let block = self.in_run(first_block, j);
            match self.probe(block, scratch).await? {
                Probe::Records { first } => return Ok(Some(first)),
                Probe::Erased => return Ok(None),
                Probe::Closed => {}
            }
        }
        Ok(None)
    }

    /// The boot's question: where does the log continue?
    async fn find_the_head(&mut self, scratch: &mut [u8]) -> Result<(), RingError<N::Error>> {
        // An anchor: the first block holding records.
        let mut anchor = None;
        for block in 0..self.blocks {
            yield_now().await;
            match self.probe(block, scratch).await? {
                Probe::Records { first } => {
                    anchor = Some((block, first));
                    break;
                }
                Probe::Erased | Probe::Closed => {}
            }
        }
        let Some((anchor, first)) = anchor else {
            // Nothing readable anywhere: a fresh part, or one of torn first
            // writes only. Continue in the first erased block, or erase
            // block zero when every block was closed.
            let mut block = None;
            for candidate in 0..self.blocks {
                yield_now().await;
                if self.probe(candidate, scratch).await? == Probe::Erased {
                    block = Some(candidate);
                    break;
                }
            }
            // A probe reaches one record's length and no further, so it
            // cannot promise the rest of the block: read it whole before
            // the head goes into it, or an append programs over residue.
            let block = block.unwrap_or(0);
            self.ensure_erased(block, scratch).await?;
            self.head = Head {
                block,
                at: 0,
                next_seq: 1,
                oldest: None,
            };
            self.erase_ahead(scratch).await?;
            return Ok(());
        };

        // The last block whose nearest records are at or after the
        // anchor's: blocks before the head carry newer sequences than the
        // anchor, blocks after it carry older ones or nothing.
        let mut lo = anchor;
        let mut hi = self.blocks;
        while hi.saturating_sub(lo) > 1 {
            yield_now().await;
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            let nearest = self.nearest_records(mid, scratch).await?;
            if nearest.is_some_and(|seq| seq >= first) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let mut head = lo;
        let scanned = self.scan_whole(head, scratch).await?;
        let mut next_seq = scanned.last.map_or(1, |last| last.saturating_add(1));
        let mut at = scanned.tail;
        if scanned.closed {
            // The log continues in the next block, past any that a torn
            // first write closed as well. Whichever block it is, it is
            // read whole before the head goes into it: a probe reaches one
            // record's length and cannot promise the rest.
            at = 0;
            for _ in 0..self.blocks {
                yield_now().await;
                head = self.next_block(head);
                match self.probe(head, scratch).await? {
                    Probe::Closed => {}
                    Probe::Erased => break,
                    Probe::Records { .. } => {
                        // The erase ahead never landed: this is the oldest
                        // data, and it goes now.
                        break;
                    }
                }
            }
            self.ensure_erased(head, scratch).await?;
        }
        if next_seq == 1 {
            next_seq = first.saturating_add(1);
        }
        self.head = Head {
            block: head,
            at,
            next_seq,
            oldest: None,
        };
        self.erase_ahead(scratch).await?;
        self.head.oldest = self.find_the_oldest(first, scratch).await?;
        Ok(())
    }

    /// The first sequence held: the first record after the erased block
    /// ahead of the head, or, before the first wrap, the anchor's.
    async fn find_the_oldest(
        &mut self,
        anchor: u64,
        scratch: &mut [u8],
    ) -> Result<Option<u64>, RingError<N::Error>> {
        let mut block = self.next_block(self.next_block(self.head.block));
        for _ in 0..self.blocks {
            yield_now().await;
            match self.probe(block, scratch).await? {
                Probe::Records { first } => return Ok(Some(first)),
                Probe::Erased => return Ok(Some(anchor)),
                Probe::Closed => block = self.next_block(block),
            }
        }
        Ok(Some(anchor))
    }

    /// The first sequence in the first block holding records at or after
    /// `block`, stopping at an erased one.
    async fn nearest_records(
        &mut self,
        block: u32,
        scratch: &mut [u8],
    ) -> Result<Option<u64>, RingError<N::Error>> {
        for candidate in block..self.blocks {
            yield_now().await;
            match self.probe(candidate, scratch).await? {
                Probe::Records { first } => return Ok(Some(first)),
                Probe::Erased => return Ok(None),
                Probe::Closed => {}
            }
        }
        Ok(None)
    }

    /// Move the head into the next block and erase the one after it.
    async fn turn_the_page(&mut self, scratch: &mut [u8]) -> Result<(), RingError<N::Error>> {
        let next = self.next_block(self.head.block);
        // The erase ahead may not have landed before a reset, or the block
        // may have closed: it goes now, and an append waits once.
        self.ensure_erased(next, scratch).await?;
        self.head.block = next;
        self.head.at = 0;
        self.erase_ahead(scratch).await?;
        // The oldest records were in the block just erased; the oldest now
        // are the first after it, or, before the first wrap, unchanged.
        let anchor = self.head.oldest.unwrap_or(self.head.next_seq);
        self.head.oldest = self.find_the_oldest(anchor, scratch).await?;
        Ok(())
    }

    /// Erase the block after the head unless it already is.
    async fn erase_ahead(&mut self, scratch: &mut [u8]) -> Result<(), RingError<N::Error>> {
        let ahead = self.next_block(self.head.block);
        self.ensure_erased(ahead, scratch).await
    }

    /// Erase `block` unless every byte of it already is: the whole block
    /// read, because a probe reads one record's length and no further.
    async fn ensure_erased(
        &mut self,
        block: u32,
        scratch: &mut [u8],
    ) -> Result<(), RingError<N::Error>> {
        if !self.is_erased(block, scratch).await? {
            self.erase(block).await?;
        }
        Ok(())
    }

    async fn erase(&mut self, block: u32) -> Result<(), RingError<N::Error>> {
        let from = self.address(block, 0)?;
        let to = from
            .checked_add(Self::block_len())
            .ok_or(RingError::OutOfRange)?;
        self.flash.erase(from, to).await.map_err(RingError::Flash)
    }

    /// What a block's first bytes say, from one probe's reach and no more.
    async fn probe(
        &mut self,
        block: u32,
        scratch: &mut [u8],
    ) -> Result<Probe, RingError<N::Error>> {
        let reach = Self::len_u32(PROBE_REACH)?.min(Self::block_len());
        let (scanned, _) = self
            .scan_block(block, reach, scratch, &mut |_| Wants::Enough)
            .await?;
        Ok(match scanned.first {
            Some(first) => Probe::Records { first },
            None if scanned.tail == 0 && !scanned.closed => Probe::Erased,
            None => Probe::Closed,
        })
    }
    /// Scan a whole block, counting what it holds.
    async fn scan_whole(
        &mut self,
        block: u32,
        scratch: &mut [u8],
    ) -> Result<Scanned, RingError<N::Error>> {
        let len = Self::block_len();
        let (scanned, _) = self
            .scan_block(block, len, scratch, &mut |_| Wants::More)
            .await?;
        self.damage.failed_crc = self.damage.failed_crc.saturating_add(scanned.failed_crc);
        if scanned.closed {
            self.damage.closed = self.damage.closed.saturating_add(1);
        }
        Ok(scanned)
    }
    /// Stream the records of one block through `scratch`, verifying each,
    /// hunting forward past one that does not hold, and stopping at the
    /// erased tail or at residue nothing readable follows. The hunt for a
    /// record's start goes no further than `reach`; a record that starts
    /// inside it is read whole.
    ///
    /// An erased header is the tail. A body lands from its first byte, so
    /// a torn write leaves bytes right after the magic's two; a block that
    /// reads erased where a record would start holds nothing after it that
    /// this log wrote.
    async fn scan_block(
        &mut self,
        block: u32,
        reach: u32,
        scratch: &mut [u8],
        visit: &mut impl FnMut(&Found<'_>) -> Wants,
    ) -> Result<(Scanned, Wants), RingError<N::Error>> {
        let base = self.address(block, 0)?;
        let len = Self::block_len();
        let mut scanned = Scanned::default();
        let mut at: u32 = 0;
        let mut wants = Wants::More;
        // Bounded by the reach: every turn either consumes a record or
        // moves the hunt forward by at least a byte.
        while at < reach {
            let remaining = len.saturating_sub(at);
            let head_len = remaining.min(Self::len_u32(HEADER)?);
            let head = scratch
                .get_mut(..Self::len_usize(head_len))
                .ok_or(RingError::ScratchTooSmall(0))?;
            self.flash
                .read(base.saturating_add(at), head)
                .await
                .map_err(RingError::Flash)?;
            let header = if head_len == Self::len_u32(HEADER)? {
                Header::parse(head)
            } else {
                None
            };
            let candidate = header.and_then(|header| {
                let record_len = header.record_len()?;
                (Self::len_u32(record_len).ok()? <= remaining).then_some(record_len)
            });
            if let Some(record_len) = candidate {
                let rest = scratch
                    .get_mut(HEADER..record_len)
                    .ok_or(RingError::ScratchTooSmall(0))?;
                self.flash
                    .read(
                        base.saturating_add(at)
                            .saturating_add(Self::len_u32(HEADER)?),
                        rest,
                    )
                    .await
                    .map_err(RingError::Flash)?;
                if let Some(found) = record::verify(scratch) {
                    scanned.first.get_or_insert(found.seq);
                    scanned.last = Some(found.seq);
                    at = at.saturating_add(Self::len_u32(record_len)?);
                    scanned.tail = at;
                    wants = visit(&found);
                    if wants == Wants::Enough {
                        return Ok((scanned, wants));
                    }
                    continue;
                }
                scanned.failed_crc = scanned.failed_crc.saturating_add(1);
                let Some(next) = self
                    .hunt(base, at.saturating_add(1), reach, scratch)
                    .await?
                else {
                    scanned.closed = true;
                    break;
                };
                at = next;
                continue;
            }
            let erased_head = scratch
                .get(..Self::len_usize(head_len))
                .is_some_and(|head| head.iter().all(|byte| *byte == 0xFF));
            if erased_head {
                // The tail: nothing this log wrote lies past an erased
                // header.
                break;
            }
            if header.is_some() {
                // A magic with a header nobody can read.
                scanned.failed_crc = scanned.failed_crc.saturating_add(1);
            }
            // Always from the next byte: a magic in the last bytes of the
            // block, too short to be a header, would otherwise be found at
            // `at` again and again.
            let from = at.saturating_add(1);
            let Some(next) = self.hunt(base, from, reach, scratch).await? else {
                scanned.closed = true;
                break;
            };
            at = next;
        }
        Ok((scanned, wants))
    }
    async fn hunt(
        &mut self,
        base: u32,
        from: u32,
        len: u32,
        scratch: &mut [u8],
    ) -> Result<Option<u32>, RingError<N::Error>> {
        let mut at = from;
        // Each window overlaps the last by one byte, so a magic across the
        // seam is seen; each turn moves by at least one byte.
        while at.saturating_add(1) < len {
            let take = len.saturating_sub(at).min(Self::len_u32(WINDOW)?);
            let window = scratch
                .get_mut(..Self::len_usize(take))
                .ok_or(RingError::ScratchTooSmall(0))?;
            self.flash
                .read(base.saturating_add(at), window)
                .await
                .map_err(RingError::Flash)?;
            if let Some(offset) = window.windows(2).position(|pair| pair == MAGIC_BYTES) {
                return Ok(Some(at.saturating_add(Self::len_u32(offset)?)));
            }
            at = at.saturating_add(take.saturating_sub(1));
        }
        Ok(None)
    }

    /// Whether every byte of the block is erased: the check before a block
    /// is appended into, which reads the whole of it once.
    async fn is_erased(
        &mut self,
        block: u32,
        scratch: &mut [u8],
    ) -> Result<bool, RingError<N::Error>> {
        let base = self.address(block, 0)?;
        let len = Self::block_len();
        let mut at = 0;
        while at < len {
            let take = len.saturating_sub(at).min(Self::len_u32(WINDOW)?);
            let window = scratch
                .get_mut(..Self::len_usize(take))
                .ok_or(RingError::ScratchTooSmall(0))?;
            self.flash
                .read(base.saturating_add(at), window)
                .await
                .map_err(RingError::Flash)?;
            if window.iter().any(|byte| *byte != 0xFF) {
                return Ok(false);
            }
            at = at.saturating_add(take);
        }
        Ok(true)
    }
    fn next_block(&self, block: u32) -> u32 {
        block
            .saturating_add(1)
            .checked_rem(self.blocks)
            .unwrap_or(0)
    }

    fn address(&self, block: u32, at: u32) -> Result<u32, RingError<N::Error>> {
        block
            .checked_mul(Self::block_len())
            .and_then(|offset| offset.checked_add(self.from))
            .and_then(|start| start.checked_add(at))
            .ok_or(RingError::OutOfRange)
    }

    fn block_len() -> u32 {
        u32::try_from(N::ERASE_SIZE).unwrap_or(u32::MAX)
    }

    fn len_u32(len: usize) -> Result<u32, RingError<N::Error>> {
        u32::try_from(len).map_err(|_| RingError::OutOfRange)
    }

    fn len_usize(len: u32) -> usize {
        usize::try_from(len).unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use embedded_storage_async::nor_flash::{
        ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
    };
    use km43::{EventKind, LogSeq};

    use super::*;

    const ERASE: usize = 512;
    const BLOCKS: u32 = 8;
    /// Sixteen kilobytes: eight blocks of 512 for most tests, four of
    /// 4096 for the one that needs a block a record cannot fill.
    const PART: usize = 16 * 1024;

    /// A byte-programmable NOR part in an array, `E` bytes a block.
    struct Part<const E: usize> {
        bytes: [u8; PART],
        /// Bytes read since the part was made.
        read: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Refused;

    impl NorFlashError for Refused {
        fn kind(&self) -> NorFlashErrorKind {
            NorFlashErrorKind::Other
        }
    }

    impl<const E: usize> ErrorType for Part<E> {
        type Error = Refused;
    }

    impl<const E: usize> ReadNorFlash for Part<E> {
        const READ_SIZE: usize = 1;

        fn read(
            &mut self,
            offset: u32,
            bytes: &mut [u8],
        ) -> impl Future<Output = Result<(), Refused>> {
            let at = offset as usize;
            self.read = self.read.saturating_add(bytes.len());
            let outcome = self
                .bytes
                .get(at..at.saturating_add(bytes.len()))
                .map(|found| bytes.copy_from_slice(found))
                .ok_or(Refused);
            core::future::ready(outcome)
        }

        fn capacity(&self) -> usize {
            PART
        }
    }

    impl<const E: usize> NorFlash for Part<E> {
        const WRITE_SIZE: usize = 1;
        const ERASE_SIZE: usize = E;

        fn erase(&mut self, from: u32, to: u32) -> impl Future<Output = Result<(), Refused>> {
            let outcome = self
                .bytes
                .get_mut(from as usize..to as usize)
                .map(|block| block.fill(0xFF))
                .ok_or(Refused);
            core::future::ready(outcome)
        }

        fn write(
            &mut self,
            offset: u32,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused>> {
            let at = offset as usize;
            let outcome = self
                .bytes
                .get_mut(at..at.saturating_add(bytes.len()))
                .map(|room| {
                    for (slot, byte) in room.iter_mut().zip(bytes) {
                        *slot &= *byte;
                    }
                })
                .ok_or(Refused);
            core::future::ready(outcome)
        }
    }

    impl<const E: usize> MultiwriteNorFlash for Part<E> {}

    fn fresh<const E: usize>() -> Part<E> {
        Part {
            bytes: [0xFF; PART],
            read: 0,
        }
    }

    /// An event for `seq`, at `at` on the clock, with an empty body.
    fn event(seq: u64, at: Option<u64>, into: &mut [u8]) -> usize {
        Event::new(LogSeq(seq), at, EventKind::BOOT, &[0xA0])
            .expect("an empty map is a body")
            .encode(into)
            .expect("fits")
    }

    /// Boot: take the part into a ring. The part is worth a few kilobytes,
    /// so it moves rather than borrows; `close` hands it back.
    fn open<const E: usize>(part: &mut Part<E>) -> Ring<Part<E>> {
        let blocks = u32::try_from(PART.checked_div(E).expect("a block size"))
            .expect("fits")
            .min(BLOCKS);
        open_with(part, blocks)
    }

    /// Boot over `blocks` blocks of the part.
    fn open_with<const E: usize>(part: &mut Part<E>, blocks: u32) -> Ring<Part<E>> {
        let taken = core::mem::replace(part, fresh());
        let mut scratch = [0u8; SCRATCH];
        block_on(Ring::open(taken, 0, blocks, &mut scratch)).expect("opens")
    }

    /// Power off: the part comes back out of the ring.
    fn close<const E: usize>(part: &mut Part<E>, ring: Ring<Part<E>>) {
        *part = ring.release();
    }

    /// Append one class A event, answering its sequence.
    fn append<const E: usize>(ring: &mut Ring<Part<E>>, at: Option<u64>) -> u64 {
        let mut payload = [0u8; 64];
        let len = event(ring.next_seq(), at, &mut payload);
        let mut scratch = [0u8; SCRATCH];
        block_on(ring.append(Class::A, &payload[..len], &mut scratch)).expect("appends")
    }

    /// Every sequence readable from `from`, and what the client asks next.
    fn read<const E: usize>(ring: &mut Ring<Part<E>>, from: u64) -> ([u64; 256], usize, u64) {
        let mut seqs = [0u64; 256];
        let mut count = 0;
        let mut scratch = [0u8; SCRATCH];
        let next = block_on(ring.read_from(from, &mut scratch, |found| {
            seqs[count] = found.seq;
            count = count.saturating_add(1);
            Wants::More
        }))
        .expect("reads");
        (seqs, count, next)
    }

    #[test]
    fn a_raw_read_answers_the_bytes_on_the_part_and_refuses_past_its_end() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        assert_eq!(append(&mut ring, None), 1);
        let mut head = [0u8; 2];
        block_on(ring.read_raw(0, &mut head)).expect("reads");
        assert_eq!(
            head, MAGIC_BYTES,
            "the first record's magic is at the ring's start"
        );
        let mut beyond = [0u8; 2];
        let end = u32::try_from(PART).expect("fits");
        assert_eq!(
            block_on(ring.read_raw(end.saturating_sub(1), &mut beyond)),
            Err(RingError::OutOfRange)
        );
        assert_eq!(block_on(ring.read_raw(end, &mut [])), Ok(()));
    }

    #[test]
    fn dropping_the_only_block_of_records_leaves_a_fresh_ring() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        for _ in 0..3 {
            append(&mut ring, None);
        }
        assert_eq!(ring.next_seq(), 4);
        let mut scratch = [0u8; SCRATCH];
        assert_eq!(
            block_on(ring.drop_oldest(&mut scratch)),
            Ok(Dropped::Block {
                block: 0,
                oldest: None
            })
        );
        assert_eq!(
            ring.head(),
            Head {
                block: 0,
                at: 0,
                next_seq: 1,
                oldest: None
            },
            "a ring with nothing on it is a fresh ring"
        );
        assert_eq!(
            block_on(ring.drop_oldest(&mut scratch)),
            Ok(Dropped::Nothing),
            "and there is nothing more to drop"
        );
        assert_eq!(append(&mut ring, None), 1);
        let (_, count, next) = read(&mut ring, 1);
        assert_eq!((count, next), (1, 2));
    }

    /// Past a wrap, every drop takes the oldest block and nothing else: the
    /// oldest sequence climbs, the next one stays where it was, what is left
    /// reads back contiguous, and a boot finds the same ring (#78).
    #[test]
    fn f_023_dropping_the_oldest_block_sheds_the_old_end_and_never_reuses_a_sequence() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open_with(&mut part, 4);
        for _ in 0..60 {
            append(&mut ring, None);
        }
        let next = ring.next_seq();
        let mut oldest = ring.head().oldest.expect("records");
        assert!(oldest > 1, "the ring has wrapped");
        let mut scratch = [0u8; SCRATCH];
        let mut dropped = 0;
        // Bounded: a drop that leaves records moves the oldest past a
        // block's worth, and four blocks hold at most three of them.
        for _ in 0..5 {
            match block_on(ring.drop_oldest(&mut scratch)).expect("drops") {
                Dropped::Block {
                    oldest: Some(left), ..
                } => {
                    dropped += 1;
                    assert!(left > oldest, "{left} after {oldest}");
                    assert_eq!(ring.next_seq(), next, "the next sequence never moves back");
                    let (seqs, count, answered) = read(&mut ring, 1);
                    assert_eq!(
                        count as u64,
                        next - left,
                        "every record from the oldest left"
                    );
                    assert!(seqs[..count].iter().copied().eq(left..next), "contiguous");
                    assert_eq!(answered, next);
                    let head = ring.head();
                    close(&mut part, ring);
                    ring = open_with(&mut part, 4);
                    assert_eq!(ring.head(), head, "a boot finds the same ring");
                    oldest = left;
                }
                Dropped::Block { oldest: None, .. } => {
                    dropped += 1;
                    assert_eq!(
                        ring.next_seq(),
                        1,
                        "the last block went: the log starts over"
                    );
                    break;
                }
                Dropped::Nothing => panic!("records were left"),
            }
        }
        assert!(dropped >= 2, "{dropped} drops");
        assert_eq!(
            block_on(ring.drop_oldest(&mut scratch)),
            Ok(Dropped::Nothing)
        );
    }

    #[test]
    fn an_undersized_scratch_is_refused_before_anything_is_dropped() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        for _ in 0..3 {
            append(&mut ring, None);
        }
        let before = ring.head();
        let mut small = [0u8; SCRATCH - 1];
        assert_eq!(
            block_on(ring.drop_oldest(&mut small)),
            Err(RingError::ScratchTooSmall(SCRATCH - 1))
        );
        assert_eq!(ring.head(), before, "the head still describes the bytes");
        let mut first = [0u8; 2];
        block_on(ring.read_raw(0, &mut first)).expect("reads");
        assert_eq!(first, MAGIC_BYTES, "and the bytes are still there");
    }

    #[test]
    fn a_block_outside_the_ring_is_erased_and_one_inside_it_is_refused() {
        let mut part: Part<ERASE> = fresh();
        // Four of the part's thirty-two blocks are the ring's.
        let mut ring = open_with(&mut part, 4);
        for _ in 0..3 {
            append(&mut ring, None);
        }
        let before = ring.head();
        block_on(ring.erase_block(6)).expect("erases");
        assert_eq!(ring.head(), before);
        for block in 0..4 {
            assert_eq!(
                block_on(ring.erase_block(block)),
                Err(RingError::InsideTheRing(block)),
                "only the oldest goes, through drop_oldest (#78)"
            );
        }
        assert_eq!(ring.head(), before);
        let blocks = u32::try_from(PART / ERASE).expect("fits");
        assert_eq!(
            block_on(ring.erase_block(blocks)),
            Err(RingError::OutOfRange),
            "the block after the last is past the part"
        );
    }

    #[test]
    fn f_023_a_fresh_part_opens_empty_and_the_first_record_is_one() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        assert_eq!(
            ring.head(),
            Head {
                block: 0,
                at: 0,
                next_seq: 1,
                oldest: None
            }
        );
        let (_, count, next) = read(&mut ring, 1);
        assert_eq!((count, next), (0, 1));
        assert_eq!(append(&mut ring, None), 1);
        assert_eq!(append(&mut ring, None), 2);
        assert_eq!(ring.head().oldest, Some(1));
        let (seqs, count, next) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1, 2]);
        assert_eq!(next, 3);
        // A reboot finds the same head.
        close(&mut part, ring);
        let ring = open(&mut part);
        assert_eq!(ring.head().next_seq, 3);
        assert_eq!(ring.head().oldest, Some(1));
        assert_eq!(ring.damage(), Damage::default());
    }

    #[test]
    fn f_023_the_ring_wraps_the_oldest_block_is_erased_one_ahead_and_the_oldest_moves() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        // About 21 bytes a record: about 24 per 512-byte block, 8 blocks.
        let mut last = 0;
        for _ in 0..300 {
            last = append(&mut ring, None);
        }
        let head = ring.head();
        assert!(head.block < BLOCKS);
        assert_eq!(head.next_seq, last + 1);
        let oldest = head.oldest.expect("the ring holds records");
        assert!(
            oldest > 1,
            "the ring wrapped and the first records are gone"
        );
        // Everything from the oldest to the newest reads back in order.
        let (seqs, count, next) = read(&mut ring, oldest);
        assert_eq!(count as u64, last - oldest + 1);
        assert!(seqs[..count].windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(next, last + 1);
        close(&mut part, ring);
        // The block after the head is erased, ready.
        let ahead = ((head.block + 1) % BLOCKS) as usize;
        assert!(
            part.bytes[ahead * ERASE..(ahead + 1) * ERASE]
                .iter()
                .all(|b| *b == 0xFF)
        );
        // And a reboot agrees on all of it.
        let rebooted = open(&mut part);
        assert_eq!(rebooted.head(), head);
    }

    #[test]
    fn p_099_a_read_from_below_the_oldest_is_answered_from_the_oldest() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        for _ in 0..300 {
            let _ = append(&mut ring, None);
        }
        let oldest = ring.head().oldest.expect("records");
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(seqs[0], oldest);
        assert!(count > 0);
        // From the middle: exactly the records from there.
        let (seqs, _, _) = read(&mut ring, oldest + 10);
        assert_eq!(seqs[0], oldest + 10);
        // Past the newest: nothing, and ask again from there.
        let newest = ring.next_seq() - 1;
        let (_, count, next) = read(&mut ring, newest + 5);
        assert_eq!((count, next), (0, newest + 5));
    }

    #[test]
    fn p_096_a_record_that_fails_its_crc_is_a_hole_and_the_scan_hunts_past_it() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        for _ in 0..5 {
            let _ = append(&mut ring, None);
        }
        close(&mut part, ring);
        // Flip a payload bit in the third record: block 0, records of one
        // length, so the third starts at 2 * len.
        let len = record::framed_len(event(1, None, &mut [0u8; 64]));
        part.bytes[2 * len + HEADER] ^= 0x01;
        let mut ring = open(&mut part);
        assert_eq!(ring.damage().failed_crc, 1);
        assert_eq!(ring.damage().closed, 0);
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1, 2, 4, 5]);
        // The head is still past the fifth record: the length of the
        // damaged one was not trusted, its magic was hunted past.
        assert_eq!(ring.head().at as usize, 5 * len);
        assert_eq!(append(&mut ring, None), 6);
    }

    #[test]
    fn f_023_a_torn_write_closes_its_block_and_is_not_damage() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        for _ in 0..3 {
            let _ = append(&mut ring, None);
        }
        let at = ring.head().at as usize;
        close(&mut part, ring);
        // A body that landed without its magic: the next record cut
        // before the last program.
        let mut payload = [0u8; 64];
        let plen = event(4, None, &mut payload);
        let mut framed = [0u8; SCRATCH];
        let f = record::frame(&mut framed, 4, Class::A, &payload[..plen]).expect("frames");
        part.bytes[at + 2..at + f.len()].copy_from_slice(f.body(&framed));
        let mut ring = open(&mut part);
        assert_eq!(
            ring.damage(),
            Damage {
                failed_crc: 0,
                closed: 1
            }
        );
        // The three records stay readable; the log continues in block 1
        // and the sequence continues from four.
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1, 2, 3]);
        assert_eq!(ring.head().block, 1);
        assert_eq!(ring.head().at, 0);
        assert_eq!(append(&mut ring, None), 4);
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1, 2, 3, 4]);
    }

    #[test]
    fn f_023_a_first_write_cut_short_on_a_fresh_part_is_an_ordinary_first_boot() {
        let mut part: Part<ERASE> = fresh();
        // Half a body at the very start of block 0, no magic, nothing else.
        part.bytes[2..10].copy_from_slice(&[0x12; 8]);
        let mut ring = open(&mut part);
        assert_eq!(ring.damage().failed_crc, 0);
        assert_eq!(ring.head().block, 1);
        assert_eq!(ring.head().next_seq, 1);
        assert_eq!(append(&mut ring, None), 1);
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1]);
    }

    #[test]
    fn l_140_the_floor_is_the_newest_timestamp_held_and_none_when_no_record_carries_one() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        let mut scratch = [0u8; SCRATCH];
        assert_eq!(block_on(ring.floor(&mut scratch)), Ok(None));
        let _ = append(&mut ring, None);
        let _ = append(&mut ring, Some(1_790_000_000_000));
        let _ = append(&mut ring, Some(1_790_000_050_000));
        let _ = append(&mut ring, None);
        assert_eq!(
            block_on(ring.floor(&mut scratch)),
            Ok(Some(1_790_000_050_000))
        );
        // A reboot finds it again by walking back, across blocks.
        for _ in 0..40 {
            let _ = append(&mut ring, None);
        }
        close(&mut part, ring);
        let mut rebooted = open(&mut part);
        assert!(rebooted.head().block >= 1);
        assert_eq!(
            block_on(rebooted.floor(&mut scratch)),
            Ok(Some(1_790_000_050_000))
        );
        // A newer timestamp appended moves it without a walk.
        let _ = append(&mut rebooted, Some(1_790_000_999_000));
        assert_eq!(
            block_on(rebooted.floor(&mut scratch)),
            Ok(Some(1_790_000_999_000))
        );
    }

    #[test]
    fn f_023_a_part_full_of_somebody_elses_bytes_opens_in_bounded_reads_and_starts_over() {
        // Four blocks of 4096, every byte a pseudo-random non-erased value,
        // the way a part out of another firmware reads.
        const BIG: usize = 4096;
        let mut part: Part<BIG> = fresh();
        let mut x: u32 = 0x1234_5678;
        for byte in &mut part.bytes {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (x >> 24) as u8 | 0x01;
        }
        part.read = 0;
        let mut ring = open(&mut part);
        // Nothing readable anywhere: the log starts over in block zero,
        // erased for it, with block one erased ahead.
        assert_eq!(ring.head().block, 0);
        assert_eq!(ring.head().next_seq, 1);
        assert_eq!(append(&mut ring, None), 1);
        close(&mut part, ring);
        // The boot read a probe's reach per block on each of its two passes
        // over them, plus the whole of the blocks it checked for erasure,
        // and never the whole of every block.
        let blocks = PART / BIG;
        let reach = 2 * blocks * (PROBE_REACH + 2 * WINDOW);
        assert!(
            part.read <= reach + 3 * BIG,
            "{} bytes read, more than {}",
            part.read,
            reach + 3 * BIG
        );
        assert!(
            part.read < 2 * PART,
            "{} bytes read: the whole part, twice",
            part.read
        );
        let ring = open(&mut part);
        assert_eq!(ring.head().next_seq, 2);
    }

    #[test]
    fn p_099_the_run_is_the_distance_in_the_ring_for_a_block_count_that_is_not_a_power_of_two() {
        // Six blocks: two to the thirty-two leaves four modulo six, so a
        // wrapping subtraction makes the run four blocks too long, and the
        // walk then hands a client the oldest records again after the
        // newest. Five would leave one, which only revisits the erased
        // block and shows nothing.
        let mut part: Part<ERASE> = fresh();
        let mut ring = open_with(&mut part, 6);
        let mut last = 0;
        for i in 0..120u64 {
            last = append(&mut ring, Some(1_790_000_000_000 + i));
        }
        let oldest = ring.head().oldest.expect("records");
        assert!(oldest > 1);
        let (seqs, count, next) = read(&mut ring, 1);
        assert_eq!(seqs[0], oldest);
        assert!(seqs[..count].windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(next, last + 1);
        let mut scratch = [0u8; SCRATCH];
        assert_eq!(
            block_on(ring.floor(&mut scratch)),
            Ok(Some(1_790_000_000_000 + 119))
        );
        // A reboot walks the same run.
        close(&mut part, ring);
        let mut rebooted = open_with(&mut part, 6);
        let (seqs, count, _) = read(&mut rebooted, 1);
        assert_eq!(seqs[0], oldest);
        assert_eq!(seqs[count - 1], last);
    }

    #[test]
    fn f_023_a_magic_in_the_last_bytes_of_a_block_does_not_trap_the_scan() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        let _ = append(&mut ring, None);
        let tail = ring.head().at as usize;
        close(&mut part, ring);
        // Residue from the tail to the end of the block, ending in the two
        // bytes of the magic with no room for a header behind them.
        for byte in &mut part.bytes[tail..ERASE] {
            *byte = 0x55;
        }
        part.bytes[ERASE - 2..ERASE].copy_from_slice(&MAGIC_BYTES);
        let mut ring = open(&mut part);
        assert_eq!(ring.head().block, 1);
        assert_eq!(ring.damage().closed, 1);
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(&seqs[..count], &[1]);
        assert_eq!(append(&mut ring, None), 2);
    }

    #[test]
    fn f_023_a_block_erased_only_at_its_start_is_erased_whole_before_the_head_goes_into_it() {
        // Four blocks of 4096. Block zero reads erased for a probe's reach
        // and holds somebody else's bytes past it; blocks one to three
        // hold bytes from their first byte, so nothing anchors.
        const BIG: usize = 4096;
        let mut part: Part<BIG> = fresh();
        for byte in &mut part.bytes[PROBE_REACH + 8..] {
            *byte = 0x5A;
        }
        let mut ring = open(&mut part);
        assert_eq!(ring.head().block, 0);
        assert_eq!(ring.head().at, 0);
        // Fill the block: every record must read back, which it cannot if
        // the residue past the reach is still there when a record lands
        // over it.
        let mut last = 0;
        let mut payload = [0u8; 64];
        let len = record::framed_len(event(1, None, &mut payload));
        for _ in 0..BIG / len {
            last = append(&mut ring, None);
        }
        let (seqs, count, _) = read(&mut ring, 1);
        assert_eq!(count as u64, last);
        assert!(seqs[..count].windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(ring.damage().failed_crc, 0);
        close(&mut part, ring);
        // And the same on a reboot, which scans the block whole.
        let mut rebooted = open(&mut part);
        assert_eq!(rebooted.damage().failed_crc, 0);
        let (_, count, _) = read(&mut rebooted, 1);
        assert_eq!(count as u64, last);
    }

    #[test]
    fn a_payload_that_is_not_the_next_event_is_refused_before_anything_lands() {
        let mut part: Part<ERASE> = fresh();
        let mut ring = open(&mut part);
        let mut payload = [0u8; 64];
        let len = event(7, None, &mut payload);
        let mut scratch = [0u8; SCRATCH];
        assert_eq!(
            block_on(ring.append(Class::A, &payload[..len], &mut scratch)),
            Err(RingError::NotTheNextEvent)
        );
        assert_eq!(
            block_on(ring.append(Class::A, b"not cbor", &mut scratch)),
            Err(RingError::NotTheNextEvent)
        );
        let mut small = [0u8; 16];
        assert_eq!(
            block_on(ring.append(Class::A, &payload[..len], &mut small)),
            Err(RingError::ScratchTooSmall(16))
        );
        close(&mut part, ring);
        assert!(part.bytes.iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn a_ring_of_one_block_or_a_scratch_under_a_record_is_refused() {
        let mut scratch = [0u8; SCRATCH];
        assert!(matches!(
            block_on(Ring::open(fresh::<ERASE>(), 0, 1, &mut scratch)),
            Err(RingError::TooFewBlocks(1))
        ));
        let mut small = [0u8; 8];
        assert!(matches!(
            block_on(Ring::open(fresh::<ERASE>(), 0, BLOCKS, &mut small)),
            Err(RingError::ScratchTooSmall(8))
        ));
    }
}
