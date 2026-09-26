//! Reading the event log from a position: one walk serves both a client's
//! `ReadLog` page and a subscription's next events.
//!
//! **A subscription is a cursor into the log.** There is no outbox (KM43
//! `ReadLog`): each subscribed session holds the next position it is owed,
//! and its events are read out of the ring from there. Replay and live
//! delivery are then one path, so nothing created between the subscription
//! and the end of its replay can fall between the two (P-094).
//!
//! The ring belongs to one task, so the sessions ask it for a batch and the
//! batch comes back as the records' own bytes: a stored record is an
//! encoded `Event`, which is exactly an `Event 0x04` body and a `LogPage`
//! entry, so nothing is decoded and built again on the way out.
//!
//! The other direction is here too: [`record_owed`] is the recorder's turn
//! of the reading plane, writing what a tick owes into the ring and telling
//! the site which records landed.
//!
//! cites: P-094, P-096, P-099, P-144, P-182

use embedded_storage_async::nor_flash::MultiwriteNorFlash;
use km43::{Event, LogSeq, MAX_LOG_PAGE_BYTES, MAX_LOG_PAGE_ENTRIES};

use crate::record::{self, Class};
use crate::ring::{Ring, RingError, Wants};
use crate::site::{OwedError, RECORD_BODY, Site, TICK_RECORDS, Tally};
use crate::tick::Tick;

/// The one site, behind whatever keeps its writers apart.
///
/// The tick is read inside the same exclusion every writer takes, so a
/// reading is never asked about at a tick older than its last write.
pub trait SiteCell {
    /// Run `with` over the site at the current tick.
    fn with<R>(&self, with: impl FnOnce(&mut Site, Tick) -> R) -> R;
}

/// What one turn of [`record_owed`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a record the ring refused is a change no client hears of until the next tick"]
pub struct PlaneTurn {
    /// Records that landed.
    pub landed: usize,
    /// A record the ring refused, given back to the site; the turn stopped
    /// there and the next tick owes it again.
    pub refused: bool,
    /// A record the site could not write: a defect, surfaced.
    pub unwritten: Option<OwedError>,
}

/// One tick of the reading plane: every record the site owes, at most
/// [`TICK_RECORDS`], appended in order under the wall-clock `at` when the
/// controller holds one. The site is held only between appends, never
/// across one.
pub async fn record_owed<N: MultiwriteNorFlash>(
    site: &impl SiteCell,
    ring: &mut Ring<N>,
    scratch: &mut [u8],
    at: Option<u64>,
) -> PlaneTurn {
    let mut done = PlaneTurn::default();
    let mut tally = Tally::new();
    let mut body = [0u8; RECORD_BODY];
    let mut payload = [0u8; record::MAX_PAYLOAD];
    for _ in 0..TICK_RECORDS {
        let seq = ring.next_seq();
        let owed = site.with(|site, now| site.next_owed(now, seq, &mut tally, &mut body));
        let owed = match owed {
            Ok(Some(owed)) => owed,
            Ok(None) => break,
            Err(why) => {
                done.unwritten = Some(why);
                break;
            }
        };
        let written = body.get(..owed.len).unwrap_or(&[]);
        let framed = Event::new(LogSeq(seq), at, owed.kind, written)
            .ok()
            .and_then(|event| event.encode(&mut payload).ok());
        let landed = match framed {
            Some(len) => ring
                .append(Class::A, payload.get(..len).unwrap_or(&[]), scratch)
                .await
                .ok(),
            None => None,
        };
        if let Some(seq) = landed {
            site.with(|site, _| site.committed(&owed.token, seq));
            done.landed = done.landed.saturating_add(1);
        } else {
            site.with(|site, _| site.not_committed(&owed.token, written));
            done.refused = true;
            break;
        }
    }
    done
}

/// Bytes one batch holds: a `LogPage`'s entry budget.
pub const LOG_BATCH_BYTES: usize = MAX_LOG_PAGE_BYTES;

const _: () = assert!(
    LOG_BATCH_BYTES >= record::MAX_PAYLOAD,
    "a batch must hold at least one record at its largest, or a walk takes nothing"
);

/// Records from one position, as the ring holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogBatch {
    bytes: [u8; LOG_BATCH_BYTES],
    lens: [u16; MAX_LOG_PAGE_ENTRIES],
    seqs: [u64; MAX_LOG_PAGE_ENTRIES],
    count: usize,
    used: usize,
    next: u64,
    oldest: u64,
    newest: u64,
}

impl Default for LogBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBatch {
    /// Nothing read, from a log holding nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; LOG_BATCH_BYTES],
            lens: [0; MAX_LOG_PAGE_ENTRIES],
            seqs: [0; MAX_LOG_PAGE_ENTRIES],
            count: 0,
            used: 0,
            next: 1,
            oldest: 0,
            newest: 0,
        }
    }

    /// Records taken.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether none was.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Record `index`: its position and its encoded `Event`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<(u64, &[u8])> {
        if index >= self.count {
            return None;
        }
        let start = self
            .lens
            .get(..index)?
            .iter()
            .fold(0usize, |at, len| at.saturating_add(usize::from(*len)));
        let len = usize::from(*self.lens.get(index)?);
        let seq = *self.seqs.get(index)?;
        Some((seq, self.bytes.get(start..start.saturating_add(len))?))
    }

    /// The position to read from next.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.next
    }

    /// The oldest position the log held, 0 for none (P-144).
    #[must_use]
    pub const fn oldest(&self) -> u64 {
        self.oldest
    }

    /// Whether the batch reached the newest record the log held.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.next > self.newest
    }

    /// Take one record; whether another at its largest still fits.
    fn take(&mut self, seq: u64, payload: &[u8], most: usize) -> Wants {
        let end = self.used.saturating_add(payload.len());
        let (Some(slot), Ok(len), Some(len_slot), Some(seq_slot)) = (
            self.bytes.get_mut(self.used..end),
            u16::try_from(payload.len()),
            self.lens.get_mut(self.count),
            self.seqs.get_mut(self.count),
        ) else {
            return Wants::Enough;
        };
        slot.copy_from_slice(payload);
        *len_slot = len;
        *seq_slot = seq;
        self.used = end;
        self.count = self.count.saturating_add(1);
        let room = LOG_BATCH_BYTES.saturating_sub(self.used) >= record::MAX_PAYLOAD;
        if room && self.count < most.min(MAX_LOG_PAGE_ENTRIES) {
            Wants::More
        } else {
            Wants::Enough
        }
    }
}

/// Read up to `most` records from `from`, or from the oldest the ring holds
/// when `from` is behind it (P-099). The ring hands each record whole or
/// not at all, and the batch stops while one more at its largest still
/// fits, so the position it answers never passes a record it left out.
pub async fn read_log<N: MultiwriteNorFlash>(
    ring: &mut Ring<N>,
    from: u64,
    most: usize,
    scratch: &mut [u8],
    batch: &mut LogBatch,
) -> Result<(), RingError<N::Error>> {
    *batch = LogBatch::new();
    let head = ring.head();
    batch.oldest = head.oldest.unwrap_or(0);
    batch.newest = head.next_seq.saturating_sub(1);
    if most == 0 {
        batch.next = from.max(batch.oldest).max(1);
        return Ok(());
    }
    let next = ring
        .read_from(from, scratch, |found| {
            batch.take(found.seq, found.payload, most)
        })
        .await?;
    batch.next = next;
    Ok(())
}
