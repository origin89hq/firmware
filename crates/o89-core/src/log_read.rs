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
use crate::ring::{Holding, Ring, RingError, Wants};
use crate::site::{OwedError, RECORD_BODY, Site, TICK_RECORDS, Tally, Token};
use crate::tick::Tick;

/// The one site, behind whatever keeps its writers apart.
///
/// The tick is read inside the same exclusion every writer takes, so a
/// reading is never asked about at a tick older than its last write.
pub trait SiteCell {
    /// Run `with` over the site at the current tick, or say it is held.
    /// Every holder runs one synchronous call and never awaits inside it,
    /// so on one cooperative executor it is never held when asked; a
    /// caller answers `SiteBusy` as a retry rather than waiting on it.
    fn with<R>(&self, with: impl FnOnce(&mut Site, Tick) -> R) -> Result<R, SiteBusy>;
}

/// The site was held by another task when it was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a site that could not be read is a question left unanswered"]
pub struct SiteBusy;

/// What the log's extent is, as [`record_owed`] tells whoever publishes it.
pub enum Extent<'a, N> {
    /// An append is about to begin: it may turn the page and erase the
    /// oldest records, so the extent published before it is no longer
    /// known to hold until one of these follows.
    Moving,
    /// The ring's head describes the part again: the append landed, or it
    /// failed and the head was found again from the bytes.
    Settled(&'a Ring<N>),
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
    /// The site was held when the turn asked for it. Nothing new was taken
    /// after that; an outcome not yet told to the site waits in the
    /// [`Unsettled`] the caller keeps, and is told first next turn.
    pub busy: bool,
    /// An append returned an error and the part has not yet said whether
    /// its record landed: the outcome is kept, the extent stays unsettled,
    /// and the next turn asks again before anything else.
    pub adrift: bool,
}

/// What became of a record handed to the ring, once the part has said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Known {
    /// It landed at this position.
    Landed(u64),
    /// It is not in the log.
    Refused,
}

/// What became of a record handed to the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Known.
    Known(Known),
    /// The append at this position failed after it touched the part, which
    /// does not say whether the record reached it: only the bytes can.
    Uncertain(u64),
}

/// What an append's error says of its record: an error from before the
/// part was touched is a record that is not there; one from the part is a
/// record that may be.
const fn after<E>(error: &RingError<E>, seq: u64) -> Outcome {
    match error {
        RingError::Flash(_) | RingError::OutOfRange => Outcome::Uncertain(seq),
        RingError::TooFewBlocks(_)
        | RingError::BlockTooSmall(_)
        | RingError::WriteSizeNotOne(_)
        | RingError::ScratchTooSmall(_)
        | RingError::Unframed(_)
        | RingError::NotTheNextEvent
        | RingError::InsideTheRing(_) => Outcome::Known(Known::Refused),
    }
}

/// A record's outcome the site has not been told yet: one the site was
/// held for when it was known, or one the part has not yet said. Kept by
/// the caller between turns; the record's announcement stays marked until
/// the site hears which way it went, so nothing is owed twice and nothing
/// is lost, and the plane appends nothing while one is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsettled {
    token: Token,
    outcome: Outcome,
    body: [u8; RECORD_BODY],
    len: usize,
    payload: [u8; record::MAX_PAYLOAD],
    payload_len: usize,
}

impl Unsettled {
    /// Ask the part what an uncertain append did: landed if the exact
    /// record is at its position; not there if the log ends before it or
    /// something else is at it, since positions are unique. A position
    /// retention has already erased is taken as not there: nothing can
    /// prove it landed, and the record is owed again rather than the plane
    /// held for good, at the cost of announcing it twice if it had landed.
    /// `None` while the part cannot answer.
    async fn resolve<N: MultiwriteNorFlash>(
        &self,
        ring: &mut Ring<N>,
        scratch: &mut [u8],
    ) -> Option<Known> {
        let seq = match self.outcome {
            Outcome::Known(known) => return Some(known),
            Outcome::Uncertain(seq) => seq,
        };
        let payload = self.payload.get(..self.payload_len).unwrap_or(&[]);
        match ring.holds(seq, payload, scratch).await {
            Ok(Holding::Present) => Some(Known::Landed(seq)),
            Ok(Holding::Absent | Holding::Other | Holding::Gone) => Some(Known::Refused),
            Err(_) => None,
        }
    }

    /// Tell the site a known outcome; whether it could be told.
    fn settle(&self, site: &impl SiteCell, known: Known) -> bool {
        let body = self.body.get(..self.len).unwrap_or(&[]);
        site.with(|site, _| match known {
            Known::Landed(seq) => site.committed(&self.token, seq),
            Known::Refused => site.not_committed(&self.token, body),
        })
        .is_ok()
    }
}

/// One tick of the reading plane: every record the site owes, at most
/// [`TICK_RECORDS`], appended in order under the wall-clock `at` when the
/// controller holds one. The site is held only between appends, never
/// across one. The ring is proven before a record is numbered, so a stale
/// head never frames one.
///
/// `extent` hears [`Extent::Moving`] before each append and
/// [`Extent::Settled`] only while the ring is proven, after the append
/// landed or after a failure once the part answered, before anything else
/// can yield: whatever answers from the log's extent never answers from one
/// an append is changing or has left unproven (P-104, P-095).
///
/// `unsettled` is the caller's across turns. An append that failed after
/// touching the part is kept there, with its record, until the part says
/// whether it landed; a known outcome the site was too held to hear is kept
/// until it hears it. Either is dealt with first, and until it is, the plane
/// takes and appends nothing new. Other writers may append meanwhile; a
/// record of theirs at the kept position proves the plane's is not there.
pub async fn record_owed<N: MultiwriteNorFlash>(
    site: &impl SiteCell,
    ring: &mut Ring<N>,
    scratch: &mut [u8],
    at: Option<u64>,
    mut extent: impl FnMut(Extent<'_, N>),
    unsettled: &mut Option<Unsettled>,
) -> PlaneTurn {
    let mut done = PlaneTurn::default();
    if let Some(pending) = unsettled.as_ref() {
        let Some(known) = pending.resolve(ring, scratch).await else {
            done.adrift = true;
            return done;
        };
        if ring.is_proven() {
            extent(Extent::Settled(ring));
        }
        if !pending.settle(site, known) {
            // Kept, now known, for the site to hear next turn.
            let mut known_pending = *pending;
            known_pending.outcome = Outcome::Known(known);
            *unsettled = Some(known_pending);
            done.busy = true;
            return done;
        }
        *unsettled = None;
    }
    if ring.prove(scratch).await.is_err() {
        // Nothing taken: the site still owes it all, next turn.
        done.adrift = true;
        return done;
    }
    extent(Extent::Settled(ring));
    let mut tally = Tally::new();
    let mut body = [0u8; RECORD_BODY];
    let mut payload = [0u8; record::MAX_PAYLOAD];
    for _ in 0..TICK_RECORDS {
        let seq = ring.next_seq();
        let owed = site.with(|site, now| site.next_owed(now, seq, &mut tally, &mut body));
        let owed = match owed {
            Ok(Ok(Some(owed))) => owed,
            Ok(Ok(None)) => break,
            Ok(Err(why)) => {
                done.unwritten = Some(why);
                break;
            }
            Err(SiteBusy) => {
                done.busy = true;
                break;
            }
        };
        let written = body.get(..owed.len).unwrap_or(&[]);
        let framed = Event::new(LogSeq(seq), at, owed.kind, written)
            .ok()
            .and_then(|event| event.encode(&mut payload).ok());
        let mut pending = Unsettled {
            token: owed.token,
            outcome: Outcome::Known(Known::Refused),
            body,
            len: owed.len,
            payload,
            payload_len: framed.unwrap_or(0),
        };
        if let Some(len) = framed {
            extent(Extent::Moving);
            pending.outcome = match ring
                .append(Class::A, payload.get(..len).unwrap_or(&[]), scratch)
                .await
            {
                Ok(landed) => Outcome::Known(Known::Landed(landed)),
                Err(error) => after(&error, seq),
            };
        }
        let Some(known) = pending.resolve(ring, scratch).await else {
            done.adrift = true;
            done.refused = true;
            *unsettled = Some(pending);
            break;
        };
        if framed.is_some() && ring.is_proven() {
            extent(Extent::Settled(ring));
        }
        pending.outcome = Outcome::Known(known);
        let landed = matches!(known, Known::Landed(_));
        if landed {
            done.landed = done.landed.saturating_add(1);
        } else {
            done.refused = true;
        }
        if !pending.settle(site, known) {
            done.busy = true;
            *unsettled = Some(pending);
            break;
        }
        if !landed {
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

    /// A batch holding `records`, each an encoded `Event` and its
    /// position, read from a log holding `oldest..=newest`: what the ring's
    /// owner hands back, for tests that interleave it with the sessions.
    #[cfg(test)]
    pub(crate) fn of(records: &[(u64, &[u8])], oldest: u64, newest: u64) -> Self {
        let mut batch = Self::new();
        batch.oldest = oldest;
        batch.newest = newest;
        for (seq, payload) in records {
            let _ = batch.take(*seq, payload, MAX_LOG_PAGE_ENTRIES);
            batch.next = seq.saturating_add(1);
        }
        batch
    }

    /// A batch that read nothing, from `from` through the holes up to
    /// `next`, in a log holding `oldest..=newest`.
    #[cfg(test)]
    pub(crate) fn nothing_until(next: u64, oldest: u64, newest: u64) -> Self {
        let mut batch = Self::new();
        batch.oldest = oldest;
        batch.newest = newest;
        batch.next = next;
        batch
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
    // The walk proves the head first when it is not; the extent the batch
    // reports is read after it, so it is never one a failure left stale.
    let mut take = |found: &record::Found<'_>| {
        if most == 0 {
            return Wants::Enough;
        }
        batch.take(found.seq, found.payload, most)
    };
    let visit: &mut dyn FnMut(&record::Found<'_>) -> Wants = &mut take;
    let next = ring.read_from(from, scratch, visit).await?;
    let head = ring.head();
    batch.oldest = head.oldest.unwrap_or(0);
    batch.newest = head.next_seq.saturating_sub(1);
    batch.next = if most == 0 {
        from.max(batch.oldest).max(1)
    } else {
        next
    };
    Ok(())
}
