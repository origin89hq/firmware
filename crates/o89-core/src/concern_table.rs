//! The concern table: what is wrong at the site, as state.
//!
//! A source reports a condition as it sees it, [`ConcernTable::observe`]
//! while it holds and [`ConcernTable::gone`] when it stops, and the table
//! keeps the row's lifecycle (KM43 "The concern lifecycle"):
//!
//! ```text
//! active ──ack──▶ active_acked
//!   │                 │
//!   └──── gone ───────┴──▶ latched_cleared | clearing_blocked ──released──▶ cleared
//!                     └───────────────────────────────────────────────────▶ cleared
//! ```
//!
//! **Acknowledging never ends a concern** (P-168): it moves `active` to
//! `active_acked` and nothing else, so a person having read an
//! over-temperature is never mistaken for the over-temperature being over.
//! **`cleared` is terminal** (P-180): a condition that comes back after it is
//! a new row with a new `cid`, and a row leaves the table only once the
//! record announcing its clear has committed, so no `cid` a client may still
//! hold is handed to another condition. A row that clears before anything
//! was ever announced about it leaves at once: no client can hold its `cid`.
//!
//! **Admission refuses rather than evicts** (P-169), and the rows above
//! `MAX_CONCERNS_BELOW_FAULT` are held for faults and protections, so a cold
//! morning's per-cell warnings cannot take the row a pack fault needs.
//!
//! What a client has been told is kept per row, and the records a tick owes
//! are derived from the difference (P-182): a row that moves and moves back
//! between two ticks owes nothing.
//!
//! cites: P-168, P-169, P-180, P-199, P-209, P-210, P-211, P-212

use km43::{
    Concern, ConcernChanged, ConcernRaised, ConcernState, ConcernsBody, ConcernsError,
    ConcernsOutcome, ConcernsPage, Condition, Id, MAX_CONCERNS, MAX_CONCERNS_BELOW_FAULT,
    ReadConcerns, Severity, Subject, VendorCode,
};

use crate::tick::Tick;

/// Rows the table holds: KM43's `MAX_CONCERNS`, which `Hello` reports.
pub const CONCERN_ROWS: usize = MAX_CONCERNS;

/// Rows an `info` or a `warning` may occupy between them (P-169).
pub const BELOW_FAULT_ROWS: usize = MAX_CONCERNS_BELOW_FAULT;

/// A condition as its source reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConcernReport {
    /// What it is about.
    pub subject: Subject,
    /// The normalised condition.
    pub cond: Condition,
    /// Its band, which decides admission.
    pub sev: Severity,
    /// The source's own code, verbatim.
    pub code: Option<VendorCode>,
}

/// How a condition went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Latch {
    /// Nothing holds it: the concern is over.
    None,
    /// The source's latch holds and will clear on the source's terms.
    Holding,
    /// The source says it cannot reset the latch yet.
    Blocked,
}

/// Why the table did not do what it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused concern is a condition nobody will be told about"]
pub enum ConcernError {
    /// Every row is taken, or every row the band below `fault` may use; the
    /// refusal is counted and nothing was evicted (P-169).
    Refused,
    /// No row holds this condition, or this `cid`.
    Unknown,
    /// Every `cid` is held.
    NoCid,
    /// An open row holds this condition under another severity or code:
    /// end it with [`ConcernTable::gone`] and observe it again.
    Changed(Id),
}

/// A row, and what a client was last told about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    cid: Id,
    report: ConcernReport,
    state: ConcernState,
    /// When the condition was first observed (P-211).
    first: Tick,
    /// The log position of the `0x0501` that opened it, once committed. A
    /// row is in the table a client reads from then on.
    opened: Option<u64>,
    /// The state the last record about it carried; `None` before the raise.
    announced: Option<ConcernState>,
}

/// One record a tick owes about a concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcernRecord {
    /// `0x0501`: a row entering, carried whole.
    Raised(ConcernRaised),
    /// `0x0502`: a row moving; to `cleared` is the row leaving.
    Changed(ConcernChanged),
}

/// The concern table.
#[derive(Debug, Clone)]
pub struct ConcernTable {
    rows: [Option<Row>; CONCERN_ROWS],
    /// The `cid` handed out last; the next is looked for after it.
    last_cid: u16,
    /// Concerns refused since boot, saturating (P-169).
    refused: u16,
    /// The log position of the last record a row entered or left by: the
    /// pin a walk is held against (P-210).
    pin: u64,
    /// Where the next tick starts looking, so a row that keeps moving
    /// cannot starve the rows after it.
    cursor: usize,
}

impl Default for ConcernTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcernTable {
    /// No rows.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rows: [None; CONCERN_ROWS],
            last_cid: 0,
            refused: 0,
            pin: 0,
            cursor: 0,
        }
    }

    /// The source says `report` holds at `now`. A row already open for the
    /// same subject and condition is that concern, and a latched one whose
    /// condition is back is active again; one open under another severity
    /// or code is refused as [`ConcernError::Changed`]. Otherwise a new row is admitted,
    /// or refused and counted when the table or its band is full.
    pub fn observe(&mut self, report: ConcernReport, now: Tick) -> Result<Id, ConcernError> {
        if let Some(row) = self.open_mut(report.subject, report.cond) {
            // A row's band and code are what its raise announced; a change
            // to either would move it across P-169's band, or say something
            // no `0x0502` can carry. The source ends it and raises anew.
            if row.report.sev != report.sev || row.report.code != report.code {
                return Err(ConcernError::Changed(row.cid));
            }
            match row.state {
                ConcernState::LatchedCleared | ConcernState::ClearingBlocked => {
                    row.state = ConcernState::Active;
                }
                ConcernState::Active | ConcernState::ActiveAcked | ConcernState::Cleared => {}
            }
            return Ok(row.cid);
        }
        let held = self.rows.iter().flatten().count();
        let below = self
            .rows
            .iter()
            .flatten()
            .filter(|row| below_fault(row.report.sev))
            .count();
        if held >= CONCERN_ROWS || (below_fault(report.sev) && below >= BELOW_FAULT_ROWS) {
            self.refused = self.refused.saturating_add(1);
            return Err(ConcernError::Refused);
        }
        let cid = self.next_cid().ok_or(ConcernError::NoCid)?;
        let free = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(ConcernError::Refused)?;
        *free = Some(Row {
            cid,
            report,
            state: ConcernState::Active,
            first: now,
            opened: None,
            announced: None,
        });
        self.last_cid = cid.get();
        Ok(cid)
    }

    /// The condition on `subject` has gone, and `latch` says what still
    /// holds. `cleared` when nothing does.
    pub fn gone(
        &mut self,
        subject: Subject,
        cond: Condition,
        latch: Latch,
    ) -> Result<Id, ConcernError> {
        let row = self.open_mut(subject, cond).ok_or(ConcernError::Unknown)?;
        let cid = row.cid;
        row.state = match latch {
            Latch::None => ConcernState::Cleared,
            Latch::Holding => ConcernState::LatchedCleared,
            Latch::Blocked => ConcernState::ClearingBlocked,
        };
        self.forget_unannounced();
        Ok(cid)
    }

    /// The source released the latch of `cid`: `cleared`.
    pub fn released(&mut self, cid: Id) -> Result<(), ConcernError> {
        let row = self.row_mut(cid).ok_or(ConcernError::Unknown)?;
        match row.state {
            ConcernState::LatchedCleared | ConcernState::ClearingBlocked => {
                row.state = ConcernState::Cleared;
            }
            ConcernState::Active | ConcernState::ActiveAcked | ConcernState::Cleared => {}
        }
        self.forget_unannounced();
        Ok(())
    }

    /// Somebody acknowledged `cid` (P-168): `active` becomes `active_acked`,
    /// and every other state stays where it is. The state it is in after.
    pub fn acknowledge(&mut self, cid: Id) -> Result<ConcernState, ConcernError> {
        let row = self.row_mut(cid).ok_or(ConcernError::Unknown)?;
        match row.state {
            ConcernState::Active => row.state = ConcernState::ActiveAcked,
            ConcernState::ActiveAcked
            | ConcernState::LatchedCleared
            | ConcernState::ClearingBlocked
            | ConcernState::Cleared => {}
        }
        Ok(row.state)
    }

    /// The state `cid` is in, while its row lives.
    #[must_use]
    pub fn state(&self, cid: Id) -> Option<ConcernState> {
        self.row(cid).map(|row| row.state)
    }

    /// Concerns refused since boot.
    #[must_use]
    pub const fn refused(&self) -> u16 {
        self.refused
    }

    /// The records owed now, at most `room` of them: a raise for a row
    /// never announced, a change for one whose state differs from what was
    /// last announced. Each is marked announced as it is taken; the caller
    /// hands every one to the log and gives back those that did not land
    /// with [`ConcernTable::unannounced`].
    pub fn owed(
        &mut self,
        rev: u32,
        now: Tick,
        room: usize,
        mut take: impl FnMut(ConcernRecord),
    ) -> Result<usize, ConcernsError> {
        let mut taken = 0usize;
        let start = self.cursor;
        for step in 0..CONCERN_ROWS {
            if taken >= room {
                break;
            }
            let at = start.saturating_add(step) % CONCERN_ROWS;
            let Some(Some(row)) = self.rows.get_mut(at) else {
                continue;
            };
            let record = match row.announced {
                None => ConcernRecord::Raised(ConcernRaised {
                    rev,
                    concern: page_row(row, now, 0),
                }),
                Some(prev) if prev != row.state => ConcernRecord::Changed(ConcernChanged {
                    rev,
                    cid: row.cid,
                    dev: row.report.subject.part().dev(),
                    cond: row.report.cond,
                    state: row.state,
                    prev,
                }),
                Some(_) => continue,
            };
            row.announced = Some(row.state);
            self.cursor = at.saturating_add(1) % CONCERN_ROWS;
            take(record);
            taken = taken.saturating_add(1);
        }
        Ok(taken)
    }

    /// A record [`ConcernTable::owed`] handed out did not reach the log:
    /// what it announced is owed again.
    pub fn unannounced(&mut self, record: &ConcernRecord) {
        match record {
            ConcernRecord::Raised(raised) => {
                if let Some(row) = self.row_mut(raised.concern.cid) {
                    row.announced = None;
                }
                // A condition that cleared while its raise was out and the
                // raise did not land was never told to anybody: it leaves
                // now, as one that clears before its raise is taken does.
                self.forget_unannounced();
            }
            ConcernRecord::Changed(changed) => {
                if let Some(row) = self.row_mut(changed.cid) {
                    row.announced = Some(changed.prev);
                }
            }
        }
    }

    /// A record [`ConcernTable::owed`] handed out committed at `seq`. A
    /// raise puts its row in the table a client reads; a clear takes its row
    /// out, and only now is its `cid` free (P-180). Either moves the pin
    /// (P-210); a change of state does not.
    pub fn committed(&mut self, record: &ConcernRecord, seq: u64) {
        match record {
            ConcernRecord::Raised(raised) => {
                if let Some(row) = self.row_mut(raised.concern.cid) {
                    row.opened = Some(seq);
                    self.pin = seq;
                }
            }
            ConcernRecord::Changed(changed) => {
                if changed.state == ConcernState::Cleared
                    && let Some(slot) = self.rows.iter_mut().find(|row| {
                        row.is_some_and(|row| {
                            row.cid == changed.cid && row.state == ConcernState::Cleared
                        })
                    })
                {
                    *slot = None;
                    self.pin = seq;
                }
            }
        }
    }

    /// The `Concerns 0x8F` body for `request` at topology revision `rev`,
    /// in P-199's order, over the rows whose raise has committed, in `cid`
    /// order (P-209).
    pub fn answer(
        &self,
        request: &ReadConcerns,
        rev: u32,
        now: Tick,
        dst: &mut [u8],
    ) -> Result<usize, ConcernsError> {
        let total = u16::try_from(self.visible().count()).unwrap_or(u16::MAX);
        let body = |outcome, page| ConcernsBody {
            rev,
            seq: self.pin,
            total,
            refused: self.refused,
            outcome,
            page,
        };
        if request.rev != 0 && request.rev != rev {
            return body(ConcernsOutcome::Superseded, None).encode(dst);
        }
        let last = self.visible().map(|row| row.cid.get()).max();
        if last.is_some_and(|last| request.from > last) {
            return body(ConcernsOutcome::OutOfRange, None).encode(dst);
        }
        let mut page = ConcernsPage::new();
        let mut after = request.from.checked_sub(1);
        // One row a turn, the smallest `cid` past the last taken: the rows
        // are not kept in `cid` order, and there are at most `CONCERN_ROWS`.
        for _ in 0..CONCERN_ROWS {
            let Some(row) = self
                .visible()
                .filter(|row| after.is_none_or(|after| row.cid.get() > after))
                .min_by_key(|row| row.cid)
            else {
                break;
            };
            if !page.push(&page_row(row, now, row.opened.unwrap_or(0)))? {
                break;
            }
            after = Some(row.cid.get());
        }
        body(ConcernsOutcome::Ok, Some(&page)).encode(dst)
    }

    /// Rows a client can read: their raise has committed.
    fn visible(&self) -> impl Iterator<Item = &Row> + '_ {
        self.rows
            .iter()
            .flatten()
            .filter(|row| row.opened.is_some())
    }

    /// A row that cleared before its raise was announced leaves at once:
    /// nothing was told about it, so no client holds its `cid`.
    fn forget_unannounced(&mut self) {
        for slot in &mut self.rows {
            if slot.is_some_and(|row| row.state == ConcernState::Cleared && row.announced.is_none())
            {
                *slot = None;
            }
        }
    }

    fn next_cid(&self) -> Option<Id> {
        let mut candidate = self.last_cid;
        // Every row holds one cid, so at most `CONCERN_ROWS` candidates are
        // taken before a free one.
        for _ in 0..=CONCERN_ROWS {
            candidate = candidate.checked_add(1).unwrap_or(1);
            let id = Id::new(candidate).ok()?;
            if self.row(id).is_none() {
                return Some(id);
            }
        }
        None
    }

    fn open_mut(&mut self, subject: Subject, cond: Condition) -> Option<&mut Row> {
        self.rows.iter_mut().flatten().find(|row| {
            row.report.subject == subject
                && row.report.cond == cond
                && row.state != ConcernState::Cleared
        })
    }

    fn row(&self, cid: Id) -> Option<&Row> {
        self.rows.iter().flatten().find(|row| row.cid == cid)
    }

    fn row_mut(&mut self, cid: Id) -> Option<&mut Row> {
        self.rows.iter_mut().flatten().find(|row| row.cid == cid)
    }
}

const fn below_fault(sev: Severity) -> bool {
    match sev {
        Severity::Info | Severity::Warning => true,
        Severity::Fault | Severity::Protection => false,
    }
}

fn page_row(row: &Row, now: Tick, seq: u64) -> Concern {
    Concern {
        cid: row.cid,
        subject: row.report.subject,
        cond: row.report.cond,
        sev: row.report.sev,
        state: row.state,
        age: now
            .since(row.first)
            .map_or(0, |age| u32::try_from(age.as_secs()).unwrap_or(u32::MAX)),
        since: None,
        code: row.report.code,
        seq,
    }
}

#[cfg(test)]
mod tests {
    use km43::{ConcernRows, ConcernsHeader, Part, VendorNamespace};

    use super::*;
    use crate::tick::Millis;

    fn dev(n: u16) -> Id {
        Id::new(n).expect("non-zero")
    }

    /// A condition on device `n` at `sev`.
    fn report(n: u16, sev: Severity) -> ConcernReport {
        ConcernReport {
            subject: Subject::Part(Part::device(dev(n))),
            cond: Condition(0x0101),
            sev,
            code: None,
        }
    }

    fn at(secs: u64) -> Tick {
        Tick::ZERO
            .after(Millis::from_millis(secs.checked_mul(1_000).expect("fits")))
            .expect("fits")
    }

    /// Every record owed now handed to the log, landing at `seq` onwards;
    /// how many there were.
    fn commit_all(table: &mut ConcernTable, now: Tick, mut seq: u64) -> usize {
        let mut records = [None; CONCERN_ROWS];
        let mut n = 0;
        table
            .owed(1, now, CONCERN_ROWS, |record| {
                records[n] = Some(record);
                n = n.checked_add(1).expect("fits");
            })
            .expect("owes");
        for record in records.iter().flatten() {
            table.committed(record, seq);
            seq = seq.checked_add(1).expect("fits");
        }
        n
    }

    fn page(table: &ConcernTable, rev: u32, from: u16) -> ([u8; 1024], usize) {
        let mut dst = [0u8; 1024];
        let len = table
            .answer(&ReadConcerns::new(rev, from), 1, at(10), &mut dst)
            .expect("answers");
        (dst, len)
    }

    #[test]
    fn p_168_acknowledging_moves_active_to_acked_and_never_further() {
        let mut table = ConcernTable::new();
        let cid = table
            .observe(report(1, Severity::Protection), at(0))
            .expect("admitted");
        commit_all(&mut table, at(0), 1);
        assert_eq!(table.acknowledge(cid), Ok(ConcernState::ActiveAcked));
        // However many times somebody reads it, the condition holds.
        assert_eq!(table.acknowledge(cid), Ok(ConcernState::ActiveAcked));
        assert_eq!(table.state(cid), Some(ConcernState::ActiveAcked));
        // The condition going away moves it; acknowledging a latch does not.
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::Holding,
            )
            .expect("open");
        assert_eq!(table.acknowledge(cid), Ok(ConcernState::LatchedCleared));
        table.released(cid).expect("held");
        assert_eq!(table.state(cid), Some(ConcernState::Cleared));
        assert_eq!(
            table.acknowledge(Id::new(999).expect("non-zero")),
            Err(ConcernError::Unknown)
        );
    }

    #[test]
    fn p_180_a_cid_is_held_until_its_clear_commits_and_a_returning_condition_is_new() {
        let mut table = ConcernTable::new();
        let first = table
            .observe(report(1, Severity::Fault), at(0))
            .expect("admitted");
        assert_eq!(commit_all(&mut table, at(1), 10), 1, "the raise");
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::None,
            )
            .expect("open");
        // Cleared, and its clear not yet committed: the row and its cid stay.
        assert_eq!(table.state(first), Some(ConcernState::Cleared));
        let again = table
            .observe(report(1, Severity::Fault), at(2))
            .expect("admitted");
        assert_ne!(again, first, "a returning condition is a new concern");
        // The clear is owed; handed out and not landed, it is owed again.
        let mut owed = [None; 2];
        let mut n = 0;
        table
            .owed(1, at(3), 2, |record| {
                owed[n] = Some(record);
                n = n.checked_add(1).expect("fits");
            })
            .expect("owes");
        let changed = owed
            .iter()
            .flatten()
            .find_map(|record| match record {
                ConcernRecord::Changed(changed) => Some(*changed),
                ConcernRecord::Raised(_) => None,
            })
            .expect("the clear is owed");
        assert_eq!(
            (changed.cid, changed.state, changed.prev),
            (first, ConcernState::Cleared, ConcernState::Active)
        );
        for record in owed.iter().flatten() {
            table.unannounced(record);
        }
        assert_eq!(
            table.state(first),
            Some(ConcernState::Cleared),
            "still held"
        );
        assert_eq!(
            commit_all(&mut table, at(4), 20),
            2,
            "the clear and the new raise"
        );
        assert_eq!(table.state(first), None, "released once its clear landed");
    }

    #[test]
    fn p_180_p_169_a_condition_that_clears_while_its_raise_is_refused_frees_its_row() {
        let mut table = ConcernTable::new();
        let cid = table
            .observe(report(1, Severity::Fault), at(0))
            .expect("admitted");
        let mut taken = None;
        table
            .owed(1, at(1), 1, |record| taken = Some(record))
            .expect("owes");
        let raised = taken.expect("the raise");
        // Cleared while the raise is out, and the raise does not land.
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::None,
            )
            .expect("open");
        assert_eq!(
            table.state(cid),
            Some(ConcernState::Cleared),
            "held while its raise is out"
        );
        table.unannounced(&raised);
        assert_eq!(table.state(cid), None, "nobody was told: the row leaves");
        assert_eq!(commit_all(&mut table, at(2), 1), 0, "and owes nothing");
        // The row is free again, down to the last one.
        for n in 1..=u16::try_from(CONCERN_ROWS).expect("fits") {
            table
                .observe(report(n, Severity::Fault), at(3))
                .expect("room for every row");
        }
    }

    #[test]
    fn p_180_a_condition_that_clears_while_its_raise_lands_is_retired_by_its_clear() {
        let mut table = ConcernTable::new();
        let cid = table
            .observe(report(1, Severity::Fault), at(0))
            .expect("admitted");
        let mut taken = None;
        table
            .owed(1, at(1), 1, |record| taken = Some(record))
            .expect("owes");
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::None,
            )
            .expect("open");
        table.committed(&taken.expect("the raise"), 7);
        assert_eq!(table.state(cid), Some(ConcernState::Cleared));
        assert_eq!(commit_all(&mut table, at(2), 8), 1, "the clear");
        assert_eq!(table.state(cid), None);
    }

    #[test]
    fn p_180_a_row_that_clears_before_anything_was_announced_leaves_owing_nothing() {
        let mut table = ConcernTable::new();
        let cid = table
            .observe(report(1, Severity::Warning), at(0))
            .expect("admitted");
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::None,
            )
            .expect("open");
        assert_eq!(table.state(cid), None);
        assert_eq!(commit_all(&mut table, at(1), 1), 0);
    }

    #[test]
    fn p_169_warnings_stop_at_their_band_and_faults_keep_the_rows_above_it() {
        let mut table = ConcernTable::new();
        for n in 1..=u16::try_from(BELOW_FAULT_ROWS).expect("fits") {
            table
                .observe(report(n, Severity::Warning), at(0))
                .expect("inside the band");
        }
        assert_eq!(
            table.observe(report(100, Severity::Info), at(0)),
            Err(ConcernError::Refused)
        );
        assert_eq!(table.refused(), 1);
        // The band full, a fault is still admitted, up to the whole table.
        let above = u16::try_from(CONCERN_ROWS - BELOW_FAULT_ROWS).expect("fits");
        for n in 0..above {
            table
                .observe(report(200 + n, Severity::Fault), at(0))
                .expect("above the band");
        }
        assert_eq!(
            table.observe(report(300, Severity::Protection), at(0)),
            Err(ConcernError::Refused)
        );
        assert_eq!(table.refused(), 2, "counted, and nothing evicted");
    }

    #[test]
    fn p_169_a_condition_back_under_another_severity_or_code_is_refused_until_it_ends() {
        let mut table = ConcernTable::new();
        let cid = table
            .observe(report(1, Severity::Fault), at(0))
            .expect("admitted");
        // Downgraded into the band it would otherwise skip the band's cap.
        assert_eq!(
            table.observe(report(1, Severity::Warning), at(1)),
            Err(ConcernError::Changed(cid))
        );
        let mut coded = report(1, Severity::Fault);
        coded.code = Some(VendorCode {
            raw: 0x4A12,
            vns: VendorNamespace::VICTRON,
        });
        assert_eq!(table.observe(coded, at(1)), Err(ConcernError::Changed(cid)));
        // The same report is the same concern.
        assert_eq!(table.observe(report(1, Severity::Fault), at(2)), Ok(cid));
        // A latched one whose condition is back is active again.
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::Blocked,
            )
            .expect("open");
        assert_eq!(table.observe(report(1, Severity::Fault), at(3)), Ok(cid));
        assert_eq!(table.state(cid), Some(ConcernState::Active));
    }

    #[test]
    fn p_199_an_empty_table_is_answered_with_no_rows_even_past_a_cursor() {
        let table = ConcernTable::new();
        for from in [0, 5] {
            let (body, len) = page(&table, 0, from);
            let header = ConcernsHeader::decode(&body[..len]).expect("reads");
            assert_eq!(header.outcome, ConcernsOutcome::Ok);
            assert_eq!((header.rows, header.next, header.total), (0, 0, 0));
        }
    }

    #[test]
    fn p_209_rows_page_in_cid_order_and_resume_at_the_row_that_did_not_fit() {
        let mut table = ConcernTable::new();
        let rows = u16::try_from(km43::MAX_CONCERN_PAGE_ROWS).expect("fits") + 1;
        for n in 1..=rows {
            table
                .observe(report(n, Severity::Fault), at(0))
                .expect("admitted");
        }
        // Rows are read only once their raise has landed.
        let (body, len) = page(&table, 0, 0);
        assert_eq!(
            ConcernsHeader::decode(&body[..len]).expect("reads").total,
            0
        );
        commit_all(&mut table, at(1), 1);
        let (body, len) = page(&table, 1, 0);
        let first = ConcernsHeader::decode(&body[..len]).expect("reads");
        assert_eq!((first.rows, first.next, first.total), (12, 13, 13));
        let mut last = 0;
        for row in ConcernRows::of(&body[..len]).expect("rows") {
            let cid = row.expect("a row").cid.get();
            assert!(cid > last, "ascending");
            last = cid;
        }
        let (body, len) = page(&table, 1, first.next);
        let second = ConcernsHeader::decode(&body[..len]).expect("reads");
        assert_eq!((second.rows, second.next), (1, 0));
        // Past the last, and under a stale revision: nothing.
        let (body, len) = page(&table, 1, rows + 1);
        let past = ConcernsHeader::decode(&body[..len]).expect("reads");
        assert_eq!((past.outcome, past.rows), (ConcernsOutcome::OutOfRange, 0));
        let (body, len) = page(&table, 7, 0);
        let stale = ConcernsHeader::decode(&body[..len]).expect("reads");
        assert_eq!(
            (stale.outcome, stale.rows),
            (ConcernsOutcome::Superseded, 0)
        );
    }

    #[test]
    fn p_210_the_pin_moves_when_a_row_enters_or_leaves_and_not_when_it_changes_state() {
        let mut table = ConcernTable::new();
        let pin = |table: &ConcernTable| {
            let (body, len) = page(table, 0, 0);
            ConcernsHeader::decode(&body[..len]).expect("reads").seq
        };
        let cid = table
            .observe(report(1, Severity::Fault), at(0))
            .expect("admitted");
        commit_all(&mut table, at(1), 40);
        assert_eq!(pin(&table), 40, "entered");
        table.acknowledge(cid).expect("held");
        commit_all(&mut table, at(2), 41);
        assert_eq!(pin(&table), 40, "a state change moves nothing");
        assert_eq!(
            table.state(cid),
            Some(ConcernState::ActiveAcked),
            "and keeps the row"
        );
        table
            .gone(
                Subject::Part(Part::device(dev(1))),
                Condition(0x0101),
                Latch::None,
            )
            .expect("open");
        commit_all(&mut table, at(3), 42);
        assert_eq!(pin(&table), 42, "left");
    }

    #[test]
    fn p_182_the_concern_records_a_tick_takes_are_bounded_and_the_rest_wait() {
        let mut table = ConcernTable::new();
        for n in 1..=6 {
            table
                .observe(report(n, Severity::Fault), at(0))
                .expect("admitted");
        }
        let mut taken = 0;
        let owed = table.owed(1, at(1), MAX_CONCERN_EVENTS, |_| taken += 1);
        assert_eq!((owed, taken), (Ok(MAX_CONCERN_EVENTS), MAX_CONCERN_EVENTS));
        let mut rest = 0;
        let owed = table.owed(1, at(2), MAX_CONCERN_EVENTS, |_| rest += 1);
        assert_eq!((owed, rest), (Ok(2), 2), "carried, not dropped");
        assert_eq!(table.owed(1, at(3), MAX_CONCERN_EVENTS, |_| {}), Ok(0));
    }

    const MAX_CONCERN_EVENTS: usize = km43::MAX_CONCERN_EVENTS_PER_TICK;
}
