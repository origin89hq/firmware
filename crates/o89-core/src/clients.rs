//! The eight enrolment rows, their counters, and the dedup table beside
//! them: one record, because P-080 lands a counter and an in-flight entry
//! in one FRAM transaction and one record is the only thing that is one
//! transaction.
//!
//! **Reclaim, then the lowest free slot, then refuse.** That order is the
//! rule and not a detail: a phone reinstalled every few months takes a
//! fresh row each time under any other order, and a site with one owner
//! runs out of a table sized for eight people. `table_full` means eight
//! distinct labels, not eight pairings (P-067, P-078, P-086). A label
//! matches byte for byte, the exact UTF-8 that entered the pair proof: no
//! case folding, no trimming, no normalisation. Two labels a person would
//! call the same are two clients, and that is the safe direction.
//!
//! **Every row carries the mask its kind was handed at enrolment** and no
//! message raises or lowers it (P-105); a kind with no mask is not a value
//! the type can hold. **Every row carries the highest counter accepted**,
//! strictly ahead or refused, because equal is the replay (P-081).
//!
//! **The table is stamped with the epoch its rows were enrolled under.**
//! A factory reset writes the epoch first and clears the table second
//! (P-085), and a power cut between the two leaves eight rows whose keys no
//! longer derive counting towards `table_full`. The stamp is what lets the
//! next boot see that and finish the reset (F-026).
//!
//! Nothing here checks a proof; `km43` does that before anything in this
//! file is asked, so what arrives is a label and a kind already
//! authenticated.
//!
//! cites: P-064, P-065, P-067, P-078, P-080, P-081, P-085, P-086, P-105,
//! F-026

use km43::{ClientCapability, ClientId, ClientKind, Counter, Epoch, MAX_CLIENTS, MAX_LABEL};

use crate::body::{Body, Held, Kept, Malformed, Reader, Writer};
use crate::dedup::{DEDUP_BYTES, Dedup, Fingerprint, Recorded, Reserved, Verdict};
use crate::epoch::Clearing;
use crate::fram::{Fram, Refused};
use crate::text::Text;
use crate::tick::Tick;

/// The bytes the client table's record budgets. The layout below takes
/// 1156 of them; the rest is room for a field nobody has asked for.
pub const CLIENT_TABLE_BYTES: usize = 1280;

/// The rows: one per slot P-086 can allocate.
pub const ROWS: usize = MAX_CLIENTS;

/// What a newly enrolled or reclaimed client's counter starts at (P-065).
/// Its first accepted request carries one.
pub const FRESHLY_ENROLLED: Counter = Counter(0);

/// One row on the part: kind, label, mask, counter.
const ROW_BYTES: usize = 1 + (1 + MAX_LABEL) + 2 + 8;
const LAYOUT: usize = 4 + ROWS * ROW_BYTES + DEDUP_BYTES;
const _: () = assert!(LAYOUT <= CLIENT_TABLE_BYTES);

/// The kind byte of a vacant row: no client kind is zero.
const VACANT: u8 = 0;

/// A client's own name for itself, as the bytes that entered the pair
/// proof: byte equality is the only comparison the protocol permits, and
/// a label past the cap is refused rather than truncated.
pub type Label = Text<MAX_LABEL>;

/// One enrolled client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    label: Label,
    kind: ClientKind,
    mask: ClientCapability,
    counter: Counter,
}

impl Row {
    /// The label that entered the pair proof.
    #[must_use]
    pub const fn label(&self) -> &Label {
        &self.label
    }

    /// The kind the client attested.
    #[must_use]
    pub const fn kind(&self) -> ClientKind {
        self.kind
    }

    /// The mask fixed from that kind at enrolment.
    #[must_use]
    pub const fn mask(&self) -> ClientCapability {
        self.mask
    }

    /// The highest counter accepted from this client.
    #[must_use]
    pub const fn counter(&self) -> Counter {
        self.counter
    }

    const fn enrolled(label: Label, kind: ClientKind) -> Self {
        Self {
            label,
            kind,
            mask: ClientCapability::granted(kind),
            counter: FRESHLY_ENROLLED,
        }
    }
}

/// What a `Pair` whose proof verified was answered with, and the slot it
/// carries. Never zero: zero names no client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a pairing nobody answers is a phone that was enrolled and not told"]
pub enum Paired {
    /// Outcome 1 `enrolled`: a free row, the lowest (P-064, P-086).
    Enrolled(ClientId),
    /// Outcome 5 `reclaimed`: the same label was already here, and its row
    /// is re-fixed with the counter back to zero (P-078).
    Reclaimed(ClientId),
}

impl Paired {
    /// The slot either answer carries.
    #[must_use]
    pub const fn client(&self) -> ClientId {
        match self {
            Self::Enrolled(id) | Self::Reclaimed(id) => *id,
        }
    }
}

/// Outcome 4 `table_full`: eight distinct labels, none of them this one
/// (P-067). Refused rather than evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TableFull;

/// Whether a signed request's counter is ahead of its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a counter checked and not acted on is a replay executed"]
pub enum Check {
    /// Strictly ahead; the row has moved to it. The caller lands the
    /// table before executing, and answers error 7 if it will not land.
    Ahead,
    /// Not ahead of the stored value: error 11, and the client takes its
    /// next counter from `Hello` key 11 (P-081).
    Stale,
    /// No row at that slot. A session bound to it should not exist.
    NoSuchClient,
}

/// What to do with a `Command`, after its counter and the dedup table
/// have both been consulted in P-080's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a command admitted and not acted on is answered by nothing"]
pub enum Admitted {
    /// Its counter is not ahead: error 11, before the table is consulted.
    Stale,
    /// No row at that slot.
    NoSuchClient,
    /// Nothing like it in the table. The counter has moved and the entry
    /// is reserved in flight, in this one change: land it, execute, then
    /// [`finished`](ClientTable::finished).
    Fresh(Reserved),
    /// A retry of a command that finished: answer with what was recorded.
    Already(Recorded),
    /// A retry of a command that only started: ask the state store.
    InFlight(Reserved),
    /// A `cmd_id` reused for different bytes: `rejected`, never executed.
    ReusedId,
    /// No room: error 7.
    Busy,
}

/// The client table: eight rows, their counters, and the dedup table, all
/// stamped with the epoch they were enrolled under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTable {
    epoch: Epoch,
    rows: [Option<Row>; ROWS],
    dedup: Dedup,
}

impl ClientTable {
    /// The empty table under the epoch a [`Clearing`] names. The only
    /// constructor: a table cannot be emptied except by a reset that
    /// moved the epoch first, or by the boot that finishes one.
    #[must_use]
    pub const fn cleared(clearing: &Clearing) -> Self {
        Self {
            epoch: clearing.epoch(),
            rows: [None; ROWS],
            dedup: Dedup::new(),
        }
    }

    /// The epoch the rows were enrolled under.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Whether the rows are under `epoch`. A table that is not is one a
    /// factory reset left behind, and the boot clears it (F-026).
    #[must_use]
    pub const fn is_under(&self, epoch: Epoch) -> bool {
        self.epoch.get() == epoch.get()
    }

    /// The row at `client`, if one is enrolled there.
    #[must_use]
    pub fn row(&self, client: ClientId) -> Option<&Row> {
        client
            .slot()
            .and_then(|slot| self.rows.get(slot))
            .and_then(Option::as_ref)
    }

    fn row_mut(&mut self, client: ClientId) -> Option<&mut Row> {
        client
            .slot()
            .and_then(|slot| self.rows.get_mut(slot))
            .and_then(Option::as_mut)
    }

    /// How many rows are enrolled.
    #[must_use]
    pub fn enrolled(&self) -> usize {
        self.rows.iter().flatten().count()
    }

    /// The dedup table, for what it can say on its own.
    #[must_use]
    pub const fn dedup(&self) -> &Dedup {
        &self.dedup
    }

    /// Enrol a client whose proof verified inside an open window: reclaim
    /// the row whose label matches byte for byte, else the lowest free
    /// slot, else refuse. A reclaimed row is re-fixed from this proof
    /// exactly as at first enrolment, its counter back to zero.
    pub fn pair(&mut self, label: Label, kind: ClientKind) -> Result<Paired, TableFull> {
        let row = Row::enrolled(label, kind);
        if let Some((id, held)) = Self::numbered(&mut self.rows)
            .find(|(_, held)| held.is_some_and(|occupied| occupied.label == label))
        {
            *held = Some(row);
            return Ok(Paired::Reclaimed(id));
        }
        let (id, free) = Self::numbered(&mut self.rows)
            .find(|(_, held)| held.is_none())
            .ok_or(TableFull)?;
        *free = Some(row);
        Ok(Paired::Enrolled(id))
    }

    /// The rows with the slot each one is, counting from one (P-086).
    fn numbered(
        rows: &mut [Option<Row>; ROWS],
    ) -> impl Iterator<Item = (ClientId, &mut Option<Row>)> {
        rows.iter_mut()
            .zip(1u32..)
            .filter_map(|(row, n)| ClientId::new(n).map(|id| (id, row)))
    }

    /// What `Hello 0x81` key 11 carries for this client: the way out of
    /// the livelock, and the only one (P-081).
    #[must_use]
    pub fn accepted(&self, client: ClientId) -> Option<Counter> {
        self.row(client).map(Row::counter)
    }

    /// Whether `counter` is strictly ahead of the row, moving the row to
    /// it if so. Equal is a replay of the frame that set the row.
    ///
    /// The row moves in this table and not on the part; the caller lands
    /// the table and only then executes, so a write that fails leaves a
    /// row that never learned the counter (P-079).
    pub fn accept(&mut self, client: ClientId, counter: Counter) -> Check {
        let Some(row) = self.row_mut(client) else {
            return Check::NoSuchClient;
        };
        if !counter.is_ahead_of(row.counter) {
            return Check::Stale;
        }
        row.counter = counter;
        Check::Ahead
    }

    /// A `Command`, in P-080's order: the counter, then the lookup, then,
    /// for a fresh one, the counter moved and the entry reserved in one
    /// change. A match moves nothing: it is answered without executing
    /// and nothing is persisted for it.
    pub fn admit(
        &mut self,
        client: ClientId,
        counter: Counter,
        cmd: u32,
        fingerprint: Fingerprint,
        now: Tick,
    ) -> Admitted {
        let Some(row) = self.row(client) else {
            return Admitted::NoSuchClient;
        };
        if !counter.is_ahead_of(row.counter) {
            return Admitted::Stale;
        }
        match self.dedup.admit(client, cmd, fingerprint, now) {
            Verdict::Fresh(seat) => {
                if let Some(row) = self.row_mut(client) {
                    row.counter = counter;
                }
                Admitted::Fresh(seat)
            }
            Verdict::Already(recorded) => Admitted::Already(recorded),
            Verdict::InFlight(seat) => Admitted::InFlight(seat),
            Verdict::ReusedId => Admitted::ReusedId,
            Verdict::Busy => Admitted::Busy,
        }
    }

    /// Say what a reserved command did, or that it did nothing.
    pub fn finished(&mut self, seat: Reserved, outcome: Option<Recorded>) {
        self.dedup.finished(seat, outcome);
    }

    /// The table as read at boot, with every dedup entry restarted at this
    /// boot's tick zero (P-121).
    #[must_use]
    pub fn rebased(mut self) -> Self {
        self.dedup = self.dedup.rebased();
        self
    }
}

/// What a boot did with the client table it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a boot that cleared the table has something to log"]
pub enum Booted {
    /// The rows are under the epoch the part holds; every dedup entry
    /// restarted at this boot's tick zero.
    Rebased,
    /// What the part held was not a table under this epoch, and the empty
    /// table under it was written in its place.
    Cleared(Because),
    /// The rows are under a later epoch than the record holds, which this
    /// firmware never does by its own hand: the epoch record regressed.
    /// The table is left as it is, because clearing it under the lower
    /// epoch would let the next enrolment derive a key the table's epoch
    /// was moved to invalidate. The store raises the record to the
    /// table's epoch: the higher of two copies of a counter that only
    /// climbs is the counter.
    Above(Epoch),
}

/// Why a boot cleared the client table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Because {
    /// Never written: a fresh part.
    Absent,
    /// Both slots written and neither held.
    Corrupt,
    /// A record that held and did not decode.
    Malformed(Malformed),
    /// The rows were enrolled under an earlier epoch: a factory reset that
    /// was cut between moving the epoch and clearing the table, finished
    /// here.
    Earlier(Epoch),
}

impl Kept<ClientTable, CLIENT_TABLE_BYTES> {
    /// Take the table as a boot does, under the epoch the boot read: rows
    /// under that epoch are kept with their entries rebased (P-121); rows
    /// under an earlier one, or no table at all, are replaced by the empty
    /// table under it, written so the next boot finds it (F-026); rows
    /// under a later one are left alone and reported. A write that is
    /// refused leaves the handle holding what the part holds, which is
    /// not a table this boot can enrol into.
    pub async fn booted<F: Fram>(
        &mut self,
        fram: &mut F,
        epoch: Epoch,
    ) -> Result<Booted, Refused<F::Error>> {
        let because = match self.held() {
            Held::Present(table) if table.is_under(epoch) => {
                let rebased = table.clone().rebased();
                self.rebase(rebased);
                return Ok(Booted::Rebased);
            }
            Held::Present(table) if table.epoch() > epoch => {
                return Ok(Booted::Above(table.epoch()));
            }
            Held::Present(table) => Because::Earlier(table.epoch()),
            Held::Absent => Because::Absent,
            Held::Corrupt => Because::Corrupt,
            Held::Malformed(malformed) => Because::Malformed(*malformed),
        };
        let cleared = ClientTable::cleared(&Clearing::found_at_boot(epoch));
        self.write(fram, cleared).await?;
        Ok(Booted::Cleared(because))
    }
}

impl Body<CLIENT_TABLE_BYTES> for ClientTable {
    fn encode(&self) -> [u8; CLIENT_TABLE_BYTES] {
        let mut out = [0u8; CLIENT_TABLE_BYTES];
        let mut dedup = [0u8; DEDUP_BYTES];
        self.dedup.encode_into(&mut dedup);
        let mut writer = Writer::over(&mut out);
        writer.u32(self.epoch.get());
        for row in &self.rows {
            match row {
                Some(row) => {
                    writer.u8(row.kind as u8);
                    row.label.put(&mut writer);
                    writer.u16(row.mask.0);
                    writer.u64(row.counter.0);
                }
                None => writer.skip(ROW_BYTES),
            }
        }
        writer.put(&dedup);
        out
    }

    fn decode(bytes: &[u8; CLIENT_TABLE_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let epoch = Epoch::new(reader.u32()?).ok_or(reader.malformed(4))?;
        let mut rows = [None; ROWS];
        for row in &mut rows {
            let kind = reader.u8()?;
            if kind == VACANT {
                reader.skip(ROW_BYTES.saturating_sub(1));
                continue;
            }
            let kind = ClientKind::try_from(kind).map_err(|()| reader.malformed(1))?;
            let label = Label::take(&mut reader)?;
            let mask = ClientCapability(reader.u16()?);
            let counter = Counter(reader.u64()?);
            *row = Some(Row {
                label,
                kind,
                mask,
                counter,
            });
        }
        let base = reader.at();
        let dedup =
            Dedup::decode(&reader.take::<DEDUP_BYTES>()?).map_err(|malformed| Malformed {
                at: base.saturating_add(malformed.at),
            })?;
        Ok(Self { epoch, rows, dedup })
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::fram::Address;

    /// Enough of the part for the client table's record.
    const PART_BYTES: usize = 4096;
    const _: () = assert!(crate::map::CLIENT_TABLE.end().0 as usize <= PART_BYTES);

    struct Part {
        bytes: [u8; PART_BYTES],
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0; PART_BYTES],
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
            let start = usize::from(at.0);
            self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
            core::future::ready(Ok(()))
        }
    }

    fn client(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    fn label(text: &str) -> Label {
        Label::new(text).expect("a label under the cap")
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    /// An empty table under epoch 1, the way a fresh unit's boot makes one.
    fn fresh() -> ClientTable {
        ClientTable::cleared(&Clearing::found_at_boot(Epoch::FIRST))
    }

    fn enrol(table: &mut ClientTable, text: &str, kind: ClientKind) -> ClientId {
        match table.pair(label(text), kind) {
            Ok(Paired::Enrolled(id)) => id,
            other => panic!("{text} was not enrolled: {other:?}"),
        }
    }

    #[test]
    fn p_086_the_lowest_free_slot_is_allocated_counting_from_one() {
        let mut table = fresh();
        assert_eq!(enrol(&mut table, "phone", ClientKind::App), client(1));
        assert_eq!(enrol(&mut table, "laptop", ClientKind::Cli), client(2));
        assert_eq!(enrol(&mut table, "cloud", ClientKind::Cloud), client(3));
        assert_eq!(table.enrolled(), 3);
        assert_eq!(table.row(client(2)).map(Row::kind), Some(ClientKind::Cli));
        assert_eq!(table.row(client(4)), None);
        assert_eq!(table.row(client(9)), None);
    }

    #[test]
    fn p_064_an_enrolment_that_succeeds_carries_the_slot_it_was_given_and_never_zero() {
        let mut table = fresh();
        let answered = table.pair(label("phone"), ClientKind::App).expect("room");
        assert_eq!(answered, Paired::Enrolled(client(1)));
        assert_eq!(answered.client().get(), 1);
        let again = table
            .pair(label("phone"), ClientKind::App)
            .expect("its own row");
        assert_eq!(again, Paired::Reclaimed(client(1)));
        assert_eq!(again.client(), answered.client());
    }

    #[test]
    fn p_067_a_full_table_refuses_rather_than_evicts() {
        let mut table = fresh();
        let texts = [
            "one", "two", "three", "four", "five", "six", "seven", "eight",
        ];
        for (n, text) in (1u32..).zip(texts) {
            assert_eq!(enrol(&mut table, text, ClientKind::App).get(), n);
        }
        assert_eq!(table.pair(label("nine"), ClientKind::App), Err(TableFull));
        assert_eq!(table.enrolled(), ROWS);
        assert_eq!(
            table.row(client(1)).map(|r| r.label().as_bytes()),
            Some(&b"one"[..])
        );
    }

    #[test]
    fn p_078_a_byte_identical_label_reclaims_its_row_with_the_counter_at_zero_and_the_mask_refixed()
    {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::Cloud);
        assert_eq!(table.accept(id, Counter(40)), Check::Ahead);
        // Reinstalled as an app: same slot, counter back, mask re-fixed
        // from the new kind, even in a full table.
        for text in ["b", "c", "d", "e", "f", "g", "h"] {
            let _ = enrol(&mut table, text, ClientKind::App);
        }
        assert_eq!(
            table.pair(label("phone"), ClientKind::App),
            Ok(Paired::Reclaimed(id))
        );
        let row = table.row(id).expect("the row");
        assert_eq!(row.counter(), FRESHLY_ENROLLED);
        assert_eq!(row.kind(), ClientKind::App);
        assert_eq!(row.mask(), ClientCapability::granted(ClientKind::App));
        assert_eq!(table.enrolled(), ROWS);
    }

    #[test]
    fn p_078_a_label_that_differs_by_case_or_a_space_is_another_client() {
        let mut table = fresh();
        let _ = enrol(&mut table, "Phone", ClientKind::App);
        assert_eq!(
            table.pair(label("phone"), ClientKind::App),
            Ok(Paired::Enrolled(client(2)))
        );
        assert_eq!(
            table.pair(label("Phone "), ClientKind::App),
            Ok(Paired::Enrolled(client(3)))
        );
    }

    #[test]
    fn p_065_a_new_client_starts_at_zero_and_its_first_counter_is_one_or_more() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        assert_eq!(table.accepted(id), Some(FRESHLY_ENROLLED));
        assert_eq!(table.accept(id, Counter(0)), Check::Stale);
        assert_eq!(table.accept(id, Counter(1)), Check::Ahead);
        assert_eq!(table.accepted(id), Some(Counter(1)));
    }

    #[test]
    fn p_081_counters_are_per_client_and_equal_is_the_replay() {
        let mut table = fresh();
        let a = enrol(&mut table, "a", ClientKind::App);
        let b = enrol(&mut table, "b", ClientKind::App);
        assert_eq!(table.accept(a, Counter(100)), Check::Ahead);
        assert_eq!(table.accept(a, Counter(100)), Check::Stale);
        assert_eq!(table.accept(a, Counter(99)), Check::Stale);
        // b's row is its own: 100 is fresh there.
        assert_eq!(table.accept(b, Counter(100)), Check::Ahead);
        assert_eq!(table.accept(a, Counter(101)), Check::Ahead);
        assert_eq!(table.accepted(a), Some(Counter(101)));
        assert_eq!(table.accepted(b), Some(Counter(100)));
        assert_eq!(table.accept(client(3), Counter(1)), Check::NoSuchClient);
        assert_eq!(table.accepted(client(3)), None);
    }

    #[test]
    fn p_105_the_mask_is_fixed_from_the_kind_and_the_cloud_gets_no_firmware_clock_or_network() {
        let mut table = fresh();
        let cloud = enrol(&mut table, "relay", ClientKind::Cloud);
        let mask = table.row(cloud).expect("the row").mask();
        assert!(mask.allows(ClientCapability::SEND_COMMAND));
        assert!(mask.allows(ClientCapability::WRITE_CONFIG));
        assert!(!mask.allows(ClientCapability::PUSH_FIRMWARE));
        assert!(!mask.allows(ClientCapability::SET_CLOCK));
        assert!(!mask.allows(ClientCapability::WRITE_NETWORK_AND_CLOUD));
        for (text, kind) in [
            ("app", ClientKind::App),
            ("browser", ClientKind::Browser),
            ("cli", ClientKind::Cli),
        ] {
            let id = table.pair(label(text), kind).expect("room").client();
            let mask = table.row(id).expect("the row").mask();
            assert!(mask.allows(ClientCapability::PUSH_FIRMWARE), "{kind:?}");
        }
        // A kind byte the registry does not name is not a client.
        assert!(ClientKind::try_from(5).is_err());
    }

    #[test]
    fn p_080_a_command_is_refused_stale_before_the_dedup_table_is_consulted() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let start = Fingerprint::of(b"start");
        let _ = table.admit(id, Counter(5), 1, start, Tick::ZERO);
        // A replay of that very frame: stale, and not `Already`.
        assert_eq!(
            table.admit(id, Counter(5), 1, start, Tick::ZERO),
            Admitted::Stale
        );
        assert_eq!(
            table.admit(client(2), Counter(1), 1, start, Tick::ZERO),
            Admitted::NoSuchClient
        );
    }

    #[test]
    fn p_080_a_fresh_command_moves_the_counter_and_reserves_the_entry_in_one_change() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let before = table.encode();
        let start = Fingerprint::of(b"start");
        let Admitted::Fresh(seat) = table.admit(id, Counter(7), 1, start, Tick::from_millis(10))
        else {
            panic!("a fresh command");
        };
        assert_eq!(table.accepted(id), Some(Counter(7)));
        assert_eq!(table.dedup().live(Tick::from_millis(10)), 1);
        // Both moved in the one body the record lands.
        let after = table.encode();
        let counter_at = 4 + 4 + MAX_LABEL;
        assert_ne!(
            before[counter_at..counter_at + 8],
            after[counter_at..counter_at + 8]
        );
        let dedup_at = 4 + ROWS * ROW_BYTES;
        assert_ne!(
            before[dedup_at..dedup_at + 25],
            after[dedup_at..dedup_at + 25]
        );
        // A retry with the next counter is the entry in flight.
        assert_eq!(
            table.admit(id, Counter(8), 1, start, Tick::from_millis(20)),
            Admitted::InFlight(seat)
        );
        table.finished(seat, Some(Recorded::Accepted));
        assert_eq!(
            table.admit(id, Counter(8), 1, start, Tick::from_millis(30)),
            Admitted::Already(Recorded::Accepted)
        );
    }

    #[test]
    fn p_080_a_matched_command_moves_nothing() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let start = Fingerprint::of(b"start");
        let Admitted::Fresh(seat) = table.admit(id, Counter(1), 1, start, Tick::ZERO) else {
            panic!("a fresh command");
        };
        table.finished(seat, Some(Recorded::Shadowed));
        let before = table.clone();
        assert_eq!(
            table.admit(id, Counter(2), 1, start, Tick::ZERO),
            Admitted::Already(Recorded::Shadowed)
        );
        assert_eq!(
            table.admit(id, Counter(2), 1, Fingerprint::of(b"stop"), Tick::ZERO),
            Admitted::ReusedId
        );
        assert_eq!(table, before);
        assert_eq!(table.accepted(id), Some(Counter(1)));
    }

    #[test]
    fn p_122_a_command_with_no_room_is_busy_and_moves_nothing() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let half = u32::try_from(crate::dedup::PER_CLIENT).expect("half the table fits a u32");
        for cmd in 0..half {
            let counter = Counter(u64::from(cmd) + 1);
            let Admitted::Fresh(seat) =
                table.admit(id, counter, cmd, Fingerprint::of(b"x"), Tick::ZERO)
            else {
                panic!("a fresh command");
            };
            table.finished(seat, Some(Recorded::Accepted));
        }
        let before = table.clone();
        assert_eq!(
            table.admit(id, Counter(99), 99, Fingerprint::of(b"x"), Tick::ZERO),
            Admitted::Busy
        );
        assert_eq!(table, before);
    }

    #[test]
    fn p_085_a_clearing_empties_every_row_and_entry_and_stamps_the_epoch() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let _ = table.admit(id, Counter(1), 1, Fingerprint::of(b"x"), Tick::ZERO);
        let cleared = ClientTable::cleared(&Clearing::found_at_boot(epoch(2)));
        assert_eq!(cleared.enrolled(), 0);
        assert_eq!(cleared.dedup().live(Tick::ZERO), 0);
        assert_eq!(cleared.epoch(), epoch(2));
        assert!(cleared.is_under(epoch(2)));
        assert!(!cleared.is_under(Epoch::FIRST));
    }

    #[test]
    fn f_026_a_table_under_a_later_epoch_is_left_alone_not_cleared_under_the_earlier_one() {
        // The record says one; the table says two. Clearing under one
        // would hand the next enrolment a key the move to two invalidated.
        let later = ClientTable::cleared(&Clearing::found_at_boot(epoch(2)));
        let mut part = Part::fresh();
        let mut kept = block_on(Kept::<ClientTable, CLIENT_TABLE_BYTES>::read(
            crate::map::CLIENT_TABLE,
            &mut part,
        ))
        .expect("reads");
        block_on(kept.write(&mut part, later.clone())).expect("the supply is fine");
        let before = part.bytes;
        assert_eq!(
            block_on(kept.booted(&mut part, Epoch::FIRST)),
            Ok(Booted::Above(epoch(2)))
        );
        assert_eq!(kept.present(), Some(&later));
        assert_eq!(part.bytes, before, "nothing was written");
        // Under its own epoch it is an ordinary table.
        assert_eq!(
            block_on(kept.booted(&mut part, epoch(2))),
            Ok(Booted::Rebased)
        );
        // Under a later one still, it is cleared: the reset that moved
        // the epoch to three is finished here.
        assert_eq!(
            block_on(kept.booted(&mut part, epoch(3))),
            Ok(Booted::Cleared(Because::Earlier(epoch(2))))
        );
        assert!(kept.present().is_some_and(|table| table.is_under(epoch(3))));
    }

    #[test]
    fn f_026_a_table_stamped_with_another_epoch_is_not_under_this_one() {
        let table = fresh();
        assert!(table.is_under(Epoch::FIRST));
        assert!(!table.is_under(epoch(2)));
        // And the stamp survives the part.
        let found = ClientTable::decode(&table.encode()).expect("decodes");
        assert_eq!(found.epoch(), Epoch::FIRST);
        assert!(!found.is_under(epoch(2)));
    }

    #[test]
    fn p_121_a_boot_restarts_the_entries_and_keeps_the_rows() {
        let mut table = fresh();
        let id = enrol(&mut table, "phone", ClientKind::App);
        let Admitted::Fresh(seat) = table.admit(
            id,
            Counter(1),
            1,
            Fingerprint::of(b"x"),
            Tick::from_millis(400_000),
        ) else {
            panic!("a fresh command");
        };
        table.finished(seat, Some(Recorded::Accepted));
        let rebooted = table.rebased();
        assert_eq!(rebooted.accepted(id), Some(Counter(1)));
        assert_eq!(rebooted.dedup().live(Tick::from_millis(599_999)), 1);
        assert_eq!(rebooted.dedup().live(Tick::from_millis(600_000)), 0);
    }

    #[test]
    fn every_row_and_entry_survives_the_round_trip() {
        let mut table = fresh();
        let a = enrol(&mut table, "pump house", ClientKind::App);
        let _ = enrol(&mut table, "", ClientKind::Browser);
        let c = enrol(
            &mut table,
            "a label of exactly thirty-two b",
            ClientKind::Cloud,
        );
        assert_eq!(table.accept(a, Counter(u64::MAX)), Check::Ahead);
        let Admitted::Fresh(seat) = table.admit(
            c,
            Counter(3),
            9,
            Fingerprint::of(b"x"),
            Tick::from_millis(77),
        ) else {
            panic!("a fresh command");
        };
        table.finished(seat, Some(Recorded::Shadowed));
        let bytes = table.encode();
        assert_eq!(ClientTable::decode(&bytes), Ok(table));
        // The budget past the layout is zero.
        assert!(bytes[LAYOUT..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_row_with_an_unknown_kind_a_long_label_or_bad_utf8_is_malformed_not_a_client() {
        let mut table = fresh();
        let _ = enrol(&mut table, "phone", ClientKind::App);
        let good = table.encode();
        // Row one starts at 4: kind, len, mask, label, counter.
        let mut kind = good;
        kind[4] = 7;
        assert_eq!(ClientTable::decode(&kind), Err(Malformed { at: 4 }));
        let mut len = good;
        len[5] = 33;
        assert_eq!(ClientTable::decode(&len), Err(Malformed { at: 5 }));
        let mut utf8 = good;
        utf8[8] = 0xFF;
        assert_eq!(ClientTable::decode(&utf8), Err(Malformed { at: 6 }));
        let mut epoch = good;
        epoch[..4].copy_from_slice(&[0; 4]);
        assert_eq!(ClientTable::decode(&epoch), Err(Malformed { at: 0 }));
        // A dedup status nobody allocated names its offset in the body.
        let mut status = good;
        let entry = 4 + ROWS * ROW_BYTES;
        status[entry..entry + 4].copy_from_slice(&1u32.to_le_bytes());
        status[entry + 24] = 3;
        assert_eq!(
            ClientTable::decode(&status),
            Err(Malformed { at: entry + 24 })
        );
    }

    #[test]
    fn a_label_past_thirty_two_bytes_is_refused_not_truncated() {
        assert_eq!(
            Label::new("a label of thirty-three bytes....").map(|l| l.len()),
            Err(crate::text::TooLong { len: 33, cap: 32 })
        );
        assert_eq!(label("").as_bytes(), b"");
        assert_eq!(label("étable").as_bytes(), "étable".as_bytes());
    }
}
