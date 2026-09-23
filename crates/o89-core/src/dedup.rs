//! Telling a client's retry apart from a second command.
//!
//! A command that starts an engine has to be safe to retry, because the
//! client that sent it may never have seen the answer. So a retry is
//! remembered and answered with what was recorded rather than executed
//! again: on a maintained contact, at a site with nobody in the room, the
//! alternative is a second start.
//!
//! Three things in the key, each a failure that was going to happen.
//! Without `client_id`, two clients numbering their commands from zero get
//! `duplicate` for a command nobody sent twice. Without the hash, a client
//! that reuses a `cmd_id` for a different command is told `duplicate`,
//! which reads as *you already sent this and it was acted on*: the client
//! stops, satisfied, and the command it asked for was never executed and
//! never refused. The lookup is on `(client_id, cmd_id)` and the hash
//! decides which answer the match gets (P-120, P-124).
//!
//! The table is one field of the client table's record, not a record of
//! its own, because P-080 lands the in-flight entry and the new counter in
//! one FRAM transaction, and one record is the only thing that is one
//! transaction. It survives a reset (P-121), refuses rather than evicts
//! (P-122), and every entry restarts at the new boot's tick zero, because
//! the tick that measures its ten minutes is zero at exactly the boot it
//! has to survive.
//!
//! cites: P-080, P-120, P-121, P-122, P-124

use km43::{ClientId, MAX_CLIENTS, MAX_CMD_DEDUP};
use sha2::{Digest as _, Sha256};

use crate::body::{Malformed, Reader, Writer};
use crate::tick::{Millis, Tick};

/// How long a command is remembered.
pub const DEDUP_WINDOW: Millis = Millis::from_millis(600_000);

/// The most live entries one client may hold: half the table, so it can
/// only be globally full when at least two clients are jointly filling it,
/// and one commissioning laptop in a retry loop cannot deny a stop request
/// to the other seven (P-122).
pub const PER_CLIENT: usize = MAX_CMD_DEDUP / 2;

/// Bytes of the digest kept: the leftmost eight of SHA-256.
pub const FINGERPRINT_BYTES: usize = 8;

/// The bytes one entry takes on the part: `client_id`, `cmd_id`, the
/// fingerprint, `inserted` and the status byte.
pub const ENTRY_BYTES: usize = 4 + 4 + FINGERPRINT_BYTES + 8 + 1;

/// The bytes the whole table takes on the part.
pub const DEDUP_BYTES: usize = ENTRY_BYTES * MAX_CMD_DEDUP;

const _: () = assert!(PER_CLIENT < MAX_CMD_DEDUP);
const _: () = assert!(MAX_CLIENTS > 1);
const _: () = assert!(ENTRY_BYTES == 25);

/// The status byte on the part: in flight, or the outcome recorded.
const IN_FLIGHT: u8 = 0;
const ACCEPTED: u8 = 1;
const SHADOWED: u8 = 6;

/// What a command's operation bytes hash to.
///
/// Over the bytes exactly as they arrived on the wire, never a
/// re-encoding: a genuine retry carries byte-identical operation bytes,
/// so it hashes the same, and a field reordered by a serialiser must not
/// turn a retry into a new command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fingerprint([u8; FINGERPRINT_BYTES]);

impl Fingerprint {
    /// The leftmost eight bytes of SHA-256 over the operation as received.
    #[must_use]
    pub fn of(operation: &[u8]) -> Self {
        let digest = Sha256::digest(operation);
        let mut kept = [0; FINGERPRINT_BYTES];
        for (slot, byte) in kept.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
        Self(kept)
    }

    /// The eight bytes as the part holds them.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }
}

/// What a completed command did, which is what a retry is answered with.
///
/// Two outcomes and not one: a retried command in shadow mode answered
/// `duplicate` tells the client an action was taken at a site where, by
/// definition, nothing was actuated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Recorded {
    /// Outcome 1: it executed.
    Accepted,
    /// Outcome 6: the behaviour ran and the hardware was not written.
    Shadowed,
}

/// A reserved entry, waiting to be told what its command did.
///
/// P-080 step 4 writes the entry before executing and step 6 completes
/// it. There is no public constructor: the only one that exists came out
/// of a [`Verdict::Fresh`], so an entry cannot be completed by anything
/// that did not reserve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a reserved entry never finished is a retry answered in-flight forever"]
pub struct Reserved {
    at: usize,
    client: ClientId,
    cmd: u32,
}

/// What the table says about a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a verdict thrown away is a command answered by nothing"]
pub enum Verdict {
    /// Nothing like it is in the table. The entry is reserved in flight;
    /// execute, then say what happened with [`Dedup::finished`].
    Fresh(Reserved),
    /// The same client, the same id, the same bytes, and it finished.
    /// Answer with what was recorded; this is the retry the window exists
    /// for.
    Already(Recorded),
    /// The same command, and the entry says only that it was started. A
    /// reset landed on one side of the execution or the other and the
    /// entry cannot say which. P-080 says to answer from the state store,
    /// which knows what the hardware is doing and this table does not.
    InFlight(Reserved),
    /// The same command, still executing under a permit this boot handed
    /// out. Error 7: the retry waits for the answer, and is never handed to
    /// the state store, which would see the hardware not moved yet and run
    /// the command a second time beside the first.
    Running,
    /// The same client and id, different bytes. A client bug: answer
    /// `rejected` with a detail a person can read, never `duplicate`, and
    /// never execute (P-124).
    ReusedId,
    /// No room, in the table or in this client's half of it. Error 7,
    /// because evicting the oldest entry is what makes a duplicate
    /// executable again (P-122).
    Busy,
}

/// What settling an entry left in flight found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a settlement that found the command running must not answer for it"]
pub(crate) enum Settling {
    /// It was still in flight and unheld, and is settled now.
    Settled,
    /// A permit holds it: its command is running.
    Held,
    /// It is not in flight any more: settled, completed or reused since.
    Gone,
}

/// One remembered command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    client: ClientId,
    cmd: u32,
    fingerprint: Fingerprint,
    inserted: Tick,
    /// In flight, or what it did.
    status: Option<Recorded>,
    /// In flight under a permit this boot still holds. Never on the part:
    /// every entry a boot reads was left by a run that is over.
    held: bool,
}

/// The commands seen inside the window.
///
/// Fixed at `MAX_CMD_DEDUP` and refuses rather than evicts: the entry it
/// would forget is the one standing between a client's retry and a second
/// start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dedup {
    entries: [Option<Entry>; MAX_CMD_DEDUP],
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

impl Dedup {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_CMD_DEDUP],
        }
    }

    /// The table as it was before a reset, with every surviving entry
    /// restarted at this boot's tick zero, so it lives a further ten
    /// minutes from that moment and never longer (P-121).
    #[must_use]
    pub fn rebased(mut self) -> Self {
        for entry in self.entries.iter_mut().flatten() {
            entry.inserted = Tick::ZERO;
            entry.held = false;
        }
        self
    }

    /// How many entries are live at `now`.
    #[must_use]
    pub fn live(&self, now: Tick) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| Self::inside(entry, now))
            .count()
    }

    /// What to do with this command, remembering it if it is fresh.
    ///
    /// The lookup is on `(client, cmd)` and the fingerprint decides which
    /// answer the match gets: agreeing is the retry, disagreeing is the
    /// client bug.
    pub fn admit(
        &mut self,
        client: ClientId,
        cmd: u32,
        fingerprint: Fingerprint,
        now: Tick,
    ) -> Verdict {
        let mut free = None;
        let mut held_by_client: usize = 0;
        for (index, slot) in self.entries.iter().enumerate() {
            let Some(entry) = slot else {
                free.get_or_insert(index);
                continue;
            };
            if !Self::inside(entry, now) {
                free.get_or_insert(index);
                continue;
            }
            if entry.client != client {
                continue;
            }
            held_by_client = held_by_client.saturating_add(1);
            if entry.cmd != cmd {
                continue;
            }
            if entry.fingerprint != fingerprint {
                return Verdict::ReusedId;
            }
            let seat = Reserved {
                at: index,
                client,
                cmd,
            };
            return match (entry.status, entry.held) {
                (Some(recorded), _) => Verdict::Already(recorded),
                (None, true) => Verdict::Running,
                (None, false) => Verdict::InFlight(seat),
            };
        }
        if held_by_client >= PER_CLIENT {
            return Verdict::Busy;
        }
        let Some(index) = free else {
            return Verdict::Busy;
        };
        let Some(slot) = self.entries.get_mut(index) else {
            return Verdict::Busy;
        };
        *slot = Some(Entry {
            client,
            cmd,
            fingerprint,
            inserted: now,
            status: None,
            held: true,
        });
        Verdict::Fresh(Reserved {
            at: index,
            client,
            cmd,
        })
    }

    /// Say what a reserved command did, or that it did nothing.
    ///
    /// `None` discards the entry. An entry is created only for a command
    /// that executed or committed to executing; `rejected`, `inhibited`
    /// and `unauthorised` name conditions the client is expected to retry
    /// past, and an entry left behind answers that retry `duplicate`: the
    /// silent no-op wearing the word for success, reached from the other
    /// side (P-120).
    ///
    /// The seat names a row, and the row is checked to still be that
    /// command: an expiry between reserving and finishing can have handed
    /// the slot on, and completing somebody else's entry is worse than
    /// losing this one.
    pub fn finished(&mut self, seat: Reserved, outcome: Option<Recorded>) {
        let Some(slot) = self.entries.get_mut(seat.at) else {
            return;
        };
        let Some(entry) = slot else {
            return;
        };
        if entry.client != seat.client || entry.cmd != seat.cmd {
            return;
        }
        match outcome {
            Some(recorded) => {
                entry.status = Some(recorded);
                entry.held = false;
            }
            None => *slot = None,
        }
    }

    /// Settle an entry a boot, or a spent permit, left in flight, as the state
    /// store decided: completed with `outcome`, or discarded for `None`. Only
    /// if the seat still names that entry as it was handed out: in flight and
    /// held by no permit. Two retries can be handed the same entry, and the
    /// one that settles second meets what the first did with it, which it
    /// must leave alone.
    pub(crate) fn settled(&mut self, seat: Reserved, outcome: Option<Recorded>) -> Settling {
        let Some(slot) = self.entries.get_mut(seat.at) else {
            return Settling::Gone;
        };
        let Some(entry) = slot else {
            return Settling::Gone;
        };
        if entry.client != seat.client || entry.cmd != seat.cmd {
            return Settling::Gone;
        }
        match (entry.status, entry.held) {
            (Some(_), _) => Settling::Gone,
            (None, true) => Settling::Held,
            (None, false) => {
                match outcome {
                    Some(recorded) => entry.status = Some(recorded),
                    None => *slot = None,
                }
                Settling::Settled
            }
        }
    }

    /// Let go of a reserved entry whose outcome the part would not take: the
    /// permit is spent, so the entry is one the state store settles, as it
    /// would be after a reset. Changes nothing the part holds.
    pub(crate) fn released(&mut self, seat: Reserved) {
        if let Some(Some(entry)) = self.entries.get_mut(seat.at)
            && entry.client == seat.client
            && entry.cmd == seat.cmd
        {
            entry.held = false;
        }
    }

    /// Whether an entry is still inside the window at `now`.
    fn inside(entry: &Entry, now: Tick) -> bool {
        now.since(entry.inserted)
            .is_some_and(|since| since < DEDUP_WINDOW)
    }

    /// The table as the part holds it: every entry, vacant ones as zeros.
    pub(crate) fn encode_into(&self, out: &mut [u8; DEDUP_BYTES]) {
        let mut writer = Writer::over(out);
        for slot in &self.entries {
            match slot {
                Some(entry) => {
                    writer.u32(entry.client.get());
                    writer.u32(entry.cmd);
                    writer.put(&entry.fingerprint.0);
                    writer.u64(entry.inserted.as_millis());
                    writer.u8(match entry.status {
                        None => IN_FLIGHT,
                        Some(Recorded::Accepted) => ACCEPTED,
                        Some(Recorded::Shadowed) => SHADOWED,
                    });
                }
                None => writer.skip(ENTRY_BYTES),
            }
        }
    }

    /// The table the part holds, or the offset that did not decode.
    pub(crate) fn decode(bytes: &[u8; DEDUP_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let mut entries = [None; MAX_CMD_DEDUP];
        for slot in &mut entries {
            let start = reader.at();
            let Some(client) = ClientId::new(reader.u32()?) else {
                reader.skip(ENTRY_BYTES.saturating_sub(4));
                continue;
            };
            let cmd = reader.u32()?;
            let fingerprint = Fingerprint(reader.take::<FINGERPRINT_BYTES>()?);
            let inserted = Tick::from_millis(reader.u64()?);
            let status = match reader.u8()? {
                IN_FLIGHT => None,
                ACCEPTED => Some(Recorded::Accepted),
                SHADOWED => Some(Recorded::Shadowed),
                _ => return Err(reader.malformed(1)),
            };
            debug_assert_eq!(reader.at().saturating_sub(start), ENTRY_BYTES);
            *slot = Some(Entry {
                client,
                cmd,
                fingerprint,
                inserted,
                status,
                held: false,
            });
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start command's operation bytes, and a different one.
    const START: &[u8] = b"\x01generator/start";
    const STOP: &[u8] = b"\x02generator/stop";

    fn client(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    fn start() -> Fingerprint {
        Fingerprint::of(START)
    }

    fn stop() -> Fingerprint {
        Fingerprint::of(STOP)
    }

    fn at(ms: u64) -> Tick {
        Tick::from_millis(ms)
    }

    /// Reserve, execute, record: the three steps P-080 puts around this
    /// table.
    fn ran(table: &mut Dedup, who: u32, cmd: u32, what: Fingerprint, now: Tick) -> Reserved {
        let Verdict::Fresh(seat) = table.admit(client(who), cmd, what, now) else {
            panic!("a command nothing like which is in the table");
        };
        table.finished(seat, Some(Recorded::Accepted));
        seat
    }

    #[test]
    fn p_120_a_retry_is_answered_with_what_was_recorded_not_started_again() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 7, start(), at(0));
        assert_eq!(
            table.admit(client(1), 7, start(), at(1_000)),
            Verdict::Already(Recorded::Accepted)
        );
        // A command that ran in shadow is answered shadowed, never
        // duplicate: nothing was actuated and the client is told so.
        let Verdict::Fresh(seat) = table.admit(client(1), 8, start(), at(0)) else {
            panic!("a fresh command");
        };
        table.finished(seat, Some(Recorded::Shadowed));
        assert_eq!(
            table.admit(client(1), 8, start(), at(2_000)),
            Verdict::Already(Recorded::Shadowed)
        );
    }

    #[test]
    fn p_120_two_clients_numbering_from_zero_do_not_dedup_each_other() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 0, start(), at(0));
        assert!(
            matches!(table.admit(client(2), 0, start(), at(0)), Verdict::Fresh(_)),
            "client 2's first command was read as client 1's retry"
        );
    }

    #[test]
    fn p_120_a_command_that_was_refused_leaves_no_entry_behind() {
        let mut table = Dedup::new();
        let Verdict::Fresh(seat) = table.admit(client(1), 3, start(), at(0)) else {
            panic!("a fresh command");
        };
        // Inhibited: the selector was at Off. The client retries past it.
        table.finished(seat, None);
        assert_eq!(table.live(at(0)), 0);
        assert!(matches!(
            table.admit(client(1), 3, start(), at(5_000)),
            Verdict::Fresh(_)
        ));
    }

    #[test]
    fn p_124_a_reused_id_with_different_bytes_is_rejected_not_duplicate_and_not_executed() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 7, start(), at(0));
        assert_eq!(
            table.admit(client(1), 7, stop(), at(1_000)),
            Verdict::ReusedId
        );
        // Nothing was reserved for it.
        assert_eq!(table.live(at(1_000)), 1);
    }

    #[test]
    fn p_122_the_table_refuses_at_thirty_two_rather_than_evicting() {
        let mut table = Dedup::new();
        // Two clients fill it jointly, sixteen each.
        for cmd in 0..16u32 {
            let _ = ran(&mut table, 1, cmd, start(), at(0));
            let _ = ran(&mut table, 2, cmd, start(), at(0));
        }
        assert_eq!(table.live(at(0)), MAX_CMD_DEDUP);
        assert_eq!(table.admit(client(3), 0, start(), at(1)), Verdict::Busy);
        // The oldest is still answered as the retry it is.
        assert_eq!(
            table.admit(client(1), 0, start(), at(1)),
            Verdict::Already(Recorded::Accepted)
        );
    }

    #[test]
    fn p_122_one_client_holds_at_most_half_and_the_others_are_unaffected() {
        let mut table = Dedup::new();
        let half = u32::try_from(PER_CLIENT).expect("half the table fits a u32");
        for cmd in 0..half {
            let _ = ran(&mut table, 1, cmd, start(), at(0));
        }
        assert_eq!(table.admit(client(1), 99, start(), at(1)), Verdict::Busy);
        assert!(matches!(
            table.admit(client(2), 99, start(), at(1)),
            Verdict::Fresh(_)
        ));
    }

    #[test]
    fn p_121_an_entry_expires_after_ten_minutes_on_the_tick() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 7, start(), at(1_000));
        assert_eq!(
            table.admit(client(1), 7, start(), at(600_999)),
            Verdict::Already(Recorded::Accepted)
        );
        assert!(matches!(
            table.admit(client(1), 7, start(), at(601_000)),
            Verdict::Fresh(_)
        ));
    }

    #[test]
    fn p_121_a_boot_restarts_every_surviving_entry_at_tick_zero() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 7, start(), at(500_000));
        let rebooted = table.rebased();
        // Ten minutes from the new boot, not from the old tick.
        assert_eq!(
            rebooted.clone().admit(client(1), 7, start(), at(599_999)),
            Verdict::Already(Recorded::Accepted)
        );
        assert!(matches!(
            rebooted.clone().admit(client(1), 7, start(), at(600_000)),
            Verdict::Fresh(_)
        ));
    }

    /// An entry a permit on this boot still holds is running, and its retry
    /// waits. One a boot found, or whose permit is spent, is handed back for
    /// the state store, never answered from the entry.
    #[test]
    fn p_080_an_entry_in_flight_is_running_until_its_permit_lets_go_then_handed_back() {
        let mut table = Dedup::new();
        let Verdict::Fresh(seat) = table.admit(client(1), 7, start(), at(0)) else {
            panic!("a fresh command");
        };
        assert_eq!(
            table.admit(client(1), 7, start(), at(100)),
            Verdict::Running
        );
        assert_eq!(
            table
                .clone()
                .rebased()
                .admit(client(1), 7, start(), at(100)),
            Verdict::InFlight(seat)
        );
        table.released(seat);
        assert_eq!(
            table.admit(client(1), 7, start(), at(100)),
            Verdict::InFlight(seat)
        );
        // A different command with the id is still the reuse it always was.
        assert_eq!(
            table.admit(client(1), 7, stop(), at(100)),
            Verdict::ReusedId
        );
    }

    #[test]
    fn a_seat_completes_only_the_entry_it_reserved() {
        let mut table = Dedup::new();
        let Verdict::Fresh(seat) = table.admit(client(1), 7, start(), at(0)) else {
            panic!("a fresh command");
        };
        // The entry expires and another client takes the slot.
        let Verdict::Fresh(_) = table.admit(client(2), 9, stop(), at(700_000)) else {
            panic!("a fresh command in the expired slot");
        };
        table.finished(seat, Some(Recorded::Accepted));
        // Neither completed nor let go: still client 2's, still running.
        assert_eq!(
            table.admit(client(2), 9, stop(), at(700_001)),
            Verdict::Running
        );
        // Nor released by a seat that no longer names it.
        table.released(seat);
        assert_eq!(
            table.admit(client(2), 9, stop(), at(700_002)),
            Verdict::Running
        );
        assert_eq!(
            table.rebased().admit(client(2), 9, stop(), at(1)),
            Verdict::InFlight(Reserved {
                at: 0,
                client: client(2),
                cmd: 9
            })
        );
    }

    #[test]
    fn p_120_the_fingerprint_is_over_the_bytes_as_they_arrived() {
        assert_eq!(Fingerprint::of(START), Fingerprint::of(START));
        assert_ne!(Fingerprint::of(START), Fingerprint::of(STOP));
        // The leftmost eight bytes of SHA-256 over the empty string.
        assert_eq!(
            Fingerprint::of(b""),
            Fingerprint::from_bytes([0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14])
        );
    }

    #[test]
    fn every_entry_survives_the_round_trip_and_a_stray_status_is_malformed() {
        let mut table = Dedup::new();
        let _ = ran(&mut table, 1, 7, start(), at(1_234));
        let Verdict::Fresh(seat) = table.admit(client(8), u32::MAX, stop(), at(1_235)) else {
            panic!("a fresh command");
        };
        table.finished(seat, Some(Recorded::Shadowed));
        let Verdict::Fresh(held) = table.admit(client(3), 1, start(), at(1_236)) else {
            panic!("a fresh command");
        };
        assert_eq!(table.live(at(1_236)), 3);
        let mut bytes = [0u8; DEDUP_BYTES];
        table.encode_into(&mut bytes);
        // The part never holds that a permit has an entry: what it gives back
        // is the entry a boot finds, in flight and held by nobody.
        table.released(held);
        assert_eq!(Dedup::decode(&bytes), Ok(table));
        // A status byte nobody allocated, in the third entry.
        bytes[2 * ENTRY_BYTES + 24] = 2;
        assert_eq!(
            Dedup::decode(&bytes),
            Err(Malformed {
                at: 2 * ENTRY_BYTES + 24
            })
        );
        // Every byte zero is the empty table.
        assert_eq!(Dedup::decode(&[0; DEDUP_BYTES]), Ok(Dedup::new()));
    }
}
