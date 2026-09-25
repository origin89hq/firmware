//! Every record the controller keeps, read in the boot's order, with the
//! rules that tie one record to another applied where both are in hand.
//!
//! A boot reads the part once and holds what it read: the epoch, the
//! client table, the controller key, the generator's state, the run
//! reason, the panic record and the rest, each as a [`Kept`] whose RAM copy
//! moves only when the part has moved. Four things happen on the way: a
//! fresh unit gets its first epoch; an epoch record behind a slot written
//! under a later one is raised to it, because a slot's epoch is a second
//! copy of a counter that only climbs and the higher copy is the counter
//! (F-026); the table is repaired as P-239 says, which may advance the
//! epoch; the boot count climbs and the last words, if a run left any, are
//! written down with it. Everything that measures a window on the tick is
//! restarted at this boot's tick zero (P-121), the recovery ladder's recent
//! cuts included (F-017).
//!
//! A boot that cannot read the part returns the bus error and nothing
//! else: there is no partial store to hold, and nothing was written, so a
//! boot tried again on the same part counts once. A write the boot could
//! not make is in the report, so the caller raises what it owes. A pending
//! manufacturing transaction is completed after all reads and before these
//! ordinary boot writes; a failed recovery write returns no store and
//! therefore no sessions. Unreadable intent is discarded without changing
//! keys.
//!
//! cites: P-085, P-121, P-235, P-237, P-239, F-026

use km43::Epoch;

use crate::body::{Held, Kept, Malformed};
use crate::boot_count::{BOOT_COUNT_BYTES, BootCount};
use crate::clients::{Clients, Repaired, Unrepaired};
use crate::drbg::{DRBG_BYTES, DrbgState};
use crate::epoch::EPOCH_BYTES;
use crate::fram::{Fram, Refused};
use crate::last_words::LastWords;
use crate::map;
use crate::network::{NETWORK_BYTES, Network};
use crate::panic_record::{PANIC_RECORD_BYTES, PanicRecord};
use crate::rail::{CUTS_RECORD_BYTES, CutsRecord};
use crate::release::{COMMS_RELEASE_BYTES, CommsRelease};
use crate::run_reason::{RUN_REASON_BYTES, RunReason};
use crate::secret::{CONTROLLER_KEY_BYTES, ControllerKey, SECRET_BYTES, Secret};
use crate::write_volume::{WRITE_VOLUME_BYTES, WriteVolume};

/// What the controller keeps on the part, as this boot read it.
pub struct Store {
    /// Versioned identity and behaviour sections.
    pub configuration: crate::Configuration,
    /// The device id and the printed secret the pairing keys derive from.
    pub secret: Kept<Secret, SECRET_BYTES>,
    /// The controller key's private half (P-235).
    pub controller: Kept<ControllerKey, CONTROLLER_KEY_BYTES>,
    /// The generator's state (P-237).
    pub drbg: Kept<DrbgState, DRBG_BYTES>,
    /// The epoch (P-085).
    pub epoch: Kept<Epoch, EPOCH_BYTES>,
    /// The client table and the dedup table (P-239).
    pub clients: Clients,
    /// Why the generator is running.
    pub run: Kept<RunReason, RUN_REASON_BYTES>,
    /// What the last run to panic said, and at which boot.
    pub panics: Kept<PanicRecord, PANIC_RECORD_BYTES>,
    /// How many times this unit has booted.
    pub boots: Kept<BootCount, BOOT_COUNT_BYTES>,
    /// The event log's byte budget.
    pub volume: Kept<WriteVolume, WRITE_VOLUME_BYTES>,
    /// The authorised comms release.
    pub release: Kept<CommsRelease, COMMS_RELEASE_BYTES>,
    /// The network master copy.
    pub network: Kept<Network, NETWORK_BYTES>,
    /// The recovery ladder's cuts of the last hour, carried as made at
    /// this boot's start, and the boot count they were written at (F-017,
    /// F-018).
    pub cuts: Kept<CutsRecord, CUTS_RECORD_BYTES>,
}

/// Why the boot has no epoch. No key derives without one, so every `Pair`
/// and `Hello` is refused until a later boot finds it or a person writes
/// one (P-085).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoEpoch<E> {
    /// Both slots written and neither holds.
    Corrupt,
    /// A record that holds and does not decode: a zero.
    Malformed(Malformed),
    /// A fresh unit whose first epoch would not land.
    Refused(Refused<E>),
    /// The record is behind a slot's epoch and raising it would not land.
    /// Enrolling under the record would issue names the move to the slot's
    /// epoch was made to retire, so nothing is enrolled.
    Regressed {
        /// What the record holds.
        record: Epoch,
        /// What the table is under.
        table: Epoch,
        /// Why the raise did not land.
        refused: Refused<E>,
    },
    /// A generation mark could not be read and the epoch it needed advanced
    /// did not land: a table that cannot be trusted and no new epoch to
    /// leave it behind under (P-239).
    Unrepaired,
}

#[cfg(feature = "defmt")]
impl<E: defmt::Format> defmt::Format for NoEpoch<E> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::Corrupt => defmt::write!(f, "both slots damaged"),
            Self::Malformed(malformed) => defmt::write!(f, "malformed at {}", malformed.at),
            Self::Refused(refused) => defmt::write!(f, "first epoch refused: {}", refused),
            Self::Regressed {
                record,
                table,
                refused,
            } => defmt::write!(
                f,
                "record at {} behind the table at {}, raise refused: {}",
                record.get(),
                table.get(),
                refused
            ),
            Self::Unrepaired => defmt::write!(f, "table unrepaired: the epoch did not advance"),
        }
    }
}

/// The epoch this boot runs under, and how it came to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochAtBoot<E> {
    /// Read from the record.
    Held(Epoch),
    /// A fresh unit: this boot wrote the first epoch.
    First,
    /// The record was behind a slot written under a later epoch and was
    /// raised to it.
    Raised {
        /// What the record held.
        from: Epoch,
        /// What it holds now, which is what the slot is under.
        to: Epoch,
    },
    /// A generation mark could not be read, so the table was repaired under
    /// a new epoch, as a factory reset would (P-239).
    Advanced {
        /// What the record held.
        from: Epoch,
        /// What it holds now.
        to: Epoch,
    },
    /// There is none.
    None(NoEpoch<E>),
}

impl<E> EpochAtBoot<E> {
    /// The epoch keys derive under, if there is one.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch> {
        match self {
            Self::Held(epoch)
            | Self::Raised { to: epoch, .. }
            | Self::Advanced { to: epoch, .. } => Some(*epoch),
            Self::First => Some(Epoch::FIRST),
            Self::None(_) => None,
        }
    }
}

#[cfg(feature = "defmt")]
impl<E: defmt::Format> defmt::Format for EpochAtBoot<E> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::Held(epoch) => defmt::write!(f, "epoch {}", epoch.get()),
            Self::First => defmt::write!(f, "first boot, epoch 1 written"),
            Self::Raised { from, to } => {
                defmt::write!(f, "epoch record raised from {} to {}", from.get(), to.get());
            }
            Self::Advanced { from, to } => {
                defmt::write!(
                    f,
                    "table repaired: epoch advanced from {} to {}",
                    from.get(),
                    to.get()
                );
            }
            Self::None(why) => defmt::write!(f, "no epoch: {}", why),
        }
    }
}

/// Whether the last words landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PanicRecorded<E> {
    /// On the part, under this boot's count.
    Landed,
    /// The write did not happen.
    Refused(Refused<E>),
    /// Not attempted: this boot's count did not land, and a record under
    /// a count the part does not hold would name a boot that never was.
    WithoutABootCount,
}

/// What the boot did, for the log and for what the caller owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a boot report nobody reads is a refused write nobody raises"]
pub struct BootReport<E> {
    /// The epoch this boot runs under, or why there is none.
    pub epoch: EpochAtBoot<E>,
    /// What the boot repaired in the client table, or nothing because there
    /// was no epoch to take it under.
    pub clients: Option<Result<Repaired, Unrepaired<E>>>,
    /// Pre-repair enrolment evidence, unavailable if boot repair fails (P-066, F-091).
    pub enrolment: crate::EnrolmentAtBoot,
    /// The number of this boot.
    pub boot: BootCount,
    /// Whether that number landed on the part.
    pub boot_recorded: Result<(), Refused<E>>,
    /// Whether the last words landed, if a run left any.
    pub panic_recorded: Option<PanicRecorded<E>>,
    /// Applied replacement or discarded unreadable bench intent.
    pub secret_recovery: crate::SecretRecovery,
}

impl Store {
    /// Read every record and apply the boot's rules. `last_words` is what
    /// the previous run left in RAM, if anything.
    pub async fn boot<F: Fram>(
        fram: &mut F,
        last_words: Option<LastWords>,
    ) -> Result<(Self, BootReport<F::Error>), crate::ProvisionFailed<F::Error>> {
        // Every read first, then every write: a read that fails returns
        // the bus error with nothing written, so a boot tried again on
        // the same part is the same boot and not one count later.
        let mut secret = Kept::<Secret, SECRET_BYTES>::read(map::DEVICE_SECRET, fram).await?;
        let mut controller =
            Kept::<ControllerKey, CONTROLLER_KEY_BYTES>::read(map::CONTROLLER_KEY, fram).await?;
        let mut drbg = Kept::<DrbgState, DRBG_BYTES>::read(map::DRBG, fram).await?;
        let mut epoch = Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, fram).await?;
        let mut clients = Clients::read(fram).await?;
        let run = Kept::<RunReason, RUN_REASON_BYTES>::read(map::RUN_REASON, fram).await?;
        let mut boots = Kept::<BootCount, BOOT_COUNT_BYTES>::read(map::BOOT_COUNT, fram).await?;
        let mut panics =
            Kept::<PanicRecord, PANIC_RECORD_BYTES>::read(map::PANIC_RECORD, fram).await?;
        let volume = Kept::<WriteVolume, WRITE_VOLUME_BYTES>::read(map::WRITE_VOLUME, fram).await?;
        let mut release =
            Kept::<CommsRelease, COMMS_RELEASE_BYTES>::read(map::COMMS_RELEASE, fram).await?;
        let network = Kept::<Network, NETWORK_BYTES>::read(map::NETWORK, fram).await?;
        let mut cuts = Kept::<CutsRecord, CUTS_RECORD_BYTES>::read(map::RECENT_CUTS, fram).await?;

        let configuration = crate::Configuration::read(fram).await?;
        let secret_recovery =
            crate::provision::finish(fram, &mut secret, &mut controller, &mut drbg).await?;

        let mut at_boot = match *epoch.held() {
            Held::Present(held) => EpochAtBoot::Held(held),
            Held::Absent => match epoch.write(fram, Epoch::FIRST).await {
                Ok(()) => EpochAtBoot::First,
                Err(refused) => EpochAtBoot::None(NoEpoch::Refused(refused)),
            },
            Held::Corrupt => EpochAtBoot::None(NoEpoch::Corrupt),
            Held::Malformed(malformed) => EpochAtBoot::None(NoEpoch::Malformed(malformed)),
        };
        // A slot's epoch is a second copy of the epoch: a record behind it
        // is raised to it, and never the other way round.
        if let (Some(record), Some(table)) = (at_boot.epoch(), clients.highest_epoch())
            && table > record
        {
            at_boot = match epoch.write(fram, table).await {
                Ok(()) => EpochAtBoot::Raised {
                    from: record,
                    to: table,
                },
                Err(refused) => EpochAtBoot::None(NoEpoch::Regressed {
                    record,
                    table,
                    refused,
                }),
            };
        }
        let (enrolment, clients_booted) =
            boot_clients(&mut clients, &mut epoch, &mut at_boot, fram).await;

        let boot = match boots.held() {
            Held::Present(previous) => previous.next(),
            Held::Absent | Held::Corrupt | Held::Malformed(_) => BootCount::FIRST,
        };
        let boot_recorded = boots.write(fram, boot).await;

        let mut panic_recorded = None;
        if let Some(words) = last_words {
            // Only under a count the part holds: a record labelled with a
            // count that never landed names a boot that never was.
            panic_recorded = Some(if boot_recorded.is_ok() {
                let record = PanicRecord {
                    boot: boot.get(),
                    words,
                };
                match panics.write(fram, record).await {
                    Ok(()) => PanicRecorded::Landed,
                    Err(refused) => PanicRecorded::Refused(refused),
                }
            } else {
                PanicRecorded::WithoutABootCount
            });
        }

        restart_windows(&mut release, &mut cuts);

        let report = BootReport {
            epoch: at_boot,
            clients: clients_booted,
            enrolment,
            boot,
            boot_recorded,
            panic_recorded,
            secret_recovery,
        };
        Ok((
            Self {
                configuration,
                secret,
                controller,
                drbg,
                epoch,
                clients,
                run,
                panics,
                boots,
                volume,
                release,
                network,
                cuts,
            },
            report,
        ))
    }
}

/// Repair the table under the boot's epoch, and say what the read is
/// evidence of for P-066's power-on window. A repair that advanced the
/// epoch moves the boot's epoch with it.
async fn boot_clients<F: Fram>(
    clients: &mut Clients,
    epoch: &mut Kept<Epoch, EPOCH_BYTES>,
    at_boot: &mut EpochAtBoot<F::Error>,
    fram: &mut F,
) -> (
    crate::EnrolmentAtBoot,
    Option<Result<Repaired, Unrepaired<F::Error>>>,
) {
    let Some(before) = at_boot.epoch() else {
        // No epoch means no enrolment, and no repair: advancing an epoch
        // nobody can read would be a guess. The dedup windows still restart
        // at tick zero, in RAM only (P-121).
        if let Some(held) = clients.commands().present() {
            let rebased = held.clone().rebased();
            clients.commands_mut().rebase(rebased);
        }
        return (crate::EnrolmentAtBoot::Unavailable, None);
    };
    let repaired = clients.booted(epoch, fram).await;
    // The record, not the repair's result, says which epoch the boot is
    // under: a repair that advanced it and then failed a later write has
    // still retired every slot of the old one.
    match (&repaired, epoch.present()) {
        (Err(Unrepaired::Epoch(_) | Unrepaired::NoEpoch), _) | (_, None) => {
            *at_boot = EpochAtBoot::None(NoEpoch::Unrepaired);
        }
        (Ok(_) | Err(Unrepaired::Write(_)), Some(&held)) if held != before => {
            *at_boot = EpochAtBoot::Advanced {
                from: before,
                to: held,
            };
        }
        (Ok(_) | Err(Unrepaired::Write(_)), Some(_)) => {}
    }
    let enrolled = at_boot.epoch().map_or(0, |under| clients.enrolled(under));
    (
        crate::EnrolmentAtBoot::from_table(repaired.as_ref().ok().copied(), enrolled),
        Some(repaired),
    )
}

/// Every window measured on the tick restarts at this boot's tick zero
/// (P-121), in RAM: the authorised release's and the recovery ladder's
/// (F-017).
fn restart_windows(
    release: &mut Kept<CommsRelease, COMMS_RELEASE_BYTES>,
    cuts: &mut Kept<CutsRecord, CUTS_RECORD_BYTES>,
) {
    if let Some(held) = release.present() {
        let rebased = held.rebased();
        release.rebase(rebased);
    }
    if let Some(held) = cuts.present() {
        let rebased = CutsRecord {
            cuts: held.cuts.rebased(),
            ..*held
        };
        cuts.rebase(rebased);
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{ClientId, ClientKind, Generation, PublicKey, Suite};

    use super::*;
    use crate::body::Body as _;
    use crate::clients::{ClientLabel, Enrolment, KeyRecord};
    use crate::dedup::Fingerprint;
    use crate::fram::{Address, FRAM_BYTES, Position, slot_bytes};
    use crate::last_words::PanicSite;
    use crate::provision::{Birth, SecretChange};
    use crate::release::{Digest, Release};
    use crate::text::Text;
    use crate::tick::Tick;
    use crate::{EPOCH_BYTES, ProvisionFailed, SECRET_CHANGE_BYTES, SecretRecovery, stage_secret};

    /// Enough of the part for every record the boot reads.
    const PART_BYTES: usize = map::END.0 as usize;
    const _: () = assert!(map::RECENT_CUTS.end().0 as usize <= PART_BYTES);
    const _: () = assert!(PART_BYTES <= FRAM_BYTES);

    #[derive(Clone)]
    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        /// An address a read touching it is refused at, for a bus that
        /// fails partway through a boot.
        refuse_reads_at: Option<u16>,
        /// Bytes landed since power-up, and the one the power is cut
        /// before, if a cut is scheduled.
        landed: usize,
        cut_at: Option<usize>,
    }

    impl Part {
        #[expect(
            clippy::large_stack_arrays,
            reason = "the whole map, as the boot reads it; a test thread's stack holds it"
        )]
        fn fresh() -> Self {
            Self {
                bytes: [0; PART_BYTES],
                falling: false,
                refuse_reads_at: None,
                landed: 0,
                cut_at: None,
            }
        }

        fn cut_before(&self, at: usize) -> Self {
            Self {
                landed: 0,
                cut_at: Some(at),
                ..self.clone()
            }
        }

        fn rebooted(&self) -> Self {
            Self {
                landed: 0,
                cut_at: None,
                ..self.clone()
            }
        }
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            let end = start.saturating_add(into.len());
            if self
                .refuse_reads_at
                .is_some_and(|refused| (start..end).contains(&usize::from(refused)))
            {
                return core::future::ready(Err(()));
            }
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
            for (offset, byte) in bytes.iter().enumerate() {
                if self.cut_at.is_some_and(|cut| self.landed >= cut) {
                    return core::future::ready(Err(Refused::Bus(())));
                }
                self.bytes[start.saturating_add(offset)] = *byte;
                self.landed = self.landed.saturating_add(1);
            }
            core::future::ready(Ok(()))
        }
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    fn id(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    fn boot(part: &mut Part, words: Option<LastWords>) -> (Store, BootReport<()>) {
        block_on(Store::boot(part, words)).expect("the part answers")
    }

    fn secret(printed: u8) -> Secret {
        Secret::new([1; 16], [printed; 32]).expect("entropy")
    }

    fn birth(key: u8, seed: u8) -> Birth {
        Birth {
            controller: ControllerKey::new([key; 32]).expect("entropy"),
            drbg: DrbgState::new([seed; 32]).expect("entropy"),
        }
    }

    /// A unit through its first manufacturing transaction and the boot that
    /// applies it.
    fn manufactured() -> (Part, Store) {
        let mut part = Part::fresh();
        block_on(stage_secret(&mut part, secret(2), Some(birth(7, 9)), false)).expect("stage");
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.secret_recovery, SecretRecovery::Applied);
        (part, store)
    }

    fn enrolled(store: &mut Store, part: &mut Part, n: u32) -> Generation {
        let under = *store.epoch.present().expect("an epoch");
        block_on(store.clients.enrol(
            id(n),
            Enrolment {
                client: PublicKey::from_bytes([u8::try_from(n).expect("small"); 32]),
                admit: [3; 32],
                suite: Suite::X25519ChachapolySha256,
                kind: ClientKind::App,
                label: ClientLabel::new("phone").expect("fits"),
            },
            under,
            part,
        ))
        .expect("the slot lands")
    }

    /// The host printed the label and says so.
    fn acknowledge(part: &mut Part) {
        let mut change = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
            map::SECRET_CHANGE,
            part,
        ))
        .expect("reads");
        block_on(change.write(part, SecretChange::Complete)).expect("acknowledged");
    }

    /// Flip a body byte in both copies of a record.
    fn damage<const N: usize>(part: &mut Part, record: crate::fram::Record<N>) {
        let start = usize::from(record.end().0).saturating_sub(slot_bytes(N).saturating_mul(2));
        part.bytes[start.saturating_add(8)] ^= 1;
        part.bytes[start.saturating_add(slot_bytes(N)).saturating_add(8)] ^= 1;
    }

    fn opens(report: &BootReport<()>) -> bool {
        crate::Panel::at_power_on(crate::Revision::A, report.enrolment, Tick::ZERO)
            .pairing_open(Tick::ZERO)
    }

    #[test]
    fn f_091_p_066_boot_repair_does_not_turn_absence_or_corruption_into_empty_evidence() {
        let mut part = Part::fresh();
        let (_, first) = boot(&mut part, None);
        assert_eq!(first.clients, Some(Ok(Repaired::Initialised)));
        assert_eq!(first.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert!(!opens(&first));
        let (mut store, second) = boot(&mut part, None);
        assert_eq!(second.enrolment, crate::EnrolmentAtBoot::Empty);
        assert!(opens(&second));
        let _ = enrolled(&mut store, &mut part, 2);
        let (_, third) = boot(&mut part, None);
        assert_eq!(third.enrolment, crate::EnrolmentAtBoot::Enrolled);
        assert!(!opens(&third));
        // A slot with no copy that reads is freed, and the boot that freed
        // it is not evidence of an empty table.
        damage(&mut part, map::CLIENT_KEYS[1]);
        let (store, repair) = boot(&mut part, None);
        assert_eq!(repair.clients, Some(Ok(Repaired::Freed)));
        assert_eq!(repair.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert_eq!(store.clients.enrolled(Epoch::FIRST), 0);
        assert!(!opens(&repair));
        let (_, next) = boot(&mut part, None);
        assert_eq!(next.enrolment, crate::EnrolmentAtBoot::Empty);
        assert!(opens(&next));
    }

    #[test]
    fn f_091_p_239_an_unreadable_mark_rebuilds_under_a_new_epoch_and_stays_closed_once() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        damage(&mut part, map::GENERATION_MARKS[0]);
        let (store, repair) = boot(&mut part, None);
        assert_eq!(repair.clients, Some(Ok(Repaired::Rebuilt(epoch(2)))));
        assert_eq!(
            repair.epoch,
            EpochAtBoot::Advanced {
                from: Epoch::FIRST,
                to: epoch(2)
            }
        );
        assert_eq!(store.epoch.present(), Some(&epoch(2)));
        assert_eq!(store.clients.enrolled(epoch(2)), 0);
        assert!(!opens(&repair));
        let (_, next) = boot(&mut part, None);
        assert_eq!(next.epoch, EpochAtBoot::Held(epoch(2)));
        assert!(opens(&next));
    }

    #[test]
    fn p_239_a_repair_cut_after_its_epoch_landed_reports_the_epoch_the_part_holds() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        damage(&mut part, map::GENERATION_MARKS[0]);
        let mut unfinished = 0;
        for cut in 0..PART_BYTES {
            let mut cut_part = part.cut_before(cut);
            let (store, report) = boot(&mut cut_part, None);
            if !matches!(report.clients, Some(Err(Unrepaired::Write(_)))) {
                continue;
            }
            if store.epoch.present() != Some(&epoch(2)) {
                continue;
            }
            unfinished += 1;
            assert_eq!(
                report.epoch.epoch(),
                Some(epoch(2)),
                "cut before byte {cut}"
            );
            assert_eq!(store.clients.enrolled(epoch(2)), 0, "cut before byte {cut}");
            assert!(!opens(&report), "cut before byte {cut}");
        }
        assert!(
            unfinished > 0,
            "no cut left the epoch advanced and the repair unfinished"
        );
    }

    #[test]
    fn f_091_p_066_empty_table_requires_a_usable_epoch_to_open() {
        for damaged in [false, true] {
            let mut part = Part::fresh();
            let _ = boot(&mut part, None);
            if damaged {
                let _second = block_on(map::EPOCH.write(
                    &mut part,
                    Position::At {
                        seq: 1,
                        slot: crate::fram::Slot::A,
                    },
                    &Epoch::FIRST.encode(),
                ))
                .unwrap();
                part.bytes[8] ^= 1;
                part.bytes[slot_bytes(EPOCH_BYTES) + 8] ^= 1;
            }
            let (_, report) = boot(&mut part, None);
            assert_eq!(report.epoch.epoch().is_some(), !damaged);
            assert_eq!(report.clients.is_some(), !damaged);
            assert_eq!(opens(&report), !damaged);
        }
    }

    #[test]
    fn f_026_p_085_a_reset_cut_after_its_epoch_leaves_a_valid_empty_table() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        let late = Tick::from_millis(1);
        let _ = block_on(store.clients.commands_mut().update(&mut part, |table| {
            table
                .dedup_mut()
                .admit(id(1), 7, Fingerprint::of(b"start"), late)
        }))
        .expect("lands");
        // The reset moves the epoch and the power goes before the slots.
        let _ = block_on(store.epoch.advance(&mut part)).expect("advances");
        // A boot on a falling supply cannot clear the dedup table under the
        // new epoch: no evidence, no window.
        part.falling = true;
        let (_, refused) = boot(&mut part, None);
        assert_eq!(refused.epoch.epoch(), Some(epoch(2)));
        assert!(matches!(refused.clients, Some(Err(Unrepaired::Write(_)))));
        assert_eq!(refused.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert!(!opens(&refused));
        part.falling = false;
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::Held(epoch(2)));
        assert_eq!(report.clients, Some(Ok(Repaired::Nothing)));
        // The slot under epoch 1 is free under epoch 2: a valid empty table.
        assert_eq!(store.clients.enrolled(epoch(2)), 0);
        assert_eq!(report.enrolment, crate::EnrolmentAtBoot::Empty);
        assert!(opens(&report));
        let commands = store.clients.commands().present().expect("held");
        assert_eq!(commands.epoch(), epoch(2));
        assert!(!commands.dedup().holds(id(1)));
    }

    #[test]
    fn f_091_p_066_empty_table_with_refused_epoch_initialisation_stays_closed() {
        let mut part = Part::fresh();
        let _ = boot(&mut part, None);
        part.bytes[..usize::from(map::EPOCH.end().0)].fill(0);
        part.falling = true;
        let (_, report) = boot(&mut part, None);
        assert_eq!(report.epoch.epoch(), None);
        assert_eq!(report.clients, None);
        assert_eq!(report.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert!(!opens(&report));
    }

    #[test]
    fn p_235_p_237_the_first_transaction_writes_the_key_and_the_generator_once() {
        let (part, store) = manufactured();
        assert!(store.secret.present() == Some(&secret(2)));
        assert_eq!(store.controller.present(), Some(&birth(7, 9).controller));
        assert_eq!(store.drbg.present(), Some(&birth(7, 9).drbg));
        // Applied carries the fingerprint of the key the part holds, and no
        // copy of the key or the state is left in the transaction.
        let mut part = part;
        let change = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
            map::SECRET_CHANGE,
            &mut part,
        ))
        .expect("reads");
        let Some(SecretChange::Applied(held, fingerprint)) = change.present() else {
            panic!("applied");
        };
        assert!(*held == secret(2));
        assert!(fingerprint.vouches_for(&birth(7, 9).controller.public()));
        let region = &part.bytes[usize::from(crate::map::SECRET_CHANGE_START.0)..];
        assert!(!region.windows(32).any(|window| window == [7; 32]));
        assert!(!region.windows(32).any(|window| window == [9; 32]));
        // A second boot changes nothing.
        let (again, report) = boot(&mut part, None);
        assert_eq!(report.secret_recovery, SecretRecovery::Unchanged);
        assert_eq!(again.drbg.present(), Some(&birth(7, 9).drbg));
    }

    #[test]
    fn p_235_p_237_a_born_unit_refuses_a_second_birth_and_an_unborn_one_needs_one() {
        let (mut part, _) = manufactured();
        acknowledge(&mut part);
        assert_eq!(
            block_on(stage_secret(&mut part, secret(3), Some(birth(8, 8)), true)),
            Err(ProvisionFailed::AlreadyBorn)
        );
        let mut unborn = Part::fresh();
        assert_eq!(
            block_on(stage_secret(&mut unborn, secret(3), None, false)),
            Err(ProvisionFailed::Unborn)
        );
        // A damaged key record is a key that was there: never written over.
        let mut damaged = Part::fresh();
        let mut key = block_on(Kept::<ControllerKey, CONTROLLER_KEY_BYTES>::read(
            map::CONTROLLER_KEY,
            &mut damaged,
        ))
        .expect("reads");
        block_on(key.write(&mut damaged, birth(4, 4).controller)).expect("lands");
        block_on(key.write(&mut damaged, birth(5, 5).controller)).expect("lands");
        damage(&mut damaged, map::CONTROLLER_KEY);
        assert_eq!(
            block_on(stage_secret(
                &mut damaged,
                secret(3),
                Some(birth(8, 8)),
                false
            )),
            Err(ProvisionFailed::AlreadyBorn)
        );
        // So is a generator record without a key beside it.
        let mut state_only = Part::fresh();
        let mut drbg = block_on(Kept::<DrbgState, DRBG_BYTES>::read(
            map::DRBG,
            &mut state_only,
        ))
        .expect("reads");
        block_on(drbg.write(&mut state_only, birth(1, 6).drbg)).expect("lands");
        assert_eq!(
            block_on(stage_secret(
                &mut state_only,
                secret(3),
                Some(birth(8, 8)),
                false
            )),
            Err(ProvisionFailed::AlreadyBorn)
        );
    }

    #[test]
    fn p_235_a_part_with_a_damaged_generator_and_no_key_cannot_stage_a_label() {
        let mut part = Part::fresh();
        let mut drbg =
            block_on(Kept::<DrbgState, DRBG_BYTES>::read(map::DRBG, &mut part)).expect("reads");
        block_on(drbg.write(&mut part, birth(1, 6).drbg)).expect("lands");
        block_on(drbg.write(&mut part, birth(1, 5).drbg)).expect("lands");
        damage(&mut part, map::DRBG);
        let before = part.bytes;
        // No key to fingerprint: a label alone is refused.
        assert_eq!(
            block_on(stage_secret(&mut part, secret(3), None, false)),
            Err(ProvisionFailed::Unborn)
        );
        // And the damaged state is never written over by a birth.
        assert_eq!(
            block_on(stage_secret(&mut part, secret(3), Some(birth(8, 8)), false)),
            Err(ProvisionFailed::AlreadyBorn)
        );
        assert_eq!(part.bytes, before);
    }

    #[test]
    fn p_235_an_unappliable_intent_is_discarded_and_the_boot_goes_on() {
        for damaged_key in [false, true] {
            let mut part = Part::fresh();
            if damaged_key {
                let mut key = block_on(Kept::<ControllerKey, CONTROLLER_KEY_BYTES>::read(
                    map::CONTROLLER_KEY,
                    &mut part,
                ))
                .expect("reads");
                block_on(key.write(&mut part, birth(4, 4).controller)).expect("lands");
                block_on(key.write(&mut part, birth(5, 5).controller)).expect("lands");
                damage(&mut part, map::CONTROLLER_KEY);
            }
            // An intent `stage_secret` refuses, left by a bench that went
            // around it: a label with no key, or a birth onto a damaged key.
            let intent = if damaged_key {
                SecretChange::Pending(secret(3), Some(birth(8, 8)))
            } else {
                SecretChange::Pending(secret(3), None)
            };
            let mut change = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
                map::SECRET_CHANGE,
                &mut part,
            ))
            .expect("reads");
            block_on(change.write(&mut part, intent)).expect("lands");
            let (store, report) = boot(&mut part, None);
            assert_eq!(report.secret_recovery, SecretRecovery::Discarded);
            // Nothing of it applied: all or nothing.
            assert!(matches!(store.secret.held(), Held::Absent));
            assert!(matches!(store.drbg.held(), Held::Absent));
            assert!(store.controller.present().is_none());
            let (_, again) = boot(&mut part, None);
            assert_eq!(again.secret_recovery, SecretRecovery::Unchanged);
        }
    }

    #[test]
    fn f_041_p_237_boot_never_writes_over_a_generator_or_a_key_the_part_holds() {
        let (mut part, mut store) = manufactured();
        // The generator moved on since manufacture.
        let advanced = DrbgState::new([0x42; 32]).expect("entropy");
        block_on(store.drbg.write(&mut part, advanced)).expect("lands");
        // A transaction carrying a birth, written past `stage_secret`'s
        // refusal, as a torn or hostile bench could leave it.
        let mut change = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
            map::SECRET_CHANGE,
            &mut part,
        ))
        .expect("reads");
        block_on(change.write(
            &mut part,
            SecretChange::Pending(secret(3), Some(birth(8, 8))),
        ))
        .expect("lands");
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.secret_recovery, SecretRecovery::Applied);
        assert!(store.secret.present() == Some(&secret(3)));
        assert_eq!(store.drbg.present(), Some(&advanced));
        assert_eq!(store.controller.present(), Some(&birth(7, 9).controller));
    }

    #[test]
    fn p_235_p_237_manufacture_cut_at_every_byte_applies_everything_or_nothing_usable() {
        let mut start = Part::fresh();
        block_on(stage_secret(
            &mut start,
            secret(2),
            Some(birth(7, 9)),
            false,
        ))
        .expect("stage");
        let mut landed_at = None;
        for at in 0..4096 {
            let mut cut = start.cut_before(at);
            let outcome = block_on(Store::boot(&mut cut, None));
            if let Ok((store, report)) = &outcome
                && report.secret_recovery == SecretRecovery::Applied
            {
                assert_eq!(store.controller.present(), Some(&birth(7, 9).controller));
                assert_eq!(store.drbg.present(), Some(&birth(7, 9).drbg));
                landed_at = Some(at);
                break;
            }
            // A cut boot exposes no key it did not finish; the next boot on
            // the same bytes finishes the transaction.
            assert!(outcome.is_err(), "a boot cut at {at} returned a store");
            let mut after = cut.rebooted();
            let (store, report) = boot(&mut after, None);
            // Applied, or already applied by the cut boot, which was cut
            // scrubbing the transaction behind it.
            assert!(
                matches!(
                    report.secret_recovery,
                    SecretRecovery::Applied | SecretRecovery::Unchanged
                ),
                "cut at {at}"
            );
            assert!(store.secret.present() == Some(&secret(2)));
            assert_eq!(store.controller.present(), Some(&birth(7, 9).controller));
            assert_eq!(store.drbg.present(), Some(&birth(7, 9).drbg));
        }
        assert!(landed_at.is_some_and(|at| at > 100), "{landed_at:?}");
    }

    #[test]
    fn p_235_secret_replacement_requires_a_new_secret_and_explicit_replacement() {
        let (mut part, store) = manufactured();
        assert!(store.secret.present() == Some(&secret(2)));
        // The label is acknowledged before another transaction.
        assert_eq!(
            block_on(stage_secret(&mut part, secret(3), None, true)),
            Err(ProvisionFailed::Pending)
        );
        acknowledge(&mut part);
        assert_eq!(
            block_on(stage_secret(&mut part, secret(2), None, true)),
            Err(ProvisionFailed::SameSecret)
        );
        assert_eq!(
            block_on(stage_secret(&mut part, secret(3), None, false)),
            Err(ProvisionFailed::AlreadyProvisioned)
        );
        block_on(stage_secret(&mut part, secret(3), None, true)).expect("stage");
        assert_eq!(
            block_on(stage_secret(&mut part, secret(4), None, true)),
            Err(ProvisionFailed::Pending)
        );
        // Staging leaves the active secret; the boot applies the new one and
        // keeps the key the unit was born with.
        let current = block_on(Kept::<Secret, SECRET_BYTES>::read(
            map::DEVICE_SECRET,
            &mut part,
        ))
        .expect("read");
        assert!(current.present() == Some(&secret(2)));
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.secret_recovery, SecretRecovery::Applied);
        assert!(store.secret.present() == Some(&secret(3)));
        assert_eq!(store.controller.present(), Some(&birth(7, 9).controller));
    }

    #[test]
    fn p_235_garbage_secret_intent_is_discarded_without_changing_what_the_unit_holds() {
        for malformed in [false, true] {
            let (mut part, _) = manufactured();
            let start = usize::from(map::LOAD_SHED_CONFIG.end().0);
            part.bytes[start..].fill(0x55);
            if malformed {
                let mut bad = [0; SECRET_CHANGE_BYTES];
                bad[0] = 2;
                let _ = block_on(map::SECRET_CHANGE.write(&mut part, Position::Start, &bad))
                    .expect("malformed intent");
            }
            let (store, report) = boot(&mut part, None);
            assert_eq!(report.secret_recovery, SecretRecovery::Discarded);
            assert!(store.secret.present() == Some(&secret(2)));
            assert_eq!(store.drbg.present(), Some(&birth(7, 9).drbg));
            assert!(part.bytes[start..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn p_235_a_refused_recovery_exposes_no_store_and_retries_at_boot() {
        let mut part = Part::fresh();
        block_on(stage_secret(&mut part, secret(2), Some(birth(7, 9)), false)).expect("stage");
        part.falling = true;
        assert!(matches!(
            block_on(Store::boot(&mut part, None)),
            Err(ProvisionFailed::Write(Refused::SupplyFalling))
        ));
        part.falling = false;
        let (store, _) = boot(&mut part, None);
        assert!(store.secret.present() == Some(&secret(2)));
        assert_eq!(store.drbg.present(), Some(&birth(7, 9).drbg));
    }

    #[test]
    fn p_085_a_first_boot_writes_epoch_one_and_initialises_the_table_under_it() {
        let mut part = Part::fresh();
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::First);
        assert_eq!(report.epoch.epoch(), Some(Epoch::FIRST));
        assert_eq!(report.clients, Some(Ok(Repaired::Initialised)));
        assert_eq!(report.boot, BootCount::FIRST);
        assert_eq!(report.boot_recorded, Ok(()));
        assert_eq!(report.panic_recorded, None);
        assert_eq!(store.epoch.present(), Some(&Epoch::FIRST));
        assert_eq!(store.clients.enrolled(Epoch::FIRST), 0);
        assert!(matches!(store.secret.held(), Held::Absent));
        assert!(matches!(store.controller.held(), Held::Absent));
        assert!(matches!(store.drbg.held(), Held::Absent));
        assert_eq!(store.run.held(), &Held::Absent);
        assert_eq!(store.release.held(), &Held::Absent);
        assert_eq!(store.network.held(), &Held::Absent);
        assert_eq!(store.volume.held(), &Held::Absent);
        // The second boot is not the first.
        let (_, again) = boot(&mut part, None);
        assert_eq!(again.epoch, EpochAtBoot::Held(Epoch::FIRST));
        assert_eq!(again.clients, Some(Ok(Repaired::Nothing)));
        assert_eq!(again.boot, BootCount::FIRST.next());
    }

    #[test]
    fn p_085_a_boot_with_no_readable_epoch_has_none_and_leaves_the_table_alone() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        // Both epoch slots damaged: slot A at 0, slot B at 16, bodies 8 in.
        let _two = block_on(map::EPOCH.write(
            &mut part,
            Position::At {
                seq: 1,
                slot: crate::fram::Slot::A,
            },
            &epoch(2).encode(),
        ));
        part.bytes[8] ^= 0x01;
        part.bytes[16 + 8] ^= 0x01;
        let before = part.bytes;
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::None(NoEpoch::Corrupt));
        assert_eq!(report.epoch.epoch(), None);
        assert_eq!(report.clients, None);
        // The slot is still there, and nothing can enrol or bind under it
        // until a person writes an epoch.
        assert_eq!(store.clients.enrolled(Epoch::FIRST), 1);
        let table = usize::from(map::NETWORK.end().0)..usize::from(map::COMMANDS.end().0);
        assert_eq!(part.bytes[table.clone()], before[table]);
        // A zero written raw is malformed, and no epoch either.
        let mut zero = Part::fresh();
        let _ = block_on(map::EPOCH.write(&mut zero, Position::Start, &[0; 4]));
        let (_, report) = boot(&mut zero, None);
        assert_eq!(
            report.epoch,
            EpochAtBoot::None(NoEpoch::Malformed(Malformed { at: 0 }))
        );
    }

    #[test]
    fn f_026_a_boot_raises_a_record_behind_a_slots_epoch_and_enrols_nothing_if_it_cannot() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = block_on(store.epoch.advance(&mut part)).expect("the supply is fine");
        let generation = enrolled(&mut store, &mut part, 3);
        // The record regresses under somebody's hand: the public write.
        block_on(store.epoch.write(&mut part, Epoch::FIRST)).expect("the supply is fine");
        let (store, report) = boot(&mut part, None);
        assert_eq!(
            report.epoch,
            EpochAtBoot::Raised {
                from: Epoch::FIRST,
                to: epoch(2)
            }
        );
        assert_eq!(report.clients, Some(Ok(Repaired::Nothing)));
        assert_eq!(store.epoch.present(), Some(&epoch(2)));
        let occupant = store
            .clients
            .occupant(id(3), epoch(2))
            .expect("still enrolled");
        assert_eq!(occupant.generation(), generation);
        // And when the raise will not land, nothing is enrolled under the
        // lower record and nothing is repaired: the slot waits.
        let mut store = store;
        block_on(store.epoch.write(&mut part, Epoch::FIRST)).expect("the supply is fine");
        part.falling = true;
        let (store, report) = boot(&mut part, None);
        assert_eq!(
            report.epoch,
            EpochAtBoot::None(NoEpoch::Regressed {
                record: Epoch::FIRST,
                table: epoch(2),
                refused: Refused::SupplyFalling,
            })
        );
        assert_eq!(report.clients, None);
        assert_eq!(store.clients.enrolled(epoch(2)), 1);
        assert_eq!(store.epoch.present(), Some(&Epoch::FIRST));
        assert!(matches!(
            store.clients.key(id(3)).and_then(|key| key.present()),
            Some(KeyRecord::Occupied(_))
        ));
    }

    #[test]
    fn p_121_a_boot_with_no_epoch_still_restarts_the_dedup_windows_at_tick_zero() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        let late = Tick::from_millis(500_000);
        let _ = block_on(store.clients.commands_mut().update(&mut part, |table| {
            table
                .dedup_mut()
                .admit(id(1), 7, Fingerprint::of(b"start"), late)
        }))
        .expect("the supply is fine");
        // Both epoch slots damaged: this boot has no epoch.
        let _two = block_on(map::EPOCH.write(
            &mut part,
            Position::At {
                seq: 1,
                slot: crate::fram::Slot::A,
            },
            &epoch(2).encode(),
        ));
        part.bytes[8] ^= 0x01;
        part.bytes[16 + 8] ^= 0x01;
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::None(NoEpoch::Corrupt));
        assert_eq!(report.clients, None);
        // The entry lives ten minutes from this boot, not from the tick it
        // was inserted at in the last one.
        let dedup = store.clients.commands().present().expect("held").dedup();
        assert_eq!(dedup.live(Tick::from_millis(599_999)), 1);
        assert_eq!(dedup.live(Tick::from_millis(600_000)), 0);
    }

    #[test]
    fn f_008_the_boot_that_finds_last_words_records_them_with_its_boot_count() {
        let mut part = Part::fresh();
        let (_, first) = boot(&mut part, None);
        assert_eq!(first.panic_recorded, None);
        let words = LastWords::Panicked(PanicSite {
            file: 0xDEAD_BEEF,
            line: 42,
        });
        let (store, second) = boot(&mut part, Some(words));
        assert_eq!(second.boot, BootCount::FIRST.next());
        assert_eq!(second.panic_recorded, Some(PanicRecorded::Landed));
        assert_eq!(
            store.panics.present(),
            Some(&PanicRecord { boot: 2, words })
        );
        // The record stays until the next panic.
        let (store, third) = boot(&mut part, None);
        assert_eq!(third.panic_recorded, None);
        assert_eq!(store.panics.present().map(|r| r.boot), Some(2));
    }

    #[test]
    fn f_017_a_boot_reads_the_ladders_cuts_and_carries_them_from_its_own_start() {
        let mut part = Part::fresh();
        let (mut store, report) = boot(&mut part, None);
        assert_eq!(store.cuts.held(), &Held::Absent);
        assert_eq!(
            CutsRecord::carried(store.cuts.held(), report.boot),
            crate::CarriedCuts {
                cuts: crate::RecentCuts::NONE,
                missed: 0
            },
            "a fresh unit has made no cut"
        );
        let seq = crate::RailSequencer::new(crate::Revision::B);
        let crate::Plan::Cut(cut) = seq.plan_recovery(Tick::from_millis(90_000)) else {
            panic!("a cut");
        };
        let kept = cut.cuts();
        let record = CutsRecord {
            boot: store.boots.present().copied(),
            cuts: kept,
        };
        block_on(store.cuts.write(&mut part, record)).expect("the supply is fine");
        let (store, report) = boot(&mut part, None);
        let carried = CutsRecord::carried(store.cuts.held(), report.boot);
        assert_eq!(carried.missed, 0, "written at the boot before this one");
        assert_eq!(carried.cuts.count(), 1);
        assert_eq!(
            carried.cuts,
            kept.rebased(),
            "moved to this boot's tick zero"
        );
    }

    #[test]
    fn p_121_the_release_and_the_dedup_table_are_rebased_at_boot() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = enrolled(&mut store, &mut part, 1);
        let late = Tick::from_millis(500_000);
        let _ = block_on(store.clients.commands_mut().update(&mut part, |table| {
            table
                .dedup_mut()
                .admit(id(1), 7, Fingerprint::of(b"start"), late)
        }))
        .expect("the supply is fine");
        block_on(store.release.write(
            &mut part,
            CommsRelease::Authorised(Release {
                version: Text::new("1.0").expect("fits"),
                image_len: 1,
                digest: Digest([9; 32]),
                authorised_at: late,
            }),
        ))
        .expect("the supply is fine");
        let (store, _) = boot(&mut part, None);
        let dedup = store.clients.commands().present().expect("held").dedup();
        assert_eq!(dedup.live(Tick::from_millis(599_999)), 1);
        assert_eq!(dedup.live(Tick::from_millis(600_000)), 0);
        let release = store.release.present().expect("a release");
        assert!(release.admits(&Digest([9; 32]), Tick::from_millis(599_999)));
        assert!(!release.admits(&Digest([9; 32]), Tick::from_millis(600_000)));
    }

    #[test]
    fn a_boot_whose_last_read_fails_writes_nothing_and_the_next_one_counts_once() {
        let mut part = Part::fresh();
        // The last section's B-prefix CRC is the last read of a record.
        // Every earlier record has been read when this transaction fails.
        let last_read = usize::from(map::LOAD_SHED_CONFIG.end().0) - slot_bytes(1024)
            + slot_bytes(crate::BEHAVIOUR_RECORD_BYTES)
            - 1;
        part.refuse_reads_at = Some(u16::try_from(last_read).expect("inside FRAM"));
        let outcome = block_on(Store::boot(
            &mut part,
            Some(LastWords::Panicked(PanicSite { file: 1, line: 2 })),
        ));
        assert!(outcome.is_err());
        // Nothing landed: no epoch, no count, no panic record, no mark.
        assert_eq!(
            block_on(map::EPOCH.read(&mut part)),
            Ok(crate::fram::Current::Empty)
        );
        assert_eq!(
            block_on(map::BOOT_COUNT.read(&mut part)),
            Ok(crate::fram::Current::Empty)
        );
        assert_eq!(
            block_on(map::PANIC_RECORD.read(&mut part)),
            Ok(crate::fram::Current::Empty)
        );
        assert_eq!(
            block_on(map::GENERATION_MARKS[0].read(&mut part)),
            Ok(crate::fram::Current::Empty)
        );
        // Tried again with the bus back, it is the first boot, once.
        part.refuse_reads_at = None;
        let (store, report) = boot(
            &mut part,
            Some(LastWords::Panicked(PanicSite { file: 1, line: 2 })),
        );
        assert_eq!(report.epoch, EpochAtBoot::First);
        assert_eq!(report.boot, BootCount::FIRST);
        assert_eq!(store.panics.present().map(|r| r.boot), Some(1));
    }

    #[test]
    fn a_boot_on_a_falling_supply_reads_everything_and_reports_every_write_it_could_not_make() {
        let mut part = Part::fresh();
        part.falling = true;
        let words = LastWords::Panicked(PanicSite { file: 1, line: 2 });
        let (store, report) = boot(&mut part, Some(words));
        assert_eq!(
            report.epoch,
            EpochAtBoot::None(NoEpoch::Refused(Refused::SupplyFalling))
        );
        assert_eq!(report.clients, None);
        assert_eq!(report.boot, BootCount::FIRST);
        assert_eq!(report.boot_recorded, Err(Refused::SupplyFalling));
        // Not even attempted: a record under a count the part does not
        // hold would name a boot that never was.
        assert_eq!(
            report.panic_recorded,
            Some(PanicRecorded::WithoutABootCount)
        );
        assert_eq!(store.epoch.held(), &Held::Absent);
        assert_eq!(store.boots.held(), &Held::Absent);
        assert_eq!(store.panics.held(), &Held::Absent);
        // With the supply back, the same boot lands everything.
        part.falling = false;
        let (_, report) = boot(&mut part, Some(words));
        assert_eq!(report.epoch, EpochAtBoot::First);
        assert_eq!(report.boot_recorded, Ok(()));
        assert_eq!(report.panic_recorded, Some(PanicRecorded::Landed));
    }
}
