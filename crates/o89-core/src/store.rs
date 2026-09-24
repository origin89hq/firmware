//! Every record the controller keeps, read in the boot's order, with the
//! rules that tie one record to another applied where both are in hand.
//!
//! A boot reads the part once and holds what it read: the epoch, the
//! client table, the counters, the run reason, the panic record and the
//! rest, each as a [`Kept`] whose RAM copy moves only when the part has
//! moved. Four things happen on the way: a fresh unit gets its first
//! epoch; an epoch record behind the table's stamp is raised to it,
//! because the stamp is a second copy of a counter that only climbs and
//! the higher copy is the counter; a table under an earlier epoch than
//! the record is cleared, finishing a reset that was cut (F-026); the boot
//! count climbs and the last words, if a run left any, are written down
//! with it. Everything that measures a window on the tick is restarted at
//! this boot's tick zero (P-121), the recovery ladder's recent cuts
//! included (F-017).
//!
//! A boot that cannot read the part returns the bus error and nothing
//! else: there is no partial store to hold, and nothing was written, so a
//! boot tried again on the same part counts once. A write the boot could
//! not make is in the report, so the caller raises what it owes. A pending
//! bench secret replacement is completed after all reads and before these
//! ordinary boot writes; a failed recovery write returns no store and therefore
//! no session keys (F-041). Unreadable intent is discarded without changing keys.
//!
//! cites: P-085, P-121, F-026

use km43::Epoch;

use crate::body::{Held, Kept, Malformed};
use crate::boot_count::{BOOT_COUNT_BYTES, BootCount};
use crate::challenge::{CHALLENGE_COUNTER_BYTES, ChallengeCounter};
use crate::clients::{Booted, CLIENT_TABLE_BYTES, ClientTable};
use crate::epoch::EPOCH_BYTES;
use crate::fram::{Fram, Refused};
use crate::last_words::LastWords;
use crate::map;
use crate::network::{NETWORK_BYTES, Network};
use crate::panic_record::{PANIC_RECORD_BYTES, PanicRecord};
use crate::rail::{CUTS_RECORD_BYTES, CutsRecord};
use crate::release::{COMMS_RELEASE_BYTES, CommsRelease};
use crate::run_reason::{RUN_REASON_BYTES, RunReason};
use crate::secret::{SECRET_BYTES, Secret};
use crate::write_volume::{WRITE_VOLUME_BYTES, WriteVolume};

/// What the controller keeps on the part, as this boot read it.
pub struct Store {
    /// Versioned identity and behaviour sections.
    pub configuration: crate::Configuration,
    /// The device secret every key derives from.
    pub secret: Kept<Secret, SECRET_BYTES>,
    /// The epoch (P-085).
    pub epoch: Kept<Epoch, EPOCH_BYTES>,
    /// The client table, its counters and the dedup table.
    pub clients: Kept<ClientTable, CLIENT_TABLE_BYTES>,
    /// Why the generator is running.
    pub run: Kept<RunReason, RUN_REASON_BYTES>,
    /// What the last run to panic said, and at which boot.
    pub panics: Kept<PanicRecord, PANIC_RECORD_BYTES>,
    /// How many times this unit has booted.
    pub boots: Kept<BootCount, BOOT_COUNT_BYTES>,
    /// The challenge counter.
    pub challenges: Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES>,
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
    /// The record is behind the table's stamp and raising it would not
    /// land. Deriving under the record would mint keys the move to the
    /// table's epoch was made to invalidate, so nothing derives.
    Regressed {
        /// What the record holds.
        record: Epoch,
        /// What the table is under.
        table: Epoch,
        /// Why the raise did not land.
        refused: Refused<E>,
    },
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
    /// The record was behind the table's stamp and was raised to it.
    Raised {
        /// What the record held.
        from: Epoch,
        /// What it holds now, which is what the table is under.
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
            Self::Held(epoch) | Self::Raised { to: epoch, .. } => Some(*epoch),
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
    /// What became of the client table, or nothing because there was no
    /// epoch to take it under.
    pub clients: Option<Result<Booted, Refused<E>>>,
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
        let mut epoch = Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, fram).await?;
        let mut clients =
            Kept::<ClientTable, CLIENT_TABLE_BYTES>::read(map::CLIENT_TABLE, fram).await?;
        let run = Kept::<RunReason, RUN_REASON_BYTES>::read(map::RUN_REASON, fram).await?;
        let mut boots = Kept::<BootCount, BOOT_COUNT_BYTES>::read(map::BOOT_COUNT, fram).await?;
        let mut panics =
            Kept::<PanicRecord, PANIC_RECORD_BYTES>::read(map::PANIC_RECORD, fram).await?;
        let mut challenges =
            Kept::<ChallengeCounter, CHALLENGE_COUNTER_BYTES>::read(map::CHALLENGE_COUNTER, fram)
                .await?;
        let volume = Kept::<WriteVolume, WRITE_VOLUME_BYTES>::read(map::WRITE_VOLUME, fram).await?;
        let mut release =
            Kept::<CommsRelease, COMMS_RELEASE_BYTES>::read(map::COMMS_RELEASE, fram).await?;
        let network = Kept::<Network, NETWORK_BYTES>::read(map::NETWORK, fram).await?;
        let mut cuts = Kept::<CutsRecord, CUTS_RECORD_BYTES>::read(map::RECENT_CUTS, fram).await?;

        let configuration = crate::Configuration::read(fram).await?;
        let secret_recovery = crate::provision::finish(fram, &mut secret, &mut challenges).await?;

        let mut at_boot = match *epoch.held() {
            Held::Present(held) => EpochAtBoot::Held(held),
            Held::Absent => match epoch.write(fram, Epoch::FIRST).await {
                Ok(()) => EpochAtBoot::First,
                Err(refused) => EpochAtBoot::None(NoEpoch::Refused(refused)),
            },
            Held::Corrupt => EpochAtBoot::None(NoEpoch::Corrupt),
            Held::Malformed(malformed) => EpochAtBoot::None(NoEpoch::Malformed(malformed)),
        };
        // The stamp is a second copy of the epoch: a record behind it is
        // raised to it, and never the other way round.
        if let (Some(record), Some(table)) =
            (at_boot.epoch(), clients.present().map(ClientTable::epoch))
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
        let (enrolment, clients_booted) = boot_clients(&mut clients, fram, at_boot.epoch()).await;

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
                epoch,
                clients,
                run,
                panics,
                boots,
                challenges,
                volume,
                release,
                network,
                cuts,
            },
            report,
        ))
    }
}

/// Capture pre-repair evidence, requiring a usable epoch and successful boot repair.
async fn boot_clients<F: Fram>(
    clients: &mut Kept<ClientTable, CLIENT_TABLE_BYTES>,
    fram: &mut F,
    epoch: Option<Epoch>,
) -> (
    crate::EnrolmentAtBoot,
    Option<Result<Booted, Refused<F::Error>>>,
) {
    if let Some(under) = epoch {
        let enrolment = crate::EnrolmentAtBoot::from_clients(clients.held());
        let booted = clients.booted(fram, under).await;
        let enrolment = if booted.is_ok() {
            enrolment
        } else {
            crate::EnrolmentAtBoot::Unavailable
        };
        (enrolment, Some(booted))
    } else {
        // No epoch means no enrolment; restart table windows at tick zero
        // in RAM only (P-121), without advertising an unusable window.
        if let Some(held) = clients.present() {
            let rebased = held.clone().rebased();
            clients.rebase(rebased);
        }
        (crate::EnrolmentAtBoot::Unavailable, None)
    }
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
    use km43::{ClientKind, Counter};

    use super::*;
    use crate::body::Body as _;
    use crate::clients::{Because, Label, Paired};
    use crate::dedup::Fingerprint;
    use crate::fram::{Address, FRAM_BYTES, Position};
    use crate::last_words::PanicSite;
    use crate::release::{Digest, Release};
    use crate::text::Text;
    use crate::tick::Tick;

    /// Enough of the part for every record the boot reads.
    const PART_BYTES: usize = map::END.0 as usize;
    const _: () = assert!(map::RECENT_CUTS.end().0 as usize <= PART_BYTES);
    const _: () = assert!(PART_BYTES <= FRAM_BYTES);

    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        /// An address a read touching it is refused at, for a bus that
        /// fails partway through a boot.
        refuse_reads_at: Option<u16>,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0; PART_BYTES],
                falling: false,
                refuse_reads_at: None,
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
            let outcome = if self.falling {
                Err(Refused::SupplyFalling)
            } else {
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    fn boot(part: &mut Part, words: Option<LastWords>) -> (Store, BootReport<()>) {
        block_on(Store::boot(part, words)).expect("the part answers")
    }

    #[test]
    fn f_091_p_066_boot_repair_does_not_turn_absence_or_corruption_into_empty_evidence() {
        let mut part = Part::fresh();
        let (mut store, report) = boot(&mut part, None);
        assert_eq!(report.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert_eq!(store.clients.present().unwrap().enrolled(), 0);
        let table = store.clients.present().unwrap().clone();
        block_on(store.clients.write(&mut part, table)).unwrap();
        let start = usize::from(map::CLIENT_TABLE.end().0)
            - 2 * crate::fram::slot_bytes(CLIENT_TABLE_BYTES);
        let second = start + crate::fram::slot_bytes(CLIENT_TABLE_BYTES);
        part.bytes[start + 8] ^= 1;
        part.bytes[second + 8] ^= 1;
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert_eq!(store.clients.present().unwrap().enrolled(), 0);
    }

    #[test]
    fn f_091_p_066_repair_boot_stays_closed_and_next_valid_empty_boot_opens() {
        for corrupt in [false, true] {
            let mut part = Part::fresh();
            if corrupt {
                let (mut store, _) = boot(&mut part, None);
                let mut table = store.clients.present().unwrap().clone();
                let _ = table
                    .pair(Label::new("lost phone").unwrap(), ClientKind::App)
                    .unwrap();
                block_on(store.clients.write(&mut part, table)).unwrap();
                let start = usize::from(map::CLIENT_TABLE.end().0)
                    - 2 * crate::fram::slot_bytes(CLIENT_TABLE_BYTES);
                let second = start + crate::fram::slot_bytes(CLIENT_TABLE_BYTES);
                part.bytes[start + 8] ^= 1;
                part.bytes[second + 8] ^= 1;
            }
            let (store, repair) = boot(&mut part, None);
            assert_eq!(store.clients.present().unwrap().enrolled(), 0);
            assert!(
                !crate::Panel::at_power_on(crate::Revision::A, repair.enrolment, Tick::ZERO)
                    .pairing_open(Tick::ZERO)
            );
            let (_, next) = boot(&mut part, None);
            assert!(
                crate::Panel::at_power_on(crate::Revision::A, next.enrolment, Tick::ZERO)
                    .pairing_open(Tick::ZERO)
            );
        }
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
                part.bytes[crate::fram::slot_bytes(EPOCH_BYTES) + 8] ^= 1;
            }
            let (store, report) = boot(&mut part, None);
            assert_eq!(store.clients.present().unwrap().enrolled(), 0);
            assert_eq!(report.epoch.epoch().is_some(), !damaged);
            assert_eq!(
                crate::Panel::at_power_on(crate::Revision::A, report.enrolment, Tick::ZERO)
                    .pairing_open(Tick::ZERO),
                !damaged
            );
        }
    }

    #[test]
    fn f_091_p_066_stale_empty_table_opens_only_after_boot_write_succeeds() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        // A reset advanced the epoch but lost power before clearing the table.
        let clearing = block_on(store.epoch.advance(&mut part)).unwrap();
        assert_eq!(clearing.epoch(), epoch(2));
        part.falling = true;
        let (store, refused) = boot(&mut part, None);
        assert_eq!(refused.epoch.epoch(), Some(epoch(2)));
        assert_eq!(refused.clients, Some(Err(Refused::SupplyFalling)));
        assert_eq!(store.clients.present().unwrap().epoch(), Epoch::FIRST);
        assert!(
            !crate::Panel::at_power_on(crate::Revision::A, refused.enrolment, Tick::ZERO)
                .pairing_open(Tick::ZERO)
        );
        assert_eq!(refused.enrolment, crate::EnrolmentAtBoot::Unavailable);

        part.falling = false;
        let (store, repaired) = boot(&mut part, None);
        assert_eq!(
            repaired.clients,
            Some(Ok(Booted::Cleared(Because::Earlier(Epoch::FIRST))))
        );
        assert_eq!(store.clients.present().unwrap().epoch(), epoch(2));
        assert_eq!(store.clients.present().unwrap().enrolled(), 0);
        assert_eq!(repaired.enrolment, crate::EnrolmentAtBoot::Empty);
        assert!(
            crate::Panel::at_power_on(crate::Revision::A, repaired.enrolment, Tick::ZERO)
                .pairing_open(Tick::ZERO)
        );
    }

    #[test]
    fn f_091_p_066_empty_table_with_refused_epoch_initialisation_stays_closed() {
        let mut part = Part::fresh();
        let _ = boot(&mut part, None);
        part.bytes[..usize::from(map::EPOCH.end().0)].fill(0);
        part.falling = true;
        let (store, report) = boot(&mut part, None);
        assert_eq!(store.clients.present().unwrap().enrolled(), 0);
        assert_eq!(report.epoch.epoch(), None);
        assert_eq!(report.enrolment, crate::EnrolmentAtBoot::Unavailable);
        assert!(
            !crate::Panel::at_power_on(crate::Revision::A, report.enrolment, Tick::ZERO)
                .pairing_open(Tick::ZERO)
        );
    }

    #[test]
    fn f_041_secret_replacement_requires_a_new_secret_and_explicit_replacement() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let old = Secret::new([1; 16], [2; 32]).expect("entropy");
        let new = Secret::new([1; 16], [3; 32]).expect("fresh entropy");
        block_on(store.secret.write(&mut part, old)).expect("old secret");
        let _ = block_on(store.challenges.mint(&mut part)).expect("mint");
        assert_eq!(
            block_on(crate::stage_secret(&mut part, old, true)),
            Err(crate::ProvisionFailed::SameSecret)
        );
        assert_eq!(
            block_on(crate::stage_secret(&mut part, new, false)),
            Err(crate::ProvisionFailed::AlreadyProvisioned)
        );
        let (store, _) = boot(&mut part, None);
        assert!(store.secret.present() == Some(&old));
        assert_eq!(store.challenges.present().expect("counter").last(), 1);
    }

    #[test]
    fn f_041_staging_keeps_the_active_pair_and_refuses_a_second_pending_secret() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let old = Secret::new([1; 16], [2; 32]).expect("entropy");
        let new = Secret::new([1; 16], [3; 32]).expect("fresh entropy");
        block_on(store.secret.write(&mut part, old)).expect("old secret");
        let _ = block_on(store.challenges.mint(&mut part)).expect("mint");
        block_on(crate::stage_secret(&mut part, new, true)).expect("stage");
        assert_eq!(
            block_on(crate::stage_secret(&mut part, new, true)),
            Err(crate::ProvisionFailed::Pending)
        );
        let current = block_on(Kept::<Secret, SECRET_BYTES>::read(
            map::DEVICE_SECRET,
            &mut part,
        ))
        .expect("read");
        assert!(current.present() == Some(&old));
        assert_eq!(
            block_on(store.challenges.mint(&mut part))
                .expect("old session")
                .counter(),
            2
        );
        let (mut store, _) = boot(&mut part, None);
        assert!(store.secret.present() == Some(&new));
        assert_eq!(
            block_on(store.challenges.mint(&mut part))
                .expect("new session")
                .counter(),
            1
        );
    }

    #[test]
    fn f_041_garbage_secret_intent_is_discarded_without_changing_the_active_pair() {
        for malformed in [false, true] {
            let mut part = Part::fresh();
            let (mut store, _) = boot(&mut part, None);
            let old = Secret::new([1; 16], [2; 32]).expect("entropy");
            block_on(store.secret.write(&mut part, old)).expect("legacy secret");
            let _ = block_on(store.challenges.mint(&mut part)).expect("mint");
            let start = usize::from(map::LOAD_SHED_CONFIG.end().0);
            part.bytes[start..].fill(0x55);
            if malformed {
                let mut bad = [0; crate::SECRET_CHANGE_BYTES];
                bad[0] = 2;
                let _ = block_on(map::SECRET_CHANGE.write(&mut part, Position::Start, &bad))
                    .expect("malformed intent");
            }
            let (store, report) = boot(&mut part, None);
            assert_eq!(report.secret_recovery, crate::SecretRecovery::Discarded);
            assert!(store.secret.present() == Some(&old));
            assert_eq!(store.challenges.present().expect("old counter").last(), 1);
            assert!(part.bytes[start..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn f_041_a_refused_secret_recovery_exposes_no_store_and_retries_at_boot() {
        let mut part = Part::fresh();
        let secret = Secret::new([1; 16], [2; 32]).expect("entropy");
        block_on(crate::stage_secret(&mut part, secret, false)).expect("stage");
        part.falling = true;
        assert!(matches!(
            block_on(Store::boot(&mut part, None)),
            Err(crate::ProvisionFailed::Write(Refused::SupplyFalling))
        ));
        part.falling = false;
        let (mut store, _) = boot(&mut part, None);
        assert!(store.secret.present() == Some(&secret));
        assert_eq!(
            block_on(store.challenges.mint(&mut part))
                .expect("mintable")
                .counter(),
            1
        );
    }

    #[test]
    fn f_041_secret_replacement_repairs_a_corrupt_challenge_counter() {
        let mut part = Part::fresh();
        part.bytes[32..72].fill(0x55);
        let (mut store, _) = boot(&mut part, None);
        let old = Secret::new([1; 16], [1; 32]).expect("old entropy");
        block_on(store.secret.write(&mut part, old)).expect("old secret");
        assert_eq!(store.challenges.held(), &Held::Corrupt);
        let secret = Secret::new([1; 16], [2; 32]).expect("entropy");
        block_on(crate::stage_secret(&mut part, secret, true)).expect("staged");
        let (mut store, _) = boot(&mut part, None);
        assert_eq!(
            block_on(store.challenges.mint(&mut part))
                .expect("mintable")
                .counter(),
            1
        );
    }

    #[test]
    fn p_085_a_first_boot_writes_epoch_one_and_clears_the_table_under_it() {
        let mut part = Part::fresh();
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::First);
        assert_eq!(report.epoch.epoch(), Some(Epoch::FIRST));
        assert_eq!(report.clients, Some(Ok(Booted::Cleared(Because::Absent))));
        assert_eq!(report.boot, BootCount::FIRST);
        assert_eq!(report.boot_recorded, Ok(()));
        assert_eq!(report.panic_recorded, None);
        assert_eq!(store.epoch.present(), Some(&Epoch::FIRST));
        let table = store.clients.present().expect("a table");
        assert!(table.is_under(Epoch::FIRST));
        assert_eq!(table.enrolled(), 0);
        assert!(matches!(store.secret.held(), Held::Absent));
        assert_eq!(store.run.held(), &Held::Absent);
        assert_eq!(store.release.held(), &Held::Absent);
        assert_eq!(store.network.held(), &Held::Absent);
        assert_eq!(store.challenges.held(), &Held::Absent);
        assert_eq!(store.volume.held(), &Held::Absent);
        // The second boot is not the first.
        let (_, again) = boot(&mut part, None);
        assert_eq!(again.epoch, EpochAtBoot::Held(Epoch::FIRST));
        assert_eq!(again.clients, Some(Ok(Booted::Rebased)));
        assert_eq!(again.boot, BootCount::FIRST.next());
    }

    #[test]
    fn f_026_a_boot_finishes_a_reset_that_was_cut_after_the_epoch_moved() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let enrolled = block_on(store.clients.update(&mut part, |table| {
            table.pair(Label::new("phone").expect("fits"), ClientKind::App)
        }))
        .expect("the supply is fine");
        assert!(matches!(enrolled, Ok(Paired::Enrolled(_))));
        // The reset moves the epoch and the power goes before the table.
        let _clearing = block_on(store.epoch.advance(&mut part)).expect("the supply is fine");
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::Held(epoch(2)));
        assert_eq!(
            report.clients,
            Some(Ok(Booted::Cleared(Because::Earlier(Epoch::FIRST))))
        );
        let table = store.clients.present().expect("a table");
        assert!(table.is_under(epoch(2)));
        assert_eq!(table.enrolled(), 0);
    }

    #[test]
    fn p_085_a_boot_with_no_readable_epoch_has_none_and_leaves_the_table_alone() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let _ = block_on(store.clients.update(&mut part, |table| {
            table.pair(Label::new("phone").expect("fits"), ClientKind::App)
        }))
        .expect("the supply is fine");
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
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, EpochAtBoot::None(NoEpoch::Corrupt));
        assert_eq!(report.epoch.epoch(), None);
        assert_eq!(report.clients, None);
        // The rows are still there, and nothing can enrol into them
        // until a person writes an epoch.
        assert_eq!(store.clients.present().map(ClientTable::enrolled), Some(1));
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
    fn f_026_a_boot_raises_a_record_behind_the_tables_stamp_and_derives_nothing_if_it_cannot() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let clearing = block_on(store.epoch.advance(&mut part)).expect("the supply is fine");
        block_on(
            store
                .clients
                .write(&mut part, ClientTable::cleared(&clearing)),
        )
        .expect("the supply is fine");
        let id = block_on(store.clients.update(&mut part, |table| {
            table.pair(Label::new("phone").expect("fits"), ClientKind::App)
        }))
        .expect("the supply is fine")
        .expect("room")
        .client();
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
        assert_eq!(report.clients, Some(Ok(Booted::Rebased)));
        assert_eq!(store.epoch.present(), Some(&epoch(2)));
        let table = store.clients.present().expect("a table");
        assert!(table.is_under(epoch(2)));
        assert_eq!(
            table.row(id).map(|row| row.label().as_bytes()),
            Some(&b"phone"[..])
        );
        // And when the raise will not land, nothing derives and nothing
        // is cleared: the rows wait for a boot that can.
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
        assert_eq!(store.clients.present().map(ClientTable::enrolled), Some(1));
        assert_eq!(store.epoch.present(), Some(&Epoch::FIRST));
    }

    #[test]
    fn p_121_a_boot_with_no_epoch_still_restarts_the_dedup_windows_at_tick_zero() {
        let mut part = Part::fresh();
        let (mut store, _) = boot(&mut part, None);
        let id = block_on(store.clients.update(&mut part, |table| {
            table.pair(Label::new("phone").expect("fits"), ClientKind::App)
        }))
        .expect("the supply is fine")
        .expect("room")
        .client();
        let late = Tick::from_millis(500_000);
        let _ = block_on(store.clients.update(&mut part, |table| {
            table.admit(id, Counter(1), 7, Fingerprint::of(b"start"), late)
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
        let table = store.clients.present().expect("the table is held");
        assert_eq!(table.dedup().live(Tick::from_millis(599_999)), 1);
        assert_eq!(table.dedup().live(Tick::from_millis(600_000)), 0);
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
        let id = block_on(store.clients.update(&mut part, |table| {
            table.pair(Label::new("phone").expect("fits"), ClientKind::App)
        }))
        .expect("the supply is fine")
        .expect("room")
        .client();
        let late = Tick::from_millis(500_000);
        let _ = block_on(store.clients.update(&mut part, |table| {
            table.admit(id, Counter(1), 7, Fingerprint::of(b"start"), late)
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
        let table = store.clients.present().expect("a table");
        assert_eq!(table.dedup().live(Tick::from_millis(599_999)), 1);
        assert_eq!(table.dedup().live(Tick::from_millis(600_000)), 0);
        let release = store.release.present().expect("a release");
        assert!(release.admits(&Digest([9; 32]), Tick::from_millis(599_999)));
        assert!(!release.admits(&Digest([9; 32]), Tick::from_millis(600_000)));
    }

    #[test]
    fn a_boot_whose_last_read_fails_writes_nothing_and_the_next_one_counts_once() {
        let mut part = Part::fresh();
        // The last section's B-prefix CRC is the last read. Every earlier
        // record has been read when this transaction fails.
        let last_read = usize::from(map::LOAD_SHED_CONFIG.end().0) - crate::fram::slot_bytes(1024)
            + crate::fram::slot_bytes(crate::BEHAVIOUR_RECORD_BYTES)
            - 1;
        part.refuse_reads_at = Some(u16::try_from(last_read).expect("inside FRAM"));
        let outcome = block_on(Store::boot(
            &mut part,
            Some(LastWords::Panicked(PanicSite { file: 1, line: 2 })),
        ));
        assert!(outcome.is_err());
        // Nothing landed: no epoch, no count, no panic record.
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
