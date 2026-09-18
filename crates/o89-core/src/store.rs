//! Every record the controller keeps, read in the boot's order, with the
//! rules that tie one record to another applied where both are in hand.
//!
//! A boot reads the part once and holds what it read: the epoch, the
//! client table, the counters, the run reason, the panic record and the
//! rest, each as a [`Kept`] whose RAM copy moves only when the part has
//! moved. Three things happen on the way: a fresh unit gets its first
//! epoch; a table that is not under the epoch the part holds is cleared,
//! finishing a reset that was cut (F-026); the boot count climbs and the
//! last words, if a run left any, are written down with it. Everything
//! that measures a window on the tick is restarted at this boot's tick
//! zero (P-121).
//!
//! A boot that cannot read the part returns the bus error and nothing
//! else: there is no partial store to hold. A write the boot could not
//! make is in the report, so the caller raises what it owes.
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
use crate::release::{COMMS_RELEASE_BYTES, CommsRelease};
use crate::run_reason::{RUN_REASON_BYTES, RunReason};
use crate::secret::{SECRET_BYTES, Secret};
use crate::write_volume::{WRITE_VOLUME_BYTES, WriteVolume};

/// What the controller keeps on the part, as this boot read it.
pub struct Store {
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
}

/// Why the boot has no epoch. No key derives without one, so every `Pair`
/// and `Hello` is refused until a later boot finds it or a person writes
/// one (P-085).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NoEpoch<E> {
    /// Both slots written and neither holds.
    Corrupt,
    /// A record that holds and does not decode: a zero.
    Malformed(Malformed),
    /// A fresh unit whose first epoch would not land.
    Refused(Refused<E>),
}

/// What the boot did, for the log and for what the caller owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a boot report nobody reads is a refused write nobody raises"]
pub struct BootReport<E> {
    /// The epoch this boot runs under, or why there is none.
    pub epoch: Result<Epoch, NoEpoch<E>>,
    /// Whether this boot wrote the unit's first epoch.
    pub first_boot: bool,
    /// What became of the client table, or nothing because there was no
    /// epoch to take it under.
    pub clients: Option<Result<Booted, Refused<E>>>,
    /// The number of this boot.
    pub boot: BootCount,
    /// Whether that number landed on the part.
    pub boot_recorded: Result<(), Refused<E>>,
    /// Whether the last words landed, if a run left any.
    pub panic_recorded: Option<Result<(), Refused<E>>>,
}

impl Store {
    /// Read every record and apply the boot's rules. `last_words` is what
    /// the previous run left in RAM, if anything.
    pub async fn boot<F: Fram>(
        fram: &mut F,
        last_words: Option<LastWords>,
    ) -> Result<(Self, BootReport<F::Error>), F::Error> {
        let secret = Kept::<Secret, SECRET_BYTES>::read(map::DEVICE_SECRET, fram).await?;

        let mut epoch = Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, fram).await?;
        let mut first_boot = false;
        let established = match *epoch.held() {
            Held::Present(held) => Ok(held),
            Held::Absent => match epoch.write(fram, Epoch::FIRST).await {
                Ok(()) => {
                    first_boot = true;
                    Ok(Epoch::FIRST)
                }
                Err(refused) => Err(NoEpoch::Refused(refused)),
            },
            Held::Corrupt => Err(NoEpoch::Corrupt),
            Held::Malformed(malformed) => Err(NoEpoch::Malformed(malformed)),
        };

        let mut clients =
            Kept::<ClientTable, CLIENT_TABLE_BYTES>::read(map::CLIENT_TABLE, fram).await?;
        let clients_booted = match established {
            Ok(under) => Some(clients.booted(fram, under).await),
            Err(_) => None,
        };

        let run = Kept::<RunReason, RUN_REASON_BYTES>::read(map::RUN_REASON, fram).await?;

        let mut boots = Kept::<BootCount, BOOT_COUNT_BYTES>::read(map::BOOT_COUNT, fram).await?;
        let boot = match boots.held() {
            Held::Present(previous) => previous.next(),
            Held::Absent | Held::Corrupt | Held::Malformed(_) => BootCount::FIRST,
        };
        let boot_recorded = boots.write(fram, boot).await;

        let mut panics =
            Kept::<PanicRecord, PANIC_RECORD_BYTES>::read(map::PANIC_RECORD, fram).await?;
        let mut panic_recorded = None;
        if let Some(words) = last_words {
            let record = PanicRecord {
                boot: boot.get(),
                words,
            };
            panic_recorded = Some(panics.write(fram, record).await);
        }

        let challenges =
            Kept::<ChallengeCounter, CHALLENGE_COUNTER_BYTES>::read(map::CHALLENGE_COUNTER, fram)
                .await?;
        let volume = Kept::<WriteVolume, WRITE_VOLUME_BYTES>::read(map::WRITE_VOLUME, fram).await?;
        let mut release =
            Kept::<CommsRelease, COMMS_RELEASE_BYTES>::read(map::COMMS_RELEASE, fram).await?;
        if let Some(held) = release.present() {
            let rebased = held.rebased();
            release.rebase(rebased);
        }
        let network = Kept::<Network, NETWORK_BYTES>::read(map::NETWORK, fram).await?;

        let report = BootReport {
            epoch: established,
            first_boot,
            clients: clients_booted,
            boot,
            boot_recorded,
            panic_recorded,
        };
        Ok((
            Self {
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
            },
            report,
        ))
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
    const PART_BYTES: usize = 4096;
    const _: () = assert!(map::CLIENT_TABLE.end().0 as usize <= PART_BYTES);
    const _: () = assert!(PART_BYTES <= FRAM_BYTES);

    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
    }

    impl Part {
        fn fresh() -> Self {
            Self {
                bytes: [0; PART_BYTES],
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
    fn p_085_a_first_boot_writes_epoch_one_and_clears_the_table_under_it() {
        let mut part = Part::fresh();
        let (store, report) = boot(&mut part, None);
        assert_eq!(report.epoch, Ok(Epoch::FIRST));
        assert!(report.first_boot);
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
        assert!(!again.first_boot);
        assert_eq!(again.epoch, Ok(Epoch::FIRST));
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
        assert_eq!(report.epoch, Ok(epoch(2)));
        assert_eq!(
            report.clients,
            Some(Ok(Booted::Cleared(Because::OtherEpoch(Epoch::FIRST))))
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
        assert_eq!(report.epoch, Err(NoEpoch::Corrupt));
        assert_eq!(report.clients, None);
        // The rows are still there, and nothing can enrol into them
        // until a person writes an epoch.
        assert_eq!(store.clients.present().map(ClientTable::enrolled), Some(1));
        // A zero written raw is malformed, and no epoch either.
        let mut zero = Part::fresh();
        let _ = block_on(map::EPOCH.write(&mut zero, Position::Start, &[0; 4]));
        let (_, report) = boot(&mut zero, None);
        assert_eq!(report.epoch, Err(NoEpoch::Malformed(Malformed { at: 0 })));
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
        assert_eq!(second.panic_recorded, Some(Ok(())));
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
    fn a_boot_on_a_falling_supply_reads_everything_and_reports_every_write_it_could_not_make() {
        let mut part = Part::fresh();
        part.falling = true;
        let words = LastWords::Panicked(PanicSite { file: 1, line: 2 });
        let (store, report) = boot(&mut part, Some(words));
        assert_eq!(report.epoch, Err(NoEpoch::Refused(Refused::SupplyFalling)));
        assert!(!report.first_boot);
        assert_eq!(report.clients, None);
        assert_eq!(report.boot, BootCount::FIRST);
        assert_eq!(report.boot_recorded, Err(Refused::SupplyFalling));
        assert_eq!(report.panic_recorded, Some(Err(Refused::SupplyFalling)));
        assert_eq!(store.epoch.held(), &Held::Absent);
        assert_eq!(store.boots.held(), &Held::Absent);
        assert_eq!(store.panics.held(), &Held::Absent);
        // With the supply back, the same boot lands everything.
        part.falling = false;
        let (_, report) = boot(&mut part, Some(words));
        assert!(report.first_boot);
        assert_eq!(report.boot_recorded, Ok(()));
        assert_eq!(report.panic_recorded, Some(Ok(())));
    }
}
