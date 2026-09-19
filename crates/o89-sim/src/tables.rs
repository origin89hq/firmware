//! The tables' write paths, each cut at every byte, with the invariant a
//! boot needs asserted after every cut (F-025).
//!
//! Six paths, six invariants. A factory reset leaves the old epoch
//! with its rows, or a higher epoch whose table the next boot clears. A
//! command leaves its counter and its in-flight entry together or leaves
//! neither. A pairing leaves the rows that were there, with or without the
//! new one, and never a row half written. A mint hands out no counter and
//! the next mint is past every one before it. A boot leaves a boot count
//! that climbs and a panic record that is whole or absent. The recovery
//! ladder's cuts leave the ones before the cut or the ones after it, and
//! never fewer than were kept.

use embassy_futures::block_on;
use km43::{ClientId, ClientKind, Counter, Epoch};
use o89_core::map::{CHALLENGE_COUNTER, CLIENT_TABLE, EPOCH, RECENT_CUTS};
use o89_core::{
    Admitted, Because, BootCount, Booted, CHALLENGE_COUNTER_BYTES, CLIENT_TABLE_BYTES,
    CUTS_RECORD_BYTES, ChallengeCounter, ClientTable, CutsRecord, EPOCH_BYTES, Fingerprint, Held,
    Kept, Label, LastWords, Paired, PanicRecorded, PanicSite, Plan, RailSequencer, Recovery,
    Revision, Store, Tick,
};

use crate::{Crashes, SimFram, crash_at_every_step};

type Epochs = Kept<Epoch, EPOCH_BYTES>;
type Clients = Kept<ClientTable, CLIENT_TABLE_BYTES>;
type Counters = Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES>;
type Cuts = Kept<CutsRecord, CUTS_RECORD_BYTES>;

fn client(n: u32) -> ClientId {
    ClientId::new(n).expect("a nonzero client")
}

fn epoch(raw: u32) -> Epoch {
    Epoch::new(raw).expect("a nonzero epoch")
}

fn label(text: &str) -> Label {
    Label::new(text).expect("a label under the cap")
}

/// A unit after its first boot with one phone enrolled: epoch one on the
/// part, the table under it with client 1 at counter zero.
fn with_one_phone() -> SimFram {
    let mut part = SimFram::fresh();
    let mut epochs = block_on(Epochs::read(EPOCH, &mut part)).expect("the part answers");
    block_on(epochs.write(&mut part, Epoch::FIRST)).expect("the supply is steady");
    let mut clients = block_on(Clients::read(CLIENT_TABLE, &mut part)).expect("the part answers");
    assert_eq!(
        block_on(clients.booted(&mut part, Epoch::FIRST)),
        Ok(Booted::Cleared(Because::Absent))
    );
    let enrolled = block_on(clients.update(&mut part, |table| {
        table.pair(label("phone"), ClientKind::App)
    }))
    .expect("the supply is steady");
    assert_eq!(enrolled, Ok(Paired::Enrolled(client(1))));
    part
}

/// The two records as a boot reads them.
fn boot(part: &mut SimFram) -> (Epochs, Clients) {
    let epochs = block_on(Epochs::read(EPOCH, part)).expect("the part is back");
    let clients = block_on(Clients::read(CLIENT_TABLE, part)).expect("the part is back");
    (epochs, clients)
}

#[test]
fn p_085_a_reset_cut_at_any_step_leaves_the_old_epoch_with_its_rows_or_a_higher_one_the_boot_clears_under()
 {
    let start = with_one_phone();
    let mut finished_by_the_boot = 0;
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (mut epochs, mut clients) = boot(part);
            let clearing = block_on(epochs.advance(part)).map_err(|_| ())?;
            block_on(clients.write(part, ClientTable::cleared(&clearing))).map_err(|_| ())
        },
        |part, step| {
            let (epochs, mut clients) = boot(part);
            let found = *epochs.present().expect("an epoch, old or new");
            let booted = block_on(clients.booted(part, found)).expect("the supply is steady");
            let table = clients.present().expect("a table after the boot");
            assert!(table.is_under(found), "cut at {step}");
            if found == Epoch::FIRST {
                // The reset did not move the epoch: the phone is still
                // enrolled and nothing was cleared.
                assert_eq!(booted, Booted::Rebased, "cut at {step}");
                assert_eq!(table.enrolled(), 1, "cut at {step}");
            } else {
                // It did: the phone's key no longer derives, and its row
                // is gone, either by the reset or by this boot.
                assert_eq!(found, epoch(2), "cut at {step}");
                assert_eq!(table.enrolled(), 0, "cut at {step}");
                if booted == Booted::Cleared(Because::Earlier(Epoch::FIRST)) {
                    finished_by_the_boot += 1;
                }
            }
        },
    )
    .expect("the path runs uncut");
    // The epoch's 20 bytes and the table's 1296: every cut inside the
    // table's write, after the epoch landed, is a reset the boot finished.
    assert_eq!(
        crashes,
        Crashes {
            steps: 20 + 16 + CLIENT_TABLE_BYTES
        }
    );
    assert_eq!(finished_by_the_boot, 16 + CLIENT_TABLE_BYTES);
}

#[test]
fn p_080_a_command_cut_at_any_step_lands_the_counter_and_the_in_flight_entry_together_or_neither() {
    let start = with_one_phone();
    let start_the_generator = Fingerprint::of(b"\x01generator/start");
    let admit = |table: &mut ClientTable| {
        table.admit(
            client(1),
            Counter(1),
            7,
            start_the_generator,
            Tick::from_millis(5_000),
        )
    };
    let mut landed = 0;
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, mut clients) = boot(part);
            match block_on(clients.update(part, admit)) {
                Ok(Admitted::Fresh(_)) => Ok(()),
                Ok(_) | Err(_) => Err(()),
            }
        },
        |part, step| {
            let (_, mut clients) = boot(part);
            assert_eq!(
                block_on(clients.booted(part, Epoch::FIRST)),
                Ok(Booted::Rebased),
                "cut at {step}"
            );
            let table = clients.present().expect("the table");
            let counter = table.accepted(client(1)).expect("the phone's row");
            // The retry: with the counter behind, stale; with it ahead,
            // either the entry is in flight or nothing remembers it.
            let retry = table.clone().admit(
                client(1),
                Counter(2),
                7,
                start_the_generator,
                Tick::from_millis(1),
            );
            match (counter, retry) {
                (Counter(0), Admitted::Fresh(_)) => {}
                (Counter(1), Admitted::InFlight(_)) => landed += 1,
                other => panic!("cut at {step}: {other:?} is a counter without its entry"),
            }
        },
    )
    .expect("the path runs uncut");
    assert_eq!(
        crashes,
        Crashes {
            steps: 16 + CLIENT_TABLE_BYTES
        }
    );
    // No cut inside the write lands the new record: only the whole of it.
    assert_eq!(landed, 0);
}

#[test]
fn p_078_a_pairing_cut_at_any_step_leaves_the_rows_that_were_there_and_never_half_a_row() {
    let start = with_one_phone();
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, mut clients) = boot(part);
            match block_on(
                clients.update(part, |table| table.pair(label("laptop"), ClientKind::Cli)),
            ) {
                Ok(Ok(Paired::Enrolled(_))) => Ok(()),
                Ok(_) | Err(_) => Err(()),
            }
        },
        |part, step| {
            let (_, mut clients) = boot(part);
            assert_eq!(
                block_on(clients.booted(part, Epoch::FIRST)),
                Ok(Booted::Rebased),
                "cut at {step}"
            );
            let table = clients.present().expect("the table");
            assert_eq!(table.enrolled(), 1, "cut at {step}");
            let phone = table.row(client(1)).expect("the phone's row");
            assert_eq!(phone.label().as_bytes(), b"phone");
            assert_eq!(phone.kind(), ClientKind::App);
            assert_eq!(table.row(client(2)), None, "cut at {step}");
        },
    )
    .expect("the path runs uncut");
    assert_eq!(
        crashes,
        Crashes {
            steps: 16 + CLIENT_TABLE_BYTES
        }
    );
}

#[test]
fn f_041_a_mint_cut_at_any_step_hands_out_no_counter_and_the_next_mint_is_past_every_one_before() {
    // One challenge has left already: the counter the part holds is one.
    let mut start = with_one_phone();
    let mut counter =
        block_on(Counters::read(CHALLENGE_COUNTER, &mut start)).expect("the part answers");
    let minted_before_the_cut = block_on(counter.mint(&mut start))
        .expect("the supply is steady")
        .counter();
    assert_eq!(minted_before_the_cut, 1);
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let mut counter = block_on(Counters::read(CHALLENGE_COUNTER, part)).map_err(|_| ())?;
            block_on(counter.mint(part)).map(|_| ()).map_err(|_| ())
        },
        |part, step| {
            let mut counter =
                block_on(Counters::read(CHALLENGE_COUNTER, part)).expect("the part is back");
            // The part holds the counter that left, or the one that was
            // about to; either way the next mint is past both.
            let held = counter.present().expect("a counter").last();
            assert!(held == 1 || held == 2, "cut at {step}: {held}");
            let next = block_on(counter.mint(part)).expect("the supply is steady");
            assert!(next.counter() > minted_before_the_cut, "cut at {step}");
            assert!(next.counter() > held, "cut at {step}");
        },
    )
    .expect("the path runs uncut");
    assert_eq!(crashes, Crashes { steps: 24 });
}

#[test]
fn f_008_a_boot_cut_at_any_step_leaves_a_boot_count_that_climbs_and_a_panic_record_whole_or_absent()
{
    let start = with_one_phone();
    let words = LastWords::Panicked(PanicSite {
        file: 0xDEAD_BEEF,
        line: 42,
    });
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, report) = block_on(Store::boot(part, Some(words))).map_err(|_| ())?;
            match (report.boot_recorded, report.panic_recorded) {
                (Ok(()), Some(PanicRecorded::Landed)) => Ok(()),
                _ => Err(()),
            }
        },
        |part, step| {
            let (store, report) = block_on(Store::boot(part, None)).expect("the part is back");
            // The cut boot was the unit's first: it wrote one or did not,
            // and this boot is one past whatever landed.
            assert!(
                report.boot == BootCount::FIRST || report.boot == BootCount::FIRST.next(),
                "cut at {step}: {:?}",
                report.boot
            );
            match store.panics.held() {
                Held::Absent => {}
                Held::Present(record) => assert_eq!(record.words, words, "cut at {step}"),
                other => panic!("cut at {step}: {other:?}"),
            }
        },
    )
    .expect("the path runs uncut");
    // The boot count's 20 bytes and the panic record's 40.
    assert_eq!(crashes, Crashes { steps: 20 + 40 });
}

#[test]
fn f_017_a_ladder_write_cut_at_any_step_keeps_the_cuts_before_it_or_after_it() {
    // One cut kept; the ladder makes a second, and its record is cut at
    // every byte on the way to the part.
    let mut seq = RailSequencer::new(Revision::B);
    let first = Tick::from_millis(90_000);
    let Plan::Cut(cut) = seq.plan_recovery(first) else {
        panic!("a cut");
    };
    let one = cut.cuts();
    assert!(matches!(
        cut.make(&mut seq, first),
        Recovery::Cycling { count: 1, .. }
    ));
    let mut start = with_one_phone();
    let mut cuts = block_on(Cuts::read(RECENT_CUTS, &mut start)).expect("the part answers");
    let record = |cuts| CutsRecord { boot: None, cuts };
    block_on(cuts.write(&mut start, record(one))).expect("the supply is steady");
    let mut after = seq;
    for ms in 90_001..=95_200 {
        let _ = after.tick(Tick::from_millis(ms));
    }
    let second = Tick::from_millis(160_000);
    let Plan::Cut(cut) = after.plan_recovery(second) else {
        panic!("a second cut");
    };
    let two = cut.cuts();
    assert_eq!(two.count(), 2);
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let mut cuts = block_on(Cuts::read(RECENT_CUTS, part)).map_err(|_| ())?;
            block_on(cuts.write(part, record(two))).map_err(|_| ())
        },
        |part, step| {
            let (store, report) = block_on(Store::boot(part, None)).expect("the part is back");
            let carried = CutsRecord::carried(store.cuts.held(), report.boot);
            assert_eq!(carried.missed, 0, "cut at {step}: the part's first boot");
            assert!(
                carried.cuts == one.rebased() || carried.cuts == two.rebased(),
                "cut at {step}: {carried:?}"
            );
        },
    )
    .expect("the path runs uncut");
    // Four bytes clearing the magic, four of sequence, twenty-nine of body,
    // four of CRC, four of magic.
    assert_eq!(
        crashes,
        Crashes {
            steps: 4 + 4 + 29 + 4 + 4
        }
    );
}

/// One boot of a revision A controller as `main` runs it up to its
/// ladder's write: the store read, the cuts carried with this boot's own
/// reset, and the record handed back to write.
fn boot_on_revision_a(part: &mut SimFram) -> (Store, CutsRecord) {
    let (store, report) = block_on(Store::boot(part, None)).expect("the part answers");
    let mut seq = RailSequencer::new(Revision::A);
    seq.carry(
        CutsRecord::carried(store.cuts.held(), report.boot),
        Tick::ZERO,
    );
    let record = CutsRecord {
        boot: store.boots.present().copied(),
        cuts: seq.recent_cuts(Tick::ZERO),
    };
    (store, record)
}

#[test]
fn f_018_three_resets_are_the_third_rung_though_every_boots_ladder_write_after_the_first_is_cut() {
    // The first boot's record lands; each boot after it is cut at step k
    // of its own, for every k, and the third boot still counts three.
    let mut start = SimFram::fresh();
    let (mut store, first) = boot_on_revision_a(&mut start);
    assert_eq!(first.cuts.count(), 1, "the first boot's own reset");
    block_on(store.cuts.write(&mut start, first)).expect("the supply is steady");
    let mut whole = start.clone();
    whole.reboot();
    let (mut store, second) = boot_on_revision_a(&mut whole);
    let before = whole.bytes_written();
    block_on(store.cuts.write(&mut whole, second)).expect("the supply is steady");
    let steps = whole.bytes_written() - before;
    assert_eq!(steps, 4 + 4 + 29 + 4 + 4);
    for step in 0..steps {
        let mut part = start.clone();
        for boot in 2..=3 {
            part.reboot();
            let (mut store, record) = boot_on_revision_a(&mut part);
            assert_eq!(record.cuts.count(), boot, "cut at {step}: boot {boot}");
            part.cut_after(step);
            let _ = block_on(store.cuts.write(&mut part, record));
        }
        part.reboot();
        let (store, report) = block_on(Store::boot(&mut part, None)).expect("the part answers");
        let mut seq = RailSequencer::new(Revision::A);
        seq.carry(
            CutsRecord::carried(store.cuts.held(), report.boot),
            Tick::ZERO,
        );
        assert_eq!(
            seq.plan_recovery(Tick::from_millis(60_000)),
            Plan::LeftOnAndRaised,
            "cut at {step}: the fourth boot's first request"
        );
    }
}
