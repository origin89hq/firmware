//! The tables' write paths, each cut at every byte, with the invariant a
//! boot needs asserted after every cut (F-025).
//!
//! A factory reset leaves the old epoch with its slots, or the new epoch
//! with every slot free, whatever its housekeeping reached. A command's
//! dedup entry lands whole or not at all. An enrolment into a free slot
//! leaves the slots that were there, with or without the new one, and never
//! half a slot. A draw leaves the generator where it was or one step on,
//! and releases nothing the next boot will draw again. A boot leaves a boot
//! count that climbs and a panic record that is whole or absent. The
//! recovery ladder's cuts leave the ones before the cut or the ones after
//! it, and never fewer than were kept. A run reason leaves the reason before
//! it or the one being declared, and the contact is moved only on one the
//! part holds.

use embassy_futures::block_on;
use km43::{ClientId, ClientKind, Epoch};
use std::cell::Cell;

use o89_core::map::{DRBG, EPOCH, RECENT_CUTS, RUN_REASON};
use o89_core::{
    Behaviour, BootCount, CUTS_RECORD_BYTES, Clients, CutsRecord, DRBG_BYTES, DrbgState,
    EPOCH_BYTES, Fingerprint, Generator, Held, Kept, KeyRecord, LastWords, PanicRecorded,
    PanicSite, Plan, RUN_REASON_BYTES, RailSequencer, Recovery, Revision, RunReason, Running,
    StartKind, Store, Tick, UnixMillis, Verdict,
};

use crate::link::{client_key, enrolment, unit};
use crate::{Crashes, SimFram, crash_at_every_step};

type Epochs = Kept<Epoch, EPOCH_BYTES>;
type Cuts = Kept<CutsRecord, CUTS_RECORD_BYTES>;
type Runs = Kept<RunReason, RUN_REASON_BYTES>;

fn client(n: u32) -> ClientId {
    ClientId::new(n).expect("a nonzero client")
}

fn epoch(raw: u32) -> Epoch {
    Epoch::new(raw).expect("a nonzero epoch")
}

/// A manufactured unit after its boots with one phone enrolled at slot 1.
fn with_one_phone() -> SimFram {
    unit().0
}

/// A part with its epoch and an empty table written and nothing else, as a
/// boot before the first finds it once the table has been set up: the
/// boot count and every record after it still to come.
fn with_a_table() -> SimFram {
    let mut part = SimFram::fresh();
    let mut epochs = block_on(Epochs::read(EPOCH, &mut part)).expect("the part answers");
    block_on(epochs.write(&mut part, Epoch::FIRST)).expect("the supply is steady");
    let _ = boot(&mut part);
    part
}

/// The epoch and the table as a boot reads them, the table repaired under
/// the epoch as the store's boot does.
fn boot(part: &mut SimFram) -> (Epochs, Clients) {
    let mut epochs = block_on(Epochs::read(EPOCH, part)).expect("the part is back");
    let mut clients = block_on(Clients::read(part)).expect("the part is back");
    let _ = block_on(clients.booted(&mut epochs, part)).expect("repairs");
    (epochs, clients)
}

#[test]
fn p_085_a_reset_cut_at_any_step_leaves_the_old_epoch_with_its_slots_or_a_new_one_with_none() {
    let start = with_one_phone();
    let mut committed_before_the_housekeeping = 0;
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let mut epochs = block_on(Epochs::read(EPOCH, part)).map_err(|_| ())?;
            let mut clients = block_on(Clients::read(part)).map_err(|_| ())?;
            block_on(o89_core::reset_clients(&mut epochs, &mut clients, part))
                .map(|_| ())
                .map_err(|_| ())
        },
        |part, step| {
            let raw = block_on(Clients::read(part)).expect("the part is back");
            let (epochs, clients) = boot(part);
            let found = *epochs.present().expect("an epoch, old or new");
            if found == Epoch::FIRST {
                // The reset did not commit: the phone is still enrolled.
                let phone = clients.occupant(client(1), found).expect("the phone");
                assert!(
                    phone.client().matches(&client_key(1).public()),
                    "cut at {step}"
                );
            } else {
                // It did: every slot is free under the new epoch, whether or
                // not the housekeeping after the epoch reached it (P-239).
                assert_eq!(found, epoch(2), "cut at {step}");
                assert_eq!(clients.enrolled(found), 0, "cut at {step}");
                if raw.enrolled(Epoch::FIRST) > 0 {
                    committed_before_the_housekeeping += 1;
                }
            }
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
    assert!(
        committed_before_the_housekeeping > 0,
        "no cut landed between the epoch and the clearing"
    );
}

#[test]
fn p_080_p_079_a_commands_entry_cut_at_any_step_lands_whole_or_not_at_all() {
    let start = with_one_phone();
    let start_the_generator = Fingerprint::of(b"\x01generator/start");
    let mut landed = 0;
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, mut clients) = boot(part);
            let verdict = block_on(clients.commands_mut().update(part, |commands| {
                commands.dedup_mut().admit(
                    client(1),
                    7,
                    start_the_generator,
                    Tick::from_millis(5_000),
                )
            }));
            match verdict {
                Ok(Verdict::Fresh(_)) => Ok(()),
                Ok(_) | Err(_) => Err(()),
            }
        },
        |part, step| {
            let (_, clients) = boot(part);
            let commands = clients.commands().present().expect("the dedup record");
            // The retry: either the entry is in flight or nothing
            // remembers the command at all.
            let retry = commands.clone().dedup_mut().admit(
                client(1),
                7,
                start_the_generator,
                Tick::from_millis(1),
            );
            match retry {
                Verdict::Fresh(_) => {}
                Verdict::InFlight(_) => landed += 1,
                other => panic!("cut at {step}: {other:?}"),
            }
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
    // No cut inside the write lands the new record: only the whole of it.
    assert_eq!(landed, 0);
}

#[test]
fn p_239_an_enrolment_cut_at_any_step_leaves_the_slots_that_were_there_and_never_half_a_slot() {
    let start = with_one_phone();
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, mut clients) = boot(part);
            block_on(clients.enrol(
                client(2),
                enrolment(2, "laptop", ClientKind::Cli),
                Epoch::FIRST,
                part,
            ))
            .map(|_| ())
            .map_err(|_| ())
        },
        |part, step| {
            let (_, clients) = boot(part);
            let phone = clients
                .occupant(client(1), Epoch::FIRST)
                .expect("the phone");
            assert_eq!(phone.label().as_bytes(), b"phone", "cut at {step}");
            assert_eq!(phone.kind(), ClientKind::App, "cut at {step}");
            assert_eq!(phone.role(), km43::Role::Owner, "cut at {step}");
            // Slot 2 is free, never a key without its label, kind and role.
            assert!(
                clients.occupant(client(2), Epoch::FIRST).is_none(),
                "cut at {step}"
            );
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
}

#[test]
fn p_239_an_enrolment_cut_at_any_step_never_lets_a_generation_be_issued_again() {
    let start = with_one_phone();
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, mut clients) = boot(part);
            block_on(clients.enrol(
                client(2),
                enrolment(2, "laptop", ClientKind::Cli),
                Epoch::FIRST,
                part,
            ))
            .map(|_| ())
            .map_err(|_| ())
        },
        |part, step| {
            // Whatever generation the cut left on the slot, free or not, the
            // enrolment tried again issues a later one.
            let (_, mut clients) = boot(part);
            let recorded = match clients.key(client(2)).and_then(Kept::present) {
                Some(KeyRecord::Free { generation }) => *generation,
                Some(KeyRecord::Occupied(occupant)) => Some(occupant.generation()),
                None => None,
            };
            let generation = block_on(clients.enrol(
                client(2),
                enrolment(2, "laptop", ClientKind::Cli),
                Epoch::FIRST,
                part,
            ))
            .expect("lands");
            assert!(Some(generation) > recorded, "cut at {step}: {generation:?}");
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
}

#[test]
fn p_237_a_draw_cut_at_any_step_is_never_released_twice() {
    // Draws have left already: the part holds the state after them.
    let mut start = with_one_phone();
    let mut generator =
        Generator::new(block_on(Kept::<DrbgState, DRBG_BYTES>::read(DRBG, &mut start)).unwrap());
    let before = block_on(generator.challenge(&mut start)).expect("a draw");
    let released = Cell::new(None);
    let crashes = crash_at_every_step(
        &start,
        |part| {
            released.set(None);
            let kept = block_on(Kept::<DrbgState, DRBG_BYTES>::read(DRBG, part)).map_err(|_| ())?;
            let mut generator = Generator::new(kept);
            let draw = block_on(generator.challenge(part)).map_err(|_| ())?;
            released.set(Some(draw));
            Ok(())
        },
        |part, step| {
            let kept = block_on(Kept::<DrbgState, DRBG_BYTES>::read(DRBG, part))
                .expect("the part is back");
            assert!(
                matches!(kept.held(), Held::Present(_)),
                "cut at {step}: the state is gone"
            );
            let mut generator = Generator::new(kept);
            let next = block_on(generator.challenge(part)).expect("a draw");
            assert_ne!(next, before, "cut at {step}: an old draw again");
            assert_ne!(Some(next), released.get(), "cut at {step}: released twice");
        },
    )
    .expect("the path runs uncut");
    assert!(crashes.steps > 0);
}

#[test]
fn f_008_a_boot_cut_at_any_step_leaves_a_boot_count_that_climbs_and_a_panic_record_whole_or_absent()
{
    let start = with_a_table();
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
    let mut start = SimFram::fresh();
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

/// A part holding `reason` as the run reason.
fn with_run_reason(reason: RunReason) -> SimFram {
    let mut part = SimFram::fresh();
    let mut runs = block_on(Runs::read(RUN_REASON, &mut part)).expect("the part answers");
    let declared = block_on(runs.declare(&mut part, reason)).expect("the supply is steady");
    assert_eq!(declared.reason(), reason);
    part
}

/// Declare `to` over a part holding `from`, cut at every step: the boot
/// finds `from` or `to` and nothing else, and a `Declared` handed out under
/// a cut names what the part holds.
fn declare_cut_at_every_step(from: RunReason, to: RunReason) -> Crashes {
    let start = with_run_reason(from);
    let declared = Cell::new(None);
    crash_at_every_step(
        &start,
        |part| {
            declared.set(None);
            let mut runs = block_on(Runs::read(RUN_REASON, part)).map_err(|_| ())?;
            let permission = block_on(runs.declare(part, to)).map_err(|_| ())?;
            declared.set(Some(permission.reason()));
            Ok(())
        },
        |part, step| {
            let runs = block_on(Runs::read(RUN_REASON, part)).expect("the part is back");
            let held = *runs.present().expect("a reason, never neither");
            assert!(held == from || held == to, "cut at {step}: {held:?}");
            if let Some(moved) = declared.get() {
                assert_eq!(
                    held, moved,
                    "cut at {step}: the contact moved on a reason the part lost"
                );
            }
        },
    )
    .expect("the path runs uncut")
}

#[test]
fn f_022_a_start_cut_at_any_step_leaves_the_part_stopped_or_holding_the_start_it_moves_on() {
    let start = RunReason::Running(Running {
        kind: StartKind::Automatic(Behaviour::Frost),
        started: UnixMillis::new(1_790_000_000_000),
    });
    let crashes = declare_cut_at_every_step(RunReason::Stopped, start);
    assert!(crashes.steps > RUN_REASON_BYTES, "{crashes:?}");
}

#[test]
fn f_022_a_stop_cut_at_any_step_leaves_the_run_or_the_stop_and_never_a_reason_for_neither() {
    let manual = RunReason::Running(Running {
        kind: StartKind::Manual,
        started: None,
    });
    let crashes = declare_cut_at_every_step(manual, RunReason::Stopped);
    assert!(crashes.steps > RUN_REASON_BYTES, "{crashes:?}");
}

#[test]
fn p_085_reset_refuses_without_clearing_when_the_supply_falls_and_retries_after_recovery() {
    let mut part = with_one_phone();
    let (mut epochs, mut clients) = boot(&mut part);
    part.set_supply(crate::Supply::Falling);
    assert_eq!(
        block_on(o89_core::reset_clients(
            &mut epochs,
            &mut clients,
            &mut part
        )),
        Err(o89_core::ResetFailed::Epoch(o89_core::EpochFailed::Write(
            o89_core::Refused::SupplyFalling
        )))
    );
    assert_eq!(epochs.present(), Some(&Epoch::FIRST));
    assert_eq!(clients.enrolled(Epoch::FIRST), 1);
    part.set_supply(crate::Supply::Steady);
    assert_eq!(
        block_on(o89_core::reset_clients(
            &mut epochs,
            &mut clients,
            &mut part
        )),
        Ok(epoch(2))
    );
    assert_eq!(epochs.present(), Some(&epoch(2)));
    assert_eq!(clients.enrolled(epoch(2)), 0);
    assert_eq!(clients.enrolled(Epoch::FIRST), 0, "and freed on the part");
}

#[test]
fn p_085_reset_refuses_an_unknown_or_exhausted_epoch_without_touching_clients() {
    for value in [None, Some(epoch(u32::MAX))] {
        let mut part = with_one_phone();
        let (mut epochs, mut clients) = boot(&mut part);
        let expected = match value {
            None => {
                let mut empty = SimFram::fresh();
                epochs = block_on(Epochs::read(EPOCH, &mut empty)).expect("empty part reads");
                o89_core::EpochFailed::Unknown
            }
            Some(value) => {
                block_on(epochs.write(&mut part, value)).expect("epoch written");
                o89_core::EpochFailed::AtTheCeiling
            }
        };
        let before = part.bytes_written();
        assert_eq!(
            block_on(o89_core::reset_clients(
                &mut epochs,
                &mut clients,
                &mut part
            )),
            Err(o89_core::ResetFailed::Epoch(expected))
        );
        assert_eq!(part.bytes_written(), before);
        assert_eq!(clients.enrolled(Epoch::FIRST), 1);
    }
}
