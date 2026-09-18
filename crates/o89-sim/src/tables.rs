//! The tables' write paths, each cut at every byte, with the invariant a
//! boot needs asserted after every cut (F-025).
//!
//! Three paths, three invariants. A factory reset leaves the old epoch
//! with its rows, or a higher epoch whose table the next boot clears. A
//! command leaves its counter and its in-flight entry together or leaves
//! neither. A pairing leaves the rows that were there, with or without the
//! new one, and never a row half written.

use embassy_futures::block_on;
use km43::{ClientId, ClientKind, Counter, Epoch};
use o89_core::map::{CLIENT_TABLE, EPOCH};
use o89_core::{
    Admitted, Because, Booted, CLIENT_TABLE_BYTES, ClientTable, EPOCH_BYTES, Fingerprint, Kept,
    Label, Paired, Tick,
};

use crate::{Crashes, SimFram, crash_at_every_step};

type Epochs = Kept<Epoch, EPOCH_BYTES>;
type Clients = Kept<ClientTable, CLIENT_TABLE_BYTES>;

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
                if booted == Booted::Cleared(Because::OtherEpoch(Epoch::FIRST)) {
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
