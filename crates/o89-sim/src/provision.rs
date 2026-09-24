//! Secret replacement and recovery under byte-by-byte power loss.
use embassy_futures::block_on;
use o89_core::{Address, Fram as _, Held, MintFailed, Secret, Store, map, stage_secret};

use crate::{SimFram, crash_at_every_step};

fn old() -> Secret {
    Secret::new([1; 16], [2; 32]).expect("entropy")
}
fn new() -> Secret {
    Secret::new([1; 16], [3; 32]).expect("fresh entropy")
}
fn start(corrupt: bool) -> SimFram {
    let mut part = SimFram::fresh();
    let (mut store, _) = block_on(Store::boot(&mut part, None)).expect("boot");
    block_on(store.secret.write(&mut part, old())).expect("legacy secret");
    for _ in 0..7 {
        let _ = block_on(store.challenges.mint(&mut part)).expect("mint");
    }
    if corrupt {
        block_on(part.write(Address(32), &[0x55; 40])).expect("damage both slots");
    }
    part
}

#[test]
fn f_041_secret_replacement_cut_at_every_byte_recovers_only_the_old_or_new_pair() {
    for (corrupt, first, prior_transaction) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (false, false, true),
    ] {
        let mut start = start(corrupt);
        if first {
            block_on(start.write(map::WRITE_VOLUME.end(), &[0; 120])).expect("unprovisioned");
        }
        if prior_transaction {
            let earlier = Secret::new([1; 16], [4; 32]).expect("earlier entropy");
            block_on(stage_secret(&mut start, earlier, true)).expect("previous transaction");
            let (mut store, _) = block_on(Store::boot(&mut start, None)).expect("previous boot");
            let mut transaction = block_on(o89_core::Kept::<
                o89_core::SecretChange,
                { o89_core::SECRET_CHANGE_BYTES },
            >::read(map::SECRET_CHANGE, &mut start))
            .expect("transaction");
            block_on(transaction.write(&mut start, o89_core::SecretChange::Complete))
                .expect("label acknowledged");
            block_on(store.secret.write(&mut start, old())).expect("legacy key fixture");
            for _ in 0..7 {
                let _ = block_on(store.challenges.mint(&mut start)).expect("mint");
            }
        }
        let previous = if first { None } else { Some(old()) };
        let crashes = crash_at_every_step(
            &start,
            |part| {
                block_on(stage_secret(part, new(), !first)).map_err(|_| ())?;
                // Store::boot is the reboot boundary; preserve the fault injector's
                // byte count so cuts also cover every byte of boot recovery.
                let (_, report) = block_on(Store::boot(part, None)).map_err(|_| ())?;
                report.boot_recorded.map_err(|_| ())?;
                Ok(())
            },
            |part, step| {
                let (mut store, _) = block_on(Store::boot(part, None)).expect("recovery boot");
                if store.secret.present() == previous.as_ref() {
                    if corrupt {
                        assert_eq!(store.challenges.held(), &Held::Corrupt, "cut {step}");
                        assert_eq!(
                            block_on(store.challenges.mint(part)),
                            Err(MintFailed::Unknown)
                        );
                    } else {
                        assert_eq!(
                            store.challenges.present().expect("old counter").last(),
                            7,
                            "cut {step}"
                        );
                    }
                } else {
                    assert!(store.secret.present() == Some(&new()), "cut {step}");
                    assert_eq!(
                        block_on(store.challenges.mint(part))
                            .expect("fresh counter")
                            .counter(),
                        1,
                        "cut {step}"
                    );
                    let (mut again, _) = block_on(Store::boot(part, None)).expect("next boot");
                    assert_eq!(
                        block_on(again.challenges.mint(part))
                            .expect("never reset again")
                            .counter(),
                        2,
                        "cut {step}"
                    );
                }
            },
        )
        .expect("uncut transaction");
        assert!(crashes.steps > 200);
    }
}

#[test]
fn f_041_secret_replacement_recovery_itself_survives_every_byte_cut() {
    let mut start = start(true);
    block_on(stage_secret(&mut start, new(), true)).expect("durable intent");
    let crashes = crash_at_every_step(
        &start,
        |part| {
            block_on(Store::boot(part, None))
                .map(|_| ())
                .map_err(|_| ())
        },
        |part, step| {
            let (mut store, _) = block_on(Store::boot(part, None)).expect("recovery retries");
            assert!(store.secret.present() == Some(&new()), "cut {step}");
            assert_eq!(
                block_on(store.challenges.mint(part))
                    .expect("mintable")
                    .counter(),
                1,
                "cut {step}"
            );
        },
    )
    .expect("uncut recovery");
    assert!(crashes.steps > 100);
}

#[test]
fn f_041_first_secret_over_a_corrupt_counter_is_mintable() {
    let mut part = SimFram::fresh();
    block_on(part.write(Address(32), &[0x55; 40])).expect("old layout");
    block_on(stage_secret(&mut part, new(), false)).expect("first secret");
    let (mut store, _) = block_on(Store::boot(&mut part, None)).expect("boot");
    assert!(store.secret.present() == Some(&new()));
    assert_eq!(
        block_on(store.challenges.mint(&mut part))
            .expect("mintable")
            .counter(),
        1
    );
    assert!(matches!(
        block_on(map::SECRET_CHANGE.read(&mut part)),
        Ok(o89_core::Current::Valid { .. })
    ));
}

#[test]
fn f_041_garbage_intent_discard_cut_at_every_byte_keeps_the_active_pair() {
    let mut start = start(false);
    let at = map::LOAD_SHED_CONFIG.end();
    block_on(start.write(at, &[0x55; 122])).expect("old layout garbage");
    let crashes = crash_at_every_step(
        &start,
        |part| {
            block_on(Store::boot(part, None))
                .map(|_| ())
                .map_err(|_| ())
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("retry discarded intent");
            assert!(store.secret.present() == Some(&old()), "cut {step}");
            assert_eq!(
                store.challenges.present().expect("old counter").last(),
                7,
                "cut {step}"
            );
            let begin = usize::from(at.0);
            let end = usize::from(map::SECRET_CHANGE.end().0);
            assert!(
                part.bytes()[begin..end].iter().all(|byte| *byte == 0),
                "cut {step}"
            );
        },
    )
    .expect("garbage does not stop boot");
    assert!(crashes.steps >= 122);
}

#[test]
fn f_041_label_acknowledgement_cut_never_resets_the_applied_counter() {
    use o89_core::{Kept, SECRET_CHANGE_BYTES, SecretChange};
    let mut start = start(false);
    block_on(stage_secret(&mut start, new(), true)).expect("stage");
    let (mut store, _) = block_on(Store::boot(&mut start, None)).expect("apply");
    assert_eq!(
        block_on(store.challenges.mint(&mut start))
            .expect("mint")
            .counter(),
        1
    );
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let mut transaction = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
                map::SECRET_CHANGE,
                part,
            ))
            .map_err(|_| ())?;
            block_on(transaction.write(part, SecretChange::Complete)).map_err(|_| ())?;
            let (_, report) = block_on(Store::boot(part, None)).map_err(|_| ())?;
            report.boot_recorded.map_err(|_| ())?;
            Ok(())
        },
        |part, step| {
            let (mut store, _) = block_on(Store::boot(part, None)).expect("retry boot");
            assert!(store.secret.present() == Some(&new()), "cut {step}");
            assert_eq!(
                block_on(store.challenges.mint(part))
                    .expect("not reset")
                    .counter(),
                2,
                "cut {step}"
            );
            let transaction = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
                map::SECRET_CHANGE,
                part,
            ))
            .expect("transaction");
            match transaction.present().expect("durable state") {
                SecretChange::Applied(secret) => assert!(*secret == new(), "cut {step}"),
                SecretChange::Complete => {}
                SecretChange::Pending(_) => panic!("cut {step} reverted application"),
            }
        },
    )
    .expect("acknowledgement");
    assert!(crashes.steps > 100);
}
