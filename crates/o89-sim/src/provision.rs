//! The manufacturing transaction and a label's replacement, under
//! byte-by-byte power loss: a unit is born whole or not at all, and nothing
//! after its birth writes its controller key or its generator again (P-235,
//! P-237).
use embassy_futures::block_on;
use o89_core::{
    Birth, ControllerKey, DrbgState, Fram as _, Held, Kept, SECRET_CHANGE_BYTES, Secret,
    SecretChange, SecretRecovery, Store, map, stage_secret,
};

use crate::link::{controller, manufactured, secret};
use crate::{SimFram, crash_at_every_step};

fn replacement() -> Secret {
    Secret::new(crate::link::DEVICE, [3; 32]).expect("fresh entropy")
}

fn birth() -> Birth {
    Birth {
        controller: controller(),
        drbg: DrbgState::new(crate::link::SEED).expect("entropy"),
    }
}

/// The generator's state as the part holds it, compared by encoding.
fn drbg(store: &Store) -> Option<[u8; 32]> {
    use o89_core::Body as _;
    store.drbg.present().map(DrbgState::encode)
}

/// A manufactured unit whose generator has drawn: its state is not the seed.
fn drawn() -> SimFram {
    let mut part = manufactured();
    let (store, _) = block_on(Store::boot(&mut part, None)).expect("boot");
    let mut generator = o89_core::Generator::new(store.drbg);
    for _ in 0..3 {
        let _ = block_on(generator.challenge(&mut part)).expect("draws");
    }
    part
}

#[test]
fn p_235_p_237_manufacture_cut_at_every_byte_is_born_whole_or_not_at_all() {
    let start = SimFram::fresh();
    let crashes = crash_at_every_step(
        &start,
        |part| {
            block_on(stage_secret(part, secret(), Some(birth()), false)).map_err(|_| ())?;
            // The boot is the reboot boundary: its applying is cut too.
            let (_, report) = block_on(Store::boot(part, None)).map_err(|_| ())?;
            report.boot_recorded.map_err(|_| ())
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("recovery boot");
            let born = (
                store.secret.present().is_some(),
                store.controller.present().is_some(),
                store.drbg.present().is_some(),
            );
            match born {
                (false, false, false) => {
                    assert!(
                        matches!(store.controller.held(), Held::Absent),
                        "cut {step}"
                    );
                    assert!(matches!(store.drbg.held(), Held::Absent), "cut {step}");
                }
                (true, true, true) => {
                    assert!(store.secret.present() == Some(&secret()), "cut {step}");
                    assert!(
                        store
                            .controller
                            .present()
                            .is_some_and(|key| key.fingerprint() == controller().fingerprint()),
                        "cut {step}"
                    );
                }
                other => panic!("cut {step}: born in part: {other:?}"),
            }
        },
    )
    .expect("uncut manufacture");
    assert!(crashes.steps > 200);
}

#[test]
fn p_235_p_237_a_replacement_label_cut_at_every_byte_keeps_the_key_and_the_generator() {
    let mut start = drawn();
    let (before, _) = block_on(Store::boot(&mut start, None)).expect("boot");
    let (fingerprint, state) = (
        before.controller.present().map(ControllerKey::fingerprint),
        drbg(&before),
    );
    assert!(state.is_some());
    let crashes = crash_at_every_step(
        &start,
        |part| {
            block_on(stage_secret(part, replacement(), None, true)).map_err(|_| ())?;
            let (_, report) = block_on(Store::boot(part, None)).map_err(|_| ())?;
            report.boot_recorded.map_err(|_| ())
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("recovery boot");
            assert!(
                store.secret.present() == Some(&secret())
                    || store.secret.present() == Some(&replacement()),
                "cut {step}"
            );
            assert!(
                store.controller.present().map(ControllerKey::fingerprint) == fingerprint,
                "cut {step}: the controller key changed"
            );
            assert_eq!(
                drbg(&store),
                state,
                "cut {step}: the generator was reseeded"
            );
        },
    )
    .expect("uncut replacement");
    assert!(crashes.steps > 100);
}

#[test]
fn p_235_a_second_birth_is_refused_and_an_unborn_unit_needs_one() {
    let mut born = manufactured();
    assert!(matches!(
        block_on(stage_secret(&mut born, replacement(), Some(birth()), true)),
        Err(o89_core::ProvisionFailed::AlreadyBorn)
    ));
    let mut unborn = SimFram::fresh();
    assert!(matches!(
        block_on(stage_secret(&mut unborn, secret(), None, false)),
        Err(o89_core::ProvisionFailed::Unborn)
    ));
}

#[test]
fn p_235_an_unappliable_intent_is_discarded_and_every_cut_boot_goes_on() {
    // An intent carrying no birth onto a unit that holds no controller key:
    // `stage_secret` refuses to write one, so it is written as bytes.
    let mut start = SimFram::fresh();
    let mut intent = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
        map::SECRET_CHANGE,
        &mut start,
    ))
    .expect("reads");
    block_on(intent.write(&mut start, SecretChange::Pending(secret(), None))).expect("written");
    let crashes = crash_at_every_step(
        &start,
        |part| {
            let (_, report) = block_on(Store::boot(part, None)).map_err(|_| ())?;
            match report.secret_recovery {
                SecretRecovery::Discarded => Ok(()),
                SecretRecovery::Unchanged | SecretRecovery::Applied => Err(()),
            }
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("the boot goes on");
            // All or nothing: not even the secret it carried.
            assert!(store.secret.present().is_none(), "cut {step}");
            assert!(store.controller.present().is_none(), "cut {step}");
        },
    )
    .expect("the discard runs uncut");
    assert!(crashes.steps > 0);
}

#[test]
fn p_235_garbage_intent_discard_cut_at_every_byte_keeps_what_the_unit_holds() {
    let mut start = drawn();
    let (before, _) = block_on(Store::boot(&mut start, None)).expect("boot");
    let state = drbg(&before);
    let at = map::LOAD_SHED_CONFIG.end();
    let len = 2 * o89_core::slot_bytes(SECRET_CHANGE_BYTES);
    block_on(start.write(at, &vec![0x55; len])).expect("garbage");
    let crashes = crash_at_every_step(
        &start,
        |part| {
            block_on(Store::boot(part, None))
                .map(|_| ())
                .map_err(|_| ())
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("retry discarded intent");
            assert!(store.secret.present() == Some(&secret()), "cut {step}");
            assert_eq!(drbg(&store), state, "cut {step}");
            let begin = usize::from(at.0);
            let end = usize::from(map::SECRET_CHANGE.end().0);
            assert!(
                part.bytes()[begin..end].iter().all(|byte| *byte == 0),
                "cut {step}"
            );
        },
    )
    .expect("garbage does not stop boot");
    assert!(crashes.steps >= len);
}

#[test]
fn p_236_label_acknowledgement_cut_at_every_byte_keeps_the_fingerprint_and_never_reseeds() {
    let mut start = SimFram::fresh();
    block_on(stage_secret(&mut start, secret(), Some(birth()), false)).expect("stage");
    let (store, _) = block_on(Store::boot(&mut start, None)).expect("apply");
    let mut generator = o89_core::Generator::new(store.drbg);
    let _ = block_on(generator.challenge(&mut start)).expect("a draw after birth");
    let (after, _) = block_on(Store::boot(&mut start, None)).expect("boot");
    let state = drbg(&after);
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
            report.boot_recorded.map_err(|_| ())
        },
        |part, step| {
            let (store, _) = block_on(Store::boot(part, None)).expect("retry boot");
            assert!(store.secret.present() == Some(&secret()), "cut {step}");
            assert_eq!(drbg(&store), state, "cut {step}: reseeded");
            let transaction = block_on(Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(
                map::SECRET_CHANGE,
                part,
            ))
            .expect("transaction");
            match transaction.present().expect("durable state") {
                SecretChange::Applied(applied, fingerprint) => {
                    assert!(*applied == secret(), "cut {step}");
                    assert!(*fingerprint == controller().fingerprint(), "cut {step}");
                }
                SecretChange::Complete => {}
                SecretChange::Pending(..) => panic!("cut {step} reverted application"),
            }
        },
    )
    .expect("acknowledgement");
    assert!(crashes.steps > 100);
}
