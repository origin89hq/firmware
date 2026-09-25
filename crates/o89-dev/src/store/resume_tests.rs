use super::*;
use o89_core::{Address, Fram, SecretChange, Store};

struct FakeLink {
    bytes: Vec<u8>,
    fail_reboot: bool,
    fail_readback: bool,
    reads_fail: bool,
    reboots: usize,
    stages: usize,
    birth_stages: usize,
}

impl FakeLink {
    fn new() -> Self {
        Self {
            bytes: vec![0; map::END.0 as usize],
            fail_reboot: false,
            fail_readback: false,
            reads_fail: false,
            reboots: 0,
            stages: 0,
            birth_stages: 0,
        }
    }

    fn transaction(&mut self) -> SecretChange {
        *block_on(Transaction::read(map::SECRET_CHANGE, self))
            .unwrap()
            .present()
            .unwrap()
    }
}

impl Fram for FakeLink {
    type Error = anyhow::Error;

    fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<()>> {
        if self.reads_fail {
            return std::future::ready(Err(anyhow!("read-back failed")));
        }
        let start = usize::from(at.0);
        into.copy_from_slice(&self.bytes[start..start.checked_add(into.len()).unwrap()]);
        std::future::ready(Ok(()))
    }

    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<Self::Error>>> {
        let start = usize::from(at.0);
        self.bytes[start..start.checked_add(bytes.len()).unwrap()].copy_from_slice(bytes);
        std::future::ready(Ok(()))
    }
}

impl SecretLink for FakeLink {
    fn reboot(&mut self) -> Result<()> {
        self.reboots = self.reboots.checked_add(1).unwrap();
        if self.fail_reboot {
            bail!("reboot failed");
        }
        let (_, report) = block_on(Store::boot(self, None)).map_err(|_| anyhow!("boot failed"))?;
        report
            .boot_recorded
            .map_err(|_| anyhow!("boot count failed"))?;
        self.reads_fail = self.fail_readback;
        Ok(())
    }

    /// What the firmware's mailbox op does with the body the host sends.
    fn stage_and_reboot(&mut self, body: &[u8], replace: bool) -> Result<()> {
        self.stages = self.stages.checked_add(1).unwrap();
        let Ok(SecretChange::Pending(secret, birth)) =
            SecretChange::decode(body.try_into().unwrap())
        else {
            bail!("not a pending transaction");
        };
        if birth.is_some() {
            self.birth_stages = self.birth_stages.checked_add(1).unwrap();
        }
        block_on(o89_core::stage_secret(self, secret, birth, replace))
            .map_err(|why| anyhow!("stage failed: {why:?}"))?;
        self.reboot()
    }
}

fn secret() -> Secret {
    Secret::new([1; 16], [2; 32]).unwrap()
}

fn birth() -> o89_core::Birth {
    o89_core::Birth {
        controller: ControllerKey::new([4; 32]).unwrap(),
        drbg: DrbgState::new([5; 32]).unwrap(),
    }
}

/// Stage `secret` as the firmware would receive it, then reboot.
fn staged(link: &mut FakeLink, secret: Secret, birth: Option<o89_core::Birth>) {
    link.stage_and_reboot(&SecretChange::Pending(secret, birth).encode(), false)
        .unwrap();
}

/// The fingerprint of the controller key the part holds.
fn held_fingerprint(link: &mut FakeLink) -> Fingerprint {
    read::<ControllerKey, CONTROLLER_KEY_BYTES>(link, map::CONTROLLER_KEY)
        .unwrap()
        .present()
        .unwrap()
        .fingerprint()
}

fn assert_label(output: &[u8], secret: Secret, fingerprint: Fingerprint) {
    let label = std::str::from_utf8(output).unwrap();
    let encoded = secret.encode();
    let payload = pairing_payload(
        &secret.device_id_bytes(),
        encoded[16..].try_into().unwrap(),
        &fingerprint,
    );
    assert!(label.contains(&format!(
        "device id      {}\n",
        hex::encode(secret.device_id_bytes())
    )));
    assert!(label.contains(&format!("printed secret {}\n", hex::encode(&encoded[16..]))));
    assert_eq!(label.matches(&payload).count(), 1);
    assert!(label.contains(&pairing_qr(&payload).unwrap()));
    assert_eq!(
        label
            .matches("shown once: it goes on the unit's label and nowhere else")
            .count(),
        1
    );
}

#[test]
fn resume_after_failed_reboot_prints_the_staged_secret_once() {
    let mut link = FakeLink::new();
    link.fail_reboot = true;
    let mut output = Vec::new();
    let error = run_secret(&mut link, None, false, false, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("o89-dev store write-secret --resume"));
    assert!(output.is_empty());
    let SecretChange::Pending(staged, Some(_)) = link.transaction() else {
        panic!("pending, with the unit's birth")
    };
    link.fail_reboot = false;
    run_secret(&mut link, None, false, true, &mut output).unwrap();
    let fingerprint = held_fingerprint(&mut link);
    assert_label(&output, staged, fingerprint);
    assert_eq!(link.stages, 1);
    assert!(matches!(link.transaction(), SecretChange::Complete));
    output.clear();
    assert!(resume_secret(&mut link, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn p_237_resume_after_failed_readback_does_not_reboot_or_reseed_the_generator() {
    let mut link = FakeLink::new();
    link.fail_readback = true;
    let mut output = Vec::new();
    let error = run_secret(&mut link, None, false, false, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("o89-dev store write-secret --resume"));
    assert!(output.is_empty());
    link.reads_fail = false;
    let SecretChange::Applied(applied, fingerprint) = link.transaction() else {
        panic!("applied")
    };
    // A draw after the boot moves the generator on; resuming must not put
    // the first state back.
    let (store, _) = block_on(Store::boot(&mut link, None)).unwrap();
    let mut generator = o89_core::Generator::new(store.drbg);
    let _ = block_on(generator.draw(&mut link)).unwrap();
    let drawn = link.bytes.clone();
    resume_secret(&mut link, &mut output).unwrap();
    assert_label(&output, applied, fingerprint);
    assert_eq!(link.reboots, 1);
    let drbg_at = usize::from(map::DRBG.end().0);
    assert_eq!(link.bytes[..drbg_at], drawn[..drbg_at]);
}

#[test]
fn resume_without_a_transaction_refuses_without_output_or_reboot() {
    let mut link = FakeLink::new();
    let mut output = Vec::new();
    let error = resume_secret(&mut link, &mut output).unwrap_err();
    assert!(error.to_string().contains("no secret label to resume"));
    assert!(output.is_empty());
    assert_eq!(link.reboots, 0);
}

#[test]
fn new_writes_refuse_pending_and_applied_transactions_even_with_replace() {
    for applied in [false, true] {
        for replace in [false, true] {
            let mut link = FakeLink::new();
            block_on(o89_core::stage_secret(
                &mut link,
                secret(),
                Some(birth()),
                false,
            ))
            .unwrap();
            if applied {
                link.reboot().unwrap();
            }
            let before = link.bytes.clone();
            let mut output = Vec::new();
            let error =
                run_secret(&mut link, Some("not hex"), replace, false, &mut output).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("o89-dev store write-secret --resume")
            );
            assert_eq!(link.bytes, before);
            assert_eq!(link.stages, 0);
            assert!(output.is_empty());
        }
    }
}

#[test]
fn resume_refuses_mismatched_applied_secret_or_unreadable_generator() {
    for damage_generator in [false, true] {
        let mut link = FakeLink::new();
        staged(&mut link, secret(), Some(birth()));
        if damage_generator {
            let at = usize::from(map::EPOCH.end().0);
            link.bytes[at..usize::from(map::DRBG.end().0)].fill(0x55);
        } else {
            let mut active = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
            block_on(active.write(&mut link, Secret::new([1; 16], [3; 32]).unwrap())).unwrap();
        }
        let mut output = Vec::new();
        assert!(resume_secret(&mut link, &mut output).is_err());
        assert!(output.is_empty());
        assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    }
}

#[test]
fn failed_output_keeps_the_same_label_resumable() {
    struct BrokenOutput;
    impl std::io::Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut link = FakeLink::new();
    staged(&mut link, secret(), Some(birth()));
    assert!(resume_secret(&mut link, &mut BrokenOutput).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    let mut output = Vec::new();
    resume_secret(&mut link, &mut output).unwrap();
    assert_label(&output, secret(), birth().controller.fingerprint());
}

#[test]
fn successful_write_prints_once_and_has_nothing_to_resume() {
    let mut link = FakeLink::new();
    let mut output = Vec::new();
    run_secret(&mut link, None, false, false, &mut output).unwrap();
    let active = *read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET)
        .unwrap()
        .present()
        .unwrap();
    let fingerprint = held_fingerprint(&mut link);
    assert_label(&output, active, fingerprint);
    assert!(matches!(link.transaction(), SecretChange::Complete));
    output.clear();
    assert!(resume_secret(&mut link, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn unreadable_transactions_refuse_resume_and_new_writes_without_mutation() {
    for malformed in [false, true] {
        let mut link = FakeLink::new();
        let start = usize::from(map::LOAD_SHED_CONFIG.end().0);
        link.bytes[start..].fill(0x55);
        if malformed {
            let mut bytes = [0; o89_core::SECRET_CHANGE_BYTES];
            bytes[0] = 3;
            let _ =
                block_on(map::SECRET_CHANGE.write(&mut link, o89_core::Position::Start, &bytes))
                    .unwrap();
        }
        let before = link.bytes.clone();
        for resume in [false, true] {
            let mut output = Vec::new();
            assert!(run_secret(&mut link, None, false, resume, &mut output).is_err());
            assert!(output.is_empty());
            assert_eq!(link.bytes, before);
            assert_eq!(link.reboots, 0);
            assert_eq!(link.stages, 0);
        }
    }
}

#[test]
fn failed_flush_does_not_acknowledge_the_label() {
    struct FailedFlush(Vec<u8>);
    impl std::io::Write for FailedFlush {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let mut link = FakeLink::new();
    staged(&mut link, secret(), Some(birth()));
    let mut output = FailedFlush(Vec::new());
    assert!(resume_secret(&mut link, &mut output).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    assert_label(&output.0, secret(), birth().controller.fingerprint());
}

#[test]
fn p_235_p_237_a_first_write_stages_a_controller_key_and_a_generator() {
    let mut link = FakeLink::new();
    let mut output = Vec::new();
    run_secret(&mut link, None, false, false, &mut output).unwrap();
    assert_eq!(link.birth_stages, 1);
    assert!(born(&mut link).unwrap());
    let label = std::str::from_utf8(&output).unwrap();
    let fingerprint = held_fingerprint(&mut link);
    assert!(label.contains(&hex::encode(fingerprint.as_bytes())));
    // Nothing printed is the private key or the seed.
    let key = read::<ControllerKey, CONTROLLER_KEY_BYTES>(&mut link, map::CONTROLLER_KEY)
        .unwrap()
        .present()
        .unwrap()
        .encode();
    let seed = read::<DrbgState, DRBG_BYTES>(&mut link, map::DRBG)
        .unwrap()
        .present()
        .unwrap()
        .encode();
    assert!(!label.contains(&hex::encode(key)));
    assert!(!label.contains(&hex::encode(seed)));
}

#[test]
fn p_235_a_born_part_stages_no_birth_and_replace_keeps_the_fingerprint() {
    let mut link = FakeLink::new();
    let mut output = Vec::new();
    run_secret(&mut link, None, false, false, &mut output).unwrap();
    let before = held_fingerprint(&mut link);
    output.clear();
    run_secret(&mut link, None, true, false, &mut output).unwrap();
    assert_eq!(link.birth_stages, 1);
    assert_eq!(held_fingerprint(&mut link), before);
    let label = std::str::from_utf8(&output).unwrap();
    assert!(label.contains(&hex::encode(before.as_bytes())));
}

#[test]
fn p_235_replace_on_an_unborn_part_is_refused_before_anything_is_staged() {
    let mut link = FakeLink::new();
    // A secret with no controller key: a unit this layout is new to.
    let mut kept = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
    block_on(kept.write(&mut link, secret())).unwrap();
    let before = link.bytes.clone();
    let mut output = Vec::new();
    let error = run_secret(&mut link, None, true, false, &mut output).unwrap_err();
    assert!(error.to_string().contains("--replace is for a born unit"));
    assert_eq!(link.bytes, before);
    assert_eq!(link.stages, 0);
    assert!(output.is_empty());
}

#[test]
fn p_237_a_part_with_a_damaged_generator_is_born_and_never_reseeded() {
    let mut link = FakeLink::new();
    let at = usize::from(map::EPOCH.end().0);
    link.bytes[at..usize::from(map::DRBG.end().0)].fill(0x55);
    assert!(born(&mut link).unwrap());
    let mut output = Vec::new();
    // No secret and no key: stage refuses to print a label with nothing to pin.
    assert!(run_secret(&mut link, None, false, false, &mut output).is_err());
    assert_eq!(link.birth_stages, 0);
    assert!(output.is_empty());
}
