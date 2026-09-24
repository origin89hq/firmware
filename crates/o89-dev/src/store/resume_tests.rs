use super::*;
use o89_core::{Address, Fram, SecretChange, Store};

struct FakeLink {
    bytes: [u8; map::END.0 as usize],
    fail_reboot: bool,
    fail_readback: bool,
    reads_fail: bool,
    reboots: usize,
    stages: usize,
}

impl FakeLink {
    fn new() -> Self {
        Self {
            bytes: [0; map::END.0 as usize],
            fail_reboot: false,
            fail_readback: false,
            reads_fail: false,
            reboots: 0,
            stages: 0,
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

    fn stage_and_reboot(&mut self, secret: Secret, replace: bool) -> Result<()> {
        self.stages = self.stages.checked_add(1).unwrap();
        block_on(o89_core::stage_secret(self, secret, replace))
            .map_err(|_| anyhow!("stage failed"))?;
        self.reboot()
    }
}

fn secret() -> Secret {
    Secret::new([1; 16], [2; 32]).unwrap()
}

fn assert_label(output: &[u8], secret: Secret) {
    let label = std::str::from_utf8(output).unwrap();
    let encoded = secret.encode();
    let payload = pairing_payload(&secret.device_id_bytes(), encoded[16..].try_into().unwrap());
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
    let SecretChange::Pending(staged) = link.transaction() else {
        panic!("pending")
    };
    link.fail_reboot = false;
    run_secret(&mut link, None, false, true, &mut output).unwrap();
    assert_label(&output, staged);
    assert_eq!(link.stages, 1);
    assert!(matches!(link.transaction(), SecretChange::Complete));
    output.clear();
    assert!(resume_secret(&mut link, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn resume_after_failed_readback_does_not_reboot_or_reset_the_counter() {
    let mut link = FakeLink::new();
    link.fail_readback = true;
    let mut output = Vec::new();
    let error = run_secret(&mut link, None, false, false, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("o89-dev store write-secret --resume"));
    assert!(output.is_empty());
    link.reads_fail = false;
    let SecretChange::Applied(applied) = link.transaction() else {
        panic!("applied")
    };
    let (mut store, _) = block_on(Store::boot(&mut link, None)).unwrap();
    assert_eq!(
        block_on(store.challenges.mint(&mut link))
            .unwrap()
            .counter(),
        1
    );
    resume_secret(&mut link, &mut output).unwrap();
    assert_label(&output, applied);
    assert_eq!(link.reboots, 1);
    assert_eq!(
        block_on(store.challenges.mint(&mut link))
            .unwrap()
            .counter(),
        2
    );
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
            block_on(o89_core::stage_secret(&mut link, secret(), false)).unwrap();
            if applied {
                link.reboot().unwrap();
            }
            let before = link.bytes;
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
fn resume_refuses_mismatched_applied_secret_or_unknown_counter() {
    for damage_counter in [false, true] {
        let mut link = FakeLink::new();
        link.stage_and_reboot(secret(), false).unwrap();
        if damage_counter {
            link.bytes[32..72].fill(0x55);
        } else {
            let mut active = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
            block_on(active.write(&mut link, Secret::new([1; 16], [3; 32]).unwrap())).unwrap();
        }
        let mut output = Vec::new();
        assert!(resume_secret(&mut link, &mut output).is_err());
        assert!(output.is_empty());
        assert!(matches!(link.transaction(), SecretChange::Applied(_)));
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
    link.stage_and_reboot(secret(), false).unwrap();
    assert!(resume_secret(&mut link, &mut BrokenOutput).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(_)));
    let mut output = Vec::new();
    resume_secret(&mut link, &mut output).unwrap();
    assert_label(&output, secret());
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
    assert_label(&output, active);
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
        let before = link.bytes;
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
    link.stage_and_reboot(secret(), false).unwrap();
    let mut output = FailedFlush(Vec::new());
    assert!(resume_secret(&mut link, &mut output).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(_)));
    assert_label(&output.0, secret());
}
