use super::ledger::Record;
use super::ledger::tests::{Scratch, exported, journaled};
use super::*;
use o89_core::{Address, Fram, SecretChange, Store};

/// What a reboot request does to the fake part.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reboot {
    /// The part boots on what it holds.
    Boots,
    /// The request fails and says so.
    Fails,
    /// The request comes back without the part having reset, as a lost
    /// `Reboot` on a part already at boot 1 does.
    Ignored,
}

struct FakeLink {
    bytes: Vec<u8>,
    reboot: Reboot,
    fail_readback: bool,
    reads_fail: bool,
    reboots: usize,
    stages: usize,
    birth_stages: usize,
    /// Steps left before the host is cut off: every read, write, reboot and
    /// stage after it fails, the part keeping what it holds. `None` never.
    steps: Option<usize>,
}

impl FakeLink {
    fn new() -> Self {
        Self {
            bytes: vec![0; map::END.0 as usize],
            reboot: Reboot::Boots,
            fail_readback: false,
            reads_fail: false,
            reboots: 0,
            stages: 0,
            birth_stages: 0,
            steps: None,
        }
    }

    /// Take one step, or fail as a host cut off at this point.
    fn step(&mut self) -> Result<()> {
        match self.steps {
            None => Ok(()),
            Some(0) => bail!("interrupted"),
            Some(left) => {
                self.steps = Some(left.checked_sub(1).unwrap());
                Ok(())
            }
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
        if let Err(error) = self.step() {
            return std::future::ready(Err(error));
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
        if let Err(error) = self.step() {
            return std::future::ready(Err(Refused::Bus(error)));
        }
        let start = usize::from(at.0);
        self.bytes[start..start.checked_add(bytes.len()).unwrap()].copy_from_slice(bytes);
        std::future::ready(Ok(()))
    }
}

impl SecretLink for FakeLink {
    fn reboot(&mut self) -> Result<()> {
        self.step()?;
        self.reboots = self.reboots.checked_add(1).unwrap();
        if self.reboot == Reboot::Fails {
            bail!("reboot failed");
        }
        let (_, report) = block_on(Store::boot(self, None)).map_err(|_| anyhow!("boot failed"))?;
        report
            .boot_recorded
            .map_err(|_| anyhow!("boot count failed"))?;
        self.reads_fail = self.fail_readback;
        Ok(())
    }

    fn reboot_blank(&mut self) -> Result<()> {
        self.reboots = self.reboots.checked_add(1).unwrap();
        if self.reboot == Reboot::Ignored {
            return Ok(());
        }
        let (_, report) = block_on(Store::boot(self, None)).map_err(|_| anyhow!("boot failed"))?;
        if report.boot != o89_core::BootCount::FIRST {
            bail!("the boot count did not start over");
        }
        Ok(())
    }

    /// What the firmware's mailbox op does with the body the host sends.
    fn stage_and_reboot(&mut self, body: &[u8], replace: bool) -> Result<()> {
        self.step()?;
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

/// Journal `birth()` for `secret()` as the station does before staging it.
fn drawn_by_station(ledger: &Ledger) {
    ledger
        .note_drawn(Record {
            device_id: DeviceId::new(secret().device_id_bytes()),
            fingerprint: birth().controller.fingerprint(),
        })
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
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    link.reboot = Reboot::Fails;
    let mut output = Vec::new();
    let error = run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("o89-dev store write-secret --resume"));
    assert!(output.is_empty());
    let SecretChange::Pending(staged, Some(_)) = link.transaction() else {
        panic!("pending, with the unit's birth")
    };
    link.reboot = Reboot::Boots;
    run_secret(&mut link, &ledger, None, false, true, &mut output).unwrap();
    let fingerprint = held_fingerprint(&mut link);
    assert_label(&output, staged, fingerprint);
    assert_eq!(link.stages, 1);
    assert!(matches!(link.transaction(), SecretChange::Complete));
    output.clear();
    assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn p_237_resume_after_failed_readback_does_not_reboot_or_reseed_the_generator() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    link.fail_readback = true;
    let mut output = Vec::new();
    let error = run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap_err();
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
    resume_secret(&mut link, &ledger, &mut output).unwrap();
    assert_label(&output, applied, fingerprint);
    assert_eq!(link.reboots, 1);
    let drbg_at = usize::from(map::DRBG.end().0);
    assert_eq!(link.bytes[..drbg_at], drawn[..drbg_at]);
}

#[test]
fn resume_without_a_transaction_refuses_without_output_or_reboot() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    let error = resume_secret(&mut link, &ledger, &mut output).unwrap_err();
    assert!(error.to_string().contains("no secret label to resume"));
    assert!(output.is_empty());
    assert_eq!(link.reboots, 0);
}

#[test]
fn new_writes_refuse_pending_and_applied_transactions_even_with_replace() {
    for applied in [false, true] {
        for replace in [false, true] {
            let mut link = FakeLink::new();
            let scratch = Scratch::new();
            let ledger = scratch.ledger();
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
            let error = run_secret(
                &mut link,
                &ledger,
                Some("not hex"),
                replace,
                false,
                &mut output,
            )
            .unwrap_err();
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
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        drawn_by_station(&ledger);
        staged(&mut link, secret(), Some(birth()));
        if damage_generator {
            let at = usize::from(map::EPOCH.end().0);
            link.bytes[at..usize::from(map::DRBG.end().0)].fill(0x55);
        } else {
            let mut active = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
            block_on(active.write(&mut link, Secret::new([1; 16], [3; 32]).unwrap())).unwrap();
        }
        let mut output = Vec::new();
        assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
        assert!(output.is_empty());
        assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    }
}

#[test]
fn p_236_resume_refuses_a_label_whose_controller_key_does_not_read_or_match() {
    for replace_key in [false, true] {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        drawn_by_station(&ledger);
        staged(&mut link, secret(), Some(birth()));
        if replace_key {
            let mut held =
                read::<ControllerKey, CONTROLLER_KEY_BYTES>(&mut link, map::CONTROLLER_KEY)
                    .unwrap();
            block_on(held.write(&mut link, ControllerKey::new([6; 32]).unwrap())).unwrap();
        } else {
            let at = usize::from(map::DEVICE_SECRET.end().0);
            link.bytes[at..usize::from(map::CONTROLLER_KEY.end().0)].fill(0x55);
        }
        let mut output = Vec::new();
        assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
        assert!(output.is_empty(), "no label for a key the unit cannot use");
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
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    drawn_by_station(&ledger);
    staged(&mut link, secret(), Some(birth()));
    assert!(resume_secret(&mut link, &ledger, &mut BrokenOutput).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    let mut output = Vec::new();
    resume_secret(&mut link, &ledger, &mut output).unwrap();
    assert_label(&output, secret(), birth().controller.fingerprint());
}

#[test]
fn successful_write_prints_once_and_has_nothing_to_resume() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let active = *read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET)
        .unwrap()
        .present()
        .unwrap();
    let fingerprint = held_fingerprint(&mut link);
    assert_label(&output, active, fingerprint);
    assert!(matches!(link.transaction(), SecretChange::Complete));
    output.clear();
    assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn unreadable_transactions_refuse_resume_and_new_writes_without_mutation() {
    for malformed in [false, true] {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
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
            assert!(run_secret(&mut link, &ledger, None, false, resume, &mut output).is_err());
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
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    drawn_by_station(&ledger);
    staged(&mut link, secret(), Some(birth()));
    let mut output = FailedFlush(Vec::new());
    assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    assert_label(&output.0, secret(), birth().controller.fingerprint());
}

#[test]
fn p_235_p_237_a_first_write_stages_a_controller_key_and_a_generator() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
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
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let before = held_fingerprint(&mut link);
    output.clear();
    run_secret(&mut link, &ledger, None, true, false, &mut output).unwrap();
    assert_eq!(link.birth_stages, 1);
    assert_eq!(held_fingerprint(&mut link), before);
    let label = std::str::from_utf8(&output).unwrap();
    assert!(label.contains(&hex::encode(before.as_bytes())));
}

#[test]
fn p_235_replace_on_an_unborn_part_holding_a_secret_stages_its_birth() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    // A secret with no controller key: a unit this layout is new to.
    let mut kept = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
    block_on(kept.write(&mut link, secret())).unwrap();
    let mut output = Vec::new();
    // Without --replace the held secret is protected, as on any unit.
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
    assert_eq!(link.stages, 0);
    run_secret(&mut link, &ledger, None, true, false, &mut output).unwrap();
    assert_eq!(link.birth_stages, 1);
    assert!(born(&mut link).unwrap());
    let fingerprint = held_fingerprint(&mut link);
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains(&hex::encode(fingerprint.as_bytes()))
    );
}

#[test]
fn p_237_a_born_part_whose_generator_does_not_read_is_refused_before_anything_is_staged() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let at = usize::from(map::EPOCH.end().0);
    link.bytes[at..usize::from(map::DRBG.end().0)].fill(0x55);
    let before = link.bytes.clone();
    let stages = link.stages;
    output.clear();
    let error = run_secret(&mut link, &ledger, None, true, false, &mut output).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("the generator does not read back")
    );
    assert_eq!(link.stages, stages, "nothing was staged");
    assert_eq!(link.bytes, before, "the label the unit has stays");
    assert!(output.is_empty());
}

#[test]
fn p_237_a_part_with_a_damaged_generator_is_born_and_never_reseeded() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let at = usize::from(map::EPOCH.end().0);
    link.bytes[at..usize::from(map::DRBG.end().0)].fill(0x55);
    assert!(born(&mut link).unwrap());
    let mut output = Vec::new();
    // No secret and no key: stage refuses to print a label with nothing to pin.
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
    assert_eq!(link.birth_stages, 0);
    assert!(output.is_empty());
}

#[test]
fn p_235_blank_without_yes_writes_nothing() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let before = link.bytes.clone();
    let reboots = link.reboots;
    output.clear();
    let error = run_blank(&mut link, false, &mut output).unwrap_err();
    assert!(error.to_string().contains("Pass --yes"));
    assert_eq!(link.bytes, before);
    assert_eq!(link.reboots, reboots);
    assert!(output.is_empty());
}

#[test]
fn p_235_p_237_a_part_written_under_an_earlier_map_is_blanked_and_born_again() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    // Bytes no record of this map wrote: the key and the generator read damaged.
    link.bytes.fill(0x55);
    assert!(born(&mut link).unwrap());
    let mut output = Vec::new();
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
    assert_eq!(link.stages, 0, "nothing may write over a damaged key");

    run_blank(&mut link, true, &mut output).unwrap();
    assert_eq!(link.reboots, 1);
    assert!(!born(&mut link).unwrap());
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("write-secret")
    );

    output.clear();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    assert_eq!(link.birth_stages, 1);
    let fingerprint = held_fingerprint(&mut link);
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains(&hex::encode(fingerprint.as_bytes()))
    );
}

#[test]
fn p_235_a_blank_that_does_not_read_back_stops_before_the_reboot() {
    let mut link = FakeLink::new();
    link.bytes.fill(0x55);
    link.reads_fail = true;
    let mut output = Vec::new();
    let error = run_blank(&mut link, true, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("reading back"));
    assert_eq!(link.reboots, 0);
    assert!(output.is_empty());
}

#[test]
fn p_235_a_provisioned_unit_blanks_to_an_unborn_one_whose_boot_count_starts_over() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    assert!(born(&mut link).unwrap());
    output.clear();
    run_blank(&mut link, true, &mut output).unwrap();
    assert!(!born(&mut link).unwrap());
    let held = read::<Secret, SECRET_BYTES>(&mut link, map::DEVICE_SECRET).unwrap();
    assert!(
        held.present().is_none(),
        "the printed secret went with the rest"
    );
}

#[test]
fn p_235_a_blank_whose_reboot_never_happened_is_not_reported_as_done() {
    let mut link = FakeLink::new();
    link.reboot = Reboot::Ignored;
    let mut output = Vec::new();
    let error = run_blank(&mut link, true, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("did not boot"), "{error:#}");
    assert!(output.is_empty());
}

/// The line the station exports for `secret` on a key with `fingerprint`.
fn record_line(secret: Secret, fingerprint: Fingerprint) -> String {
    format!(
        r#"{{"format":"o89-controller-record","version":1,"device_id":"{}","controller_fp":"{}"}}"#,
        hex::encode(secret.device_id_bytes()),
        hex::encode(fingerprint.as_bytes())
    )
}

fn active(link: &mut FakeLink) -> Secret {
    *read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)
        .unwrap()
        .present()
        .unwrap()
}

/// Every byte the station wrote to its export file and its journal.
fn station_files(scratch: &Scratch) -> Vec<u8> {
    let mut bytes = Vec::new();
    for name in ["units.jsonl", "units.jsonl.drawn"] {
        if let Ok(read) = std::fs::read(scratch.0.join(name)) {
            bytes.extend(read);
        }
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn p_249_a_first_write_exports_the_station_s_fingerprint_and_no_secret_byte() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let secret = active(&mut link);
    let fingerprint = held_fingerprint(&mut link);
    assert_eq!(exported(&ledger), [record_line(secret, fingerprint)]);
    let label = std::str::from_utf8(&output).unwrap();
    assert!(label.contains("record         exported to "), "{label}");

    let files = station_files(&scratch);
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
    let encoded = secret.encode();
    let printed = &encoded[DEVICE_ID_BYTES..];
    let payload = pairing_payload(
        &secret.device_id_bytes(),
        printed.try_into().unwrap(),
        &fingerprint,
    );
    for (what, bytes) in [
        ("private key", &key[..]),
        ("generator state", &seed[..]),
        ("printed secret", printed),
    ] {
        assert!(!contains(&files, bytes), "{what} written raw");
        assert!(
            !contains(&files, hex::encode(bytes).as_bytes()),
            "{what} written as hex"
        );
    }
    assert!(!contains(&files, payload.as_bytes()), "pairing payload");
    assert!(!contains(&files, b"km43:"), "pairing payload");
}

#[test]
fn p_249_resume_of_a_pending_or_applied_write_exports_the_same_record_once() {
    for pending in [true, false] {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        if pending {
            link.reboot = Reboot::Fails;
        } else {
            link.fail_readback = true;
        }
        let mut output = Vec::new();
        assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
        assert!(
            exported(&ledger).is_empty(),
            "nothing before the part confirms"
        );
        link.reboot = Reboot::Boots;
        link.fail_readback = false;
        link.reads_fail = false;
        resume_secret(&mut link, &ledger, &mut output).unwrap();
        let expected = record_line(active(&mut link), held_fingerprint(&mut link));
        assert_eq!(exported(&ledger), std::slice::from_ref(&expected));
        assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
        assert_eq!(exported(&ledger), [expected]);
    }
}

#[test]
fn p_249_a_label_resumed_after_its_record_was_exported_adds_no_second_record() {
    struct FailedFlush;
    impl std::io::Write for FailedFlush {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut FailedFlush).is_err());
    let expected = record_line(active(&mut link), held_fingerprint(&mut link));
    assert_eq!(exported(&ledger), std::slice::from_ref(&expected));
    let mut output = Vec::new();
    resume_secret(&mut link, &ledger, &mut output).unwrap();
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("record         already in ")
    );
    assert_eq!(exported(&ledger), [expected]);
}

#[test]
fn p_249_a_birth_that_never_reached_the_part_leaves_no_exportable_record() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    // Cut off at the stage itself: every read before it counted on a twin.
    let before_stage = {
        let mut counter = FakeLink::new();
        counter.steps = Some(usize::MAX);
        ensure_no_transaction(&mut counter).unwrap();
        let _ = generate_secret(&mut counter, None, false).unwrap();
        let _ = born(&mut counter).unwrap();
        usize::MAX - counter.steps.unwrap()
    };
    link.steps = Some(before_stage);
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
    assert_eq!(link.stages, 0);
    assert!(output.is_empty());
    assert_eq!(
        std::fs::read_to_string(scratch.0.join("units.jsonl.drawn"))
            .unwrap()
            .lines()
            .count(),
        1,
        "the draw was journaled before the stage"
    );
    link.steps = None;
    assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
    assert!(exported(&ledger).is_empty());
    // The next write draws again and exports only what the part took.
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    assert_eq!(
        exported(&ledger),
        [record_line(active(&mut link), held_fingerprint(&mut link))]
    );
}

/// Run a first write cut off after `steps` steps, then resume it to the end.
/// Returns the first write's result.
fn cut_then_resume(link: &mut FakeLink, ledger: &Ledger, steps: usize) -> Result<()> {
    link.steps = Some(steps);
    let first = run_secret(link, ledger, None, false, false, &mut Vec::new());
    link.steps = None;
    first
}

#[test]
fn p_249_a_write_cut_off_at_every_step_exports_the_station_s_record_once_or_not_at_all() {
    let mut completed = false;
    for steps in 0..10_000 {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        let first = cut_then_resume(&mut link, &ledger, steps);
        let drawn: Vec<String> = std::fs::read_to_string(scratch.0.join("units.jsonl.drawn"))
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default();
        assert!(drawn.len() <= 1, "step {steps}");
        if first.is_ok() {
            assert_eq!(
                exported(&ledger),
                [record_line(active(&mut link), held_fingerprint(&mut link))]
            );
            completed = true;
            break;
        }
        let mut output = Vec::new();
        let transaction = block_on(Transaction::read(map::SECRET_CHANGE, &mut link)).unwrap();
        match transaction.held() {
            Held::Absent => {
                // The birth never reached the part: nothing to resume and
                // nothing exported, whatever the journal holds.
                assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
                assert!(exported(&ledger).is_empty(), "step {steps}");
            }
            Held::Present(SecretChange::Pending(..) | SecretChange::Applied(..)) => {
                resume_secret(&mut link, &ledger, &mut output)
                    .unwrap_or_else(|error| panic!("step {steps}: {error:#}"));
                let expected = record_line(active(&mut link), held_fingerprint(&mut link));
                // The record names the key the station drew and journaled.
                assert_eq!(
                    drawn,
                    [expected.replace("o89-controller-record", "o89-controller-drawn")],
                    "step {steps}"
                );
                assert_eq!(
                    exported(&ledger),
                    std::slice::from_ref(&expected),
                    "step {steps}"
                );
                assert!(resume_secret(&mut link, &ledger, &mut output).is_err());
                assert_eq!(exported(&ledger), [expected], "step {steps}");
            }
            other => panic!("step {steps}: {other:?}"),
        }
    }
    assert!(completed, "a write with room for every step completes");
}

#[test]
fn p_249_a_resume_cut_off_at_every_step_still_exports_one_record() {
    let mut completed = false;
    for steps in 0..10_000 {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        link.reboot = Reboot::Fails;
        assert!(run_secret(&mut link, &ledger, None, false, false, &mut Vec::new()).is_err());
        link.reboot = Reboot::Boots;
        link.steps = Some(steps);
        let resumed = resume_secret(&mut link, &ledger, &mut Vec::new());
        link.steps = None;
        if resumed.is_err() {
            assert!(exported(&ledger).len() <= 1, "step {steps}");
            resume_secret(&mut link, &ledger, &mut Vec::new())
                .unwrap_or_else(|error| panic!("step {steps}: {error:#}"));
        } else {
            completed = true;
        }
        assert_eq!(
            exported(&ledger),
            [record_line(active(&mut link), held_fingerprint(&mut link))],
            "step {steps}"
        );
        if completed {
            break;
        }
    }
    assert!(completed, "a resume with room for every step completes");
}

#[test]
fn p_249_a_part_that_applied_a_key_the_station_did_not_draw_fails_loudly_and_exports_nothing() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    // The station drew one key for this device id; the part took another.
    ledger
        .note_drawn(Record {
            device_id: DeviceId::new(secret().device_id_bytes()),
            fingerprint: ControllerKey::new([9; 32]).unwrap().fingerprint(),
        })
        .unwrap();
    staged(&mut link, secret(), Some(birth()));
    let mut output = Vec::new();
    let error = resume_secret(&mut link, &ledger, &mut output).unwrap_err();
    assert!(format!("{error:#}").contains("did not draw"), "{error:#}");
    assert!(
        output.is_empty(),
        "no label for a key the station cannot vouch for"
    );
    assert!(exported(&ledger).is_empty());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
}

#[test]
fn p_249_replace_takes_the_fingerprint_from_the_station_s_earlier_record() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, false, false, &mut output).unwrap();
    let first = active(&mut link);
    let fingerprint = held_fingerprint(&mut link);
    // The same device id: the record it has already names the key.
    let same = hex::encode(first.device_id_bytes());
    run_secret(&mut link, &ledger, Some(&same), true, false, &mut output).unwrap();
    assert_eq!(exported(&ledger), [record_line(first, fingerprint)]);
    // A new device id on the kept key: the earlier record is the source.
    output.clear();
    run_secret(&mut link, &ledger, None, true, false, &mut output).unwrap();
    let second = active(&mut link);
    assert_ne!(second.device_id_bytes(), first.device_id_bytes());
    assert_eq!(
        exported(&ledger),
        [
            record_line(first, fingerprint),
            record_line(second, fingerprint)
        ]
    );
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("record         exported to ")
    );
}

#[test]
fn p_249_replace_on_a_unit_the_station_has_no_record_of_exports_nothing_and_says_why() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    // Born elsewhere: its key reached the part and its label was printed
    // without this station's ledger.
    staged(&mut link, secret(), Some(birth()));
    let mut transaction = block_on(Transaction::read(map::SECRET_CHANGE, &mut link)).unwrap();
    block_on(transaction.write(&mut link, SecretChange::Complete)).unwrap();
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, None, true, false, &mut output).unwrap();
    let label = std::str::from_utf8(&output).unwrap();
    assert!(label.contains("record         none exported"), "{label}");
    assert!(label.contains("does not take the part's word"), "{label}");
    assert_label(&output, active(&mut link), birth().controller.fingerprint());
    assert!(exported(&ledger).is_empty());
    assert!(!scratch.0.join("units.jsonl").exists());
    assert!(matches!(link.transaction(), SecretChange::Complete));
}

#[test]
fn p_249_a_device_id_exported_with_another_fingerprint_is_refused_before_staging() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let id = "0123456789abcdef0123456789abcdef";
    let mut output = Vec::new();
    run_secret(&mut link, &ledger, Some(id), false, false, &mut output).unwrap();
    let before = exported(&ledger);
    // A unit blanked and born again under the same device id draws a new
    // key; the record the cloud holds for that id names the old one.
    run_blank(&mut link, true, &mut output).unwrap();
    let stages = link.stages;
    output.clear();
    let error = run_secret(&mut link, &ledger, Some(id), false, false, &mut output).unwrap_err();
    assert!(error.to_string().contains("second fingerprint"), "{error}");
    assert_eq!(link.stages, stages, "nothing staged");
    assert!(!born(&mut link).unwrap());
    assert!(output.is_empty());
    assert_eq!(exported(&ledger), before);

    // A replace naming another unit's exported id on a different key.
    let other = FakeLink::new();
    let mut other = other;
    run_secret(&mut other, &ledger, None, false, false, &mut output).unwrap();
    let stages = other.stages;
    let before = exported(&ledger);
    let error = run_secret(&mut other, &ledger, Some(id), true, false, &mut output).unwrap_err();
    assert!(error.to_string().contains("second fingerprint"), "{error}");
    assert_eq!(other.stages, stages, "nothing staged");
    assert_eq!(exported(&ledger), before);
}

#[test]
fn p_249_an_export_that_cannot_be_written_prints_no_label_and_stays_resumable() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let mut output = Vec::new();
    link.reboot = Reboot::Fails;
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
    link.reboot = Reboot::Boots;
    // The export file stops being writable once the birth is staged.
    std::fs::create_dir(scratch.0.join("units.jsonl")).unwrap();
    let error = resume_secret(&mut link, &ledger, &mut output).unwrap_err();
    assert!(
        format!("{error:#}").contains("no label printed"),
        "{error:#}"
    );
    assert!(output.is_empty());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    std::fs::remove_dir(scratch.0.join("units.jsonl")).unwrap();
    resume_secret(&mut link, &ledger, &mut output).unwrap();
    assert_eq!(
        exported(&ledger),
        [record_line(active(&mut link), held_fingerprint(&mut link))]
    );
}

#[test]
fn p_249_a_resume_against_another_export_file_prints_no_label_and_stays_resumable() {
    let mut link = FakeLink::new();
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    link.reboot = Reboot::Fails;
    assert!(run_secret(&mut link, &ledger, None, false, false, &mut Vec::new()).is_err());
    link.reboot = Reboot::Boots;
    // A typo, or the same relative name from another directory.
    let elsewhere = Scratch::new();
    let wrong = elsewhere.ledger();
    let mut output = Vec::new();
    let error = resume_secret(&mut link, &wrong, &mut output).unwrap_err();
    assert!(
        format!("{error:#}").contains("resume with the --export file"),
        "{error:#}"
    );
    assert!(output.is_empty(), "no label");
    assert!(exported(&wrong).is_empty());
    assert!(matches!(link.transaction(), SecretChange::Applied(..)));
    // The right file still completes it, once.
    resume_secret(&mut link, &ledger, &mut output).unwrap();
    assert_eq!(
        exported(&ledger),
        [record_line(active(&mut link), held_fingerprint(&mut link))]
    );
}

#[test]
fn p_249_a_journal_that_cannot_be_read_or_written_stages_nothing() {
    for torn in [true, false] {
        let mut link = FakeLink::new();
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        let journal = scratch.0.join("units.jsonl.drawn");
        if torn {
            std::fs::write(&journal, r#"{"format":"o89-contr"#).unwrap();
        } else {
            std::fs::create_dir(&journal).unwrap();
        }
        let mut output = Vec::new();
        assert!(run_secret(&mut link, &ledger, None, false, false, &mut output).is_err());
        assert_eq!(link.stages, 0, "nothing staged");
        assert!(!born(&mut link).unwrap());
        assert!(output.is_empty());
        assert!(exported(&ledger).is_empty());
        if torn {
            assert_eq!(
                std::fs::read_to_string(&journal).unwrap(),
                r#"{"format":"o89-contr"#
            );
        }
    }
}

#[test]
fn p_249_a_device_id_awaiting_resume_on_one_unit_is_refused_to_another_before_staging() {
    let scratch = Scratch::new();
    let ledger = scratch.ledger();
    let id = "0123456789abcdef0123456789abcdef";
    let mut first = FakeLink::new();
    first.reboot = Reboot::Fails;
    assert!(run_secret(&mut first, &ledger, Some(id), false, false, &mut Vec::new()).is_err());
    first.reboot = Reboot::Boots;
    let mut second = FakeLink::new();
    let mut output = Vec::new();
    let error = run_secret(&mut second, &ledger, Some(id), false, false, &mut output).unwrap_err();
    assert!(
        error.to_string().contains("choose another device id"),
        "{error}"
    );
    assert_eq!(second.stages, 0);
    assert!(output.is_empty());
    assert_eq!(journaled(&ledger).len(), 1);
    // The first unit's record is still the one exported.
    resume_secret(&mut first, &ledger, &mut output).unwrap();
    assert_eq!(
        exported(&ledger),
        [record_line(
            active(&mut first),
            held_fingerprint(&mut first)
        )]
    );
}
