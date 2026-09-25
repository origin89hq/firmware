//! The store from the host's side: every record read with the `Kept` the
//! firmware reads with. Epoch writes use the same record seam; secret writes
//! stage a firmware transaction, reboot, and verify it before printing the label.
//!
//! On a unit's first transaction the host also draws the controller key and
//! the generator's first state from the operating system's generator (P-235,
//! P-237). Both go to the controller in the staged transaction and nowhere
//! else: they are never printed, never written to disk, and the buffers that
//! held them are cleared once the transaction is staged. What the label
//! prints is the fingerprint the controller wrote into the applied
//! transaction, so a resumed label never needs the private key (P-236).

use anyhow::{Context, Result, anyhow, bail};
use embassy_futures::block_on;
use km43::{ClientId, Epoch, Fingerprint};
use o89_core::Address;
use o89_core::mailbox::DATA_BYTES;
use o89_core::{
    BOOT_COUNT_BYTES, Birth, Body, BootCount, COMMS_RELEASE_BYTES, CONTROLLER_KEY_BYTES, Clients,
    CommsRelease, ControllerKey, DEVICE_ID_BYTES, DRBG_BYTES, DrbgState, EPOCH_BYTES, Held, Kept,
    NETWORK_BYTES, Network, PANIC_RECORD_BYTES, PRINTED_SECRET_BYTES, PanicRecord,
    RUN_REASON_BYTES, Refused, RunReason, SECRET_BYTES, Secret, SecretChange, WRITE_VOLUME_BYTES,
    WriteVolume, map,
};
use zeroize::{Zeroize as _, Zeroizing};

use crate::link::Link;

/// Every record, decoded, one line each. Never a key, a seed or an admission
/// key: only whether each is there.
pub fn show(link: &mut Link) -> Result<()> {
    show_into(link, &mut std::io::stdout().lock())
}

fn show_into(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    out: &mut impl std::io::Write,
) -> Result<()> {
    let secret = read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)?;
    match secret.held() {
        Held::Present(secret) => writeln!(
            out,
            "secret      Present, device id {}",
            hex::encode(secret.device_id_bytes())
        )?,
        Held::Absent => writeln!(out, "secret      Absent")?,
        Held::Corrupt => writeln!(out, "secret      Corrupt")?,
        Held::Malformed(at) => writeln!(out, "secret      Malformed({at:?})")?,
    }
    let controller = read::<ControllerKey, CONTROLLER_KEY_BYTES>(link, map::CONTROLLER_KEY)?;
    match controller.held() {
        Held::Present(key) => writeln!(
            out,
            "controller  Present, fingerprint {}",
            hex::encode(key.fingerprint().as_bytes())
        )?,
        Held::Absent => writeln!(out, "controller  Absent")?,
        Held::Corrupt => writeln!(out, "controller  Corrupt")?,
        Held::Malformed(at) => writeln!(out, "controller  Malformed({at:?})")?,
    }
    let drbg = read::<DrbgState, DRBG_BYTES>(link, map::DRBG)?;
    writeln!(
        out,
        "drbg        {}",
        match drbg.held() {
            Held::Present(_) => "Present".to_owned(),
            Held::Absent => "Absent".to_owned(),
            Held::Corrupt => "Corrupt".to_owned(),
            Held::Malformed(at) => format!("Malformed({at:?})"),
        }
    )?;
    line(out, "epoch", &read::<Epoch, EPOCH_BYTES>(link, map::EPOCH)?)?;
    line(
        out,
        "boots",
        &read::<BootCount, BOOT_COUNT_BYTES>(link, map::BOOT_COUNT)?,
    )?;
    line(
        out,
        "volume",
        &read::<WriteVolume, WRITE_VOLUME_BYTES>(link, map::WRITE_VOLUME)?,
    )?;
    line(
        out,
        "run",
        &read::<RunReason, RUN_REASON_BYTES>(link, map::RUN_REASON)?,
    )?;
    line(
        out,
        "panics",
        &read::<PanicRecord, PANIC_RECORD_BYTES>(link, map::PANIC_RECORD)?,
    )?;
    line(
        out,
        "release",
        &read::<CommsRelease, COMMS_RELEASE_BYTES>(link, map::COMMS_RELEASE)?,
    )?;
    line(
        out,
        "network",
        &read::<Network, NETWORK_BYTES>(link, map::NETWORK)?,
    )?;
    let clients = block_on(Clients::read(link))?;
    for id in (1u32..).map_while(ClientId::new).take(o89_core::SLOTS) {
        // `KeyRecord`'s `Debug` leaves the admission key out.
        if let (Some(key), Some(mark)) = (clients.key(id), clients.mark(id)) {
            writeln!(
                out,
                "slot {:<6} {:?}, mark {:?}",
                id.get(),
                key.held(),
                mark.held()
            )?;
        }
    }
    line(out, "dedup", clients.commands())?;
    Ok(())
}

fn read<T: Body<N>, const N: usize>(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    record: o89_core::Record<N>,
) -> Result<Kept<T, N>> {
    block_on(Kept::<T, N>::read(record, link))
}

fn line<T: Body<N> + core::fmt::Debug, const N: usize>(
    out: &mut impl std::io::Write,
    name: &str,
    kept: &Kept<T, N>,
) -> Result<()> {
    writeln!(out, "{name:<11} {:?}", kept.held())?;
    Ok(())
}

/// Bytes from the operating system's generator, whose error is not one
/// `anyhow` takes as it is: it does not implement the standard trait
/// without `std`, which the crate keeps off.
fn fill(into: &mut [u8]) -> Result<()> {
    getrandom::fill(into).map_err(|error| anyhow!("the operating system's generator: {error}"))
}

fn refused(refused: Refused<anyhow::Error>) -> anyhow::Error {
    match refused {
        Refused::SupplyFalling => anyhow!("refused: the supply is falling"),
        Refused::AtTheCeiling => anyhow!("refused: the record's sequence is at its ceiling"),
        Refused::Bus(error) => error,
    }
}

/// Write the epoch, only ever upward.
pub fn write_epoch(link: &mut Link, raw: u32) -> Result<()> {
    let epoch = Epoch::new(raw).context("zero is not an epoch")?;
    let mut kept = read::<Epoch, EPOCH_BYTES>(link, map::EPOCH)?;
    match kept.held() {
        Held::Present(held) if *held >= epoch => bail!(
            "the part holds epoch {}; a step back would retire nothing and repeat enrolment names",
            held.get()
        ),
        Held::Present(_) | Held::Absent | Held::Corrupt | Held::Malformed(_) => {}
    }
    block_on(kept.write(link, epoch)).map_err(refused)?;
    println!("epoch {raw} written");
    Ok(())
}

/// Zero every byte the map names, read each back, and reboot onto a store
/// that holds nothing. The controller key, the generator, the printed secret
/// and every enrolment go with it: the unit is a new one, born again by
/// `write-secret`, and its old label pairs with nothing. It exists because
/// nothing else may write over a key or a generator that reads as damaged
/// (P-235, P-237), and a part written under an earlier map reads that way.
pub fn blank(link: &mut Link, yes: bool) -> Result<()> {
    run_blank(link, yes, &mut std::io::stdout().lock())
}

fn run_blank(
    link: &mut impl SecretLink,
    yes: bool,
    output: &mut impl std::io::Write,
) -> Result<()> {
    if !yes {
        bail!(
            "blank erases the controller key, the generator, the printed secret and every \
             enrolment; the unit's label stops working and it needs a new one from \
             write-secret. Pass --yes."
        );
    }
    let end = usize::from(map::END.0);
    let zeros = [0u8; DATA_BYTES];
    let mut back = [0u8; DATA_BYTES];
    // At most END / DATA_BYTES + 1 transactions, each read back before the next.
    for start in (0..end).step_by(DATA_BYTES) {
        let len = DATA_BYTES.min(end.saturating_sub(start));
        let at = u16::try_from(start).context("the map fits the FRAM's addresses")?;
        let chunk = zeros.get(..len).context("chunk length")?;
        block_on(link.write(Address(at), chunk)).map_err(refused)?;
        let read = back.get_mut(..len).context("chunk length")?;
        block_on(link.read(Address(at), read))
            .with_context(|| format!("reading back {len} bytes at {at:#06x}"))?;
        if read.iter().any(|byte| *byte != 0) {
            bail!(
                "{len} bytes at {at:#06x} did not read back blank; the unit is half erased, run blank again"
            );
        }
    }
    link.reboot()?;
    if born(link)? {
        bail!("the rebooted unit still holds a controller key or a generator");
    }
    writeln!(
        output,
        "blanked {end} bytes of FRAM; the unit is unborn: o89-dev store write-secret gives it a key, a generator and a label"
    )?;
    Ok(())
}

/// Write the secret, and on a unit's first transaction its controller key
/// and generator; the label is shown once.
pub fn write_secret(
    link: &mut Link,
    device_id: Option<&str>,
    replace: bool,
    resume: bool,
) -> Result<()> {
    run_secret(
        link,
        device_id,
        replace,
        resume,
        &mut std::io::stdout().lock(),
    )
}

fn run_secret(
    link: &mut impl SecretLink,
    device_id: Option<&str>,
    replace: bool,
    resume: bool,
    output: &mut impl std::io::Write,
) -> Result<()> {
    if resume {
        return resume_secret(link, output).context(RESUME);
    }
    ensure_no_transaction(link)?;
    let secret = generate_secret(link, device_id, replace)?;
    let birth = if born(link)? {
        // Checked before anything is staged: once applied, the new label
        // has replaced the old one, and one that pairs with nothing is not
        // printed (P-237).
        if read::<DrbgState, DRBG_BYTES>(link, map::DRBG)?
            .present()
            .is_none()
        {
            bail!(
                "the generator does not read back, so this unit cannot pair; nothing staged, the label it has stays"
            );
        }
        None
    } else {
        Some(generate_birth()?)
    };
    // `Birth` is `Copy` and has no way to clear itself; the encoded body is
    // the copy that crosses to the controller, and it is cleared below.
    let mut body = Zeroizing::new(SecretChange::Pending(secret, birth).encode());
    link.stage_and_reboot(&body[..], replace).context(RESUME)?;
    body.zeroize();
    show_applied(link, secret, output).context(RESUME)
}

const RESUME: &str = "secret write interrupted; run: o89-dev store write-secret --resume";

type Transaction = Kept<SecretChange, { o89_core::SECRET_CHANGE_BYTES }>;

fn ensure_no_transaction(link: &mut impl o89_core::Fram<Error = anyhow::Error>) -> Result<()> {
    match read::<SecretChange, { o89_core::SECRET_CHANGE_BYTES }>(link, map::SECRET_CHANGE)?.held()
    {
        Held::Present(SecretChange::Pending(..) | SecretChange::Applied(..)) => bail!(RESUME),
        Held::Absent | Held::Present(SecretChange::Complete) => Ok(()),
        Held::Corrupt | Held::Malformed(_) => {
            bail!("unreadable secret transaction; reboot before provisioning")
        }
    }
}

/// Whether the part holds a controller key or a generator, or damage where
/// either would be: the firmware refuses birth material for any of these
/// (P-235, P-237), and so does the host before drawing any.
fn born(link: &mut impl o89_core::Fram<Error = anyhow::Error>) -> Result<bool> {
    let controller = read::<ControllerKey, CONTROLLER_KEY_BYTES>(link, map::CONTROLLER_KEY)?;
    let drbg = read::<DrbgState, DRBG_BYTES>(link, map::DRBG)?;
    Ok(!matches!(controller.held(), Held::Absent) || !matches!(drbg.held(), Held::Absent))
}

/// The controller key and the generator's first state, drawn here and
/// recorded nowhere. The raw draws are cleared as they are consumed.
fn generate_birth() -> Result<Birth> {
    let mut key = Zeroizing::new([0u8; CONTROLLER_KEY_BYTES]);
    fill(&mut *key)?;
    let mut seed = Zeroizing::new([0u8; DRBG_BYTES]);
    fill(&mut *seed)?;
    Ok(Birth {
        controller: ControllerKey::new(*key)
            .map_err(|_| anyhow!("the generator returned zeros"))?,
        drbg: DrbgState::new(*seed).map_err(|_| anyhow!("the generator returned zeros"))?,
    })
}

trait SecretLink: o89_core::Fram<Error = anyhow::Error> {
    fn reboot(&mut self) -> Result<()>;
    /// Stage the encoded `SecretChange::Pending` body and reboot to apply it.
    fn stage_and_reboot(&mut self, body: &[u8], replace: bool) -> Result<()>;
}

impl SecretLink for Link {
    fn stage_and_reboot(&mut self, body: &[u8], replace: bool) -> Result<()> {
        self.write_secret(body, replace)
    }
    fn reboot(&mut self) -> Result<()> {
        Link::reboot(self)
    }
}

fn resume_secret(link: &mut impl SecretLink, output: &mut impl std::io::Write) -> Result<()> {
    let transaction = block_on(Transaction::read(map::SECRET_CHANGE, link))?;
    let secret = match *transaction.held() {
        Held::Present(SecretChange::Pending(secret, _)) => {
            link.reboot()?;
            secret
        }
        Held::Present(SecretChange::Applied(secret, _)) => secret,
        Held::Absent | Held::Present(SecretChange::Complete) => {
            bail!("no secret label to resume")
        }
        Held::Corrupt | Held::Malformed(_) => {
            bail!("unreadable secret transaction; no label printed")
        }
    };
    show_applied(link, secret, output)
}

fn generate_secret(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    device_id: Option<&str>,
    replace: bool,
) -> Result<Secret> {
    let kept = read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)?;
    if let Held::Present(_) = kept.held()
        && !replace
    {
        bail!("the part holds a secret; --replace invalidates the label every holder has");
    }
    let id: [u8; DEVICE_ID_BYTES] = if let Some(text) = device_id {
        hex::decode(text)
            .context("the device id is hex")?
            .try_into()
            .map_err(|found: Vec<u8>| {
                anyhow!(
                    "the device id is {DEVICE_ID_BYTES} bytes, not {}",
                    found.len()
                )
            })?
    } else {
        let mut id = [0u8; DEVICE_ID_BYTES];
        fill(&mut id)?;
        id
    };
    let mut printed = Zeroizing::new([0u8; PRINTED_SECRET_BYTES]);
    fill(&mut *printed)?;
    let secret = Secret::new(id, *printed).map_err(|_| anyhow!("the generator returned zeros"))?;
    Ok(secret)
}

fn show_applied(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    secret: Secret,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let applied = read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)?;
    let mut transaction = block_on(Transaction::read(map::SECRET_CHANGE, link))?;
    let drbg = read::<DrbgState, DRBG_BYTES>(link, map::DRBG)?;
    let fingerprint = match transaction.present() {
        Some(SecretChange::Applied(held, fingerprint)) if *held == secret => *fingerprint,
        Some(SecretChange::Applied(..) | SecretChange::Pending(..) | SecretChange::Complete)
        | None => bail!("the controller did not finish applying the secret; no label printed"),
    };
    if applied.present() != Some(&secret) || drbg.present().is_none() {
        bail!("the controller did not finish applying the secret; no label printed");
    }
    // The label vouches for the key the unit pairs with now, not the one
    // the transaction recorded: a key that no longer reads or no longer
    // matches would print a label nothing can pair against (P-236).
    let key = read::<ControllerKey, CONTROLLER_KEY_BYTES>(link, map::CONTROLLER_KEY)?;
    if key.present().map(ControllerKey::fingerprint) != Some(fingerprint) {
        bail!("the controller key does not read back as the one applied; no label printed");
    }
    let encoded = secret.encode();
    let id = secret.device_id_bytes();
    let printed: Zeroizing<[u8; PRINTED_SECRET_BYTES]> = Zeroizing::new(
        encoded
            .get(DEVICE_ID_BYTES..)
            .context("secret bytes")?
            .try_into()
            .context("printed secret length")?,
    );
    let payload = pairing_payload(&id, &printed, &fingerprint);
    let qr = pairing_qr(&payload)?;
    writeln!(output, "device id      {}", hex::encode(id))?;
    writeln!(output, "printed secret {}", hex::encode(*printed))?;
    writeln!(
        output,
        "fingerprint    {}",
        hex::encode(fingerprint.as_bytes())
    )?;
    writeln!(output, "{payload}")?;
    // Explicit black on white keeps the QR readable on either terminal theme.
    writeln!(output, "\x1b[30;47m{qr}\x1b[0m")?;
    writeln!(
        output,
        "shown once: it goes on the unit's label and nowhere else"
    )?;
    output.flush()?;
    // A failed output remains resumable. A crash between output and acknowledgement
    // can repeat the same label, but never substitutes an unseen secret.
    block_on(transaction.write(link, SecretChange::Complete)).map_err(refused)?;
    Ok(())
}

/// P-038, P-044, P-049, P-236: the label's ASCII payload, version 2, with no
/// trailing newline.
fn pairing_payload(
    id: &[u8; DEVICE_ID_BYTES],
    printed: &[u8; PRINTED_SECRET_BYTES],
    fingerprint: &Fingerprint,
) -> String {
    format!(
        "km43:2:{}:{}:{}",
        hex::encode(id),
        hex::encode(printed),
        hex::encode(fingerprint.as_bytes())
    )
}

/// Render only in memory; neither the payload nor the QR is saved on the host.
fn pairing_qr(payload: &str) -> Result<String> {
    let code = qrcode::QrCode::new(payload.as_bytes()).context("encoding the pairing QR")?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; DEVICE_ID_BYTES] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    const PAYLOAD: &str = "km43:2:0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:efcdab8967452301efcdab8967452301";

    fn fingerprint() -> Fingerprint {
        let mut bytes = [0u8; 16];
        for (slot, byte) in bytes.iter_mut().zip(ID.iter().rev()) {
            *slot = *byte;
        }
        Fingerprint::from_label(bytes)
    }

    #[test]
    fn p_049_pairing_payload_is_exactly_137_lowercase_characters_and_round_trips() {
        let mut secret = [0; PRINTED_SECRET_BYTES];
        secret[..16].copy_from_slice(&ID);
        secret[16..].copy_from_slice(&ID);
        let payload = pairing_payload(&ID, &secret, &fingerprint());
        assert_eq!(payload, PAYLOAD);
        assert_eq!(payload.len(), 137);
        assert_eq!(payload, payload.to_lowercase());
        let fields: Vec<&str> = payload.split(':').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[..2], ["km43", "2"]);
        assert_eq!(hex::decode(fields[2]).unwrap(), ID);
        assert_eq!(hex::decode(fields[3]).unwrap(), secret);
        assert_eq!(hex::decode(fields[4]).unwrap(), fingerprint().as_bytes());
    }

    #[test]
    fn p_049_pairing_payload_preserves_leading_zeroes() {
        let payload = pairing_payload(
            &[0; DEVICE_ID_BYTES],
            &[0; PRINTED_SECRET_BYTES],
            &Fingerprint::from_label([0; 16]),
        );
        assert_eq!(
            payload,
            "km43:2:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000:00000000000000000000000000000000"
        );
        assert_eq!(payload.len(), 137);
    }

    #[test]
    fn p_049_terminal_qr_decodes_to_the_exact_payload() {
        let rendered = pairing_qr(PAYLOAD).expect("the fixed length payload fits");
        let rows: Vec<Vec<char>> = rendered.lines().map(|row| row.chars().collect()).collect();
        // Decode the actual half-block terminal rendering, including its quiet zone.
        let width = rows[0].len();
        let height = rows.len() * 2;
        let mut image = rqrr::PreparedImage::prepare_from_bitmap(width * 4, height * 4, |x, y| {
            let x = x / 4;
            let y = y / 4;
            match rows[y / 2][x] {
                '█' => true,
                '▀' => y % 2 == 0,
                '▄' => y % 2 != 0,
                ' ' => false,
                other => panic!("unexpected QR character {other}"),
            }
        });
        let grids = image.detect_grids();
        assert_eq!(grids.len(), 1);
        assert_eq!(grids[0].decode().expect("a scannable QR").1, PAYLOAD);
        assert!(rows[0].iter().all(|pixel| *pixel == ' '));
    }

    #[test]
    fn pairing_qr_rejects_oversized_input() {
        assert!(pairing_qr(&"x".repeat(10_000)).is_err());
    }
}

#[cfg(test)]
mod resume_tests;
