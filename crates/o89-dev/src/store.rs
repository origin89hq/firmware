//! The store from the host's side: every record read with the `Kept` the
//! firmware reads with. Epoch writes use the same record seam; secret writes
//! stage a firmware transaction, reboot, and verify it before printing the label.

use anyhow::{Context, Result, anyhow, bail};
use embassy_futures::block_on;
use km43::Epoch;
use o89_core::{
    BOOT_COUNT_BYTES, Body, BootCount, CHALLENGE_COUNTER_BYTES, CLIENT_TABLE_BYTES,
    COMMS_RELEASE_BYTES, ChallengeCounter, ClientTable, CommsRelease, DEVICE_ID_BYTES, EPOCH_BYTES,
    Held, Kept, NETWORK_BYTES, Network, PANIC_RECORD_BYTES, PRINTED_SECRET_BYTES, PanicRecord,
    RUN_REASON_BYTES, Refused, RunReason, SECRET_BYTES, Secret, WRITE_VOLUME_BYTES, WriteVolume,
    map,
};

use crate::link::Link;

/// Every record, decoded, one line each.
pub fn show(link: &mut Link) -> Result<()> {
    let secret = block_on(Kept::<Secret, SECRET_BYTES>::read(map::DEVICE_SECRET, link))?;
    match secret.held() {
        Held::Present(secret) => {
            let bytes = secret.encode();
            let id = bytes.get(..DEVICE_ID_BYTES).unwrap_or(&[]);
            println!("secret      Present, device id {}", hex::encode(id));
        }
        Held::Absent => println!("secret      Absent"),
        Held::Corrupt => println!("secret      Corrupt"),
        Held::Malformed(at) => println!("secret      Malformed({at:?})"),
    }
    line("epoch", &read::<Epoch, EPOCH_BYTES>(link, map::EPOCH)?);
    line(
        "boots",
        &read::<BootCount, BOOT_COUNT_BYTES>(link, map::BOOT_COUNT)?,
    );
    line(
        "challenges",
        &read::<ChallengeCounter, CHALLENGE_COUNTER_BYTES>(link, map::CHALLENGE_COUNTER)?,
    );
    line(
        "volume",
        &read::<WriteVolume, WRITE_VOLUME_BYTES>(link, map::WRITE_VOLUME)?,
    );
    line(
        "run",
        &read::<RunReason, RUN_REASON_BYTES>(link, map::RUN_REASON)?,
    );
    line(
        "panics",
        &read::<PanicRecord, PANIC_RECORD_BYTES>(link, map::PANIC_RECORD)?,
    );
    line(
        "release",
        &read::<CommsRelease, COMMS_RELEASE_BYTES>(link, map::COMMS_RELEASE)?,
    );
    line(
        "network",
        &read::<Network, NETWORK_BYTES>(link, map::NETWORK)?,
    );
    line(
        "clients",
        &read::<ClientTable, CLIENT_TABLE_BYTES>(link, map::CLIENT_TABLE)?,
    );
    Ok(())
}

fn read<T: Body<N>, const N: usize>(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    record: o89_core::Record<N>,
) -> Result<Kept<T, N>> {
    block_on(Kept::<T, N>::read(record, link))
}

fn line<T: Body<N> + core::fmt::Debug, const N: usize>(name: &str, kept: &Kept<T, N>) {
    println!("{name:<11} {:?}", kept.held());
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
            "the part holds epoch {}; a step back would leave a client table stamped above the record",
            held.get()
        ),
        Held::Present(_) | Held::Absent | Held::Corrupt | Held::Malformed(_) => {}
    }
    block_on(kept.write(link, epoch)).map_err(refused)?;
    println!("epoch {raw} written");
    Ok(())
}

/// Write the secret, shown once.
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
    link.stage_and_reboot(secret, replace).context(RESUME)?;
    show_applied(link, secret, output).context(RESUME)
}

const RESUME: &str = "secret write interrupted; run: o89-dev store write-secret --resume";

type Transaction = Kept<o89_core::SecretChange, { o89_core::SECRET_CHANGE_BYTES }>;

fn ensure_no_transaction(link: &mut impl o89_core::Fram<Error = anyhow::Error>) -> Result<()> {
    match read::<o89_core::SecretChange, { o89_core::SECRET_CHANGE_BYTES }>(
        link,
        map::SECRET_CHANGE,
    )?
    .held()
    {
        Held::Present(o89_core::SecretChange::Pending(_) | o89_core::SecretChange::Applied(_)) => {
            bail!(RESUME)
        }
        Held::Absent | Held::Present(o89_core::SecretChange::Complete) => Ok(()),
        Held::Corrupt | Held::Malformed(_) => {
            bail!("unreadable secret transaction; reboot before provisioning")
        }
    }
}

trait SecretLink: o89_core::Fram<Error = anyhow::Error> {
    fn reboot(&mut self) -> Result<()>;
    fn stage_and_reboot(&mut self, secret: Secret, replace: bool) -> Result<()>;
}

impl SecretLink for Link {
    fn stage_and_reboot(&mut self, secret: Secret, replace: bool) -> Result<()> {
        self.write_secret(&secret.encode(), replace)
    }
    fn reboot(&mut self) -> Result<()> {
        Link::reboot(self)
    }
}

fn resume_secret(link: &mut impl SecretLink, output: &mut impl std::io::Write) -> Result<()> {
    let transaction = block_on(Transaction::read(map::SECRET_CHANGE, link))?;
    let secret = match *transaction.held() {
        Held::Present(o89_core::SecretChange::Pending(secret)) => {
            link.reboot()?;
            secret
        }
        Held::Present(o89_core::SecretChange::Applied(secret)) => secret,
        Held::Absent | Held::Present(o89_core::SecretChange::Complete) => {
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
        bail!("the part holds a secret; --replace orphans every client enrolled under it");
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
    let mut printed = [0u8; PRINTED_SECRET_BYTES];
    fill(&mut printed)?;
    let secret = Secret::new(id, printed).map_err(|_| anyhow!("the generator returned zeros"))?;
    Ok(secret)
}

fn show_applied(
    link: &mut impl o89_core::Fram<Error = anyhow::Error>,
    secret: Secret,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let applied = read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)?;
    let mut transaction = block_on(Transaction::read(map::SECRET_CHANGE, link))?;
    let counter = read::<ChallengeCounter, CHALLENGE_COUNTER_BYTES>(link, map::CHALLENGE_COUNTER)?;
    if applied.present() != Some(&secret)
        || counter.present().is_none()
        || transaction.present() != Some(&o89_core::SecretChange::Applied(secret))
    {
        bail!("the controller did not finish applying the secret; no label printed");
    }
    let encoded = secret.encode();
    let id = secret.device_id_bytes();
    let printed: [u8; PRINTED_SECRET_BYTES] = encoded
        .get(DEVICE_ID_BYTES..)
        .context("secret bytes")?
        .try_into()
        .context("printed secret length")?;
    let payload = pairing_payload(&id, &printed);
    let qr = pairing_qr(&payload)?;
    writeln!(output, "device id      {}", hex::encode(id))?;
    writeln!(output, "printed secret {}", hex::encode(printed))?;
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
    block_on(transaction.write(link, o89_core::SecretChange::Complete)).map_err(refused)?;
    // Boot scrubs the previous transaction slot without resetting the counter.
    Ok(())
}

/// P-038, P-044, P-049: the label's ASCII payload, with no trailing newline.
fn pairing_payload(id: &[u8; DEVICE_ID_BYTES], printed: &[u8; PRINTED_SECRET_BYTES]) -> String {
    format!("km43:1:{}:{}", hex::encode(id), hex::encode(printed))
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

    const PAYLOAD: &str = "km43:1:0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn p_049_pairing_payload_is_exactly_104_lowercase_characters() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let mut secret = [0; PRINTED_SECRET_BYTES];
        secret[..16].copy_from_slice(&id);
        secret[16..].copy_from_slice(&id);
        let payload = pairing_payload(&id, &secret);
        assert_eq!(payload, PAYLOAD);
        assert_eq!(payload.len(), 104);
    }

    #[test]
    fn p_049_pairing_payload_preserves_leading_zeroes() {
        let payload = pairing_payload(&[0; DEVICE_ID_BYTES], &[0; PRINTED_SECRET_BYTES]);
        assert_eq!(
            payload,
            "km43:1:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(payload.len(), 104);
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
