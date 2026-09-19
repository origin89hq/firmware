//! The store from the host's side: every record read with the `Kept` the
//! firmware reads with, and the two records the bench writes, the epoch
//! and the secret, written with the same.

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
    link: &mut Link,
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
pub fn write_secret(link: &mut Link, device_id: Option<&str>, replace: bool) -> Result<()> {
    let mut kept = read::<Secret, SECRET_BYTES>(link, map::DEVICE_SECRET)?;
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
    block_on(kept.write(link, secret)).map_err(refused)?;
    println!("device id      {}", hex::encode(id));
    println!("printed secret {}", hex::encode(printed));
    println!("shown once: it goes on the unit's label and nowhere else");
    Ok(())
}
