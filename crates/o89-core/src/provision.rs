//! Bench-only secret replacement, recovered before any session can mint.
//!
//! cites: F-041, P-044

use crate::challenge::{CHALLENGE_COUNTER_BYTES, ChallengeCounter};
use crate::{Body, Fram, Held, Kept, Malformed, Refused, SECRET_BYTES, Secret, map};

/// One state byte and the new identity and printed secret.
pub const SECRET_CHANGE_BYTES: usize = 49;

/// A committed intent; no secret material is formatted or logged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretChange {
    /// No replacement remains to finish.
    Complete,
    /// Finish this replacement before exposing either secret or counter.
    Pending(Secret),
}

impl Body<SECRET_CHANGE_BYTES> for SecretChange {
    fn encode(&self) -> [u8; SECRET_CHANGE_BYTES] {
        let mut out = [0; SECRET_CHANGE_BYTES];
        if let Self::Pending(secret) = self {
            let mut writer = crate::body::Writer::over(&mut out);
            writer.u8(1);
            writer.put(&secret.encode());
        }
        out
    }

    fn decode(bytes: &[u8; SECRET_CHANGE_BYTES]) -> Result<Self, Malformed> {
        let mut reader = crate::body::Reader::over(bytes);
        match reader.u8()? {
            0 => Ok(Self::Complete),
            1 => Secret::decode(&reader.take::<SECRET_BYTES>()?).map(Self::Pending),
            _ => Err(Malformed { at: 0 }),
        }
    }
}

/// What boot did with the bench transaction, included in the boot report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecretRecovery {
    /// No replacement was pending.
    Unchanged,
    /// A valid intent supplied fresh key material and a fresh counter.
    Applied,
    /// Unreadable intent or a torn staging write was erased; active records stayed.
    Discarded,
}

/// A failed replacement or boot recovery never supplies usable new keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProvisionFailed<E> {
    /// Reading the part failed.
    Read(E),
    /// A transaction write failed; the next boot retries committed intent.
    Write(Refused<E>),
    /// Staging found unreadable intent; reboot discards it without changing keys.
    Unknown,
    /// Replacement was not explicitly requested.
    AlreadyProvisioned,
    /// Reusing the same secret would repeat challenges after resetting.
    SameSecret,
    /// An earlier replacement must finish at boot first.
    Pending,
}

impl<E> From<E> for ProvisionFailed<E> {
    fn from(error: E) -> Self {
        Self::Read(error)
    }
}

/// Stage a freshly generated, never previously used secret, then reboot before answering clients
/// with it. This does not touch the active secret or its counter: even a session
/// running during this write still uses the old pair. Boot completes the intent
/// with [`finish`] before returning a store. There is no counter-only reset.
pub async fn stage_secret<F: Fram>(
    fram: &mut F,
    secret: Secret,
    replace: bool,
) -> Result<(), ProvisionFailed<F::Error>> {
    let current = Kept::<Secret, SECRET_BYTES>::read(map::DEVICE_SECRET, fram).await?;
    if let Some(old) = current.present() {
        if *old == secret {
            return Err(ProvisionFailed::SameSecret);
        }
        if !replace {
            return Err(ProvisionFailed::AlreadyProvisioned);
        }
    }
    let mut change =
        Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(map::SECRET_CHANGE, fram).await?;
    match change.held() {
        Held::Present(SecretChange::Pending(_)) => return Err(ProvisionFailed::Pending),
        Held::Corrupt | Held::Malformed(_) => return Err(ProvisionFailed::Unknown),
        Held::Absent | Held::Present(SecretChange::Complete) => {}
    }
    change
        .write(fram, SecretChange::Pending(secret))
        .await
        .map_err(ProvisionFailed::Write)
}

/// Commit the new secret, then counter zero, then mark the intent complete.
/// Counter values used under the old secret derive different challenges under
/// the fresh secret, so restarting at zero is safe. A cut before intent commits
/// keeps the old pair; a cut afterwards replays this sequence before any session
/// exists. A failed write returns no Store, so neither a partly replaced pair nor
/// a counter reset repeated by recovery can mint a challenge. Clearing the intent
/// is the commit point after which boot never resets this counter again.
/// Unreadable intent cannot authorize any application step: erase only that
/// record and retain the active secret/counter, including on legacy-layout units.
pub(crate) async fn finish<F: Fram>(
    fram: &mut F,
    secret: &mut Kept<Secret, SECRET_BYTES>,
    challenges: &mut Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES>,
) -> Result<SecretRecovery, ProvisionFailed<F::Error>> {
    let mut change =
        Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(map::SECRET_CHANGE, fram).await?;
    match *change.held() {
        Held::Absent => discard_residue(fram, &mut change).await,
        Held::Corrupt | Held::Malformed(_) => {
            change.erase(fram).await.map_err(ProvisionFailed::Write)?;
            Ok(SecretRecovery::Discarded)
        }
        Held::Present(SecretChange::Complete) => {
            change
                .erase_previous(fram)
                .await
                .map_err(ProvisionFailed::Write)?;
            Ok(SecretRecovery::Unchanged)
        }
        Held::Present(SecretChange::Pending(new)) => {
            if secret.present() != Some(&new) {
                secret
                    .write(fram, new)
                    .await
                    .map_err(ProvisionFailed::Write)?;
            }
            challenges
                .write(fram, ChallengeCounter::fresh())
                .await
                .map_err(ProvisionFailed::Write)?;
            change
                .write(fram, SecretChange::Complete)
                .await
                .map_err(ProvisionFailed::Write)?;
            change
                .erase_previous(fram)
                .await
                .map_err(ProvisionFailed::Write)?;
            Ok(SecretRecovery::Applied)
        }
    }
}

/// An interrupted discard can read absent with residue in the other slot.
/// Inspect the bounded reservation so the next boot finishes erasing it, while
/// a blank region causes no writes. Unreadable intent never authorizes a reset.
async fn discard_residue<F: Fram>(
    fram: &mut F,
    change: &mut Kept<SecretChange, SECRET_CHANGE_BYTES>,
) -> Result<SecretRecovery, ProvisionFailed<F::Error>> {
    let mut bytes = [0; crate::fram::slot_bytes(SECRET_CHANGE_BYTES).saturating_mul(2)];
    fram.read(map::SECRET_CHANGE_START, &mut bytes).await?;
    if bytes.iter().all(|byte| *byte == 0) || bytes.iter().all(|byte| *byte == 0xff) {
        return Ok(SecretRecovery::Unchanged);
    }
    change.erase(fram).await.map_err(ProvisionFailed::Write)?;
    Ok(SecretRecovery::Discarded)
}
