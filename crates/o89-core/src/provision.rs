//! The manufacturing transaction, recovered before any session can draw.
//!
//! The station stages a printed secret and, on a unit's first transaction,
//! the controller key and the generator's first state, all drawn from its
//! own CSPRNG and recorded nowhere (P-235, P-237). The next boot applies
//! them before it returns a store, so no session ever sees a half-written
//! identity. The controller key and the generator are written **once**: a
//! transaction onto a unit that holds either carries neither, and boot never
//! writes over one that is there, because re-initialising the generator
//! returns a unit to a sequence it has already drawn from, and a new
//! controller key breaks every phone that pinned the old one.
//!
//! Once applied, the transaction keeps the secret and the controller key's
//! fingerprint, which is public, until the host has printed the label and
//! acknowledged it; the controller key and the generator's state are not
//! kept past the boot that wrote them.
//!
//! cites: F-041, P-044, P-049, P-235, P-236, P-237

use km43::{FINGERPRINT_BYTES, Fingerprint};

use crate::drbg::{DRBG_BYTES, DrbgState};
use crate::secret::{CONTROLLER_KEY_BYTES, ControllerKey};
use crate::{Body, Fram, Held, Kept, Malformed, Refused, SECRET_BYTES, Secret, map};

/// One state byte, the secret, a byte saying whether the unit is being
/// born, then the controller key and the generator's state, or the
/// fingerprint once applied.
pub const SECRET_CHANGE_BYTES: usize = 1 + SECRET_BYTES + 1 + CONTROLLER_KEY_BYTES + DRBG_BYTES;

const _: () = assert!(FINGERPRINT_BYTES <= CONTROLLER_KEY_BYTES + DRBG_BYTES);

/// What a unit is born with besides its label: written once, on the first
/// transaction, and never by a later one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Birth {
    /// The controller key's private half (P-235).
    pub controller: ControllerKey,
    /// The generator's first state (P-237).
    pub drbg: DrbgState,
}

/// A committed intent; no secret material is formatted or logged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretChange {
    /// The label has been acknowledged; no transaction remains to finish.
    Complete,
    /// Finish this before exposing a secret, a key or a generator.
    Pending(Secret, Option<Birth>),
    /// Applied at boot, retained until the host has printed the label: the
    /// secret, and the fingerprint of the controller key the part holds.
    Applied(Secret, Fingerprint),
}

impl Body<SECRET_CHANGE_BYTES> for SecretChange {
    fn encode(&self) -> [u8; SECRET_CHANGE_BYTES] {
        let mut out = [0; SECRET_CHANGE_BYTES];
        let mut writer = crate::body::Writer::over(&mut out);
        match self {
            Self::Complete => {}
            Self::Pending(secret, birth) => {
                writer.u8(1);
                writer.put(&secret.encode());
                match birth {
                    Some(birth) => {
                        writer.u8(1);
                        writer.put(&birth.controller.encode());
                        writer.put(&birth.drbg.encode());
                    }
                    None => writer.u8(0),
                }
            }
            Self::Applied(secret, fingerprint) => {
                writer.u8(2);
                writer.put(&secret.encode());
                writer.u8(0);
                writer.put(fingerprint.as_bytes());
            }
        }
        out
    }

    fn decode(bytes: &[u8; SECRET_CHANGE_BYTES]) -> Result<Self, Malformed> {
        let mut reader = crate::body::Reader::over(bytes);
        let state = reader.u8()?;
        if state == 0 {
            return Ok(Self::Complete);
        }
        let secret = Secret::decode(&reader.take::<SECRET_BYTES>()?)?;
        let born = reader.u8()?;
        match (state, born) {
            (1, 0) => Ok(Self::Pending(secret, None)),
            (1, 1) => {
                let controller = ControllerKey::decode(&reader.take::<CONTROLLER_KEY_BYTES>()?)
                    .map_err(|_| reader.malformed(CONTROLLER_KEY_BYTES))?;
                let drbg = DrbgState::decode(&reader.take::<DRBG_BYTES>()?)
                    .map_err(|_| reader.malformed(DRBG_BYTES))?;
                Ok(Self::Pending(secret, Some(Birth { controller, drbg })))
            }
            (2, 0) => Ok(Self::Applied(
                secret,
                Fingerprint::from_label(reader.take::<FINGERPRINT_BYTES>()?),
            )),
            _ => Err(Malformed { at: 0 }),
        }
    }
}

impl core::fmt::Debug for SecretChange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Complete => "Complete",
            Self::Pending(_, None) => "Pending",
            Self::Pending(_, Some(_)) => "Pending(birth)",
            Self::Applied(..) => "Applied",
        })
    }
}

/// What boot did with the transaction, included in the boot report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecretRecovery {
    /// No transaction was pending.
    Unchanged,
    /// A valid intent supplied a fresh secret, and on a first transaction the
    /// controller key and the generator.
    Applied,
    /// Unreadable intent or a torn staging write was erased; active records stayed.
    Discarded,
}

/// A failed transaction or boot recovery never supplies usable new keys.
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
    /// Reusing the same secret.
    SameSecret,
    /// An earlier transaction must finish at boot and its label must be acknowledged.
    Pending,
    /// The unit already holds a controller key or a generator, or a damaged
    /// record where one was: neither is ever written twice (P-235, P-237).
    AlreadyBorn,
    /// The unit holds no controller key it can read, and the transaction
    /// carries none: it would print a label with nothing to pin.
    Unborn,
}

impl<E> From<E> for ProvisionFailed<E> {
    fn from(error: E) -> Self {
        Self::Read(error)
    }
}

/// What the part holds where the controller key and the generator live.
async fn birth_records<F: Fram>(
    fram: &mut F,
) -> Result<(Held<ControllerKey>, Held<DrbgState>), F::Error> {
    let controller =
        Kept::<ControllerKey, CONTROLLER_KEY_BYTES>::read(map::CONTROLLER_KEY, fram).await?;
    let drbg = Kept::<DrbgState, DRBG_BYTES>::read(map::DRBG, fram).await?;
    Ok((*controller.held(), *drbg.held()))
}

/// Stage a freshly generated, never previously used secret, and on a unit's
/// first transaction its controller key and generator, then reboot before
/// answering clients with any of it. This does not touch what the unit
/// holds: a session running during this write still uses it. Boot completes
/// the intent with [`finish`] before returning a store.
pub async fn stage_secret<F: Fram>(
    fram: &mut F,
    secret: Secret,
    birth: Option<Birth>,
    replace: bool,
) -> Result<(), ProvisionFailed<F::Error>> {
    let mut change =
        Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(map::SECRET_CHANGE, fram).await?;
    match change.held() {
        Held::Present(SecretChange::Pending(..) | SecretChange::Applied(..)) => {
            return Err(ProvisionFailed::Pending);
        }
        Held::Corrupt | Held::Malformed(_) => return Err(ProvisionFailed::Unknown),
        Held::Absent | Held::Present(SecretChange::Complete) => {}
    }
    let (controller, drbg) = birth_records(fram).await?;
    if birth.is_some() {
        // Anything but a record never written is one that was: a damaged
        // key or state is never written over (P-235, P-237).
        if !matches!(controller, Held::Absent) || !matches!(drbg, Held::Absent) {
            return Err(ProvisionFailed::AlreadyBorn);
        }
    } else if !matches!(controller, Held::Present(_)) {
        // Without a key to fingerprint, the label would vouch for nothing,
        // and the boot could not apply the transaction.
        return Err(ProvisionFailed::Unborn);
    }
    let current = Kept::<Secret, SECRET_BYTES>::read(map::DEVICE_SECRET, fram).await?;
    if let Some(old) = current.present() {
        if *old == secret {
            return Err(ProvisionFailed::SameSecret);
        }
        if !replace {
            return Err(ProvisionFailed::AlreadyProvisioned);
        }
    }
    change
        .write(fram, SecretChange::Pending(secret, birth))
        .await
        .map_err(ProvisionFailed::Write)
}

/// Commit the new secret, then on a first transaction the controller key and
/// the generator, each only onto a record never written, then mark the intent
/// applied with the fingerprint of the key the part holds. An intent that
/// would leave no readable controller key is erased and nothing of it is
/// applied, the secret included: the boot goes on without it. A cut before the
/// intent commits keeps what the unit held; a cut afterwards replays this
/// before any session exists, and a replay writes nothing twice. Applying is
/// the commit point after which the key and the state leave the intent.
/// Unreadable intent cannot authorize any step: only that record is erased.
pub(crate) async fn finish<F: Fram>(
    fram: &mut F,
    secret: &mut Kept<Secret, SECRET_BYTES>,
    controller: &mut Kept<ControllerKey, CONTROLLER_KEY_BYTES>,
    drbg: &mut Kept<DrbgState, DRBG_BYTES>,
) -> Result<SecretRecovery, ProvisionFailed<F::Error>> {
    let mut change =
        Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(map::SECRET_CHANGE, fram).await?;
    match *change.held() {
        Held::Absent => discard_residue(fram, &mut change).await,
        Held::Corrupt | Held::Malformed(_) => {
            change.erase(fram).await.map_err(ProvisionFailed::Write)?;
            Ok(SecretRecovery::Discarded)
        }
        Held::Present(SecretChange::Complete | SecretChange::Applied(..)) => {
            change
                .erase_previous(fram)
                .await
                .map_err(ProvisionFailed::Write)?;
            Ok(SecretRecovery::Unchanged)
        }
        Held::Present(SecretChange::Pending(new, birth)) => {
            // All or nothing: a transaction that would leave the unit with
            // no controller key applies nothing, and is erased so that it
            // never blocks a boot again.
            let key = match (controller.present(), birth) {
                (Some(held), _) => *held,
                (None, Some(birth)) if matches!(controller.held(), Held::Absent) => {
                    birth.controller
                }
                (None, Some(_) | None) => {
                    change.erase(fram).await.map_err(ProvisionFailed::Write)?;
                    return Ok(SecretRecovery::Discarded);
                }
            };
            if secret.present() != Some(&new) {
                secret
                    .write(fram, new)
                    .await
                    .map_err(ProvisionFailed::Write)?;
            }
            if let Some(birth) = birth {
                if matches!(controller.held(), Held::Absent) {
                    controller
                        .write(fram, birth.controller)
                        .await
                        .map_err(ProvisionFailed::Write)?;
                }
                if matches!(drbg.held(), Held::Absent) {
                    drbg.write(fram, birth.drbg)
                        .await
                        .map_err(ProvisionFailed::Write)?;
                }
            }
            // The fingerprint of what the part holds, which is what a client
            // will be shown in message 2.
            change
                .write(fram, SecretChange::Applied(new, key.fingerprint()))
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
