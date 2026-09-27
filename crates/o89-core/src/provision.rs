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
//! **The station's reseed** is the one other write of the generator, and
//! P-237's one exception: a fresh state from the station's CSPRNG, staged
//! over SWD through the same record, onto a unit whose generator record
//! holds no intact state (damaged in both slots, never written, or a body
//! of zeros) and whose controller key reads. Staging refuses it while an
//! intact state reads back from either slot, while the part has no key, or
//! while another transaction is unfinished; the boot checks the same again
//! before it writes, reads the state back off the part, and scrubs the
//! intent so no copy of the state outlives the boot.
//! It writes the state and nothing else: the controller key, the printed
//! secret and every client slot stay byte for byte.
//!
//! cites: F-041, P-044, P-049, P-235, P-236, P-237

use km43::{FINGERPRINT_BYTES, Fingerprint};

use crate::drbg::{DRBG_BYTES, DrbgState};
use crate::secret::{CONTROLLER_KEY_BYTES, ControllerKey};
use crate::{Body, Fram, Held, Kept, Malformed, Refused, SECRET_BYTES, Secret, Unverified, map};

/// One state byte, the secret, a byte saying whether the unit is being
/// born, then the controller key and the generator's state, or the
/// fingerprint once applied. A reseed is the state byte and the state.
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
    /// The station's fresh state for a generator whose record holds no
    /// intact state (P-237). Applied at boot and scrubbed there; it is
    /// never retained past the boot that applies it.
    Reseed(DrbgState),
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
            Self::Reseed(state) => {
                writer.u8(3);
                writer.put(&state.encode());
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
        if state == 3 {
            return DrbgState::decode(&reader.take::<DRBG_BYTES>()?)
                .map(Self::Reseed)
                .map_err(|_| reader.malformed(DRBG_BYTES));
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
            Self::Reseed(_) => "Reseed",
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
    /// Unreadable intent or a torn staging write was erased, or a reseed the
    /// boot would not apply or the part did not keep was scrubbed; active
    /// records stayed.
    Discarded,
    /// The station's reseed wrote the generator a fresh state, read it back
    /// off the part, and scrubbed the intent (P-237).
    Reseeded,
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
    /// carries none: it would print a label with nothing to pin. For a
    /// reseed, the unit is one to provision again, not to reseed.
    Unborn,
    /// A reseed onto a generator record that reads back an intact state,
    /// from either slot. A live generator is never replaced (P-237).
    NotDamaged,
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

/// Refuse a new transaction while another is unfinished or unreadable: the
/// boot finishes one, and the host acknowledges a label, before the next.
fn ready_for_a_transaction<E>(
    change: &Kept<SecretChange, SECRET_CHANGE_BYTES>,
) -> Result<(), ProvisionFailed<E>> {
    match change.held() {
        Held::Present(
            SecretChange::Pending(..) | SecretChange::Applied(..) | SecretChange::Reseed(_),
        ) => Err(ProvisionFailed::Pending),
        Held::Corrupt | Held::Malformed(_) => Err(ProvisionFailed::Unknown),
        Held::Absent | Held::Present(SecretChange::Complete) => Ok(()),
    }
}

/// Stage the station's fresh generator state for a unit whose generator
/// record holds no intact state, then reboot before any session can use it
/// (P-237's station reseed). The record may read damaged in both slots,
/// never written or malformed. Beside a controller key that reads, and with
/// no transaction pending or unacknowledged, none of these is a birth still
/// under way, because a birth writes the key and the generator before it is
/// applied; and a fresh state from the station repeats nothing the unit
/// drew. Refused while an intact state reads back from either slot
/// ([`ProvisionFailed::NotDamaged`]), while the part holds no controller key
/// it can read ([`ProvisionFailed::Unborn`]), and while another transaction
/// is unfinished. Boot applies it with [`finish`], which checks the same
/// again. Only the bench mailbox calls this, over SWD; no message, reset,
/// update or comms input reaches it.
pub async fn stage_reseed<F: Fram>(
    fram: &mut F,
    state: DrbgState,
) -> Result<(), ProvisionFailed<F::Error>> {
    let mut change =
        Kept::<SecretChange, SECRET_CHANGE_BYTES>::read(map::SECRET_CHANGE, fram).await?;
    ready_for_a_transaction(&change)?;
    let (controller, drbg) = birth_records(fram).await?;
    if controller.present().is_none() {
        return Err(ProvisionFailed::Unborn);
    }
    match drbg {
        Held::Present(_) => return Err(ProvisionFailed::NotDamaged),
        Held::Corrupt | Held::Absent | Held::Malformed(_) => {}
    }
    change
        .write(fram, SecretChange::Reseed(state))
        .await
        .map_err(ProvisionFailed::Write)
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
    ready_for_a_transaction(&change)?;
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
/// A staged reseed is applied by [`reseed`]. Unreadable intent cannot
/// authorize any step: only that record is erased.
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
        Held::Present(SecretChange::Reseed(state)) => {
            reseed(fram, &mut change, controller, drbg, state).await
        }
    }
}

/// Apply a staged reseed: write the state only while the key reads and the
/// generator record still holds no intact state, and keep what the part
/// reads back, never what was meant to land. A cut before the write lands
/// replays it; a cut after finds the state and writes nothing. Either way
/// the intent is scrubbed before any session exists, so the state it
/// carried is on the part in the generator's record alone (P-237).
async fn reseed<F: Fram>(
    fram: &mut F,
    change: &mut Kept<SecretChange, SECRET_CHANGE_BYTES>,
    controller: &Kept<ControllerKey, CONTROLLER_KEY_BYTES>,
    drbg: &mut Kept<DrbgState, DRBG_BYTES>,
    state: DrbgState,
) -> Result<SecretRecovery, ProvisionFailed<F::Error>> {
    if controller.present().is_some() && drbg.present().is_none() {
        match drbg.write_verified(fram, state).await {
            // A disagreement leaves whatever the part read back, damage
            // included, and the intent is scrubbed below: retrying a write
            // the part will not keep would hold every boot on it.
            Ok(()) | Err(Unverified::Disagreed) => {}
            Err(Unverified::Refused(refused)) => return Err(ProvisionFailed::Write(refused)),
            Err(Unverified::ReadBack(bus)) => return Err(ProvisionFailed::Read(bus)),
        }
    }
    let recovery = if drbg.present() == Some(&state) {
        SecretRecovery::Reseeded
    } else {
        SecretRecovery::Discarded
    };
    change
        .write(fram, SecretChange::Complete)
        .await
        .map_err(ProvisionFailed::Write)?;
    change
        .erase_previous(fram)
        .await
        .map_err(ProvisionFailed::Write)?;
    Ok(recovery)
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
