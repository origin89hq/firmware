//! What a unit is born with: the device id etched into it, the printed
//! secret on its label, and the controller key clients pin.
//!
//! Provisioned at manufacture by the tool that prints the label; read
//! at every boot; never exposed to the comms processor and never logged.
//! The types have no `Debug` for the reason the keys in `km43` have none:
//! a secret should not be one `?secret` away from a bench log.
//!
//! The printed secret derives the pairing's two keys and nothing else
//! (P-088). The controller key is the unit's identity for its life: only
//! its private half is stored, the public half is derived when it is
//! needed, and a factory reset never touches it (P-235). Its fingerprint is
//! the one part of it that leaves the station (P-236).
//!
//! cites: P-038, P-044, P-088, P-235

use km43::{DeviceId, Fingerprint, KEY_BYTES, Label, PrintedSecret, PublicKey, StaticKey};

use crate::body::{Body, Malformed, Reader, Writer};

pub use o89_link::DEVICE_ID_BYTES;

/// Bytes of the printed secret (P-044).
pub const PRINTED_SECRET_BYTES: usize = 32;

/// The bytes the secret takes in its record: the id, then the secret.
pub const SECRET_BYTES: usize = DEVICE_ID_BYTES + PRINTED_SECRET_BYTES;

/// What a unit knows about itself. No `Debug`, no `Format`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secret {
    device_id: [u8; DEVICE_ID_BYTES],
    printed: [u8; PRINTED_SECRET_BYTES],
}

/// A printed secret with no entropy in it: every byte zero. The tool that
/// writes one has failed, and a unit that derives from it has no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoEntropy;

impl Secret {
    /// The pair as the manufacturing tool hands it over, refused when the
    /// printed secret is all zero.
    pub fn new(
        device_id: [u8; DEVICE_ID_BYTES],
        printed: [u8; PRINTED_SECRET_BYTES],
    ) -> Result<Self, NoEntropy> {
        if printed.iter().any(|byte| *byte != 0) {
            Ok(Self { device_id, printed })
        } else {
            Err(NoEntropy)
        }
    }

    /// The sixteen bytes of P-038, which every `Discover` publishes.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        DeviceId::new(self.device_id)
    }

    /// The same sixteen bytes, as key 3 of a `Discover` carries them.
    #[must_use]
    pub const fn device_id_bytes(&self) -> [u8; DEVICE_ID_BYTES] {
        self.device_id
    }

    /// The label P-049 prints, which derives the pairing's pre-shared key
    /// and its refusal key and nothing else (P-088).
    #[must_use]
    pub const fn label(&self) -> Label {
        Label::new(
            DeviceId::new(self.device_id),
            PrintedSecret::new(self.printed),
        )
    }
}

/// The bytes the controller key takes in its record: the private half.
pub const CONTROLLER_KEY_BYTES: usize = KEY_BYTES;

/// The private half of the controller key, as the part holds it (P-235).
/// No `Debug`, no `Format`: it leaves only as the key it builds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ControllerKey([u8; CONTROLLER_KEY_BYTES]);

impl ControllerKey {
    /// A key the manufacturing station drew, refused when every byte is
    /// zero.
    pub fn new(private: [u8; CONTROLLER_KEY_BYTES]) -> Result<Self, NoEntropy> {
        if private.iter().any(|byte| *byte != 0) {
            Ok(Self(private))
        } else {
            Err(NoEntropy)
        }
    }

    /// The key pair, its public half derived from the private one.
    #[must_use]
    pub fn key(&self) -> StaticKey {
        StaticKey::from_stored(self.0)
    }

    /// The public half, `CS`.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.key().public()
    }

    /// P-236's fingerprint, which the label prints.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public())
    }
}

impl core::fmt::Debug for ControllerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ControllerKey(..)")
    }
}

impl Body<CONTROLLER_KEY_BYTES> for ControllerKey {
    fn encode(&self) -> [u8; CONTROLLER_KEY_BYTES] {
        self.0
    }

    fn decode(bytes: &[u8; CONTROLLER_KEY_BYTES]) -> Result<Self, Malformed> {
        Self::new(*bytes).map_err(|NoEntropy| Malformed { at: 0 })
    }
}

impl Body<SECRET_BYTES> for Secret {
    fn encode(&self) -> [u8; SECRET_BYTES] {
        let mut out = [0u8; SECRET_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.put(&self.device_id);
        writer.put(&self.printed);
        out
    }

    fn decode(bytes: &[u8; SECRET_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let device_id = reader.take::<DEVICE_ID_BYTES>()?;
        let printed = reader.take::<PRINTED_SECRET_BYTES>()?;
        Self::new(device_id, printed).map_err(|NoEntropy| reader.malformed(PRINTED_SECRET_BYTES))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_044_a_secret_survives_the_round_trip_and_derives_the_same_keys() {
        let secret = Secret::new([1; 16], [2; 32]).expect("entropy");
        let found = Secret::decode(&secret.encode()).expect("decodes");
        assert!(found == secret);
        assert_eq!(found.device_id(), DeviceId::new([1; 16]));
        assert_eq!(found.label().device_id(), secret.label().device_id());
    }

    #[test]
    fn p_044_a_printed_secret_of_zeros_is_refused_and_not_a_record() {
        assert!(Secret::new([1; 16], [0; 32]).is_err());
        let mut bytes = [0u8; SECRET_BYTES];
        bytes[..16].copy_from_slice(&[1; 16]);
        assert_eq!(Secret::decode(&bytes).err(), Some(Malformed { at: 16 }));
    }

    #[test]
    fn p_235_the_controller_key_round_trips_and_its_public_half_is_derived() {
        let key = ControllerKey::new([9; 32]).expect("entropy");
        let found = ControllerKey::decode(&key.encode()).expect("decodes");
        assert_eq!(found.encode(), key.encode());
        assert!(found.public().matches(&key.key().public()));
        assert!(found.fingerprint().vouches_for(&key.public()));
        let other = ControllerKey::new([8; 32]).expect("entropy");
        assert!(!other.fingerprint().vouches_for(&key.public()));
    }

    #[test]
    fn p_235_a_controller_key_of_zeros_is_refused_and_not_a_record() {
        assert!(ControllerKey::new([0; 32]).is_err());
        assert_eq!(
            ControllerKey::decode(&[0; 32]).err(),
            Some(Malformed { at: 0 })
        );
    }

    #[test]
    fn p_038_a_device_id_of_zeros_is_an_id_like_any_other() {
        // The id is a salt, not a secret; it is whatever was etched.
        let secret = Secret::new([0; 16], [3; 32]).expect("entropy in the secret");
        assert_eq!(secret.device_id(), DeviceId::new([0; 16]));
    }
}
