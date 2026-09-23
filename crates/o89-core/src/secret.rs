//! The two things a unit is born with: the device id etched into it and
//! the printed secret on its label, from which every key derives.
//!
//! Written once, at manufacture, by the tool that prints the label; read
//! at every boot; never exposed to the comms processor and never logged.
//! The type has no `Debug` for the reason the keys in `km43` have none:
//! the one secret on this device that can never be rotated should not be
//! one `?secret` away from a bench log.
//!
//! cites: P-038, P-044

use km43::{DeviceId, DeviceSecret, PrintedSecret};

use crate::body::{Body, Malformed, Reader, Writer};

/// Bytes of the device id (P-038).
pub const DEVICE_ID_BYTES: usize = 16;

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

    /// The pair every key on the device descends from.
    #[must_use]
    pub const fn device_secret(&self) -> DeviceSecret {
        DeviceSecret::new(
            DeviceId::new(self.device_id),
            PrintedSecret::new(self.printed),
        )
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
        assert_eq!(
            found.device_secret().challenge(5),
            secret.device_secret().challenge(5)
        );
    }

    #[test]
    fn p_044_a_printed_secret_of_zeros_is_refused_and_not_a_record() {
        assert!(Secret::new([1; 16], [0; 32]).is_err());
        let mut bytes = [0u8; SECRET_BYTES];
        bytes[..16].copy_from_slice(&[1; 16]);
        assert_eq!(Secret::decode(&bytes).err(), Some(Malformed { at: 16 }));
    }

    #[test]
    fn p_038_a_device_id_of_zeros_is_an_id_like_any_other() {
        // The id is a salt, not a secret; it is whatever was etched.
        let secret = Secret::new([0; 16], [3; 32]).expect("entropy in the secret");
        assert_eq!(secret.device_id(), DeviceId::new([0; 16]));
    }
}
