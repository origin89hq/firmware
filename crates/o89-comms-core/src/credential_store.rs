//! A single fixed NVS record. Replacement erases the old credential first.
//!
//! This cache is reconstructible from the controller. Power loss can leave it
//! empty, never an acknowledged partial record. It deliberately is not an
//! ESP-IDF key/value NVS format: no allocator, history, or second network.
use crate::{CREDENTIAL_BYTES, Credential};

/// Four-byte commit marker, length, payload, and checksum; padded to flash words.
pub const STORED_CREDENTIAL_BYTES: usize = 204;
const COMMIT: [u8; 4] = *b"O89N";

/// Operations on the dedicated credential partition, never application flash.
pub trait CredentialFlash {
    /// Adapter error.
    type Error;
    /// Read at a partition-relative byte offset.
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error>;
    /// Erase the whole credential partition, including obsolete passphrases.
    fn erase(&mut self) -> Result<(), Self::Error>;
    /// Program erased flash at a partition-relative byte offset.
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// The record was unreadable, incomplete, corrupt, or could not be committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStorageError;

/// Load a committed cache. An erased or interrupted record is an empty cache.
pub fn load_credential(
    flash: &mut impl CredentialFlash,
) -> Result<Option<Credential>, CredentialStorageError> {
    let mut bytes = [0; STORED_CREDENTIAL_BYTES];
    flash
        .read(0, &mut bytes)
        .map_err(|_| CredentialStorageError)?;
    if bytes.get(..4) != Some(COMMIT.as_slice()) {
        return Ok(None);
    }
    let len = u32::from_le_bytes(
        bytes
            .get(4..8)
            .ok_or(CredentialStorageError)?
            .try_into()
            .map_err(|_| CredentialStorageError)?,
    );
    let len = usize::try_from(len).map_err(|_| CredentialStorageError)?;
    let payload = bytes
        .get(8..200)
        .and_then(|data| data.get(..len))
        .ok_or(CredentialStorageError)?;
    let checksum = u32::from_le_bytes(
        bytes
            .get(200..204)
            .ok_or(CredentialStorageError)?
            .try_into()
            .map_err(|_| CredentialStorageError)?,
    );
    if crc(bytes.get(4..200).ok_or(CredentialStorageError)?) != checksum {
        return Err(CredentialStorageError);
    }
    Credential::decode(payload)
        .map(Some)
        .map_err(|_| CredentialStorageError)
}

/// Erase, write, commit, then read back before reporting success. Failure leaves
/// RAM policy to `Network::apply`; the caller must not advertise durability.
pub fn store_credential(
    flash: &mut impl CredentialFlash,
    credential: &Credential,
) -> Result<(), CredentialStorageError> {
    let mut bytes = [0u8; STORED_CREDENTIAL_BYTES];
    let payload = credential.encoded();
    let len = u32::try_from(payload.len()).map_err(|_| CredentialStorageError)?;
    bytes
        .get_mut(4..8)
        .ok_or(CredentialStorageError)?
        .copy_from_slice(&len.to_le_bytes());
    bytes
        .get_mut(8..200)
        .and_then(|data| data.get_mut(..payload.len()))
        .ok_or(CredentialStorageError)?
        .copy_from_slice(payload);
    let checksum = crc(bytes.get(4..200).ok_or(CredentialStorageError)?);
    bytes
        .get_mut(200..204)
        .ok_or(CredentialStorageError)?
        .copy_from_slice(&checksum.to_le_bytes());
    flash.erase().map_err(|_| CredentialStorageError)?;
    flash
        .write(4, bytes.get(4..).ok_or(CredentialStorageError)?)
        .map_err(|_| CredentialStorageError)?;
    flash
        .write(0, &COMMIT)
        .map_err(|_| CredentialStorageError)?;
    if load_credential(flash)? != Some(*credential) {
        return Err(CredentialStorageError);
    }
    Ok(())
}

fn crc(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
        }
    }
    !value
}

const _: () = assert!(CREDENTIAL_BYTES == 192);

#[cfg(test)]
mod tests {
    use super::*;
    use km43::NetChange;
    struct Flash {
        bytes: [u8; 4096],
        budget: usize,
    }
    impl CredentialFlash for Flash {
        type Error = ();
        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), ()> {
            if self.budget == 0 {
                return Err(());
            }
            bytes.copy_from_slice(
                &self.bytes[offset as usize..(offset as usize).checked_add(bytes.len()).unwrap()],
            );
            Ok(())
        }
        fn erase(&mut self) -> Result<(), ()> {
            for byte in &mut self.bytes {
                if self.budget == 0 {
                    return Err(());
                }
                self.budget = self.budget.checked_sub(1).unwrap();
                *byte = 255;
            }
            Ok(())
        }
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), ()> {
            for (at, byte) in bytes.iter().enumerate() {
                if self.budget == 0 {
                    return Err(());
                }
                self.budget = self.budget.checked_sub(1).unwrap();
                self.bytes[(offset as usize).checked_add(at).unwrap()] &= byte;
            }
            Ok(())
        }
    }
    fn record() -> Credential {
        Credential::new(NetChange::Set {
            version: 7,
            ssid: "site",
            psk: "password",
            country: "CA",
            hostname: "origin89",
        })
        .unwrap()
    }
    #[test]
    fn l_136_record_replaces_and_clear_physically_erases_the_passphrase() {
        let mut flash = Flash {
            bytes: [255; 4096],
            budget: usize::MAX,
        };
        assert_eq!(load_credential(&mut flash), Ok(None));
        store_credential(&mut flash, &record()).unwrap();
        assert_eq!(load_credential(&mut flash), Ok(Some(record())));
        let clear = Credential::new(NetChange::Clear {
            version: 8,
            country: "CA",
            hostname: "origin89",
        })
        .unwrap();
        store_credential(&mut flash, &clear).unwrap();
        assert_eq!(load_credential(&mut flash), Ok(Some(clear)));
        assert!(!flash.bytes.windows(8).any(|window| window == b"password"));
    }
    #[test]
    fn l_137_power_loss_at_every_byte_never_loads_a_partial_new_record() {
        for budget in 0..=4301 {
            let mut flash = Flash {
                bytes: [255; 4096],
                budget,
            };
            let result = store_credential(&mut flash, &record());
            flash.budget = usize::MAX;
            let loaded = load_credential(&mut flash);
            assert!(
                matches!(loaded, Ok(None) | Err(CredentialStorageError))
                    || loaded == Ok(Some(record()))
            );
            if result.is_ok() {
                assert_eq!(loaded, Ok(Some(record())));
            }
        }
    }
    #[test]
    fn l_137_interrupted_replacement_or_clear_is_old_new_or_unavailable() {
        let old = record();
        let replacement = Credential::new(km43::NetChange::Set {
            version: 8,
            ssid: "second",
            psk: "different",
            country: "US",
            hostname: "origin89",
        })
        .unwrap();
        let clear = Credential::new(km43::NetChange::Clear {
            version: 8,
            country: "US",
            hostname: "origin89",
        })
        .unwrap();
        let mut initial = Flash {
            bytes: [255; 4096],
            budget: usize::MAX,
        };
        store_credential(&mut initial, &old).unwrap();
        for next in [replacement, clear] {
            for budget in 0..=4301 {
                let mut flash = Flash {
                    bytes: initial.bytes,
                    budget,
                };
                let result = store_credential(&mut flash, &next);
                flash.budget = usize::MAX;
                let loaded = load_credential(&mut flash);
                assert!(
                    matches!(loaded, Ok(None) | Err(CredentialStorageError))
                        || loaded == Ok(Some(old))
                        || loaded == Ok(Some(next))
                );
                if result.is_ok() {
                    assert_eq!(loaded, Ok(Some(next)));
                }
            }
        }
    }

    #[test]
    fn corrupt_payload_or_length_and_failed_reads_are_refused() {
        let mut flash = Flash {
            bytes: [255; 4096],
            budget: usize::MAX,
        };
        store_credential(&mut flash, &record()).unwrap();
        flash.bytes[20] ^= 1;
        assert_eq!(load_credential(&mut flash), Err(CredentialStorageError));
        flash.bytes[4..8].fill(255);
        assert_eq!(load_credential(&mut flash), Err(CredentialStorageError));
        flash.budget = 0;
        assert_eq!(load_credential(&mut flash), Err(CredentialStorageError));
    }
}
