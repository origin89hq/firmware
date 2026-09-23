//! The single credential cache (L-136), independent of flash and the radio.

use km43::{LinkEnvelope, LinkMessageType, NetChange, NetConfig, NetVerdict, ReqId};
use o89_link::link_header;

/// Maximum encoded credential record. Overflow refuses the change.
pub const CREDENTIAL_BYTES: usize = 192;

/// One validated network configuration, including a clear. Debug never prints secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Credential {
    bytes: [u8; CREDENTIAL_BYTES],
    len: usize,
    version: u32,
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// A malformed or unsupported configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCredential;

impl Credential {
    /// Validate and copy a configuration without allocating.
    pub fn new(change: NetChange<'_>) -> Result<Self, InvalidCredential> {
        let (version, country, hostname) = match change {
            NetChange::Set {
                version,
                ssid,
                psk,
                country,
                hostname,
            } => {
                if ssid.is_empty()
                    || ssid.len() > 32
                    || ssid.as_bytes().contains(&0)
                    || psk.as_bytes().contains(&0)
                {
                    return Err(InvalidCredential);
                }
                (version, country, hostname)
            }
            NetChange::Clear {
                version,
                country,
                hostname,
            } => (version, country, hostname),
        };
        if <[u8; 2]>::try_from(country.as_bytes())
            .ok()
            .and_then(|code| o89_link::Country::new(code).ok())
            .is_none()
            || hostname.is_empty()
            || hostname.len() > 32
            || !hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || hostname.starts_with('-')
            || hostname.ends_with('-')
        {
            return Err(InvalidCredential);
        }
        let mut bytes = [0; CREDENTIAL_BYTES];
        let len = change
            .write(
                link_header(LinkMessageType::NetConfig, ReqId(1)),
                &mut bytes,
            )
            .map_err(|_| InvalidCredential)?;
        Ok(Self {
            bytes,
            len,
            version,
        })
    }

    /// Decode a stored record through the same validation as a link update.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidCredential> {
        let envelope = LinkEnvelope::decode(bytes).map_err(|_| InvalidCredential)?;
        Self::new(NetChange::decode(envelope).map_err(|_| InvalidCredential)?)
    }

    /// Encoded bytes for the storage adapter.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    /// The validated fields for the radio adapter.
    pub fn change(&self) -> Result<NetChange<'_>, InvalidCredential> {
        let envelope = LinkEnvelope::decode(self.encoded()).map_err(|_| InvalidCredential)?;
        NetChange::decode(envelope).map_err(|_| InvalidCredential)
    }

    /// Controller configuration version, with no ordering implied.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// One RAM credential and the version that actually reached NVS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    credential: Option<Credential>,
    stored_version: u32,
    dirty: bool,
}

impl Network {
    /// Restore the cache before association, without waiting for the controller.
    #[must_use]
    pub const fn new(credential: Option<Credential>) -> Self {
        let stored_version = match credential {
            Some(value) => value.version,
            None => 0,
        };
        Self {
            credential,
            stored_version,
            dirty: false,
        }
    }

    /// Replace rather than append; a failed write still replaces RAM (L-136, L-137).
    /// The adapter returns true only after durable storage succeeds.
    pub fn apply(
        &mut self,
        change: NetChange<'_>,
        mut store: impl FnMut(&Credential) -> bool,
    ) -> NetVerdict {
        let Ok(credential) = Credential::new(change) else {
            return NetVerdict {
                outcome: NetConfig::RejectedInvalid,
                version: self.credential.as_ref().map_or(0, Credential::version),
            };
        };
        if !self.dirty && self.credential == Some(credential) {
            return NetVerdict {
                outcome: NetConfig::Stored,
                version: credential.version,
            };
        }
        self.credential = Some(credential);
        let outcome = if store(&credential) {
            self.stored_version = credential.version;
            self.dirty = false;
            NetConfig::Stored
        } else {
            self.dirty = true;
            NetConfig::NvsWriteFailed
        };
        NetVerdict {
            outcome,
            version: credential.version,
        }
    }

    /// The currently active RAM configuration, even after a persistence failure.
    #[must_use]
    pub const fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }

    /// Advertise durable state, so the next handshake repairs a failed write.
    #[must_use]
    pub const fn stored_version(&self) -> u32 {
        self.stored_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set(version: u32, ssid: &str) -> NetChange<'_> {
        NetChange::Set {
            version,
            ssid,
            psk: "password",
            country: "CA",
            hostname: "origin89",
        }
    }
    #[test]
    fn l_136_set_replaces_the_only_network_even_with_an_older_version() {
        let mut network = Network::new(None);
        assert_eq!(
            network.apply(set(8, "first"), |_| true).outcome,
            NetConfig::Stored
        );
        assert_eq!(
            network.apply(set(2, "second"), |_| true).outcome,
            NetConfig::Stored
        );
        assert_eq!(network.credential().unwrap().change(), Ok(set(2, "second")));
        assert_eq!(network.stored_version(), 2);
    }
    #[test]
    fn l_137_failed_write_uses_new_ram_and_advertises_old_durable_version() {
        let mut network = Network::new(Some(Credential::new(set(1, "old")).unwrap()));
        let verdict = network.apply(set(2, "new"), |_| false);
        assert_eq!(verdict.outcome, NetConfig::NvsWriteFailed);
        assert_eq!(verdict.version, 2);
        assert_eq!(network.credential().unwrap().change(), Ok(set(2, "new")));
        assert_eq!(
            network.apply(set(2, "new"), |_| true).outcome,
            NetConfig::Stored
        );
        assert_eq!(network.stored_version(), 2);
    }
    #[test]
    fn l_136_clear_removes_ram_credentials_even_when_storage_fails() {
        let mut network = Network::new(Some(Credential::new(set(1, "old")).unwrap()));
        let clear = NetChange::Clear {
            version: 2,
            country: "CA",
            hostname: "origin89",
        };
        assert_eq!(
            network.apply(clear, |_| false).outcome,
            NetConfig::NvsWriteFailed
        );
        assert_eq!(network.credential().unwrap().change(), Ok(clear));
        assert_eq!(network.apply(clear, |_| true).outcome, NetConfig::Stored);
        let rebooted = Network::new(network.credential().copied());
        assert_eq!(rebooted.stored_version(), 2);
        assert_eq!(rebooted.credential().unwrap().change(), Ok(clear));
    }
    #[test]
    fn invalid_configuration_does_not_touch_ram_or_flash() {
        let mut network = Network::new(None);
        for ssid in ["", "123456789012345678901234567890123", "bad\0name"] {
            assert_eq!(
                network
                    .apply(set(1, ssid), |_| panic!("must not write"))
                    .outcome,
                NetConfig::RejectedInvalid
            );
        }
        assert!(network.credential().is_none());
    }
    #[test]
    fn invalid_country_hostname_and_password_leave_the_active_network_untouched() {
        let original = Credential::new(set(1, "site")).unwrap();
        let mut network = Network::new(Some(original));
        for (country, hostname, psk) in [
            ("ZZ", "origin89", "password"),
            ("ca", "origin89", "password"),
            ("CA", "-invalid", "password"),
            ("CA", "bad.host", "password"),
            ("CA", "", "password"),
            ("CA", "origin89", "short"),
            ("CA", "origin89", "pass\0word"),
        ] {
            let change = NetChange::Set {
                version: 2,
                ssid: "site",
                psk,
                country,
                hostname,
            };
            let verdict = network.apply(change, |_| {
                panic!("invalid configuration must not reach flash")
            });
            assert_eq!(verdict.outcome, NetConfig::RejectedInvalid);
            assert_eq!(verdict.version, 1);
            assert_eq!(network.credential(), Some(&original));
        }
    }

    #[test]
    fn maximum_fields_round_trip_and_truncated_records_are_refused() {
        let change = NetChange::Set {
            version: u32::MAX,
            ssid: "12345678901234567890123456789012",
            psk: "123456789012345678901234567890123456789012345678901234567890123",
            country: "CA",
            hostname: "12345678901234567890123456789012",
        };
        let record = Credential::new(change).unwrap();
        assert_eq!(Credential::decode(record.encoded()), Ok(record));
        for len in 0..record.encoded().len() {
            assert!(Credential::decode(&record.encoded()[..len]).is_err());
        }
    }
}
