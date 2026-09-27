//! The single credential cache (L-136), independent of flash and the radio.
//!
//! The origin token rides inside the encoded `NetConfig` the record holds,
//! so it is stored in the same write as the configuration and its version
//! and cannot outlive them or arrive without them (L-132, L-138).

use km43::{LinkEnvelope, LinkMessageType, NetChange, NetConfig, NetStamp, NetVerdict, ReqId};
use o89_link::link_header;

/// Maximum encoded credential record. Overflow refuses the change.
pub const CREDENTIAL_BYTES: usize = 192;

/// One validated network configuration, including a clear. Debug never prints secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Credential {
    bytes: [u8; CREDENTIAL_BYTES],
    len: usize,
    stamp: NetStamp,
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("stamp", &self.stamp)
            .finish_non_exhaustive()
    }
}

/// A malformed or unsupported configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCredential;

impl Credential {
    /// Validate and copy a configuration without allocating. A `set` or
    /// `clear` at version 0 is refused: zero is the unwritten clear's, which
    /// carries no token (L-133, L-138).
    pub fn new(change: NetChange<'_>) -> Result<Self, InvalidCredential> {
        let stamp = NetStamp::of(&change).map_err(|_| InvalidCredential)?;
        let metadata = match change {
            NetChange::ClearUnwritten => None,
            NetChange::Set {
                ssid,
                psk,
                country,
                hostname,
                ..
            } => {
                if ssid.is_empty()
                    || ssid.len() > 32
                    || ssid.as_bytes().contains(&0)
                    || psk.as_bytes().contains(&0)
                {
                    return Err(InvalidCredential);
                }
                Some((country, hostname))
            }
            NetChange::Clear {
                country, hostname, ..
            } => Some((country, hostname)),
        };
        if let Some((country, hostname)) = metadata
            && (<[u8; 2]>::try_from(country.as_bytes())
                .ok()
                .and_then(|code| o89_link::Country::new(code).ok())
                .is_none()
                || hostname.is_empty()
                || hostname.len() > 32
                || !hostname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || hostname.starts_with('-')
                || hostname.ends_with('-'))
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
        Ok(Self { bytes, len, stamp })
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
        self.stamp.net_version()
    }

    /// The version with the origin token it was sent under (L-138).
    #[must_use]
    pub const fn stamp(&self) -> NetStamp {
        self.stamp
    }
}

/// One RAM credential and the version and token that actually reached NVS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    credential: Option<Credential>,
    stored: NetStamp,
    dirty: bool,
}

impl Network {
    /// Restore the cache before association, without waiting for the controller.
    #[must_use]
    pub const fn new(credential: Option<Credential>) -> Self {
        let stored = match credential {
            Some(value) => value.stamp,
            None => NetStamp::Unwritten,
        };
        Self {
            credential,
            stored,
            dirty: false,
        }
    }

    /// Replace rather than append; a failed write still replaces RAM (L-136, L-137).
    /// The adapter returns true only after durable storage succeeds, and
    /// until one does the version and token reported are flash's, as
    /// `km43::NetStamp::settle` states the rule (L-132, L-137).
    pub fn apply(
        &mut self,
        change: NetChange<'_>,
        mut store: impl FnMut(&Credential) -> bool,
    ) -> NetVerdict {
        let Ok(credential) = Credential::new(change) else {
            return NetVerdict {
                outcome: NetConfig::RejectedInvalid,
                version: self.stored.net_version(),
            };
        };
        if !self.dirty && self.credential == Some(credential) {
            return NetVerdict {
                outcome: NetConfig::Stored,
                version: credential.version(),
            };
        }
        self.credential = Some(credential);
        let outcome = if store(&credential) {
            self.stored = credential.stamp;
            self.dirty = false;
            NetConfig::Stored
        } else {
            self.dirty = true;
            NetConfig::NvsWriteFailed
        };
        NetVerdict {
            outcome,
            version: self.stored.net_version(),
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
        self.stored.net_version()
    }

    /// The version and token that reached NVS, which `LinkUp` reports
    /// (L-132, L-137): never the RAM copy's after a failed write.
    #[must_use]
    pub const fn stored(&self) -> NetStamp {
        self.stored
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
            origin: km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]),
        }
    }
    #[test]
    fn l_137_unwritten_clear_failure_reports_the_persisted_version_and_retries() {
        let mut network = Network::new(Some(Credential::new(set(7, "foreign")).unwrap()));
        assert_eq!(
            network.apply(NetChange::ClearUnwritten, |_| false),
            NetVerdict {
                outcome: NetConfig::NvsWriteFailed,
                version: 7,
            }
        );
        assert_eq!(
            network.credential().unwrap().change(),
            Ok(NetChange::ClearUnwritten)
        );
        assert_eq!(network.stored_version(), 7);
        assert_eq!(
            network.apply(NetChange::ClearUnwritten, |_| true),
            NetVerdict {
                outcome: NetConfig::Stored,
                version: 0,
            }
        );
        assert_eq!(network.stored_version(), 0);
        assert_eq!(
            network.apply(NetChange::ClearUnwritten, |_| panic!("duplicate erase")),
            NetVerdict {
                outcome: NetConfig::Stored,
                version: 0,
            }
        );
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
        assert_eq!(verdict.version, 1);
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
            origin: km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]),
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
                origin: km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]),
            };
            let verdict = network.apply(change, |_| {
                panic!("invalid configuration must not reach flash")
            });
            assert_eq!(verdict.outcome, NetConfig::RejectedInvalid);
            assert_eq!(verdict.version, 1);
            assert_eq!(network.credential(), Some(&original));
        }
    }

    const FOREIGN: km43::NetOrigin = km43::NetOrigin::new([0xC3; km43::NET_ORIGIN_BYTES]);

    #[test]
    fn l_137_a_failed_write_keeps_reporting_the_persisted_token_at_an_equal_version() {
        let theirs = NetChange::Set {
            version: 3,
            ssid: "theirs",
            psk: "password",
            country: "US",
            hostname: "elsewhere",
            origin: FOREIGN,
        };
        let mut network = Network::new(Some(Credential::new(theirs).unwrap()));
        let before = network.stored();
        assert_eq!(before.net_origin(), Some(FOREIGN));
        let verdict = network.apply(set(3, "ours"), |_| false);
        assert_eq!(
            verdict,
            NetVerdict {
                outcome: NetConfig::NvsWriteFailed,
                version: 3
            }
        );
        assert_eq!(network.credential().unwrap().change(), Ok(set(3, "ours")));
        assert_eq!(network.stored(), before, "flash's token, not RAM's");
        assert_eq!(
            network.apply(set(3, "ours"), |_| true).outcome,
            NetConfig::Stored
        );
        assert_eq!(
            network.stored().net_origin(),
            Some(km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]))
        );
    }

    #[test]
    fn l_138_the_token_is_stored_in_the_record_with_its_version() {
        let record = Credential::new(set(4, "site")).unwrap();
        let decoded = Credential::decode(record.encoded()).unwrap();
        assert_eq!(decoded.stamp(), record.stamp());
        assert_eq!(
            decoded.stamp().net_origin(),
            Some(km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]))
        );
        let unwritten = Credential::new(NetChange::ClearUnwritten).unwrap();
        assert_eq!(unwritten.stamp(), NetStamp::Unwritten);
        assert_eq!(Network::new(None).stored(), NetStamp::Unwritten);
    }

    #[test]
    fn l_133_a_written_change_at_version_zero_is_refused_whatever_it_carries() {
        let mut network = Network::new(Some(Credential::new(set(2, "site")).unwrap()));
        let clear = NetChange::Clear {
            version: 0,
            country: "CA",
            hostname: "origin89",
            origin: FOREIGN,
        };
        for change in [set(0, "site"), clear] {
            assert_eq!(Credential::new(change), Err(InvalidCredential));
            assert_eq!(
                network.apply(change, |_| panic!("must not write")),
                NetVerdict {
                    outcome: NetConfig::RejectedInvalid,
                    version: 2
                }
            );
        }
        assert_eq!(network.stored().net_version(), 2);
    }

    #[test]
    fn maximum_fields_round_trip_and_truncated_records_are_refused() {
        let change = NetChange::Set {
            version: u32::MAX,
            ssid: "12345678901234567890123456789012",
            psk: "123456789012345678901234567890123456789012345678901234567890123",
            country: "CA",
            hostname: "12345678901234567890123456789012",
            origin: km43::NetOrigin::new([0x5A; km43::NET_ORIGIN_BYTES]),
        };
        let record = Credential::new(change).unwrap();
        assert_eq!(Credential::decode(record.encoded()), Ok(record));
        for len in 0..record.encoded().len() {
            assert!(Credential::decode(&record.encoded()[..len]).is_err());
        }
    }
}
