//! The master copy of the Wi-Fi credentials, and the version and origin
//! token the comms processor's cache is compared against.
//!
//! The controller holds the master copy and the comms processor a cache in
//! its own NVS, because the two chips boot independently and a comms
//! processor that had to wait for the controller before associating turns
//! a slow boot into a site with no connectivity (L-130). The version and
//! the origin token decide a push: the controller pushes after every
//! link-up whose reported version is *different*, not *newer*, or whose
//! token is not this section's, so a board out of another unit is
//! overwritten and a fresh board is provisioned (L-133). The token is drawn
//! when the section is created from version 0, on its first write and on a
//! repair of an unreadable one, and kept through every later write, the
//! factory clear included (L-138): a board unplugged across a repair comes
//! back at a version the repaired section reaches again. A clear
//! carries no credential (L-131); the country is on the wire because a
//! radio in the wrong regulatory domain is an illegal transmitter (L-134);
//! and a factory reset clears, so a passphrase does not survive on a board
//! about to be pulled (L-135).
//!
//! cites: L-130, L-131, L-133, L-134, L-138

use core::num::NonZeroU32;

use km43::{NET_ORIGIN_BYTES, NetOrigin, NetStamp};

use crate::body::{Body, Malformed, Reader, Writer};
use crate::text::{Text, TooLong};

/// The bytes the copy takes in its record.
pub const NETWORK_BYTES: usize = 160;

/// Bytes of an SSID.
pub const SSID_BYTES: usize = 32;

/// The passphrase's bounds, inclusive (L-131).
pub const PSK_MIN: usize = 8;
/// The passphrase's upper bound, inclusive (L-131).
pub const PSK_MAX: usize = 63;

/// Bytes of the hostname.
pub const HOSTNAME_BYTES: usize = 32;

const NONE: u8 = 0;
const SET: u8 = 1;
const LAYOUT: usize =
    4 + NET_ORIGIN_BYTES + 1 + 2 + (1 + HOSTNAME_BYTES) + 1 + (1 + SSID_BYTES) + (1 + PSK_MAX);
const _: () = assert!(LAYOUT <= NETWORK_BYTES);

/// A passphrase of 8 to 63 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Psk(Text<PSK_MAX>);

impl core::fmt::Debug for Psk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Psk({} bytes)", self.0.len())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Psk {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Psk({=usize} bytes)", self.0.len());
    }
}

/// A passphrase outside its bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BadPsk {
    /// The bytes it had.
    pub len: usize,
}

impl Psk {
    /// `text`, refused outside 8 to 63 bytes.
    pub fn new(text: &str) -> Result<Self, BadPsk> {
        let bad = BadPsk { len: text.len() };
        if text.len() < PSK_MIN {
            return Err(bad);
        }
        Text::new(text).map(Self).map_err(|TooLong { .. }| bad)
    }

    /// The passphrase.
    #[must_use]
    pub const fn as_text(&self) -> &Text<PSK_MAX> {
        &self.0
    }
}

pub use o89_link::{BadCountry, Country};

/// One network's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Credentials {
    /// The network's name.
    pub ssid: Text<SSID_BYTES>,
    /// Its passphrase.
    pub psk: Psk,
    /// Where the radio is.
    pub country: Country,
    /// What the comms processor calls itself on that network.
    pub hostname: Text<HOSTNAME_BYTES>,
}

/// The master copy: a version that climbs on every change with the origin
/// token drawn when the section was created, and the credentials, if any
/// are set. A version of 0 has no token, and every other version has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Network {
    stamp: NetStamp,
    credentials: Option<Credentials>,
    country: Option<[u8; 2]>,
    hostname: Text<HOSTNAME_BYTES>,
}

/// The version is at the top of its `u32`; refused rather than wrapped,
/// because a version back at one matches a cache that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VersionCeiling;

/// Why a validated network write cannot replace the master copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkChangeError {
    /// The section or retained passphrase is invalid.
    Invalid(km43::ConfigError),
    /// No further version is representable.
    VersionCeiling,
}
impl From<km43::ConfigError> for NetworkChangeError {
    fn from(why: km43::ConfigError) -> Self {
        Self::Invalid(why)
    }
}

/// A validated write, before anything is written (L-138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a validated write that is never written changes nothing"]
pub enum NetworkChange {
    /// A write to a written section, which keeps the section's token.
    Edit(Network),
    /// The write that creates the section from version 0, which owes a token
    /// drawn for it before it can be written.
    Create(Unoriginated),
}

/// The section a write creates, at version 1, until it has its origin token.
/// Nothing can encode or send it: the only way on is [`Self::originate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a created section with no token is never written"]
pub struct Unoriginated {
    credentials: Option<Credentials>,
    country: [u8; 2],
    hostname: Text<HOSTNAME_BYTES>,
}

impl Unoriginated {
    /// The section at version 1 under `origin`, a fresh draw from the
    /// generator (P-237).
    #[must_use]
    pub const fn originate(self, origin: NetOrigin) -> Network {
        Network {
            stamp: NetStamp::Written {
                version: NonZeroU32::MIN,
                origin,
            },
            credentials: self.credentials,
            country: Some(self.country),
            hostname: self.hostname,
        }
    }
}

impl Network {
    /// A unit out of its box: version zero, no network.
    pub const NONE: Self = Self {
        stamp: NetStamp::Unwritten,
        credentials: None,
        country: None,
        hostname: Text::EMPTY,
    };

    /// The version the comms processor's cache is compared against.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.stamp.net_version()
    }

    /// The token drawn when the section was created, none while it is
    /// unwritten (L-138).
    #[must_use]
    pub const fn origin(&self) -> Option<NetOrigin> {
        self.stamp.net_origin()
    }

    /// The version and token together, as the comms processor's `LinkUp` is
    /// compared against them (L-133).
    #[must_use]
    pub const fn stamp(&self) -> NetStamp {
        self.stamp
    }

    /// The stamp of the next write: the next version under the same token,
    /// or version 1 under `fresh` when this one creates the section.
    fn next(&self, fresh: NetOrigin) -> Result<NetStamp, VersionCeiling> {
        Ok(match self.stamp {
            NetStamp::Unwritten => NetStamp::Written {
                version: NonZeroU32::MIN,
                origin: fresh,
            },
            NetStamp::Written { version, origin } => NetStamp::Written {
                version: version.checked_add(1).ok_or(VersionCeiling)?,
                origin,
            },
        })
    }

    /// The credentials, if a network is set.
    #[must_use]
    pub const fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    /// Set the network, moving the version. `fresh` becomes the token only
    /// when this creates the section; a written one keeps its own.
    pub fn set(
        &mut self,
        credentials: Credentials,
        fresh: NetOrigin,
    ) -> Result<(), VersionCeiling> {
        self.stamp = self.next(fresh)?;
        self.country = Some(credentials.country.as_bytes());
        self.hostname = credentials.hostname;
        self.credentials = Some(credentials);
        Ok(())
    }

    /// Clear the network, moving the version under the same token, so a
    /// cache that still holds the old one is told (L-131, L-135, L-138). An
    /// unwritten section stays unwritten: a reset creates no section.
    pub fn clear(&mut self) -> Result<(), VersionCeiling> {
        let NetStamp::Written { version, origin } = self.stamp else {
            return Ok(());
        };
        self.stamp = NetStamp::Written {
            version: version.checked_add(1).ok_or(VersionCeiling)?,
            origin,
        };
        self.credentials = None;
        Ok(())
    }

    /// Validate a whole write, resolving a retained passphrase only for its
    /// SSID. A write to an unwritten section is its creation and owes a
    /// token; any other keeps the section's (L-138).
    pub fn changed(
        &self,
        write: km43::NetworkWrite<'_>,
    ) -> Result<NetworkChange, NetworkChangeError> {
        use km43::{ConfigError, PassphraseChange};
        let held = self.credentials.as_ref();
        let held_ssid = held
            .map(|join| km43::Ssid::new(join.ssid.as_str()))
            .transpose()?;
        let passphrase = write.passphrase(held_ssid)?;
        let country_bytes = write
            .country
            .as_str()
            .as_bytes()
            .try_into()
            .map_err(|_| ConfigError::CountryNotCapitals)?;
        let country = Country::new(country_bytes).map_err(|_| ConfigError::CountryNotCapitals)?;
        let hostname = Text::new(write.hostname.as_str()).map_err(|_| ConfigError::NotAHostname)?;
        let credentials = match write.join {
            None => None,
            Some(join) => {
                let psk = match passphrase {
                    PassphraseChange::Set(value) => {
                        Psk::new(value.as_str()).map_err(|_| ConfigError::NoPassphraseHeld)?
                    }
                    PassphraseChange::Keep => held.ok_or(ConfigError::NoPassphraseHeld)?.psk,
                    PassphraseChange::Clear => return Err(ConfigError::NoPassphraseHeld.into()),
                };
                Some(Credentials {
                    ssid: Text::new(join.ssid.as_str())
                        .map_err(|_| ConfigError::NoPassphraseHeld)?,
                    psk,
                    country,
                    hostname,
                })
            }
        };
        Ok(match self.stamp {
            NetStamp::Unwritten => NetworkChange::Create(Unoriginated {
                credentials,
                country: country.as_bytes(),
                hostname,
            }),
            NetStamp::Written { version, origin } => NetworkChange::Edit(Self {
                stamp: NetStamp::Written {
                    version: version
                        .checked_add(1)
                        .ok_or(NetworkChangeError::VersionCeiling)?,
                    origin,
                },
                credentials,
                country: Some(country.as_bytes()),
                hostname,
            }),
        })
    }

    /// The public shape has no field capable of holding the passphrase.
    pub fn read_body(&self) -> Result<km43::NetworkRead<'_>, km43::ConfigError> {
        let country = self
            .country
            .as_ref()
            .ok_or(km43::ConfigError::CountryNotCapitals)?;
        let country =
            core::str::from_utf8(country).map_err(|_| km43::ConfigError::CountryNotCapitals)?;
        Ok(km43::NetworkRead {
            join: self
                .credentials
                .as_ref()
                .map(|join| {
                    km43::Ssid::new(join.ssid.as_str()).map(|ssid| km43::JoinRead {
                        ssid,
                        psk_set: true,
                    })
                })
                .transpose()?,
            country: km43::Country::new(country)?,
            hostname: km43::Hostname::new(self.hostname.as_str())?,
        })
    }

    /// The radio's copy, including credentials only on the private link.
    #[must_use]
    pub fn change(&self) -> Option<km43::NetChange<'_>> {
        if *self == Self::NONE {
            return Some(km43::NetChange::ClearUnwritten);
        }
        let NetStamp::Written { version, origin } = self.stamp else {
            return None;
        };
        let version = version.get();
        let country = core::str::from_utf8(self.country.as_ref()?).ok()?;
        let hostname = self.hostname.as_str();
        Some(match self.credentials.as_ref() {
            Some(join) => km43::NetChange::Set {
                version,
                ssid: join.ssid.as_str(),
                psk: join.psk.as_text().as_str(),
                country,
                hostname,
                origin,
            },
            None => km43::NetChange::Clear {
                version,
                country,
                hostname,
                origin,
            },
        })
    }

    /// Whether a comms processor stating `cache` after link-up gets a push:
    /// when the version differs, not when ours is newer, or when its token is
    /// absent or not this section's while the section is written (L-133).
    #[must_use]
    pub fn needs_push(&self, cache: &km43::LinkUp<'_>) -> bool {
        self.stamp.needs_push(cache)
    }
}

impl Body<NETWORK_BYTES> for Network {
    fn encode(&self) -> [u8; NETWORK_BYTES] {
        let mut out = [0u8; NETWORK_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.u32(self.version());
        writer.put(
            &self
                .origin()
                .map_or([0; NET_ORIGIN_BYTES], |origin| *origin.bytes()),
        );
        writer.u8(if self.country.is_some() { SET } else { NONE });
        writer.put(&self.country.unwrap_or([0; 2]));
        self.hostname.put(&mut writer);
        match &self.credentials {
            None => writer.u8(NONE),
            Some(credentials) => {
                writer.u8(SET);
                credentials.ssid.put(&mut writer);
                credentials.psk.0.put(&mut writer);
            }
        }
        out
    }

    fn decode(bytes: &[u8; NETWORK_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let version = reader.u32()?;
        let origin = NetOrigin::new(reader.take::<NET_ORIGIN_BYTES>()?);
        let stamp = match NonZeroU32::new(version) {
            Some(version) => NetStamp::Written { version, origin },
            // An unwritten section has no token, and bytes where one would be
            // are not a section this firmware wrote.
            None if *origin.bytes() == [0; NET_ORIGIN_BYTES] => NetStamp::Unwritten,
            None => return Err(reader.malformed(NET_ORIGIN_BYTES)),
        };
        let present = reader.u8()?;
        let country_bytes = reader.take::<2>()?;
        let country = match present {
            NONE => None,
            SET => Some(
                Country::new(country_bytes)
                    .map_err(|_| reader.malformed(2))?
                    .as_bytes(),
            ),
            _ => return Err(reader.malformed(1)),
        };
        let hostname = Text::take(&mut reader)?;
        let credentials = match reader.u8()? {
            NONE => None,
            SET => {
                let ssid = Text::take(&mut reader)?;
                let psk = Text::<PSK_MAX>::take(&mut reader)?;
                if psk.len() < PSK_MIN {
                    return Err(reader.malformed(PSK_MAX.saturating_add(1)));
                }
                Some(Credentials {
                    ssid,
                    psk: Psk(psk),
                    country: Country::new(country.ok_or(reader.malformed(2))?)
                        .map_err(|_| reader.malformed(2))?,
                    hostname,
                })
            }
            _ => return Err(reader.malformed(1)),
        };
        let value = Self {
            stamp,
            credentials,
            country,
            hostname,
        };
        if version != 0 {
            value.read_body().map_err(|_| Malformed { at: 0 })?;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: NetOrigin = NetOrigin::new([0x5A; NET_ORIGIN_BYTES]);
    const FOREIGN: NetOrigin = NetOrigin::new([0xC3; NET_ORIGIN_BYTES]);

    /// The comms processor's `LinkUp` as the controller compares it.
    fn cache(net_version: u32, net_origin: Option<NetOrigin>) -> km43::LinkUp<'static> {
        km43::LinkUp {
            version: km43::Version { major: 1, minor: 0 },
            role: km43::Side::Comms,
            fw: "0.1.0",
            boot_id: 1,
            hw: "comms",
            net_version: Some(net_version),
            device_id: None,
            net_origin,
        }
    }

    fn cabin() -> Credentials {
        Credentials {
            ssid: Text::new("cabin").expect("fits"),
            psk: Psk::new("correct horse").expect("long enough"),
            country: Country::new(*b"CA").expect("a country"),
            hostname: Text::new("origin89").expect("fits"),
        }
    }

    fn write(ssid: &str) -> km43::NetworkWrite<'_> {
        km43::NetworkWrite {
            join: Some(km43::JoinWrite {
                ssid: km43::Ssid::new(ssid).expect("ssid"),
                psk: Some(km43::Passphrase::new("correct horse").expect("psk")),
            }),
            country: km43::Country::new("CA").expect("country"),
            hostname: km43::Hostname::new("origin89").expect("host"),
        }
    }

    fn edited(network: &Network, ssid: &str) -> Network {
        match network.changed(write(ssid)).expect("valid") {
            NetworkChange::Edit(next) => next,
            NetworkChange::Create(_) => panic!("a written section is edited"),
        }
    }

    #[test]
    fn l_135_clear_retains_radio_metadata_and_advances_version() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        network.clear().expect("clear");
        assert_eq!(
            network.change(),
            Some(km43::NetChange::Clear {
                version: 2,
                country: "CA",
                hostname: "origin89",
                origin: ORIGIN,
            })
        );
        assert_eq!(Network::decode(&network.encode()), Ok(network));
    }

    #[test]
    fn l_135_a_reset_of_an_unwritten_section_creates_no_section() {
        let mut network = Network::NONE;
        network.clear().expect("nothing to clear");
        assert_eq!(network, Network::NONE);
        assert_eq!(network.change(), Some(km43::NetChange::ClearUnwritten));
    }

    #[test]
    fn p_107_keep_requires_the_byte_identical_ssid() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        let mut write = km43::NetworkWrite {
            join: Some(km43::JoinWrite {
                ssid: km43::Ssid::new("cabin").expect("ssid"),
                psk: None,
            }),
            country: km43::Country::new("CA").expect("country"),
            hostname: km43::Hostname::new("new-host").expect("host"),
        };
        let NetworkChange::Edit(kept) = network.changed(write).expect("kept") else {
            panic!("a written section is edited");
        };
        assert_eq!(kept.credentials().expect("join").psk, cabin().psk);
        write.join.as_mut().expect("join").ssid = km43::Ssid::new("Cabin").expect("ssid");
        assert_eq!(
            network.changed(write),
            Err(NetworkChangeError::Invalid(
                km43::ConfigError::PassphraseForAnotherNetwork
            ))
        );
        assert_eq!(
            Network::NONE.changed(write),
            Err(NetworkChangeError::Invalid(
                km43::ConfigError::NoPassphraseHeld
            ))
        );
    }

    #[test]
    fn p_106_read_has_presence_but_no_passphrase() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        let mut bytes = [0; km43::MAX_NETWORK_READ_BYTES];
        let len = network
            .read_body()
            .expect("body")
            .encode(&mut bytes)
            .expect("encoded");
        let read = km43::NetworkRead::decode(&bytes[..len]).expect("read");
        assert!(read.join.expect("join").psk_set);
        assert!(!bytes.windows(13).any(|window| window == b"correct horse"));
    }

    #[test]
    fn l_133_a_push_follows_a_different_version_not_a_newer_one() {
        let mut network = Network::NONE;
        assert!(!network.needs_push(&cache(0, None)));
        network.set(cabin(), ORIGIN).expect("room in the version");
        assert_eq!(network.version(), 1);
        assert!(
            network.needs_push(&cache(0, None)),
            "a fresh board is provisioned"
        );
        assert!(
            network.needs_push(&cache(7, Some(ORIGIN))),
            "a higher version is overwritten, not deferred to"
        );
        assert!(!network.needs_push(&cache(1, Some(ORIGIN))));
    }

    #[test]
    fn l_133_an_equal_version_from_the_same_origin_needs_no_push() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        let network = edited(&network, "cabin-2");
        assert_eq!(network.version(), 2);
        assert!(!network.needs_push(&cache(2, Some(ORIGIN))));
    }

    #[test]
    fn l_133_an_equal_version_from_another_controller_is_pushed() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        assert!(
            network.needs_push(&cache(1, Some(FOREIGN))),
            "a board out of another unit at this very version is overwritten"
        );
    }

    #[test]
    fn l_133_a_cache_with_no_token_is_pushed_while_the_master_is_written() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("set");
        assert!(network.needs_push(&cache(1, None)));
        let mut silent = cache(1, None);
        silent.net_version = None;
        assert!(network.needs_push(&silent), "no version matches nothing");
    }

    #[test]
    fn l_133_an_unwritten_master_compares_the_version_alone() {
        let network = Network::NONE;
        assert!(!network.needs_push(&cache(0, None)), "0 against 0");
        assert!(
            network.needs_push(&cache(4, Some(FOREIGN))),
            "a foreign cache gets the unwritten clear"
        );
    }

    #[test]
    fn l_138_the_write_that_creates_the_section_owes_a_token_and_later_ones_keep_it() {
        let NetworkChange::Create(created) = Network::NONE.changed(write("cabin")).expect("valid")
        else {
            panic!("an unwritten section is created");
        };
        let mut network = created.originate(ORIGIN);
        assert_eq!(
            network.stamp(),
            NetStamp::Written {
                version: NonZeroU32::MIN,
                origin: ORIGIN,
            }
        );
        let network2 = edited(&network, "cabin-2");
        assert_eq!((network2.version(), network2.origin()), (2, Some(ORIGIN)));
        network.set(cabin(), FOREIGN).expect("set");
        assert_eq!(
            (network.version(), network.origin()),
            (2, Some(ORIGIN)),
            "a fresh draw is ignored once the section has its token"
        );
        network.clear().expect("clear");
        assert_eq!((network.version(), network.origin()), (3, Some(ORIGIN)));
        assert!(matches!(
            network.change(),
            Some(km43::NetChange::Clear { origin, .. }) if origin == ORIGIN
        ));
    }

    #[test]
    fn l_138_a_repaired_section_is_pushed_to_a_module_that_missed_the_repair() {
        // Before the damage: version 3 under the first token, and a module
        // that stored it and was then unplugged.
        let mut before = Network::NONE;
        before.set(cabin(), ORIGIN).expect("1");
        let before = edited(&edited(&before, "cabin-2"), "cabin-3");
        let unplugged = cache(before.version(), before.origin());
        assert!(!before.needs_push(&unplugged));
        // The section reads unreadable, so the repair writes it at
        // `expected_version` 0 and draws a new token (P-100, P-108).
        let NetworkChange::Create(created) = Network::NONE.changed(write("cabin")).expect("valid")
        else {
            panic!("a repair creates the section");
        };
        let mut repaired = created.originate(FOREIGN);
        for version in 1..=3 {
            assert_eq!(repaired.version(), version);
            assert!(
                repaired.needs_push(&unplugged),
                "the old passphrase at version {version} is not this section's"
            );
            repaired = edited(&repaired, "cabin");
        }
    }

    #[test]
    fn l_131_a_clear_moves_the_version_and_carries_no_credential() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("room in the version");
        network.clear().expect("room in the version");
        assert_eq!(network.version(), 2);
        assert_eq!(network.credentials(), None);
        assert!(
            network.needs_push(&cache(1, Some(ORIGIN))),
            "a cache holding the old network is told"
        );
        let mut top = Network {
            stamp: NetStamp::Written {
                version: NonZeroU32::MAX,
                origin: ORIGIN,
            },
            credentials: None,
            country: Some(*b"CA"),
            hostname: Text::new("origin89").expect("fits"),
        };
        assert_eq!(top.set(cabin(), ORIGIN), Err(VersionCeiling));
        assert_eq!(top.clear(), Err(VersionCeiling));
        assert_eq!(
            top.changed(km43::NetworkWrite {
                join: None,
                country: km43::Country::new("CA").expect("country"),
                hostname: km43::Hostname::new("origin89").expect("hostname"),
            }),
            Err(NetworkChangeError::VersionCeiling)
        );
    }

    #[test]
    fn l_131_a_passphrase_is_eight_to_sixty_three_bytes() {
        assert_eq!(Psk::new("seven77"), Err(BadPsk { len: 7 }));
        assert!(Psk::new("eight888").is_ok());
        assert!(Psk::new(&"x".repeat(63)).is_ok());
        assert_eq!(Psk::new(&"x".repeat(64)), Err(BadPsk { len: 64 }));
    }

    #[test]
    fn l_134_a_country_is_an_assigned_code_and_nothing_else() {
        assert!(Country::new(*b"CA").is_ok());
        assert!(Country::new(*b"US").is_ok());
        assert!(Country::new(*b"ZW").is_ok());
        assert_eq!(Country::new(*b"ca"), Err(BadCountry));
        assert_eq!(Country::new(*b"C1"), Err(BadCountry));
        // Two capitals the standard has not assigned.
        assert_eq!(Country::new(*b"XX"), Err(BadCountry));
        assert_eq!(Country::new(*b"ZZ"), Err(BadCountry));
        assert_eq!(Country::new(*b"AA"), Err(BadCountry));
    }

    /// Where the fields sit after the version and the token.
    const HOSTNAME_AT: usize = 4 + NET_ORIGIN_BYTES + 1 + 2;

    #[test]
    fn l_130_the_copy_survives_the_round_trip_and_refuses_what_the_wire_would() {
        let mut network = Network::NONE;
        network.set(cabin(), ORIGIN).expect("room in the version");
        assert_eq!(Network::decode(&network.encode()), Ok(network));
        assert_eq!(Network::decode(&Network::NONE.encode()), Ok(Network::NONE));
        // A short passphrase on the part: refused as the wire refuses it.
        let psk_at = HOSTNAME_AT + 1 + HOSTNAME_BYTES + 1 + 1 + SSID_BYTES;
        let mut short = network.encode();
        short[psk_at] = 3;
        assert_eq!(Network::decode(&short), Err(Malformed { at: psk_at }));
        let mut country = network.encode();
        country[HOSTNAME_AT - 2] = b'c';
        assert_eq!(
            Network::decode(&country),
            Err(Malformed {
                at: HOSTNAME_AT - 2
            })
        );
        let mut state = network.encode();
        state[HOSTNAME_AT - 3] = 2;
        assert_eq!(
            Network::decode(&state),
            Err(Malformed {
                at: HOSTNAME_AT - 1
            })
        );
    }

    #[test]
    fn l_138_the_token_is_kept_on_the_part_and_refused_beside_version_zero() {
        let mut network = Network::NONE;
        network.set(cabin(), FOREIGN).expect("set");
        let decoded = Network::decode(&network.encode()).expect("round trip");
        assert_eq!(decoded.origin(), Some(FOREIGN));
        let mut stray = Network::NONE.encode();
        stray[4 + NET_ORIGIN_BYTES - 1] = 1;
        assert_eq!(Network::decode(&stray), Err(Malformed { at: 4 }));
        let mut zero = network.encode();
        zero[..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Network::decode(&zero),
            Err(Malformed { at: 4 }),
            "a written section's token beside version 0 is not an unwritten one"
        );
    }
}
