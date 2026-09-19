//! The master copy of the Wi-Fi credentials, and the version the comms
//! processor's cache is compared against.
//!
//! The controller holds the master copy and the comms processor a cache in
//! its own NVS, because the two chips boot independently and a comms
//! processor that had to wait for the controller before associating turns
//! a slow boot into a site with no connectivity (L-130). The version is
//! what decides a push: the controller pushes after every link-up whose
//! reported version is *different*, not *newer*, so a board out of another
//! unit is overwritten and a fresh board is provisioned (L-133). A clear
//! carries no credential (L-131); the country is on the wire because a
//! radio in the wrong regulatory domain is an illegal transmitter (L-134);
//! and a factory reset clears, so a passphrase does not survive on a board
//! about to be pulled (L-135).
//!
//! cites: L-130, L-131, L-133, L-134

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
const LAYOUT: usize = 4 + 1 + (1 + SSID_BYTES) + (1 + PSK_MAX) + 2 + (1 + HOSTNAME_BYTES);
const _: () = assert!(LAYOUT <= NETWORK_BYTES);

/// A passphrase of 8 to 63 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Psk(Text<PSK_MAX>);

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

/// Two bytes of ISO 3166-1 alpha-2: one of the codes the standard has
/// assigned, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Country([u8; 2]);

/// Two bytes that are not an assigned country code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BadCountry;

/// The 249 officially assigned codes of ISO 3166-1 alpha-2, sorted so a
/// lookup can bisect. A code the standard assigns later needs a firmware
/// release, which is the right cost: a radio in a domain nobody has
/// defined is the illegal transmitter L-134 exists to prevent.
#[rustfmt::skip]
const ASSIGNED: &[[u8; 2]] = &[
    *b"AD", *b"AE", *b"AF", *b"AG", *b"AI", *b"AL", *b"AM", *b"AO", *b"AQ", *b"AR", *b"AS", *b"AT",
    *b"AU", *b"AW", *b"AX", *b"AZ", *b"BA", *b"BB", *b"BD", *b"BE", *b"BF", *b"BG", *b"BH", *b"BI",
    *b"BJ", *b"BL", *b"BM", *b"BN", *b"BO", *b"BQ", *b"BR", *b"BS", *b"BT", *b"BV", *b"BW", *b"BY",
    *b"BZ", *b"CA", *b"CC", *b"CD", *b"CF", *b"CG", *b"CH", *b"CI", *b"CK", *b"CL", *b"CM", *b"CN",
    *b"CO", *b"CR", *b"CU", *b"CV", *b"CW", *b"CX", *b"CY", *b"CZ", *b"DE", *b"DJ", *b"DK", *b"DM",
    *b"DO", *b"DZ", *b"EC", *b"EE", *b"EG", *b"EH", *b"ER", *b"ES", *b"ET", *b"FI", *b"FJ", *b"FK",
    *b"FM", *b"FO", *b"FR", *b"GA", *b"GB", *b"GD", *b"GE", *b"GF", *b"GG", *b"GH", *b"GI", *b"GL",
    *b"GM", *b"GN", *b"GP", *b"GQ", *b"GR", *b"GS", *b"GT", *b"GU", *b"GW", *b"GY", *b"HK", *b"HM",
    *b"HN", *b"HR", *b"HT", *b"HU", *b"ID", *b"IE", *b"IL", *b"IM", *b"IN", *b"IO", *b"IQ", *b"IR",
    *b"IS", *b"IT", *b"JE", *b"JM", *b"JO", *b"JP", *b"KE", *b"KG", *b"KH", *b"KI", *b"KM", *b"KN",
    *b"KP", *b"KR", *b"KW", *b"KY", *b"KZ", *b"LA", *b"LB", *b"LC", *b"LI", *b"LK", *b"LR", *b"LS",
    *b"LT", *b"LU", *b"LV", *b"LY", *b"MA", *b"MC", *b"MD", *b"ME", *b"MF", *b"MG", *b"MH", *b"MK",
    *b"ML", *b"MM", *b"MN", *b"MO", *b"MP", *b"MQ", *b"MR", *b"MS", *b"MT", *b"MU", *b"MV", *b"MW",
    *b"MX", *b"MY", *b"MZ", *b"NA", *b"NC", *b"NE", *b"NF", *b"NG", *b"NI", *b"NL", *b"NO", *b"NP",
    *b"NR", *b"NU", *b"NZ", *b"OM", *b"PA", *b"PE", *b"PF", *b"PG", *b"PH", *b"PK", *b"PL", *b"PM",
    *b"PN", *b"PR", *b"PS", *b"PT", *b"PW", *b"PY", *b"QA", *b"RE", *b"RO", *b"RS", *b"RU", *b"RW",
    *b"SA", *b"SB", *b"SC", *b"SD", *b"SE", *b"SG", *b"SH", *b"SI", *b"SJ", *b"SK", *b"SL", *b"SM",
    *b"SN", *b"SO", *b"SR", *b"SS", *b"ST", *b"SV", *b"SX", *b"SY", *b"SZ", *b"TC", *b"TD", *b"TF",
    *b"TG", *b"TH", *b"TJ", *b"TK", *b"TL", *b"TM", *b"TN", *b"TO", *b"TR", *b"TT", *b"TV", *b"TW",
    *b"TZ", *b"UA", *b"UG", *b"UM", *b"US", *b"UY", *b"UZ", *b"VA", *b"VC", *b"VE", *b"VG", *b"VI",
    *b"VN", *b"VU", *b"WF", *b"WS", *b"YE", *b"YT", *b"ZA", *b"ZM", *b"ZW",
];

impl Country {
    /// `code`, refused unless the standard has assigned it.
    pub fn new(code: [u8; 2]) -> Result<Self, BadCountry> {
        ASSIGNED
            .binary_search(&code)
            .map(|_| Self(code))
            .map_err(|_| BadCountry)
    }

    /// The two bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> [u8; 2] {
        self.0
    }
}

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

/// The master copy: a version that climbs on every change, and the
/// credentials, if any are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Network {
    version: u32,
    credentials: Option<Credentials>,
}

/// The version is at the top of its `u32`; refused rather than wrapped,
/// because a version back at one matches a cache that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VersionCeiling;

impl Network {
    /// A unit out of its box: version zero, no network.
    pub const NONE: Self = Self {
        version: 0,
        credentials: None,
    };

    /// The version the comms processor's cache is compared against.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The credentials, if a network is set.
    #[must_use]
    pub const fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    /// Set the network, moving the version.
    pub fn set(&mut self, credentials: Credentials) -> Result<(), VersionCeiling> {
        self.version = self.version.checked_add(1).ok_or(VersionCeiling)?;
        self.credentials = Some(credentials);
        Ok(())
    }

    /// Clear the network, moving the version, so a cache that still holds
    /// the old one is told (L-131, L-135).
    pub fn clear(&mut self) -> Result<(), VersionCeiling> {
        self.version = self.version.checked_add(1).ok_or(VersionCeiling)?;
        self.credentials = None;
        Ok(())
    }

    /// Whether a comms processor reporting `cached` after link-up gets a
    /// push: when the versions differ, not when ours is newer (L-133).
    #[must_use]
    pub const fn needs_push(&self, cached: u32) -> bool {
        cached != self.version
    }
}

impl Body<NETWORK_BYTES> for Network {
    fn encode(&self) -> [u8; NETWORK_BYTES] {
        let mut out = [0u8; NETWORK_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.u32(self.version);
        match &self.credentials {
            None => writer.u8(NONE),
            Some(credentials) => {
                writer.u8(SET);
                credentials.ssid.put(&mut writer);
                credentials.psk.0.put(&mut writer);
                writer.put(&credentials.country.0);
                credentials.hostname.put(&mut writer);
            }
        }
        out
    }

    fn decode(bytes: &[u8; NETWORK_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let version = reader.u32()?;
        let credentials = match reader.u8()? {
            NONE => None,
            SET => {
                let ssid = Text::take(&mut reader)?;
                let psk = Text::<PSK_MAX>::take(&mut reader)?;
                if psk.len() < PSK_MIN {
                    return Err(reader.malformed(PSK_MAX.saturating_add(1)));
                }
                let country =
                    Country::new(reader.take::<2>()?).map_err(|BadCountry| reader.malformed(2))?;
                let hostname = Text::take(&mut reader)?;
                Some(Credentials {
                    ssid,
                    psk: Psk(psk),
                    country,
                    hostname,
                })
            }
            _ => return Err(reader.malformed(1)),
        };
        Ok(Self {
            version,
            credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cabin() -> Credentials {
        Credentials {
            ssid: Text::new("cabin").expect("fits"),
            psk: Psk::new("correct horse").expect("long enough"),
            country: Country::new(*b"CA").expect("a country"),
            hostname: Text::new("origin89").expect("fits"),
        }
    }

    #[test]
    fn l_133_a_push_follows_a_different_version_not_a_newer_one() {
        let mut network = Network::NONE;
        assert!(!network.needs_push(0));
        network.set(cabin()).expect("room in the version");
        assert_eq!(network.version(), 1);
        assert!(network.needs_push(0), "a fresh board is provisioned");
        assert!(
            network.needs_push(7),
            "a board out of another unit is overwritten"
        );
        assert!(!network.needs_push(1));
    }

    #[test]
    fn l_131_a_clear_moves_the_version_and_carries_no_credential() {
        let mut network = Network::NONE;
        network.set(cabin()).expect("room in the version");
        network.clear().expect("room in the version");
        assert_eq!(network.version(), 2);
        assert_eq!(network.credentials(), None);
        assert!(
            network.needs_push(1),
            "a cache holding the old network is told"
        );
        let mut top = Network {
            version: u32::MAX,
            credentials: None,
        };
        assert_eq!(top.set(cabin()), Err(VersionCeiling));
        assert_eq!(top.clear(), Err(VersionCeiling));
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
        // The table bisects only if it is sorted, and it is the assigned
        // set only if it has 249 entries of two capitals each.
        assert_eq!(ASSIGNED.len(), 249);
        assert!(ASSIGNED.windows(2).all(|w| w[0] < w[1]));
        assert!(
            ASSIGNED
                .iter()
                .all(|c| c[0].is_ascii_uppercase() && c[1].is_ascii_uppercase())
        );
    }

    #[test]
    fn l_130_the_copy_survives_the_round_trip_and_refuses_what_the_wire_would() {
        let mut network = Network::NONE;
        network.set(cabin()).expect("room in the version");
        assert_eq!(Network::decode(&network.encode()), Ok(network));
        assert_eq!(Network::decode(&Network::NONE.encode()), Ok(Network::NONE));
        // A short passphrase on the part: refused as the wire refuses it.
        let mut short = network.encode();
        short[4 + 1 + 1 + SSID_BYTES] = 3;
        assert_eq!(
            Network::decode(&short),
            Err(Malformed {
                at: 4 + 1 + 1 + SSID_BYTES
            })
        );
        let mut country = network.encode();
        country[4 + 1 + 1 + SSID_BYTES + 1 + PSK_MAX] = b'c';
        assert_eq!(
            Network::decode(&country),
            Err(Malformed {
                at: 4 + 1 + 1 + SSID_BYTES + 1 + PSK_MAX
            })
        );
        let mut state = network.encode();
        state[4] = 2;
        assert_eq!(Network::decode(&state), Err(Malformed { at: 4 }));
    }
}
