//! What the radio runs: the cached network, a radio that only scans, or
//! nothing.
//!
//! The comms processor raises no access point of its own. A phone reaches
//! it over BLE for setup (#96) and over the site network once the station
//! has joined; the pairing window gates `Pair` at the controller and
//! changes nothing here. With no network cached but a country known, from
//! a clear that kept one, the station interface comes up without joining,
//! so a client can still scan for a network to set. An unwritten clear
//! turns Wi-Fi off entirely (L-133), and so does a record whose country
//! does not read: no country is ever guessed.

use km43::NetChange;
use o89_link::Country;

use crate::Credential;

/// What the radio runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a radio plan nobody applies leaves the radio as it was"]
pub enum Plan {
    /// Nothing: no network record, one that does not read, or an unwritten
    /// clear.
    Off,
    /// No network cached: the station interface up for scans only, under
    /// the record's country.
    Scan {
        /// The regulatory country it listens under.
        country: Country,
    },
    /// The cached network.
    Station,
}

impl Plan {
    /// The plan for the network record held.
    pub fn of(credential: Option<&Credential>) -> Self {
        let Some(change) = credential.and_then(|credential| credential.change().ok()) else {
            return Self::Off;
        };
        match change {
            NetChange::Set { country, .. } => {
                country_of(country).map_or(Self::Off, |_| Self::Station)
            }
            NetChange::Clear { country, .. } => {
                country_of(country).map_or(Self::Off, |country| Self::Scan { country })
            }
            NetChange::ClearUnwritten => Self::Off,
        }
    }
}

fn country_of(code: &str) -> Option<Country> {
    let code: [u8; 2] = code.as_bytes().try_into().ok()?;
    Country::new(code).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(country: &'static str) -> Credential {
        Credential::new(NetChange::Set {
            version: 3,
            ssid: "cabin",
            psk: "correct horse",
            country,
            hostname: "origin89",
        })
        .expect("valid")
    }

    fn clear() -> Credential {
        Credential::new(NetChange::Clear {
            version: 4,
            country: "CA",
            hostname: "origin89",
        })
        .expect("valid")
    }

    #[test]
    fn l_133_no_record_or_an_unwritten_clear_keeps_the_radio_off() {
        let unwritten = Credential::new(NetChange::ClearUnwritten).expect("valid");
        assert_eq!(Plan::of(None), Plan::Off);
        assert_eq!(Plan::of(Some(&unwritten)), Plan::Off);
    }

    #[test]
    fn a_cached_network_runs_the_station_and_never_anything_beside_it() {
        assert_eq!(Plan::of(Some(&set("CA"))), Plan::Station);
    }

    #[test]
    fn with_no_network_cached_the_radio_only_scans_under_the_records_country() {
        assert_eq!(
            Plan::of(Some(&clear())),
            Plan::Scan {
                country: Country::new(*b"CA").expect("assigned")
            }
        );
    }
}
