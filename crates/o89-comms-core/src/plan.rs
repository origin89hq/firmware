//! What the radio runs: the cached network, a radio that only scans, or
//! nothing.
//!
//! The comms processor raises no access point of its own. A phone reaches
//! it over BLE for setup (#96) and over the site network once the station
//! has joined. On the pinned radio a station brought up for scans alone
//! leaves BLE advertising nothing, and one started beside a BLE connection
//! drops it, so Wi-Fi stays off while the controller's pairing window is
//! open, and with no network cached it stays off until a client asks for a
//! scan (#166). With a country known, from a clear
//! that kept one, the station interface then comes up without joining, so
//! the client that asked can pick a network to set. An unwritten clear
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
    /// No network cached and a client asking for a scan: the station
    /// interface up for scans only, under the record's country.
    Scan {
        /// The regulatory country it listens under.
        country: Country,
    },
    /// The cached network.
    Station,
}

impl Plan {
    /// The plan for the network record held, whether the controller's
    /// pairing window is open, and whether a client wants the radio to
    /// scan. While the window is open, Wi-Fi stays off: the window is when a
    /// phone pairs over BLE, and on the pinned radio a station that is not
    /// joined can stop BLE advertising (bench 2026-09-25). With no network
    /// cached, it stays off until a scan is wanted, for the same reason: BLE
    /// is then the only way in (#166).
    pub fn of(credential: Option<&Credential>, pairing_open: bool, scan_wanted: bool) -> Self {
        if pairing_open {
            return Self::Off;
        }
        let Some(change) = credential.and_then(|credential| credential.change().ok()) else {
            return Self::Off;
        };
        match change {
            NetChange::Set { country, .. } => {
                country_of(country).map_or(Self::Off, |_| Self::Station)
            }
            NetChange::Clear { country, .. } => match country_of(country) {
                Some(country) if scan_wanted => Self::Scan { country },
                Some(_) | None => Self::Off,
            },
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
        for scan_wanted in [false, true] {
            assert_eq!(Plan::of(None, false, scan_wanted), Plan::Off);
            assert_eq!(Plan::of(Some(&unwritten), false, scan_wanted), Plan::Off);
        }
    }

    #[test]
    fn a_cached_network_runs_the_station_and_never_anything_beside_it() {
        for scan_wanted in [false, true] {
            assert_eq!(
                Plan::of(Some(&set("CA")), false, scan_wanted),
                Plan::Station
            );
        }
    }

    #[test]
    fn f_043_while_the_pairing_window_is_open_wifi_stays_off() {
        let unwritten = Credential::new(NetChange::ClearUnwritten).expect("valid");
        for record in [None, Some(set("CA")), Some(clear()), Some(unwritten)] {
            for scan_wanted in [false, true] {
                assert_eq!(
                    Plan::of(record.as_ref(), true, scan_wanted),
                    Plan::Off,
                    "{record:?}"
                );
            }
        }
        // The station and the scans come back once it closes.
        assert_eq!(Plan::of(Some(&set("CA")), false, false), Plan::Station);
    }

    #[test]
    fn f_044_with_no_network_cached_wifi_stays_off_until_a_scan_is_wanted() {
        // Off, so a phone can open a BLE connection (#166).
        assert_eq!(Plan::of(Some(&clear()), false, false), Plan::Off);
        assert_eq!(
            Plan::of(Some(&clear()), false, true),
            Plan::Scan {
                country: Country::new(*b"CA").expect("assigned")
            }
        );
    }
}
