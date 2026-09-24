//! What the radio runs: the cached network, the provisioning access point,
//! both, or nothing.
//!
//! The access point is the browser's way in when the cached network cannot
//! be reached from the phone at the panel. It runs while no network is
//! cached, or while the controller reports its pairing window open, and
//! only with a regulatory country from the controller's network record: a
//! pairing report carries none, and no country is ever guessed. An
//! unwritten clear turns Wi-Fi off entirely, access point included (L-133).
//! So a unit never given a network has no access point; its first pairing
//! is over BLE (#96).
//!
//! The pairing window is the link's, measured on this side's clock from the
//! report's receipt and ended by a newer closed report, the link falling or
//! the controller rebooting (L-196). When its end would take the access
//! point down, clients on it get [`DRAIN`] to take the answers already on
//! their way, and no new client is taken meanwhile.
//!
//! The access point's clients take rows from the one connection table, like
//! every other transport's.

use km43::NetChange;
use o89_link::{Country, Millis};

use crate::Credential;

/// How long the access point's clients have to take what is already queued
/// for them once the pairing window that raised it has closed (L-196).
pub const DRAIN: Millis = Millis::from_millis(500);

/// What the radio runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a radio plan nobody applies leaves the radio as it was"]
pub enum Plan {
    /// Nothing: no network record, one that does not read, or an unwritten
    /// clear.
    Off,
    /// The cached network.
    Station,
    /// The access point alone: no network cached, a country known.
    AccessPoint {
        /// The regulatory country it transmits under.
        country: Country,
    },
    /// The cached network, and the access point while the pairing window
    /// is open.
    Both {
        /// The regulatory country both transmit under.
        country: Country,
    },
}

impl Plan {
    /// The plan for the network record held and whether the controller's
    /// pairing window is open.
    pub fn of(credential: Option<&Credential>, pairing_open: bool) -> Self {
        let Some(change) = credential.and_then(|credential| credential.change().ok()) else {
            return Self::Off;
        };
        match change {
            NetChange::Set { country, .. } => match (country_of(country), pairing_open) {
                (Some(country), true) => Self::Both { country },
                (Some(_), false) => Self::Station,
                (None, _) => Self::Off,
            },
            NetChange::Clear { country, .. } => {
                country_of(country).map_or(Self::Off, |country| Self::AccessPoint { country })
            }
            NetChange::ClearUnwritten => Self::Off,
        }
    }

    /// Whether the access point runs.
    #[must_use]
    pub const fn has_access_point(self) -> bool {
        match self {
            Self::AccessPoint { .. } | Self::Both { .. } => true,
            Self::Off | Self::Station => false,
        }
    }

    /// Whether moving to `next` takes the access point down because the
    /// pairing window closed, with the network unchanged: the one change
    /// that drains first (L-196).
    #[must_use]
    pub const fn window_closes(self, next: Self) -> bool {
        matches!((self, next), (Self::Both { .. }, Self::Station))
    }
}

fn country_of(code: &str) -> Option<Country> {
    let code: [u8; 2] = code.as_bytes().try_into().ok()?;
    Country::new(code).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> Credential {
        Credential::new(NetChange::Set {
            version: 3,
            ssid: "cabin",
            psk: "correct horse",
            country: "CA",
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

    fn canada() -> Country {
        Country::new(*b"CA").expect("assigned")
    }

    #[test]
    fn l_133_no_record_or_an_unwritten_clear_keeps_every_radio_off_even_with_the_window_open() {
        let unwritten = Credential::new(NetChange::ClearUnwritten).expect("valid");
        for pairing_open in [false, true] {
            assert_eq!(Plan::of(None, pairing_open), Plan::Off);
            assert_eq!(Plan::of(Some(&unwritten), pairing_open), Plan::Off);
        }
    }

    #[test]
    fn with_no_network_cached_the_access_point_runs_under_the_records_country() {
        for pairing_open in [false, true] {
            assert_eq!(
                Plan::of(Some(&clear()), pairing_open),
                Plan::AccessPoint { country: canada() }
            );
        }
    }

    #[test]
    fn l_196_a_cached_network_raises_the_access_point_only_while_the_window_is_open() {
        assert_eq!(Plan::of(Some(&set()), false), Plan::Station);
        assert_eq!(
            Plan::of(Some(&set()), true),
            Plan::Both { country: canada() }
        );
        assert!(!Plan::Station.has_access_point());
        assert!(Plan::Both { country: canada() }.has_access_point());
        assert!(Plan::AccessPoint { country: canada() }.has_access_point());
        assert!(!Plan::Off.has_access_point());
    }

    #[test]
    fn l_196_only_the_window_closing_drains_the_access_point() {
        let both = Plan::Both { country: canada() };
        let alone = Plan::AccessPoint { country: canada() };
        assert!(both.window_closes(Plan::Station));
        // A changed record, an unwritten clear, or no change at all is not
        // the window closing.
        assert!(!both.window_closes(Plan::Off));
        assert!(!both.window_closes(alone));
        assert!(!both.window_closes(both));
        assert!(!alone.window_closes(Plan::Off));
        assert!(!Plan::Station.window_closes(both));
        assert_eq!(DRAIN.as_millis(), 500);
    }
}
