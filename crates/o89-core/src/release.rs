//! The authorised comms release: which bytes the comms processor may
//! install, in FRAM because a brown-out on a weak bank in February is the
//! ordinary case in the middle of an install.
//!
//! The controller authorises a digest, and the digest is what decides: an
//! image that arrives by any transport is installed only when its SHA-256
//! equals the authorised one (L-170, L-171). At most one release is
//! authorised at a time; a new one replaces it, both logged by the caller;
//! and an authorisation lapses when its ten-minute install window expires,
//! because the recovery ladder is suspended while an install is in flight
//! and a suspension with no end is a wedged comms processor nobody
//! power-cycles (L-174). The window is measured on the tick, so a surviving
//! authorisation restarts at the new boot's tick zero, as a dedup entry
//! does, and lives a further ten minutes and never longer.
//!
//! cites: L-170, L-174

use crate::body::{Body, Malformed, Reader, Writer};
use crate::text::Text;
use crate::tick::{Millis, Tick};

/// The bytes the release takes in its record.
pub const COMMS_RELEASE_BYTES: usize = 96;

/// Bytes of the version text on the link.
pub const VERSION_BYTES: usize = 32;

/// Bytes of the digest: SHA-256 over the whole image.
pub const DIGEST_BYTES: usize = 32;

/// How long an authorisation lives.
pub const INSTALL_WINDOW: Millis = Millis::from_millis(10 * 60 * 1_000);

const NONE: u8 = 0;
const AUTHORISED: u8 = 1;
const LAYOUT: usize = 1 + 1 + VERSION_BYTES + 4 + DIGEST_BYTES + 8;
const _: () = assert!(LAYOUT <= COMMS_RELEASE_BYTES);

/// SHA-256 over the whole image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Digest(pub [u8; DIGEST_BYTES]);

/// One authorised release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Release {
    /// What it calls itself; informative, the digest decides.
    pub version: Text<VERSION_BYTES>,
    /// The image's length in bytes.
    pub image_len: u32,
    /// The digest the arriving bytes must hash to.
    pub digest: Digest,
    /// When it was authorised, on the tick of the boot that holds it.
    pub authorised_at: Tick,
}

impl Release {
    /// Whether the window is still open at `now`.
    #[must_use]
    pub fn is_live(&self, now: Tick) -> bool {
        now.since(self.authorised_at)
            .is_some_and(|since| since < INSTALL_WINDOW)
    }
}

/// What the controller has authorised: one release or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommsRelease {
    /// Nothing may be installed.
    None,
    /// This, and only this, inside its window.
    Authorised(Release),
}

impl CommsRelease {
    /// Authorise `release`, replacing whatever was authorised; what was
    /// replaced comes back so both can be logged (L-174).
    pub fn authorise(&mut self, release: Release) -> Option<Release> {
        let replaced = self.take();
        *self = Self::Authorised(release);
        replaced
    }

    /// Revoke, handing back what was authorised.
    pub fn revoke(&mut self) -> Option<Release> {
        self.take()
    }

    /// The release whose window is open at `now`, if there is one.
    #[must_use]
    pub fn live(&self, now: Tick) -> Option<&Release> {
        match self {
            Self::None => None,
            Self::Authorised(release) => release.is_live(now).then_some(release),
        }
    }

    /// Whether `digest` is the authorised one and its window is open.
    #[must_use]
    pub fn admits(&self, digest: &Digest, now: Tick) -> bool {
        self.live(now)
            .is_some_and(|release| release.digest == *digest)
    }

    /// As read at boot: the surviving authorisation restarted at this
    /// boot's tick zero.
    #[must_use]
    pub fn rebased(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Authorised(release) => Self::Authorised(Release {
                authorised_at: Tick::ZERO,
                ..release
            }),
        }
    }

    fn take(&mut self) -> Option<Release> {
        match core::mem::replace(self, Self::None) {
            Self::None => None,
            Self::Authorised(release) => Some(release),
        }
    }
}

impl Body<COMMS_RELEASE_BYTES> for CommsRelease {
    fn encode(&self) -> [u8; COMMS_RELEASE_BYTES] {
        let mut out = [0u8; COMMS_RELEASE_BYTES];
        let mut writer = Writer::over(&mut out);
        match self {
            Self::None => writer.u8(NONE),
            Self::Authorised(release) => {
                writer.u8(AUTHORISED);
                release.version.put(&mut writer);
                writer.u32(release.image_len);
                writer.put(&release.digest.0);
                writer.u64(release.authorised_at.as_millis());
            }
        }
        out
    }

    fn decode(bytes: &[u8; COMMS_RELEASE_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        match reader.u8()? {
            NONE => Ok(Self::None),
            AUTHORISED => {
                let version = Text::take(&mut reader)?;
                let image_len = reader.u32()?;
                let digest = Digest(reader.take::<DIGEST_BYTES>()?);
                let authorised_at = Tick::from_millis(reader.u64()?);
                Ok(Self::Authorised(Release {
                    version,
                    image_len,
                    digest,
                    authorised_at,
                }))
            }
            _ => Err(reader.malformed(1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(digest: u8, at: u64) -> Release {
        Release {
            version: Text::new("1.4.0+abc123").expect("fits"),
            image_len: 95_040,
            digest: Digest([digest; DIGEST_BYTES]),
            authorised_at: Tick::from_millis(at),
        }
    }

    #[test]
    fn l_174_one_release_at_a_time_and_a_new_one_replaces_it_with_both_in_hand() {
        let mut held = CommsRelease::None;
        assert_eq!(held.authorise(release(1, 0)), None);
        assert_eq!(held.authorise(release(2, 5)), Some(release(1, 0)));
        assert_eq!(held.live(Tick::from_millis(5)), Some(&release(2, 5)));
        assert!(!held.admits(&Digest([1; 32]), Tick::from_millis(5)));
        assert!(held.admits(&Digest([2; 32]), Tick::from_millis(5)));
        assert_eq!(held.revoke(), Some(release(2, 5)));
        assert_eq!(held, CommsRelease::None);
        assert_eq!(held.revoke(), None);
    }

    #[test]
    fn l_174_an_authorisation_lapses_at_ten_minutes_and_a_reboot_gives_it_ten_more_never_longer() {
        let mut held = CommsRelease::None;
        let _ = held.authorise(release(3, 1_000));
        assert!(held.admits(&Digest([3; 32]), Tick::from_millis(600_999)));
        assert!(!held.admits(&Digest([3; 32]), Tick::from_millis(601_000)));
        assert_eq!(held.live(Tick::from_millis(601_000)), None);
        let rebooted = held.rebased();
        assert!(rebooted.admits(&Digest([3; 32]), Tick::from_millis(599_999)));
        assert!(!rebooted.admits(&Digest([3; 32]), Tick::from_millis(600_000)));
        assert_eq!(CommsRelease::None.rebased(), CommsRelease::None);
    }

    #[test]
    fn l_170_the_digest_survives_the_round_trip_and_a_stray_state_is_malformed() {
        let held = CommsRelease::Authorised(release(4, 77));
        assert_eq!(CommsRelease::decode(&held.encode()), Ok(held));
        assert_eq!(
            CommsRelease::decode(&[0; COMMS_RELEASE_BYTES]),
            Ok(CommsRelease::None)
        );
        let mut stray = held.encode();
        stray[0] = 2;
        assert_eq!(CommsRelease::decode(&stray), Err(Malformed { at: 0 }));
        let mut long = held.encode();
        long[1] = 33;
        assert_eq!(CommsRelease::decode(&long), Err(Malformed { at: 1 }));
    }
}
