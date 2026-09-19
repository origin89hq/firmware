//! The challenge counter: the whole of the challenge's security, and the
//! reason it is written before the challenge leaves.
//!
//! The part has no RNG. A challenge is a PRF of the device secret in
//! counter mode, unpredictable to anybody who does not hold the printed
//! secret, and distinct for every counter value; so a counter that repeats
//! re-mints a challenge that a recorded `Hello` or `Pair` proof verifies
//! against a second time. The counter therefore outlives a reset, and it
//! is written to FRAM before the challenge it names goes out, never after
//! (F-041).
//!
//! That order is a type here. A challenge is derived from a [`Minted`],
//! and a `Minted` comes out of [`Kept::mint`] only after the part has the
//! counter. A write that fails mints nothing.
//!
//! cites: F-041

use km43::DeviceSecret;

use crate::body::{Body, Held, Kept, Malformed};
use crate::fram::{Fram, Refused};

/// The bytes the counter takes in its record: one `u64`, the width the
/// derivation takes.
pub const CHALLENGE_COUNTER_BYTES: usize = 8;

/// Bytes of a challenge, as the derivation hands it out.
pub const CHALLENGE_BYTES: usize = 16;

/// The last counter minted. A fresh part has minted none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChallengeCounter(u64);

impl ChallengeCounter {
    /// The last counter a challenge was derived from.
    #[must_use]
    pub const fn last(&self) -> u64 {
        self.0
    }
}

impl Body<CHALLENGE_COUNTER_BYTES> for ChallengeCounter {
    fn encode(&self) -> [u8; CHALLENGE_COUNTER_BYTES] {
        self.0.to_le_bytes()
    }

    fn decode(bytes: &[u8; CHALLENGE_COUNTER_BYTES]) -> Result<Self, Malformed> {
        Ok(Self(u64::from_le_bytes(*bytes)))
    }
}

/// A counter the part holds, which is the only thing a challenge can be
/// derived from. There is no public constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a counter minted and not used is a write for nothing"]
pub struct Minted {
    counter: u64,
}

impl Minted {
    /// The counter the challenge is derived from.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The challenge for this counter under `secret`: the PRF the
    /// architecture names, computed by the protocol crate.
    #[must_use]
    pub fn challenge(&self, secret: &DeviceSecret) -> [u8; CHALLENGE_BYTES] {
        secret.challenge(self.counter)
    }
}

/// Why nothing was minted. Every variant is a `Discover` answered without
/// a challenge, and the caller raises a concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a mint that failed leaves a Discover to answer"]
pub enum MintFailed<E> {
    /// The record holds no counter this image can read: corrupt or
    /// malformed. Minting from any guess could repeat a challenge, so
    /// nothing is minted until a person writes a counter past every one
    /// that could have been used.
    Unknown,
    /// The counter is at the top of its `u64`, which no unit reaches.
    AtTheCeiling,
    /// The write did not happen.
    Write(Refused<E>),
}

impl Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES> {
    /// The next counter, written before it is handed out. A fresh part
    /// mints one; a written part mints the next.
    pub async fn mint<F: Fram>(&mut self, fram: &mut F) -> Result<Minted, MintFailed<F::Error>> {
        let last = match self.held() {
            Held::Present(counter) => counter.0,
            Held::Absent => 0,
            Held::Corrupt | Held::Malformed(_) => return Err(MintFailed::Unknown),
        };
        let counter = last.checked_add(1).ok_or(MintFailed::AtTheCeiling)?;
        self.write(fram, ChallengeCounter(counter))
            .await
            .map_err(MintFailed::Write)?;
        Ok(Minted { counter })
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{DeviceId, PrintedSecret};

    use super::*;
    use crate::fram::{Address, Position};
    use crate::map::CHALLENGE_COUNTER;

    struct Part {
        bytes: [u8; 128],
        falling: bool,
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            into.copy_from_slice(&self.bytes[start..][..into.len()]);
            core::future::ready(Ok(()))
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            let outcome = if self.falling {
                Err(Refused::SupplyFalling)
            } else {
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    fn part() -> Part {
        Part {
            bytes: [0; 128],
            falling: false,
        }
    }

    fn secret() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new([7; 16]), PrintedSecret::new([9; 32]))
    }

    type Counter = Kept<ChallengeCounter, CHALLENGE_COUNTER_BYTES>;

    #[test]
    fn f_041_a_fresh_part_mints_one_and_every_mint_after_it_is_the_next() {
        let mut part = part();
        let mut kept = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        let first = block_on(kept.mint(&mut part)).expect("the supply is fine");
        assert_eq!(first.counter(), 1);
        let second = block_on(kept.mint(&mut part)).expect("the supply is fine");
        assert_eq!(second.counter(), 2);
        // What the part holds is the last one handed out: a reboot mints
        // three, never two again.
        let mut rebooted = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        assert_eq!(rebooted.present(), Some(&ChallengeCounter(2)));
        let third = block_on(rebooted.mint(&mut part)).expect("the supply is fine");
        assert_eq!(third.counter(), 3);
        assert_ne!(third.challenge(&secret()), second.challenge(&secret()));
        assert_eq!(second.challenge(&secret()), secret().challenge(2));
    }

    #[test]
    fn f_041_a_write_that_fails_mints_nothing_and_moves_nothing() {
        let mut part = part();
        let mut kept = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        let _one = block_on(kept.mint(&mut part)).expect("the supply is fine");
        part.falling = true;
        assert_eq!(
            block_on(kept.mint(&mut part)),
            Err(MintFailed::Write(Refused::SupplyFalling))
        );
        assert_eq!(kept.present(), Some(&ChallengeCounter(1)));
        part.falling = false;
        // The next one that lands is two: the refused mint left no gap
        // and no repeat.
        let next = block_on(kept.mint(&mut part)).expect("the supply is fine");
        assert_eq!(next.counter(), 2);
    }

    #[test]
    fn f_041_a_counter_nobody_can_read_mints_nothing_rather_than_guessing() {
        let mut part = part();
        let mut kept = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        let _one = block_on(kept.mint(&mut part)).expect("the supply is fine");
        let _two = block_on(kept.mint(&mut part)).expect("the supply is fine");
        // Both slots damaged: slot A at 32, slot B at 52, bodies 8 in.
        part.bytes[32 + 8] ^= 0x01;
        part.bytes[52 + 8] ^= 0x01;
        let mut damaged = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        assert_eq!(damaged.held(), &Held::Corrupt);
        assert_eq!(block_on(damaged.mint(&mut part)), Err(MintFailed::Unknown));
    }

    #[test]
    fn f_041_a_counter_at_its_ceiling_mints_nothing() {
        let mut part = part();
        let at_top = ChallengeCounter(u64::MAX);
        let _ = block_on(CHALLENGE_COUNTER.write(&mut part, Position::Start, &at_top.encode()));
        let mut kept = block_on(Counter::read(CHALLENGE_COUNTER, &mut part)).expect("reads");
        assert_eq!(
            block_on(kept.mint(&mut part)),
            Err(MintFailed::AtTheCeiling)
        );
        assert_eq!(ChallengeCounter::decode(&at_top.encode()), Ok(at_top));
    }
}
