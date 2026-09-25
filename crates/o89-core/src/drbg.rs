//! The generator every challenge and every controller ephemeral key is a
//! draw from, because the part has no RNG (P-237).
//!
//! The state is thirty-two bytes the station wrote at manufacture and
//! recorded nowhere. `km43`'s [`Drbg`] advances it one way on every draw,
//! writes the successor through a [`DrbgStore`], reads it back and compares
//! before it releases the draw; this file is that store. It writes the
//! record and reads it back **off the part**, never from the RAM copy, which
//! is the half of P-237 the type cannot check.
//!
//! **Never re-initialised.** Nothing here makes a state: a factory reset
//! does not touch the record, a boot that finds it damaged keeps it
//! damaged, and only the manufacturing transaction writes a first one, onto
//! a part that holds none. A generator that cannot be read back is
//! [`Unavailable`]: every `Pair` and `Hello` is refused, `Discover` answers
//! error 18, and the caller raises condition 22 `entropy unavailable`.
//!
//! A failed draw gives the generator up, as `km43` requires, and the next
//! draw starts again from whatever the record holds. That is not a
//! re-initialisation: if the successor landed it is the successor, and if
//! it did not, the draw that would repeat was never released.
//!
//! cites: P-063, P-237

use core::fmt;

use km43::{Drbg, DrbgStore, Entropy, KEY_BYTES};

use crate::body::{Body, Held, Kept, Malformed};
use crate::fram::{Fram, Record};

/// The bytes the generator's state takes in its record.
pub const DRBG_BYTES: usize = KEY_BYTES;

/// Bytes of a challenge (P-063).
pub const CHALLENGE_BYTES: usize = km43::CHALLENGE_BYTES;

/// The generator's state as the part holds it. No `Debug` of the bytes and
/// no `Format`: a state in a log is every draw after it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DrbgState([u8; DRBG_BYTES]);

impl DrbgState {
    /// A state the manufacturing station drew, refused when every byte is
    /// zero: a station whose generator failed, and not a secret.
    pub fn new(bytes: [u8; DRBG_BYTES]) -> Result<Self, crate::NoEntropy> {
        if bytes.iter().any(|byte| *byte != 0) {
            Ok(Self(bytes))
        } else {
            Err(crate::NoEntropy)
        }
    }
}

impl fmt::Debug for DrbgState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DrbgState(..)")
    }
}

impl Body<DRBG_BYTES> for DrbgState {
    fn encode(&self) -> [u8; DRBG_BYTES] {
        self.0
    }

    fn decode(bytes: &[u8; DRBG_BYTES]) -> Result<Self, Malformed> {
        Self::new(*bytes).map_err(|crate::NoEntropy| Malformed { at: 0 })
    }
}

/// No draw: the state is not on the part, or its successor would not read
/// back. P-237's refusal of every `Pair` and `Hello`, and condition 22.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a draw that did not happen is a handshake to refuse"]
pub struct Unavailable;

/// The generator between draws, and the record it lives in.
pub struct Generator {
    kept: Kept<DrbgState, DRBG_BYTES>,
    drbg: Option<Drbg>,
}

impl fmt::Debug for Generator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generator")
            .field("available", &self.drbg.is_some())
            .finish_non_exhaustive()
    }
}

impl Generator {
    /// The generator over what the boot read. A record that holds no state
    /// is a generator that draws nothing until the manufacturing
    /// transaction writes one.
    #[must_use]
    pub fn new(kept: Kept<DrbgState, DRBG_BYTES>) -> Self {
        let drbg = kept.present().map(|state| Drbg::from_stored(state.0));
        Self { kept, drbg }
    }

    /// What the record held at the last read, for the boot report and the
    /// bench.
    #[must_use]
    pub const fn held(&self) -> &Held<DrbgState> {
        self.kept.held()
    }

    /// Whether the last draw, or the boot, left a generator to draw from.
    /// One that did not may still recover on the next draw, when the
    /// record reads back.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.drbg.is_some()
    }

    /// One draw, released only once its successor is on the part and read
    /// back from it.
    pub async fn draw<F: Fram>(&mut self, fram: &mut F) -> Result<Entropy, Unavailable> {
        let drbg = match self.drbg.take() {
            Some(drbg) => drbg,
            None => self.recovered(fram).await?,
        };
        let mut store = Store {
            kept: &mut self.kept,
            fram,
        };
        let (next, entropy) = drbg.draw(&mut store).await.map_err(|_| Unavailable)?;
        self.drbg = Some(next);
        Ok(entropy)
    }

    /// A challenge: one draw, its first sixteen bytes (P-063).
    pub async fn challenge<F: Fram>(
        &mut self,
        fram: &mut F,
    ) -> Result<[u8; CHALLENGE_BYTES], Unavailable> {
        Ok(self.draw(fram).await?.into_challenge())
    }

    /// Start again from the part after a draw was withheld.
    async fn recovered<F: Fram>(&mut self, fram: &mut F) -> Result<Drbg, Unavailable> {
        self.kept = Kept::read(self.kept.record(), fram)
            .await
            .map_err(|_| Unavailable)?;
        self.kept
            .present()
            .map(|state| Drbg::from_stored(state.0))
            .ok_or(Unavailable)
    }
}

/// The record as `km43` writes and reads it through a draw.
struct Store<'a, F> {
    kept: &'a mut Kept<DrbgState, DRBG_BYTES>,
    fram: &'a mut F,
}

/// Why the store failed; only that it did matters to the draw.
struct NotStored;

impl<F: Fram> DrbgStore for Store<'_, F> {
    type Error = NotStored;

    async fn write(&mut self, state: &[u8; KEY_BYTES]) -> Result<(), NotStored> {
        let state = DrbgState::new(*state).map_err(|crate::NoEntropy| NotStored)?;
        self.kept
            .write(self.fram, state)
            .await
            .map_err(|_| NotStored)
    }

    /// Off the part: a read of the RAM copy would satisfy the comparison
    /// and not P-237.
    async fn read(&mut self) -> Result<[u8; KEY_BYTES], NotStored> {
        let record: Record<DRBG_BYTES> = self.kept.record();
        *self.kept = Kept::read(record, self.fram).await.map_err(|_| NotStored)?;
        self.kept.present().map(|state| state.0).ok_or(NotStored)
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::fram::{Address, Refused};
    use crate::map::DRBG;

    /// A part in an array: writes that can be lost or refused, reads that
    /// can fail, and a count of transactions.
    struct Part {
        bytes: [u8; 256],
        lose_writes: bool,
        refuse_writes: bool,
        fail_reads: bool,
    }

    impl Part {
        fn seeded(seed: u8) -> Self {
            let mut part = Self {
                bytes: [0xFF; 256],
                lose_writes: false,
                refuse_writes: false,
                fail_reads: false,
            };
            let mut kept =
                block_on(Kept::<DrbgState, DRBG_BYTES>::read(DRBG, &mut part)).expect("reads");
            block_on(kept.write(&mut part, DrbgState::new([seed; 32]).expect("entropy")))
                .expect("seeded");
            part
        }

        fn generator(&mut self) -> Generator {
            Generator::new(block_on(Kept::read(DRBG, self)).expect("reads"))
        }
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            let result = if self.fail_reads {
                Err(())
            } else {
                into.copy_from_slice(&self.bytes[start..][..into.len()]);
                Ok(())
            };
            core::future::ready(result)
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            let result = if self.refuse_writes {
                Err(Refused::Bus(()))
            } else {
                if !self.lose_writes {
                    let start = usize::from(at.0);
                    self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                }
                Ok(())
            };
            core::future::ready(result)
        }
    }

    #[test]
    fn f_041_p_237_draws_never_repeat_across_a_reboot() {
        let mut part = Part::seeded(7);
        let mut seen = [[0u8; CHALLENGE_BYTES]; 24];
        let mut count = 0;
        for _ in 0..3 {
            let mut generator = part.generator();
            for _ in 0..8 {
                let challenge = block_on(generator.challenge(&mut part)).expect("draws");
                assert!(!seen[..count].contains(&challenge), "a challenge repeated");
                seen[count] = challenge;
                count += 1;
            }
        }
    }

    #[test]
    fn f_041_p_237_a_draw_whose_successor_did_not_land_is_withheld_and_never_repeated() {
        let mut part = Part::seeded(9);
        let mut generator = part.generator();
        let first = block_on(generator.challenge(&mut part)).expect("draws");
        part.lose_writes = true;
        assert_eq!(block_on(generator.challenge(&mut part)), Err(Unavailable));
        assert!(!generator.is_available());
        // The part still holds the successor of the first draw, so the draw
        // that was withheld is the one the recovered generator releases:
        // released once, never twice.
        part.lose_writes = false;
        let recovered = block_on(generator.challenge(&mut part)).expect("recovers");
        assert_ne!(recovered, first);
        let next = block_on(generator.challenge(&mut part)).expect("draws");
        assert_ne!(next, recovered);
        assert_eq!(part.generator().held(), generator.held());
    }

    #[test]
    fn p_237_a_generator_whose_record_does_not_read_draws_nothing() {
        let mut part = Part::seeded(3);
        let mut generator = part.generator();
        part.fail_reads = true;
        assert_eq!(block_on(generator.draw(&mut part)).err(), Some(Unavailable));
        part.refuse_writes = true;
        part.fail_reads = false;
        assert_eq!(block_on(generator.draw(&mut part)).err(), Some(Unavailable));
    }

    #[test]
    fn p_237_an_unprovisioned_part_has_no_generator_and_makes_none() {
        let mut part = Part {
            bytes: [0xFF; 256],
            lose_writes: false,
            refuse_writes: false,
            fail_reads: false,
        };
        let mut generator = part.generator();
        assert_eq!(generator.held(), &Held::Absent);
        assert!(!generator.is_available());
        assert_eq!(block_on(generator.draw(&mut part)).err(), Some(Unavailable));
        // Nothing was written: an absent state stays absent.
        assert!(part.bytes.iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn p_237_a_state_of_zeros_is_not_a_state() {
        assert!(DrbgState::new([0; 32]).is_err());
        assert_eq!(DrbgState::decode(&[0; 32]).err(), Some(Malformed { at: 0 }));
        let mut one_bit = [0u8; 32];
        one_bit[31] = 1;
        assert!(DrbgState::new(one_bit).is_ok());
    }
}
