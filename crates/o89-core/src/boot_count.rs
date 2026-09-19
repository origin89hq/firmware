//! How many times this unit has booted, so a record can say at which.

use crate::body::{Body, Malformed};

/// The bytes the count takes in its record: one `u32`.
pub const BOOT_COUNT_BYTES: usize = 4;

/// The number of the current boot, counting the first from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BootCount(u32);

impl BootCount {
    /// The first boot of a unit.
    pub const FIRST: Self = Self(1);

    /// The number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The boot after this one. Saturating: four billion boots is not a
    /// number a unit reaches, and a count that stayed at the top would
    /// still order every record before it.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl Body<BOOT_COUNT_BYTES> for BootCount {
    fn encode(&self) -> [u8; BOOT_COUNT_BYTES] {
        self.0.to_le_bytes()
    }

    /// Zero is not a boot: the first is one.
    fn decode(bytes: &[u8; BOOT_COUNT_BYTES]) -> Result<Self, Malformed> {
        match u32::from_le_bytes(*bytes) {
            0 => Err(Malformed { at: 0 }),
            count => Ok(Self(count)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boot_count_starts_at_one_and_climbs() {
        assert_eq!(BootCount::FIRST.get(), 1);
        assert_eq!(BootCount::FIRST.next(), BootCount(2));
        assert_eq!(BootCount::decode(&BootCount(2).encode()), Ok(BootCount(2)));
    }

    #[test]
    fn a_zero_is_not_a_boot() {
        assert_eq!(BootCount::decode(&[0; 4]), Err(Malformed { at: 0 }));
    }

    #[test]
    fn a_count_at_the_top_stays_there_rather_than_wrapping() {
        assert_eq!(BootCount(u32::MAX).next(), BootCount(u32::MAX));
    }
}
