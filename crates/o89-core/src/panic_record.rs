//! The panic record: what the last words carried, and which boot it was,
//! kept past a power cut.
//!
//! The last words live in RAM the runtime does not zero, which survives a
//! reset and not a power cut. A controller that panics, resets, and loses
//! the mains before anybody reads why is the one failure that cannot be
//! debugged from four hours away, so the boot that finds last words writes
//! them here with its boot count, and the record stays until the next
//! panic replaces it.
//!
//! cites: F-008

use crate::body::{Body, Malformed, Reader, Writer};
use crate::last_words::{LastWords, WORDS, Words};

/// The bytes the record takes: the boot count, then the five words.
pub const PANIC_RECORD_BYTES: usize = 4 + 4 * WORDS;

/// What the previous run said last, and at which boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanicRecord {
    /// The boot that found the words, which is the one after the run that
    /// wrote them.
    pub boot: u32,
    /// The words.
    pub words: LastWords,
}

impl Body<PANIC_RECORD_BYTES> for PanicRecord {
    fn encode(&self) -> [u8; PANIC_RECORD_BYTES] {
        let mut out = [0u8; PANIC_RECORD_BYTES];
        let mut writer = Writer::over(&mut out);
        writer.u32(self.boot);
        for word in self.words.encode() {
            writer.u32(word);
        }
        out
    }

    fn decode(bytes: &[u8; PANIC_RECORD_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let boot = reader.u32()?;
        let mut words: Words = [0; WORDS];
        for word in &mut words {
            *word = reader.u32()?;
        }
        let words = LastWords::decode(&words).ok_or(Malformed { at: 4 })?;
        Ok(Self { boot, words })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::last_words::PanicSite;
    use crate::{Blame, Millis, Task};

    #[test]
    fn f_008_a_panic_record_survives_the_round_trip_with_its_boot() {
        let record = PanicRecord {
            boot: 412,
            words: LastWords::Panicked(PanicSite {
                file: 0xDEAD_BEEF,
                line: 42,
            }),
        };
        assert_eq!(PanicRecord::decode(&record.encode()), Ok(record));
        let starved = PanicRecord {
            boot: 413,
            words: LastWords::Starved(Blame {
                task: Task::OneWire,
                overdue: Millis::from_millis(31_000),
            }),
        };
        assert_eq!(PanicRecord::decode(&starved.encode()), Ok(starved));
    }

    #[test]
    fn f_008_words_that_are_not_a_record_are_malformed_not_a_panic() {
        let mut bytes = [0u8; PANIC_RECORD_BYTES];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(PanicRecord::decode(&bytes), Err(Malformed { at: 4 }));
    }
}
