//! What a run writes down before it lets the watchdog fire, or panics, so
//! the next boot can say why.
//!
//! A boot that says *watchdog reset, `OneWire` silent for 31 s* is worth an
//! hour on the bench; one that says only *watchdog reset* is not. The words
//! live in RAM the runtime does not zero, and the pattern is the one the
//! self-test proved on the bench on 2026-09-14: a magic word, its complement,
//! and the payload after them, so that uninitialised RAM, which holds any
//! bit pattern at all, reads as nothing rather than as somebody's blame.
//! Nothing here touches memory; this encodes and decodes the words, and the
//! adapter owns where they sit.
//!
//! cites: F-008

use crate::{Millis, Task};

/// The number of words the record takes.
pub const WORDS: usize = 5;

/// The words as the adapter stores them.
pub type Words = [u32; WORDS];

/// The words after a record has been taken, or before any was written.
pub const CLEARED: Words = [0; WORDS];

const MAGIC: u32 = 0x4C41_5354; // "LAST"
const STARVED: u32 = 1;
const PANICKED: u32 = 2;

/// The task that stopped checking in, and by how much, as the supervisor
/// wrote it before withholding the feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Blame {
    /// Who was silent.
    pub task: Task,
    /// How long past its window it had been when the feed was withheld.
    pub overdue: Millis,
}

/// Where a panic happened, as much of it as five words carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanicSite {
    /// A hash of the source file's path, which the host resolves against
    /// the image that was running.
    pub file: u32,
    /// The line.
    pub line: u32,
}

/// What the previous run said last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LastWords {
    /// The supervisor withheld the feed and the watchdog fired.
    Starved(Blame),
    /// The image panicked and reset itself.
    Panicked(PanicSite),
}

impl LastWords {
    /// The words to store.
    ///
    /// An overdue longer than a `u32` of milliseconds saturates: 49 days
    /// past a window is not a number that needs its top bits.
    #[must_use]
    pub fn encode(self) -> Words {
        let (kind, a, b) = match self {
            Self::Starved(blame) => {
                let overdue = u32::try_from(blame.overdue.as_millis()).unwrap_or(u32::MAX);
                (STARVED, blame.task.index(), overdue)
            }
            Self::Panicked(site) => (PANICKED, site.file, site.line),
        };
        [MAGIC, !MAGIC, kind, a, b]
    }

    /// Read the words back, or nothing when they are not a record.
    #[must_use]
    pub fn decode(words: &Words) -> Option<Self> {
        let [magic, complement, kind, a, b] = *words;
        if magic != MAGIC || complement != !MAGIC {
            return None;
        }
        match kind {
            STARVED => Task::from_index(a).map(|task| {
                Self::Starved(Blame {
                    task,
                    overdue: Millis::from_millis(u64::from(b)),
                })
            }),
            PANICKED => Some(Self::Panicked(PanicSite { file: a, line: b })),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_008_a_blame_survives_the_reset_and_names_the_task() {
        let blame = Blame {
            task: Task::OneWire,
            overdue: Millis::from_millis(31_000),
        };
        let words = LastWords::Starved(blame).encode();
        assert_eq!(LastWords::decode(&words), Some(LastWords::Starved(blame)));
        let site = PanicSite {
            file: 0xDEAD_BEEF,
            line: 42,
        };
        let words = LastWords::Panicked(site).encode();
        assert_eq!(LastWords::decode(&words), Some(LastWords::Panicked(site)));
    }

    #[test]
    fn f_008_uninitialised_ram_reads_as_no_record() {
        assert_eq!(LastWords::decode(&CLEARED), None);
        // The magic alone is not enough: its complement has to be there too,
        // which is what tells a record from RAM that happens to hold "LAST".
        assert_eq!(LastWords::decode(&[MAGIC, MAGIC, STARVED, 0, 0]), None);
        assert_eq!(LastWords::decode(&[MAGIC, !MAGIC, 7, 0, 0]), None);
        assert_eq!(
            LastWords::decode(&[MAGIC, !MAGIC, STARVED, u32::MAX, 0]),
            None
        );
        assert_eq!(LastWords::decode(&[0x5555_5555; WORDS]), None);
    }

    #[test]
    fn f_008_an_overdue_past_a_u32_saturates_rather_than_wraps() {
        let blame = Blame {
            task: Task::Adc,
            overdue: Millis::from_millis(u64::MAX),
        };
        let words = LastWords::Starved(blame).encode();
        assert_eq!(
            LastWords::decode(&words),
            Some(LastWords::Starved(Blame {
                task: Task::Adc,
                overdue: Millis::from_millis(u64::from(u32::MAX)),
            }))
        );
    }
}
