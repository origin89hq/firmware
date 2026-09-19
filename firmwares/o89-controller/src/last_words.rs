//! Where the last words live: RAM the runtime does not zero.
//!
//! The words are atomics because any bit pattern is a valid value, which is
//! the whole requirement for memory nobody initialised; what they mean is
//! `o89_core`'s to say, and it says nothing of a pattern that is not a
//! record (F-008). The magic word is stored last, so a reset between two
//! stores leaves no record rather than half of one.

use core::sync::atomic::Ordering;

use o89_core::{CLEARED, LastWords, WORDS, Words};
use portable_atomic::AtomicU32;

#[expect(
    unsafe_code,
    reason = "`link_section` is an unsafe attribute on this edition; `.uninit` is the section the runtime never zeroes, which is what lets the words outlive a reset"
)]
#[unsafe(link_section = ".uninit.LAST_WORDS")]
static LAST_WORDS: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];

/// Write a record for the next boot to find. The magic goes last.
pub fn write(words: LastWords) {
    let encoded: Words = words.encode();
    for (slot, word) in LAST_WORDS.iter().zip(encoded).rev() {
        slot.store(word, Ordering::Relaxed);
    }
}

/// Clear the words: a provisional record whose moment has passed.
pub fn clear() {
    for slot in &LAST_WORDS {
        slot.store(0, Ordering::Relaxed);
    }
}

/// Read and clear whatever the previous run left.
pub fn take() -> Option<LastWords> {
    let mut words = CLEARED;
    for (word, slot) in words.iter_mut().zip(&LAST_WORDS) {
        *word = slot.load(Ordering::Relaxed);
    }
    for slot in &LAST_WORDS {
        slot.store(0, Ordering::Relaxed);
    }
    LastWords::decode(&words)
}
