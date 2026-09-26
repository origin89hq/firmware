//! What the vendor dialects share: a poll's outcome and its errors, the
//! vendor words a dialect reads that no metric kind carries, and the one
//! step that writes a reply's cells into the store.
//!
//! A register a dialect cannot publish as a signal, because KM43 has no kind
//! for it or the vendor's value cannot fill the kind it has, is still read
//! and handed back typed: a charge stage, an alarm, a magnitude. It never
//! enters the store and nothing in it is a signal.
//!
//! cites: F-052

use km43::Id;
use o89_core::{Signals, Tick};

use crate::dialect::Block;
use crate::modbus::{ModbusError, Registers};
use crate::{PollError, Polled};

/// What a vendor poll wrote, and the vendor's words beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a poll's outcome is the device's presence and its conditions"]
pub struct Report<T> {
    /// The signals written.
    pub polled: Polled,
    /// What the vendor said beside them.
    pub conditions: T,
}

/// Why a vendor word was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused vendor word is a condition that was not read"]
pub enum ConditionError {
    /// The register is not in the reply: the registers are not the read
    /// this word comes from.
    Missing(u16),
    /// The register holds a value its vendor does not define.
    Undefined {
        /// The register.
        register: u16,
        /// What it held.
        raw: u16,
    },
}

/// Why a vendor poll stopped.
///
/// Whatever the poll wrote before it stopped stands, as for a
/// [`PollError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed poll is a device whose readings were not refreshed"]
pub enum VendorError<E> {
    /// Reading or writing the register map's cells failed.
    Poll(PollError<E>),
    /// The cells were written; the separate read of the vendor's condition
    /// words failed, so the conditions are unknown.
    Conditions(ModbusError<E>),
    /// A reply held a vendor word its vendor does not define. Nothing from
    /// that reply was written: its CRC held, so the word is what the device
    /// sent, and a device sending words its manual does not define is not
    /// one whose other registers can be trusted as that manual's.
    Condition(ConditionError),
}

/// A two-state vendor flag whose words are `0x0000` for clear and `0xFFFF`
/// for raised, as both PZEM manuals define their alarm registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Alarm {
    /// `0x0000`.
    Clear,
    /// `0xFFFF`.
    Raised,
}

impl Alarm {
    /// The alarm at `register`, refusing any word but the two defined.
    pub(crate) fn at(registers: &Registers<'_>, register: u16) -> Result<Self, ConditionError> {
        match word(registers, register)? {
            0x0000 => Ok(Self::Clear),
            0xFFFF => Ok(Self::Raised),
            raw => Err(ConditionError::Undefined { register, raw }),
        }
    }
}

/// The word at `register`.
pub(crate) fn word(registers: &Registers<'_>, register: u16) -> Result<u16, ConditionError> {
    registers
        .at(register)
        .ok_or(ConditionError::Missing(register))
}

/// Two words low first from `register`, as both PZEM manuals order their
/// 32-bit values. A pair that would reach past `0xFFFF` is missing at
/// `register`, the only one of its two addresses that exists.
pub(crate) fn low_first(registers: &Registers<'_>, register: u16) -> Result<u32, ConditionError> {
    let high = register
        .checked_add(1)
        .ok_or(ConditionError::Missing(register))?;
    let low = u32::from(word(registers, register)?);
    let high = u32::from(word(registers, high)?);
    Ok(low | (high << 16))
}

/// Write `block`'s cells from `registers` into `store` at `now`, the `n`th
/// cell as `signal(n)`, and say how many were written.
///
/// Stops at the first cell that fails; what it wrote before stands.
pub(crate) fn publish<E, const N: usize>(
    block: &Block,
    registers: &Registers<'_>,
    signal: impl Fn(usize) -> Option<Id>,
    now: Tick,
    store: &mut Signals<N>,
) -> Result<Polled, PollError<E>> {
    let mut cell = 0usize;
    for seen in block.decode(registers) {
        let seen = seen.map_err(|error| PollError::Decode { cell, error })?;
        let sig = signal(cell).ok_or(PollError::Signals)?;
        store.write(sig, now, seen).map_err(PollError::Store)?;
        cell = cell.saturating_add(1);
    }
    Ok(Polled { written: cell })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modbus::tests::register_reply;
    use crate::modbus::{Address, Function, Read, parse};

    fn registers(frame: &[u8], count: u16) -> Registers<'_> {
        let read = Read::new(Address::new(1).unwrap(), Function::ReadInput, 0, count).unwrap();
        parse(read, frame).unwrap()
    }

    #[test]
    fn an_alarm_word_is_clear_or_raised_and_anything_else_is_refused() {
        // Built by hand: three registers, 0x0000, 0xFFFF and 0x0001.
        let (frame, len) = register_reply(1, 0x04, &[0x0000, 0xFFFF, 0x0001]);
        let words = registers(&frame[..len], 3);
        assert_eq!(Alarm::at(&words, 0), Ok(Alarm::Clear));
        assert_eq!(Alarm::at(&words, 1), Ok(Alarm::Raised));
        assert_eq!(
            Alarm::at(&words, 2),
            Err(ConditionError::Undefined {
                register: 2,
                raw: 0x0001
            })
        );
        assert_eq!(Alarm::at(&words, 3), Err(ConditionError::Missing(3)));
    }

    #[test]
    fn a_low_first_pair_joins_its_words_and_a_half_missing_pair_is_refused() {
        // Built by hand: 0x0001_86A0 low word first, then one lone word.
        let (frame, len) = register_reply(1, 0x04, &[0x86A0, 0x0001, 0x1234]);
        let words = registers(&frame[..len], 3);
        assert_eq!(low_first(&words, 0), Ok(100_000));
        assert_eq!(low_first(&words, 2), Err(ConditionError::Missing(3)));
        assert_eq!(
            low_first(&words, 0xFFFF),
            Err(ConditionError::Missing(0xFFFF))
        );
    }
}
