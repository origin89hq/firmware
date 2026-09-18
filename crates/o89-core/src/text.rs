//! Bounded text at the boundaries: the bytes that arrived, up to a cap,
//! compared byte for byte.
//!
//! Every text this store holds has a cap the protocol names, and every
//! comparison the protocol permits on one is byte equality: no case
//! folding, no trimming, no normalisation. So a text is an array and a
//! length, validated once as UTF-8 and trusted thereafter, and a text past
//! its cap is refused rather than truncated, because "pump hous" is a
//! different label and somebody acts on it wrongly.

use core::fmt;

use crate::body::{Malformed, Reader, Writer};

/// Up to `N` bytes of UTF-8, `N` at most 255 so the length is one byte on
/// the part.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

/// A text past its cap, carrying the length it had and the cap it hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TooLong {
    /// The bytes the text had.
    pub len: usize,
    /// The bytes the field holds.
    pub cap: usize,
}

impl<const N: usize> Text<N> {
    /// The bytes the field holds.
    pub const CAPACITY: usize = N;

    /// Nothing.
    pub const EMPTY: Self = Self {
        bytes: [0; N],
        len: 0,
    };

    /// `text`, or a refusal past the cap.
    pub fn new(text: &str) -> Result<Self, TooLong> {
        const { assert!(N <= u8::MAX as usize) }
        let too_long = TooLong {
            len: text.len(),
            cap: N,
        };
        let len = u8::try_from(text.len()).map_err(|_| too_long)?;
        let mut bytes = [0u8; N];
        let room = bytes.get_mut(..text.len()).ok_or(too_long)?;
        room.copy_from_slice(text.as_bytes());
        Ok(Self { bytes, len })
    }

    /// The bytes, exactly as many as there are.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The text. It was UTF-8 when it was made or decoded, so the empty
    /// string here is unreachable and only there because a `str` cannot
    /// be assumed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let text = core::str::from_utf8(self.as_bytes());
        debug_assert!(text.is_ok(), "a text is validated when it is made");
        text.unwrap_or("")
    }

    /// How many bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The length and then the whole field, the unused tail zero.
    pub(crate) fn put(&self, writer: &mut Writer<'_>) {
        writer.u8(self.len);
        writer.put(&self.bytes);
    }

    /// The length and the field, refusing a length past the cap and bytes
    /// that are not UTF-8.
    pub(crate) fn take(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let len = reader.u8()?;
        if usize::from(len) > N {
            return Err(reader.malformed(1));
        }
        let bytes = reader.take::<N>()?;
        let text = Self { bytes, len };
        if core::str::from_utf8(text.as_bytes()).is_err() {
            return Err(reader.malformed(N));
        }
        Ok(text)
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Text").field(&self.as_str()).finish()
    }
}

#[cfg(feature = "defmt")]
impl<const N: usize> defmt::Format for Text<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{=str}", self.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_holds_what_it_was_given_up_to_its_cap() {
        let text = Text::<8>::new("étable").expect("seven bytes fit eight");
        assert_eq!(text.as_str(), "étable");
        assert_eq!(text.len(), 7);
        assert!(!text.is_empty());
        assert!(Text::<8>::EMPTY.is_empty());
        assert_eq!(Text::<8>::new("exactly8").map(|t| t.len()), Ok(8));
    }

    #[test]
    fn a_text_past_its_cap_is_refused_not_truncated() {
        assert_eq!(Text::<8>::new("nine char"), Err(TooLong { len: 9, cap: 8 }));
    }

    #[test]
    fn a_text_survives_the_round_trip_and_refuses_a_long_length_or_bad_utf8() {
        let text = Text::<4>::new("ab").expect("fits");
        let mut bytes = [0u8; 5];
        text.put(&mut Writer::over(&mut bytes));
        assert_eq!(bytes, [2, b'a', b'b', 0, 0]);
        assert_eq!(Text::<4>::take(&mut Reader::over(&bytes)), Ok(text));
        let long = [5, b'a', b'b', 0, 0];
        assert_eq!(
            Text::<4>::take(&mut Reader::over(&long)),
            Err(Malformed { at: 0 })
        );
        let bad = [2, 0xFF, b'b', 0, 0];
        assert_eq!(
            Text::<4>::take(&mut Reader::over(&bad)),
            Err(Malformed { at: 1 })
        );
        let short = [1, b'a'];
        assert_eq!(
            Text::<4>::take(&mut Reader::over(&short)),
            Err(Malformed { at: 1 })
        );
    }
}
