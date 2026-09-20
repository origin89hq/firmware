//! What a broken line costs a reader, and the worst frame the wire carries.
//!
//! KM43 frames are `COBS(envelope | crc16) 0x00`, so the delimiter is the
//! one byte a frame body cannot hold and a reader that lost its footing
//! finds it again at the next one (P-030). What that costs is the subject
//! here: when a pair is pulled mid-frame the fragment runs into whatever
//! arrives next, and the two are read as one, so the frame whose delimiter
//! closes that run is lost and the frame after it is read. One frame, not
//! the link.
//!
//! [`worst_case`] is the payload both the host test and the bench measure
//! with, written once so that "worst case" means the same thing in a test
//! and in a bench log.

use km43::{DELIMITER, MAX_PAYLOAD};

/// Fill `payload` with the worst case for the wire.
///
/// No byte is the delimiter, so COBS never finds a zero to end a run
/// cheaply and the encoding is the longest that payload length allows;
/// the bytes vary with `seed` so a run of frames is not one frame
/// repeated, which would let a stuck buffer look like a working one.
///
/// Refuses nothing: a payload longer than [`MAX_PAYLOAD`] cannot be
/// framed, and the caller sizing it is the caller that knows.
pub fn worst_case(payload: &mut [u8], seed: u32) {
    debug_assert!(payload.len() <= MAX_PAYLOAD, "a payload KM43 can frame");
    let mut state = seed | 1;
    for byte in payload.iter_mut() {
        // A small xorshift, so the bytes are spread and the sequence is the
        // same on the host and on the part.
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        // Never the delimiter: that is what makes it the worst case.
        *byte = match state.to_le_bytes() {
            [b, ..] if b != DELIMITER => b,
            _ => 0xff,
        };
    }
}

#[cfg(test)]
mod tests {
    use km43::{FrameReader, FrameWriter, MAX_FRAME, Received, max_frame_len};

    use super::*;

    /// One frame of `payload` bytes on the wire, worst case, by `seed`.
    fn frame(seed: u32, payload_len: usize, wire: &mut [u8; MAX_FRAME]) -> usize {
        let mut payload = [0u8; MAX_PAYLOAD];
        let payload = payload.get_mut(..payload_len).expect("a payload that fits");
        worst_case(payload, seed);
        FrameWriter::new()
            .write(payload, wire)
            .expect("a frame that fits")
    }

    /// Every frame the reader hands up from `bytes`, and what it refused.
    #[derive(Default, PartialEq, Eq, Debug)]
    struct Read {
        frames: usize,
        dropped: usize,
        abandoned: usize,
    }

    fn feed(reader: &mut FrameReader, bytes: &[u8], seen: &mut Read) {
        for byte in bytes {
            match reader.push(*byte) {
                Received::Frame(_) => seen.frames = seen.frames.saturating_add(1),
                Received::Dropped(_) => seen.dropped = seen.dropped.saturating_add(1),
                Received::Abandoned => seen.abandoned = seen.abandoned.saturating_add(1),
                Received::Nothing => {}
            }
        }
    }

    #[test]
    fn the_worst_case_payload_holds_no_delimiter_and_fills_the_wire() {
        let mut payload = [0u8; MAX_PAYLOAD];
        worst_case(&mut payload, 1);
        assert!(
            !payload.contains(&DELIMITER),
            "a delimiter in the body would cheapen the encoding"
        );
        let mut wire = [0u8; MAX_FRAME];
        let len = FrameWriter::new()
            .write(&payload, &mut wire)
            .expect("frames");
        assert_eq!(
            len,
            max_frame_len(MAX_PAYLOAD),
            "the longest a full payload can be on the wire"
        );
        // And a different seed is a different frame, so a run of them is
        // not one frame repeated.
        let mut other = [0u8; MAX_PAYLOAD];
        worst_case(&mut other, 2);
        assert_ne!(payload, other);
    }

    #[test]
    fn f_086_a_pair_pulled_mid_frame_costs_one_frame_and_the_next_is_read() {
        // A thousand pulls: every cut point of a frame, across payload
        // lengths, each followed by two whole frames. The fragment runs
        // into the frame after it and the two are read as one, so that
        // frame is lost; the frame after *it* has to arrive whole. That is
        // recovery inside one delimiter.
        let mut trials = 0u32;
        for payload_len in [1usize, 2, 17, 64, 255, 256, 700, MAX_PAYLOAD] {
            let mut cut_wire = [0u8; MAX_FRAME];
            let cut_len = frame(7, payload_len, &mut cut_wire);
            let mut next_wire = [0u8; MAX_FRAME];
            let next_len = frame(11, payload_len, &mut next_wire);
            let mut after_wire = [0u8; MAX_FRAME];
            let after_len = frame(13, payload_len, &mut after_wire);
            // Cut everywhere but at the delimiter itself: a frame that
            // ended is not a frame that was cut.
            for cut in 1..cut_len {
                trials = trials.saturating_add(1);
                let mut reader = FrameReader::new();
                let mut seen = Read::default();
                feed(&mut reader, cut_wire.get(..cut).expect("fits"), &mut seen);
                feed(
                    &mut reader,
                    next_wire.get(..next_len).expect("fits"),
                    &mut seen,
                );
                let after_cut = seen.frames;
                feed(
                    &mut reader,
                    after_wire.get(..after_len).expect("fits"),
                    &mut seen,
                );
                assert_eq!(
                    seen.frames.saturating_sub(after_cut),
                    1,
                    "the frame after the loss was not read whole: payload {payload_len}, cut {cut}"
                );
                assert!(
                    seen.frames <= 2,
                    "more frames than were sent whole: payload {payload_len}, cut {cut}"
                );
            }
        }
        assert!(trials >= 1000, "only {trials} pulls");
    }

    #[test]
    fn f_086_a_pull_the_line_goes_quiet_after_loses_nothing_that_follows_it() {
        // The other shape of the same fault: the pair is pulled and
        // nothing arrives for a while. The reader is told how long the
        // line has been quiet, abandons the part-frame, and the frame
        // after it is read whole rather than merged into the fragment.
        let mut cut_wire = [0u8; MAX_FRAME];
        let cut_len = frame(7, 512, &mut cut_wire);
        let mut next_wire = [0u8; MAX_FRAME];
        let next_len = frame(11, 512, &mut next_wire);
        for cut in 1..cut_len {
            let mut reader = FrameReader::new();
            let mut seen = Read::default();
            feed(&mut reader, cut_wire.get(..cut).expect("fits"), &mut seen);
            // The line quiet for longer than a frame can take to arrive.
            let mut abandoned = 0u32;
            if let Received::Abandoned = reader.tick(None, 60_000) {
                abandoned = 1;
            }
            feed(
                &mut reader,
                next_wire.get(..next_len).expect("fits"),
                &mut seen,
            );
            assert_eq!(abandoned, 1, "the part-frame was not abandoned, cut {cut}");
            assert_eq!(
                seen.frames, 1,
                "the frame after the quiet was not read whole, cut {cut}"
            );
        }
    }
}
