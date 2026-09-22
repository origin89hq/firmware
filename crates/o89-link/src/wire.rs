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

/// How many bytes of a worst-case payload carry its number.
pub const STAMP_BYTES: usize = 4;

/// Stamp `payload` with `number`, keeping it delimiter-free.
///
/// Seven bits a byte with the top bit set, so no byte of the stamp is the
/// delimiter and the payload is still the worst case COBS can be given.
/// Four bytes carry twenty-eight bits, which is more than any run counts.
pub fn stamp(payload: &mut [u8], number: u32) {
    for (at, byte) in payload.iter_mut().take(STAMP_BYTES).enumerate() {
        let shift = u32::try_from(at).unwrap_or(0).saturating_mul(7);
        let bits = number.checked_shr(shift).unwrap_or(0) & 0x7f;
        *byte = u8::try_from(bits).unwrap_or(0) | 0x80;
    }
}

/// How many times the cut bench pulls the pair.
pub const CUTS: u32 = 1_000;
/// Frames in one pull: the frame that is cut, the frame its fragment runs
/// into and is refused with, and the frame after that, which must arrive
/// whole. Recovery inside one delimiter is the third frame arriving.
pub const PER_CUT: u32 = 3;
/// How many numbered frames the cut run sends.
pub const CUT_RUN: u32 = CUTS * PER_CUT;
// [`Arrivals::by_position`] has a slot a position.
const _: () = assert!(PER_CUT == 3);

/// Where the `number`th frame of the cut run is cut, as how many of its
/// `wire_len` bytes are sent, or `None` for a frame sent whole.
///
/// The first frame of every pull is the one cut, and the thousand cuts
/// sweep the frame from its first byte to the last byte before the
/// delimiter, so a fragment of one byte and a fragment short of only its
/// delimiter are both among them; never the delimiter itself, since a
/// frame that ended is not a frame that was cut. A wire too short to cut
/// is sent whole.
#[must_use]
pub fn cut_point(number: u32, wire_len: usize) -> Option<usize> {
    if number == 0 || number > CUT_RUN || number % PER_CUT != 1 {
        return None;
    }
    let trial = (number / PER_CUT).min(CUTS.saturating_sub(1));
    // Cut positions run from one byte to one short of the whole frame.
    let last = wire_len.checked_sub(1).filter(|last| *last >= 1)?;
    let span = last.checked_sub(1)?;
    let steps = usize::try_from(CUTS.saturating_sub(1)).ok()?.max(1);
    let trial = usize::try_from(trial).ok()?;
    let offset = trial.checked_mul(span)?.checked_div(steps)?;
    Some(1usize.saturating_add(offset))
}

/// What the controller counts when every frame of the cut run reached it
/// as sent: the numbered frames that arrived and the frames refused, both
/// one a pull, and never a third frame lost.
#[must_use]
pub const fn cut_run_expected() -> (u32, u32) {
    (CUTS, CUTS)
}

/// The numbered frames a run delivered, as the receiving side counts them
/// (F-086, F-087): how many, the highest, and two things a count alone
/// cannot say. Numbers arrive in the order they were sent, so an arrival
/// not above the one before it is a duplicate or a frame out of order,
/// which the sender never produces; and each number's position in a pull
/// of [`PER_CUT`] says which frame of the pull it was, so a cut run whose
/// arrivals all sit in the third position, strictly increasing and no
/// higher than the run, delivered every third frame and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Arrivals {
    /// How many numbered frames arrived.
    pub count: u32,
    /// The highest number that arrived.
    pub highest: u32,
    /// Arrivals whose number was not above the one before it.
    pub not_increasing: u32,
    /// Arrivals by position in a pull: the frame that would be cut, the
    /// frame that would run into it, the frame that must arrive.
    pub by_position: [u32; 3],
    last: u32,
}

impl Arrivals {
    /// No arrivals yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count: 0,
            highest: 0,
            not_increasing: 0,
            by_position: [0; 3],
            last: 0,
        }
    }

    /// A numbered frame arrived whole.
    pub fn arrived(&mut self, number: u32) {
        self.count = self.count.saturating_add(1);
        self.highest = self.highest.max(number);
        if number <= self.last {
            self.not_increasing = self.not_increasing.saturating_add(1);
        }
        self.last = number;
        let position = usize::try_from(number.saturating_sub(1) % PER_CUT).unwrap_or(0);
        if let Some(slot) = self.by_position.get_mut(position) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Numbers below the highest that did not arrive.
    #[must_use]
    pub const fn missing(&self) -> u32 {
        self.highest.saturating_sub(self.count)
    }
}

/// The number [`stamp`] wrote, or `None` if the payload is too short.
#[must_use]
pub fn stamped(payload: &[u8]) -> Option<u32> {
    let bytes = payload.get(..STAMP_BYTES)?;
    let mut number = 0u32;
    for (at, byte) in bytes.iter().enumerate() {
        let shift = u32::try_from(at).unwrap_or(0).saturating_mul(7);
        let bits = u32::from(*byte & 0x7f);
        number |= bits.checked_shl(shift).unwrap_or(0);
    }
    Some(number)
}

#[cfg(test)]
mod tests {
    use km43::{FrameReader, FrameWriter, MAX_FRAME, Received, max_frame_len};

    use super::*;

    #[test]
    fn every_numbered_bench_frame_survives_framing() {
        let mut writer = FrameWriter::new();
        let mut reader = FrameReader::new();
        let mut payload = [0; MAX_PAYLOAD];
        let mut wire = [0; MAX_FRAME];
        let mut arrived = 0;
        for number in 1..=10_000 {
            worst_case(&mut payload, number);
            stamp(&mut payload, number);
            let len = writer.write(&payload, &mut wire).expect("frames");
            for &byte in &wire[..len] {
                match reader.push(byte) {
                    Received::Frame(frame) => {
                        assert_eq!(frame, payload);
                        assert_eq!(stamped(frame), Some(number));
                        arrived += 1;
                    }
                    Received::Nothing => {}
                    other => panic!("frame {number}: {other:?}"),
                }
            }
        }
        assert_eq!(arrived, 10_000);
    }

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
    fn a_stamped_payload_reads_back_its_number_and_holds_no_delimiter() {
        for number in [0u32, 1, 2, 127, 128, 9_999, 10_000, 0x0fff_ffff] {
            let mut payload = [0u8; MAX_PAYLOAD];
            worst_case(&mut payload, 3);
            stamp(&mut payload, number);
            assert_eq!(stamped(&payload), Some(number), "number {number}");
            assert!(
                !payload.contains(&DELIMITER),
                "the stamp put a delimiter in the body, number {number}"
            );
        }
        // Too short to carry one, and says so rather than inventing one.
        assert_eq!(stamped(&[0x80, 0x80]), None);
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

    const PULLS: usize = CUTS as usize;

    /// The cut run, as the module puts it on the wire, read by the
    /// controller's own reader: the numbers that arrived in order, how
    /// many frames were refused and abandoned, and where each pull cut.
    /// Arrays, not a heap: the domain tests allocate no more than the part.
    struct Replay {
        arrived: [u32; PULLS],
        arrivals: usize,
        dropped: u32,
        abandoned: u32,
        cuts: [usize; PULLS],
        pulls: usize,
    }

    fn replay() -> Replay {
        let mut writer = FrameWriter::new();
        let mut reader = FrameReader::new();
        let mut payload = [0u8; MAX_PAYLOAD];
        let mut wire = [0u8; MAX_FRAME];
        let mut replay = Replay {
            arrived: [0; PULLS],
            arrivals: 0,
            dropped: 0,
            abandoned: 0,
            cuts: [0; PULLS],
            pulls: 0,
        };
        for number in 1..=CUT_RUN {
            worst_case(&mut payload, number);
            stamp(&mut payload, number);
            let len = writer.write(&payload, &mut wire).expect("frames");
            let sent = match cut_point(number, len) {
                Some(cut) => {
                    *replay.cuts.get_mut(replay.pulls).expect("a thousand pulls") = cut;
                    replay.pulls = replay.pulls.saturating_add(1);
                    cut
                }
                None => len,
            };
            for byte in wire.get(..sent).expect("fits") {
                match reader.push(*byte) {
                    Received::Frame(frame) => {
                        let slot = replay.arrived.get_mut(replay.arrivals);
                        *slot.expect("no more arrivals than pulls") =
                            stamped(frame).expect("numbered");
                        replay.arrivals = replay.arrivals.saturating_add(1);
                    }
                    Received::Dropped(_) => replay.dropped = replay.dropped.saturating_add(1),
                    Received::Abandoned => replay.abandoned = replay.abandoned.saturating_add(1),
                    Received::Nothing => {}
                }
            }
        }
        replay
    }

    #[test]
    fn f_086_the_cut_run_costs_one_frame_a_pull_and_the_third_always_arrives() {
        let replay = replay();
        let (expected_arrived, expected_refused) = cut_run_expected();
        assert_eq!(replay.pulls, PULLS);
        assert_eq!(replay.arrivals, expected_arrived as usize);
        assert_eq!(replay.dropped, expected_refused);
        assert_eq!(replay.abandoned, 0);
        // Exactly the third frame of every pull, and every one of them.
        for (pull, number) in replay.arrived.iter().enumerate() {
            let pull = u32::try_from(pull).expect("fits");
            assert_eq!(
                *number,
                pull.saturating_add(1).saturating_mul(PER_CUT),
                "pull {pull}"
            );
        }
    }

    #[test]
    fn f_086_the_cuts_sweep_the_frame_from_its_first_byte_to_its_last_before_the_delimiter() {
        let replay = replay();
        let mut writer = FrameWriter::new();
        let mut payload = [0u8; MAX_PAYLOAD];
        let mut wire = [0u8; MAX_FRAME];
        worst_case(&mut payload, 1);
        stamp(&mut payload, 1);
        let len = writer.write(&payload, &mut wire).expect("frames");
        assert_eq!(replay.cuts[0], 1);
        assert_eq!(replay.cuts[PULLS.saturating_sub(1)], len.saturating_sub(1));
        assert!(
            replay.cuts.windows(2).all(|pair| pair[0] <= pair[1]),
            "the sweep is monotonic"
        );
        assert!(
            replay.cuts.iter().all(|cut| *cut < len),
            "never the delimiter"
        );
    }

    #[test]
    fn f_086_only_the_first_frame_of_a_pull_is_cut_and_nothing_past_the_run() {
        for number in [2, 3, 5, 6, CUT_RUN - 1, CUT_RUN] {
            assert_eq!(cut_point(number, 1_000), None, "frame {number}");
        }
        assert_eq!(cut_point(0, 1_000), None);
        assert_eq!(cut_point(CUT_RUN + 1, 1_000), None);
        assert_eq!(cut_point(CUT_RUN + PER_CUT + 1, 1_000), None);
    }

    #[test]
    fn f_086_a_wire_too_short_to_cut_is_sent_whole() {
        assert_eq!(cut_point(1, 0), None);
        assert_eq!(cut_point(1, 1), None);
        // Two bytes: one byte and the delimiter, cut after the one.
        assert_eq!(cut_point(1, 2), Some(1));
        assert_eq!(cut_point(CUT_RUN - 2, 2), Some(1));
    }

    #[test]
    fn f_086_arrivals_in_order_are_counted_by_position_with_none_out_of_order() {
        let mut arrivals = Arrivals::new();
        for number in [3u32, 6, 9, 12] {
            arrivals.arrived(number);
        }
        assert_eq!(arrivals.count, 4);
        assert_eq!(arrivals.highest, 12);
        assert_eq!(arrivals.missing(), 8);
        assert_eq!(arrivals.not_increasing, 0);
        assert_eq!(arrivals.by_position, [0, 0, 4]);
    }

    #[test]
    fn f_086_a_duplicate_or_a_frame_out_of_order_is_counted_as_not_increasing() {
        let mut arrivals = Arrivals::new();
        for number in [1u32, 2, 2, 5, 4] {
            arrivals.arrived(number);
        }
        assert_eq!(arrivals.count, 5);
        assert_eq!(arrivals.not_increasing, 2);
        // Positions: 1 and 4 first, 2, 2 and 5 second, none third.
        assert_eq!(arrivals.by_position, [2, 3, 0]);
    }

    #[test]
    fn f_086_the_cut_run_read_by_the_arrivals_tracker_proves_every_third_frame() {
        let replay = replay();
        let mut arrivals = Arrivals::new();
        for number in replay.arrived.iter().take(replay.arrivals) {
            arrivals.arrived(*number);
        }
        assert_eq!(arrivals.count, CUTS);
        assert_eq!(arrivals.highest, CUT_RUN);
        assert_eq!(arrivals.not_increasing, 0);
        assert_eq!(arrivals.by_position, [0, 0, CUTS]);
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
                assert_eq!(
                    seen.frames, 0,
                    "merged fragment accepted: payload {payload_len}, cut {cut}"
                );
                assert_eq!(
                    seen.dropped, 1,
                    "merged fragment not refused: payload {payload_len}, cut {cut}"
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
