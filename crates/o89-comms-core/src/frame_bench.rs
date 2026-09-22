//! Keep the stress sender out of the controller's link-up handshake, and
//! plan the cut bench: the pair pulled mid-frame a thousand times, on the
//! wire, by the sender itself (F-086).

use crate::Frame;

/// How many times the cut bench pulls the pair.
pub const CUTS: u32 = 1_000;
/// Frames in one pull: the frame that is cut, the frame its fragment runs
/// into and is refused with, and the frame after that, which must arrive
/// whole. Recovery inside one delimiter is the third frame arriving.
pub const PER_CUT: u32 = 3;
/// How many numbered frames the cut run sends.
pub const CUT_RUN: u32 = CUTS * PER_CUT;

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

/// The frames bench starts only after both ends have linked. Our own
/// `LinkUpAck` can arrive before the controller has received its answer;
/// starting a batch then starves reads, fills the RX FIFO, and stalls the
/// controller's writes until it rebuilds its UART (#63).
pub struct FrameBenchStart {
    controller_ready: bool,
    matching_mode: bool,
    no_flow: bool,
}

impl FrameBenchStart {
    /// Wait for the controller's first validated heartbeat.
    #[must_use]
    pub const fn new(no_flow: bool) -> Self {
        Self {
            controller_ready: false,
            matching_mode: false,
            no_flow,
        }
    }

    /// Observe output from the validated link state machine. A heartbeat
    /// answer means a valid controller heartbeat was received; handshakes
    /// clear that evidence so it cannot survive a reconnect.
    pub fn observe(&mut self, frame: Frame) {
        match frame {
            Frame::HeartbeatAck { .. } => self.controller_ready = true,
            Frame::LinkUp { .. } | Frame::LinkUpAck { .. } => {
                self.controller_ready = false;
                self.matching_mode = false;
            }
            Frame::Heartbeat { .. }
            | Frame::DownloadRefused { .. }
            | Frame::CloseReport { .. }
            | Frame::NetFailed { .. }
            | Frame::Refuse { .. } => {}
        }
    }

    /// Record the mode from the link's validated controller handshake.
    pub fn controller(&mut self, mode: Option<bool>) {
        self.matching_mode = mode == Some(self.no_flow);
    }

    /// Whether a batch may start. Loss of our link clears the peer's proof.
    pub fn ready(&mut self, linked: bool) -> bool {
        self.controller_ready &= linked;
        self.matching_mode &= linked;
        self.controller_ready && self.matching_mode
    }
}

/// Decode the bench prerelease carried in the firmware identity. Ordinary
/// controller images do not arm either bench mode.
pub(crate) fn controller_mode(firmware: &str) -> Option<bool> {
    match firmware
        .split_once('+')
        .and_then(|(release, _)| release.split_once('-'))
        .and_then(|(_, pre)| pre.split('.').next())
    {
        Some("bn") => Some(true),
        Some("bf") => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km43::{FrameReader, FrameWriter, MAX_FRAME, MAX_PAYLOAD, Received, ReqId};
    use o89_link::{stamp, stamped, worst_case};

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
    fn our_link_up_alone_does_not_start_the_blast() {
        let mut start = FrameBenchStart::new(false);
        start.observe(Frame::LinkUpAck { req_id: ReqId(1) });
        start.observe(Frame::Heartbeat { req_id: ReqId(2) });
        assert!(!start.ready(true));
    }

    #[test]
    fn a_valid_controller_heartbeat_starts_the_linked_blast() {
        let mut start = FrameBenchStart::new(false);
        start.controller(Some(false));
        start.observe(Frame::HeartbeatAck { req_id: ReqId(1) });
        assert!(start.ready(true));
        assert!(start.ready(true));
    }

    #[test]
    fn losing_our_link_requires_a_new_controller_heartbeat() {
        let mut start = FrameBenchStart::new(false);
        start.controller(Some(false));
        start.observe(Frame::HeartbeatAck { req_id: ReqId(1) });
        assert!(!start.ready(false));
        assert!(!start.ready(true));
        start.controller(Some(false));
        start.observe(Frame::HeartbeatAck { req_id: ReqId(2) });
        assert!(start.ready(true));
    }

    #[test]
    fn either_handshake_clears_the_previous_controller_proof() {
        for frame in [
            Frame::LinkUp { req_id: ReqId(2) },
            Frame::LinkUpAck { req_id: ReqId(2) },
        ] {
            let mut start = FrameBenchStart::new(false);
            start.controller(Some(false));
            start.observe(Frame::HeartbeatAck { req_id: ReqId(1) });
            assert!(start.ready(true));
            start.observe(frame);
            assert!(!start.ready(true));
        }
    }
    #[test]
    fn only_the_matching_bench_controller_can_start_a_run() {
        for no_flow in [false, true] {
            for (firmware, expected) in [
                ("0.0.0", false),
                ("0.0.0-bf+g0123abcd", !no_flow),
                ("0.0.0-bn+g0123abcd", no_flow),
                ("0.0.0-bn.dirty+g0123abcd", no_flow),
                ("0.0.0-bf.dirty+g0123abcd", !no_flow),
            ] {
                let mut start = FrameBenchStart::new(no_flow);
                start.controller(controller_mode(firmware));
                assert!(!start.ready(true), "still needs the heartbeat");
                start.observe(Frame::HeartbeatAck { req_id: ReqId(1) });
                assert_eq!(start.ready(true), expected, "{firmware}");
            }
        }
    }
}
