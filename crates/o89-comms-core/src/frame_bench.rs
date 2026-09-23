//! Keep the stress sender out of the controller's link-up handshake. The
//! cut bench's plan, the pair pulled mid-frame a thousand times on the wire
//! by the sender itself, is `o89-link`'s, where both sides read it (F-086).

use crate::Frame;

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
            | Frame::NetReport { .. }
            | Frame::TimeOffer { .. }
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
    use km43::ReqId;

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
