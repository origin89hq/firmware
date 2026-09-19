//! The timing and the rules both sides' link-local frames meet.

use km43::{
    ErrorBody, FrameError, FrameWriter, Header, Incoming, LinkEnvelope, LinkErrorCode, LinkHeader,
    LinkMessageType, MessageType, ReqId, SessionId, Side, Version,
};

use crate::Millis;

/// A heartbeat every two seconds (L-100).
pub const HEARTBEAT_PERIOD: Millis = Millis::from_millis(2_000);

/// Three missed heartbeats: the link is dead (L-100, L-110, L-120).
pub const DEAD_AFTER: Millis = Millis::from_millis(6_000);

/// How often `LinkUp` goes out while the link is down: the cadence L-120
/// gives the comms processor, and the controller keeps the same one.
pub const LINKUP_PERIOD: Millis = Millis::from_millis(2_000);

/// The version of the link both firmwares speak.
pub const OURS: Version = Version::V1_0;

/// The envelopes a side writes on the link are small: two texts of 32, a
/// handful of integers, a refusal with no detail. A quarter of the payload
/// cap holds every one with room.
pub const LINK_ENVELOPE: usize = 256;

/// Why a frame did not encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The body would not write.
    Body,
    /// The envelope would not frame into its buffer.
    Frame(FrameError),
}

// By hand: KM43's `FrameError` carries no `defmt` impl to derive through.
#[cfg(feature = "defmt")]
impl defmt::Format for EncodeError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::Body => defmt::write!(f, "Body"),
            Self::Frame(_) => defmt::write!(f, "Frame"),
        }
    }
}

/// The header of a link-local frame: always session 0 (L-181).
#[must_use]
pub const fn link_header(kind: LinkMessageType, req_id: ReqId) -> LinkHeader {
    LinkHeader {
        kind,
        session: SessionId::None,
        req_id,
    }
}

/// Whether `envelope` is the peer refusing something of ours: an
/// `ErrorResponse` on session 0 with request 0. It is never answered with
/// another error (L-181), and it carries no request id for anything to
/// wait on. An error with a session or a request id is a client's frame.
#[must_use]
pub fn is_peer_refusal(envelope: &LinkEnvelope<'_>) -> bool {
    envelope.opcode() == MessageType::ErrorResponse as u8
        && envelope.session() == SessionId::None
        && envelope.req_id() == ReqId(0)
}

/// Frame this side's refusal of a link-local frame into `dst`: an
/// `ErrorResponse` on session 0 with request 0, the code and no detail
/// (L-181). Its length.
pub fn frame_refusal(
    code: LinkErrorCode,
    writer: &mut FrameWriter,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut envelope = [0u8; LINK_ENVELOPE];
    let len = ErrorBody {
        code: Incoming::LinkLocal(code),
        detail: "",
    }
    .write(
        Header {
            kind: MessageType::ErrorResponse,
            session: SessionId::None,
            req_id: ReqId(0),
        },
        &mut envelope,
    )
    .map_err(|_| EncodeError::Body)?;
    let payload = envelope.get(..len).ok_or(EncodeError::Body)?;
    writer.write(payload, dst).map_err(EncodeError::Frame)
}

/// Whether a frame of `kind` still crosses a link protocol major mismatch
/// at `side` (L-050): the statement and the heartbeat with their answers,
/// and the one release frame that side takes, the acknowledgement of its
/// own release at the controller and the release itself at the comms
/// processor. Everything else is refused with code 261.
#[must_use]
pub const fn crosses_mismatch(side: Side, kind: LinkMessageType) -> bool {
    match kind {
        LinkMessageType::LinkUp
        | LinkMessageType::LinkUpAck
        | LinkMessageType::Heartbeat
        | LinkMessageType::HeartbeatAck => true,
        LinkMessageType::CommsReleaseAck => matches!(side, Side::Controller),
        LinkMessageType::CommsRelease => matches!(side, Side::Comms),
        LinkMessageType::ClientConnected
        | LinkMessageType::ClientConnectedAck
        | LinkMessageType::ClientDisconnected
        | LinkMessageType::ClientDisconnectedAck
        | LinkMessageType::CloseConnection
        | LinkMessageType::CloseConnectionAck
        | LinkMessageType::NetConfig
        | LinkMessageType::NetConfigAck
        | LinkMessageType::TimeOffer
        | LinkMessageType::TimeOfferAck
        | LinkMessageType::EnterDownload
        | LinkMessageType::EnterDownloadAck => false,
    }
}

/// Whether a request of `kind` arriving at `side` before that side is linked
/// is refused with 258 (L-033). Before the link only the handshake and the
/// heartbeat are admitted; the controller answers a `ClientConnected` with
/// an outcome of its own for that, an `EnterDownload` has the window's
/// answer at the comms processor (L-191), and an answer is not a request.
#[must_use]
pub const fn refused_before_link(side: Side, kind: LinkMessageType) -> bool {
    match kind {
        LinkMessageType::ClientDisconnected | LinkMessageType::TimeOffer => {
            matches!(side, Side::Controller)
        }
        LinkMessageType::CloseConnection
        | LinkMessageType::NetConfig
        | LinkMessageType::CommsRelease => matches!(side, Side::Comms),
        LinkMessageType::LinkUp
        | LinkMessageType::LinkUpAck
        | LinkMessageType::Heartbeat
        | LinkMessageType::HeartbeatAck
        | LinkMessageType::ClientConnected
        | LinkMessageType::EnterDownload
        | LinkMessageType::ClientConnectedAck
        | LinkMessageType::ClientDisconnectedAck
        | LinkMessageType::CloseConnectionAck
        | LinkMessageType::NetConfigAck
        | LinkMessageType::TimeOfferAck
        | LinkMessageType::CommsReleaseAck
        | LinkMessageType::EnterDownloadAck => false,
    }
}

#[cfg(test)]
mod tests {
    use km43::{FrameReader, Heartbeat, MAX_FRAME, Received};

    use super::*;

    #[test]
    fn l_181_a_refusal_is_framed_on_session_zero_with_request_zero_and_read_as_one() {
        let mut wire = [0u8; MAX_FRAME];
        let len = frame_refusal(LinkErrorCode::WrongSide, &mut FrameWriter::new(), &mut wire)
            .expect("frames");
        let mut reader = FrameReader::new();
        let mut refusals = 0u32;
        for byte in wire.get(..len).expect("fits") {
            if let Received::Frame(frame) = reader.push(*byte) {
                let envelope = LinkEnvelope::decode(frame).expect("an envelope");
                assert_eq!(envelope.opcode(), MessageType::ErrorResponse as u8);
                assert!(is_peer_refusal(&envelope));
                refusals = refusals.checked_add(1).expect("fits");
            }
        }
        assert_eq!(refusals, 1);
    }

    #[test]
    fn l_181_a_frame_with_a_request_id_is_not_a_peer_refusal() {
        let mut buf = [0u8; 64];
        let len = Heartbeat {
            uptime_s: 1,
            conns: 0,
        }
        .write(link_header(LinkMessageType::Heartbeat, ReqId(0)), &mut buf)
        .expect("encodes");
        let beat = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert!(!is_peer_refusal(&beat), "a heartbeat is not a refusal");
        let len = ErrorBody {
            code: Incoming::LinkLocal(LinkErrorCode::WrongSide),
            detail: "",
        }
        .write(
            Header {
                kind: MessageType::ErrorResponse,
                session: SessionId::None,
                req_id: ReqId(5),
            },
            &mut buf,
        )
        .expect("encodes");
        let answer = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert!(
            !is_peer_refusal(&answer),
            "an error with a request id is a client's"
        );
    }

    #[test]
    fn l_181_a_refusal_that_does_not_fit_is_an_error_not_a_panic() {
        let mut tiny = [0u8; 4];
        assert!(matches!(
            frame_refusal(LinkErrorCode::WrongSide, &mut FrameWriter::new(), &mut tiny),
            Err(EncodeError::Frame(_))
        ));
    }

    #[test]
    fn l_033_before_the_link_each_side_admits_only_the_handshake() {
        for side in [Side::Controller, Side::Comms] {
            for kind in [
                LinkMessageType::LinkUp,
                LinkMessageType::LinkUpAck,
                LinkMessageType::Heartbeat,
                LinkMessageType::HeartbeatAck,
            ] {
                assert!(!refused_before_link(side, kind), "{kind:?} at {side:?}");
            }
        }
        for kind in [
            LinkMessageType::ClientDisconnected,
            LinkMessageType::TimeOffer,
        ] {
            assert!(refused_before_link(Side::Controller, kind), "{kind:?}");
        }
        for kind in [
            LinkMessageType::CloseConnection,
            LinkMessageType::NetConfig,
            LinkMessageType::CommsRelease,
        ] {
            assert!(refused_before_link(Side::Comms, kind), "{kind:?}");
        }
        // Answered with outcomes of their own before the link.
        assert!(!refused_before_link(
            Side::Controller,
            LinkMessageType::ClientConnected
        ));
        assert!(!refused_before_link(
            Side::Comms,
            LinkMessageType::EnterDownload
        ));
    }

    #[test]
    fn l_050_the_link_crosses_a_mismatch_and_only_each_sides_release_frame_with_it() {
        for side in [Side::Controller, Side::Comms] {
            for kind in [
                LinkMessageType::LinkUp,
                LinkMessageType::LinkUpAck,
                LinkMessageType::Heartbeat,
                LinkMessageType::HeartbeatAck,
            ] {
                assert!(crosses_mismatch(side, kind), "{kind:?} at {side:?}");
            }
            for kind in [
                LinkMessageType::CloseConnection,
                LinkMessageType::NetConfig,
                LinkMessageType::EnterDownload,
                LinkMessageType::TimeOffer,
            ] {
                assert!(!crosses_mismatch(side, kind), "{kind:?} at {side:?}");
            }
        }
        assert!(crosses_mismatch(
            Side::Controller,
            LinkMessageType::CommsReleaseAck
        ));
        assert!(!crosses_mismatch(
            Side::Controller,
            LinkMessageType::CommsRelease
        ));
        assert!(crosses_mismatch(Side::Comms, LinkMessageType::CommsRelease));
        assert!(!crosses_mismatch(
            Side::Comms,
            LinkMessageType::CommsReleaseAck
        ));
    }
}
