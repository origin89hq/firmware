//! The download window (F-033, F-034, L-190): for 1 500 ms from the
//! firmware's own start, the controller UART is read for `EnterDownload`
//! and for nothing else.
//!
//! A request that arrives inside it is honoured: answered `entering` with
//! its own `req_id`, after which the firmware sets the ROM's force-download
//! flag and resets into the ROM. Every other frame is left unanswered: the
//! controller states itself again once the window has passed, and a window
//! that answered would be a window running code it did not need to. Nothing
//! here can see a client transport, because none exists for another second;
//! the request can only come from this UART.

use km43::{
    DownloadRequest, DownloadVerdict, EnterDownload, FrameReader, FrameWriter, Intake,
    LinkEnvelope, LinkMessageType, MAX_FRAME, Received, ReqId, Side, arriving,
};

use o89_link::{EncodeError, Millis, Tick, link_header};

/// How long the window stays open (L-190): the half-open interval from the
/// firmware's start to 1 500 ms after it.
pub const WINDOW: Millis = Millis::from_millis(1_500);

/// The window, from the tick it opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    opened: Tick,
}

impl Window {
    /// Open the window at `now`, the firmware's own start.
    #[must_use]
    pub const fn open(now: Tick) -> Self {
        Self { opened: now }
    }

    /// Whether a byte read at `now` is inside the window: from the opening
    /// up to, and not including, [`WINDOW`] after it. A `now` before the
    /// opening is a tick from another boot, and outside.
    #[must_use]
    pub fn is_open(&self, now: Tick) -> bool {
        now.since(self.opened)
            .is_some_and(|open| open.as_millis() < WINDOW.as_millis())
    }

    /// Take one byte read at `now` off the controller UART.
    ///
    /// `Some` when the byte completes an `EnterDownload` the window
    /// honours. `None` for every other byte: one read once the window has
    /// closed, which the reader never sees; a frame still arriving; noise or
    /// a frame that fails its check, which the reader counts and resyncs
    /// past at the next delimiter; any other message; a request carrying a
    /// client's session; and a request whose body does not read.
    pub fn take(&self, reader: &mut FrameReader, byte: u8, now: Tick) -> Option<Honour> {
        if !self.is_open(now) {
            return None;
        }
        let Received::Frame(frame) = reader.push(byte) else {
            return None;
        };
        let envelope = LinkEnvelope::decode(frame).ok()?;
        match arriving(envelope.opcode(), Side::Comms, envelope.session()) {
            Intake::Act(LinkMessageType::EnterDownload) => {}
            Intake::Act(_) | Intake::Refuse(_) => return None,
        }
        let req_id = envelope.req_id();
        DownloadRequest::decode(envelope).ok()?;
        Some(Honour { req_id })
    }
}

/// An `EnterDownload` the window honours (F-034). Only [`Window::take`]
/// makes one; the firmware answers it, then sets the ROM's flag and resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an honoured request nobody answers leaves the controller knocking until its three seconds pass"]
pub struct Honour {
    req_id: ReqId,
}

impl Honour {
    /// The request's own id, which the answer carries (L-190).
    #[must_use]
    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }

    /// The `entering` answer, framed into `dst`, and its length.
    pub fn answer(
        &self,
        writer: &mut FrameWriter,
        dst: &mut [u8; MAX_FRAME],
    ) -> Result<usize, EncodeError> {
        let mut envelope = [0u8; 32];
        let len = DownloadVerdict {
            outcome: EnterDownload::Entering,
        }
        .write(
            link_header(LinkMessageType::EnterDownloadAck, self.req_id),
            &mut envelope,
        )
        .map_err(|_| EncodeError::Body)?;
        let envelope = envelope.get(..len).ok_or(EncodeError::Body)?;
        writer.write(envelope, dst).map_err(EncodeError::Frame)
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use km43::{
        DownloadReason, Heartbeat, LinkHeader, LinkUp, MessageType, SessionId, Side, Version,
    };

    use super::*;

    const OPENED: Tick = Tick::from_millis(40);

    /// An envelope as the controller writes it, framed for the wire.
    fn wire(envelope: &[u8], out: &mut [u8; MAX_FRAME]) -> usize {
        FrameWriter::new()
            .write(envelope, out)
            .expect("the envelope frames")
    }

    fn request(req_id: ReqId, session: SessionId, out: &mut [u8; MAX_FRAME]) -> usize {
        let mut envelope = [0u8; 32];
        let len = DownloadRequest {
            reason: DownloadReason::Bench,
        }
        .write(
            LinkHeader {
                kind: LinkMessageType::EnterDownload,
                session,
                req_id,
            },
            &mut envelope,
        )
        .expect("the request encodes");
        wire(envelope.get(..len).expect("fits"), out)
    }

    /// Feed `bytes`, the last at `last`, and hand back what the last byte
    /// did; every byte before it must have done nothing.
    fn feed(window: Window, reader: &mut FrameReader, bytes: &[u8], last: Tick) -> Option<Honour> {
        let (final_byte, before) = bytes.split_last().expect("a frame has bytes");
        for byte in before {
            assert_eq!(window.take(reader, *byte, OPENED), None, "honoured early");
        }
        window.take(reader, *final_byte, last)
    }

    #[test]
    fn f_033_a_request_inside_the_window_is_honoured_with_its_own_req_id() {
        let window = Window::open(OPENED);
        let mut reader = FrameReader::new();
        let mut frame = [0u8; MAX_FRAME];
        let len = request(ReqId(0x5A5A_0001), SessionId::None, &mut frame);
        let honour =
            feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED).expect("honoured");
        assert_eq!(honour.req_id(), ReqId(0x5A5A_0001));

        let mut answer = [0u8; MAX_FRAME];
        let len = honour
            .answer(&mut FrameWriter::new(), &mut answer)
            .expect("the answer builds");
        let mut back = FrameReader::new();
        let mut verdict = None;
        for byte in answer.get(..len).expect("fits") {
            if let Received::Frame(frame) = back.push(*byte) {
                let envelope = LinkEnvelope::decode(frame).expect("an envelope");
                assert_eq!(envelope.opcode(), LinkMessageType::EnterDownloadAck as u8);
                assert_eq!(envelope.req_id(), ReqId(0x5A5A_0001));
                assert_eq!(envelope.session(), SessionId::None);
                verdict = Some(DownloadVerdict::decode(envelope).expect("a verdict"));
            }
        }
        assert_eq!(
            verdict,
            Some(DownloadVerdict {
                outcome: EnterDownload::Entering
            })
        );
    }

    #[test]
    fn l_190_a_request_completing_at_the_last_millisecond_is_honoured() {
        let window = Window::open(OPENED);
        let mut frame = [0u8; MAX_FRAME];
        let len = request(ReqId(7), SessionId::None, &mut frame);
        let last = OPENED.after(Millis::from_millis(1_499)).expect("fits");
        assert!(window.is_open(last));
        let honour = feed(
            window,
            &mut FrameReader::new(),
            frame.get(..len).expect("fits"),
            last,
        );
        assert_eq!(honour.map(|h| h.req_id()), Some(ReqId(7)));
    }

    #[test]
    fn l_190_a_request_completing_at_fifteen_hundred_milliseconds_is_not_honoured() {
        let window = Window::open(OPENED);
        let mut frame = [0u8; MAX_FRAME];
        let len = request(ReqId(7), SessionId::None, &mut frame);
        let closed = OPENED.after(WINDOW).expect("fits");
        assert!(!window.is_open(closed));
        let honour = feed(
            window,
            &mut FrameReader::new(),
            frame.get(..len).expect("fits"),
            closed,
        );
        assert_eq!(honour, None);
    }

    #[test]
    fn l_190_a_tick_before_the_opening_is_outside_the_window() {
        let window = Window::open(OPENED);
        assert!(!window.is_open(Tick::ZERO));
        assert!(window.is_open(OPENED));
    }

    #[test]
    fn f_033_every_other_frame_is_left_unanswered() {
        let window = Window::open(OPENED);
        let mut reader = FrameReader::new();
        let mut envelope = [0u8; 256];
        let mut frame = [0u8; MAX_FRAME];

        let header = |kind| LinkHeader {
            kind,
            session: SessionId::None,
            req_id: ReqId(3),
        };
        let len = LinkUp {
            version: Version::V1_0,
            role: Side::Controller,
            fw: "0.0.0+g0123abcd",
            boot_id: 9,
            hw: "controller-a rev A",
            net_version: None,
        }
        .write(header(LinkMessageType::LinkUp), &mut envelope)
        .expect("encodes");
        let len = wire(envelope.get(..len).expect("fits"), &mut frame);
        assert_eq!(
            feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED),
            None
        );

        let len = Heartbeat {
            uptime_s: 1,
            conns: 0,
        }
        .write(header(LinkMessageType::Heartbeat), &mut envelope)
        .expect("encodes");
        let len = wire(envelope.get(..len).expect("fits"), &mut frame);
        assert_eq!(
            feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED),
            None
        );

        // The answer the controller would never send, in the direction it
        // cannot come from: refused by the intake, and not honoured.
        let len = DownloadVerdict {
            outcome: EnterDownload::Entering,
        }
        .write(header(LinkMessageType::EnterDownloadAck), &mut envelope)
        .expect("encodes");
        let len = wire(envelope.get(..len).expect("fits"), &mut frame);
        assert_eq!(
            feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED),
            None
        );

        // An error, and a message of the session layer: neither is a request.
        let len = km43::ErrorBody {
            code: km43::Incoming::LinkLocal(km43::LinkErrorCode::WrongSide),
            detail: "",
        }
        .write(
            km43::Header {
                kind: MessageType::ErrorResponse,
                session: SessionId::None,
                req_id: ReqId(0),
            },
            &mut envelope,
        )
        .expect("encodes");
        let len = wire(envelope.get(..len).expect("fits"), &mut frame);
        assert_eq!(
            feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED),
            None
        );

        // And the request after all of them is still honoured.
        let len = request(ReqId(4), SessionId::None, &mut frame);
        let honour = feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED);
        assert_eq!(honour.map(|h| h.req_id()), Some(ReqId(4)));
    }

    #[test]
    fn l_191_a_request_in_a_clients_session_is_not_honoured() {
        let window = Window::open(OPENED);
        let mut frame = [0u8; MAX_FRAME];
        let session = SessionId::Assigned(NonZeroU16::new(5).expect("nonzero"));
        let len = request(ReqId(7), session, &mut frame);
        let honour = feed(
            window,
            &mut FrameReader::new(),
            frame.get(..len).expect("fits"),
            OPENED,
        );
        assert_eq!(honour, None);
    }

    #[test]
    fn f_033_a_request_whose_body_does_not_read_is_not_honoured() {
        let window = Window::open(OPENED);
        // A reason no version allocates: the header is an `EnterDownload`,
        // the body is not one.
        let mut envelope = [0u8; 32];
        let mut cbor = LinkHeader {
            kind: LinkMessageType::EnterDownload,
            session: SessionId::None,
            req_id: ReqId(8),
        }
        .write(1, &mut envelope)
        .expect("the header encodes");
        cbor.key(1).expect("key");
        cbor.u64(9).expect("value");
        let len = cbor.finish().expect("finishes");
        let mut frame = [0u8; MAX_FRAME];
        let len = wire(envelope.get(..len).expect("fits"), &mut frame);
        let honour = feed(
            window,
            &mut FrameReader::new(),
            frame.get(..len).expect("fits"),
            OPENED,
        );
        assert_eq!(honour, None);
    }

    #[test]
    fn f_033_noise_and_a_broken_frame_do_not_hide_the_request_after_them() {
        let window = Window::open(OPENED);
        let mut reader = FrameReader::new();
        // The ROM's text at its own baud, read at the link's: bytes, and a
        // delimiter somewhere in them.
        for byte in b"ESP-ROM:esp32c6-20220919\r\n\x00garbage" {
            assert_eq!(window.take(&mut reader, *byte, OPENED), None);
        }
        let mut frame = [0u8; MAX_FRAME];
        let len = request(ReqId(11), SessionId::None, &mut frame);
        // The same request with one bit flipped fails its check; a read that
        // lost the middle of one leaves a run the next delimiter ends.
        let mut flipped = frame;
        let middle = len.checked_div(2).expect("a length");
        *flipped.get_mut(middle).expect("inside") ^= 0x10;
        assert_eq!(
            feed(
                window,
                &mut reader,
                flipped.get(..len).expect("fits"),
                OPENED
            ),
            None
        );
        let head = frame.get(..middle).expect("fits");
        let tail = frame
            .get(middle.checked_add(2).expect("inside")..len)
            .expect("fits");
        for byte in head.iter().chain(tail) {
            assert_eq!(window.take(&mut reader, *byte, OPENED), None);
        }
        // The next whole request is honoured.
        let len = request(ReqId(12), SessionId::None, &mut frame);
        let honour = feed(window, &mut reader, frame.get(..len).expect("fits"), OPENED);
        assert_eq!(honour.map(|h| h.req_id()), Some(ReqId(12)));
    }

    #[test]
    fn f_033_a_window_that_hears_nothing_closes_without_honouring() {
        let window = Window::open(OPENED);
        let mut reader = FrameReader::new();
        let mut now = OPENED;
        // Bounded: one step a millisecond until the window has closed.
        for _ in 0..=WINDOW.as_millis() {
            assert_eq!(window.take(&mut reader, 0xFF, now), None);
            now = now.after(Millis::from_millis(1)).expect("fits");
        }
        assert!(!window.is_open(now));
    }
}
