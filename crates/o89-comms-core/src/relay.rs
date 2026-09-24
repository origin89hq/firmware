//! A client's frame on its way to the controller, and the controller's on
//! its way back: the envelope's four elements and nothing under them.
//!
//! Inbound, every frame from a client has its connection's handle written
//! over its `session_id` (P-021), so the controller answers on the
//! connection the frame came from, and a client cannot speak on another's
//! handle or on the link's own session 0. The body is copied as it stands;
//! it is under a MAC this side cannot check. A frame that is not four
//! elements, or whose elements do not read, is answered here with
//! `Error 1` on session 0, request 0, on the connection it arrived on
//! (P-025, P-028): the controller could not route an answer to it. A
//! link-local `type` from a client is dropped and answered with 257,
//! echoing the handle and the request (L-002, L-182). Neither is ever
//! handed to the link: nothing in a client's bytes reaches the state
//! machine that reads the controller UART (L-194, L-191).
//!
//! Outbound, a frame the controller sends goes to the link when its type
//! is link-local or it is a refusal of one of ours (L-181), to the open
//! connection its `session_id` names otherwise, and nowhere when no open
//! connection has that handle. A refusal carrying one of the six link
//! codes no client may see is not forwarded (L-180).

use km43::{
    CborReader, CborWriter, Conn, Envelope, ErrorBody, ErrorCode, Header, Incoming, LinkEnvelope,
    LinkErrorCode, MAX_PAYLOAD, MessageType, ReqId, SessionId,
};
use o89_link::{EncodeError, is_peer_refusal};

/// What to do with a client's frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a client frame nobody forwarded or answered is one its client waits on"]
pub enum Inbound {
    /// Forward this many bytes of the stamped frame to the controller.
    Forward(usize),
    /// Send this many bytes back to the client instead: a refusal of its
    /// frame, which the controller never sees.
    Answer(usize),
}

/// Where a frame from the controller goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a frame from the controller that went nowhere is one nobody decided to drop"]
pub enum Route {
    /// To the link, as [`Link::received`](crate::Link::received) takes it:
    /// a link-local frame, or a refusal of one of ours.
    Link,
    /// To the client on this connection, as it stands.
    Client(Conn),
    /// Nowhere: no open connection has its handle, it is no envelope, or
    /// it is a refusal no client may see.
    Nowhere,
}

/// Whether `opcode` is in the link-local range, request or response
/// (L-002).
const fn is_link_local(opcode: u8) -> bool {
    let request = opcode & 0x7F;
    0x60 <= request && request <= 0x7E
}

/// Stamp `frame`, which arrived on `conn`, into `dst` (P-021), or write the
/// refusal its client is owed there instead.
pub fn stamp(
    conn: Conn,
    frame: &[u8],
    dst: &mut [u8; MAX_PAYLOAD],
) -> Result<Inbound, EncodeError> {
    let Some(head) = Head::read(frame) else {
        // P-025: too malformed to echo anything, so 0, 0, on this
        // connection. P-028: a fifth element is refused before any is read.
        return refuse(Incoming::Client(ErrorCode::MalformedFrame), None, dst);
    };
    let echo = Header {
        kind: MessageType::ErrorResponse,
        session: SessionId::from(conn.get()),
        req_id: head.req_id,
    };
    if is_link_local(head.opcode) {
        // L-002: dropped here and answered, never forwarded.
        return refuse(
            Incoming::LinkLocal(LinkErrorCode::LinkTypeOnClientTransport),
            Some(echo),
            dst,
        );
    }
    let mut cbor = CborWriter::new(dst);
    let written = cbor
        .array(4)
        .and_then(|()| cbor.raw(head.opcode_item))
        .and_then(|()| cbor.u64(u64::from(conn.get())))
        .and_then(|()| cbor.raw(head.req_item))
        .and_then(|()| cbor.raw(head.body))
        .and_then(|()| cbor.finish());
    match written {
        Ok(len) => Ok(Inbound::Forward(len)),
        // The handle took more bytes than the client's 0: an envelope at
        // the limit no longer fits it.
        Err(_) => refuse(
            Incoming::Client(ErrorCode::PayloadTooLarge),
            Some(echo),
            dst,
        ),
    }
}

/// The four elements of a client's envelope, as they arrived.
struct Head<'a> {
    opcode: u8,
    opcode_item: &'a [u8],
    req_id: ReqId,
    req_item: &'a [u8],
    body: &'a [u8],
}

impl<'a> Head<'a> {
    /// `None` for anything but exactly four elements that read: a type, a
    /// `u16` session, a `u32` request and a map, and nothing after them.
    fn read(frame: &'a [u8]) -> Option<Self> {
        if frame.len() > MAX_PAYLOAD {
            return None;
        }
        let mut cbor = CborReader::new(frame);
        if cbor.array().ok()? != 4 {
            return None;
        }
        let opcode_item = cbor.raw().ok()?;
        let opcode = CborReader::new(opcode_item).u8().ok()?;
        // Read to prove it is a session id, then written over.
        let _session = cbor.u16().ok()?;
        let req_item = cbor.raw().ok()?;
        let req_id = ReqId(CborReader::new(req_item).u32().ok()?);
        let body = cbor.raw().ok()?;
        CborReader::new(body).map().ok()?;
        cbor.finish().ok()?;
        Some(Self {
            opcode,
            opcode_item,
            req_id,
            req_item,
            body,
        })
    }
}

/// An `Error` for the client, echoing `header` when its envelope read and
/// 0, 0 when it did not (L-182).
fn refuse(
    code: Incoming,
    header: Option<Header>,
    dst: &mut [u8; MAX_PAYLOAD],
) -> Result<Inbound, EncodeError> {
    let header = header.unwrap_or(Header {
        kind: MessageType::ErrorResponse,
        session: SessionId::None,
        req_id: ReqId(0),
    });
    ErrorBody { code, detail: "" }
        .write(header, dst)
        .map(Inbound::Answer)
        .map_err(|_| EncodeError::Body)
}

/// Where `frame`, from the controller, goes, given the connection a handle
/// opens onto.
pub fn route(frame: &[u8], open: impl Fn(u16) -> Option<Conn>) -> Route {
    let Ok(envelope) = LinkEnvelope::decode(frame) else {
        return Route::Nowhere;
    };
    if is_link_local(envelope.opcode()) || is_peer_refusal(&envelope) {
        return Route::Link;
    }
    let Some(conn) = open(u16::from(envelope.session())) else {
        return Route::Nowhere;
    };
    if envelope.opcode() == MessageType::ErrorResponse as u8
        && let Ok(client) = Envelope::decode(frame)
        && let Ok(hint) = ErrorBody::from_envelope(client)
        && let Incoming::LinkLocal(code) = hint.code()
        && !code.reaches_a_client()
    {
        // L-180: one of the six codes about the two firmwares.
        return Route::Nowhere;
    }
    Route::Client(conn)
}

#[cfg(test)]
mod tests {
    use km43::{CloseConnections, CloseReason, Hint, LinkHeader, LinkMessageType};

    use super::*;

    const HANDLE: u16 = 0x0102;

    fn conn(handle: u16) -> Conn {
        Conn::new(handle).expect("a handle")
    }

    /// A client's `kind` with `session` and request 7, and one body key.
    fn client_frame(kind: MessageType, session: u16, out: &mut [u8; MAX_PAYLOAD]) -> usize {
        let mut cbor = Header {
            kind,
            session: SessionId::from(session),
            req_id: ReqId(7),
        }
        .write(1, out)
        .expect("fits");
        cbor.key(1).expect("fits");
        cbor.text("opaque").expect("fits");
        cbor.finish().expect("fits")
    }

    fn hint_of(frame: &[u8]) -> (Header, Incoming) {
        let envelope = Envelope::decode(frame).expect("an envelope");
        let header = envelope.header();
        let hint: Hint<'_> = ErrorBody::from_envelope(envelope).expect("an error");
        (header, hint.code())
    }

    #[test]
    fn p_021_every_client_frame_carries_its_handle_and_its_body_unchanged() {
        for session in [0, 1, HANDLE, 0xFFFF] {
            let mut frame = [0u8; MAX_PAYLOAD];
            let len = client_frame(MessageType::Discover, session, &mut frame);
            let mut out = [0u8; MAX_PAYLOAD];
            let Ok(Inbound::Forward(stamped)) = stamp(conn(HANDLE), &frame[..len], &mut out) else {
                panic!("forwarded");
            };
            let envelope = Envelope::decode(&out[..stamped]).expect("an envelope");
            assert_eq!(
                envelope.header(),
                Header {
                    kind: MessageType::Discover,
                    session: SessionId::from(HANDLE),
                    req_id: ReqId(7),
                },
                "from session {session}"
            );
            let mut body = envelope.into_body();
            assert_eq!(body.key(), Ok(1));
            assert_eq!(body.text(), Ok("opaque"));
            assert_eq!(body.finish(), Ok(()));
        }
    }

    #[test]
    fn p_021_a_client_refusal_shaped_like_a_link_refusal_is_stamped_as_the_clients() {
        // An `Error` on 0, 0 from the controller would be the link's; from a
        // client it leaves carrying the client's handle, and the controller
        // reads it as the client's own (L-181).
        let mut frame = [0u8; MAX_PAYLOAD];
        let len = ErrorBody {
            code: Incoming::LinkLocal(LinkErrorCode::WrongSide),
            detail: "",
        }
        .write(
            Header {
                kind: MessageType::ErrorResponse,
                session: SessionId::None,
                req_id: ReqId(0),
            },
            &mut frame,
        )
        .expect("fits");
        let mut out = [0u8; MAX_PAYLOAD];
        let Ok(Inbound::Forward(stamped)) = stamp(conn(3), &frame[..len], &mut out) else {
            panic!("forwarded");
        };
        let envelope = LinkEnvelope::decode(&out[..stamped]).expect("an envelope");
        assert_eq!(envelope.session(), SessionId::from(3));
        assert!(!is_peer_refusal(&envelope));
    }

    #[test]
    fn p_025_a_frame_that_does_not_parse_is_answered_with_zero_zero() {
        let unreadable: [&[u8]; 6] = [
            &[],
            &[0xFF],
            // Not an array.
            &[0xA0],
            // A session wider than a u16.
            &[0x84, 0x00, 0x1A, 0x00, 0x01, 0x00, 0x00, 0x07, 0xA0],
            // Four elements, the fourth no map.
            &[0x84, 0x00, 0x00, 0x07, 0x01],
            // Bytes after the envelope.
            &[0x84, 0x00, 0x00, 0x07, 0xA0, 0x00],
        ];
        for frame in unreadable {
            let mut out = [0u8; MAX_PAYLOAD];
            let Ok(Inbound::Answer(len)) = stamp(conn(HANDLE), frame, &mut out) else {
                panic!("{frame:02x?} answered");
            };
            let (header, code) = hint_of(&out[..len]);
            assert_eq!(header.session, SessionId::None, "{frame:02x?}");
            assert_eq!(header.req_id, ReqId(0), "{frame:02x?}");
            assert_eq!(code, Incoming::Client(ErrorCode::MalformedFrame));
        }
    }

    #[test]
    fn p_028_a_five_element_envelope_is_refused_with_error_1_before_any_is_read() {
        // A fifth element, with a first element that would read as a
        // link-local type: refused as the wrong shape, not as a type.
        let five = [0x85, 0x18, 0x60, 0x00, 0x07, 0xA0, 0x00];
        let mut out = [0u8; MAX_PAYLOAD];
        let Ok(Inbound::Answer(len)) = stamp(conn(HANDLE), &five, &mut out) else {
            panic!("answered");
        };
        let (header, code) = hint_of(&out[..len]);
        assert_eq!((header.session, header.req_id), (SessionId::None, ReqId(0)));
        assert_eq!(code, Incoming::Client(ErrorCode::MalformedFrame));
    }

    #[test]
    fn l_002_a_link_local_type_from_a_client_is_answered_257_and_never_forwarded() {
        for kind in [
            LinkMessageType::PairingWindow,
            LinkMessageType::EnterDownload,
            LinkMessageType::ClientConnected,
            LinkMessageType::HeartbeatAck,
        ] {
            let mut frame = [0u8; MAX_PAYLOAD];
            let len = CloseConnections {
                conn: 0,
                reason: CloseReason::Resync,
            }
            .write(
                LinkHeader {
                    kind,
                    session: SessionId::None,
                    req_id: ReqId(9),
                },
                &mut frame,
            )
            .expect("fits");
            let mut out = [0u8; MAX_PAYLOAD];
            let Ok(Inbound::Answer(answer)) = stamp(conn(HANDLE), &frame[..len], &mut out) else {
                panic!("{kind:?} answered here");
            };
            let (header, code) = hint_of(&out[..answer]);
            // L-182: its envelope parsed, so the handle and request are echoed.
            assert_eq!(header.session, SessionId::from(HANDLE), "{kind:?}");
            assert_eq!(header.req_id, ReqId(9), "{kind:?}");
            assert_eq!(
                code,
                Incoming::LinkLocal(LinkErrorCode::LinkTypeOnClientTransport)
            );
        }
    }

    #[test]
    fn an_envelope_the_handle_no_longer_fits_is_refused_as_too_large() {
        // A client envelope at the limit with session 0: the handle takes
        // two more bytes than the 0 did.
        let mut frame = [0u8; MAX_PAYLOAD];
        let mut cbor = Header {
            kind: MessageType::Discover,
            session: SessionId::None,
            req_id: ReqId(7),
        }
        .write(1, &mut frame)
        .expect("fits");
        cbor.key(1).expect("fits");
        // Head 5 bytes, key 1, byte-string head 3: the rest is the string.
        cbor.bytes(&[0u8; MAX_PAYLOAD - 9]).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(len, MAX_PAYLOAD);
        let mut out = [0u8; MAX_PAYLOAD];
        let Ok(Inbound::Answer(answer)) = stamp(conn(HANDLE), &frame[..len], &mut out) else {
            panic!("answered");
        };
        let (header, code) = hint_of(&out[..answer]);
        assert_eq!(header.session, SessionId::from(HANDLE));
        assert_eq!(code, Incoming::Client(ErrorCode::PayloadTooLarge));
        // A handle of one byte still fits the same envelope.
        let Ok(Inbound::Forward(stamped)) = stamp(conn(5), &frame[..len], &mut out) else {
            panic!("forwarded");
        };
        assert_eq!(stamped, MAX_PAYLOAD);
        // Longer than any envelope is refused before it is read.
        let long = [0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            stamp(conn(5), &long, &mut out),
            Ok(Inbound::Answer(_))
        ));
    }

    fn only(handle: u16) -> impl Fn(u16) -> Option<Conn> {
        move |session| (session == handle).then(|| conn(handle))
    }

    fn refusal(code: Incoming, session: u16, req_id: u32, out: &mut [u8; MAX_PAYLOAD]) -> usize {
        ErrorBody { code, detail: "" }
            .write(
                Header {
                    kind: MessageType::ErrorResponse,
                    session: SessionId::from(session),
                    req_id: ReqId(req_id),
                },
                out,
            )
            .expect("fits")
    }

    #[test]
    fn p_021_a_controller_frame_goes_to_the_open_connection_its_session_names() {
        let mut frame = [0u8; MAX_PAYLOAD];
        let len = client_frame(MessageType::DiscoverResponse, HANDLE, &mut frame);
        assert!(matches!(
            route(&frame[..len], only(HANDLE)),
            Route::Client(to) if to == conn(HANDLE)
        ));
        // No open connection with that handle, or no handle at all.
        assert!(matches!(route(&frame[..len], only(9)), Route::Nowhere));
        let len = client_frame(MessageType::DiscoverResponse, 0, &mut frame);
        assert!(matches!(route(&frame[..len], only(HANDLE)), Route::Nowhere));
        assert!(matches!(route(&[0x01, 0x02], only(HANDLE)), Route::Nowhere));
    }

    #[test]
    fn l_181_a_link_frame_or_a_refusal_of_ours_stays_on_the_link() {
        let mut frame = [0u8; MAX_PAYLOAD];
        let len = CloseConnections {
            conn: 0,
            reason: CloseReason::Resync,
        }
        .write(
            LinkHeader {
                kind: LinkMessageType::CloseConnection,
                session: SessionId::None,
                req_id: ReqId(3),
            },
            &mut frame,
        )
        .expect("fits");
        assert!(matches!(route(&frame[..len], only(HANDLE)), Route::Link));
        let len = refusal(
            Incoming::LinkLocal(LinkErrorCode::WrongSide),
            0,
            0,
            &mut frame,
        );
        assert!(matches!(route(&frame[..len], only(HANDLE)), Route::Link));
    }

    #[test]
    fn l_003_a_link_frame_on_a_session_goes_to_the_link_never_to_that_client() {
        let mut frame = [0u8; MAX_PAYLOAD];
        let len = CloseConnections {
            conn: 0,
            reason: CloseReason::Resync,
        }
        .write(
            LinkHeader {
                kind: LinkMessageType::CloseConnection,
                session: SessionId::from(HANDLE),
                req_id: ReqId(3),
            },
            &mut frame,
        )
        .expect("fits");
        // The link refuses it with 263 (`arriving`).
        assert!(matches!(route(&frame[..len], only(HANDLE)), Route::Link));
    }

    #[test]
    fn l_180_only_the_three_link_codes_for_a_client_reach_one() {
        let mut frame = [0u8; MAX_PAYLOAD];
        for code in [
            LinkErrorCode::LinkTypeOnClientTransport,
            LinkErrorCode::BeforeLinkUp,
            LinkErrorCode::UnknownHandle,
        ] {
            let len = refusal(Incoming::LinkLocal(code), HANDLE, 4, &mut frame);
            assert!(
                matches!(route(&frame[..len], only(HANDLE)), Route::Client(_)),
                "{code:?}"
            );
        }
        for code in [
            LinkErrorCode::WrongSide,
            LinkErrorCode::ConnectionTableFull,
            LinkErrorCode::LinkMajorMismatch,
            LinkErrorCode::TooManyOutstanding,
            LinkErrorCode::NonZeroSession,
            LinkErrorCode::NoAuthorisation,
        ] {
            let len = refusal(Incoming::LinkLocal(code), HANDLE, 4, &mut frame);
            assert!(
                matches!(route(&frame[..len], only(HANDLE)), Route::Nowhere),
                "{code:?}"
            );
        }
        // A client code is the client's.
        let len = refusal(
            Incoming::Client(ErrorCode::BusyRetry),
            HANDLE,
            4,
            &mut frame,
        );
        assert!(matches!(
            route(&frame[..len], only(HANDLE)),
            Route::Client(_)
        ));
    }
}
