//! A WebSocket as the comms processor serves one: the opening handshake,
//! the frame heads a client sends, and the frames this side writes back.
//!
//! One protocol message per binary frame (P-034). A client's frame is
//! masked, whole and binary, and holds at most one envelope: a text frame
//! is refused with 1003, a fragmented message or an unmasked frame with
//! 1002, a frame longer than any envelope with 1009, and the connection is
//! closed rather than resynchronised. Pings are answered, pongs ignored, and
//! a close is answered with a close. What the frame carries is not read
//! here: it goes to [`Link::from_client`](crate::Link::from_client) as it
//! stands.
//!
//! The handshake is RFC 6455's on KM43's path, `km43::WS_PATH`, and any
//! other request-target is answered 404 without an upgrade (P-223). Nothing
//! else it carries is decided on: no origin, no subprotocol. The client's
//! identity is proved end to end to the controller, never to this side.
//! A request longer than [`REQUEST_BYTES`] is refused, never truncated.

use core::fmt::{self, Write as _};

use km43::{MAX_PAYLOAD, WS_PATH};
use sha1::{Digest, Sha1};

use crate::Closed;

/// The longest opening handshake read. A longer one is refused.
pub const REQUEST_BYTES: usize = 1_024;

/// The handshake's answer: the status line, three headers, and the key.
pub const RESPONSE_BYTES: usize = 160;

/// The longest frame head: two bytes, an eight-byte length, a mask.
pub const HEAD_BYTES: usize = 14;

/// The longest payload a control frame may carry (RFC 6455 §5.5).
pub const CONTROL_PAYLOAD: usize = 125;

/// Close frames this side writes carry at most this much reason text.
pub const REASON_BYTES: usize = CONTROL_PAYLOAD - 2;

/// RFC 6455 §1.3.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Why an opening handshake is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused handshake is answered and closed"]
pub enum Refusal {
    /// Longer than [`REQUEST_BYTES`] before its blank line.
    TooLong,
    /// Not `GET <target> HTTP/1.1`.
    NotGet,
    /// A request-target other than `WS_PATH`, exactly (P-223).
    NotFound,
    /// No `Upgrade: websocket` or no `Connection: upgrade`.
    NotUpgrade,
    /// A version other than 13.
    Version,
    /// A key that is not sixteen bytes in base64, missing or repeated.
    Key,
}

impl Refusal {
    /// The HTTP answer: 404 a path other than KM43's, 426 names the version
    /// this side speaks, 431 a request too long, 400 anything else.
    #[must_use]
    pub const fn response(self) -> &'static [u8] {
        match self {
            Self::NotFound => b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n",
            Self::TooLong => {
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
            }
            Self::Version => {
                b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n\r\n"
            }
            Self::NotGet | Self::NotUpgrade | Self::Key => {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
            }
        }
    }
}

/// Where the request's header block ends, past its blank line: `None`
/// until the blank line has arrived.
#[must_use]
pub fn request_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|at| at.checked_add(4))
}

/// Answer an opening handshake: the `101` into `response`, and its length.
pub fn accept(request: &[u8], response: &mut [u8; RESPONSE_BYTES]) -> Result<usize, Refusal> {
    let end = request_end(request).ok_or(Refusal::TooLong)?;
    if end > REQUEST_BYTES {
        return Err(Refusal::TooLong);
    }
    let text = request
        .get(..end)
        .and_then(|head| core::str::from_utf8(head).ok())
        .ok_or(Refusal::NotGet)?;
    let mut lines = text.split("\r\n");
    let mut start = lines.next().ok_or(Refusal::NotGet)?.split(' ');
    let (Some("GET"), Some(target), Some("HTTP/1.1"), None) =
        (start.next(), start.next(), start.next(), start.next())
    else {
        return Err(Refusal::NotGet);
    };
    if target.is_empty() {
        return Err(Refusal::NotGet);
    }
    // Exactly: a trailing slash or a query is another resource (P-223).
    if target != WS_PATH {
        return Err(Refusal::NotFound);
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut version = None;
    let mut key = None;
    // Bounded by the request's own length.
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Refusal::NotGet)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= has_token(value, "websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection |= has_token(value, "upgrade");
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            version = Some(value);
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            if key.is_some() {
                return Err(Refusal::Key);
            }
            key = Some(value);
        }
    }
    if !upgrade || !connection {
        return Err(Refusal::NotUpgrade);
    }
    if version != Some("13") {
        return Err(Refusal::Version);
    }
    let key = key.filter(|key| is_key(key)).ok_or(Refusal::Key)?;
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(GUID.as_bytes());
    let digest: [u8; 20] = hash.finalize().into();
    let mut out = Text {
        bytes: response,
        len: 0,
    };
    let written = write!(
        out,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        Base64(&digest)
    );
    written.map_err(|fmt::Error| Refusal::Key)?;
    Ok(out.len)
}

/// Whether a comma-separated header value holds `token`, in any case.
fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|item| item.trim_matches([' ', '\t']).eq_ignore_ascii_case(token))
}

/// Sixteen bytes in base64: twenty-two digits and `==` (RFC 6455 §4.1).
fn is_key(key: &str) -> bool {
    key.len() == 24
        && key.ends_with("==")
        && key
            .bytes()
            .take(22)
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

struct Base64<'a>(&'a [u8]);

impl fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let digit = |index: u32| {
            DIGITS
                .get(usize::try_from(index & 0x3F).unwrap_or(0))
                .map_or('=', |digit| char::from(*digit))
        };
        for chunk in self.0.chunks(3) {
            let (bytes, kept) = match *chunk {
                [first] => ([first, 0, 0], 2),
                [first, second] => ([first, second, 0], 3),
                [first, second, third] => ([first, second, third], 4),
                _ => return Err(fmt::Error),
            };
            let [first, second, third] = bytes.map(u32::from);
            let bits = (first << 16) | (second << 8) | third;
            for (at, shift) in [18, 12, 6, 0].into_iter().enumerate() {
                f.write_char(if at < kept { digit(bits >> shift) } else { '=' })?;
            }
        }
        Ok(())
    }
}

struct Text<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl fmt::Write for Text<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// A WebSocket close code (RFC 6455 §7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// The purpose is fulfilled.
    pub const NORMAL: Self = Self(1000);
    /// A frame that breaks the protocol.
    pub const PROTOCOL: Self = Self(1002);
    /// A kind of data this side does not take: text.
    pub const UNSUPPORTED: Self = Self(1003);
    /// Against policy.
    pub const POLICY: Self = Self(1008);
    /// Too big to take.
    pub const TOO_BIG: Self = Self(1009);
    /// Something failed on this side.
    pub const INTERNAL: Self = Self(1011);
    /// Restarting: reconnect.
    pub const RESTART: Self = Self(1012);
    /// Overloaded or unavailable for now: try again later.
    pub const TRY_AGAIN: Self = Self(1013);
}

/// Why this side closes a WebSocket, as a client can show it (L-061).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Goodbye {
    /// The table closed it.
    Table(Closed),
    /// No row for it: the link is down or every row is taken.
    Refused(crate::Refused),
    /// Its frame broke the protocol.
    Violation(Violation),
    /// The client closed first; its close is answered.
    Answered,
}

impl Goodbye {
    /// The code and the reason text.
    #[must_use]
    pub const fn close(self) -> (CloseCode, &'static str) {
        match self {
            Self::Table(Closed::TableFull) => {
                (CloseCode::TRY_AGAIN, "controller connection table full")
            }
            Self::Table(Closed::HandleInUse) => (CloseCode::TRY_AGAIN, "connection handle in use"),
            Self::Table(Closed::ControllerNotLinked) | Self::Refused(crate::Refused::NotLinked) => {
                (CloseCode::TRY_AGAIN, "controller link not up")
            }
            Self::Table(Closed::Unanswered) => (CloseCode::INTERNAL, "controller did not answer"),
            Self::Table(Closed::ByController(reason)) => match reason {
                km43::CloseReason::SessionExpired => (CloseCode::NORMAL, "session expired"),
                km43::CloseReason::Shedding => (CloseCode::TRY_AGAIN, "controller shedding load"),
                km43::CloseReason::AuthenticationFailures => {
                    (CloseCode::POLICY, "too many authentication failures")
                }
                km43::CloseReason::Resync => (CloseCode::RESTART, "connections resynchronised"),
            },
            Self::Table(Closed::LinkLost) => (CloseCode::TRY_AGAIN, "controller link lost"),
            Self::Table(Closed::Overrun) => (CloseCode::POLICY, "client too slow"),
            Self::Refused(crate::Refused::TableFull) => {
                (CloseCode::TRY_AGAIN, "connection table full")
            }
            Self::Violation(Violation::Text) => (CloseCode::UNSUPPORTED, "binary frames only"),
            Self::Violation(Violation::TooBig) => (CloseCode::TOO_BIG, "frame over one message"),
            Self::Violation(Violation::Protocol) => (CloseCode::PROTOCOL, "protocol error"),
            Self::Answered => (CloseCode::NORMAL, ""),
        }
    }
}

/// A client frame this side refuses, closing the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A text frame: protocol messages are binary (P-034).
    Text,
    /// Longer than one envelope (P-034).
    TooBig,
    /// Unmasked, reserved bits or opcodes, fragmented, or a control frame
    /// too long or fragmented.
    Protocol,
}

/// What a client's frame head says the frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a frame head read and not acted on leaves the stream mid-frame"]
pub enum Incoming {
    /// One protocol message, this long (P-034).
    Message(usize),
    /// A ping with this much payload, to answer with a pong.
    Ping(usize),
    /// A pong with this much payload, to read and ignore.
    Pong(usize),
    /// A close with this much payload, to read and answer.
    Close(usize),
}

/// A client frame's head, once whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// What it is and how long.
    pub incoming: Incoming,
    /// Its mask, to [`unmask`] the payload with.
    pub mask: [u8; 4],
}

/// How long the head that starts with `first` is: two bytes, then 2 or 8
/// for a longer length, then the mask's 4.
#[must_use]
pub const fn head_len(first: [u8; 2]) -> usize {
    let [_, second] = first;
    match second & 0x7F {
        126 => 8,
        127 => HEAD_BYTES,
        _ => 6,
    }
}

/// Read a client frame's head: `head` is exactly [`head_len`] bytes.
pub fn read_head(head: &[u8]) -> Result<Head, Violation> {
    let (&[first, second], rest) = head.split_first_chunk::<2>().ok_or(Violation::Protocol)?;
    let fin = first & 0x80 != 0;
    if first & 0x70 != 0 || second & 0x80 == 0 {
        // Reserved bits with no extension agreed, or a frame the client
        // did not mask (RFC 6455 §5.1).
        return Err(Violation::Protocol);
    }
    let (len, rest) = match second & 0x7F {
        126 => {
            let (bytes, rest) = rest.split_first_chunk::<2>().ok_or(Violation::Protocol)?;
            (u64::from(u16::from_be_bytes(*bytes)), rest)
        }
        127 => {
            let (bytes, rest) = rest.split_first_chunk::<8>().ok_or(Violation::Protocol)?;
            (u64::from_be_bytes(*bytes), rest)
        }
        short => (u64::from(short), rest),
    };
    let mask: [u8; 4] = rest.try_into().map_err(|_| Violation::Protocol)?;
    let len = usize::try_from(len).map_err(|_| Violation::TooBig)?;
    let control = |make: fn(usize) -> Incoming| {
        if fin && len <= CONTROL_PAYLOAD {
            Ok(make(len))
        } else {
            Err(Violation::Protocol)
        }
    };
    let incoming = match first & 0x0F {
        0x1 => return Err(Violation::Text),
        0x2 if fin && len <= MAX_PAYLOAD => Incoming::Message(len),
        0x2 if fin => return Err(Violation::TooBig),
        0x8 => control(Incoming::Close)?,
        0x9 => control(Incoming::Ping)?,
        0xA => control(Incoming::Pong)?,
        // A continuation or an unfinished binary frame is a message in
        // pieces (P-034); the rest are reserved.
        _ => return Err(Violation::Protocol),
    };
    Ok(Head { incoming, mask })
}

/// Undo a client's mask in place.
pub fn unmask(mask: [u8; 4], payload: &mut [u8]) {
    for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
        *byte ^= key;
    }
}

/// What this side writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outgoing {
    /// One protocol message (P-034).
    Binary,
    /// A pong.
    Pong,
    /// A close.
    Close,
}

/// The head of a frame this side writes, unmasked as a server's are, for a
/// payload of `len`; its length. A control frame over 125 bytes, or a
/// message over one envelope, is refused.
pub fn write_head(
    kind: Outgoing,
    len: usize,
    head: &mut [u8; HEAD_BYTES],
) -> Result<usize, Violation> {
    let (opcode, limit) = match kind {
        Outgoing::Binary => (0x2, MAX_PAYLOAD),
        Outgoing::Pong => (0xA, CONTROL_PAYLOAD),
        Outgoing::Close => (0x8, CONTROL_PAYLOAD),
    };
    if len > limit {
        return Err(Violation::TooBig);
    }
    let [first, second, rest @ ..] = head;
    *first = 0x80 | opcode;
    if let Ok(short @ 0..=125) = u8::try_from(len) {
        *second = short;
        return Ok(2);
    }
    let wide = u16::try_from(len).map_err(|_| Violation::TooBig)?;
    *second = 126;
    rest.get_mut(..2)
        .ok_or(Violation::TooBig)?
        .copy_from_slice(&wide.to_be_bytes());
    Ok(4)
}

/// A close frame's payload: the code, then the reason cut to
/// [`REASON_BYTES`] at a character boundary. Its length.
#[must_use]
pub fn close_payload(goodbye: Goodbye, payload: &mut [u8; CONTROL_PAYLOAD]) -> usize {
    let (code, reason) = goodbye.close();
    let [high, low, rest @ ..] = payload;
    [*high, *low] = code.0.to_be_bytes();
    let mut cut = reason.len().min(REASON_BYTES);
    // Bounded by the reason's length.
    while !reason.is_char_boundary(cut) {
        cut = cut.saturating_sub(1);
    }
    let text = reason.as_bytes().get(..cut).unwrap_or(&[]);
    if let Some(dst) = rest.get_mut(..text.len()) {
        dst.copy_from_slice(text);
    }
    text.len().saturating_add(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_REQUEST: &[u8] = b"GET /km43 HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: http://example.com\r\nSec-WebSocket-Version: 13\r\n\r\n";

    fn accepted(request: &[u8]) -> Result<[u8; RESPONSE_BYTES], Refusal> {
        let mut response = [0u8; RESPONSE_BYTES];
        let len = accept(request, &mut response)?;
        assert!(len <= RESPONSE_BYTES);
        Ok(response)
    }

    fn text(response: &[u8; RESPONSE_BYTES]) -> &str {
        let end = request_end(response).expect("a whole response");
        core::str::from_utf8(&response[..end]).expect("text")
    }

    #[test]
    fn the_rfc_handshake_is_answered_with_its_accept_key() {
        let response = accepted(RFC_REQUEST).expect("accepted");
        assert_eq!(
            text(&response),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        );
    }

    #[test]
    fn a_handshake_reads_its_headers_in_any_case_and_among_other_tokens() {
        let request = b"GET /km43 HTTP/1.1\r\nconnection: keep-alive, Upgrade\r\nUPGRADE: WebSocket\r\nsec-websocket-key:  dGhlIHNhbXBsZSBub25jZQ==\t\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert!(accepted(request).is_ok());
    }

    #[test]
    fn a_handshake_that_is_not_an_upgrade_is_refused_with_its_reason() {
        let cases: [(&[u8], Refusal); 8] = [
            (b"POST /km43 HTTP/1.1\r\n\r\n", Refusal::NotGet),
            (b"GET /km43 HTTP/1.0\r\nUpgrade: websocket\r\n\r\n", Refusal::NotGet),
            (b"GET /km43 HTTP/1.1 extra\r\n\r\n", Refusal::NotGet),
            (
                b"GET /km43 HTTP/1.1\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                Refusal::NotUpgrade,
            ),
            (
                b"GET /km43 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                Refusal::Version,
            ),
            (
                b"GET /km43 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n",
                Refusal::Key,
            ),
            (
                b"GET /km43 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: short==\r\n\r\n",
                Refusal::Key,
            ),
            (
                b"GET /km43 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                Refusal::Key,
            ),
        ];
        for (request, refusal) in cases {
            assert_eq!(
                accepted(request).err(),
                Some(refusal),
                "{}",
                core::str::from_utf8(request).unwrap_or("")
            );
        }
    }

    /// RFC 6455's example request with its target replaced.
    fn to(target: &str) -> ([u8; 256], usize) {
        let mut out = [0u8; 256];
        let rest = RFC_REQUEST.strip_prefix(b"GET /km43").expect("the example");
        let bytes = b"GET ".iter().chain(target.as_bytes()).chain(rest);
        let len = out
            .iter_mut()
            .zip(bytes)
            .map(|(at, byte)| *at = *byte)
            .count();
        (out, len)
    }

    #[test]
    fn p_223_the_upgrade_is_on_km43s_path_and_nowhere_else() {
        assert_eq!(WS_PATH, "/km43");
        let (request, len) = to(WS_PATH);
        assert!(accepted(&request[..len]).is_ok());
        for other in ["/", "/km43/", "/km43?x=1", "/KM43", "/km4", "/km43/x", "*"] {
            let (request, len) = to(other);
            assert_eq!(
                accepted(&request[..len]).err(),
                Some(Refusal::NotFound),
                "{other}"
            );
        }
        assert_eq!(
            Refusal::NotFound.response(),
            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn p_223_a_request_that_is_not_a_get_is_refused_before_its_path() {
        // The 404 is for a GET to another resource; a malformed start line
        // is a bad request wherever it points.
        for request in [
            b"POST /other HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /other HTTP/1.0\r\n\r\n",
            b"GET  HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(accepted(request).err(), Some(Refusal::NotGet));
        }
    }

    #[test]
    fn a_handshake_past_its_bound_is_refused_not_truncated() {
        // No blank line within the bound.
        let mut long = [b'a'; REQUEST_BYTES + 8];
        long[..4].copy_from_slice(b"GET ");
        assert_eq!(accepted(&long).err(), Some(Refusal::TooLong));
        // A blank line only past the bound.
        let mut late = [b'x'; REQUEST_BYTES + 4];
        late[REQUEST_BYTES..].copy_from_slice(b"\r\n\r\n");
        assert_eq!(accepted(&late).err(), Some(Refusal::TooLong));
        assert_eq!(request_end(b"GET / HTTP/1.1\r\n"), None);
        assert!(Refusal::Version.response().starts_with(b"HTTP/1.1 426"));
        assert!(Refusal::TooLong.response().starts_with(b"HTTP/1.1 431"));
    }

    /// A client's head for `opcode` and `len`, masked, as bytes.
    fn head(fin: bool, opcode: u8, len: usize) -> ([u8; HEAD_BYTES], usize) {
        let mut out = [0u8; HEAD_BYTES];
        out[0] = (u8::from(fin) << 7) | opcode;
        let total = if let Ok(short @ 0..=125) = u8::try_from(len) {
            out[1] = 0x80 | short;
            out[2..6].copy_from_slice(&[1, 2, 3, 4]);
            6
        } else if let Ok(wide) = u16::try_from(len) {
            out[1] = 0xFE;
            out[2..4].copy_from_slice(&wide.to_be_bytes());
            out[4..8].copy_from_slice(&[1, 2, 3, 4]);
            8
        } else {
            out[1] = 0xFF;
            out[2..10].copy_from_slice(&u64::try_from(len).expect("fits").to_be_bytes());
            out[10..14].copy_from_slice(&[1, 2, 3, 4]);
            14
        };
        assert_eq!(head_len([out[0], out[1]]), total);
        (out, total)
    }

    #[test]
    fn p_034_one_whole_binary_frame_is_one_message() {
        for len in [0, 1, 125, 126, MAX_PAYLOAD] {
            let (bytes, n) = head(true, 0x2, len);
            assert_eq!(
                read_head(&bytes[..n]),
                Ok(Head {
                    incoming: Incoming::Message(len),
                    mask: [1, 2, 3, 4]
                })
            );
        }
    }

    #[test]
    fn p_034_a_message_in_pieces_text_or_over_one_envelope_is_refused() {
        let cases = [
            (head(false, 0x2, 10), Violation::Protocol),
            (head(true, 0x0, 10), Violation::Protocol),
            (head(true, 0x1, 10), Violation::Text),
            (head(true, 0x2, MAX_PAYLOAD + 1), Violation::TooBig),
            (head(true, 0x2, 1 << 40), Violation::TooBig),
            (head(true, 0x3, 1), Violation::Protocol),
            (head(false, 0x9, 1), Violation::Protocol),
            (head(true, 0x9, 126), Violation::Protocol),
        ];
        for ((bytes, n), violation) in cases {
            assert_eq!(
                read_head(&bytes[..n]),
                Err(violation),
                "{:02x?}",
                &bytes[..n]
            );
        }
    }

    #[test]
    fn an_unmasked_or_extended_frame_is_a_protocol_error() {
        // The head as `head_len` reads it, whatever the mask bit says.
        let (mut bytes, n) = head(true, 0x2, 3);
        bytes[1] &= 0x7F;
        assert_eq!(read_head(&bytes[..n]), Err(Violation::Protocol));
        let (mut bytes, n) = head(true, 0x2, 3);
        bytes[0] |= 0x40;
        assert_eq!(read_head(&bytes[..n]), Err(Violation::Protocol));
        assert_eq!(read_head(&bytes[..1]), Err(Violation::Protocol));
    }

    #[test]
    fn control_frames_are_read_for_their_answer() {
        for (opcode, incoming) in [
            (0x8, Incoming::Close(2)),
            (0x9, Incoming::Ping(2)),
            (0xA, Incoming::Pong(2)),
        ] {
            let (bytes, n) = head(true, opcode, 2);
            assert_eq!(
                read_head(&bytes[..n]).map(|head| head.incoming),
                Ok(incoming)
            );
        }
    }

    #[test]
    fn a_payload_is_unmasked_in_place() {
        let mut payload = [0x85, 0x02, 0x03, 0x05, 0xA1];
        unmask([1, 2, 3, 4], &mut payload);
        assert_eq!(payload, [0x84, 0x00, 0x00, 0x01, 0xA0]);
    }

    #[test]
    fn frames_this_side_writes_are_unmasked_and_bounded() {
        let mut out = [0u8; HEAD_BYTES];
        assert_eq!(write_head(Outgoing::Binary, 5, &mut out), Ok(2));
        assert_eq!(out[..2], [0x82, 5]);
        assert_eq!(write_head(Outgoing::Binary, MAX_PAYLOAD, &mut out), Ok(4));
        assert_eq!(out[..4], [0x82, 126, 0x04, 0x00]);
        assert_eq!(
            write_head(Outgoing::Binary, MAX_PAYLOAD + 1, &mut out),
            Err(Violation::TooBig)
        );
        assert_eq!(write_head(Outgoing::Pong, 125, &mut out), Ok(2));
        assert_eq!(out[..2], [0x8A, 125]);
        assert_eq!(
            write_head(Outgoing::Close, 126, &mut out),
            Err(Violation::TooBig)
        );
    }

    #[test]
    fn l_061_a_closed_connection_says_why_in_a_close_a_client_can_show() {
        let mut payload = [0u8; CONTROL_PAYLOAD];
        let len = close_payload(Goodbye::Table(Closed::TableFull), &mut payload);
        assert_eq!(&payload[..2], &1013u16.to_be_bytes());
        assert_eq!(&payload[2..len], b"controller connection table full");
        let len = close_payload(Goodbye::Refused(crate::Refused::TableFull), &mut payload);
        assert_eq!(&payload[2..len], b"connection table full");
        let len = close_payload(Goodbye::Answered, &mut payload);
        assert_eq!((len, &payload[..2]), (2, &1000u16.to_be_bytes()[..]));
        // Every reason fits a close frame.
        for goodbye in [
            Goodbye::Table(Closed::HandleInUse),
            Goodbye::Table(Closed::ControllerNotLinked),
            Goodbye::Table(Closed::Unanswered),
            Goodbye::Table(Closed::LinkLost),
            Goodbye::Table(Closed::Overrun),
            Goodbye::Table(Closed::ByController(km43::CloseReason::Resync)),
            Goodbye::Table(Closed::ByController(km43::CloseReason::SessionExpired)),
            Goodbye::Table(Closed::ByController(km43::CloseReason::Shedding)),
            Goodbye::Table(Closed::ByController(
                km43::CloseReason::AuthenticationFailures,
            )),
            Goodbye::Refused(crate::Refused::NotLinked),
            Goodbye::Violation(Violation::Text),
            Goodbye::Violation(Violation::TooBig),
            Goodbye::Violation(Violation::Protocol),
        ] {
            let (_, reason) = goodbye.close();
            assert!(
                !reason.is_empty() && reason.len() <= REASON_BYTES,
                "{goodbye:?}"
            );
        }
    }
}
