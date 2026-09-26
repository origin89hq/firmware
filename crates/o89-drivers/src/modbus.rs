//! Modbus RTU: a register read, the reply it gets, and every way the reply
//! can be wrong.
//!
//! The board's RS-485 transceivers are auto-direction with the receiver
//! always on, so the first bytes after a request are the request itself.
//! [`read`] requires them, byte for byte, and discards them before the reply
//! is parsed (F-050); a frame heard back different from the one sent is a
//! collision on the bus and is refused rather than parsed around.
//!
//! Every wait has a deadline: [`Timing::response`] for the device to start
//! answering, [`Timing::gap`] for each burst after that. The receive loop
//! runs at most once per byte of its buffer, because every burst is at least
//! a byte, and each receive waits at most `response` until the reply begins
//! and `gap` after: a device dribbling bytes holds the bus for a bounded
//! time that a bus task's check-in period has to cover.
//!
//! cites: F-050

use crc::{CRC_16_MODBUS, Crc};
use o89_core::Millis;

use crate::port::{PortFault, Rs485};

/// The CRC every RTU frame ends with, sent low byte first.
const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_MODBUS);

/// The bytes of a read request: address, function, start, count, CRC.
pub const REQUEST_BYTES: usize = 8;
/// The largest RTU frame the specification allows.
pub const FRAME_BYTES: usize = 256;
/// What [`read`] receives into: the echo of the request, then a reply.
pub const RECEIVE_BYTES: usize = REQUEST_BYTES + FRAME_BYTES;
/// The most registers one read may ask for (Modbus application protocol
/// v1.1b3, §6.3 and §6.4).
pub const MAX_REGISTERS: u16 = 125;

/// The bytes of an exception reply: address, function, code, CRC.
const EXCEPTION_BYTES: usize = 5;
/// The bytes around a register reply's data: address, function, byte count
/// and CRC.
const REPLY_OVERHEAD: usize = 5;
/// The bit a server sets in the function code of an exception reply.
const EXCEPTION_BIT: u8 = 0x80;

/// A server address on the bus, 1 to 247. Zero is broadcast, which is never
/// answered and so never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Address(u8);

impl Address {
    /// `address`, or `None` for broadcast and the reserved range.
    #[must_use]
    pub const fn new(address: u8) -> Option<Self> {
        match address {
            1..=247 => Some(Self(address)),
            _ => None,
        }
    }

    /// The byte on the wire.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Which register space a read asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Function {
    /// `0x03`, read holding registers.
    ReadHolding,
    /// `0x04`, read input registers.
    ReadInput,
}

impl Function {
    /// The function code on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ReadHolding => 0x03,
            Self::ReadInput => 0x04,
        }
    }
}

/// A register read: `count` registers from `start` on the server at
/// `address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Read {
    address: Address,
    function: Function,
    start: u16,
    count: u16,
}

impl Read {
    /// A read, or `None` when `count` is zero, above [`MAX_REGISTERS`], or
    /// runs past register `0xFFFF`.
    #[must_use]
    pub const fn new(address: Address, function: Function, start: u16, count: u16) -> Option<Self> {
        if count == 0 || count > MAX_REGISTERS {
            return None;
        }
        if start.checked_add(count.saturating_sub(1)).is_none() {
            return None;
        }
        Some(Self {
            address,
            function,
            start,
            count,
        })
    }

    /// A read whose count and range a checked [`crate::dialect::Block`]
    /// has already held to what [`Read::new`] requires.
    pub(crate) const fn checked(
        address: Address,
        function: Function,
        start: u16,
        count: u16,
    ) -> Self {
        Self {
            address,
            function,
            start,
            count,
        }
    }

    /// The server it asks.
    #[must_use]
    pub const fn address(self) -> Address {
        self.address
    }

    /// The register space.
    #[must_use]
    pub const fn function(self) -> Function {
        self.function
    }

    /// The first register.
    #[must_use]
    pub const fn start(self) -> u16 {
        self.start
    }

    /// How many registers.
    #[must_use]
    pub const fn count(self) -> u16 {
        self.count
    }

    /// The request frame, CRC included.
    #[must_use]
    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let [start_hi, start_lo] = self.start.to_be_bytes();
        let [count_hi, count_lo] = self.count.to_be_bytes();
        let body = [
            self.address.get(),
            self.function.code(),
            start_hi,
            start_lo,
            count_hi,
            count_lo,
        ];
        let [crc_lo, crc_hi] = CRC16.checksum(&body).to_le_bytes();
        let [a, f, sh, sl, ch, cl] = body;
        [a, f, sh, sl, ch, cl, crc_lo, crc_hi]
    }

    /// The data bytes of the reply this read expects when it is not an
    /// exception: two per register, at most 250.
    fn data_bytes(self) -> usize {
        usize::from(self.count).saturating_mul(2)
    }
}

/// Why a server refused a request, from the exception reply's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Exception {
    /// `0x01`: the server does not implement the function.
    IllegalFunction,
    /// `0x02`: a register in the range does not exist on this server.
    IllegalDataAddress,
    /// `0x03`: a value in the request is not allowed.
    IllegalDataValue,
    /// `0x04`: the server failed while serving the request.
    ServerDeviceFailure,
    /// `0x05`: accepted, and it will take a while.
    Acknowledge,
    /// `0x06`: busy with a long command.
    ServerDeviceBusy,
    /// `0x08`: the server's memory failed a parity check.
    MemoryParityError,
    /// `0x0A`: a gateway could not route the request.
    GatewayPathUnavailable,
    /// `0x0B`: a gateway's target did not answer.
    GatewayTargetFailedToRespond,
    /// A code the specification does not allocate, carried as itself.
    Unallocated(u8),
}

impl Exception {
    /// The exception a code names.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::IllegalFunction,
            0x02 => Self::IllegalDataAddress,
            0x03 => Self::IllegalDataValue,
            0x04 => Self::ServerDeviceFailure,
            0x05 => Self::Acknowledge,
            0x06 => Self::ServerDeviceBusy,
            0x08 => Self::MemoryParityError,
            0x0A => Self::GatewayPathUnavailable,
            0x0B => Self::GatewayTargetFailedToRespond,
            other => Self::Unallocated(other),
        }
    }
}

/// Why a reply was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused reply is a device whose values were not read"]
pub enum ReplyError {
    /// Fewer bytes than the reply's own header says it has.
    Short,
    /// More bytes than the reply's own header says it has.
    Overlong,
    /// The CRC does not match.
    Crc,
    /// A server other than the one asked answered.
    WrongAddress(u8),
    /// A function other than the one asked came back.
    WrongFunction(u8),
    /// The byte count is not two per register asked for.
    ByteCount(u8),
    /// The server answered with an exception.
    Exception(Exception),
}

/// Why a read produced no registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed read is a device whose values were not read"]
pub enum ModbusError<E> {
    /// No reply began before [`Timing::response`].
    Timeout,
    /// The frame heard back is not the frame sent: missing, cut short, or
    /// different, which is two speakers on the bus at once (F-050).
    Echo,
    /// The reply arrived and was refused.
    Reply(ReplyError),
    /// The port reported an error while sending or receiving.
    Port(E),
}

/// How long a read waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timing {
    /// For the echo and then the first byte of the reply.
    pub response: Millis,
    /// For each burst once the reply has begun.
    pub gap: Millis,
}

/// A reply's registers, in the order asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers<'a> {
    start: u16,
    data: &'a [u8],
}

impl Registers<'_> {
    /// The first register's address.
    #[must_use]
    pub const fn start(&self) -> u16 {
        self.start
    }

    /// How many registers there are.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len() / 2
    }

    /// Whether there are none. A parsed reply always has at least one.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The register at `address`, or `None` outside the reply.
    #[must_use]
    pub fn at(&self, address: u16) -> Option<u16> {
        let index = usize::from(address.checked_sub(self.start)?);
        let at = index.checked_mul(2)?;
        match self.data.get(at..at.checked_add(2)?)? {
            [hi, lo] => Some(u16::from_be_bytes([*hi, *lo])),
            _ => None,
        }
    }
}

/// How long the reply beginning `head` says it is, once enough of it has
/// arrived to say.
fn expected(head: &[u8]) -> Option<usize> {
    match head {
        [_, function, ..] if function & EXCEPTION_BIT != 0 => Some(EXCEPTION_BYTES),
        [_, _, count, ..] => Some(REPLY_OVERHEAD.saturating_add(usize::from(*count))),
        _ => None,
    }
}

/// Parse `frame`, the bytes after the echo, as the reply to `read`.
pub fn parse<'a>(read: &Read, frame: &'a [u8]) -> Result<Registers<'a>, ReplyError> {
    let want = expected(frame).ok_or(ReplyError::Short)?;
    if frame.len() < want {
        return Err(ReplyError::Short);
    }
    if frame.len() > want {
        return Err(ReplyError::Overlong);
    }
    let body_len = want.saturating_sub(2);
    let (body, crc) = frame.split_at_checked(body_len).ok_or(ReplyError::Short)?;
    let sent = match crc {
        [lo, hi] => u16::from_le_bytes([*lo, *hi]),
        _ => return Err(ReplyError::Short),
    };
    if CRC16.checksum(body) != sent {
        return Err(ReplyError::Crc);
    }
    let [address, function, rest @ ..] = body else {
        return Err(ReplyError::Short);
    };
    if *address != read.address().get() {
        return Err(ReplyError::WrongAddress(*address));
    }
    if *function == read.function().code() | EXCEPTION_BIT {
        let [code] = rest else {
            return Err(ReplyError::Short);
        };
        return Err(ReplyError::Exception(Exception::from_code(*code)));
    }
    if *function != read.function().code() {
        return Err(ReplyError::WrongFunction(*function));
    }
    let [count, data @ ..] = rest else {
        return Err(ReplyError::Short);
    };
    if usize::from(*count) != read.data_bytes() {
        return Err(ReplyError::ByteCount(*count));
    }
    Ok(Registers {
        start: read.start(),
        data,
    })
}

/// Send `read` on `port` and return the registers it answers with.
///
/// The request's echo is required and discarded (F-050); the reply is then
/// read until its own header says it is complete, the line goes quiet, or
/// `into` is full.
pub async fn read<'a, P: Rs485>(
    port: &mut P,
    read: &Read,
    timing: Timing,
    into: &'a mut [u8; RECEIVE_BYTES],
) -> Result<Registers<'a>, ModbusError<P::Error>> {
    let request = read.encode();
    port.send(&request).await.map_err(ModbusError::Port)?;
    let mut heard = 0usize;
    // Every successful receive adds at least one byte, so this runs at most
    // once per byte of `into`.
    while heard < RECEIVE_BYTES {
        let reply_begun = heard > REQUEST_BYTES;
        let within = if reply_begun {
            timing.gap
        } else {
            timing.response
        };
        let Some(free) = into.get_mut(heard..) else {
            break;
        };
        match port.receive(free, within).await {
            Ok(0) | Err(PortFault::Timeout) => break,
            Ok(n) => heard = heard.saturating_add(n.min(free.len())),
            Err(PortFault::Line(error)) => return Err(ModbusError::Port(error)),
        }
        let Some(echo) = into.get(..heard.min(REQUEST_BYTES)) else {
            break;
        };
        if request.get(..echo.len()) != Some(echo) {
            return Err(ModbusError::Echo);
        }
        let reply = into.get(REQUEST_BYTES..heard).unwrap_or(&[]);
        if expected(reply).is_some_and(|want| reply.len() >= want) {
            break;
        }
    }
    if heard < REQUEST_BYTES {
        return Err(ModbusError::Echo);
    }
    let reply = into.get(REQUEST_BYTES..heard).unwrap_or(&[]);
    if reply.is_empty() {
        return Err(ModbusError::Timeout);
    }
    parse(read, reply).map_err(ModbusError::Reply)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;

    /// A port that plays back scripted bursts and records what was sent.
    pub(crate) struct Scripted<'a> {
        pub bursts: &'a [&'a [u8]],
        pub next: usize,
        pub sent: [u8; REQUEST_BYTES],
        pub fault: Option<u8>,
        pub waits: [Option<Millis>; 8],
    }

    impl<'a> Scripted<'a> {
        pub(crate) fn new(bursts: &'a [&'a [u8]]) -> Self {
            Self {
                bursts,
                next: 0,
                sent: [0; REQUEST_BYTES],
                fault: None,
                waits: [None; 8],
            }
        }
    }

    impl Rs485 for Scripted<'_> {
        type Error = u8;

        fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), u8>> {
            self.sent.copy_from_slice(bytes);
            ready(Ok(()))
        }

        fn receive(
            &mut self,
            into: &mut [u8],
            within: Millis,
        ) -> impl Future<Output = Result<usize, PortFault<u8>>> {
            ready(self.burst(into, within))
        }
    }

    impl Scripted<'_> {
        fn burst(&mut self, into: &mut [u8], within: Millis) -> Result<usize, PortFault<u8>> {
            if let Some(slot) = self.waits.get_mut(self.next) {
                *slot = Some(within);
            }
            if let Some(fault) = self.fault.take() {
                return Err(PortFault::Line(fault));
            }
            let Some(burst) = self.bursts.get(self.next) else {
                return Err(PortFault::Timeout);
            };
            self.next = self.next.checked_add(1).unwrap();
            let n = burst.len().min(into.len());
            into[..n].copy_from_slice(&burst[..n]);
            Ok(n)
        }
    }

    pub(crate) const TIMING: Timing = Timing {
        response: Millis::from_millis(200),
        gap: Millis::from_millis(5),
    };

    /// Frames in these tests are built by hand from the Modbus application
    /// protocol specification v1.1b3 and the RTU CRC; none is a bench
    /// capture.
    /// A register reply from `address`, built by hand: the frame and its
    /// length.
    pub(crate) fn register_reply(
        address: u8,
        function: u8,
        words: &[u16],
    ) -> ([u8; FRAME_BYTES], usize) {
        let mut frame = [0u8; FRAME_BYTES];
        let count = u8::try_from(words.len().checked_mul(2).unwrap()).unwrap();
        frame[..3].copy_from_slice(&[address, function, count]);
        for (slot, word) in frame[3..].as_chunks_mut::<2>().0.iter_mut().zip(words) {
            *slot = word.to_be_bytes();
        }
        let body = usize::from(count).checked_add(3).unwrap();
        let crc = CRC16.checksum(&frame[..body]).to_le_bytes();
        frame[body..][..2].copy_from_slice(&crc);
        (frame, body.checked_add(2).unwrap())
    }

    fn with_crc<const N: usize>(body: &[u8]) -> [u8; N] {
        let mut frame = [0; N];
        frame[..body.len()].copy_from_slice(body);
        let crc = CRC16.checksum(body).to_le_bytes();
        frame[body.len()..].copy_from_slice(&crc);
        frame
    }

    fn input(start: u16, count: u16) -> Read {
        Read::new(Address::new(1).unwrap(), Function::ReadInput, start, count).unwrap()
    }

    /// The reply to `input(0x3100, 2)`: 0x04D2 and 0x0010.
    fn reply() -> [u8; 9] {
        with_crc(&[0x01, 0x04, 0x04, 0x04, 0xD2, 0x00, 0x10])
    }

    #[test]
    fn a_request_is_encoded_with_its_crc_low_byte_first() {
        // The specification's own example, §6.3: read holding registers
        // 108 to 110 from server 17, whose CRC is 0x8776 sent as 76 87.
        let read = Read::new(
            Address::new(0x11).unwrap(),
            Function::ReadHolding,
            0x006B,
            3,
        )
        .unwrap();
        assert_eq!(
            read.encode(),
            [0x11, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x76, 0x87]
        );
    }

    #[test]
    fn an_address_and_a_read_are_refused_outside_what_the_protocol_allows() {
        assert_eq!(Address::new(0), None);
        assert_eq!(Address::new(248), None);
        assert_eq!(Address::new(247).map(Address::get), Some(247));
        let one = Address::new(1).unwrap();
        assert_eq!(Read::new(one, Function::ReadInput, 0, 0), None);
        assert_eq!(Read::new(one, Function::ReadInput, 0, 126), None);
        assert!(Read::new(one, Function::ReadInput, 0, 125).is_some());
        assert_eq!(Read::new(one, Function::ReadInput, 0xFFFF, 2), None);
        assert!(Read::new(one, Function::ReadInput, 0xFFFF, 1).is_some());
    }

    #[test]
    fn a_well_formed_reply_parses_to_its_registers_by_address() {
        let frame = reply();
        let registers = parse(&input(0x3100, 2), &frame).unwrap();
        assert_eq!(registers.len(), 2);
        assert_eq!(registers.at(0x3100), Some(0x04D2));
        assert_eq!(registers.at(0x3101), Some(0x0010));
        assert_eq!(registers.at(0x30FF), None);
        assert_eq!(registers.at(0x3102), None);
    }

    #[test]
    fn f_050_a_short_reply_is_refused() {
        let frame = reply();
        for len in 0..frame.len() {
            assert_eq!(
                parse(&input(0x3100, 2), &frame[..len]),
                Err(ReplyError::Short),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn f_050_an_overlong_reply_is_refused() {
        let mut frame = [0u8; 10];
        frame[..9].copy_from_slice(&reply());
        assert_eq!(parse(&input(0x3100, 2), &frame), Err(ReplyError::Overlong));
    }

    #[test]
    fn f_050_a_reply_failing_its_crc_is_refused_at_every_single_bit_flip() {
        let good = reply();
        let flips = (0..good.len()).flat_map(|byte| (0..8u32).map(move |bit| (byte, bit)));
        for (byte, bit) in flips {
            let mut frame = good;
            frame[byte] ^= 1u8.rotate_left(bit);
            let result = parse(&input(0x3100, 2), &frame);
            // A flip in the byte count changes the length the header claims,
            // which is refused as a length before the CRC is reached.
            assert!(
                matches!(
                    result,
                    Err(ReplyError::Crc | ReplyError::Short | ReplyError::Overlong)
                ),
                "byte {byte} bit {bit}: {result:?}"
            );
        }
    }

    #[test]
    fn f_050_a_reply_from_another_server_is_refused() {
        let frame: [u8; 9] = with_crc(&[0x02, 0x04, 0x04, 0x04, 0xD2, 0x00, 0x10]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::WrongAddress(2))
        );
    }

    #[test]
    fn a_reply_with_another_function_or_byte_count_is_refused() {
        let frame: [u8; 9] = with_crc(&[0x01, 0x03, 0x04, 0x04, 0xD2, 0x00, 0x10]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::WrongFunction(0x03))
        );
        // A consistent frame carrying one register where two were asked.
        let frame: [u8; 7] = with_crc(&[0x01, 0x04, 0x02, 0x04, 0xD2]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::ByteCount(2))
        );
    }

    #[test]
    fn f_050_an_exception_reply_is_its_own_error_carrying_its_code() {
        let frame: [u8; 5] = with_crc(&[0x01, 0x84, 0x02]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::Exception(Exception::IllegalDataAddress))
        );
        let frame: [u8; 5] = with_crc(&[0x01, 0x84, 0x7F]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::Exception(Exception::Unallocated(0x7F)))
        );
        // An exception to a function that was not asked is the wrong
        // function, not an answer.
        let frame: [u8; 5] = with_crc(&[0x01, 0x83, 0x02]);
        assert_eq!(
            parse(&input(0x3100, 2), &frame),
            Err(ReplyError::WrongFunction(0x83))
        );
    }

    #[test]
    fn f_050_the_echo_is_discarded_whether_it_arrives_alone_or_with_the_reply() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let reply = reply();

        let bursts: [&[u8]; 2] = [&echo, &reply];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(&mut port, &read, TIMING, &mut buf)).unwrap();
        assert_eq!(registers.at(0x3100), Some(0x04D2));
        assert_eq!(port.sent, echo);

        let mut joined = [0u8; 17];
        joined[..8].copy_from_slice(&echo);
        joined[8..].copy_from_slice(&reply);
        let bursts: [&[u8]; 1] = [&joined];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(&mut port, &read, TIMING, &mut buf)).unwrap();
        assert_eq!(registers.at(0x3101), Some(0x0010));

        // The reply split across bursts after the echo.
        let bursts: [&[u8]; 3] = [&echo, &reply[..4], &reply[4..]];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(&mut port, &read, TIMING, &mut buf)).unwrap();
        assert_eq!(registers.at(0x3100), Some(0x04D2));
        // The first two waits are for the echo and the reply to begin; the
        // third is inside the reply.
        assert_eq!(
            port.waits[..3],
            [
                Some(TIMING.response),
                Some(TIMING.response),
                Some(TIMING.gap)
            ]
        );
    }

    #[test]
    fn f_050_a_reply_parsed_without_its_echo_discarded_would_be_refused() {
        // The guard the discard exists for: the echo read as the reply is a
        // request frame, which fails as a reply.
        let read = input(0x3100, 2);
        let mut joined = [0u8; 17];
        joined[..8].copy_from_slice(&read.encode());
        joined[8..].copy_from_slice(&reply());
        assert!(parse(&read, &joined).is_err());
    }

    #[test]
    fn f_050_a_missing_cut_or_different_echo_is_refused() {
        let read = input(0x3100, 2);
        let echo = read.encode();

        // Nothing heard at all: the frame never reached the bus.
        let mut port = Scripted::new(&[]);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Echo)
        );

        let bursts: [&[u8]; 1] = [&echo[..5]];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Echo)
        );

        let mut garbled = echo;
        garbled[3] ^= 0x10;
        let reply = reply();
        let bursts: [&[u8]; 2] = [&garbled, &reply];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Echo)
        );
    }

    #[test]
    fn f_050_a_device_that_never_answers_is_a_timeout_and_not_a_reply_error() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let bursts: [&[u8]; 1] = [&echo];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Timeout)
        );
    }

    #[test]
    fn a_reply_that_stops_partway_is_short_and_a_line_fault_is_the_port_s() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let reply = reply();
        let bursts: [&[u8]; 2] = [&echo, &reply[..6]];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Reply(ReplyError::Short))
        );

        let bursts: [&[u8]; 1] = [&echo];
        let mut port = Scripted::new(&bursts);
        port.fault = Some(7);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Port(7))
        );
    }

    #[test]
    fn f_050_trailing_bytes_in_the_reply_s_burst_are_refused_as_overlong() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let mut long = [0u8; 10];
        long[..9].copy_from_slice(&reply());
        let bursts: [&[u8]; 2] = [&echo, &long];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        assert_eq!(
            block_on(super::read(&mut port, &read, TIMING, &mut buf)),
            Err(ModbusError::Reply(ReplyError::Overlong))
        );
    }

    #[test]
    fn a_largest_read_fills_its_buffer_exactly() {
        let read = input(0, MAX_REGISTERS);
        let echo = read.encode();
        let mut body = [0u8; 253];
        body[..3].copy_from_slice(&[0x01, 0x04, 250]);
        body[3..].iter_mut().zip(0u8..).for_each(|(b, v)| *b = v);
        let reply: [u8; 255] = with_crc(&body);
        let bursts: [&[u8]; 2] = [&echo, &reply];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(&mut port, &read, TIMING, &mut buf)).unwrap();
        assert_eq!(registers.len(), 125);
        assert_eq!(registers.at(124), Some(u16::from_be_bytes([248, 249])));
    }
}
