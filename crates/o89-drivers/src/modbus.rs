//! Modbus RTU: a register read, the reply it gets, and every way the reply
//! can be wrong.
//!
//! The board's RS-485 transceivers are auto-direction with the receiver
//! always on, so the first bytes after a request are the request itself.
//! [`read`] requires them, byte for byte, and discards them before the reply
//! is parsed (F-050); a frame heard back different from the one sent is a
//! collision on the bus and is refused rather than parsed around.
//!
//! A read is at most two receives, each bounded by [`Timing::response`]: the
//! echo, alone or with the reply behind it, and then the reply if it came
//! separately. The port ends a burst at the inter-frame gap, so a reply is
//! one burst: a reply cut by a gap is short, and is never joined to what
//! the line carries next.
//!
//! cites: F-050

use crc::{CRC_16_MODBUS, Crc};
use o89_core::Millis;

use crate::port::{Burst, Ended, PortFault, Rs485};

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
    /// The port reported a burst it cannot have received: no bytes, more
    /// than the buffer holds, or a full buffer with room left.
    Adapter,
}

/// How long a read waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timing {
    /// For the echo, and then for the reply to begin.
    pub response: Millis,
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
pub fn parse(read: Read, frame: &[u8]) -> Result<Registers<'_>, ReplyError> {
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
/// The request's echo is required, byte for byte, and discarded (F-050).
/// The reply is the rest of the echo's burst, or the next burst when the
/// echo came alone.
pub async fn read<'a, P: Rs485>(
    port: &mut P,
    read: Read,
    timing: Timing,
    into: &'a mut [u8; RECEIVE_BYTES],
) -> Result<Registers<'a>, ModbusError<P::Error>> {
    let request = read.encode();
    port.send(&request).await.map_err(ModbusError::Port)?;
    let heard = match burst(port, into, timing.response).await {
        Ok(len) => len,
        // Nothing heard at all: the frame never reached the bus.
        Err(ModbusError::Timeout) => return Err(ModbusError::Echo),
        Err(error) => return Err(error),
    };
    let echo = into.get(..heard.min(REQUEST_BYTES)).unwrap_or(&[]);
    if heard < REQUEST_BYTES || echo != request.as_slice() {
        return Err(ModbusError::Echo);
    }
    let heard = if heard == REQUEST_BYTES {
        let rest = into.get_mut(REQUEST_BYTES..).unwrap_or(&mut []);
        REQUEST_BYTES.saturating_add(burst(port, rest, timing.response).await?)
    } else {
        heard
    };
    let reply = into.get(REQUEST_BYTES..heard).unwrap_or(&[]);
    parse(read, reply).map_err(ModbusError::Reply)
}

/// One receive into `into`, refusing a burst the port cannot have received.
async fn burst<P: Rs485>(
    port: &mut P,
    into: &mut [u8],
    within: Millis,
) -> Result<usize, ModbusError<P::Error>> {
    let room = into.len();
    match port.receive(into, within).await {
        Ok(Burst { len, ended }) => {
            let consistent = match ended {
                Ended::Gap => len > 0 && len <= room,
                Ended::Full => len > 0 && len == room,
            };
            if consistent {
                Ok(len)
            } else {
                Err(ModbusError::Adapter)
            }
        }
        Err(PortFault::Timeout) => Err(ModbusError::Timeout),
        Err(PortFault::Line(error)) => Err(ModbusError::Port(error)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;

    /// A port that plays back scripted bursts and records what was sent.
    ///
    /// Each script entry is one burst ending at the gap, or ending `Full`
    /// when it fills the buffer, as an honest adapter reports; `lie`
    /// replaces the next report with one no adapter should make.
    pub(crate) struct Scripted<'a> {
        pub bursts: &'a [&'a [u8]],
        pub next: usize,
        pub sent: [u8; REQUEST_BYTES],
        pub fault: Option<u8>,
        pub lie: Option<Burst>,
        pub waits: [Option<Millis>; 4],
    }

    impl<'a> Scripted<'a> {
        pub(crate) fn new(bursts: &'a [&'a [u8]]) -> Self {
            Self {
                bursts,
                next: 0,
                sent: [0; REQUEST_BYTES],
                fault: None,
                lie: None,
                waits: [None; 4],
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
        ) -> impl Future<Output = Result<Burst, PortFault<u8>>> {
            ready(self.burst(into, within))
        }
    }

    impl Scripted<'_> {
        fn burst(&mut self, into: &mut [u8], within: Millis) -> Result<Burst, PortFault<u8>> {
            if let Some(slot) = self.waits.get_mut(self.next) {
                *slot = Some(within);
            }
            if let Some(fault) = self.fault.take() {
                return Err(PortFault::Line(fault));
            }
            if let Some(lie) = self.lie.take() {
                return Ok(lie);
            }
            let Some(burst) = self.bursts.get(self.next) else {
                return Err(PortFault::Timeout);
            };
            self.next = self.next.checked_add(1).unwrap();
            let len = burst.len().min(into.len());
            into[..len].copy_from_slice(&burst[..len]);
            let ended = if len == into.len() {
                Ended::Full
            } else {
                Ended::Gap
            };
            Ok(Burst { len, ended })
        }
    }

    pub(crate) const TIMING: Timing = Timing {
        response: Millis::from_millis(200),
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
        let registers = parse(input(0x3100, 2), &frame).unwrap();
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
                parse(input(0x3100, 2), &frame[..len]),
                Err(ReplyError::Short),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn f_050_an_overlong_reply_is_refused() {
        let mut frame = [0u8; 10];
        frame[..9].copy_from_slice(&reply());
        assert_eq!(parse(input(0x3100, 2), &frame), Err(ReplyError::Overlong));
    }

    #[test]
    fn f_050_a_reply_failing_its_crc_is_refused_at_every_single_bit_flip() {
        let good = reply();
        let flips = (0..good.len()).flat_map(|byte| (0..8u32).map(move |bit| (byte, bit)));
        for (byte, bit) in flips {
            let mut frame = good;
            frame[byte] ^= 1u8.rotate_left(bit);
            let result = parse(input(0x3100, 2), &frame);
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
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::WrongAddress(2))
        );
    }

    #[test]
    fn a_reply_with_another_function_or_byte_count_is_refused() {
        let frame: [u8; 9] = with_crc(&[0x01, 0x03, 0x04, 0x04, 0xD2, 0x00, 0x10]);
        assert_eq!(
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::WrongFunction(0x03))
        );
        // A consistent frame carrying one register where two were asked.
        let frame: [u8; 7] = with_crc(&[0x01, 0x04, 0x02, 0x04, 0xD2]);
        assert_eq!(
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::ByteCount(2))
        );
    }

    #[test]
    fn f_050_an_exception_reply_is_its_own_error_carrying_its_code() {
        let frame: [u8; 5] = with_crc(&[0x01, 0x84, 0x02]);
        assert_eq!(
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::Exception(Exception::IllegalDataAddress))
        );
        let frame: [u8; 5] = with_crc(&[0x01, 0x84, 0x7F]);
        assert_eq!(
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::Exception(Exception::Unallocated(0x7F)))
        );
        // An exception to a function that was not asked is the wrong
        // function, not an answer.
        let frame: [u8; 5] = with_crc(&[0x01, 0x83, 0x02]);
        assert_eq!(
            parse(input(0x3100, 2), &frame),
            Err(ReplyError::WrongFunction(0x83))
        );
    }

    fn run(port: &mut Scripted<'_>, read: Read) -> Result<[Option<u16>; 2], ModbusError<u8>> {
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(port, read, TIMING, &mut buf))?;
        Ok([
            registers.at(read.start()),
            registers.at(read.start().checked_add(1).unwrap()),
        ])
    }

    fn echo_then(reply: &[u8]) -> ([u8; RECEIVE_BYTES], usize) {
        let mut joined = [0u8; RECEIVE_BYTES];
        joined[..REQUEST_BYTES].copy_from_slice(&input(0x3100, 2).encode());
        joined[REQUEST_BYTES..][..reply.len()].copy_from_slice(reply);
        (joined, REQUEST_BYTES.checked_add(reply.len()).unwrap())
    }

    #[test]
    fn f_050_the_echo_is_discarded_whether_it_arrives_alone_or_with_the_reply() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let reply = reply();

        let bursts: [&[u8]; 2] = [&echo, &reply];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Ok([Some(0x04D2), Some(0x0010)]));
        assert_eq!(port.sent, echo);
        // Two receives, each given the response deadline.
        assert_eq!(
            port.waits,
            [Some(TIMING.response), Some(TIMING.response), None, None]
        );

        let (joined, len) = echo_then(&reply);
        let bursts: [&[u8]; 1] = [&joined[..len]];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Ok([Some(0x04D2), Some(0x0010)]));
        assert_eq!(port.waits, [Some(TIMING.response), None, None, None]);
    }

    #[test]
    fn f_050_a_reply_cut_by_a_gap_is_short_and_never_joined_to_the_next_burst() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let reply = reply();
        // The two halves together carry a valid CRC; the gap between them
        // ended the frame, so they are two frames and the first is short.
        let bursts: [&[u8]; 3] = [&echo, &reply[..4], &reply[4..]];
        let mut port = Scripted::new(&bursts);
        assert_eq!(
            run(&mut port, read),
            Err(ModbusError::Reply(ReplyError::Short))
        );
        assert_eq!(port.next, 2, "the burst after the gap was never read");

        let (joined, len) = echo_then(&reply[..4]);
        let bursts: [&[u8]; 2] = [&joined[..len], &reply[4..]];
        let mut port = Scripted::new(&bursts);
        assert_eq!(
            run(&mut port, read),
            Err(ModbusError::Reply(ReplyError::Short))
        );
    }

    #[test]
    fn f_050_a_port_that_does_not_echo_is_refused_rather_than_read_as_the_reply() {
        let read = input(0x3100, 2);
        let reply = reply();
        let bursts: [&[u8]; 1] = [&reply];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Err(ModbusError::Echo));
    }

    #[test]
    fn f_050_a_missing_cut_or_different_echo_is_refused() {
        let read = input(0x3100, 2);
        let echo = read.encode();

        // Nothing heard at all: the frame never reached the bus.
        let mut port = Scripted::new(&[]);
        assert_eq!(run(&mut port, read), Err(ModbusError::Echo));

        let bursts: [&[u8]; 1] = [&echo[..5]];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Err(ModbusError::Echo));

        let mut garbled = echo;
        garbled[3] ^= 0x10;
        let reply = reply();
        let bursts: [&[u8]; 2] = [&garbled, &reply];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Err(ModbusError::Echo));
    }

    #[test]
    fn f_050_a_device_that_never_answers_is_a_timeout_and_not_a_reply_error() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let bursts: [&[u8]; 1] = [&echo];
        let mut port = Scripted::new(&bursts);
        assert_eq!(run(&mut port, read), Err(ModbusError::Timeout));
    }

    #[test]
    fn a_line_fault_is_the_port_s_error() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let bursts: [&[u8]; 1] = [&echo];
        let mut port = Scripted::new(&bursts);
        port.fault = Some(7);
        assert_eq!(run(&mut port, read), Err(ModbusError::Port(7)));
    }

    #[test]
    fn a_burst_no_adapter_can_have_received_is_refused_rather_than_clamped() {
        let read = input(0x3100, 2);
        for lie in [
            Burst {
                len: 0,
                ended: Ended::Gap,
            },
            Burst {
                len: RECEIVE_BYTES + 1,
                ended: Ended::Gap,
            },
            Burst {
                len: RECEIVE_BYTES + 1,
                ended: Ended::Full,
            },
            Burst {
                len: REQUEST_BYTES,
                ended: Ended::Full,
            },
        ] {
            let mut port = Scripted::new(&[]);
            port.lie = Some(lie);
            assert_eq!(run(&mut port, read), Err(ModbusError::Adapter), "{lie:?}");
        }
    }

    #[test]
    fn f_050_trailing_bytes_in_the_reply_s_burst_are_refused_as_overlong() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        let mut long = [0u8; 10];
        long[..9].copy_from_slice(&reply());
        let bursts: [&[u8]; 2] = [&echo, &long];
        let mut port = Scripted::new(&bursts);
        assert_eq!(
            run(&mut port, read),
            Err(ModbusError::Reply(ReplyError::Overlong))
        );
    }

    #[test]
    fn a_reply_that_fills_the_buffer_ends_the_read_and_is_judged_as_it_stands() {
        let read = input(0x3100, 2);
        let echo = read.encode();
        // A babbling line: the buffer fills, the port says so, and what was
        // heard is refused rather than waited on.
        let babble = [0x01u8; FRAME_BYTES + 1];
        let bursts: [&[u8]; 2] = [&echo, &babble];
        let mut port = Scripted::new(&bursts);
        assert_eq!(
            run(&mut port, read),
            Err(ModbusError::Reply(ReplyError::Overlong))
        );
        assert_eq!(port.next, 2);
    }

    #[test]
    fn a_largest_read_decodes_all_its_registers() {
        let read = input(0, MAX_REGISTERS);
        let echo = read.encode();
        let mut body = [0u8; 253];
        body[..3].copy_from_slice(&[0x01, 0x04, 250]);
        body[3..].iter_mut().zip(0u8..).for_each(|(b, v)| *b = v);
        let reply: [u8; 255] = with_crc(&body);
        let bursts: [&[u8]; 2] = [&echo, &reply];
        let mut port = Scripted::new(&bursts);
        let mut buf = [0; RECEIVE_BYTES];
        let registers = block_on(super::read(&mut port, read, TIMING, &mut buf)).unwrap();
        assert_eq!(registers.len(), 125);
        assert_eq!(registers.at(0), Some(u16::from_be_bytes([0, 1])));
        assert_eq!(registers.at(124), Some(u16::from_be_bytes([248, 249])));
        assert_eq!(registers.at(125), None);
    }
}
