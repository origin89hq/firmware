//! A byte port over a UART: the bursts the port contract asks for, ended at
//! the framing's inter-frame gap, written once over a line that the
//! controller and a host test both provide.
//!
//! The controller's UARTs hand over bytes as they arrive and know nothing
//! of frames. [`Framed`] turns that into the [`Rs485`] and [`Listener`]
//! contract: [`Rs485::discard`] empties only what has already arrived and
//! never waits on the line; a receive waits its deadline for the first
//! byte, then takes bytes until the line has been idle for the framing's
//! gap or the buffer is full, and says which. Nothing here names a
//! peripheral, so the contract is a host test against a line with a clock
//! ([`tests`]); the timing a real UART and transceiver give is the bench's.
//!
//! What the contract cannot catch, it does not claim to: a reply that
//! arrives after the next exchange's discard is that exchange's, as far as
//! any port can tell (the [`modbus`](crate::modbus) module says so too).
//! The bus task keeps the next exchange outside that window instead, by
//! waiting a response bound after an exchange that timed out.
//!
//! cites: F-050

use core::future::Future;
use core::num::NonZeroU32;

use km43::{DataBits, Parity, StopBits};
use o89_core::Millis;

use crate::port::{Burst, Ended, Listener, PortFault, Rs485};

/// A line the controller only listens on: bytes as they arrive.
pub trait ReceiveLine {
    /// What the line reports: framing, parity, overrun.
    type Error;

    /// Move what has already arrived into `into` and say how much, without
    /// waiting: 0 when nothing has.
    fn drain(&mut self, into: &mut [u8]) -> Result<usize, Self::Error>;

    /// Wait at most `within` for a byte, then move what has arrived into
    /// `into` and say how much: 0 when the wait ran out with nothing.
    fn read(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> impl Future<Output = Result<usize, Self::Error>>;
}

/// A line the controller also sends on.
pub trait SerialLine: ReceiveLine {
    /// Send `bytes`, returning once the last has left the wire.
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
}

/// How a serial line runs: the rate and the character's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Framing {
    /// Bits per second.
    pub rate: NonZeroU32,
    /// Data bits.
    pub data_bits: DataBits,
    /// Parity.
    pub parity: Parity,
    /// Stop bits.
    pub stop_bits: StopBits,
}

/// Above this rate the Modbus RTU gap is a fixed 1.75 ms rather than three
/// and a half characters (Modbus over serial line v1.02, §2.5.1.1).
const FIXED_GAP_ABOVE: u32 = 19_200;
/// The fixed gap, in microseconds.
const FIXED_GAP_US: u64 = 1_750;

impl Framing {
    /// The bits one character takes on the wire: start, data, parity, stop.
    #[must_use]
    pub const fn character_bits(&self) -> u8 {
        let data: u8 = match self.data_bits {
            DataBits::Seven => 7,
            DataBits::Eight => 8,
        };
        let framing: u8 = match (self.parity, self.stop_bits) {
            (Parity::None, StopBits::One) => 2,
            (Parity::None, StopBits::Two) | (Parity::Even | Parity::Odd, StopBits::One) => 3,
            (Parity::Even | Parity::Odd, StopBits::Two) => 4,
        };
        data.saturating_add(framing)
    }

    /// The idle time that ends a frame: three and a half characters, or
    /// 1.75 ms above 19200 bit/s, rounded up to the millisecond the
    /// executor's timer counts in, so a burst never ends inside a frame.
    #[must_use]
    pub fn gap(&self) -> Millis {
        let micros = if self.rate.get() > FIXED_GAP_ABOVE {
            FIXED_GAP_US
        } else {
            // 3.5 characters is 7 half-characters.
            let half_characters = u64::from(self.character_bits()).saturating_mul(7);
            half_characters
                .saturating_mul(1_000_000)
                .div_ceil(u64::from(self.rate.get()).saturating_mul(2))
        };
        Millis::from_millis(micros.div_ceil(1_000))
    }

    /// How long `bytes` characters take on the wire, rounded up to the
    /// millisecond.
    #[must_use]
    pub fn wire_time(&self, bytes: u32) -> Millis {
        let bits = u64::from(bytes).saturating_mul(u64::from(self.character_bits()));
        Millis::from_millis(
            bits.saturating_mul(1_000)
                .div_ceil(u64::from(self.rate.get())),
        )
    }
}

/// What [`Rs485::discard`] empties at a time.
const DISCARD_CHUNK: usize = 32;
/// The most chunks one discard takes: past it, a line that keeps
/// delivering bytes while it is emptied is noise, and the discard returns
/// rather than spin; the next exchange's echo check refuses what is left.
const DISCARD_CHUNKS: usize = 64;

/// A line, framed into bursts at `gap`.
#[derive(Debug)]
pub struct Framed<L> {
    line: L,
    gap: Millis,
}

impl<L> Framed<L> {
    /// `line`, whose bursts end after `gap` of silence.
    pub const fn new(line: L, gap: Millis) -> Self {
        Self { line, gap }
    }

    /// The gap that ends a burst.
    #[must_use]
    pub const fn gap(&self) -> Millis {
        self.gap
    }

    /// The line.
    pub const fn line(&mut self) -> &mut L {
        &mut self.line
    }
}

impl<L: ReceiveLine> Framed<L> {
    /// One burst into `into`: the first byte within `within`, then every
    /// byte until `gap` passes with none or `into` is full.
    ///
    /// Bounded by `into`: every pass after the first takes at least one
    /// byte or ends the burst.
    async fn burst(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> Result<Burst, PortFault<L::Error>> {
        let room = into.len();
        let first = self
            .line
            .read(into, within)
            .await
            .map_err(PortFault::Line)?;
        if first == 0 {
            return Err(PortFault::Timeout);
        }
        let mut len = first.min(room);
        for _ in 0..room {
            let Some(rest) = into.get_mut(len..).filter(|rest| !rest.is_empty()) else {
                break;
            };
            let more = self
                .line
                .read(rest, self.gap)
                .await
                .map_err(PortFault::Line)?;
            if more == 0 {
                return Ok(Burst {
                    len,
                    ended: Ended::Gap,
                });
            }
            len = len.saturating_add(more).min(room);
        }
        Ok(Burst {
            len,
            ended: Ended::Full,
        })
    }
}

impl<L: SerialLine> Rs485 for Framed<L> {
    type Error = L::Error;

    fn discard(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        let mut scratch = [0u8; DISCARD_CHUNK];
        let mut emptied = Ok(());
        for _ in 0..DISCARD_CHUNKS {
            match self.line.drain(&mut scratch) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => {
                    emptied = Err(error);
                    break;
                }
            }
        }
        core::future::ready(emptied)
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.line.send(bytes).await
    }

    async fn receive(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> Result<Burst, PortFault<Self::Error>> {
        self.burst(into, within).await
    }
}

impl<L: ReceiveLine> Listener for Framed<L> {
    type Error = L::Error;

    async fn receive(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> Result<Burst, PortFault<Self::Error>> {
        self.burst(into, within).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! A line with a clock: every byte arrives at a millisecond, and a read
    //! moves the clock to the byte it waited for, or by its whole wait.

    use super::*;
    use crate::modbus::tests::register_reply;
    use crate::modbus::{self, Address, Function, ModbusError, Read, Timing};
    use core::future::ready;
    use embassy_futures::block_on;

    /// The most bytes a fake line carries.
    const BYTES: usize = 512;

    /// Bytes on a line, each with the millisecond it arrives at.
    pub(crate) struct Timed {
        bytes: [(u64, u8); BYTES],
        len: usize,
        /// Bytes before this have been handed out or drained.
        next: usize,
        /// The line's clock.
        pub(crate) now: u64,
        /// What was sent, and when.
        pub(crate) sent: [(u64, usize); 8],
        sends: usize,
        /// Fail the next read with this.
        pub(crate) fault: Option<u8>,
    }

    impl Timed {
        pub(crate) fn new() -> Self {
            Self {
                bytes: [(0, 0); BYTES],
                len: 0,
                next: 0,
                now: 0,
                sent: [(0, 0); 8],
                sends: 0,
                fault: None,
            }
        }

        /// `frame` arriving from `at`, one byte every `spacing` ms.
        pub(crate) fn arrive(&mut self, at: u64, spacing: u64, frame: &[u8]) {
            let mut when = at;
            for byte in frame {
                self.bytes[self.len] = (when, *byte);
                self.len = self.len.checked_add(1).unwrap();
                when = when.checked_add(spacing).unwrap();
            }
            self.bytes[..self.len].sort_by_key(|(at, _)| *at);
        }

        /// Move the clock on by `by` milliseconds.
        pub(crate) fn wait(&mut self, by: u64) {
            self.now = self.now.checked_add(by).unwrap();
        }

        /// How many bytes have arrived by now.
        fn arrived(&self) -> usize {
            self.bytes[..self.len]
                .iter()
                .take_while(|(at, _)| *at <= self.now)
                .count()
        }

        fn take(&mut self, into: &mut [u8]) -> usize {
            let end = self
                .arrived()
                .min(self.next.checked_add(into.len()).unwrap());
            let n = end.saturating_sub(self.next);
            for (slot, (_, byte)) in into.iter_mut().zip(&self.bytes[self.next..end]) {
                *slot = *byte;
            }
            self.next = end.max(self.next);
            n
        }
    }

    impl ReceiveLine for Timed {
        type Error = u8;

        fn drain(&mut self, into: &mut [u8]) -> Result<usize, u8> {
            Ok(self.take(into))
        }

        fn read(
            &mut self,
            into: &mut [u8],
            within: Millis,
        ) -> impl Future<Output = Result<usize, u8>> {
            if let Some(fault) = self.fault.take() {
                return ready(Err(fault));
            }
            if self.arrived() <= self.next {
                let deadline = self.now.checked_add(within.as_millis()).unwrap();
                match self.bytes[self.next..self.len].first() {
                    Some((at, _)) if *at <= deadline => self.now = *at,
                    Some(_) | None => {
                        self.now = deadline;
                        return ready(Ok(0));
                    }
                }
            }
            ready(Ok(self.take(into)))
        }
    }

    impl SerialLine for Timed {
        fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), u8>> {
            self.sent[self.sends] = (self.now, bytes.len());
            self.sends = self.sends.checked_add(1).unwrap();
            ready(Ok(()))
        }
    }

    const GAP: Millis = Millis::from_millis(5);

    fn framing(rate: u32, parity: Parity, stop_bits: StopBits) -> Framing {
        Framing {
            rate: NonZeroU32::new(rate).unwrap(),
            data_bits: DataBits::Eight,
            parity,
            stop_bits,
        }
    }

    #[test]
    fn the_gap_is_three_and_a_half_characters_and_fixed_above_19200() {
        // 9600 8N2: eleven bits, 4.01 ms, rounded up.
        assert_eq!(
            framing(9_600, Parity::None, StopBits::Two).gap(),
            Millis::from_millis(5)
        );
        // 9600 8N1: ten bits, 3.65 ms.
        assert_eq!(
            framing(9_600, Parity::None, StopBits::One).gap(),
            Millis::from_millis(4)
        );
        // 19200 is still counted in characters: 1.82 ms.
        assert_eq!(
            framing(19_200, Parity::None, StopBits::One).gap(),
            Millis::from_millis(2)
        );
        // Above it, 1.75 ms whatever the rate.
        assert_eq!(
            framing(115_200, Parity::Even, StopBits::One).gap(),
            Millis::from_millis(2)
        );
        assert_eq!(
            framing(19_201, Parity::None, StopBits::One).gap(),
            Millis::from_millis(2)
        );
        // At one bit a second a character is a long wait, and still bounded.
        assert_eq!(
            framing(1, Parity::Odd, StopBits::Two).gap(),
            Millis::from_millis(42_000)
        );
        assert_eq!(
            framing(9_600, Parity::None, StopBits::Two).wire_time(8),
            Millis::from_millis(10)
        );
    }

    #[test]
    fn f_050_discard_returns_at_once_and_drops_only_what_had_arrived() {
        let mut line = Timed::new();
        line.arrive(0, 1, &[0xAA, 0xBB]);
        line.arrive(50, 1, &[0x01, 0x02, 0x03]);
        line.now = 10;
        let mut port = Framed::new(line, GAP);
        block_on(port.discard()).unwrap();
        // No time passed on the line, and what had not arrived is still to
        // come.
        assert_eq!(port.line().now, 10);
        let mut into = [0u8; 8];
        let burst = block_on(Rs485::receive(
            &mut port,
            &mut into,
            Millis::from_millis(100),
        ))
        .unwrap();
        assert_eq!(
            (burst, &into[..3]),
            (
                Burst {
                    len: 3,
                    ended: Ended::Gap
                },
                &[0x01, 0x02, 0x03][..]
            )
        );
        // A discard with nothing buffered is as quick.
        block_on(port.discard()).unwrap();
        assert_eq!(
            port.line().now,
            52_u64.checked_add(GAP.as_millis()).unwrap()
        );
    }

    #[test]
    fn f_050_a_burst_ends_at_the_gap_and_two_frames_apart_are_two_bursts() {
        let mut line = Timed::new();
        line.arrive(3, 1, &[1, 2, 3, 4]);
        // Exactly one gap after the last byte: a new frame.
        line.arrive(7_u64.checked_add(GAP.as_millis()).unwrap(), 1, &[9, 8]);
        let mut port = Framed::new(line, GAP);
        let mut into = [0u8; 16];
        let within = Millis::from_millis(20);
        let first = block_on(Rs485::receive(&mut port, &mut into, within)).unwrap();
        assert_eq!(
            (first, &into[..4]),
            (
                Burst {
                    len: 4,
                    ended: Ended::Gap
                },
                &[1, 2, 3, 4][..]
            )
        );
        let second = block_on(Rs485::receive(&mut port, &mut into, within)).unwrap();
        assert_eq!(
            (second, &into[..2]),
            (
                Burst {
                    len: 2,
                    ended: Ended::Gap
                },
                &[9, 8][..]
            )
        );
    }

    #[test]
    fn f_050_frames_closer_than_the_gap_are_one_burst() {
        let mut line = Timed::new();
        line.arrive(0, 1, &[1, 2]);
        line.arrive(GAP.as_millis(), 1, &[3]);
        let mut port = Framed::new(line, GAP);
        let mut into = [0u8; 16];
        let burst = block_on(Rs485::receive(&mut port, &mut into, Millis::from_millis(1))).unwrap();
        assert_eq!(burst.len, 3);
        assert_eq!(burst.ended, Ended::Gap);
    }

    #[test]
    fn f_050_a_burst_that_fills_the_buffer_says_so() {
        let mut line = Timed::new();
        line.arrive(0, 1, &[1, 2, 3, 4, 5, 6]);
        let mut port = Framed::new(line, GAP);
        let mut into = [0u8; 4];
        let burst = block_on(Rs485::receive(&mut port, &mut into, Millis::from_millis(1))).unwrap();
        assert_eq!(
            burst,
            Burst {
                len: 4,
                ended: Ended::Full
            }
        );
        // The rest is the next burst.
        let rest = block_on(Rs485::receive(&mut port, &mut into, Millis::from_millis(1))).unwrap();
        assert_eq!((rest.len, &into[..2]), (2, &[5, 6][..]));
    }

    #[test]
    fn f_050_nothing_before_the_deadline_is_a_timeout_and_a_line_fault_is_the_line_s() {
        let mut line = Timed::new();
        line.arrive(30, 1, &[1]);
        let mut port = Framed::new(line, GAP);
        let mut into = [0u8; 4];
        assert_eq!(
            block_on(Rs485::receive(
                &mut port,
                &mut into,
                Millis::from_millis(29)
            )),
            Err(PortFault::Timeout)
        );
        assert_eq!(port.line().now, 29);
        port.line().fault = Some(7);
        assert_eq!(
            block_on(Listener::receive(
                &mut port,
                &mut into,
                Millis::from_millis(5)
            )),
            Err(PortFault::Line(7))
        );
    }

    const RESPONSE: Timing = Timing {
        response: Millis::from_millis(100),
    };

    fn exchange() -> (Read, [u8; modbus::REQUEST_BYTES]) {
        let read = Read::new(Address::new(1).unwrap(), Function::ReadInput, 0, 1).unwrap();
        (read, read.encode())
    }

    #[test]
    fn f_050_a_reply_after_the_response_deadline_is_refused_and_the_next_discard_drops_it() {
        let (read, request) = exchange();
        let (late, late_len) = register_reply(1, 0x04, &[0x1111]);
        let (fresh, fresh_len) = register_reply(1, 0x04, &[0x2222]);
        let mut line = Timed::new();
        // The echo comes back at once; the reply starts 150 ms later,
        // past the 100 ms the exchange waits.
        line.arrive(1, 1, &request);
        line.arrive(160, 1, &late[..late_len]);
        let mut port = Framed::new(line, GAP);
        let mut buf = [0u8; modbus::RECEIVE_BYTES];
        assert_eq!(
            block_on(modbus::read(&mut port, read, RESPONSE, &mut buf)),
            Err(ModbusError::Timeout)
        );
        // The bus task waits a response bound before the next exchange, so
        // the late reply has arrived by the time that exchange discards.
        port.line().wait(RESPONSE.response.as_millis());
        let at = port.line().now;
        port.line().arrive(at.checked_add(1).unwrap(), 1, &request);
        port.line()
            .arrive(at.checked_add(20).unwrap(), 1, &fresh[..fresh_len]);
        let registers = block_on(modbus::read(&mut port, read, RESPONSE, &mut buf)).unwrap();
        assert_eq!(registers.at(0), Some(0x2222));
    }

    #[test]
    fn f_050_a_reply_later_than_the_next_discard_is_taken_for_the_next_exchange_s() {
        // The undetectable case, shown so that nobody counts on it: a reply
        // still arriving after the next discard is that exchange's.
        let (read, request) = exchange();
        let (late, late_len) = register_reply(1, 0x04, &[0x1111]);
        let mut line = Timed::new();
        line.arrive(1, 1, &request);
        let mut port = Framed::new(line, GAP);
        let mut buf = [0u8; modbus::RECEIVE_BYTES];
        assert_eq!(
            block_on(modbus::read(&mut port, read, RESPONSE, &mut buf)),
            Err(ModbusError::Timeout)
        );
        let at = port.line().now;
        port.line().arrive(at.checked_add(1).unwrap(), 1, &request);
        port.line()
            .arrive(at.checked_add(30).unwrap(), 1, &late[..late_len]);
        let registers = block_on(modbus::read(&mut port, read, RESPONSE, &mut buf)).unwrap();
        assert_eq!(registers.at(0), Some(0x1111));
    }
}
