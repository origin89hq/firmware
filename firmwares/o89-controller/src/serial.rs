//! The serial buses: the three RS-485 channels on USART2, USART3 and USART4,
//! and the two VE.Direct ports on LPUART1 and LPUART2, receive only.
//!
//! Each is a line `o89-drivers` frames into bursts at the channel's
//! inter-frame gap ([`Framed`]), so what is timing here is the UART's and
//! what is a frame is the host-tested adapter's. An RS-485 channel's line is
//! the buffered UART, interrupt-driven, whose receiver is always on as the
//! board's transceivers are (F-050); a VE.Direct port's is a receiver alone
//! on a DMA ring, with no transmit pin to take, so nothing here can send to
//! a Victron product. A VE.Direct pin's pull is the revision's for the
//! product the port is configured for (F-051).
//!
//! Every await has a deadline: a receive's is its caller's, a send's is
//! the frame's wire time and a margin, and a UART that never finishes one
//! is a line error, not a task that stops checking in.

use embassy_futures::poll_once;
use embassy_stm32::gpio::Pull;
use embassy_stm32::usart::{self, BufferedUart, Config, RingBufferedUartRx};
use embassy_time::{Duration, with_timeout};
use embedded_io_async::{Read, ReadReady, Write};
use km43::{DataBits, Parity, StopBits};
use o89_core::{Millis, VeDirectInput};
use o89_drivers::serial::{Framing, ReceiveLine, SerialLine};

/// What a serial line reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LineError {
    /// The UART: framing, noise, overrun, parity.
    Uart(usart::Error),
    /// A frame did not leave the wire inside its deadline.
    Stalled,
}

/// How long past its wire time a frame may take to leave.
const SEND_MARGIN: Millis = Millis::from_millis(20);

/// An RS-485 channel's UART.
pub struct Rs485Line {
    uart: BufferedUart<'static>,
    framing: Framing,
}

impl Rs485Line {
    /// The channel's UART, running at `framing`.
    pub const fn new(uart: BufferedUart<'static>, framing: Framing) -> Self {
        Self { uart, framing }
    }
}

impl ReceiveLine for Rs485Line {
    type Error = LineError;

    fn drain(&mut self, into: &mut [u8]) -> Result<usize, LineError> {
        match self.uart.read_ready() {
            Ok(false) => Ok(0),
            // Ready: the read takes what is buffered without waiting.
            Ok(true) => match poll_once(self.uart.read(into)) {
                core::task::Poll::Ready(read) => read.map_err(LineError::Uart),
                core::task::Poll::Pending => Ok(0),
            },
            Err(error) => Err(LineError::Uart(error)),
        }
    }

    async fn read(&mut self, into: &mut [u8], within: Millis) -> Result<usize, LineError> {
        match with_timeout(duration(within), self.uart.read(into)).await {
            Ok(read) => read.map_err(LineError::Uart),
            Err(_) => Ok(0),
        }
    }
}

impl SerialLine for Rs485Line {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), LineError> {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let deadline = self
            .framing
            .wire_time(len)
            .as_millis()
            .saturating_add(SEND_MARGIN.as_millis());
        let sent = async {
            self.uart.write_all(bytes).await?;
            self.uart.flush().await
        };
        match with_timeout(Duration::from_millis(deadline), sent).await {
            Ok(sent) => sent.map_err(LineError::Uart),
            Err(_) => Err(LineError::Stalled),
        }
    }
}

/// A VE.Direct port's receiver.
pub struct VeDirectLine {
    rx: RingBufferedUartRx<'static>,
}

impl VeDirectLine {
    /// The port's receiver, already started.
    pub const fn new(rx: RingBufferedUartRx<'static>) -> Self {
        Self { rx }
    }
}

impl ReceiveLine for VeDirectLine {
    type Error = LineError;

    fn drain(&mut self, into: &mut [u8]) -> Result<usize, LineError> {
        match self.rx.read_ready() {
            Ok(false) => Ok(0),
            Ok(true) => match poll_once(self.rx.read(into)) {
                core::task::Poll::Ready(read) => read.map_err(LineError::Uart),
                core::task::Poll::Pending => Ok(0),
            },
            Err(error) => Err(LineError::Uart(error)),
        }
    }

    async fn read(&mut self, into: &mut [u8], within: Millis) -> Result<usize, LineError> {
        match with_timeout(duration(within), self.rx.read(into)).await {
            Ok(read) => read.map_err(LineError::Uart),
            Err(_) => Ok(0),
        }
    }
}

/// A [`Millis`] as the timer's duration.
pub const fn duration(millis: Millis) -> Duration {
    Duration::from_millis(millis.as_millis())
}

/// The pull a VE.Direct receive pin takes, from the revision's policy.
pub const fn vedirect_pull(input: VeDirectInput) -> Pull {
    match input {
        VeDirectInput::Floating => Pull::None,
        VeDirectInput::PullUp => Pull::Up,
    }
}

/// The UART configuration for `framing`, with the receive pin at `pull`.
pub fn config(framing: Framing, pull: Pull) -> Config {
    let mut config = Config::default();
    config.baudrate = framing.rate.get();
    // The UART's word includes the parity bit; embassy sets the length.
    config.data_bits = match framing.data_bits {
        DataBits::Seven => usart::DataBits::DataBits7,
        DataBits::Eight => usart::DataBits::DataBits8,
    };
    config.parity = match framing.parity {
        Parity::None => usart::Parity::ParityNone,
        Parity::Even => usart::Parity::ParityEven,
        Parity::Odd => usart::Parity::ParityOdd,
    };
    config.stop_bits = match framing.stop_bits {
        StopBits::One => usart::StopBits::STOP1,
        StopBits::Two => usart::StopBits::STOP2,
    };
    config.rx_pull = pull;
    config
}
