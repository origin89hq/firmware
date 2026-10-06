//! FDCAN1 on CN5, classic CAN, behind `o89-drivers`' [`Can`] seam.
//!
//! The peripheral is configured only when the configuration puts a device
//! on the bus: until then `PB9` is analogue from reset and the transceiver
//! holds its undriven `TXD` recessive (`Line::CanTx`, released). Once
//! configured, FDCAN1 drives it recessive whenever it is not sending, and
//! the only driver on this bus, a Pylontech-class BMS, never sends.

use embassy_stm32::can::enums::BusError;
use embassy_stm32::can::{Can as Fdcan, CanConfigurator};
use embassy_time::{Duration, with_timeout};
use o89_core::Millis;
use o89_drivers::port::{Can, CanFrame, CanId, PortFault};

use crate::serial::duration;

/// A bus error FDCAN1 counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Fault {
    /// More than five equal bits.
    Stuff,
    /// A fixed-format field malformed.
    Form,
    /// A frame sent and acknowledged by nobody.
    Acknowledge,
    /// A dominant bit sent and read back recessive.
    BitRecessive,
    /// A recessive bit sent and read back dominant.
    BitDominant,
    /// A received frame's CRC.
    Crc,
    /// The driver's own error.
    Software,
}

impl From<BusError> for Fault {
    fn from(error: BusError) -> Self {
        match error {
            BusError::Stuff => Self::Stuff,
            BusError::Form => Self::Form,
            BusError::Acknowledge => Self::Acknowledge,
            BusError::BitRecessive => Self::BitRecessive,
            BusError::BitDominant => Self::BitDominant,
            BusError::Crc => Self::Crc,
            BusError::Software => Self::Software,
        }
    }
}

/// What the bus reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CanError {
    /// A bus error the controller counted.
    Bus(Fault),
    /// A frame the seam cannot carry: a remote frame, or an identifier
    /// outside its width, which a classic controller never delivers.
    Frame,
    /// A frame did not leave inside its deadline.
    Stalled,
}

/// How long a frame may wait for a mailbox and the bus.
const SEND: Duration = Duration::from_millis(100);

/// The bus, in normal mode.
pub struct Port {
    can: Fdcan<'static>,
}

impl Port {
    /// FDCAN1 at `rate` bit/s, joined to the bus.
    pub fn new(mut configurator: CanConfigurator<'static>, rate: u32) -> Self {
        configurator.set_bitrate(rate);
        Self {
            can: configurator.into_normal_mode(),
        }
    }
}

impl Can for Port {
    type Error = CanError;

    async fn send(&mut self, frame: &CanFrame) -> Result<(), CanError> {
        let raw = if frame.id().is_extended() {
            embassy_stm32::can::Frame::new_extended(frame.id().raw(), frame.data())
        } else {
            let id = u16::try_from(frame.id().raw()).map_err(|_| CanError::Frame)?;
            embassy_stm32::can::Frame::new_standard(id, frame.data())
        }
        .map_err(|_| CanError::Frame)?;
        match with_timeout(SEND, self.can.write(&raw)).await {
            Ok(_) => Ok(()),
            Err(_) => Err(CanError::Stalled),
        }
    }

    async fn receive(&mut self, within: Millis) -> Result<CanFrame, PortFault<CanError>> {
        let envelope = match with_timeout(duration(within), self.can.read()).await {
            Ok(Ok(envelope)) => envelope,
            Ok(Err(error)) => return Err(PortFault::Line(CanError::Bus(error.into()))),
            Err(_) => return Err(PortFault::Timeout),
        };
        let frame = envelope.frame;
        let id = match frame.id() {
            embedded_can::Id::Standard(id) => CanId::standard(id.as_raw()),
            embedded_can::Id::Extended(id) => CanId::extended(id.as_raw()),
        };
        if frame.header().rtr() {
            return Err(PortFault::Line(CanError::Frame));
        }
        id.and_then(|id| CanFrame::new(id, frame.data()))
            .ok_or(PortFault::Line(CanError::Frame))
    }
}
