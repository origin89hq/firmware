//! The seams every driver reads through, one per kind of line.
//!
//! Nothing here names a peripheral. The controller implements each trait
//! over its own UART, FDCAN, pin or ADC; a test implements it over a
//! captured or hand-built exchange, which is what makes a driver a host
//! test. Every wait a driver makes on a line has a deadline it passes in.

use core::future::Future;

use o89_core::Millis;

/// Why a receive produced nothing to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed receive is a device that did not answer"]
pub enum PortFault<E> {
    /// Nothing arrived before the deadline.
    Timeout,
    /// The line reported an error: framing, parity, overrun, a bus fault.
    Line(E),
}

/// An RS-485 byte port.
///
/// The board's transceivers switch direction by themselves and keep the
/// receiver on, so every byte sent is heard back first (F-050). The port
/// does not hide that; the Modbus framing discards it.
pub trait Rs485 {
    /// What the line reports.
    type Error;

    /// Send `bytes` as one frame, returning once the last one has left.
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;

    /// Wait at most `within` for the first byte, then return the burst that
    /// arrived with it: every byte until the line has been idle for the
    /// framing's inter-frame gap, or until `into` is full.
    ///
    /// Returns the number of bytes written into `into`, at least one.
    /// [`PortFault::Timeout`] when none arrived before the deadline.
    fn receive(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> impl Future<Output = Result<usize, PortFault<Self::Error>>>;
}

/// The largest CAN 2.0 payload.
pub const CAN_DATA_BYTES: usize = 8;

/// A CAN identifier, standard or extended, refused when it does not fit its
/// width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CanId {
    /// An 11-bit identifier.
    Standard(u16),
    /// A 29-bit identifier.
    Extended(u32),
}

impl CanId {
    /// The largest 11-bit identifier.
    const STANDARD_MAX: u16 = 0x7FF;
    /// The largest 29-bit identifier.
    const EXTENDED_MAX: u32 = 0x1FFF_FFFF;

    /// An 11-bit identifier, or `None` when `id` needs more bits.
    #[must_use]
    pub const fn standard(id: u16) -> Option<Self> {
        if id > Self::STANDARD_MAX {
            None
        } else {
            Some(Self::Standard(id))
        }
    }

    /// A 29-bit identifier, or `None` when `id` needs more bits.
    #[must_use]
    pub const fn extended(id: u32) -> Option<Self> {
        if id > Self::EXTENDED_MAX {
            None
        } else {
            Some(Self::Extended(id))
        }
    }
}

/// One classic CAN data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CanFrame {
    id: CanId,
    len: u8,
    data: [u8; CAN_DATA_BYTES],
}

impl CanFrame {
    /// A frame carrying `data`, or `None` past eight bytes.
    #[must_use]
    pub fn new(id: CanId, data: &[u8]) -> Option<Self> {
        let len = u8::try_from(data.len()).ok()?;
        let mut bytes = [0; CAN_DATA_BYTES];
        bytes.get_mut(..data.len())?.copy_from_slice(data);
        Some(Self {
            id,
            len,
            data: bytes,
        })
    }

    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> CanId {
        self.id
    }

    /// The payload, zero to eight bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// A CAN port.
pub trait Can {
    /// What the controller reports: bus-off, error passive, overrun.
    type Error;

    /// Queue `frame` for transmission.
    fn send(&mut self, frame: &CanFrame) -> impl Future<Output = Result<(), Self::Error>>;

    /// Wait at most `within` for the next frame.
    fn receive(
        &mut self,
        within: Millis,
    ) -> impl Future<Output = Result<CanFrame, PortFault<Self::Error>>>;
}

/// Whether anything answered a 1-Wire reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Presence {
    /// A device pulled the line low in the presence window.
    Present,
    /// Nothing did: no probe on the line.
    Absent,
}

/// A 1-Wire line.
///
/// Each operation is one slot of the protocol, microseconds long, timed by
/// the adapter from delays it calibrated at construction; none waits on a
/// device, so none takes a deadline. A line held low reads as a fault, not
/// as a device.
pub trait OneWire {
    /// What the line reports, such as a line held low.
    type Error;

    /// A reset pulse and the presence window after it.
    fn reset(&mut self) -> impl Future<Output = Result<Presence, Self::Error>>;

    /// One write slot.
    fn write_bit(&mut self, bit: bool) -> impl Future<Output = Result<(), Self::Error>>;

    /// One read slot.
    fn read_bit(&mut self) -> impl Future<Output = Result<bool, Self::Error>>;
}

/// An input the ADC can convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdcInput {
    /// The part's internal reference, which every other conversion is
    /// scaled against.
    Reference,
    /// An external input, numbered by the board's configuration.
    Channel(u8),
}

/// One conversion's raw result, in counts of the converter's resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Counts(pub u16);

/// An ADC sampler.
///
/// A conversion completes in microseconds on the part's own clock, so it
/// takes no deadline; an adapter whose conversion can stall reports that as
/// an error rather than waiting.
pub trait Sampler {
    /// What the converter reports: an input the board has not wired, an
    /// overrun.
    type Error;

    /// Convert `input` once.
    fn sample(&mut self, input: AdcInput) -> impl Future<Output = Result<Counts, Self::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_can_identifier_is_refused_past_its_width_and_accepted_at_it() {
        assert_eq!(CanId::standard(0x7FF), Some(CanId::Standard(0x7FF)));
        assert_eq!(CanId::standard(0x800), None);
        assert_eq!(
            CanId::extended(0x1FFF_FFFF),
            Some(CanId::Extended(0x1FFF_FFFF))
        );
        assert_eq!(CanId::extended(0x2000_0000), None);
        assert_eq!(CanId::standard(0), Some(CanId::Standard(0)));
    }

    #[test]
    fn a_can_frame_carries_zero_to_eight_bytes_and_refuses_nine() {
        let id = CanId::standard(0x351).unwrap();
        let empty = CanFrame::new(id, &[]).unwrap();
        assert_eq!(empty.data(), &[] as &[u8]);
        let full = CanFrame::new(id, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(full.data(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(full.id(), id);
        assert_eq!(CanFrame::new(id, &[0; 9]), None);
    }
}
