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

/// Why a burst ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Ended {
    /// The line went idle for the framing's inter-frame gap: the frame
    /// ended here.
    Gap,
    /// The buffer filled before the line went idle: the frame may go on.
    Full,
}

/// What one receive delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Burst {
    /// The bytes written at the front of the buffer, at least one.
    pub len: usize,
    /// Why the burst ended: [`Ended::Full`] exactly when `len` is the
    /// buffer's length, and [`Ended::Gap`] only with room left.
    pub ended: Ended,
}

/// An RS-485 byte port.
///
/// The board's transceivers switch direction by themselves and keep the
/// receiver on, so every byte sent is heard back first (F-050). The port
/// does not hide that; the Modbus framing discards it.
pub trait Rs485 {
    /// What the line reports.
    type Error;

    /// Drop every byte received before this call and not yet handed out,
    /// returning at once without waiting on the line: what a refused or
    /// late exchange left behind never reaches the next one.
    fn discard(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Send `bytes` as one frame, returning once the last one has left.
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;

    /// Wait at most `within` for the first byte, then return the burst that
    /// arrived with it: every byte until the line has been idle for the
    /// framing's inter-frame gap, or until `into` is full, and which of the
    /// two ended it. A burst that ends at the gap is a whole frame, or the
    /// frames the line carried back to back without a gap between them.
    ///
    /// `within` bounds only the wait for the first byte; the burst then
    /// takes its wire time and the gap, which the framing decides.
    /// [`PortFault::Timeout`] when nothing arrived before the deadline. A
    /// reader refuses a burst of no bytes, more bytes than `into` holds,
    /// [`Ended::Full`] with room left, or [`Ended::Gap`] with none, as the
    /// adapter's defect.
    fn receive(
        &mut self,
        into: &mut [u8],
        within: Millis,
    ) -> impl Future<Output = Result<Burst, PortFault<Self::Error>>>;
}

/// The largest CAN 2.0 payload.
pub const CAN_DATA_BYTES: usize = 8;

/// A CAN identifier, standard or extended, that fits its width: built only
/// through [`CanId::standard`] and [`CanId::extended`].
///
/// ```compile_fail
/// use o89_drivers::port::CanId;
///
/// let too_wide = CanId { raw: 0x800, extended: false };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CanId {
    raw: u32,
    extended: bool,
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
            return None;
        }
        let [high, low] = id.to_be_bytes();
        Some(Self {
            raw: u32::from_be_bytes([0, 0, high, low]),
            extended: false,
        })
    }

    /// A 29-bit identifier, or `None` when `id` needs more bits.
    #[must_use]
    pub const fn extended(id: u32) -> Option<Self> {
        if id > Self::EXTENDED_MAX {
            return None;
        }
        Some(Self {
            raw: id,
            extended: true,
        })
    }

    /// The identifier's value, within its width.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.raw
    }

    /// Whether it is a 29-bit identifier.
    #[must_use]
    pub const fn is_extended(self) -> bool {
        self.extended
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
        let top = CanId::standard(0x7FF).unwrap();
        assert_eq!((top.raw(), top.is_extended()), (0x7FF, false));
        assert_eq!(CanId::standard(0x800), None);
        assert_eq!(CanId::standard(u16::MAX), None);
        let top = CanId::extended(0x1FFF_FFFF).unwrap();
        assert_eq!((top.raw(), top.is_extended()), (0x1FFF_FFFF, true));
        assert_eq!(CanId::extended(0x2000_0000), None);
        assert_eq!(CanId::extended(u32::MAX), None);
        // The same number in either width is a different identifier.
        assert_ne!(CanId::standard(0x351), CanId::extended(0x351));
        assert_eq!(CanId::standard(0).map(CanId::raw), Some(0));
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
