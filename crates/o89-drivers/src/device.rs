//! The devices a site can have, and the one call that reads each.
//!
//! A closed set, so an enum: a dialect lands as a variant, and every match
//! that has to answer for it stops compiling until it does. A bus task owns
//! its port and calls the poll entry for its kind of bus. Every device today
//! is on RS-485; the first device on another bus brings its own entry and a
//! refusal of devices on the wrong one, which configuration checks against
//! [`Device::bus`] before either runs.

use km43::Id;
use o89_core::{SignalError, Signals, Tick};

use crate::dialect::{DecodeError, RegisterMap};
use crate::modbus::{self, Address, ModbusError, RECEIVE_BYTES, Timing};
use crate::port::Rs485;

/// The kinds of line a device can be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BusKind {
    /// An RS-485 byte port.
    Rs485,
    /// A CAN port.
    Can,
    /// A 1-Wire line.
    OneWire,
    /// The ADC.
    Adc,
}

/// A Modbus server and the store signals its register map's cells publish
/// as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ModbusDevice {
    address: Address,
    map: &'static RegisterMap,
    first: Id,
}

impl ModbusDevice {
    /// The server at `address` speaking `map`, whose cells publish as
    /// consecutive signals from `first` in the map's poll order.
    ///
    /// `None` when the map has no cells, which would poll as a silent
    /// device, or when the signals would run past `0xFFFF`. Keeping ranges
    /// of different devices apart is the configuration's to check.
    #[must_use]
    pub fn new(address: Address, map: &'static RegisterMap, first: Id) -> Option<Self> {
        let cells = u16::try_from(map.cells().count()).ok()?;
        first.get().checked_add(cells.checked_sub(1)?)?;
        Some(Self {
            address,
            map,
            first,
        })
    }

    /// The server's address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The register map.
    #[must_use]
    pub const fn map(&self) -> &'static RegisterMap {
        self.map
    }

    /// The signal the map's `index`th cell publishes as.
    #[must_use]
    pub fn signal(&self, index: usize) -> Option<Id> {
        let offset = u16::try_from(index).ok()?;
        Id::new(self.first.get().checked_add(offset)?).ok()
    }
}

/// A device on the site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Device {
    /// A Modbus RTU server described by a register map.
    Modbus(ModbusDevice),
}

/// Why a poll stopped.
///
/// Whatever was written before the failure stands; the rest of the device's
/// signals keep their last values and age out through the store's maximum
/// age. A failed exchange writes nothing, so a garbled reply never
/// replaces a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed poll is a device whose readings were not refreshed"]
pub enum PollError<E> {
    /// The read of the block at `block` failed.
    Modbus {
        /// The block's position in the map.
        block: usize,
        /// Why.
        error: ModbusError<E>,
    },
    /// The cell at `cell`, counted across the map, could not be decoded.
    Decode {
        /// The cell's position in the map.
        cell: usize,
        /// Why.
        error: DecodeError,
    },
    /// The store refused a write.
    Store(SignalError),
    /// The device's signals run past `0xFFFF`, which [`ModbusDevice::new`]
    /// refuses; reported rather than wrapped onto another device's.
    Signals,
}

/// What a poll wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a poll's outcome is the device's presence"]
pub struct Polled {
    /// The signals written, one per cell.
    pub written: usize,
}

impl Device {
    /// The kind of bus it is on.
    #[must_use]
    pub const fn bus(&self) -> BusKind {
        match self {
            Self::Modbus(_) => BusKind::Rs485,
        }
    }

    /// Read the device over an RS-485 port and write every cell into
    /// `store` at `now`, with its declared provenance.
    ///
    /// Each block is one exchange bounded by `timing`; the poll stops at the
    /// first failure.
    pub async fn poll_rs485<P: Rs485, const N: usize>(
        &self,
        port: &mut P,
        timing: Timing,
        now: Tick,
        store: &mut Signals<N>,
    ) -> Result<Polled, PollError<P::Error>> {
        match self {
            Self::Modbus(device) => poll_modbus(device, port, timing, now, store).await,
        }
    }
}

async fn poll_modbus<P: Rs485, const N: usize>(
    device: &ModbusDevice,
    port: &mut P,
    timing: Timing,
    now: Tick,
    store: &mut Signals<N>,
) -> Result<Polled, PollError<P::Error>> {
    let mut cell = 0usize;
    let mut buf = [0u8; RECEIVE_BYTES];
    for (block_at, block) in device.map.blocks.iter().enumerate() {
        let read = block.read(device.address);
        let registers = modbus::read(port, read, timing, &mut buf)
            .await
            .map_err(|error| PollError::Modbus {
                block: block_at,
                error,
            })?;
        for seen in block.decode(&registers) {
            let seen = seen.map_err(|error| PollError::Decode { cell, error })?;
            let sig = device.signal(cell).ok_or(PollError::Signals)?;
            store.write(sig, now, seen).map_err(PollError::Store)?;
            cell = cell.saturating_add(1);
        }
    }
    Ok(Polled { written: cell })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::tests::cell;
    use crate::dialect::{Block, Kind};
    use crate::modbus::tests::{Scripted, TIMING};
    use crate::modbus::{Function, ReplyError};
    use embassy_futures::block_on;
    use km43::{Dialect, Provenance, SignalDomain, Validity};
    use o89_core::{ChargeSource, Ineligible, Limits, Millis};

    /// Two blocks built by hand for these tests; not a vendor's map.
    static FIRST: [crate::dialect::Cell; 2] = [
        cell(
            0x10,
            Kind::DcVoltage,
            SignalDomain::Live,
            -2,
            Provenance::Measured,
        ),
        cell(
            0x11,
            Kind::StateOfCharge,
            SignalDomain::Live,
            0,
            Provenance::Estimated,
        ),
    ];
    static SECOND: [crate::dialect::Cell; 1] = [cell(
        0x40,
        Kind::DcCurrent,
        SignalDomain::LimitUpper,
        -2,
        Provenance::Reported,
    )];
    static BLOCKS: [Block; 2] = [
        crate::block!(Function::ReadInput, 0x10, 2, &FIRST),
        crate::block!(Function::ReadHolding, 0x40, 1, &SECOND),
    ];
    static EMPTY: RegisterMap = RegisterMap {
        dialect: Dialect(0xF001),
        blocks: &[],
    };
    static MAP: RegisterMap = RegisterMap {
        dialect: Dialect(0xF000),
        blocks: &BLOCKS,
    };

    /// A counted state of charge in tenths of a percent, signed, built by
    /// hand; not a vendor's row.
    static SOC_CELLS: [crate::dialect::Cell; 1] = [crate::dialect::Cell {
        sign: crate::dialect::Sign::Signed,
        ..cell(
            0x20,
            Kind::StateOfCharge,
            SignalDomain::Live,
            -1,
            Provenance::Counted,
        )
    }];
    static SOC_BLOCKS: [Block; 1] = [crate::block!(Function::ReadInput, 0x20, 1, &SOC_CELLS)];
    static SOC_MAP: RegisterMap = RegisterMap {
        dialect: Dialect(0xF002),
        blocks: &SOC_BLOCKS,
    };

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    fn device() -> Device {
        Device::Modbus(ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(20)).unwrap())
    }

    fn store() -> Signals<4> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
        for n in 20..=22 {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    fn reply(function: u8, words: &[u16]) -> ([u8; crate::modbus::FRAME_BYTES], usize) {
        crate::modbus::tests::register_reply(7, function, words)
    }

    fn echo(block: usize) -> [u8; 8] {
        BLOCKS[block].read(Address::new(7).unwrap()).encode()
    }

    #[test]
    fn f_052_a_poll_writes_every_cell_with_its_declared_provenance() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (second, second_len) = reply(0x03, &[5000]);
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = store();

        let polled =
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)).unwrap();
        assert_eq!(polled, Polled { written: 3 });

        let volts = store.sample(id(20), Tick::ZERO).unwrap();
        assert_eq!(
            (volts.value(), volts.q.provenance_of()),
            (Some(13_250), Provenance::Measured)
        );
        let soc = store.sample(id(21), Tick::ZERO).unwrap();
        assert_eq!(
            (soc.value(), soc.q.provenance_of()),
            (Some(640), Provenance::Estimated)
        );
        let limit = store.sample(id(22), Tick::ZERO).unwrap();
        assert_eq!(
            (limit.value(), limit.q.provenance_of()),
            (Some(50_000), Provenance::Reported)
        );
        assert_eq!(
            store.current(id(21), Tick::ZERO, ChargeSource::CountedOnly.accepts()),
            Err(Ineligible::Provenance(Provenance::Estimated))
        );
    }

    #[test]
    fn an_implausible_state_of_charge_is_out_of_range_and_never_eligible() {
        let soc =
            Device::Modbus(ModbusDevice::new(Address::new(7).unwrap(), &SOC_MAP, id(30)).unwrap());
        let read = SOC_BLOCKS[0].read(Address::new(7).unwrap());
        for (raw, expected) in [
            ((-1i16).cast_unsigned(), None),
            (0, Some(0)),
            (1000, Some(1000)),
            (1001, None),
            (0x7FFF, None),
        ] {
            let mut store = Signals::<1>::new();
            let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
            store.register(id(30), limits).unwrap();
            let echo = read.encode();
            let (frame, len) = reply(0x04, &[raw]);
            let bursts: [&[u8]; 2] = [&echo, &frame[..len]];
            let mut port = Scripted::new(&bursts);
            let polled = block_on(soc.poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store));
            assert_eq!(polled, Ok(Polled { written: 1 }), "{raw}");

            let eligible = store.current(id(30), Tick::ZERO, ChargeSource::CountedOnly.accepts());
            match expected {
                Some(value) => {
                    let eligible = eligible.unwrap();
                    assert_eq!(
                        (eligible.value(), eligible.provenance()),
                        (value, Provenance::Counted)
                    );
                }
                None => assert_eq!(
                    eligible,
                    Err(Ineligible::NoValue(Validity::OutOfRange)),
                    "{raw}"
                ),
            }
        }
    }

    #[test]
    fn a_failed_block_stops_the_poll_writes_nothing_for_it_and_keeps_what_came_before() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (mut second, second_len) = reply(0x03, &[5000]);
        second[4] ^= 1;
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = store();

        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(PollError::Modbus {
                block: 1,
                error: ModbusError::Reply(ReplyError::Crc)
            })
        );
        assert_eq!(
            store.sample(id(20), Tick::ZERO).unwrap().value(),
            Some(13_250)
        );
        // The limit was never read, so it has never had a value.
        let limit = store.sample(id(22), Tick::ZERO).unwrap();
        assert_eq!(limit.value(), None);
        assert_eq!(limit.q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn a_device_that_never_answers_writes_nothing_and_ages_out_through_the_store() {
        let mut store = store();
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let (second, second_len) = reply(0x03, &[5000]);
        let (e0, e1) = (echo(0), echo(1));
        let bursts: [&[u8]; 4] = [&e0, &first[..first_len], &e1, &second[..second_len]];
        let mut port = Scripted::new(&bursts);
        let _ = block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)).unwrap();

        let bursts: [&[u8]; 1] = [&e0];
        let mut port = Scripted::new(&bursts);
        let later = Tick::from_millis(60_001);
        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, later, &mut store)),
            Err(PollError::Modbus {
                block: 0,
                error: ModbusError::Timeout
            })
        );
        let volts = store.sample(id(20), later).unwrap();
        assert_eq!(volts.q.validity_of(), Validity::Stale);
        assert_eq!(volts.value(), Some(13_250));
    }

    #[test]
    fn a_write_to_a_signal_the_store_does_not_hold_is_refused() {
        let (first, first_len) = reply(0x04, &[1325, 64]);
        let e0 = echo(0);
        let bursts: [&[u8]; 2] = [&e0, &first[..first_len]];
        let mut port = Scripted::new(&bursts);
        let mut store = Signals::<4>::new();
        assert_eq!(
            block_on(device().poll_rs485(&mut port, TIMING, Tick::ZERO, &mut store)),
            Err(PollError::Store(SignalError::Unknown(id(20))))
        );
    }

    #[test]
    fn a_device_s_signals_are_consecutive_and_refused_past_the_top_of_the_range() {
        let Device::Modbus(device) = device();
        assert_eq!(
            device.bus_signals(),
            [Some(id(20)), Some(id(21)), Some(id(22))]
        );
        assert_eq!(Device::Modbus(device).bus(), BusKind::Rs485);
        assert!(ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(0xFFFD)).is_some());
        assert_eq!(
            ModbusDevice::new(Address::new(7).unwrap(), &MAP, id(0xFFFE)),
            None
        );
        assert_eq!(
            ModbusDevice::new(Address::new(7).unwrap(), &EMPTY, id(1)),
            None
        );
    }

    impl ModbusDevice {
        fn bus_signals(&self) -> [Option<Id>; 3] {
            [self.signal(0), self.signal(1), self.signal(2)]
        }
    }
}
