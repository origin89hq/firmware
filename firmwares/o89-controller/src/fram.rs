//! The FM24W256 on I2C2, under the discipline the seven brown-outs taught:
//! no transaction starts on a falling supply, and one in flight completes.
//!
//! The part is 32 KB of ferroelectric RAM, byte-addressed, no erase, no
//! write latency, with a two-byte address in front of every transaction.
//! What is stored where is `o89-core`'s business; this moves bytes and
//! refuses to start moving them when the voltage detector says the supply
//! is below the level it was armed at (F-021). A transaction the bus has
//! started runs to its end on the part's own energy, which is what makes
//! *refuse to start* the whole of the rule.
//!
//! The transfers are blocking behind the async seam. The DMA path timed
//! out on the bench on 2026-09-18 while the blocking one, the self-test's
//! since 2026-09-14, answered; the longest transfer, the client table, is
//! about thirty milliseconds at 400 kHz, which the executor absorbs. The
//! DMA path is a bench question filed on its own, not a rule.
//!
//! Past the boot the part is shared: the recorder keeps the ladder's cuts
//! and serves the bench, the link task keeps the challenge counter and the
//! client table, and each writes only its own records. They meet at one
//! async mutex, a [`Lease`] each, held for one transfer: the transfer
//! blocks and never awaits, so the lock never waits on anything but the
//! transfer in front of it, and a NOR erase in the recorder never holds a
//! challenge back.
//!
//! cites: F-021

use core::future::Future;

use embassy_stm32::i2c::{I2c, Master};
use embassy_stm32::mode::Blocking;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use o89_core::{Address, FRAM_BYTES, Fram as FramSeam, Refused};
use static_cell::StaticCell;

use crate::pvd;

/// The part's 7-bit address with A2, A1 and A0 tied low (U9).
pub const ADDRESS: u8 = 0x50;

/// What the bus reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum FramError {
    /// The I2C driver refused or timed out.
    Bus(embassy_stm32::i2c::Error),
    /// An address past the part: a map that is wrong.
    OutOfRange,
}

/// The part and the bus it is on.
pub struct Fram {
    i2c: I2c<'static, Blocking, Master>,
}

impl Fram {
    /// Take the bus. Nothing is touched until the first access.
    pub const fn new(i2c: I2c<'static, Blocking, Master>) -> Self {
        Self { i2c }
    }

    const fn in_range(at: Address, len: usize) -> Result<(), FramError> {
        let end = (at.0 as usize).saturating_add(len);
        if end > FRAM_BYTES {
            return Err(FramError::OutOfRange);
        }
        Ok(())
    }
}

impl FramSeam for Fram {
    type Error = FramError;

    fn read(
        &mut self,
        at: Address,
        into: &mut [u8],
    ) -> impl Future<Output = Result<(), FramError>> {
        core::future::ready(self.read_now(at, into))
    }

    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<FramError>>> {
        core::future::ready(self.write_now(at, bytes))
    }
}

impl Fram {
    fn read_now(&mut self, at: Address, into: &mut [u8]) -> Result<(), FramError> {
        Self::in_range(at, into.len())?;
        self.i2c
            .blocking_write_read(ADDRESS, &at.0.to_be_bytes(), into)
            .map_err(FramError::Bus)
    }

    fn write_now(&mut self, at: Address, bytes: &[u8]) -> Result<(), Refused<FramError>> {
        Self::in_range(at, bytes.len()).map_err(Refused::Bus)?;
        // The rule: nothing starts on a falling supply. Read at the last
        // instant before the bus is claimed.
        if pvd::supply_is_below_level() {
            return Err(Refused::SupplyFalling);
        }
        self.i2c
            .blocking_write_vectored(ADDRESS, &[&at.0.to_be_bytes(), bytes])
            .map_err(|error| Refused::Bus(FramError::Bus(error)))
    }
}

/// The part, once the boot hands it over.
static SHARED: StaticCell<Mutex<CriticalSectionRawMutex, Fram>> = StaticCell::new();

/// One task's way to the part: a transfer at a time, under the lock.
#[derive(Clone, Copy)]
pub struct Lease(&'static Mutex<CriticalSectionRawMutex, Fram>);

/// Hand the part over after the boot, once, as a lease that copies to
/// every task that keeps records on it.
pub fn share(fram: Fram) -> Lease {
    Lease(SHARED.init(Mutex::new(fram)))
}

impl FramSeam for Lease {
    type Error = FramError;

    fn read(
        &mut self,
        at: Address,
        into: &mut [u8],
    ) -> impl Future<Output = Result<(), FramError>> {
        let part = self.0;
        async move { part.lock().await.read_now(at, into) }
    }

    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<FramError>>> {
        let part = self.0;
        async move { part.lock().await.write_now(at, bytes) }
    }
}
