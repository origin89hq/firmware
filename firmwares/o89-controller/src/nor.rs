//! The W25Q128JV on SPI1: 16 MB of NOR in 4 KB sectors and 256-byte pages,
//! driven under the trait the ring is written against.
//!
//! The smallest driver that can identify, read, program and erase, and say
//! when the part is done. A program never crosses a page, an erase is a
//! whole sector, and both are waited out by polling the status register
//! with a deadline, so a part that never comes back is an error rather
//! than a task that never checks in. The part programs bits 1→0 and lets
//! a byte be programmed again, which is what the ring's magic-last write
//! needs and what `MultiwriteNorFlash` promises.
//!
//! The transfers are blocking behind the async seam: a record is under
//! three hundred bytes at 8 MHz, and the waits for an erase or a program
//! are sleeps, not spins. The DMA path hung on the bench on 2026-09-18
//! and is a bench question filed on its own.
//!
//! cites: F-023

use core::future::Future;

use embassy_stm32::gpio::Output;
use embassy_stm32::mode::Blocking;
use embassy_stm32::spi::Spi;
use embassy_stm32::spi::mode::Master;
use embassy_time::{Duration, Instant, Timer};
use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};

/// Bytes in one erase sector.
pub const SECTOR: usize = 4096;
/// Bytes in one program page.
pub const PAGE: usize = 256;
/// Bytes on the part.
pub const CAPACITY: usize = 16 * 1024 * 1024;
/// What the identification answers: Winbond, serial NOR, 128 Mbit.
pub const JEDEC: [u8; 3] = [0xEF, 0x40, 0x18];

const CMD_WRITE_ENABLE: u8 = 0x06;
const CMD_READ_STATUS_1: u8 = 0x05;
const CMD_READ: u8 = 0x03;
const CMD_PAGE_PROGRAM: u8 = 0x02;
const CMD_SECTOR_ERASE: u8 = 0x20;
const CMD_JEDEC: u8 = 0x9F;
const STATUS_BUSY: u8 = 0x01;

/// The datasheet's maximum page program time is 3 ms.
const PROGRAM_DEADLINE: Duration = Duration::from_millis(20);
/// The datasheet's maximum sector erase time is 400 ms.
const ERASE_DEADLINE: Duration = Duration::from_millis(600);

/// What the part or its bus reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum NorError {
    /// The SPI driver refused.
    Bus(embassy_stm32::spi::Error),
    /// The part stayed busy past the deadline.
    Busy,
    /// An address past the part.
    OutOfRange,
    /// An erase not on a sector boundary.
    NotAligned,
}

impl NorFlashError for NorError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            Self::Bus(_) | Self::Busy => NorFlashErrorKind::Other,
            Self::OutOfRange => NorFlashErrorKind::OutOfBounds,
            Self::NotAligned => NorFlashErrorKind::NotAligned,
        }
    }
}

/// The part, its bus and its chip select.
pub struct Nor {
    spi: Spi<'static, Blocking, Master>,
    cs: Output<'static>,
}

impl Nor {
    /// Take the bus. The chip select must already be high.
    pub const fn new(spi: Spi<'static, Blocking, Master>, cs: Output<'static>) -> Self {
        Self { spi, cs }
    }

    /// One command with the select held: the command bytes out, then
    /// `data` written or `into` read, then the select released.
    fn transaction(
        &mut self,
        command: &[u8],
        data: &[u8],
        into: &mut [u8],
    ) -> Result<(), NorError> {
        self.cs.set_low();
        let outcome = self.exchange(command, data, into);
        self.cs.set_high();
        outcome
    }

    fn exchange(&mut self, command: &[u8], data: &[u8], into: &mut [u8]) -> Result<(), NorError> {
        self.spi.blocking_write(command).map_err(NorError::Bus)?;
        if !data.is_empty() {
            self.spi.blocking_write(data).map_err(NorError::Bus)?;
        }
        if !into.is_empty() {
            self.spi.blocking_read(into).map_err(NorError::Bus)?;
        }
        Ok(())
    }

    fn command_at(command: u8, at: u32) -> [u8; 4] {
        let [_, a2, a1, a0] = at.to_be_bytes();
        [command, a2, a1, a0]
    }

    /// The three identification bytes.
    pub fn jedec(&mut self) -> Result<[u8; 3], NorError> {
        let mut id = [0u8; 3];
        self.transaction(&[CMD_JEDEC], &[], &mut id)?;
        Ok(id)
    }

    fn busy(&mut self) -> Result<bool, NorError> {
        let mut status = [0u8; 1];
        self.transaction(&[CMD_READ_STATUS_1], &[], &mut status)?;
        Ok(status.first().is_some_and(|s| s & STATUS_BUSY != 0))
    }

    /// Sleep until the part is idle, or give up after `deadline`.
    async fn wait_ready(&mut self, deadline: Duration) -> Result<(), NorError> {
        let until = Instant::now().checked_add(deadline).ok_or(NorError::Busy)?;
        // Bounded by the deadline: every turn sleeps a millisecond.
        loop {
            if !self.busy()? {
                return Ok(());
            }
            if Instant::now() > until {
                return Err(NorError::Busy);
            }
            Timer::after_millis(1).await;
        }
    }

    fn write_enable(&mut self) -> Result<(), NorError> {
        self.transaction(&[CMD_WRITE_ENABLE], &[], &mut [])
    }

    fn in_range(at: u32, len: usize) -> Result<(), NorError> {
        let end = usize::try_from(at)
            .ok()
            .and_then(|at| at.checked_add(len))
            .ok_or(NorError::OutOfRange)?;
        if end > CAPACITY {
            return Err(NorError::OutOfRange);
        }
        Ok(())
    }
}

impl ErrorType for Nor {
    type Error = NorError;
}

impl ReadNorFlash for Nor {
    const READ_SIZE: usize = 1;

    fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<(), NorError>> {
        let outcome = Self::in_range(offset, bytes.len()).and_then(|()| {
            if bytes.is_empty() {
                Ok(())
            } else {
                self.transaction(&Self::command_at(CMD_READ, offset), &[], bytes)
            }
        });
        core::future::ready(outcome)
    }

    fn capacity(&self) -> usize {
        CAPACITY
    }
}

impl NorFlash for Nor {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = SECTOR;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), NorError> {
        let sector = u32::try_from(SECTOR).map_err(|_| NorError::OutOfRange)?;
        if from.checked_rem(sector) != Some(0) || to.checked_rem(sector) != Some(0) || to < from {
            return Err(NorError::NotAligned);
        }
        let len = usize::try_from(to.saturating_sub(from)).map_err(|_| NorError::OutOfRange)?;
        Self::in_range(from, len)?;
        let mut at = from;
        // Bounded by the range: each turn erases one sector.
        while at < to {
            self.write_enable()?;
            self.transaction(&Self::command_at(CMD_SECTOR_ERASE, at), &[], &mut [])?;
            self.wait_ready(ERASE_DEADLINE).await?;
            at = at.saturating_add(sector);
        }
        Ok(())
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), NorError> {
        Self::in_range(offset, bytes.len())?;
        let page = u32::try_from(PAGE).map_err(|_| NorError::OutOfRange)?;
        let mut at = offset;
        let mut rest = bytes;
        // Bounded by the bytes: each turn programs up to the end of a page.
        while !rest.is_empty() {
            let room = page.saturating_sub(at.checked_rem(page).unwrap_or(0));
            let take = rest.len().min(usize::try_from(room).unwrap_or(rest.len()));
            let (chunk, after) = rest.split_at(take);
            self.write_enable()?;
            self.transaction(&Self::command_at(CMD_PAGE_PROGRAM, at), chunk, &mut [])?;
            self.wait_ready(PROGRAM_DEADLINE).await?;
            at = at.saturating_add(u32::try_from(take).map_err(|_| NorError::OutOfRange)?);
            rest = after;
        }
        Ok(())
    }
}

impl MultiwriteNorFlash for Nor {}
