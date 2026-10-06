//! The 1-Wire line on `PC4`, bit-banged, behind `o89-drivers`' [`OneWire`]
//! seam.
//!
//! No peripheral is free for it, so each slot is the pin and CPU delay
//! loops whose length is calibrated when the line is built: a known count
//! of loops is timed against the time driver, and `o89-drivers`'
//! [`Calibration`] turns the standard slots into loops. The pin is open
//! drain: pulled low for a slot's low phase and released to R16's pull-up,
//! never driven high (`Line::OneWire`, released).
//!
//! Only the phases a device's timing is sampled inside run with interrupts
//! masked: a one's 6 µs low, and a read's 3 µs low and its sample 10 µs
//! later, inside the 15 µs a device holds the line. A longer phase, a
//! zero's low or a reset's, tolerates the few microseconds an interrupt
//! adds, and is left unmasked so the link's UART is never held off for a
//! slot. Every slot yields to the executor after it ends: a probe's read is
//! some 150 slots, and the tasks sharing the executor run between them.

use embassy_futures::yield_now;
use embassy_stm32::gpio::{Flex, Speed};
use embassy_time::Instant;
use o89_drivers::onewire::{CALIBRATION_LOOPS, Calibration, CalibrationError, STANDARD, Slots};
use o89_drivers::port::{OneWire, Presence};

/// What the line reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LineError {
    /// The line read low before a reset: a short, or a device stuck
    /// holding it.
    HeldLow,
}

/// The line, with its slots in delay loops.
pub struct Line {
    pin: Flex<'static>,
    delays: Slots,
}

impl Line {
    /// The pin, released, and its delays calibrated now.
    pub fn new(mut pin: Flex<'static>) -> Result<Self, CalibrationError> {
        pin.set_high();
        pin.set_as_input_output(Speed::Low);
        // Masked, so an interrupt in the count is not taken for a slow core;
        // about 6 ms at 64 MHz, once a boot.
        let elapsed = cortex_m::interrupt::free(|_| {
            let start = Instant::now();
            cortex_m::asm::delay(CALIBRATION_LOOPS);
            start.elapsed().as_micros()
        });
        let calibration = Calibration::from_count(
            CALIBRATION_LOOPS,
            u32::try_from(elapsed).unwrap_or(u32::MAX),
        )?;
        Ok(Self {
            pin,
            delays: calibration.delays(&STANDARD),
        })
    }
}

impl OneWire for Line {
    type Error = LineError;

    async fn reset(&mut self) -> Result<Presence, LineError> {
        if self.pin.is_low() {
            return Err(LineError::HeldLow);
        }
        self.pin.set_low();
        cortex_m::asm::delay(self.delays.reset_low);
        self.pin.set_high();
        cortex_m::asm::delay(self.delays.presence_sample);
        let present = self.pin.is_low();
        cortex_m::asm::delay(self.delays.reset_rest);
        yield_now().await;
        Ok(if present {
            Presence::Present
        } else {
            Presence::Absent
        })
    }

    async fn write_bit(&mut self, bit: bool) -> Result<(), LineError> {
        if bit {
            cortex_m::interrupt::free(|_| {
                self.pin.set_low();
                cortex_m::asm::delay(self.delays.one_low);
                self.pin.set_high();
            });
            cortex_m::asm::delay(self.delays.one_rest);
        } else {
            self.pin.set_low();
            cortex_m::asm::delay(self.delays.zero_low);
            self.pin.set_high();
            cortex_m::asm::delay(self.delays.zero_rest);
        }
        yield_now().await;
        Ok(())
    }

    async fn read_bit(&mut self) -> Result<bool, LineError> {
        let bit = cortex_m::interrupt::free(|_| {
            self.pin.set_low();
            cortex_m::asm::delay(self.delays.read_low);
            self.pin.set_high();
            cortex_m::asm::delay(self.delays.read_sample);
            self.pin.is_high()
        });
        cortex_m::asm::delay(self.delays.read_rest);
        yield_now().await;
        Ok(bit)
    }
}
