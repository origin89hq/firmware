//! ADC1 and the controller's own inputs, behind `o89-drivers`' [`Sampler`]
//! seam: `VREFINT` first, scaled against its factory calibration, then
//! each input (`o89-drivers`' `adc` module).
//!
//! A conversion takes microseconds on the part's own clock, so it is the
//! blocking read: a pass is some sixty-four of them, well under a
//! millisecond of the executor.

use embassy_stm32::adc::{Adc, SampleTimeOf, VrefInt};
use embassy_stm32::mode::Blocking;
use embassy_stm32::peripherals::ADC1;
use o89_core::{Readings, Tick};
use o89_drivers::adc::{self, AdcError, Input, Sampled, VrefintCal};
use o89_drivers::port::{AdcInput, Counts};

use crate::board::{AdcPins, HOUSE_CHANNEL, START_CHANNEL, TANK_CHANNEL};

/// What the converter reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum SampleError {
    /// A channel the board has not wired.
    Unwired(u8),
}

/// How long each conversion samples, in microseconds: `VREFINT` needs
/// 4 µs (DS13560), and the dividers' source impedance is about 9 kΩ.
const SAMPLE_US: u32 = 20;

/// The converter, the reference and the board's three inputs.
pub struct Sampler {
    adc: Adc<'static, ADC1, Blocking>,
    vrefint: VrefInt,
    pins: AdcPins,
    cal: Option<VrefintCal>,
    sample: SampleTimeOf<ADC1>,
    inputs: [Input; 3],
}

impl Sampler {
    /// ADC1 with the reference enabled, and `inputs` on `pins`.
    pub fn new(mut adc: Adc<'static, ADC1, Blocking>, pins: AdcPins, inputs: [Input; 3]) -> Self {
        let vrefint = adc.enable_vrefint();
        let cal = VrefintCal::new(stm32_metapac::VREFINTCAL.data().read());
        let sample = adc.sample_time_for_us(SAMPLE_US);
        Self {
            adc,
            vrefint,
            pins,
            cal,
            sample,
            inputs,
        }
    }

    /// One pass over every input into `store` at `now`.
    pub async fn read<R: Readings>(&mut self, now: Tick, store: &mut R) -> Result<Sampled, Pass> {
        let cal = self.cal.ok_or(Pass::Calibration)?;
        let inputs = self.inputs;
        adc::read(self, cal, &inputs, now, store)
            .await
            .map_err(Pass::Adc)
    }
}

/// Why a pass wrote nothing, or stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Pass {
    /// The factory's `VREFINT_CAL` is outside what the datasheet allows:
    /// nothing can be scaled against it.
    Calibration,
    /// The driver stopped.
    Adc(AdcError<SampleError>),
}

impl o89_drivers::port::Sampler for Sampler {
    type Error = SampleError;

    fn sample(
        &mut self,
        input: AdcInput,
    ) -> impl core::future::Future<Output = Result<Counts, SampleError>> {
        let sample = self.sample;
        let counts = match input {
            AdcInput::Reference => self.adc.blocking_read(&mut self.vrefint, sample),
            AdcInput::Channel(HOUSE_CHANNEL) => {
                self.adc.blocking_read(&mut self.pins.house, sample)
            }
            AdcInput::Channel(START_CHANNEL) => {
                self.adc.blocking_read(&mut self.pins.start, sample)
            }
            AdcInput::Channel(TANK_CHANNEL) => self.adc.blocking_read(&mut self.pins.tank, sample),
            AdcInput::Channel(other) => {
                return core::future::ready(Err(SampleError::Unwired(other)));
            }
        };
        core::future::ready(Ok(Counts(counts)))
    }
}
