//! The onboard analogue inputs, over the [`Sampler`] seam.
//!
//! The converter measures against VDDA, which is the 3.3 V rail and is not
//! assumed: every pass converts the internal reference first and scales it
//! against `VREFINT_CAL`, the part's factory conversion of the same
//! reference at 3.0 V (RM0444, "Temperature sensor and internal reference
//! voltage"). Each input is then a voltage at its pin, kept as an exact
//! fraction of millivolts until the one rounding that makes it a published
//! value:
//!
//! - a [`Divider`] brings a battery down to the pin; the input is the pin
//!   times the ratio, published as a DC voltage in millivolts;
//! - a [`Loop`] is a 4–20 mA sender across a sense resistor; 4 mA is an
//!   empty tank and 20 mA a full one, both inclusive, published in tenths of
//!   a percent. A current below 4 mA or above 20 mA is no level at all and
//!   publishes `absent`: an open loop, a missing sender or a short.
//!
//! A conversion at the top of the converter's range is a voltage at or
//! above VDDA, not a reading, and publishes `out_of_range`; a loop whose
//! full scale already means more than 20 mA publishes `absent` instead,
//! because that much is known. A failed conversion or an implausible
//! reference writes nothing.
//!
//! Taken from the self-test (`origin89hq/origin89`,
//! `firmwares/o89-selftest/src/checks/adc.rs` and `calib.rs`): the
//! reference scaling, the sixteen-sample average, and the board's ÷11
//! dividers and 150 Ω sense resistor (`docs/BOARD-A.md`).

use km43::{Id, Provenance, QualityError, SignalDomain, Validity};
use o89_core::{Observation, SignalError, Signals, Tick};

use crate::dialect::Kind;
use crate::port::{AdcInput, Counts, Sampler};

/// The converter's largest count at 12 bits.
pub const FULL_SCALE: u16 = 4095;

/// Conversions averaged per input on each pass.
pub const SAMPLES: u16 = 16;

/// The VDDA at which `VREFINT_CAL` was taken, in millivolts (RM0444).
pub const CAL_VDDA_MV: u16 = 3000;

/// What a divider publishes as: millivolts.
pub const DIVIDER_KIND: Kind = Kind::DcVoltage;

/// What a tank loop publishes as: tenths of a percent.
pub const LOOP_KIND: Kind = Kind::TankLevel;

/// Every input reads what is at its pin.
const PROVENANCE: Provenance = Provenance::Measured;

// Each kind carries a measurement, at the scale the arithmetic below assumes.
const _: () = assert!(
    DIVIDER_KIND
        .accepts(SignalDomain::Live)
        .contains(PROVENANCE)
);
const _: () = assert!(LOOP_KIND.accepts(SignalDomain::Live).contains(PROVENANCE));
const _: () = assert!(DIVIDER_KIND.scale() == -3);
const _: () = assert!(LOOP_KIND.scale() == -1);

/// The factory conversion of the internal reference at [`CAL_VDDA_MV`].
///
/// Built only inside what the STM32G0B1 datasheet allows for `VREFINT`,
/// 1.182 to 1.232 V, so an erased or misread word is refused rather than scaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VrefintCal(u16);

impl VrefintCal {
    /// 1.182 V at 3.0 V, in counts, rounded down.
    pub const LOWEST: u16 = 1613;
    /// 1.232 V at 3.0 V, in counts, rounded up.
    pub const HIGHEST: u16 = 1682;

    /// The word the adapter read, or `None` outside the datasheet's range.
    #[must_use]
    pub const fn new(word: u16) -> Option<Self> {
        if word < Self::LOWEST || word > Self::HIGHEST {
            return None;
        }
        Some(Self(word))
    }

    /// The word.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The analogue supply, from a conversion of the internal reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Vdda {
    cal: VrefintCal,
    reference: u16,
}

/// Why a reference conversion gives no supply to scale against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused reference is a pass with nothing to scale against"]
pub enum ReferenceError {
    /// The reference converted to zero.
    Zero,
    /// The supply it implies is outside [`Vdda::LOWEST_MV`] to
    /// [`Vdda::HIGHEST_MV`].
    OutOfRange,
}

impl Vdda {
    /// The part's lowest analogue supply, 1.62 V.
    pub const LOWEST_MV: u32 = 1620;
    /// The part's highest analogue supply, 3.6 V.
    pub const HIGHEST_MV: u32 = 3600;

    /// The supply that makes the reference convert to `reference`.
    pub fn from_reference(cal: VrefintCal, reference: Counts) -> Result<Self, ReferenceError> {
        let Counts(reference) = reference;
        if reference == 0 {
            return Err(ReferenceError::Zero);
        }
        let vdda = Self { cal, reference };
        let lowest = u64::from(Self::LOWEST_MV).saturating_mul(u64::from(reference));
        let highest = u64::from(Self::HIGHEST_MV).saturating_mul(u64::from(reference));
        let exact = vdda.cal_product();
        if exact < lowest || exact > highest {
            return Err(ReferenceError::OutOfRange);
        }
        Ok(vdda)
    }

    /// The supply in millivolts, rounded to the nearest.
    #[must_use]
    pub fn millivolts(self) -> u32 {
        let rounded = divide_rounding(self.cal_product(), u64::from(self.reference));
        u32::try_from(rounded).unwrap_or(u32::MAX)
    }

    /// `CAL_VDDA_MV × VREFINT_CAL`: the supply times the reference's counts.
    fn cal_product(self) -> u64 {
        u64::from(CAL_VDDA_MV).saturating_mul(u64::from(self.cal.get()))
    }

    /// The voltage at a pin that converted to `counts`, exactly.
    fn pin(self, counts: u16) -> Pin {
        Pin {
            numerator: u64::from(counts).saturating_mul(self.cal_product()),
            denominator: u64::from(self.reference).saturating_mul(u64::from(FULL_SCALE)),
            saturated: counts >= FULL_SCALE,
        }
    }
}

/// A pin voltage of `numerator / denominator` millivolts, never zero below.
#[derive(Debug, Clone, Copy)]
struct Pin {
    numerator: u64,
    denominator: u64,
    /// The conversion hit the top: the pin is at or above this.
    saturated: bool,
}

/// A resistive divider in front of a pin: the input is the pin times
/// `(top + bottom) / bottom`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Divider {
    top_ohms: u32,
    bottom_ohms: u32,
}

impl Divider {
    /// Board A's battery dividers on `AIN_HOUSE` and `AIN_START`: 100 kΩ over
    /// 10 kΩ, one eleventh (`A-29`).
    pub const BOARD_A: Self = Self {
        top_ohms: 100_000,
        bottom_ohms: 10_000,
    };

    /// `top_ohms` over `bottom_ohms`, or `None` for a zero bottom.
    #[must_use]
    pub const fn new(top_ohms: u32, bottom_ohms: u32) -> Option<Self> {
        if bottom_ohms == 0 {
            return None;
        }
        Some(Self {
            top_ohms,
            bottom_ohms,
        })
    }

    /// The input in millivolts, or why there is none.
    fn observe(self, pin: Pin) -> Result<Observation, QualityError> {
        if pin.saturated {
            return Observation::missing(Validity::OutOfRange);
        }
        let total = u64::from(self.top_ohms).saturating_add(u64::from(self.bottom_ohms));
        let millivolts = divide_rounding(
            pin.numerator.saturating_mul(total),
            pin.denominator.saturating_mul(u64::from(self.bottom_ohms)),
        );
        match i32::try_from(millivolts) {
            Ok(millivolts) => Observation::value(millivolts, PROVENANCE),
            Err(_) => Observation::missing(Validity::OutOfRange),
        }
    }
}

/// A 4–20 mA current loop across a sense resistor to ground.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Loop {
    sense_ohms: u32,
}

impl Loop {
    /// Board A's tank sender on `AIN_TANK`: R46, 150 Ω, so 4–20 mA is 0.6 to
    /// 3.0 V at the pin (`A-27`).
    pub const BOARD_A: Self = Self { sense_ohms: 150 };

    /// The loop's lowest current, an empty tank, in milliamperes.
    pub const EMPTY_MA: u64 = 4;
    /// The loop's highest current, a full tank, in milliamperes.
    pub const FULL_MA: u64 = 20;

    /// A loop across `sense_ohms`, or `None` for zero.
    #[must_use]
    pub const fn new(sense_ohms: u32) -> Option<Self> {
        if sense_ohms == 0 {
            return None;
        }
        Some(Self { sense_ohms })
    }

    /// The level in tenths of a percent, or why there is none.
    fn observe(self, pin: Pin) -> Result<Observation, QualityError> {
        // `pin` millivolts across `sense` ohms is `pin / sense` milliamperes,
        // so a current of `ma` is a pin of `ma × sense × denominator` in the
        // numerator's terms, compared without rounding.
        let per_ma = pin.denominator.saturating_mul(u64::from(self.sense_ohms));
        let empty = per_ma.saturating_mul(Self::EMPTY_MA);
        let full = per_ma.saturating_mul(Self::FULL_MA);
        if pin.saturated {
            // At the top, the pin is at least full scale: more than 20 mA
            // when full scale is, and otherwise unknown.
            if pin.numerator > full {
                return Observation::missing(Validity::Absent);
            }
            return Observation::missing(Validity::OutOfRange);
        }
        if pin.numerator < empty || pin.numerator > full {
            return Observation::missing(Validity::Absent);
        }
        let span = full.saturating_sub(empty);
        let tenths = divide_rounding(
            pin.numerator.saturating_sub(empty).saturating_mul(1000),
            span,
        );
        let tenths = i32::try_from(tenths).unwrap_or(i32::MAX);
        match LOOP_KIND.intrinsic() {
            Some(range) if !range.holds(tenths) => Observation::missing(Validity::OutOfRange),
            Some(_) | None => Observation::value(tenths, PROVENANCE),
        }
    }
}

/// How an input's pin voltage becomes what it publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Scaling {
    /// A voltage behind a divider, in millivolts.
    Divider(Divider),
    /// A tank level on a current loop, in tenths of a percent.
    Loop(Loop),
}

impl Scaling {
    /// What an input that converted to `counts` against `vdda` publishes.
    pub fn observe(self, vdda: Vdda, counts: u16) -> Result<Observation, QualityError> {
        let pin = vdda.pin(counts);
        match self {
            Self::Divider(divider) => divider.observe(pin),
            Self::Loop(tank) => tank.observe(pin),
        }
    }
}

/// An external input, its scaling, and the signal it publishes as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Input {
    /// The converter's channel.
    pub channel: u8,
    /// How it is scaled.
    pub scaling: Scaling,
    /// The signal it publishes as.
    pub signal: Id,
}

/// Why a pass stopped.
///
/// A pass stops at the first failure; what it wrote before stands, and the
/// rest keep their last writes and age out through the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed pass is inputs whose readings were not refreshed"]
pub enum AdcError<E> {
    /// The sampler reported an error.
    Sampler(E),
    /// The sampler returned more than [`FULL_SCALE`]: the adapter's defect.
    Counts(u16),
    /// The reference gave nothing to scale against; nothing was written.
    Reference(ReferenceError),
    /// The store refused a write.
    Store(SignalError),
    /// KM43 refused an observation: a defect surfaced rather than hidden.
    Quality(QualityError),
}

/// What a pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a pass's outcome is the supply it measured"]
pub struct Sampled {
    /// The supply every input was scaled against.
    pub vdda: Vdda,
    /// The signals written, one per input.
    pub written: usize,
}

/// Convert the reference and every input, [`SAMPLES`] times each, and write
/// each input into `store` at `now`.
pub async fn read<S: Sampler, const N: usize>(
    sampler: &mut S,
    cal: VrefintCal,
    inputs: &[Input],
    now: Tick,
    store: &mut Signals<N>,
) -> Result<Sampled, AdcError<S::Error>> {
    let reference = average(sampler, AdcInput::Reference).await?;
    let vdda = Vdda::from_reference(cal, Counts(reference)).map_err(AdcError::Reference)?;
    let mut written = 0usize;
    for input in inputs {
        let counts = average(sampler, AdcInput::Channel(input.channel)).await?;
        let seen = input
            .scaling
            .observe(vdda, counts)
            .map_err(AdcError::Quality)?;
        store
            .write(input.signal, now, seen)
            .map_err(AdcError::Store)?;
        written = written.saturating_add(1);
    }
    Ok(Sampled { vdda, written })
}

/// The mean of [`SAMPLES`] conversions of `input`, rounded to the nearest.
async fn average<S: Sampler>(sampler: &mut S, input: AdcInput) -> Result<u16, AdcError<S::Error>> {
    let mut total = 0u64;
    for _ in 0..SAMPLES {
        let Counts(counts) = sampler.sample(input).await.map_err(AdcError::Sampler)?;
        if counts > FULL_SCALE {
            return Err(AdcError::Counts(counts));
        }
        total = total.saturating_add(u64::from(counts));
    }
    let mean = divide_rounding(total, u64::from(SAMPLES));
    Ok(u16::try_from(mean).unwrap_or(FULL_SCALE))
}

/// `numerator / denominator`, rounding half up; zero for a zero denominator,
/// which no caller passes.
fn divide_rounding(numerator: u64, denominator: u64) -> u64 {
    let half = denominator / 2;
    numerator
        .saturating_add(half)
        .checked_div(denominator)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;
    use km43::Sample;
    use o89_core::{Limits, Millis};

    /// A sampler returning fixed counts per input, built by hand.
    struct Fixed {
        reference: u16,
        channels: [u16; 4],
        /// Makes channel 3 fail.
        broken: bool,
        conversions: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Overrun;

    impl Sampler for Fixed {
        type Error = Overrun;

        fn sample(&mut self, input: AdcInput) -> impl Future<Output = Result<Counts, Overrun>> {
            self.conversions = self.conversions.checked_add(1).unwrap();
            ready(match input {
                AdcInput::Reference => Ok(Counts(self.reference)),
                AdcInput::Channel(3) if self.broken => Err(Overrun),
                AdcInput::Channel(n) => Ok(Counts(self.channels[usize::from(n)])),
            })
        }
    }

    fn cal() -> VrefintCal {
        VrefintCal::new(1650).unwrap()
    }

    /// The supply at exactly 3.3 V: 1650 × 3000 / 1500.
    fn vdda() -> Vdda {
        Vdda::from_reference(cal(), Counts(1500)).unwrap()
    }

    /// The supply at exactly 3.0 V: the reference reads its calibration.
    fn vdda_at_cal() -> Vdda {
        Vdda::from_reference(cal(), Counts(1650)).unwrap()
    }

    fn value(seen: Result<Observation, QualityError>) -> (Option<i32>, Validity) {
        let seen = seen.unwrap();
        (seen.reading(), seen.quality().validity_of())
    }

    fn id(n: u16) -> Id {
        Id::new(n).unwrap()
    }

    const DIVIDER: Scaling = Scaling::Divider(Divider::BOARD_A);
    const TANK: Scaling = Scaling::Loop(Loop::BOARD_A);

    #[test]
    fn a_known_reference_reading_scales_exactly() {
        assert_eq!(vdda().millivolts(), 3300);
        assert_eq!(vdda_at_cal().millivolts(), 3000);
        // Half a millivolt rounds up: 1650 × 3000 / 1501 is 3297.80.
        let near = Vdda::from_reference(cal(), Counts(1501)).unwrap();
        assert_eq!(near.millivolts(), 3298);
        // At 3.0 V a count is 3000 / 4095 mV: 819 counts is 600 mV exactly,
        // and eleven times that is 6.6 V.
        assert_eq!(
            value(DIVIDER.observe(vdda_at_cal(), 819)),
            (Some(6600), Validity::Ok)
        );
    }

    #[test]
    fn a_reference_that_is_zero_or_implies_an_impossible_supply_is_refused() {
        assert_eq!(
            Vdda::from_reference(cal(), Counts(0)),
            Err(ReferenceError::Zero)
        );
        // 1650 × 3000 / 3056 is 1.6198 V, under 1.62 V; 3055 is inside.
        assert_eq!(
            Vdda::from_reference(cal(), Counts(3056)),
            Err(ReferenceError::OutOfRange)
        );
        assert!(Vdda::from_reference(cal(), Counts(3055)).is_ok());
        // 1650 × 3000 / 1375 is 3.6 V exactly, the highest; 1374 is over.
        assert_eq!(
            Vdda::from_reference(cal(), Counts(1375)).map(Vdda::millivolts),
            Ok(3600)
        );
        assert_eq!(
            Vdda::from_reference(cal(), Counts(1374)),
            Err(ReferenceError::OutOfRange)
        );
    }

    #[test]
    fn a_calibration_word_outside_the_datasheet_s_reference_is_refused() {
        assert_eq!(VrefintCal::new(1613).map(VrefintCal::get), Some(1613));
        assert_eq!(VrefintCal::new(1682).map(VrefintCal::get), Some(1682));
        assert_eq!(VrefintCal::new(1612), None);
        assert_eq!(VrefintCal::new(1683), None);
        // An erased word, and one never programmed.
        assert_eq!(VrefintCal::new(0xFFFF), None);
        assert_eq!(VrefintCal::new(0), None);
    }

    #[test]
    fn a_divider_reads_zero_at_zero_and_refuses_its_full_scale() {
        assert_eq!(value(DIVIDER.observe(vdda(), 0)), (Some(0), Validity::Ok));
        // One count under the top: 4094 × 3300 / 4095 × 11 is 36 291.1 mV.
        assert_eq!(
            value(DIVIDER.observe(vdda(), 4094)),
            (Some(36_291), Validity::Ok)
        );
        // The top is the pin at or above the supply, not a voltage.
        assert_eq!(
            value(DIVIDER.observe(vdda(), FULL_SCALE)),
            (None, Validity::OutOfRange)
        );
        // A 13.2 V bank is 1.2 V at the pin: 1489.09 counts at 3.3 V.
        assert_eq!(
            value(DIVIDER.observe(vdda(), 1489)),
            (Some(13_199), Validity::Ok)
        );
        assert_eq!(Divider::new(1, 0), None);
        assert_eq!(Divider::new(100_000, 10_000), Some(Divider::BOARD_A));
    }

    #[test]
    fn a_tank_loop_in_range_reads_its_level_with_both_ends_inclusive() {
        // At 3.0 V, 819 counts is 600 mV: 4 mA across 150 Ω, empty.
        assert_eq!(
            value(TANK.observe(vdda_at_cal(), 819)),
            (Some(0), Validity::Ok)
        );
        // 2457 counts is 1800 mV: 12 mA, half full.
        assert_eq!(
            value(TANK.observe(vdda_at_cal(), 2457)),
            (Some(500), Validity::Ok)
        );
        // At 3.3 V, 3000 mV is 3722.73 counts: 3723 is 20.0015 mA and
        // 3722 is 19.9961 mA, 99.98 % rounded to 100.0.
        assert_eq!(
            value(TANK.observe(vdda(), 3722)),
            (Some(1000), Validity::Ok)
        );
        // 4 mA at 3.3 V is 744.68 counts: 745 is inside, 0.03 % rounded to 0.
        assert_eq!(value(TANK.observe(vdda(), 745)), (Some(0), Validity::Ok));
    }

    #[test]
    fn a_tank_loop_open_or_shorted_is_absent_not_a_level() {
        // Open: nothing flows.
        assert_eq!(value(TANK.observe(vdda(), 0)), (None, Validity::Absent));
        // Just under 4 mA: 744 counts at 3.3 V is 3.9965 mA.
        assert_eq!(value(TANK.observe(vdda(), 744)), (None, Validity::Absent));
        // Just over 20 mA: 3723 counts at 3.3 V is 20.0015 mA.
        assert_eq!(value(TANK.observe(vdda(), 3723)), (None, Validity::Absent));
        // Shorted to the rail: the converter tops out, and at 3.3 V full
        // scale is already 22 mA.
        assert_eq!(
            value(TANK.observe(vdda(), FULL_SCALE)),
            (None, Validity::Absent)
        );
        // At 3.0 V full scale is 20 mA exactly, so the top says only "at
        // least 20 mA", which is no value either way.
        assert_eq!(
            value(TANK.observe(vdda_at_cal(), FULL_SCALE)),
            (None, Validity::OutOfRange)
        );
        // One count under is 19.995 mA, a level.
        assert_eq!(
            value(TANK.observe(vdda_at_cal(), 4094)),
            (Some(1000), Validity::Ok)
        );
        assert_eq!(Loop::new(0), None);
        assert_eq!(Loop::new(150), Some(Loop::BOARD_A));
    }

    fn inputs() -> [Input; 3] {
        [
            Input {
                channel: 0,
                scaling: DIVIDER,
                signal: id(50),
            },
            Input {
                channel: 1,
                scaling: DIVIDER,
                signal: id(51),
            },
            Input {
                channel: 2,
                scaling: TANK,
                signal: id(52),
            },
        ]
    }

    fn store() -> Signals<4> {
        let mut store = Signals::new();
        let limits = Limits::new(Millis::from_millis(10_000), None).unwrap();
        for n in 50..=53 {
            store.register(id(n), limits).unwrap();
        }
        store
    }

    fn sample(store: &Signals<4>, n: u16) -> Sample {
        store.sample(id(n), Tick::ZERO).unwrap()
    }

    #[test]
    fn a_pass_scales_every_input_against_the_reference_and_writes_it_measured() {
        let mut sampler = Fixed {
            reference: 1500,
            channels: [1489, 0, 3722, 0],
            broken: false,
            conversions: 0,
        };
        let mut store = store();
        let pass = block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)).unwrap();
        assert_eq!((pass.vdda.millivolts(), pass.written), (3300, 3));
        assert_eq!(sampler.conversions, 4 * usize::from(SAMPLES));

        let house = sample(&store, 50);
        assert_eq!(
            (house.value(), house.q.provenance_of()),
            (Some(13_199), Provenance::Measured)
        );
        assert_eq!(sample(&store, 51).value(), Some(0));
        let tank = sample(&store, 52);
        assert_eq!(
            (tank.value(), tank.q.provenance_of()),
            (Some(1000), Provenance::Measured)
        );
    }

    #[test]
    fn a_pass_with_an_implausible_reference_writes_nothing() {
        let mut sampler = Fixed {
            reference: 0,
            channels: [1489, 1489, 1489, 0],
            broken: false,
            conversions: 0,
        };
        let mut store = store();
        assert_eq!(
            block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)),
            Err(AdcError::Reference(ReferenceError::Zero))
        );
        for n in 50..=52 {
            assert_eq!(sample(&store, n).q.validity_of(), Validity::Initialising);
        }
    }

    #[test]
    fn a_failed_conversion_stops_the_pass_and_keeps_what_came_before() {
        let mut sampler = Fixed {
            reference: 1500,
            channels: [1489, 1489, 1489, 0],
            broken: true,
            conversions: 0,
        };
        let broken = [
            inputs()[0],
            Input {
                channel: 3,
                scaling: DIVIDER,
                signal: id(53),
            },
        ];
        let mut store = store();
        assert_eq!(
            block_on(read(&mut sampler, cal(), &broken, Tick::ZERO, &mut store)),
            Err(AdcError::Sampler(Overrun))
        );
        assert_eq!(sample(&store, 50).value(), Some(13_199));
        assert_eq!(sample(&store, 53).q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn a_count_past_the_converter_s_range_is_the_adapter_s_defect() {
        let mut sampler = Fixed {
            reference: 1500,
            channels: [4096, 0, 0, 0],
            broken: false,
            conversions: 0,
        };
        let mut store = store();
        assert_eq!(
            block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)),
            Err(AdcError::Counts(4096))
        );
        assert_eq!(sample(&store, 50).q.validity_of(), Validity::Initialising);
    }

    #[test]
    fn a_write_to_a_signal_the_store_does_not_hold_is_refused() {
        let mut sampler = Fixed {
            reference: 1500,
            channels: [1489, 0, 0, 0],
            broken: false,
            conversions: 0,
        };
        let mut store = Signals::<1>::new();
        assert_eq!(
            block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)),
            Err(AdcError::Store(SignalError::Unknown(id(50))))
        );
    }

    #[test]
    fn the_average_rounds_to_the_nearest_count() {
        struct Alternating(bool);
        impl Sampler for Alternating {
            type Error = Overrun;
            fn sample(&mut self, _: AdcInput) -> impl Future<Output = Result<Counts, Overrun>> {
                self.0 = !self.0;
                ready(Ok(Counts(if self.0 { 101 } else { 100 })))
            }
        }
        // Eight of 100 and eight of 101: 100.5, rounded up.
        assert_eq!(
            block_on(average(&mut Alternating(false), AdcInput::Reference)),
            Ok(101)
        );
    }
}
