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
//! above VDDA, not a reading: an input any of whose conversions reached it
//! publishes `out_of_range`, whatever the mean; a loop whose
//! full scale already means more than 20 mA publishes `absent` instead,
//! because that much is known. A failed conversion or an implausible
//! reference writes nothing.
//!
//! Taken from the self-test (`origin89hq/origin89`,
//! `firmwares/o89-selftest/src/checks/adc.rs` and `calib.rs`): the
//! reference scaling and the sixteen-sample average. The resistors are the
//! board's, and the caller builds each [`Divider`] and [`Loop`] from its
//! board module; the tests use board A's (`docs/BOARD-A.md`) as fixtures.

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
    /// A conversion of the reference reached the top of the range, which the
    /// mean of the others can hide: the supply it would give is not one to
    /// scale against.
    Clipped,
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
        // At most 3000 × 1682 over at least one: never past a `u32`.
        divide_rounding(self.cal_product(), u64::from(self.reference))
            .and_then(|mv| u32::try_from(mv).ok())
            .unwrap_or(u32::MAX)
    }

    /// `CAL_VDDA_MV × VREFINT_CAL`: the supply times the reference's counts.
    fn cal_product(self) -> u64 {
        u64::from(CAL_VDDA_MV).saturating_mul(u64::from(self.cal.get()))
    }

    /// The voltage at a pin that converted to `counts`, exactly, at the top
    /// of the range when `counts` is or any conversion behind it was.
    /// `None` only past a `u64`, which the calibration's bounds rule out.
    fn pin(self, counts: u16, clipped: bool) -> Option<Pin> {
        let saturated = clipped || counts >= FULL_SCALE;
        let counts = if saturated { FULL_SCALE } else { counts };
        Some(Pin {
            numerator: u64::from(counts).checked_mul(self.cal_product())?,
            denominator: u64::from(self.reference).checked_mul(u64::from(FULL_SCALE))?,
            saturated,
        })
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
    /// The largest resistance either side may have, 100 MΩ.
    ///
    /// An arithmetic bound of this API, not a fact about any board: it keeps
    /// the exact pin fraction times the divider's total inside a `u64`, so a
    /// scaling can never overflow into a wrong measurement.
    pub const MAX_OHMS: u32 = 100_000_000;

    /// `top_ohms` over `bottom_ohms`, or `None` for a zero bottom or either
    /// side above [`Divider::MAX_OHMS`].
    #[must_use]
    pub const fn new(top_ohms: u32, bottom_ohms: u32) -> Option<Self> {
        if bottom_ohms == 0 || top_ohms > Self::MAX_OHMS || bottom_ohms > Self::MAX_OHMS {
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
        let total = u64::from(self.top_ohms).checked_add(u64::from(self.bottom_ohms));
        let millivolts = total.and_then(|total| {
            divide_rounding(
                pin.numerator.checked_mul(total)?,
                pin.denominator.checked_mul(u64::from(self.bottom_ohms))?,
            )
        });
        match millivolts.and_then(|mv| i32::try_from(mv).ok()) {
            Some(millivolts) => Observation::value(millivolts, PROVENANCE),
            None => Observation::missing(Validity::OutOfRange),
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
        let bounds = pin
            .denominator
            .checked_mul(u64::from(self.sense_ohms))
            .and_then(|per_ma| {
                Some((
                    per_ma.checked_mul(Self::EMPTY_MA)?,
                    per_ma.checked_mul(Self::FULL_MA)?,
                ))
            });
        let Some((empty, full)) = bounds else {
            return Observation::missing(Validity::OutOfRange);
        };
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
        let tenths = pin
            .numerator
            .checked_sub(empty)
            .and_then(|above| above.checked_mul(1000))
            .and_then(|scaled| divide_rounding(scaled, full.checked_sub(empty)?))
            .and_then(|tenths| i32::try_from(tenths).ok());
        match (tenths, LOOP_KIND.intrinsic()) {
            (Some(tenths), Some(range)) if range.holds(tenths) => {
                Observation::value(tenths, PROVENANCE)
            }
            (Some(tenths), None) => Observation::value(tenths, PROVENANCE),
            (Some(_) | None, Some(_)) | (None, None) => Observation::missing(Validity::OutOfRange),
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
        self.observe_mean(
            vdda,
            Mean {
                counts,
                clipped: false,
            },
        )
    }

    /// What a mean of conversions publishes: at the top of the range when
    /// any one conversion was, whatever the mean.
    fn observe_mean(self, vdda: Vdda, mean: Mean) -> Result<Observation, QualityError> {
        let Some(pin) = vdda.pin(mean.counts, mean.clipped) else {
            return Observation::missing(Validity::OutOfRange);
        };
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
    if reference.clipped {
        return Err(AdcError::Reference(ReferenceError::Clipped));
    }
    let vdda = Vdda::from_reference(cal, Counts(reference.counts)).map_err(AdcError::Reference)?;
    let mut written = 0usize;
    for input in inputs {
        let mean = average(sampler, AdcInput::Channel(input.channel)).await?;
        let seen = input
            .scaling
            .observe_mean(vdda, mean)
            .map_err(AdcError::Quality)?;
        store
            .write(input.signal, now, seen)
            .map_err(AdcError::Store)?;
        written = written.saturating_add(1);
    }
    Ok(Sampled { vdda, written })
}

/// The mean of [`SAMPLES`] conversions of `input`, rounded to the nearest.
async fn average<S: Sampler>(sampler: &mut S, input: AdcInput) -> Result<Mean, AdcError<S::Error>> {
    let mut total = 0u64;
    let mut clipped = false;
    for _ in 0..SAMPLES {
        let Counts(counts) = sampler.sample(input).await.map_err(AdcError::Sampler)?;
        if counts > FULL_SCALE {
            return Err(AdcError::Counts(counts));
        }
        clipped |= counts == FULL_SCALE;
        total = total.saturating_add(u64::from(counts));
    }
    // Sixteen counts of at most `FULL_SCALE` each: the mean fits.
    let counts = divide_rounding(total, u64::from(SAMPLES))
        .and_then(|mean| u16::try_from(mean).ok())
        .ok_or(AdcError::Counts(FULL_SCALE))?;
    Ok(Mean { counts, clipped })
}

/// The mean of one input's conversions, and whether any of them hit the top
/// of the range, which the mean alone can hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mean {
    counts: u16,
    clipped: bool,
}

/// `numerator / denominator`, rounding half up, or `None` for a zero
/// denominator or a sum past a `u64`.
fn divide_rounding(numerator: u64, denominator: u64) -> Option<u64> {
    numerator
        .checked_add(denominator / 2)?
        .checked_div(denominator)
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

    /// Board A's battery divider, 100 kΩ over 10 kΩ (`A-29`): a fixture.
    fn divider() -> Scaling {
        Scaling::Divider(Divider::new(100_000, 10_000).unwrap())
    }

    /// Board A's tank sense resistor, R46, 150 Ω (`A-27`): a fixture.
    fn tank() -> Scaling {
        Scaling::Loop(Loop::new(150).unwrap())
    }

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
            value(divider().observe(vdda_at_cal(), 819)),
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
        assert_eq!(value(divider().observe(vdda(), 0)), (Some(0), Validity::Ok));
        // One count under the top: 4094 × 3300 / 4095 × 11 is 36 291.1 mV.
        assert_eq!(
            value(divider().observe(vdda(), 4094)),
            (Some(36_291), Validity::Ok)
        );
        // The top is the pin at or above the supply, not a voltage.
        assert_eq!(
            value(divider().observe(vdda(), FULL_SCALE)),
            (None, Validity::OutOfRange)
        );
        // A 13.2 V bank is 1.2 V at the pin: 1489.09 counts at 3.3 V.
        assert_eq!(
            value(divider().observe(vdda(), 1489)),
            (Some(13_199), Validity::Ok)
        );
        assert_eq!(Divider::new(1, 0), None);
    }

    #[test]
    fn a_divider_at_the_largest_resistances_scales_exactly_and_one_ohm_more_is_refused() {
        let max = Divider::MAX_OHMS;
        let even = Scaling::Divider(Divider::new(max, max).unwrap());
        // A ratio of two at the top of the range: 4094 counts at 3.3 V is
        // 3299.19 mV at the pin and 6598.39 mV in front of the divider.
        assert_eq!(
            value(even.observe(vdda(), 4094)),
            (Some(6598), Validity::Ok)
        );
        // The same ratio from small resistances gives the same answer.
        let small = Scaling::Divider(Divider::new(1, 1).unwrap());
        assert_eq!(
            value(small.observe(vdda(), 4094)),
            (Some(6598), Validity::Ok)
        );
        // The largest ratio the bound allows: 100 MΩ over 1 Ω.
        let steep = Scaling::Divider(Divider::new(max, 1).unwrap());
        assert_eq!(
            value(steep.observe(vdda(), 4094)),
            (None, Validity::OutOfRange)
        );
        assert_eq!(value(steep.observe(vdda(), 0)), (Some(0), Validity::Ok));
        assert_eq!(Divider::new(max + 1, max), None);
        assert_eq!(Divider::new(max, max + 1), None);
    }

    #[test]
    fn a_tank_loop_in_range_reads_its_level_with_both_ends_inclusive() {
        // At 3.0 V, 819 counts is 600 mV: 4 mA across 150 Ω, empty.
        assert_eq!(
            value(tank().observe(vdda_at_cal(), 819)),
            (Some(0), Validity::Ok)
        );
        // 2457 counts is 1800 mV: 12 mA, half full.
        assert_eq!(
            value(tank().observe(vdda_at_cal(), 2457)),
            (Some(500), Validity::Ok)
        );
        // At 3.3 V, 3000 mV is 3722.73 counts: 3723 is 20.0015 mA and
        // 3722 is 19.9961 mA, 99.98 % rounded to 100.0.
        assert_eq!(
            value(tank().observe(vdda(), 3722)),
            (Some(1000), Validity::Ok)
        );
        // 4 mA at 3.3 V is 744.68 counts: 745 is inside, 0.03 % rounded to 0.
        assert_eq!(value(tank().observe(vdda(), 745)), (Some(0), Validity::Ok));
    }

    #[test]
    fn a_tank_loop_open_or_shorted_is_absent_not_a_level() {
        // Open: nothing flows.
        assert_eq!(value(tank().observe(vdda(), 0)), (None, Validity::Absent));
        // Just under 4 mA: 744 counts at 3.3 V is 3.9965 mA.
        assert_eq!(value(tank().observe(vdda(), 744)), (None, Validity::Absent));
        // Just over 20 mA: 3723 counts at 3.3 V is 20.0015 mA.
        assert_eq!(
            value(tank().observe(vdda(), 3723)),
            (None, Validity::Absent)
        );
        // Shorted to the rail: the converter tops out, and at 3.3 V full
        // scale is already 22 mA.
        assert_eq!(
            value(tank().observe(vdda(), FULL_SCALE)),
            (None, Validity::Absent)
        );
        // At 3.0 V full scale is 20 mA exactly, so the top says only "at
        // least 20 mA", which is no value either way.
        assert_eq!(
            value(tank().observe(vdda_at_cal(), FULL_SCALE)),
            (None, Validity::OutOfRange)
        );
        // One count under is 19.995 mA, a level.
        assert_eq!(
            value(tank().observe(vdda_at_cal(), 4094)),
            (Some(1000), Validity::Ok)
        );
        assert_eq!(Loop::new(0), None);
    }

    fn inputs() -> [Input; 3] {
        [
            Input {
                channel: 0,
                scaling: divider(),
                signal: id(50),
            },
            Input {
                channel: 1,
                scaling: divider(),
                signal: id(51),
            },
            Input {
                channel: 2,
                scaling: tank(),
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
                scaling: divider(),
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

    /// Every input converts to `low` for its first `lows` samples of each
    /// sixteen and to `high` after; the reference to a fixed count.
    struct Mixed {
        reference: u16,
        low: u16,
        high: u16,
        lows: u16,
        taken: u16,
    }

    impl Sampler for Mixed {
        type Error = Overrun;

        fn sample(&mut self, input: AdcInput) -> impl Future<Output = Result<Counts, Overrun>> {
            ready(Ok(Counts(match input {
                AdcInput::Reference => self.reference,
                AdcInput::Channel(_) => {
                    let n = self.taken;
                    self.taken = n.checked_add(1).unwrap() % SAMPLES;
                    if n < self.lows { self.low } else { self.high }
                }
            })))
        }
    }

    fn pass(reference: u16, lows: u16, input: Input) -> Sample {
        let mut sampler = Mixed {
            reference,
            low: 4094,
            high: FULL_SCALE,
            lows,
            taken: 0,
        };
        let mut store = store();
        let _ = block_on(read(&mut sampler, cal(), &[input], Tick::ZERO, &mut store)).unwrap();
        store.sample(input.signal, Tick::ZERO).unwrap()
    }

    #[test]
    fn a_pass_with_some_conversions_at_the_top_is_no_reading_though_its_mean_is_under() {
        let divider = Input {
            channel: 0,
            scaling: divider(),
            signal: id(50),
        };
        let tank = Input {
            channel: 2,
            scaling: tank(),
            signal: id(52),
        };
        // Nine of 4094 and seven of 4095: the mean rounds to 4094.
        let seen = pass(1500, 9, divider);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::OutOfRange)
        );
        // At 3.0 V, 4094 alone is 19.995 mA, a full tank; with clipped
        // conversions behind it the loop is at least full scale, 20 mA,
        // which says nothing either way.
        let seen = pass(1650, 9, tank);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::OutOfRange)
        );
        // The same passes with no conversion at the top read their values.
        let seen = pass(1500, SAMPLES, divider);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (Some(36_291), Validity::Ok)
        );
        let seen = pass(1650, SAMPLES, tank);
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (Some(1000), Validity::Ok)
        );
        // At 3.3 V full scale is 22 mA: one clipped conversion says the loop
        // went past 20 mA, however low the mean, and a loop past 20 mA is
        // absent. Fifteen of 3000 and one of 4095 is a mean of 3068,
        // 16.5 mA, which alone would read a level.
        let mut sampler = Mixed {
            reference: 1500,
            low: 3000,
            high: FULL_SCALE,
            lows: SAMPLES - 1,
            taken: 0,
        };
        let mut store = store();
        let _ = block_on(read(&mut sampler, cal(), &[tank], Tick::ZERO, &mut store)).unwrap();
        let seen = store.sample(tank.signal, Tick::ZERO).unwrap();
        assert_eq!(
            (seen.value(), seen.q.validity_of()),
            (None, Validity::Absent)
        );
        // A single conversion at the top is enough.
        let seen = pass(1500, SAMPLES - 1, divider);
        assert_eq!(seen.q.validity_of(), Validity::OutOfRange);
    }

    #[test]
    fn a_reference_with_any_conversion_at_the_top_writes_nothing() {
        /// The reference reads `clean` fifteen times and `last` once; every
        /// channel reads 1489.
        struct Reference {
            clean: u16,
            last: u16,
            taken: u16,
        }
        impl Sampler for Reference {
            type Error = Overrun;
            fn sample(&mut self, input: AdcInput) -> impl Future<Output = Result<Counts, Overrun>> {
                ready(Ok(Counts(match input {
                    AdcInput::Reference => {
                        self.taken = self.taken.checked_add(1).unwrap();
                        if self.taken == SAMPLES {
                            self.last
                        } else {
                            self.clean
                        }
                    }
                    AdcInput::Channel(_) => 1489,
                })))
            }
        }
        // Fifteen of 1500 and one of 4095: the mean, 1662, is a plausible
        // 2.978 V, and scaling against it would be wrong.
        let mut sampler = Reference {
            clean: 1500,
            last: FULL_SCALE,
            taken: 0,
        };
        let mut store = store();
        assert_eq!(
            block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)),
            Err(AdcError::Reference(ReferenceError::Clipped))
        );
        assert_eq!(sample(&store, 50).q.validity_of(), Validity::Initialising);
        // The same pass with its last conversion one under the top scales.
        let mut sampler = Reference {
            clean: 1500,
            last: FULL_SCALE - 1,
            taken: 0,
        };
        let pass = block_on(read(&mut sampler, cal(), &inputs(), Tick::ZERO, &mut store)).unwrap();
        assert_eq!((pass.vdda.millivolts(), pass.written), (2978, 3));
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
            Ok(Mean {
                counts: 101,
                clipped: false
            })
        );
    }
}
