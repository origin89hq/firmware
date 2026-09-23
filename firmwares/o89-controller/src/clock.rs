//! The clock tree this image runs on.
//!
//! SYSCLK 64 MHz from the 12 MHz crystal through the PLL: 12 MHz × 16 is a
//! 192 MHz VCO, /3 is the core, /4 is 48 MHz for the peripherals that want
//! it. The RTC runs from the 32.768 kHz crystal, and `reset::rtc_clock`
//! asserts that it does rather than assuming it. The ADC's own clock comes
//! from the HSI, under its 35 MHz limit and independent of the bus; CAN
//! takes the raw crystal. The self-test proved this tree on board A revision
//! A over three sessions.

use embassy_stm32::rcc::mux::{Adcsel, Fdcansel};
use embassy_stm32::rcc::{
    AHBPrescaler, APBPrescaler, Config, Hse, HseMode, LsConfig, Pll, PllMul, PllPreDiv, PllQDiv,
    PllRDiv, PllSource, Sysclk,
};
use embassy_stm32::time::Hertz;

/// The crystal on `PF0`/`PF1`.
pub const HSE: Hertz = Hertz(12_000_000);

/// The tree, for `embassy_stm32::init`.
#[must_use]
pub fn config() -> Config {
    let mut config = Config::default();
    config.hse = Some(Hse {
        freq: HSE,
        mode: HseMode::Oscillator,
    });
    config.pll = Some(Pll {
        source: PllSource::Hse,
        prediv: PllPreDiv::Div1,
        mul: PllMul::Mul16,
        divp: None,
        divq: Some(PllQDiv::Div4),
        divr: Some(PllRDiv::Div3),
    });
    config.sys = Sysclk::Pll1R;
    config.ahb_pre = AHBPrescaler::Div1;
    config.apb1_pre = APBPrescaler::Div1;
    config.ls = LsConfig::default_lse();
    config.mux.fdcansel = Fdcansel::Hse;
    config.mux.adcsel = Adcsel::Hsi;
    config
}
