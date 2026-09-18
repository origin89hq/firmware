//! The first statements after reset, through the registers, before the HAL
//! owns anything.
//!
//! `RUN` and `KICK` driven low, push-pull, so that no image reaches its
//! second decision with the generator's contact undriven (F-001); the three
//! RS-485 transmit lines driven high, so the transceivers stop holding their
//! buses low (F-002). The module lines are not touched: they are inputs
//! from reset until the rail is up (F-003). The HAL takes the same pins a
//! few milliseconds later and sets the same levels before it changes the
//! mode, so nothing glitches on the way.

use stm32_metapac::gpio::vals::{Moder, Ot};
use stm32_metapac::{GPIOA, GPIOB, GPIOD, RCC};

use crate::board::{KICK, RS485_1_TX, RS485_2_TX, RS485_3_TX, RUN};

/// The output bits are set before the pins become outputs, so each pin
/// goes from high-impedance to its level with no instant at the other one.
pub fn generator_and_bus_lines() {
    RCC.gpioenr().modify(|w| {
        w.set_gpioaen(true);
        w.set_gpioben(true);
        w.set_gpioden(true);
    });

    GPIOD.bsrr().write(|w| {
        w.set_br(RUN, true);
        w.set_br(KICK, true);
    });
    GPIOD.otyper().modify(|w| {
        w.set_ot(RUN, Ot::PUSH_PULL);
        w.set_ot(KICK, Ot::PUSH_PULL);
    });
    GPIOD.moder().modify(|w| {
        w.set_moder(RUN, Moder::OUTPUT);
        w.set_moder(KICK, Moder::OUTPUT);
    });

    GPIOA.bsrr().write(|w| {
        w.set_bs(RS485_1_TX, true);
        w.set_bs(RS485_3_TX, true);
    });
    GPIOA.otyper().modify(|w| {
        w.set_ot(RS485_1_TX, Ot::PUSH_PULL);
        w.set_ot(RS485_3_TX, Ot::PUSH_PULL);
    });
    GPIOA.moder().modify(|w| {
        w.set_moder(RS485_1_TX, Moder::OUTPUT);
        w.set_moder(RS485_3_TX, Moder::OUTPUT);
    });

    GPIOB.bsrr().write(|w| w.set_bs(RS485_2_TX, true));
    GPIOB
        .otyper()
        .modify(|w| w.set_ot(RS485_2_TX, Ot::PUSH_PULL));
    GPIOB
        .moder()
        .modify(|w| w.set_moder(RS485_2_TX, Moder::OUTPUT));
}
