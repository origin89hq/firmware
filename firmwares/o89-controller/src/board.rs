//! Controller board A, revision A: every pin this image touches, in one place.
//!
//! From the 2026-09-09 export's flying-probe netlist, checked against the
//! HAL's pin-function table for the `stm32g0b1re`; `docs/BOARD-A.md` is the
//! same table with the sources, and the gate holds the two together. No
//! other file names a pin: what a task owns it is handed from [`Board`].
//!
//! A pin no task takes yet is still here, with the milestone that takes it
//! on its `expect`: the day the pin is read, the expectation fails the
//! build and the marker comes off. That keeps the table whole from the
//! first image and makes the list of what is still unconfigured a list the
//! compiler checks.
//!
//! Left alone on purpose, and not in [`Board`]: `PA13` and `PA14` are the
//! probe's and are never reconfigured on revision A (F-012); `PF0`, `PF1`,
//! `PC14` and `PC15` are the crystals', owned by the clock configuration;
//! `PA11` and `PA12` stay untouched (`BOARD-A.md`); the nineteen unused pads
//! stay in their reset state. The gate reads the line below against the pin
//! map's rows, so a row is either taken by [`Board::split`] or named here.
//!
//! leaves alone: PA13, PA14, PF0, PF1, PC14, PC15
//!
//! The lines with a fail state that the first statements of `main` drive
//! through the registers, before the HAL owns anything, are named here too:
//! `RUN` is `PD0`, `KICK` is `PD1`, and the RS-485 transmit lines are `PA2`,
//! `PB10` and `PA0`, so that the register writes and the pins the HAL is
//! handed are one list.

use embassy_stm32::peripherals as p;
use embassy_stm32::{Peri, PeripheralType, Peripherals};
use o89_core::Revision;

/// The board this image is built for.
pub const REVISION: Revision = Revision::A;

/// `RUN` on `GPIOD`.
pub const RUN: usize = 0;
/// `KICK` on `GPIOD`.
pub const KICK: usize = 1;
/// RS-485 #1 transmit on `GPIOA`.
pub const RS485_1_TX: usize = 2;
/// RS-485 #2 transmit on `GPIOB`.
pub const RS485_2_TX: usize = 10;
/// RS-485 #3 transmit on `GPIOA`.
pub const RS485_3_TX: usize = 0;

/// One RS-485 channel: the USART and its two pins.
pub struct Rs485<U, T, R>
where
    U: PeripheralType + 'static,
    T: PeripheralType + 'static,
    R: PeripheralType + 'static,
{
    /// The USART instance.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub usart: Peri<'static, U>,
    /// Transmit, which idles high (F-002).
    pub tx: Peri<'static, T>,
    /// Receive.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub rx: Peri<'static, R>,
}

/// One VE.Direct port: receive only, the pull-up off by default (F-051).
pub struct VeDirect<U, R>
where
    U: PeripheralType + 'static,
    R: PeripheralType + 'static,
{
    /// The LPUART instance.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub usart: Peri<'static, U>,
    /// Receive, through 1 kΩ, on connector pin 3 on revision A.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub rx: Peri<'static, R>,
}

/// The link to the module, and the lines into it that are inputs until the
/// rail is up (F-003).
pub struct Module {
    /// USART1, the module's UART0.
    #[expect(dead_code, reason = "taken in M3, the link")]
    pub usart: Peri<'static, p::USART1>,
    /// `ESP_TX`, to the module's RXD0.
    #[expect(dead_code, reason = "taken in M3, the link")]
    pub tx: Peri<'static, p::PB6>,
    /// `ESP_RX`, from the module's TXD0.
    #[expect(dead_code, reason = "taken in M3, the link")]
    pub rx: Peri<'static, p::PB7>,
    /// `ESP_RTS`, to the module's IO4.
    #[expect(dead_code, reason = "taken in M3, the link")]
    pub rts: Peri<'static, p::PB3>,
    /// `ESP_CTS`, from the module's IO5.
    #[expect(dead_code, reason = "taken in M3, the link")]
    pub cts: Peri<'static, p::PB4>,
    /// `ESP_EN`, held low across every rail cycle (F-004).
    #[expect(dead_code, reason = "taken by the rail sequence, M1")]
    pub en: Peri<'static, p::PC2>,
    /// `ESP_BOOT`, the IO9 strap.
    #[expect(dead_code, reason = "taken in M3, the bench flashing path")]
    pub boot: Peri<'static, p::PC3>,
    /// `ESP_PWR_EN`: the rail, high is on; off with the pin high-impedance
    /// on revision A (F-014).
    #[expect(dead_code, reason = "taken by the rail sequence, M1")]
    pub rail: Peri<'static, p::PC5>,
}

/// The board, split into what each task owns.
pub struct Board {
    /// The independent watchdog.
    pub iwdg: Peri<'static, p::IWDG>,
    /// The RTC on the LSE.
    #[expect(dead_code, reason = "taken in M4, the time offers")]
    pub rtc: Peri<'static, p::RTC>,

    /// `RUN` to board B, CN9 pin 3.
    pub gen_run: Peri<'static, p::PD0>,
    /// `KICK` to board B, CN9 pin 4.
    pub gen_kick: Peri<'static, p::PD1>,
    /// `FEEDBACK` from board B, CN9 pin 5; the internal pull-up, low is
    /// both relays closed (F-013).
    #[expect(dead_code, reason = "taken in M8, authority")]
    pub gen_feedback: Peri<'static, p::PD2>,

    /// The status lamp, active high.
    pub led_status: Peri<'static, p::PC6>,
    /// The fault lamp, active high.
    pub led_fault: Peri<'static, p::PC7>,

    /// RS-485 #1 on CN2: EPEver-class devices.
    pub rs485_1: Rs485<p::USART2, p::PA2, p::PA3>,
    /// RS-485 #2 on CN3: the PZEM DC meters.
    pub rs485_2: Rs485<p::USART3, p::PB10, p::PB11>,
    /// RS-485 #3 on CN4: PZEM-016 and modules.
    pub rs485_3: Rs485<p::USART4, p::PA0, p::PA1>,

    /// FDCAN1 on CN5.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub fdcan1: Peri<'static, p::FDCAN1>,
    /// CAN receive.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub can_rx: Peri<'static, p::PB8>,
    /// CAN transmit.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub can_tx: Peri<'static, p::PB9>,

    /// VE.Direct 1 on CN6.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub vedirect_1: VeDirect<p::LPUART1, p::PC0>,
    /// VE.Direct 2 on CN7.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub vedirect_2: VeDirect<p::LPUART2, p::PC1>,

    /// The FRAM's I2C.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub i2c2: Peri<'static, p::I2C2>,
    /// FRAM SCL.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub fram_scl: Peri<'static, p::PB13>,
    /// FRAM SDA.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub fram_sda: Peri<'static, p::PB14>,

    /// The NOR's SPI.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub spi1: Peri<'static, p::SPI1>,
    /// NOR chip select.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub nor_cs: Peri<'static, p::PA4>,
    /// NOR clock.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub nor_sck: Peri<'static, p::PA5>,
    /// NOR MISO.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub nor_miso: Peri<'static, p::PA6>,
    /// NOR MOSI.
    #[expect(dead_code, reason = "taken in M2, persistence")]
    pub nor_mosi: Peri<'static, p::PA7>,

    /// `OW_DATA_F`: the 1-Wire bus, bit-banged.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub onewire: Peri<'static, p::PC4>,

    /// The ADC.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub adc1: Peri<'static, p::ADC1>,
    /// `AIN_HOUSE`: the bank voltage.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub ain_house: Peri<'static, p::PB0>,
    /// `AIN_START`: the start battery.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub ain_start: Peri<'static, p::PB1>,
    /// `AIN_TANK`: the tank sender's 4–20 mA.
    #[expect(dead_code, reason = "taken in M5, the site")]
    pub ain_tank: Peri<'static, p::PB2>,

    /// `SEL_AUTO`, pulled up, switch to ground.
    #[expect(dead_code, reason = "taken in M4, the gestures")]
    pub sel_auto: Peri<'static, p::PB12>,
    /// `SEL_MANUAL`, pulled up, switch to ground.
    #[expect(dead_code, reason = "taken in M4, the gestures")]
    pub sel_manual: Peri<'static, p::PB15>,

    /// The module.
    #[expect(dead_code, reason = "taken by the rail sequence, M1")]
    pub module: Module,
}

impl Board {
    /// Hand every task its pins. Anything not listed stays in its reset state.
    #[must_use]
    pub fn split(p: Peripherals) -> Self {
        Self {
            iwdg: p.IWDG,
            rtc: p.RTC,
            gen_run: p.PD0,
            gen_kick: p.PD1,
            gen_feedback: p.PD2,
            led_status: p.PC6,
            led_fault: p.PC7,
            rs485_1: Rs485 {
                usart: p.USART2,
                tx: p.PA2,
                rx: p.PA3,
            },
            rs485_2: Rs485 {
                usart: p.USART3,
                tx: p.PB10,
                rx: p.PB11,
            },
            rs485_3: Rs485 {
                usart: p.USART4,
                tx: p.PA0,
                rx: p.PA1,
            },
            fdcan1: p.FDCAN1,
            can_rx: p.PB8,
            can_tx: p.PB9,
            vedirect_1: VeDirect {
                usart: p.LPUART1,
                rx: p.PC0,
            },
            vedirect_2: VeDirect {
                usart: p.LPUART2,
                rx: p.PC1,
            },
            i2c2: p.I2C2,
            fram_scl: p.PB13,
            fram_sda: p.PB14,
            spi1: p.SPI1,
            nor_cs: p.PA4,
            nor_sck: p.PA5,
            nor_miso: p.PA6,
            nor_mosi: p.PA7,
            onewire: p.PC4,
            adc1: p.ADC1,
            ain_house: p.PB0,
            ain_start: p.PB1,
            ain_tank: p.PB2,
            sel_auto: p.PB12,
            sel_manual: p.PB15,
            module: Module {
                usart: p.USART1,
                tx: p.PB6,
                rx: p.PB7,
                rts: p.PB3,
                cts: p.PB4,
                en: p.PC2,
                boot: p.PC3,
                rail: p.PC5,
            },
        }
    }
}
