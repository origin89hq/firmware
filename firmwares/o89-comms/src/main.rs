//! The comms processor: a pipe, and nothing the controller trusts.
//!
//! This chip is hostile by assumption. It carries frames between a client and
//! the controller and can read none of them: every client message is
//! authenticated end to end under a key derived from the printed secret,
//! which this part never holds. So the rule this crate lives under is narrow
//! and absolute: it forwards bytes and never inspects them. It must never
//! depend on `o89-core`, and the gate refuses the dependency.
//!
//! The boot, in the order the recovery story on board A revision A fixes
//! (#1): the watchdog re-armed as the first statement after `esp_hal::init`,
//! which disables every watchdog (F-032); UART0 to the controller, at the
//! link's rate with flow control (F-030); the download window, listening for
//! one link-local request and nothing else, honouring it by the ROM's flag
//! and a reset (F-033, F-034); the OTA slot confirmed only once the window
//! has run, so a rollback lands on an image that honours it (F-036); only
//! then the scheduler, the true random source for `boot_id` (F-035), and the
//! link: `LinkUp`, the heartbeat, and the rules for a controller that goes
//! quiet (L-120, L-121). The radio and the transports arrive with M4. The
//! entry is the HAL's bare one: nothing of the scheduler's or the
//! executor's runs before the window, and the executor is entered only once
//! the window and the confirmation are behind the boot.
//!
//! Nothing here prints. The module's only wire on board A is the link, and a
//! console on it would put a person's text into a CRC (#2); what this side
//! does is read on the controller's log, and a panic is a reset by the
//! watchdog.

#![no_std]
#![no_main]

mod link;
mod ota;
mod panic;
mod window;

use esp_hal::rng::{Rng, TrngSource};
use esp_hal::rtc_cntl::{Rtc, RwdtStage, RwdtStageAction};
use esp_hal::time::Duration;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config, CtsConfig, HwFlowControl, RtsConfig, RxConfig, Uart};
use esp_rtos::embassy::Executor;
use km43::{FrameReader, FrameWriter};
use static_cell::StaticCell;

// The ESP-IDF application descriptor, which the ROM bootloader reads before
// it will run anything. Without it `espflash` refuses the image outright.
esp_bootloader_esp_idf::esp_app_desc!();

/// The link's rate (F-030).
const BAUD: u32 = 921_600;
/// The receive FIFO level at which `RTS` asks the controller to wait: the
/// FIFO is 128 bytes, and 96 leaves room for what is already in flight.
const RTS_AT: u8 = 96;
/// How long the part may go unfed before it resets: a hang in the window
/// re-opens the window, a hang in the link reboots into it (F-032).
const WATCHDOG: Duration = Duration::from_secs(8);

/// The executor the link runs on, entered at the end of the boot.
static EXECUTOR: StaticCell<Executor> = StaticCell::new();

#[esp_hal::main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default());
    // 1. The watchdog, first: `esp_hal::init` disabled every one (F-032).
    let mut rtc = Rtc::new(p.RTC_TIMER);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WATCHDOG);
    rtc.rwdt
        .set_stage_action(RwdtStage::Stage0, RwdtStageAction::ResetSystem);
    rtc.rwdt.enable();

    // 2. UART0 to the controller, before anything else, on the pins the
    // board wires (#2): RXD0 is GPIO17, TXD0 GPIO16, the controller's RTS
    // arrives on GPIO4 as our CTS, our RTS leaves on GPIO5. Until this
    // statement the two outputs are what the part makes them (datasheet
    // v1.5, table 2-1): through a reset or a brown-out both undriven, then
    // GPIO16 the ROM's transmit, idle high on a weak pull-up, and GPIO5 an
    // input with no pull. Neither net has a pull on board A, so the
    // controller's CTS floats until this line takes GPIO5 as RTS.
    let wired = Config::default()
        .with_baudrate(BAUD)
        .with_hw_flow_ctrl(HwFlowControl {
            cts: if cfg!(feature = "no-flow") {
                CtsConfig::Disabled
            } else {
                CtsConfig::Enabled
            },
            rts: RtsConfig::Enabled(RTS_AT),
        })
        .with_rx(RxConfig::default().with_fifo_full_threshold(32));
    let Ok(uart) = Uart::new(p.UART0, wired) else {
        // No link is no way to hear the controller: the watchdog resets
        // the part, and the boot after it tries again.
        loop {
            esp_hal::delay::Delay::new().delay_millis(1_000);
        }
    };
    let mut uart = uart
        .with_rx(p.GPIO17)
        .with_tx(p.GPIO16)
        .with_cts(p.GPIO4)
        .with_rts(p.GPIO5);
    let mut reader = FrameReader::new();
    let mut writer = FrameWriter::new();

    // 3. The download window (F-033, F-034). Does not return when honoured.
    window::run(&mut uart, &mut reader, &mut writer, &mut rtc.rwdt);

    // 4. The window has run: this image honours it, which is what makes it
    // safe to keep (F-036). A slot in pending verification is confirmed.
    ota::confirm_if_pending(p.FLASH);

    // 5. The scheduler, then the true random source for the `boot_id`
    // (F-035): the bare RNG is pseudo-random until the ADC feeds it.
    let timg0 = TimerGroup::new(p.TIMG0);
    esp_rtos::start(timg0.timer0, p.FROM_CPU_INTR0);
    let _entropy = TrngSource::new(p.RNG, p.ADC1);
    let boot_id = Rng::new().random();

    // 6. The executor, entered only now, and the link on it for the rest
    // of the run. The pool holds one and this is its only spawn; a refusal
    // leaves the watchdog unfed, which is the reset that tries again, and so
    // does an executor that is somehow already taken.
    let uart = uart.into_async();
    let Some(executor) = EXECUTOR.try_init(Executor::new()) else {
        loop {
            esp_hal::delay::Delay::new().delay_millis(1_000);
        }
    };
    executor.run(
        move |spawner| match link::run(uart, reader, writer, rtc.rwdt, boot_id) {
            Ok(token) => spawner.spawn(token),
            Err(_) => loop {
                esp_hal::delay::Delay::new().delay_millis(1_000);
            },
        },
    )
}
