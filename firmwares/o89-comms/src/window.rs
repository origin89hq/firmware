//! The download window's wire (F-033, F-034, L-190): UART0 read for the
//! window's length before anything else runs, each byte handed to the
//! window in `o89-comms-core`, which decides; this file owns the UART, the
//! ROM's flag and the reset.
//!
//! A read that fails loses what it held, and the frame reader finds the
//! next frame at its delimiter. The ROM is entered only once `entering` has
//! left the pin: an answer that does not build or does not go out leaves
//! the window listening, and the controller's next knock, 100 ms later
//! under the same id, is answered instead (L-192).

use esp_hal::Blocking;
use esp_hal::peripherals::LP_AON;
use esp_hal::rtc_cntl::Rwdt;
use esp_hal::time::Instant;
use esp_hal::uart::Uart;
use km43::{FrameReader, FrameWriter, MAX_FRAME};
use o89_comms_core::{Honour, Tick, Window, WindowRan};

/// Run the window on `uart`. Returns the proof it ran once it has closed,
/// which is the only thing the OTA slot is confirmed against (F-089);
/// never returns when a request was honoured.
pub fn run(
    uart: &mut Uart<'_, Blocking>,
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    rwdt: &mut Rwdt,
) -> WindowRan {
    let window = Window::open(now());
    let mut chunk = [0u8; 64];
    // Bounded by the window: every turn either reads what the FIFO holds
    // or passes, and the watchdog is fed on each.
    loop {
        if let Some(ran) = window.closed(now()) {
            return ran;
        }
        rwdt.feed();
        if !uart.read_ready() {
            continue;
        }
        let Ok(count) = uart.read(&mut chunk) else {
            continue;
        };
        for byte in chunk.get(..count).unwrap_or(&[]) {
            if let Some(honour) = window.take(reader, *byte, now())
                && answered(uart, writer, honour)
            {
                enter_download(rwdt);
            }
        }
    }
}

/// The part's clock as the window reads it.
fn now() -> Tick {
    Tick::from_millis(Instant::now().duration_since_epoch().as_millis())
}

/// `entering`, flushed out of the pin before the reset takes the FIFO.
/// Whether all of it left.
fn answered(uart: &mut Uart<'_, Blocking>, writer: &mut FrameWriter, honour: Honour) -> bool {
    let mut frame = [0u8; MAX_FRAME];
    let Ok(len) = honour.answer(writer, &mut frame) else {
        return false;
    };
    let mut bytes = frame.get(..len).unwrap_or(&[]);
    // Bounded by the frame: every turn writes at least one byte or stops.
    while !bytes.is_empty() {
        match uart.write(bytes) {
            Ok(0) | Err(_) => return false,
            Ok(n) => bytes = bytes.get(n..).unwrap_or(&[]),
        }
    }
    uart.flush().is_ok()
}

/// The ROM's route into serial download: the watchdog disarmed, then
/// `FORCE_DOWNLOAD_BOOT` in `LP_AON.SYS_CFG`, then a reset. Nothing runs
/// after this. The watchdog goes first because it lives in the LP domain
/// and outlives the software reset, and the ROM's loader does not feed it:
/// left armed, it reset the chip out of the loader eight seconds in, after
/// esptool's erase and before its first write (bench 2026-09-19).
fn enter_download(rwdt: &mut Rwdt) -> ! {
    rwdt.disable();
    LP_AON::regs()
        .sys_cfg()
        .modify(|_, w| w.force_download_boot().set_bit());
    esp_hal::system::software_reset()
}
