//! A panic is a reset.
//!
//! Nothing here can print: the module's only wire on board A is the link,
//! and a panic message on it would be bytes in a CRC (#2). The reset is
//! immediate rather than the watchdog's eight seconds later, so the window
//! re-opens as soon as it can; what panicked is not recorded on this side,
//! and the controller's log shows the module's `boot_id` change.

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    esp_hal::system::software_reset()
}
