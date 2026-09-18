//! No panic path in production: the reason is written down, and the part
//! resets into its fail state.
//!
//! A controller that panics silently and reboots into an unexplained state
//! is the one failure that cannot be debugged from four hours away. The
//! production handler writes where the panic happened to the last words,
//! which the next boot's record carries, and resets; the reason reaches
//! FRAM with M2. The bench build keeps `panic-probe` instead, which halts
//! with the message on the probe.

#[cfg(feature = "bench")]
use panic_probe as _;

#[cfg(not(feature = "bench"))]
mod production {
    use core::panic::PanicInfo;

    use cortex_m::peripheral::SCB;
    use o89_core::{LastWords, PanicSite};

    use crate::last_words;

    /// FNV-1a over the file's path: 32 bits the host resolves against the
    /// image that was running.
    fn fnv1a(bytes: &[u8]) -> u32 {
        bytes.iter().fold(0x811C_9DC5, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
        })
    }

    #[panic_handler]
    fn panic(info: &PanicInfo) -> ! {
        let site = info
            .location()
            .map_or(PanicSite { file: 0, line: 0 }, |at| PanicSite {
                file: fnv1a(at.file().as_bytes()),
                line: at.line(),
            });
        last_words::write(LastWords::Panicked(site));
        SCB::sys_reset()
    }
}
