//! Why the part reset and what the backup domain says, read from the
//! registers.
//!
//! The reset flags stay set until software clears them, so they are read
//! before the HAL initialises and cleared right after, and the next boot
//! reads its own reason rather than this one's (F-009). The RTC's clock is
//! read from the backup domain after the HAL has configured it, and what it
//! says is the answer: an RTC on the LSI is a fault, never a fallback
//! (F-010).

use o89_core::{BackupDomain, ResetFlags, RtcClock, RtcSource};
use stm32_metapac::rcc::vals::Rtcsel;
use stm32_metapac::{RCC, RTC};

/// Read the reset flags and clear them. Call before `embassy_stm32::init`.
pub fn take_flags() -> ResetFlags {
    let csr = RCC.csr().read();
    let flags = ResetFlags::NONE
        .pin(csr.pinrstf())
        .power(csr.pwrrstf())
        .watchdog(csr.iwdgrstf())
        .window_watchdog(csr.wwdgrstf())
        .software(csr.sftrstf())
        .low_power(csr.lpwrrstf())
        .option_byte(csr.oblrstf());
    RCC.csr().modify(|w| w.set_rmvf(true));
    flags
}

/// What clocks the RTC, as the backup domain reports it. Call after the
/// HAL has configured the clocks.
pub fn rtc_clock() -> RtcClock {
    let bdcr = RCC.bdcr().read();
    let source = match bdcr.rtcsel() {
        Rtcsel::Disable => RtcSource::None,
        Rtcsel::Lse => RtcSource::Lse,
        Rtcsel::Lsi => RtcSource::Lsi,
        Rtcsel::HseDiv32 => RtcSource::Hse,
    };
    RtcClock::from_backup_domain(bdcr.lserdy(), source)
}

/// Whether the RTC's calendar was initialised before this boot and kept
/// running: the backup domain's own statement (L-143).
pub fn backup_domain() -> BackupDomain {
    RCC.apbenr1().modify(|w| w.set_rtcapben(true));
    if RTC.icsr().read().inits() {
        BackupDomain::Valid
    } else {
        BackupDomain::Invalid
    }
}
