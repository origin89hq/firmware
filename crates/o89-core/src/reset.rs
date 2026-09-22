//! Why the part reset, what the RTC's backup domain says, and the record a
//! boot writes about both.
//!
//! The reset flags live in `RCC.CSR` and stay set until software clears
//! them, so the adapter reads them before the HAL initialises and clears
//! them right after; what it reads is decoded here, where a laptop can check
//! that a watchdog reset is never reported as a power-on. An RTC on the LSI
//! keeps time to a few percent, looks alive and does not survive the backup
//! domain, so the LSE is asserted rather than assumed, and a backup domain
//! the RTC reports invalid is recorded rather than inferred months later
//! (L-143).
//!
//! cites: F-009, F-010

use km43::{Boot, BootCause, Starved};

use crate::{LastWords, RailThroughReset, Revision};

/// The reset flags as `RCC.CSR` reports them. Several can be set at once,
/// so this is a set, built from the register one flag at a time:
/// `ResetFlags::NONE.pin(csr.pinrstf()).power(csr.pwrrstf())` and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ResetFlags(u8);

impl ResetFlags {
    /// No flag set.
    pub const NONE: Self = Self(0);

    const PIN: u8 = 1 << 0;
    const POWER: u8 = 1 << 1;
    const WATCHDOG: u8 = 1 << 2;
    const WINDOW_WATCHDOG: u8 = 1 << 3;
    const SOFTWARE: u8 = 1 << 4;
    const LOW_POWER: u8 = 1 << 5;
    const OPTION_BYTE: u8 = 1 << 6;

    const fn with(self, flag: u8, set: bool) -> Self {
        if set { Self(self.0 | flag) } else { self }
    }

    const fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// `PINRSTF`: the `NRST` pin, which revision A does not bring out.
    #[must_use]
    pub const fn pin(self, set: bool) -> Self {
        self.with(Self::PIN, set)
    }

    /// `PWRRSTF`: power-on, power-down or brown-out, which share one flag.
    #[must_use]
    pub const fn power(self, set: bool) -> Self {
        self.with(Self::POWER, set)
    }

    /// `IWDGRSTF`: the independent watchdog starved.
    #[must_use]
    pub const fn watchdog(self, set: bool) -> Self {
        self.with(Self::WATCHDOG, set)
    }

    /// `WWDGRSTF`: the window watchdog, which no image starts.
    #[must_use]
    pub const fn window_watchdog(self, set: bool) -> Self {
        self.with(Self::WINDOW_WATCHDOG, set)
    }

    /// `SFTRSTF`: a software-requested reset.
    #[must_use]
    pub const fn software(self, set: bool) -> Self {
        self.with(Self::SOFTWARE, set)
    }

    /// `LPWRRSTF`: an illegal low-power mode entry.
    #[must_use]
    pub const fn low_power(self, set: bool) -> Self {
        self.with(Self::LOW_POWER, set)
    }

    /// `OBLRSTF`: an option-byte reload.
    #[must_use]
    pub const fn option_byte(self, set: bool) -> Self {
        self.with(Self::OPTION_BYTE, set)
    }
}

/// Why the part reset. One cause per boot: the most specific flag wins,
/// because a watchdog reset also raises the pin flag on this family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ResetCause {
    /// Power-on, power-down or brown-out. A sagging supply lands here.
    Power,
    /// The `NRST` pin.
    Pin,
    /// The independent watchdog starved: a task stopped checking in.
    Watchdog,
    /// The window watchdog, which no image of ours starts.
    WindowWatchdog,
    /// A software-requested reset: the panic path, or a deliberate one.
    Software,
    /// An illegal low-power mode entry.
    LowPower,
    /// An option-byte reload: the bank flip.
    OptionByte,
}

impl ResetCause {
    /// Decode the flags, the most specific first.
    #[must_use]
    pub const fn from_flags(flags: ResetFlags) -> Self {
        if flags.has(ResetFlags::WATCHDOG) {
            Self::Watchdog
        } else if flags.has(ResetFlags::WINDOW_WATCHDOG) {
            Self::WindowWatchdog
        } else if flags.has(ResetFlags::SOFTWARE) {
            Self::Software
        } else if flags.has(ResetFlags::LOW_POWER) {
            Self::LowPower
        } else if flags.has(ResetFlags::OPTION_BYTE) {
            Self::OptionByte
        } else if flags.has(ResetFlags::PIN) && !flags.has(ResetFlags::POWER) {
            Self::Pin
        } else {
            Self::Power
        }
    }
}

/// What `RCC.BDCR` selects as the RTC's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RtcSource {
    /// No clock: the RTC is not running.
    None,
    /// The 32.768 kHz crystal.
    Lse,
    /// The internal RC, which does not survive the backup domain.
    Lsi,
    /// The high-speed crystal divided down, which stops with the core.
    Hse,
}

/// The RTC's clock, asserted from the backup domain rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RtcClock {
    /// The crystal is ready and selected.
    Lse,
    /// Anything else: reported as a fault, never taken as a fallback.
    Fault {
        /// Whether the crystal had started at all.
        lse_ready: bool,
        /// What was selected instead, or as well.
        source: RtcSource,
    },
}

impl RtcClock {
    /// Read the backup domain's answer: only a ready crystal that is also
    /// selected counts.
    #[must_use]
    pub const fn from_backup_domain(lse_ready: bool, source: RtcSource) -> Self {
        match (lse_ready, source) {
            (true, RtcSource::Lse) => Self::Lse,
            (false, RtcSource::Lse) | (_, RtcSource::None | RtcSource::Lsi | RtcSource::Hse) => {
                Self::Fault { lse_ready, source }
            }
        }
    }
}

/// Whether the RTC's backup domain kept its state through the reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BackupDomain {
    /// The calendar was initialised before this boot and is still running.
    Valid,
    /// The RTC reports it never initialised, or lost it: a dead cell, or a
    /// first boot. L-143 says this is recorded, not inferred.
    Invalid,
}

/// What a boot writes down about itself, before anything else happens: the
/// class A boot record (`0x0601`) on the ring, and the line on the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BootRecord {
    /// Why the part reset.
    pub cause: ResetCause,
    /// What the previous run wrote before it stopped, if it did.
    pub words: Option<LastWords>,
    /// What clocks the RTC.
    pub rtc: RtcClock,
    /// Whether the backup domain survived.
    pub backup: BackupDomain,
    /// The board this image was built for.
    pub revision: Revision,
    /// Whether this reset power-cycled the module: on revision A every
    /// reset does, which nobody chose, and the record says so (F-014).
    pub module_rail_cycled: bool,
}

impl BootRecord {
    /// Assemble the record from what the adapter read.
    #[must_use]
    pub const fn new(
        cause: ResetCause,
        words: Option<LastWords>,
        rtc: RtcClock,
        backup: BackupDomain,
        revision: Revision,
    ) -> Self {
        let module_rail_cycled = matches!(revision.rail_through_reset(), RailThroughReset::Off);
        Self {
            cause,
            words,
            rtc,
            backup,
            revision,
            module_rail_cycled,
        }
    }

    /// The record as KM43's boot body carries it.
    ///
    /// Last words ride only with the reset they explain (P-214): a starved
    /// task with the watchdog that starving it fired, a panic site with the
    /// software reset the panic handler asks for. Words beside any other
    /// cause are from a run that did not end the way they say, and are left
    /// to the probe's log rather than put in a record that contradicts
    /// itself. A software reset with a panic site is a panic.
    #[must_use]
    pub fn body(&self) -> Boot {
        let cause = match (self.cause, self.words) {
            (ResetCause::Watchdog, Some(LastWords::Starved(blame))) => {
                BootCause::Watchdog(Some(Starved {
                    task: blame.task.byte(),
                    overdue_ms: u32::try_from(blame.overdue.as_millis()).unwrap_or(u32::MAX),
                }))
            }
            (ResetCause::Watchdog, None | Some(LastWords::Panicked(_))) => {
                BootCause::Watchdog(None)
            }
            (ResetCause::Software, Some(LastWords::Panicked(site))) => {
                BootCause::Panic(km43::PanicSite {
                    file: site.file,
                    line: site.line,
                })
            }
            (ResetCause::Software, None | Some(LastWords::Starved(_))) => BootCause::SoftwareReset,
            (ResetCause::Power, _) => BootCause::Power,
            (ResetCause::Pin, _) => BootCause::PinReset,
            (ResetCause::WindowWatchdog, _) => BootCause::WindowWatchdog,
            (ResetCause::LowPower, _) => BootCause::LowPowerEntry,
            (ResetCause::OptionByte, _) => BootCause::OptionByteReload,
        };
        Boot {
            cause,
            backup_valid: matches!(self.backup, BackupDomain::Valid),
            rtc_crystal: matches!(self.rtc, RtcClock::Lse),
            rail_cycled: self.module_rail_cycled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blame, Millis, PanicSite, Task};

    #[test]
    fn f_009_the_most_specific_reset_flag_names_the_cause() {
        // A watchdog reset also raises the pin flag on this family, and a
        // boot that read that as a pin reset would hide every starvation.
        let starved = ResetFlags::NONE.watchdog(true).pin(true);
        assert_eq!(ResetCause::from_flags(starved), ResetCause::Watchdog);
        let panicked = ResetFlags::NONE.software(true).pin(true);
        assert_eq!(ResetCause::from_flags(panicked), ResetCause::Software);
        let flipped = ResetFlags::NONE.option_byte(true).pin(true);
        assert_eq!(ResetCause::from_flags(flipped), ResetCause::OptionByte);
        // Every flag at once, as a register full of history reads: still
        // the watchdog, and never the pin.
        let all = ResetFlags::NONE
            .pin(true)
            .power(true)
            .watchdog(true)
            .window_watchdog(true)
            .software(true)
            .low_power(true)
            .option_byte(true);
        assert_eq!(ResetCause::from_flags(all), ResetCause::Watchdog);
    }

    #[test]
    fn f_009_a_pin_reset_is_only_one_with_no_power_flag() {
        let pin = ResetFlags::NONE.pin(true);
        assert_eq!(ResetCause::from_flags(pin), ResetCause::Pin);
        // Power-on raises both; a brown-out is not somebody pressing reset.
        let cold = ResetFlags::NONE.pin(true).power(true);
        assert_eq!(ResetCause::from_flags(cold), ResetCause::Power);
        // A flag passed as false is not set.
        assert_eq!(ResetFlags::NONE.pin(false), ResetFlags::NONE);
    }

    #[test]
    fn f_009_no_flag_at_all_reads_as_power() {
        // Flags already cleared, or a part that reports nothing: the boot
        // is not left without a cause, and the cause is the one that cannot
        // be mistaken for a fault of ours.
        assert_eq!(ResetCause::from_flags(ResetFlags::NONE), ResetCause::Power);
        assert_eq!(ResetFlags::default(), ResetFlags::NONE);
    }

    #[test]
    fn f_010_only_a_ready_and_selected_crystal_is_the_rtc_clock() {
        assert_eq!(
            RtcClock::from_backup_domain(true, RtcSource::Lse),
            RtcClock::Lse
        );
        // Selected but not ready: the RTC is not ticking.
        assert_eq!(
            RtcClock::from_backup_domain(false, RtcSource::Lse),
            RtcClock::Fault {
                lse_ready: false,
                source: RtcSource::Lse
            }
        );
        // The LSI fallback looks alive and is a fault, never a clock.
        assert_eq!(
            RtcClock::from_backup_domain(true, RtcSource::Lsi),
            RtcClock::Fault {
                lse_ready: true,
                source: RtcSource::Lsi
            }
        );
        assert_eq!(
            RtcClock::from_backup_domain(false, RtcSource::None),
            RtcClock::Fault {
                lse_ready: false,
                source: RtcSource::None
            }
        );
    }

    fn starved() -> LastWords {
        LastWords::Starved(Blame {
            task: Task::OneWire,
            overdue: Millis::from_millis(31_000),
        })
    }

    fn panicked() -> LastWords {
        LastWords::Panicked(PanicSite {
            file: 0x9E37_79B9,
            line: 212,
        })
    }

    fn record(cause: ResetCause, words: Option<LastWords>) -> BootRecord {
        BootRecord::new(
            cause,
            words,
            RtcClock::Lse,
            BackupDomain::Valid,
            Revision::B,
        )
    }

    #[test]
    fn f_014_the_boot_record_says_the_rail_cycled_on_revision_a_only() {
        let on_a = BootRecord::new(
            ResetCause::Watchdog,
            Some(starved()),
            RtcClock::Lse,
            BackupDomain::Valid,
            Revision::A,
        );
        assert!(on_a.module_rail_cycled);
        assert!(on_a.body().rail_cycled, "the ring says what the probe said");
        assert_eq!(on_a.words, Some(starved()));
        let on_b = BootRecord::new(
            ResetCause::Watchdog,
            None,
            RtcClock::Lse,
            BackupDomain::Invalid,
            Revision::B,
        );
        assert!(!on_b.module_rail_cycled);
        assert!(!on_b.body().rail_cycled);
        assert_eq!(on_b.backup, BackupDomain::Invalid);
    }

    #[test]
    fn f_008_the_ring_names_the_task_that_starved_the_watchdog() {
        let body = record(ResetCause::Watchdog, Some(starved())).body();
        assert_eq!(
            body.cause,
            BootCause::Watchdog(Some(Starved {
                task: Task::OneWire.byte(),
                overdue_ms: 31_000,
            }))
        );
        assert_eq!(
            Task::from_index(u32::from(Task::OneWire.byte())),
            Some(Task::OneWire)
        );
        // A watchdog the previous run never got to explain is still a
        // watchdog, with nobody named.
        assert_eq!(
            record(ResetCause::Watchdog, None).body().cause,
            BootCause::Watchdog(None)
        );
        // An overdue past a u32 of milliseconds saturates, as the words do.
        let long = LastWords::Starved(Blame {
            task: Task::Rail,
            overdue: Millis::from_millis(u64::MAX),
        });
        assert_eq!(
            record(ResetCause::Watchdog, Some(long)).body().cause,
            BootCause::Watchdog(Some(Starved {
                task: Task::Rail.byte(),
                overdue_ms: u32::MAX,
            }))
        );
    }

    #[test]
    fn f_008_a_software_reset_with_a_panic_site_is_a_panic_and_without_one_is_not() {
        assert_eq!(
            record(ResetCause::Software, Some(panicked())).body().cause,
            BootCause::Panic(km43::PanicSite {
                file: 0x9E37_79B9,
                line: 212,
            })
        );
        assert_eq!(
            record(ResetCause::Software, None).body().cause,
            BootCause::SoftwareReset
        );
    }

    #[test]
    fn p_214_last_words_beside_a_cause_they_do_not_explain_stay_off_the_ring() {
        // A panic site beside a watchdog, a starved task beside a software
        // reset, and either beside a cause with no words of its own: each
        // body carries the cause alone, which is one KM43 decodes.
        let cases = [
            (ResetCause::Watchdog, panicked(), BootCause::Watchdog(None)),
            (ResetCause::Software, starved(), BootCause::SoftwareReset),
            (ResetCause::Power, panicked(), BootCause::Power),
            (ResetCause::Pin, starved(), BootCause::PinReset),
            (
                ResetCause::WindowWatchdog,
                starved(),
                BootCause::WindowWatchdog,
            ),
            (ResetCause::LowPower, panicked(), BootCause::LowPowerEntry),
            (
                ResetCause::OptionByte,
                starved(),
                BootCause::OptionByteReload,
            ),
        ];
        for (cause, words, expected) in cases {
            let body = record(cause, Some(words)).body();
            assert_eq!(body.cause, expected, "{cause:?} with {words:?}");
            let mut out = [0u8; km43::BOOT_MAX_BYTES];
            let len = body.encode(&mut out).expect("encodes");
            assert_eq!(
                Boot::decode(out.get(..len).expect("written")),
                Ok(body),
                "{cause:?}: a body KM43 refuses"
            );
        }
    }

    #[test]
    fn f_009_the_ring_carries_the_backup_domain_and_the_clock_as_they_were() {
        let dead = BootRecord::new(
            ResetCause::Power,
            None,
            RtcClock::Fault {
                lse_ready: true,
                source: RtcSource::Lsi,
            },
            BackupDomain::Invalid,
            Revision::A,
        )
        .body();
        assert_eq!(dead.cause, BootCause::Power);
        assert!(!dead.backup_valid, "a dead backup cell reads as a live one");
        assert!(!dead.rtc_crystal, "the LSI fallback reads as the crystal");
        let healthy = record(ResetCause::Pin, None).body();
        assert_eq!(healthy.cause, BootCause::PinReset);
        assert!(healthy.backup_valid && healthy.rtc_crystal);
        assert_eq!(
            record(ResetCause::OptionByte, None).body().cause,
            BootCause::OptionByteReload,
            "a bank swap read as a power cut"
        );
    }
}
