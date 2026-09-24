//! Diagnostic radio reports only: P-216–P-221 and L-200–L-207.
use crate::Tick;
use core::num::NonZeroU32;
use km43::{
    HeldList, LinkEnvelope, LinkMessageType, Radio, RadioReport, ReqId, ScanAnswer, ScanOrder,
    ScanRefusal, ScanResult, ScanState, WifiError, WifiStatus, WifiStatusChanged,
};

/// One encoded result, bounded by the protocol's maximum payload. Overflow
/// refuses a replacement and retains the previous list.
pub const WIFI_LIST_BYTES: usize = km43::MAX_PAYLOAD;
/// Shared refresh interval on the monotonic clock (P-218).
pub const WIFI_SCAN_INTERVAL_MS: u64 = 10_000;
/// Result deadline after the started acknowledgement (L-203).
pub const WIFI_SCAN_TIMEOUT_MS: u64 = 15_000;
/// Same-version diagnostic record interval (P-220).
pub const WIFI_RECORD_INTERVAL_MS: u64 = 600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    order: ScanOrder,
    started: Option<Tick>,
}

/// One scan, one retained list, and one report. None grants authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wifi {
    pending: Option<Pending>,
    next: Option<NonZeroU32>,
    last_start: Option<Tick>,
    state: ScanState,
    list: [u8; WIFI_LIST_BYTES],
    list_len: usize,
    list_at: Tick,
    report: Option<RadioReport>,
    announced: Option<(RadioReport, Tick)>,
}

impl Wifi {
    /// Empty diagnostic state at controller boot; scan numbers never wrap.
    pub const EMPTY: Self = Self {
        pending: None,
        next: Some(NonZeroU32::MIN),
        last_start: None,
        state: ScanState::None,
        list: [0; WIFI_LIST_BYTES],
        list_len: 0,
        list_at: Tick::ZERO,
        report: None,
        announced: None,
    };

    /// P-218: joining precedes refusals; otherwise the first gate wins.
    #[must_use]
    pub fn refresh(
        &mut self,
        authorised: bool,
        written: bool,
        linked: bool,
        now: Tick,
    ) -> Option<ScanRefusal> {
        if self.pending.is_some() {
            return None;
        }
        let refused = if !authorised {
            Some(ScanRefusal::Unauthorised)
        } else if !written {
            Some(ScanRefusal::RadioOff)
        } else if !linked {
            Some(ScanRefusal::LinkDown)
        } else if self
            .last_start
            .is_some_and(|at| elapsed(now, at) < WIFI_SCAN_INTERVAL_MS)
        {
            Some(ScanRefusal::TooSoon)
        } else {
            None
        };
        if refused.is_some() {
            return refused;
        }
        let Some(scan) = self.next else {
            self.state = ScanState::Failed;
            return None;
        };
        self.next = scan.get().checked_add(1).and_then(NonZeroU32::new);
        self.pending = Some(Pending {
            order: ScanOrder { scan },
            started: None,
        });
        self.last_start = Some(now);
        self.state = ScanState::Running;
        None
    }

    /// The only order that may be issued or retried.
    #[must_use]
    pub const fn order(&self) -> Option<ScanOrder> {
        match self.pending {
            Some(pending) => Some(pending.order),
            None => None,
        }
    }

    /// Whether the order has already been accepted.
    #[must_use]
    pub fn started_already(&self) -> bool {
        self.pending
            .is_some_and(|pending| pending.started.is_some())
    }

    /// Start the result deadline only on a matching started acknowledgement.
    pub fn started(&mut self, now: Tick) {
        if let Some(pending) = &mut self.pending {
            pending.started = Some(now);
        }
    }

    /// Refusal, give-up, or timeout retains the last completed list.
    pub fn failed(&mut self) {
        if self.pending.take().is_some() {
            self.state = ScanState::Failed;
        }
    }

    /// A stale scan is acknowledged by the link but discarded here.
    pub fn result(&mut self, result: ScanResult<'_>, now: Tick) {
        if self.order().is_none_or(|order| order.scan != result.scan) {
            return;
        }
        if result.list.is_some() {
            let mut bytes = [0; WIFI_LIST_BYTES];
            let Ok(len) = result.write(
                o89_link::link_header(LinkMessageType::WifiScanResult, ReqId(1)),
                &mut bytes,
            ) else {
                self.failed();
                return;
            };
            self.list = bytes;
            self.list_len = len;
            self.list_at = now;
            self.pending = None;
            self.state = ScanState::Complete;
        } else {
            self.failed();
        }
    }

    /// P-217: read the held bytes through the published codec, without translating rows.
    pub fn answer(
        &self,
        refused: Option<ScanRefusal>,
        now: Tick,
        dst: &mut [u8],
    ) -> Result<usize, WifiError> {
        let held = self
            .list
            .get(..self.list_len)
            .and_then(|bytes| LinkEnvelope::decode(bytes).ok())
            .and_then(|envelope| ScanResult::decode(envelope).ok())
            .and_then(|result| result.list)
            .map(|list| HeldList {
                age_ms: u32::try_from(elapsed(now, self.list_at)).unwrap_or(u32::MAX),
                list,
            });
        ScanAnswer::new(self.state, refused, held)?.encode(dst)
    }

    /// P-219: the section version and current-boot report remain distinct.
    #[must_use]
    pub const fn status(&self, section: u32) -> WifiStatus {
        WifiStatus {
            section,
            report: self.report,
        }
    }

    /// L-207: this stores a diagnostic and changes no configuration.
    pub fn reported(&mut self, report: RadioReport) {
        self.report = Some(report);
    }

    /// P-219 and L-203: no report survives a lost link or another comms boot.
    pub fn lost(&mut self) {
        self.report = None;
        self.failed();
    }

    /// L-203: equality with the deadline is expired.
    pub fn tick(&mut self, now: Tick) {
        if self
            .pending
            .and_then(|pending| pending.started)
            .is_some_and(|at| elapsed(now, at) >= WIFI_SCAN_TIMEOUT_MS)
        {
            self.failed();
        }
    }

    /// P-220: announce the state held now, suppress joining and address-only changes.
    #[must_use]
    pub fn record(&self, section: u32, now: Tick) -> Option<WifiStatusChanged> {
        let report = self.report?;
        if matches!(report.radio, Radio::Joining) {
            return None;
        }
        if let Some((previous, at)) = self.announced {
            if same_announcement(previous, report) {
                return None;
            }
            if previous.version == report.version && elapsed(now, at) < WIFI_RECORD_INTERVAL_MS {
                return None;
            }
        }
        Some(WifiStatusChanged { section, report })
    }
    /// Advance the record rate only after the recorder queue accepted the decision.
    pub fn recorded(&mut self, record: WifiStatusChanged, now: Tick) {
        self.announced = Some((record.report, now));
    }
}

fn same_announcement(left: RadioReport, right: RadioReport) -> bool {
    left.version == right.version
        && match (left.radio, right.radio) {
            (Radio::Joined { .. }, Radio::Joined { .. }) => true,
            (a, b) => a == b,
        }
}

fn elapsed(now: Tick, at: Tick) -> u64 {
    now.as_millis().saturating_sub(at.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use km43::{ScanList, WifiFailure};
    fn record(wifi: &mut Wifi, section: u32, now: Tick) -> Option<WifiStatusChanged> {
        let record = wifi.record(section, now);
        if let Some(record) = record {
            wifi.recorded(record, now);
        }
        record
    }
    #[test]
    fn f_093_p_220_full_recorder_queue_keeps_the_record_due_without_spending_the_interval() {
        let mut wifi = Wifi::EMPTY;
        wifi.reported(RadioReport {
            version: 1,
            radio: Radio::Off,
        });
        let due = wifi.record(1, at(0)).expect("due");
        assert_eq!(
            wifi.record(1, at(1)),
            Some(due),
            "queue refused: remains due"
        );
        wifi.recorded(due, at(1));
        assert_eq!(wifi.record(1, at(2)), None);
    }
    fn at(ms: u64) -> Tick {
        Tick::from_millis(ms)
    }
    fn started(wifi: &mut Wifi, ms: u64) -> ScanOrder {
        assert_eq!(wifi.refresh(true, true, true, at(ms)), None);
        let order = wifi.order().expect("one scan");
        wifi.started(at(ms));
        order
    }
    fn answer(wifi: &Wifi, now: u64) -> (ScanState, Option<u32>, usize) {
        let mut bytes = [0; WIFI_LIST_BYTES];
        let len = wifi.answer(None, at(now), &mut bytes).expect("encodes");
        let answer = ScanAnswer::decode(&bytes[..len]).expect("decodes");
        (
            answer.scan(),
            answer.held().map(|held| held.age_ms),
            answer.held().map_or(0, |held| held.list.len()),
        )
    }
    #[test]
    fn p_218_first_gate_wins_running_joins_and_exactly_ten_seconds_permits() {
        let mut wifi = Wifi::EMPTY;
        for (auth, written, linked, refused) in [
            (false, false, false, ScanRefusal::Unauthorised),
            (true, false, false, ScanRefusal::RadioOff),
            (true, true, false, ScanRefusal::LinkDown),
        ] {
            assert_eq!(wifi.refresh(auth, written, linked, at(0)), Some(refused));
        }
        let one = started(&mut wifi, 0);
        assert_eq!(wifi.refresh(false, false, false, at(1)), None);
        assert_eq!(wifi.order(), Some(one));
        wifi.failed();
        assert_eq!(
            wifi.refresh(true, true, true, at(9999)),
            Some(ScanRefusal::TooSoon)
        );
        assert_eq!(wifi.refresh(true, true, true, at(10_000)), None);
        assert_eq!(wifi.order().expect("next").scan.get(), 2);
    }
    #[test]
    fn p_217_l_203_failed_refresh_keeps_completed_empty_list_and_its_age() {
        let mut wifi = Wifi::EMPTY;
        assert_eq!(answer(&wifi, 0), (ScanState::None, None, 0));
        let order = started(&mut wifi, 0);
        wifi.result(
            ScanResult {
                scan: order.scan,
                list: Some(ScanList::new(&[], 0).expect("empty")),
            },
            at(100),
        );
        assert_eq!(answer(&wifi, 200), (ScanState::Complete, Some(100), 0));
        started(&mut wifi, 10_000);
        wifi.failed();
        assert_eq!(answer(&wifi, 11_000), (ScanState::Failed, Some(10_900), 0));
    }
    #[test]
    fn l_200_l_203_late_number_is_discarded_and_timeout_starts_at_ack() {
        let mut wifi = Wifi::EMPTY;
        assert_eq!(wifi.refresh(true, true, true, at(0)), None);
        assert_eq!(wifi.order().expect("first").scan.get(), 1);
        wifi.tick(at(20_000));
        assert_eq!(answer(&wifi, 20_000).0, ScanState::Running);
        wifi.started(at(20_000));
        wifi.result(
            ScanResult {
                scan: NonZeroU32::new(2).expect("nonzero"),
                list: None,
            },
            at(21_000),
        );
        wifi.tick(at(34_999));
        assert_eq!(answer(&wifi, 34_999).0, ScanState::Running);
        wifi.tick(at(35_000));
        assert_eq!(answer(&wifi, 35_000).0, ScanState::Failed);
    }
    #[test]
    fn p_219_l_203_lost_boot_drops_report_and_fails_running_scan() {
        let mut wifi = Wifi::EMPTY;
        started(&mut wifi, 0);
        wifi.reported(RadioReport {
            version: 4,
            radio: Radio::Joined { ipv4: [1, 2, 3, 4] },
        });
        assert_eq!(wifi.status(5).report.expect("report").version, 4);
        wifi.lost();
        assert_eq!(
            wifi.status(5),
            WifiStatus {
                section: 5,
                report: None
            }
        );
        assert_eq!(answer(&wifi, 1).0, ScanState::Failed);
    }
    #[test]
    fn f_093_p_220_ten_minute_boundary_uses_current_state_and_new_version_is_immediate() {
        let mut wifi = Wifi::EMPTY;
        let joined = RadioReport {
            version: 1,
            radio: Radio::Joined { ipv4: [1, 2, 3, 4] },
        };
        wifi.reported(RadioReport {
            version: 1,
            radio: Radio::Joining,
        });
        assert_eq!(record(&mut wifi, 1, at(0)), None);
        wifi.reported(joined);
        assert_eq!(record(&mut wifi, 1, at(1)).expect("first").report, joined);
        wifi.reported(RadioReport {
            version: 1,
            radio: Radio::Failed {
                reason: WifiFailure::Lost,
            },
        });
        assert_eq!(record(&mut wifi, 1, at(600_000)), None);
        let latest = RadioReport {
            version: 1,
            radio: Radio::Failed {
                reason: WifiFailure::NoIp,
            },
        };
        wifi.reported(latest);
        assert_eq!(
            record(&mut wifi, 1, at(600_001)).expect("boundary").report,
            latest
        );
        wifi.reported(RadioReport {
            version: 2,
            radio: Radio::Off,
        });
        assert_eq!(
            record(&mut wifi, 2, at(600_002))
                .expect("new version")
                .report
                .version,
            2
        );
        assert_eq!(record(&mut wifi, 2, at(1_200_002)), None);
    }
    #[test]
    fn p_220_recovered_state_cancels_deferred_record_and_ip_alone_is_not_a_change() {
        let mut wifi = Wifi::EMPTY;
        let joined = RadioReport {
            version: 1,
            radio: Radio::Joined { ipv4: [1, 2, 3, 4] },
        };
        wifi.reported(joined);
        assert!(record(&mut wifi, 1, at(0)).is_some());
        wifi.reported(RadioReport {
            version: 1,
            radio: Radio::Failed {
                reason: WifiFailure::Lost,
            },
        });
        assert!(record(&mut wifi, 1, at(1)).is_none());
        wifi.reported(RadioReport {
            version: 1,
            radio: Radio::Joined { ipv4: [1, 2, 3, 5] },
        });
        assert!(record(&mut wifi, 1, at(600_000)).is_none());
    }
}
