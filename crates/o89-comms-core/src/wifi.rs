//! Bounded scan reduction and diagnostic radio state (L-200–L-206).
use crate::Millis;
use core::num::NonZeroU32;
use km43::{
    AccessPoint, LinkEnvelope, LinkMessageType, Radio, RadioReport, ReqId, ScanList, ScanOrder,
    ScanResult, WifiBand, WifiScan, WifiSecurity,
};

/// The vendor scan API reports at most a u16 count. Larger input is refused.
pub const MAX_HEARD_APS: usize = u16::MAX as usize;
/// One result envelope; encoding overflow reports a failed scan.
pub const SCAN_RESULT_BYTES: usize = km43::MAX_PAYLOAD;
/// Associated this long without IPv4, the station reports `no_ip` (F-092).
pub const NO_IP: Millis = Millis::from_millis(4_000);
/// The DHCP client's wait before it resends DISCOVER. smoltcp waits 10 s,
/// so one lost DISCOVER read as `no_ip` for six seconds before the resend
/// (firmware #143); at 2 s it is resent inside the `no_ip` bound.
pub const DHCP_DISCOVER_RESEND: Millis = Millis::from_millis(2_000);
const _: () = assert!(DHCP_DISCOVER_RESEND.as_millis() < NO_IP.as_millis());

/// A borrowed observation at the adapter seam. Invalid UTF-8 has no SSID.
#[derive(Debug, Clone, Copy)]
pub struct HeardAp<'a> {
    /// None for non-UTF-8; empty for hidden.
    pub ssid: Option<&'a str>,
    /// Signal strength in dBm.
    pub rssi: i8,
    /// Protocol security classification.
    pub security: WifiSecurity,
    /// Channel in the 2.4 GHz band.
    pub channel: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    ssid: [u8; 32],
    len: usize,
    rssi: i8,
    security: WifiSecurity,
    channel: u8,
}
impl Row {
    const EMPTY: Self = Self {
        ssid: [0; 32],
        len: 0,
        rssi: i8::MIN,
        security: WifiSecurity::Other,
        channel: 1,
    };
    fn text(&self) -> &str {
        core::str::from_utf8(self.ssid.get(..self.len).unwrap_or(&[])).unwrap_or("")
    }
    fn borrowed(&self) -> AccessPoint<'_> {
        AccessPoint {
            ssid: self.text(),
            rssi: self.rssi,
            security: self.security,
            band: WifiBand::Ghz24,
            channel: self.channel,
        }
    }
}

/// At most 16 unique SSIDs, strongest first. Full means count omitted APs;
/// no retained row is evicted. Input must already be strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanRows {
    rows: [Row; km43::MAX_SCAN_APS],
    len: usize,
    unlisted: u16,
}

/// Input was not sorted, exceeded the vendor count, or contained an invalid row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidScan;

impl ScanRows {
    /// Consume a borrowed vendor slice in one bounded pass, without allocation.
    /// The adapter sorts its vendor-owned slice in place before this call.
    pub fn collect<T>(heard: &[T], read: impl Fn(&T) -> HeardAp<'_>) -> Result<Self, InvalidScan> {
        if heard.len() > MAX_HEARD_APS {
            return Err(InvalidScan);
        }
        let mut held = Self {
            rows: [Row::EMPTY; km43::MAX_SCAN_APS],
            len: 0,
            unlisted: 0,
        };
        let mut previous = i8::MAX;
        for raw in heard {
            let ap = read(raw);
            if ap.rssi > previous {
                return Err(InvalidScan);
            }
            previous = ap.rssi;
            let Some(ssid) = ap.ssid.filter(|ssid| !ssid.is_empty()) else {
                held.unlisted = held.unlisted.saturating_add(1);
                continue;
            };
            if ssid.len() > 32 || !(1..=14).contains(&ap.channel) {
                return Err(InvalidScan);
            }
            if held
                .rows
                .get(..held.len)
                .ok_or(InvalidScan)?
                .iter()
                .any(|row| row.text() == ssid)
            {
                continue;
            }
            let Some(row) = held.rows.get_mut(held.len) else {
                held.unlisted = held.unlisted.saturating_add(1);
                continue;
            };
            row.ssid
                .get_mut(..ssid.len())
                .ok_or(InvalidScan)?
                .copy_from_slice(ssid.as_bytes());
            row.len = ssid.len();
            row.rssi = ap.rssi;
            row.security = ap.security;
            row.channel = ap.channel;
            held.len = held.len.saturating_add(1);
        }
        Ok(held)
    }
    /// Encode exactly the rows selected above with the shared link codec.
    pub fn write(
        &self,
        scan: NonZeroU32,
        req_id: ReqId,
        dst: &mut [u8],
    ) -> Result<usize, InvalidScan> {
        let rows = self.rows.each_ref().map(Row::borrowed);
        let list = ScanList::new(rows.get(..self.len).ok_or(InvalidScan)?, self.unlisted)
            .map_err(|_| InvalidScan)?;
        ScanResult {
            scan,
            list: Some(list),
        }
        .write(
            o89_link::link_header(LinkMessageType::WifiScanResult, req_id),
            dst,
        )
        .map_err(|_| InvalidScan)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Active {
    order: ScanOrder,
    req_id: ReqId,
    taken: bool,
}

/// One scan/result and one latest radio report. All queues have depth one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiDiagnostics {
    active: Option<Active>,
    result: [u8; SCAN_RESULT_BYTES],
    result_len: usize,
    report: RadioReport,
    outcome: bool,
    association_since: Option<u64>,
    announced: Option<RadioReport>,
}
impl WifiDiagnostics {
    /// Empty NVS means version zero and off.
    pub const EMPTY: Self = Self {
        active: None,
        result: [0; SCAN_RESULT_BYTES],
        result_len: 0,
        report: RadioReport {
            version: 0,
            radio: Radio::Off,
        },
        outcome: false,
        association_since: None,
        announced: None,
    };
    /// Duplicate retries retain their first verdict; another order is busy
    /// until the result is acknowledged or given up (L-200, L-201).
    #[must_use]
    pub fn scan(&mut self, order: ScanOrder, req_id: ReqId, country: bool) -> WifiScan {
        if let Some(active) = self.active {
            return if active.order == order && active.req_id == req_id {
                WifiScan::Started
            } else {
                WifiScan::RefusedBusy
            };
        }
        if !country {
            return WifiScan::RefusedRadioOff;
        }
        self.active = Some(Active {
            order,
            req_id,
            taken: false,
        });
        WifiScan::Started
    }
    /// Hand the accepted order to the sole radio owner exactly once.
    #[must_use]
    pub fn take_scan(&mut self) -> Option<NonZeroU32> {
        let active = self.active.as_mut()?;
        if active.taken {
            return None;
        }
        active.taken = true;
        Some(active.order.scan)
    }
    /// Finish only the active scan, once. Failed encoding becomes a failed result.
    pub fn finished(&mut self, scan: NonZeroU32, rows: Option<&ScanRows>) {
        if self.active.is_none_or(|active| active.order.scan != scan) || self.result_len != 0 {
            return;
        }
        self.result_len = rows
            .and_then(|rows| rows.write(scan, ReqId(1), &mut self.result).ok())
            .unwrap_or_else(|| {
                ScanResult { scan, list: None }
                    .write(
                        o89_link::link_header(LinkMessageType::WifiScanResult, ReqId(1)),
                        &mut self.result,
                    )
                    .unwrap_or(0)
            });
    }
    /// Immutable result body through the same codec on every retry.
    #[must_use]
    pub fn result(&self) -> Option<ScanResult<'_>> {
        self.result
            .get(..self.result_len)
            .and_then(|bytes| LinkEnvelope::decode(bytes).ok())
            .and_then(|envelope| ScanResult::decode(envelope).ok())
    }
    /// Session teardown completes an accepted scan with failure if it did not finish.
    pub fn cancel_scan(&mut self) {
        if let Some(active) = self.active {
            self.finished(active.order.scan, None);
        }
    }

    /// Acknowledgement or L-015 give-up frees the one scan slot.
    pub fn result_done(&mut self) {
        self.active = None;
        self.result_len = 0;
    }
    /// New radio observation about the credential installation actually in RAM.
    /// L-204 applies to this installation: any version change, including a lower
    /// L-133 push, resets its first outcome. Old numeric versions have no history.
    pub fn observe(&mut self, report: RadioReport) {
        if report.version != self.report.version {
            self.outcome = false;
            self.association_since = None;
        }
        if matches!(report.radio, Radio::Off) {
            self.association_since = None;
        }
        if matches!(report.radio, Radio::Joining) && self.outcome {
            return;
        }
        if matches!(report.radio, Radio::Joined { .. } | Radio::Failed { .. }) {
            self.outcome = true;
        }
        self.report = report;
    }
    /// Observe the station seam: DHCP absence and association loss are core
    /// decisions. [`NO_IP`] bounds the first DHCP outcome; retries continue.
    pub fn station(
        &mut self,
        version: u32,
        connected: bool,
        ipv4: Option<[u8; 4]>,
        failure: Option<km43::WifiFailure>,
        now: u64,
    ) {
        if version != self.report.version {
            self.observe(RadioReport {
                version,
                radio: Radio::Joining,
            });
        }
        let radio = if connected {
            let since = *self.association_since.get_or_insert(now);
            if let Some(ipv4) = ipv4 {
                Radio::Joined { ipv4 }
            } else if now.saturating_sub(since) >= NO_IP.as_millis() {
                Radio::Failed {
                    reason: km43::WifiFailure::NoIp,
                }
            } else {
                Radio::Joining
            }
        } else if let Some(reason) = failure {
            self.association_since = None;
            Radio::Failed { reason }
        } else if self.association_since.take().is_some() {
            Radio::Failed {
                reason: km43::WifiFailure::Lost,
            }
        } else {
            Radio::Joining
        };
        self.observe(RadioReport { version, radio });
    }

    /// Latest state waits behind an immutable outstanding report (L-206).
    #[must_use]
    pub fn due(&self) -> Option<RadioReport> {
        (self.announced != Some(self.report)).then_some(self.report)
    }
    /// Remember only what was sent, so a newer report remains due.
    pub fn reported(&mut self, report: RadioReport) {
        self.announced = Some(report);
    }
    /// Each newly linked controller is owed the current report (L-204).
    pub fn linked(&mut self) {
        self.announced = None;
    }
    /// No result for an old controller boot survives loss of the cable.
    pub fn lost(&mut self) {
        self.result_done();
        self.announced = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ap(ssid: Option<&str>, rssi: i8) -> HeardAp<'_> {
        HeardAp {
            ssid,
            rssi,
            security: WifiSecurity::Wpa2Personal,
            channel: 6,
        }
    }
    fn result(rows: &ScanRows) -> (usize, u16) {
        let mut bytes = [0; SCAN_RESULT_BYTES];
        let len = rows
            .write(NonZeroU32::MIN, ReqId(1), &mut bytes)
            .expect("encoded");
        let result = ScanResult::decode(LinkEnvelope::decode(&bytes[..len]).expect("envelope"))
            .expect("result");
        let list = result.list.expect("complete");
        (list.len(), list.unlisted())
    }
    #[test]
    fn l_204_backwards_version_push_is_a_new_installation_with_no_outcome_yet() {
        let mut wifi = WifiDiagnostics::EMPTY;
        wifi.observe(RadioReport {
            version: 3,
            radio: Radio::Joined { ipv4: [1, 2, 3, 4] },
        });
        wifi.observe(RadioReport {
            version: 3,
            radio: Radio::Joining,
        });
        assert!(matches!(
            wifi.due().expect("outcome").radio,
            Radio::Joined { .. }
        ));
        let lower = RadioReport {
            version: 2,
            radio: Radio::Joining,
        };
        wifi.observe(lower);
        assert_eq!(wifi.due(), Some(lower));
    }

    #[test]
    fn f_092_l_201_cancelled_radio_session_finishes_an_accepted_scan_once() {
        let mut wifi = WifiDiagnostics::EMPTY;
        let order = ScanOrder {
            scan: NonZeroU32::MIN,
        };
        assert_eq!(wifi.scan(order, ReqId(1), true), WifiScan::Started);
        assert_eq!(wifi.take_scan(), Some(order.scan));
        wifi.cancel_scan();
        assert_eq!(wifi.result().expect("failed result").list, None);
        wifi.cancel_scan();
        assert_eq!(wifi.result().expect("same result").scan, order.scan);
        wifi.result_done();
        assert_eq!(wifi.result(), None);
    }

    #[test]
    fn f_092_l_204_dhcp_deadline_and_association_loss_produce_failures_without_rejoining() {
        let mut wifi = WifiDiagnostics::EMPTY;
        wifi.station(4, true, None, None, 0);
        assert_eq!(wifi.due().expect("trying").radio, Radio::Joining);
        wifi.station(4, true, None, None, 3999);
        assert_eq!(wifi.due().expect("trying").radio, Radio::Joining);
        wifi.station(4, true, None, None, 4000);
        assert_eq!(
            wifi.due().expect("failed").radio,
            Radio::Failed {
                reason: km43::WifiFailure::NoIp
            }
        );
        wifi.station(4, true, Some([1, 2, 3, 4]), None, 4001);
        assert_eq!(
            wifi.due().expect("joined").radio,
            Radio::Joined { ipv4: [1, 2, 3, 4] }
        );
        wifi.station(4, false, None, None, 4002);
        assert_eq!(
            wifi.due().expect("lost").radio,
            Radio::Failed {
                reason: km43::WifiFailure::Lost
            }
        );
        wifi.station(4, false, None, None, 4003);
        assert_eq!(
            wifi.due().expect("still lost").radio,
            Radio::Failed {
                reason: km43::WifiFailure::Lost
            }
        );
        for reason in [
            km43::WifiFailure::AuthFailed,
            km43::WifiFailure::NotFound,
            km43::WifiFailure::NoIp,
            km43::WifiFailure::Lost,
            km43::WifiFailure::Other,
        ] {
            wifi.station(4, false, None, Some(reason), 4004);
            assert_eq!(wifi.due().expect("failure").radio, Radio::Failed { reason });
        }
    }

    #[test]
    fn l_200_no_country_refuses_even_passive_intake_and_duplicate_order_starts_once() {
        let mut wifi = WifiDiagnostics::EMPTY;
        let order = ScanOrder {
            scan: NonZeroU32::MIN,
        };
        assert_eq!(wifi.scan(order, ReqId(1), false), WifiScan::RefusedRadioOff);
        assert_eq!(wifi.take_scan(), None);
        assert_eq!(wifi.scan(order, ReqId(1), true), WifiScan::Started);
        assert_eq!(wifi.scan(order, ReqId(1), true), WifiScan::Started);
        assert_eq!(wifi.scan(order, ReqId(2), true), WifiScan::RefusedBusy);
        assert_eq!(wifi.take_scan(), Some(order.scan));
        assert_eq!(wifi.take_scan(), None);
    }
    #[test]
    fn l_201_one_result_per_started_scan_and_failed_is_distinct_from_empty() {
        let mut wifi = WifiDiagnostics::EMPTY;
        let order = ScanOrder {
            scan: NonZeroU32::MIN,
        };
        assert_eq!(wifi.scan(order, ReqId(1), true), WifiScan::Started);
        wifi.finished(order.scan, None);
        assert_eq!(wifi.result().expect("failed").list, None);
        let rows = ScanRows::collect::<HeardAp<'_>>(&[], |ap| *ap).expect("empty scan");
        wifi.finished(order.scan, Some(&rows));
        assert_eq!(wifi.result().expect("still failed").list, None);
        assert_eq!(wifi.scan(order, ReqId(2), true), WifiScan::RefusedBusy);
        wifi.result_done();
        assert_eq!(wifi.scan(order, ReqId(2), true), WifiScan::Started);
        wifi.finished(order.scan, Some(&rows));
        assert!(
            wifi.result()
                .expect("complete")
                .list
                .expect("list")
                .is_empty()
        );
    }
    #[test]
    fn l_202_one_strongest_row_per_ssid_hidden_and_non_utf8_count_as_unlisted() {
        let aps = [
            ap(Some("mesh"), -10),
            ap(Some("mesh"), -20),
            ap(Some(""), -30),
            ap(None, -40),
            ap(Some("shed"), -50),
        ];
        let rows = ScanRows::collect(&aps, |ap| *ap).expect("sorted");
        assert_eq!(result(&rows), (2, 2));
        assert_eq!(rows.rows[0].rssi, -10);
        assert_eq!(rows.rows[1].text(), "shed");
        assert!(ScanRows::collect(&[ap(Some("a"), -50), ap(Some("b"), -10)], |ap| *ap).is_err());
    }
    #[test]
    fn l_202_full_table_counts_omitted_aps_but_not_merged_listed_duplicates() {
        let names = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "q", "a",
        ];
        let aps = names.map(|name| ap(Some(name), -20));
        let rows = ScanRows::collect(&aps, |ap| *ap).expect("bounded");
        assert_eq!(result(&rows), (km43::MAX_SCAN_APS, 2));
        assert_eq!(rows.rows[15].text(), "p");
    }
    #[test]
    fn l_204_l_205_first_outcome_prevents_joining_again_and_version_is_ram_version() {
        let mut wifi = WifiDiagnostics::EMPTY;
        assert_eq!(
            wifi.due(),
            Some(RadioReport {
                version: 0,
                radio: Radio::Off
            })
        );
        let failure = RadioReport {
            version: 4,
            radio: Radio::Failed {
                reason: km43::WifiFailure::AuthFailed,
            },
        };
        wifi.observe(failure);
        wifi.observe(RadioReport {
            version: 4,
            radio: Radio::Joining,
        });
        assert_eq!(wifi.due(), Some(failure));
        wifi.observe(RadioReport {
            version: 5,
            radio: Radio::Joining,
        });
        assert_eq!(wifi.due().expect("new version").version, 5);
        assert_eq!(wifi.due().expect("joining").radio, Radio::Joining);
    }
    #[test]
    fn l_206_only_newest_waits_while_the_outstanding_body_is_immutable() {
        let mut wifi = WifiDiagnostics::EMPTY;
        let sent = wifi.due().expect("initial");
        let latest = RadioReport {
            version: 2,
            radio: Radio::Joined { ipv4: [1, 2, 3, 4] },
        };
        wifi.observe(RadioReport {
            version: 1,
            radio: Radio::Joining,
        });
        wifi.observe(latest);
        wifi.reported(sent);
        assert_eq!(wifi.due(), Some(latest));
        wifi.reported(latest);
        assert_eq!(wifi.due(), None);
        wifi.linked();
        assert_eq!(wifi.due(), Some(latest));
    }
}
