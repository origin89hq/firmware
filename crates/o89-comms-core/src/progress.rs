//! Comms watchdog progress (F-032), with time supplied by the caller.
//! Wi-Fi owns only its three reports; resetting them cannot report for BLE.

/// A report expires at this age, including the boundary.
pub const PROGRESS_TIMEOUT_MS: u64 = 6_000;

/// One independently owned operation's last report, in milliseconds since boot.
#[derive(Clone, Copy)]
#[must_use]
pub struct Progress {
    last_ms: u64,
}

impl Progress {
    /// Start the operation's grace period at `now_ms`.
    pub const fn at(now_ms: u64) -> Self {
        Self { last_ms: now_ms }
    }

    /// Only the operation's owner reports completed progress.
    pub fn progress(&mut self, now_ms: u64) {
        self.last_ms = now_ms;
    }

    /// A reversed clock is not evidence of progress.
    #[must_use]
    pub fn healthy(&self, now_ms: u64) -> bool {
        now_ms
            .checked_sub(self.last_ms)
            .is_some_and(|age| age < PROGRESS_TIMEOUT_MS)
    }
}

/// Operations owned and restarted by the Wi-Fi loop; BLE is a separate owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// Embassy network runner.
    Network,
    /// Station association or the idle access-point holder.
    Station,
    /// Time query loop or its idle access-point holder.
    Ntp,
}

/// Wi-Fi's reports, excluding the independently running BLE task.
#[must_use]
pub struct WifiProgress {
    network: Progress,
    station: Progress,
    ntp: Progress,
}

impl WifiProgress {
    /// Start the Wi-Fi operations' grace period.
    pub const fn at(now_ms: u64) -> Self {
        Self {
            network: Progress::at(now_ms),
            station: Progress::at(now_ms),
            ntp: Progress::at(now_ms),
        }
    }

    /// The idle loop or a new session starts only its own operations' periods.
    pub fn reset(&mut self, now_ms: u64) {
        *self = Self::at(now_ms);
    }

    /// Record one Wi-Fi operation, without refreshing its peers.
    pub fn progress(&mut self, task: Task, now_ms: u64) {
        match task {
            Task::Network => &mut self.network,
            Task::Station => &mut self.station,
            Task::Ntp => &mut self.ntp,
        }
        .progress(now_ms);
    }

    /// Every Wi-Fi operation must have reported within the deadline.
    #[must_use]
    pub fn healthy(&self, now_ms: u64) -> bool {
        let Self {
            network,
            station,
            ntp,
        } = self;
        network.healthy(now_ms) && station.healthy(now_ms) && ntp.healthy(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_032_late_task_start_gets_its_own_bounded_grace_period() {
        let started_ms = 10_000;
        let mut wifi = WifiProgress::at(0);
        let mut ble = Progress::at(0);
        assert!(!wifi.healthy(started_ms) && !ble.healthy(started_ms));
        wifi.reset(started_ms);
        ble.progress(started_ms);
        assert!(wifi.healthy(started_ms) && ble.healthy(started_ms));
        assert!(wifi.healthy(15_999) && ble.healthy(15_999));
        assert!(!wifi.healthy(16_000));
        assert!(!ble.healthy(16_000));
        assert!(!wifi.healthy(16_001));
        assert!(!ble.healthy(16_001));
    }

    #[test]
    fn f_032_wifi_restarts_cannot_hide_a_stalled_ble_task() {
        let mut wifi = WifiProgress::at(0);
        let ble = Progress::at(0);
        for now in (1_000..=6_000).step_by(1_000) {
            wifi.reset(now);
        }
        assert!(wifi.healthy(6_000));
        assert!(!(wifi.healthy(6_000) && ble.healthy(6_000)));
    }

    #[test]
    fn f_032_each_wifi_task_alone_can_withhold_the_watchdog_feed() {
        let tasks = [Task::Network, Task::Station, Task::Ntp];
        for stalled in tasks {
            let mut wifi = WifiProgress::at(100);
            let mut ble = Progress::at(100);
            for task in tasks {
                if task != stalled {
                    wifi.progress(task, 6_100);
                }
            }
            ble.progress(6_100);
            assert!(ble.healthy(6_100));
            assert!(!wifi.healthy(6_100));
            wifi.progress(stalled, 6_100);
            assert!(wifi.healthy(6_100) && ble.healthy(6_100));
        }
    }

    #[test]
    fn f_032_progress_expires_at_exactly_six_thousand_milliseconds() {
        let mut wifi = WifiProgress::at(100);
        let mut ble = Progress::at(100);
        assert!(wifi.healthy(6_099) && ble.healthy(6_099));
        assert!(!wifi.healthy(6_100));
        assert!(!ble.healthy(6_100));
        assert!(!wifi.healthy(6_101));
        assert!(!ble.healthy(6_101));
        wifi.reset(6_100);
        assert!(wifi.healthy(6_100));
        assert!(!ble.healthy(6_100));
        ble.progress(6_100);
        assert!(wifi.healthy(6_100) && ble.healthy(6_100));
    }

    #[test]
    fn f_032_reversed_time_does_not_prove_progress() {
        let wifi = WifiProgress::at(100);
        let ble = Progress::at(100);
        assert!(!wifi.healthy(99));
        assert!(!ble.healthy(99));
        assert!(wifi.healthy(100) && ble.healthy(100));
        let end = Progress::at(u64::MAX);
        assert!(end.healthy(u64::MAX));
        assert!(!end.healthy(0));
    }
}
