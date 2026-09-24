//! Successful recorder seam for signed clock requests in the host bench.
use super::*;

/// Recorder diagnostics only; the M5 concern records are not implemented yet.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ClockNote {
    Stepped,
    FloorOverridden,
}

#[derive(Clone, Copy)]
pub(super) enum FloorOverride {
    Armed,
    Unarmed,
}

impl Bench {
    pub(super) fn client_time(&mut self, asked: o89_core::TimeAsked) -> o89_core::TimeAnswer {
        // The recorder seam: a successful calendar write and audit append.
        // Storage faults and backup-domain retention have their own tests.
        let mut current = self.calendar.map(|(at, tick)| {
            o89_core::UnixMillis::new(
                at.as_millis()
                    .checked_add(self.now.since(tick).unwrap().as_millis())
                    .unwrap(),
            )
            .unwrap()
        });
        if asked.authorised && self.clock.client_rate_limited(self.now) {
            o89_core::TimeAnswer::Busy
        } else {
            let outcome = if asked.authorised {
                match o89_core::WallClock::client(
                    asked.at,
                    current,
                    o89_core::UnixMillis::new(1_700_000_000_000).unwrap(),
                    matches!(self.floor_override, FloorOverride::Armed),
                ) {
                    o89_core::ClientSet::Set {
                        change,
                        stepped,
                        overridden,
                    } => {
                        self.calendar = Some((change.new_value(), self.now));
                        assert!(self.clock.client_applied(change, self.now));
                        if overridden {
                            self.floor_override = FloorOverride::Unarmed;
                            self.clock_notes.push(ClockNote::FloorOverridden);
                        }
                        if stepped {
                            self.clock_notes.push(ClockNote::Stepped);
                        }
                        current = Some(change.new_value());
                        self.clock_records.push(change.record());
                        assert!(self.clock.audit_written(self.now).is_some());
                        km43::Time::Accepted
                    }
                    o89_core::ClientSet::Rejected => km43::Time::Rejected,
                    o89_core::ClientSet::NeedsButton => km43::Time::NeedsButton,
                }
            } else {
                km43::Time::Unauthorised
            };
            o89_core::TimeAnswer::Ack(
                km43::TimeAck::new(outcome, current.map(o89_core::UnixMillis::as_millis)).unwrap(),
            )
        }
    }
}

#[test]
fn p_115_bench_accepts_and_records_a_step_over_one_hour() {
    let mut bench = Bench::new(Capabilities::default());
    let initial = 1_700_000_000_000;
    bench.calendar = Some((o89_core::UnixMillis::new(initial).unwrap(), bench.now));
    let target = initial + 3_600_001;
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 1,
            at: target,
            authorised: true
        }),
        o89_core::TimeAnswer::Ack(km43::TimeAck::new(km43::Time::Accepted, Some(target)).unwrap())
    );
    assert_eq!(
        bench.clock_records,
        vec![km43::ControllerRecord::TimeSet {
            old: Some(initial),
            new: target,
            source: km43::TimeSource::Client,
        }]
    );
    assert_eq!(bench.calendar.unwrap().0.as_millis(), target);
    assert!(!bench.clock.audit_pending());
    assert_eq!(bench.clock_notes, vec![ClockNote::Stepped]);
}

#[test]
fn p_113_bench_rejected_time_reports_the_current_reading() {
    let mut bench = Bench::new(Capabilities::default());
    let initial = 1_700_000_000_000;
    let stored = Some((o89_core::UnixMillis::new(initial).unwrap(), bench.now));
    bench.calendar = stored;
    bench.now = Tick::from_millis(61_000);
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 1,
            at: u64::MAX,
            authorised: true
        }),
        o89_core::TimeAnswer::Ack(
            km43::TimeAck::new(km43::Time::Rejected, Some(initial + 60_000)).unwrap()
        )
    );
    assert_eq!(bench.calendar, stored);
    assert!(bench.clock_records.is_empty());
}

#[test]
fn p_116_p_117_bench_spends_the_floor_override_only_on_acceptance() {
    let mut bench = Bench::new(Capabilities::default());
    bench.floor_override = FloorOverride::Armed;
    let target = 1_699_999_999_999;
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 1,
            at: target,
            authorised: true
        }),
        o89_core::TimeAnswer::Ack(km43::TimeAck::new(km43::Time::Accepted, Some(target)).unwrap())
    );
    assert!(matches!(bench.floor_override, FloorOverride::Unarmed));
    assert_eq!(bench.clock_notes, vec![ClockNote::FloorOverridden]);
    assert_eq!(
        bench.clock_records,
        vec![km43::ControllerRecord::TimeSet {
            old: None,
            new: target,
            source: km43::TimeSource::Client,
        }]
    );
    bench.floor_override = FloorOverride::Armed;
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 2,
            at: target,
            authorised: true
        }),
        o89_core::TimeAnswer::Busy
    );
    assert!(matches!(bench.floor_override, FloorOverride::Armed));
    assert_eq!(bench.clock_records.len(), 1);
    assert_eq!(bench.clock_notes.len(), 1);
}

#[test]
fn p_114_p_105_bench_refusals_report_elapsed_time_without_writing() {
    let mut bench = Bench::new(Capabilities::default());
    let initial = 1_700_000_000_000;
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 1,
            at: initial,
            authorised: true
        }),
        o89_core::TimeAnswer::Ack(km43::TimeAck::new(km43::Time::Accepted, Some(initial)).unwrap())
    );
    bench.now = Tick::from_millis(61_000);
    // Permission refusal precedes rate limiting in the recorder.
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 2,
            at: initial,
            authorised: false
        }),
        o89_core::TimeAnswer::Ack(
            km43::TimeAck::new(km43::Time::Unauthorised, Some(initial + 60_000)).unwrap()
        )
    );
    bench.now = Tick::from_millis(901_000);
    assert_eq!(
        bench.client_time(o89_core::TimeAsked {
            ticket: 3,
            at: initial - 1,
            authorised: true
        }),
        o89_core::TimeAnswer::Ack(
            km43::TimeAck::new(km43::Time::NeedsButton, Some(initial + 900_000)).unwrap()
        )
    );
    assert_eq!(bench.clock_records.len(), 1);
    assert!(bench.clock_notes.is_empty());
    assert_eq!(bench.calendar.unwrap().0.as_millis(), initial);
}
