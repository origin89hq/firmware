//! Successful recorder seam for signed clock requests in the host bench.
use super::*;

impl Bench {
    pub(super) fn client_time(&mut self, asked: o89_core::TimeAsked) -> o89_core::TimeAnswer {
        // The recorder seam: a successful calendar write and audit append.
        // Storage faults and backup-domain retention have their own tests.
        let current = self.calendar.map(|(at, tick)| {
            o89_core::UnixMillis::new(
                at.as_millis()
                    .checked_add(self.now.since(tick).unwrap().as_millis())
                    .unwrap(),
            )
            .unwrap()
        });
        if self.clock.client_rate_limited(self.now) {
            o89_core::TimeAnswer::Busy
        } else {
            let outcome = if asked.authorised {
                match o89_core::WallClock::client(
                    asked.at,
                    current,
                    o89_core::UnixMillis::new(1_700_000_000_000).unwrap(),
                    false,
                ) {
                    o89_core::ClientSet::Set {
                        change,
                        stepped,
                        overridden,
                    } => {
                        assert!(
                            !stepped && !overridden,
                            "fixture handles ordinary client sets"
                        );
                        self.calendar = Some((change.new_value(), self.now));
                        assert!(self.clock.client_applied(change, self.now));
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
                km43::TimeAck::new(outcome, self.calendar.map(|(at, _)| at.as_millis())).unwrap(),
            )
        }
    }
}
