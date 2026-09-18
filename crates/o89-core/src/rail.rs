//! The module rail sequence: how the comms processor's 3.3 V rail and its
//! `EN` line move, and the ladder's rungs that move them.
//!
//! Two facts about controller board A revision A decide the shape. `EN` has
//! only an RC delay, so a short rail cut can bring the rail back with the
//! module never reset; the controller holds `EN` low itself from before the
//! rail drops until after it has settled (origin89hq/hardware#14, F-004).
//! And switching the rail on after minutes off corrupts the controller
//! within milliseconds, 22 times of 22, while short cycles pass hundreds of
//! times (origin89hq/hardware#5); so on revision A no cut is longer than
//! five seconds, and the ladder's third rung, fifteen minutes off (L-112),
//! is not executed: the rail stays on and comms unrecoverable is raised
//! instead (F-005). The rungs' counts and their timers' other ends, the
//! heartbeats that trigger a recovery, live in the link's state machine and
//! arrive with it; this owns what happens once a recovery is asked for.
//!
//! Nothing here touches a pin. The adapter applies [`Lines`] and reports
//! [`RailEvent`]s.
//!
//! cites: F-004, F-005

use crate::{Millis, Revision, ThirdRung, Tick};

/// What the rail line is asked to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RailLine {
    /// The module is powered.
    On,
    /// The module is not.
    Off,
}

/// What the `EN` line is asked to be. Never driven high: the board's own
/// pull-up raises it when it is released, and a pin driven high into an
/// unpowered module back-powers it (F-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EnLine {
    /// Driven low: the module is held in reset.
    HeldLow,
    /// High-impedance: the board's pull-up owns it.
    Released,
}

/// The two lines, as the adapter should drive them right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Lines {
    /// The rail.
    pub rail: RailLine,
    /// `EN`.
    pub en: EnLine,
}

/// What a step of the sequence wants written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RailEvent {
    /// The rail was cut and restored: comms power cycled (`0x0802`), with
    /// the count of cycles in the last hour, this one included.
    PowerCycled {
        /// How many cycles in the last hour.
        count: u8,
    },
    /// The rail is up and settled, and `EN` has been released: the module
    /// is booting and the link may be configured (F-006).
    Settled,
    /// The ladder asked for its third rung and this board does not execute
    /// it: the rail stays on, comms unrecoverable (`0x0803`) is raised.
    Unrecoverable,
}

/// What a recovery request did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a recovery is a rung of the ladder, and one nobody logs is a boot loop nobody can name"]
pub enum Recovery {
    /// A cut has started, the count of cycles in the last hour included.
    Cycling {
        /// How many cycles in the last hour, this one included.
        count: u8,
        /// How long the rail will be off.
        off_for: Millis,
    },
    /// The third rung on a board that does not execute it: nothing moved,
    /// and comms unrecoverable is to be raised.
    LeftOnAndRaised,
    /// A cut is already in progress; nothing changed.
    Busy,
}

/// The cut a recovery cycle makes (L-111).
pub const CUT: Millis = Millis::from_millis(5_000);

/// How long the rail settles before `EN` is released. The RC on `EN` is
/// 10 ms; this leaves the rail's own rise well behind. The bench measures
/// the switch-on (board A's open item 9) and this number moves with it.
pub const SETTLE: Millis = Millis::from_millis(100);

/// The window the ladder counts cycles in (L-112).
const HOUR: Millis = Millis::from_millis(60 * 60 * 1_000);

/// Cycles in an hour after which the third rung applies (L-112).
const CYCLES_BEFORE_THE_THIRD_RUNG: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Rail off, `EN` held low, until the moment the rail comes back.
    Cut { until: Tick },
    /// Rail on, `EN` held low, until the rail has settled.
    Rising { until: Tick },
    /// Rail on, `EN` released.
    Up,
    /// Rail off and nothing scheduled: the state before the first power-on.
    Off,
}

/// The sequence, for one board revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailSequencer {
    revision: Revision,
    phase: Phase,
    /// When the last cycles started, oldest overwritten.
    cycles: [Option<Tick>; CYCLES_BEFORE_THE_THIRD_RUNG],
}

impl RailSequencer {
    /// Before the first power-on: the rail as the board leaves it through
    /// reset, off on revision A and on on revision B.
    #[must_use]
    pub const fn new(revision: Revision) -> Self {
        let phase = match revision {
            Revision::A => Phase::Off,
            Revision::B => Phase::Up,
        };
        Self {
            revision,
            phase,
            cycles: [None; CYCLES_BEFORE_THE_THIRD_RUNG],
        }
    }

    /// Power the module at boot: the rail on with `EN` held low, released
    /// once the rail has settled. On a board whose rail is already on, the
    /// module is booting by itself and this takes ownership without a cut.
    pub fn power_on(&mut self, now: Tick) -> Lines {
        if let Phase::Off = self.phase {
            self.phase = Phase::Rising {
                until: now.after(SETTLE).unwrap_or(now),
            };
        }
        self.lines()
    }

    /// The ladder asks for a recovery: a cut, or the third rung.
    pub fn recover(&mut self, now: Tick) -> Recovery {
        if let Phase::Cut { .. } | Phase::Rising { .. } = self.phase {
            return Recovery::Busy;
        }
        let recent = self.cycles_within(HOUR, now);
        if recent >= CYCLES_BEFORE_THE_THIRD_RUNG {
            return match self.revision.third_rung() {
                ThirdRung::LeaveOnAndRaise => Recovery::LeftOnAndRaised,
                ThirdRung::Cut(off_for) => self.cut(now, off_for),
            };
        }
        self.cut(now, CUT)
    }

    /// Advance by time: the rail comes back at the end of a cut, and `EN`
    /// is released once the rail has settled.
    pub fn tick(&mut self, now: Tick) -> Option<RailEvent> {
        match self.phase {
            Phase::Cut { until } if now >= until => {
                self.phase = Phase::Rising {
                    until: now.after(SETTLE).unwrap_or(now),
                };
                let count = self.cycles_within(HOUR, now);
                Some(RailEvent::PowerCycled {
                    count: u8::try_from(count).unwrap_or(u8::MAX),
                })
            }
            Phase::Rising { until } if now >= until => {
                self.phase = Phase::Up;
                Some(RailEvent::Settled)
            }
            Phase::Cut { .. } | Phase::Rising { .. } | Phase::Up | Phase::Off => None,
        }
    }

    /// How the two lines should be driven right now.
    #[must_use]
    pub const fn lines(&self) -> Lines {
        match self.phase {
            Phase::Cut { .. } => Lines {
                rail: RailLine::Off,
                en: EnLine::HeldLow,
            },
            Phase::Rising { .. } => Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow,
            },
            Phase::Up => Lines {
                rail: RailLine::On,
                en: EnLine::Released,
            },
            Phase::Off => Lines {
                rail: RailLine::Off,
                en: EnLine::Released,
            },
        }
    }

    /// Whether the rail is up and settled, which is when the link may be
    /// configured (F-006).
    #[must_use]
    pub const fn settled(&self) -> bool {
        matches!(self.phase, Phase::Up)
    }

    fn cut(&mut self, now: Tick, off_for: Millis) -> Recovery {
        // The cap is the board's, whatever the rung asked for.
        let off_for = if off_for > self.revision.longest_rail_off() {
            self.revision.longest_rail_off()
        } else {
            off_for
        };
        // The oldest slot is overwritten, an empty one first of all.
        if let Some(slot) = self
            .cycles
            .iter_mut()
            .min_by_key(|slot| slot.map_or(0, Tick::as_millis))
        {
            *slot = Some(now);
        }
        self.phase = Phase::Cut {
            until: now.after(off_for).unwrap_or(now),
        };
        let count = self.cycles_within(HOUR, now);
        Recovery::Cycling {
            count: u8::try_from(count).unwrap_or(u8::MAX),
            off_for,
        }
    }

    fn cycles_within(&self, window: Millis, now: Tick) -> usize {
        self.cycles
            .iter()
            .flatten()
            .filter(|at| now.since(**at).is_some_and(|ago| ago <= window))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    /// What the sequencer reports between `from` and `until`, ticked one
    /// millisecond at a time: up to four events, in order, `None` after.
    fn run(seq: &mut RailSequencer, from: u64, until: u64) -> [Option<(u64, RailEvent)>; 4] {
        let mut events = [None; 4];
        let mut count = 0;
        for ms in from..=until {
            if let Some(event) = seq.tick(at(ms)) {
                if let Some(slot) = events.get_mut(count) {
                    *slot = Some((ms, event));
                }
                count = count.saturating_add(1);
            }
        }
        assert!(count <= events.len(), "more events than the fixture holds");
        events
    }

    const NONE: [Option<(u64, RailEvent)>; 4] = [None; 4];

    #[test]
    fn f_004_en_is_held_low_from_before_the_rail_drops_until_after_it_settles() {
        let mut seq = RailSequencer::new(Revision::A);
        seq.power_on(at(0));
        run(&mut seq, 0, 200);
        assert!(seq.settled());
        // The cut: EN low in the same step the rail goes off.
        assert_eq!(
            seq.recover(at(1_000)),
            Recovery::Cycling {
                count: 1,
                off_for: CUT
            }
        );
        assert_eq!(
            seq.lines(),
            Lines {
                rail: RailLine::Off,
                en: EnLine::HeldLow
            }
        );
        // Through the cut and the rise, EN never leaves low while the rail
        // is off or rising.
        for ms in 1_000..=6_100 {
            seq.tick(at(ms));
            let lines = seq.lines();
            if lines.rail == RailLine::Off || !seq.settled() {
                assert_eq!(lines.en, EnLine::HeldLow, "at {ms}");
            }
        }
        // Released only once the rail has settled.
        assert!(seq.settled());
        assert_eq!(
            seq.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::Released
            }
        );
    }

    #[test]
    fn f_004_at_boot_the_rail_comes_up_with_en_low_and_is_released_after_the_settle() {
        let mut seq = RailSequencer::new(Revision::A);
        assert_eq!(seq.lines().rail, RailLine::Off);
        assert!(!seq.settled());
        assert_eq!(
            seq.power_on(at(0)),
            Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow
            }
        );
        assert_eq!(run(&mut seq, 0, 99), NONE);
        assert_eq!(
            run(&mut seq, 100, 100),
            [Some((100, RailEvent::Settled)), None, None, None]
        );
        assert!(seq.settled());
        // Powering on again does nothing to a rail that is up.
        assert_eq!(seq.power_on(at(200)).en, EnLine::Released);
        // Revision B's rail is on through reset: ownership, no cut.
        let mut b = RailSequencer::new(Revision::B);
        assert!(b.settled());
        assert_eq!(b.power_on(at(0)).en, EnLine::Released);
    }

    #[test]
    fn f_005_a_cut_on_revision_a_is_five_seconds_and_the_rail_comes_back() {
        let mut seq = RailSequencer::new(Revision::A);
        seq.power_on(at(0));
        run(&mut seq, 0, 200);
        assert!(matches!(seq.recover(at(10_000)), Recovery::Cycling { .. }));
        let events = run(&mut seq, 10_000, 16_000);
        assert_eq!(
            events,
            [
                Some((15_000, RailEvent::PowerCycled { count: 1 })),
                Some((15_100, RailEvent::Settled)),
                None,
                None
            ]
        );
        // Off for exactly the cut, never longer.
        assert_eq!(CUT, Revision::A.longest_rail_off());
    }

    #[test]
    fn f_005_the_third_cycle_in_an_hour_leaves_the_rail_on_and_raises_on_revision_a() {
        let mut seq = RailSequencer::new(Revision::A);
        seq.power_on(at(0));
        run(&mut seq, 0, 200);
        let mut now = 60_000;
        for expected in 1..=2 {
            assert_eq!(
                seq.recover(at(now)),
                Recovery::Cycling {
                    count: expected,
                    off_for: CUT
                }
            );
            run(&mut seq, now, now + 6_000);
            now += 60_000;
        }
        // The third inside the hour.
        assert_eq!(
            seq.recover(at(now)),
            Recovery::Cycling {
                count: 3,
                off_for: CUT
            }
        );
        run(&mut seq, now, now + 6_000);
        now += 60_000;
        // A fourth request inside the hour is the third rung: nothing moves.
        let before = seq.lines();
        assert_eq!(seq.recover(at(now)), Recovery::LeftOnAndRaised);
        assert_eq!(seq.lines(), before);
        assert_eq!(seq.lines().rail, RailLine::On);
        assert_eq!(run(&mut seq, now, now + 1_000), NONE);
        // An hour after the first cycle it has aged out and cycling resumes.
        let later = 60_000 + 3_600_001;
        assert!(matches!(
            seq.recover(at(later)),
            Recovery::Cycling { count: 3, .. }
        ));
    }

    #[test]
    fn f_005_revision_b_executes_the_third_rung_inside_its_own_cap() {
        let mut seq = RailSequencer::new(Revision::B);
        let mut now = 60_000;
        for _ in 0..3 {
            assert!(matches!(seq.recover(at(now)), Recovery::Cycling { .. }));
            run(&mut seq, now, now + 6_000);
            now += 60_000;
        }
        assert_eq!(
            seq.recover(at(now)),
            Recovery::Cycling {
                count: 3,
                off_for: Millis::from_millis(900_000)
            }
        );
        assert_eq!(seq.lines().rail, RailLine::Off);
    }

    #[test]
    fn a_recovery_during_a_cut_or_a_rise_changes_nothing() {
        let mut seq = RailSequencer::new(Revision::A);
        seq.power_on(at(0));
        assert_eq!(seq.recover(at(50)), Recovery::Busy);
        run(&mut seq, 0, 200);
        assert!(matches!(seq.recover(at(1_000)), Recovery::Cycling { .. }));
        assert_eq!(seq.recover(at(2_000)), Recovery::Busy);
        assert_eq!(seq.lines().rail, RailLine::Off);
    }
}
