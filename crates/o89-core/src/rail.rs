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
//! The cuts of the last hour outlive a controller reset: the adapter keeps
//! [`RecentCuts`] on the FRAM before the rail goes off, and a boot carries
//! them as made at its own start, the P-121 rule for every window measured
//! on the tick. On revision A the reset that began the boot is one of them
//! (F-017, F-018).
//!
//! cites: F-004, F-005

use crate::body::{Body, Held, Malformed};
use crate::{Millis, RailThroughReset, Revision, ThirdRung, Tick};

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

/// What the `BOOT` strap, the module's IO9, is asked to be. Never driven
/// high, for the same reason as `EN` (F-003): low across a reset selects
/// the ROM's download mode, and the module's own pull-up owns it released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BootLine {
    /// Driven low: the ROM reads it at the reset and enters download mode.
    HeldLow,
    /// High-impedance: a normal boot.
    Released,
}

/// The three lines, as the adapter should drive them right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Lines {
    /// The rail.
    pub rail: RailLine,
    /// `EN`.
    pub en: EnLine,
    /// `BOOT`, IO9.
    pub boot: BootLine,
}

/// Which boot a module reset is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ModuleBoot {
    /// The straps released: the module boots its firmware.
    Normal,
    /// IO9 held low across the reset: the ROM's serial download mode, the
    /// strapping route into the window (F-038). On revision A it needs
    /// IO8 held high by a wire (hardware#6); revision B wires that pull-up.
    Download,
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
    /// The cut was due and not made: the count it would have added could
    /// not be kept on the FRAM first (F-017), so nothing moved, and the
    /// ladder asks again. The adapter reports this, never the sequencer,
    /// which plans a cut on a copy of itself and keeps the copy only once
    /// its count has landed.
    Deferred,
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

/// What a request to reset the module, rail on, did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a reset nobody waits for is a window nobody uses"]
pub enum ModuleReset {
    /// `EN` is held low; the rail stays on, and the module boots when it
    /// is released, which is the `Settled` the tick reports.
    Holding,
    /// The rail is off or in a cycle: nothing to reset.
    NotPowered,
}

/// How long `EN` is held for a reset with the rail on: the RC on the line
/// is 10 ms, and the module wants its reset held for more than that.
pub const EN_HELD: Millis = Millis::from_millis(50);

/// How long the strap stays low after `EN` is released: the reset's RC is
/// 10 ms and the ROM reads its straps as it comes out of reset, so a
/// hundred is ten of those.
pub const STRAP_HELD: Millis = Millis::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Rail off, `EN` held low, until the moment the rail comes back.
    Cut { until: Tick },
    /// Rail on, `EN` held low, until the rail has settled; the strap held
    /// with it when the boot is for download.
    Rising { until: Tick, strap: bool },
    /// Rail on, `EN` released, the strap still low until the ROM has read
    /// it.
    Strapping { until: Tick },
    /// Rail on, `EN` released.
    Up,
    /// Rail off and nothing scheduled: the state before the first power-on.
    Off,
}

/// The bytes [`RecentCuts`] takes in its record: a count, then an instant
/// for each cut the ladder remembers.
pub const RECENT_CUTS_BYTES: usize = 1 + 8 * CYCLES_BEFORE_THE_THIRD_RUNG;

/// The ladder's cuts of the last hour, oldest first, as the FRAM keeps them
/// across a controller reset (F-017).
///
/// The instants are on the tick of the boot that wrote them, which a reset
/// restarts; so a boot carries every one of them as made at its own start
/// ([`RecentCuts::rebased`]). That counts a cut as recent for up to an hour
/// longer than it was, and never for less.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RecentCuts([Option<Tick>; CYCLES_BEFORE_THE_THIRD_RUNG]);

impl RecentCuts {
    /// No cut in the last hour.
    pub const NONE: Self = Self([None; CYCLES_BEFORE_THE_THIRD_RUNG]);

    /// As many cuts as the third rung needs, all at the boot's start: what a
    /// record that does not read counts as (F-017).
    pub const FULL: Self = Self([Some(Tick::ZERO); CYCLES_BEFORE_THE_THIRD_RUNG]);

    /// The cuts a boot starts from, given the record as it read: its cuts,
    /// none for a record never written, and the full ladder for one that is
    /// there and does not read, because a count the part lost is never
    /// taken as zero.
    #[must_use]
    pub const fn carried(held: &Held<Self>) -> Self {
        match held {
            Held::Present(cuts) => *cuts,
            Held::Absent => Self::NONE,
            Held::Corrupt | Held::Malformed(_) => Self::FULL,
        }
    }

    /// Every cut moved to this boot's start (P-121): the previous boot's
    /// tick means nothing on this one, and the start is the latest the cut
    /// can have been.
    #[must_use]
    pub fn rebased(self) -> Self {
        Self(self.0.map(|cut| cut.map(|_| Tick::ZERO)))
    }

    /// How many cuts.
    #[must_use]
    pub fn count(&self) -> usize {
        self.0.iter().flatten().count()
    }

    /// The cuts of `cycles` at most an hour before `now`, oldest first.
    fn within_the_hour(cycles: &[Option<Tick>; CYCLES_BEFORE_THE_THIRD_RUNG], now: Tick) -> Self {
        let mut cuts = Self::NONE;
        let mut recent = cycles
            .iter()
            .flatten()
            .filter(|at| now.since(**at).is_some_and(|ago| ago <= HOUR));
        for slot in &mut cuts.0 {
            *slot = recent.next().copied();
        }
        cuts.0
            .sort_unstable_by_key(|cut| cut.map_or(u64::MAX, Tick::as_millis));
        cuts
    }
}

impl Body<RECENT_CUTS_BYTES> for RecentCuts {
    fn encode(&self) -> [u8; RECENT_CUTS_BYTES] {
        let mut bytes = [0u8; RECENT_CUTS_BYTES];
        let cuts = self.0.iter().flatten();
        let count = u8::try_from(self.count()).unwrap_or(u8::MAX);
        if let Some(first) = bytes.first_mut() {
            *first = count;
        }
        let (instants, _) = bytes.get_mut(1..).unwrap_or(&mut []).as_chunks_mut::<8>();
        for (cut, instant) in cuts.zip(instants) {
            *instant = cut.as_millis().to_le_bytes();
        }
        bytes
    }

    /// A count past what the ladder remembers does not decode.
    fn decode(bytes: &[u8; RECENT_CUTS_BYTES]) -> Result<Self, Malformed> {
        let count = usize::from(*bytes.first().ok_or(Malformed { at: 0 })?);
        if count > CYCLES_BEFORE_THE_THIRD_RUNG {
            return Err(Malformed { at: 0 });
        }
        let mut cuts = Self::NONE;
        let (instants, _) = bytes.get(1..).unwrap_or(&[]).as_chunks::<8>();
        for (slot, instant) in cuts.0.iter_mut().zip(instants).take(count) {
            *slot = Some(Tick::from_millis(u64::from_le_bytes(*instant)));
        }
        Ok(cuts)
    }
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
        let phase = match revision.rail_through_reset() {
            RailThroughReset::Off => Phase::Off,
            RailThroughReset::On => Phase::Up,
        };
        Self {
            revision,
            phase,
            cycles: [None; CYCLES_BEFORE_THE_THIRD_RUNG],
        }
    }

    /// Start from the cuts a previous boot kept, carried as made at this
    /// boot's start (F-017). On a board whose rail is off through a reset,
    /// the reset that began this boot cut the rail too, and is counted as
    /// a cut at `now` (F-018).
    pub fn carry(&mut self, carried: RecentCuts, now: Tick) {
        self.cycles = carried.0;
        match self.revision.rail_through_reset() {
            RailThroughReset::Off => self.remember_cut(now),
            RailThroughReset::On => {}
        }
    }

    /// The cuts of the last hour as of `now`, for the FRAM (F-017): the
    /// adapter keeps them whenever they differ from what the part holds,
    /// before the lines move, so a cut is on the part before the rail goes
    /// off and one that has aged out is off it before the next boot could
    /// carry it again.
    #[must_use]
    pub fn recent_cuts(&self, now: Tick) -> RecentCuts {
        RecentCuts::within_the_hour(&self.cycles, now)
    }

    /// Power the module at boot: the rail on with `EN` held low, released
    /// once the rail has settled. On a board whose rail is already on, the
    /// module is booting by itself and this takes ownership without a cut.
    pub fn power_on(&mut self, now: Tick) -> Lines {
        if let Phase::Off = self.phase {
            self.phase = Phase::Rising {
                until: now.after(SETTLE).unwrap_or(now),
                strap: false,
            };
        }
        self.lines()
    }

    /// The ladder asks for a recovery: a cut, or the third rung.
    pub fn recover(&mut self, now: Tick) -> Recovery {
        if let Phase::Cut { .. } | Phase::Rising { .. } | Phase::Strapping { .. } = self.phase {
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

    /// Reset the module with the rail on: `EN` held low for [`EN_HELD`],
    /// then released, which is a module boot the link sees as `Settled`.
    /// The bench's way into the download window (KM43 L-192), which is
    /// sent only after a reset the controller performed.
    pub fn reset_module(&mut self, now: Tick, boot: ModuleBoot) -> ModuleReset {
        let held = now.after(EN_HELD).unwrap_or(now);
        match self.phase {
            Phase::Up | Phase::Rising { .. } | Phase::Strapping { .. } => {
                // A reset asked while the rail is still settling keeps the
                // settling's deadline when it is the later one: EN is never
                // released before the rail has settled (F-004, F-006).
                let until = match self.phase {
                    Phase::Rising { until, .. } => until.max(held),
                    Phase::Up | Phase::Strapping { .. } | Phase::Cut { .. } | Phase::Off => held,
                };
                self.phase = Phase::Rising {
                    until,
                    strap: match boot {
                        ModuleBoot::Normal => false,
                        ModuleBoot::Download => true,
                    },
                };
                ModuleReset::Holding
            }
            Phase::Cut { .. } | Phase::Off => ModuleReset::NotPowered,
        }
    }

    /// Advance by time: the rail comes back at the end of a cut, and `EN`
    /// is released once the rail has settled.
    pub fn tick(&mut self, now: Tick) -> Option<RailEvent> {
        match self.phase {
            Phase::Cut { until } if now >= until => {
                self.phase = Phase::Rising {
                    until: now.after(SETTLE).unwrap_or(now),
                    strap: false,
                };
                let count = self.cycles_within(HOUR, now);
                Some(RailEvent::PowerCycled {
                    count: u8::try_from(count).unwrap_or(u8::MAX),
                })
            }
            Phase::Rising { until, strap: true } if now >= until => {
                // `EN` released with the strap still low: the ROM reads it
                // as the reset lets go. The rail has settled and the module
                // is booting, which is what the link waits for; the strap
                // is released on its own clock, and the ROM's first words
                // are on the UART the link builds now.
                self.phase = Phase::Strapping {
                    until: now.after(STRAP_HELD).unwrap_or(now),
                };
                Some(RailEvent::Settled)
            }
            Phase::Rising {
                until,
                strap: false,
            } if now >= until => {
                self.phase = Phase::Up;
                Some(RailEvent::Settled)
            }
            Phase::Strapping { until } if now >= until => {
                self.phase = Phase::Up;
                None
            }
            Phase::Cut { .. }
            | Phase::Rising { .. }
            | Phase::Strapping { .. }
            | Phase::Up
            | Phase::Off => None,
        }
    }

    /// How the three lines should be driven right now.
    #[must_use]
    pub const fn lines(&self) -> Lines {
        match self.phase {
            Phase::Cut { .. } => Lines {
                rail: RailLine::Off,
                en: EnLine::HeldLow,
                boot: BootLine::Released,
            },
            Phase::Rising { strap: false, .. } => Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow,
                boot: BootLine::Released,
            },
            Phase::Rising { strap: true, .. } => Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow,
                boot: BootLine::HeldLow,
            },
            Phase::Strapping { .. } => Lines {
                rail: RailLine::On,
                en: EnLine::Released,
                boot: BootLine::HeldLow,
            },
            Phase::Up => Lines {
                rail: RailLine::On,
                en: EnLine::Released,
                boot: BootLine::Released,
            },
            Phase::Off => Lines {
                rail: RailLine::Off,
                en: EnLine::Released,
                boot: BootLine::Released,
            },
        }
    }

    /// Whether the rail is up and settled, which is when the link may be
    /// configured (F-006).
    #[must_use]
    pub const fn settled(&self) -> bool {
        matches!(self.phase, Phase::Up | Phase::Strapping { .. })
    }

    fn cut(&mut self, now: Tick, off_for: Millis) -> Recovery {
        // The cap is the board's, whatever the rung asked for.
        let off_for = if off_for > self.revision.longest_rail_off() {
            self.revision.longest_rail_off()
        } else {
            off_for
        };
        self.remember_cut(now);
        self.phase = Phase::Cut {
            until: now.after(off_for).unwrap_or(now),
        };
        let count = self.cycles_within(HOUR, now);
        Recovery::Cycling {
            count: u8::try_from(count).unwrap_or(u8::MAX),
            off_for,
        }
    }

    /// A cut at `now`: an empty slot first of all, then the oldest cut. An
    /// empty slot sorts before any cut, one carried at tick zero included.
    fn remember_cut(&mut self, now: Tick) {
        if let Some(slot) = self
            .cycles
            .iter_mut()
            .min_by_key(|slot| slot.map(Tick::as_millis))
        {
            *slot = Some(now);
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
                en: EnLine::HeldLow,
                boot: BootLine::Released
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
                en: EnLine::Released,
                boot: BootLine::Released
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
                en: EnLine::HeldLow,
                boot: BootLine::Released
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

    #[test]
    fn a_module_reset_holds_en_with_the_rail_on_and_settles_when_released() {
        let mut rail = RailSequencer::new(Revision::A);
        let _ = rail.power_on(Tick::from_millis(0));
        assert_eq!(rail.tick(Tick::from_millis(100)), Some(RailEvent::Settled));
        assert_eq!(
            rail.reset_module(Tick::from_millis(1_000), ModuleBoot::Normal),
            ModuleReset::Holding
        );
        assert_eq!(
            rail.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow,
                boot: BootLine::Released
            }
        );
        assert_eq!(rail.tick(Tick::from_millis(1_040)), None);
        assert_eq!(
            rail.tick(Tick::from_millis(1_050)),
            Some(RailEvent::Settled)
        );
        assert_eq!(
            rail.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::Released,
                boot: BootLine::Released
            }
        );
    }

    #[test]
    fn a_strapped_reset_holds_the_boot_line_low_across_the_reset_and_releases_it_after() {
        let mut rail = RailSequencer::new(Revision::A);
        let _ = rail.power_on(Tick::from_millis(0));
        assert_eq!(rail.tick(Tick::from_millis(100)), Some(RailEvent::Settled));
        assert_eq!(rail.lines().boot, BootLine::Released, "a normal boot");
        assert_eq!(
            rail.reset_module(Tick::from_millis(1_000), ModuleBoot::Download),
            ModuleReset::Holding
        );
        assert_eq!(
            rail.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::HeldLow,
                boot: BootLine::HeldLow,
            },
            "the strap is low before the reset lets go"
        );
        // `EN` released, the strap still low for the ROM to read: settled
        // for the link, which builds its UART in time for the ROM's banner.
        assert_eq!(
            rail.tick(Tick::from_millis(1_050)),
            Some(RailEvent::Settled)
        );
        assert!(rail.settled());
        assert_eq!(
            rail.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::Released,
                boot: BootLine::HeldLow,
            }
        );
        assert!(matches!(
            rail.recover(Tick::from_millis(1_060)),
            Recovery::Busy
        ));
        assert_eq!(rail.tick(Tick::from_millis(1_140)), None);
        assert_eq!(rail.tick(Tick::from_millis(1_150)), None);
        assert_eq!(
            rail.lines(),
            Lines {
                rail: RailLine::On,
                en: EnLine::Released,
                boot: BootLine::Released,
            },
            "released once read"
        );
        // A normal reset after it never touches the strap.
        let _ = rail.reset_module(Tick::from_millis(2_000), ModuleBoot::Normal);
        assert_eq!(rail.lines().boot, BootLine::Released);
        let _ = rail.tick(Tick::from_millis(2_050));
        assert_eq!(rail.lines().boot, BootLine::Released);
    }

    #[test]
    fn f_004_a_reset_asked_while_the_rail_settles_never_releases_en_early() {
        let mut rail = RailSequencer::new(Revision::A);
        let _ = rail.power_on(Tick::from_millis(0));
        // Ten milliseconds into the rail's settling, a reset for download.
        assert_eq!(
            rail.reset_module(Tick::from_millis(10), ModuleBoot::Download),
            ModuleReset::Holding
        );
        assert_eq!(rail.lines().en, EnLine::HeldLow);
        // Its own fifty milliseconds would end at 60; the rail settles at 100.
        assert_eq!(rail.tick(Tick::from_millis(60)), None);
        assert_eq!(rail.lines().en, EnLine::HeldLow, "EN still held at 60 ms");
        assert_eq!(rail.tick(Tick::from_millis(99)), None);
        assert_eq!(
            rail.tick(Tick::from_millis(100)),
            Some(RailEvent::Settled),
            "released with the settling, strap still low"
        );
        assert_eq!(rail.lines().boot, BootLine::HeldLow);
        // Late in the settling, the reset's own hold is the later deadline.
        let mut late = RailSequencer::new(Revision::A);
        let _ = late.power_on(Tick::from_millis(0));
        let _ = late.reset_module(Tick::from_millis(90), ModuleBoot::Normal);
        assert_eq!(late.tick(Tick::from_millis(100)), None);
        assert_eq!(late.tick(Tick::from_millis(140)), Some(RailEvent::Settled));
    }

    #[test]
    fn a_module_reset_with_the_rail_off_or_cut_resets_nothing_and_counts_no_cycle() {
        let mut rail = RailSequencer::new(Revision::A);
        assert_eq!(
            rail.reset_module(Tick::from_millis(0), ModuleBoot::Normal),
            ModuleReset::NotPowered
        );
        let _ = rail.power_on(Tick::from_millis(0));
        let _ = rail.tick(Tick::from_millis(100));
        let cycling = rail.recover(Tick::from_millis(200));
        assert!(matches!(cycling, Recovery::Cycling { count: 1, .. }));
        assert_eq!(
            rail.reset_module(Tick::from_millis(300), ModuleBoot::Normal),
            ModuleReset::NotPowered
        );
        // The reset is not a rail cycle: the ladder's count does not move.
        let _ = rail.tick(Tick::from_millis(5_200));
        let _ = rail.tick(Tick::from_millis(5_300));
        assert_eq!(
            rail.reset_module(Tick::from_millis(6_000), ModuleBoot::Normal),
            ModuleReset::Holding
        );
        let _ = rail.tick(Tick::from_millis(6_050));
        assert!(matches!(
            rail.recover(Tick::from_millis(7_000)),
            Recovery::Cycling { count: 2, .. }
        ));
    }

    /// A sequencer on `revision` at the start of a boot that carries
    /// `kept`, powered and settled.
    fn booted(revision: Revision, kept: RecentCuts) -> RailSequencer {
        let mut seq = RailSequencer::new(revision);
        seq.carry(kept.rebased(), at(0));
        let _ = seq.power_on(at(0));
        let _ = run(&mut seq, 0, 200);
        seq
    }

    #[test]
    fn f_017_the_third_rung_is_reached_across_controller_resets() {
        // Revision B keeps its rail through a reset, so only the ladder's
        // own cuts count, one a boot, each boot starting from what the part
        // kept.
        let mut kept = RecentCuts::NONE;
        for boot in 1..=3u8 {
            let mut seq = booted(Revision::B, kept);
            let Recovery::Cycling { count, off_for } = seq.recover(at(60_000)) else {
                panic!("boot {boot}: a cut");
            };
            assert_eq!(count, boot, "the count carries across the reset");
            assert_eq!(off_for, CUT);
            kept = seq.recent_cuts(at(60_000));
        }
        let mut seq = booted(Revision::B, kept);
        let Recovery::Cycling { off_for, .. } = seq.recover(at(60_000)) else {
            panic!("the third rung cuts on revision B");
        };
        assert_eq!(
            off_for,
            Millis::from_millis(900_000),
            "the fifteen minutes of L-112"
        );
    }

    #[test]
    fn f_017_a_carried_cut_expires_an_hour_into_the_boot_that_carried_it() {
        let seq = booted(Revision::B, RecentCuts::FULL);
        assert_eq!(seq.recent_cuts(at(3_600_000)).count(), 3);
        assert_eq!(seq.recent_cuts(at(3_600_001)), RecentCuts::NONE);
    }

    #[test]
    fn f_017_a_record_that_does_not_read_counts_as_the_full_ladder() {
        assert_eq!(RecentCuts::carried(&Held::Corrupt), RecentCuts::FULL);
        assert_eq!(
            RecentCuts::carried(&Held::Malformed(Malformed { at: 0 })),
            RecentCuts::FULL
        );
        assert_eq!(RecentCuts::carried(&Held::Absent), RecentCuts::NONE);
        let one = RecentCuts([Some(at(7)), None, None]);
        assert_eq!(RecentCuts::carried(&Held::Present(one)), one);
        // Full, a revision A boot's first request is the third rung.
        let mut seq = booted(Revision::A, RecentCuts::carried(&Held::Corrupt));
        assert_eq!(seq.recover(at(60_000)), Recovery::LeftOnAndRaised);
    }

    #[test]
    fn f_017_the_cuts_round_trip_through_their_record_and_a_count_past_three_is_refused() {
        for cuts in [
            RecentCuts::NONE,
            RecentCuts([Some(at(1_000)), None, None]),
            RecentCuts([Some(at(1)), Some(at(2)), Some(at(u64::MAX))]),
        ] {
            assert_eq!(RecentCuts::decode(&cuts.encode()), Ok(cuts));
        }
        let mut bytes = RecentCuts::FULL.encode();
        bytes[0] = 4;
        assert_eq!(RecentCuts::decode(&bytes), Err(Malformed { at: 0 }));
    }

    #[test]
    fn f_017_a_boot_carries_every_cut_as_made_at_its_start_and_keeps_them_oldest_first() {
        let cuts = RecentCuts([Some(at(5_000)), Some(at(900)), None]);
        assert_eq!(
            cuts.rebased(),
            RecentCuts([Some(Tick::ZERO), Some(Tick::ZERO), None])
        );
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let _ = seq.recover(at(5_000));
        let _ = run(&mut seq, 5_001, 10_200);
        let _ = seq.recover(at(20_000));
        assert_eq!(
            seq.recent_cuts(at(20_000)),
            RecentCuts([Some(at(5_000)), Some(at(20_000)), None])
        );
    }

    #[test]
    fn f_018_on_revision_a_the_reset_that_began_a_boot_is_a_cut() {
        let mut kept = RecentCuts::NONE;
        for boot in 1..=3usize {
            let seq = booted(Revision::A, kept);
            kept = seq.recent_cuts(at(0));
            assert_eq!(kept.count(), boot);
        }
        // Three resets inside the hour: the ladder's first request on the
        // next boot is the third rung, which revision A does not execute.
        let mut seq = booted(Revision::A, kept);
        assert_eq!(seq.recover(at(60_000)), Recovery::LeftOnAndRaised);
    }

    #[test]
    fn f_018_revision_b_keeps_its_rail_through_a_reset_and_counts_no_cut_for_it() {
        let seq = booted(Revision::B, RecentCuts::NONE);
        assert_eq!(seq.recent_cuts(at(0)), RecentCuts::NONE);
    }
}
