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
//! on the tick. On revision A the reset that began the boot is one of them,
//! and so is the reset that began every boot since the record was written,
//! which the boot count tells (F-017, F-018).
//!
//! cites: F-004, F-005

use crate::body::{Body, Held, Malformed};
use crate::{BootCount, Millis, RailThroughReset, Revision, ThirdRung, Tick};

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
    /// The cut was due and not made, and nothing moved: the count it would
    /// have added could not be kept on the FRAM first (F-017), which the
    /// adapter reports, or the module was reset while it went out, which
    /// [`PlannedCut::make`] does. The ladder asks again.
    Deferred,
}

/// What a recovery request plans, before anything moves (F-017).
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a plan nobody answers is a ladder waiting on a word that never comes"]
pub enum Plan {
    /// The third rung on a board that does not execute it: nothing moves,
    /// and comms unrecoverable is to be raised.
    LeftOnAndRaised,
    /// A cut is already in progress; nothing changes.
    Busy,
    /// A cut, made once the count it adds is kept.
    Cut(PlannedCut),
}

/// A cut planned and not made (F-017): the sequencer as it was asked, the
/// instant of the cut and the rung's off time. [`cuts`](Self::cuts) is the
/// count to keep on the FRAM first, and [`make`](Self::make) the only way
/// to the cut, which the adapter calls once that count has landed; a plan
/// dropped instead moves nothing. Not `Copy`, so a plan is made once.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a planned cut is made or deferred, and the link waits to hear which"]
pub struct PlannedCut {
    asked: RailSequencer,
    at: Tick,
    off_for: Millis,
}

impl PlannedCut {
    /// The cuts of the last hour with this one, to keep before it is made:
    /// the cuts the sequencer holds once [`make`](Self::make) has made it.
    #[must_use]
    pub fn cuts(&self) -> RecentCuts {
        let mut cut = self.asked;
        let _counted = cut.cut(self.at, self.off_for);
        cut.recent_cuts(self.at)
    }

    /// Make the cut, its count kept: the lines move at `at`, the whole off
    /// time runs from there (L-111), and the cut counts for the hour from
    /// there (L-112). The count kept named the request's instant, a moment
    /// earlier, and the adapter's next write corrects it. A sequencer that
    /// moved since the plan, a module reset served while the count went
    /// out, is left as it is and the cut is [`Recovery::Deferred`]: it was
    /// planned for a module that is no longer as it was.
    pub fn make(self, sequencer: &mut RailSequencer, at: Tick) -> Recovery {
        if *sequencer != self.asked {
            return Recovery::Deferred;
        }
        let (count, off_for) = sequencer.cut(at, self.off_for);
        Recovery::Cycling { count, off_for }
    }
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
    /// Rail off, `EN` held low, until the moment the rail comes back,
    /// `off_for` after the lines moved.
    Cut { until: Tick, off_for: Millis },
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

#[cfg(test)]
impl RecentCuts {
    /// One cut, at `at`.
    pub(crate) const fn one_at(at: Tick) -> Self {
        Self([Some(at), None, None])
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

/// The bytes a [`CutsRecord`] takes: the boot count, then the cuts.
pub const CUTS_RECORD_BYTES: usize = 4 + RECENT_CUTS_BYTES;

/// The ladder's record on the FRAM (F-017, F-018): the cuts of the last
/// hour, and the boot count the part held when they were written. Every
/// boot counted after that one began with a reset, and none of their own
/// records landed; the boot that reads the record counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CutsRecord {
    /// The boot count on the part when the record was written: the
    /// writer's own once it has landed, the one before otherwise, and none
    /// on a part that never held one.
    pub boot: Option<BootCount>,
    /// The cuts of the last hour, on the writer's tick.
    pub cuts: RecentCuts,
}

impl CutsRecord {
    /// What the boot numbered `boot` carries of the record as it read: its
    /// cuts as made at this boot's start, and the boots between its writer
    /// and this one. None for a record never written, which no boot before
    /// this one kept; the full ladder for one that is there and does not
    /// read, or that names this boot or a later one, because a count the
    /// part lost is never taken as zero.
    #[must_use]
    pub fn carried(held: &Held<Self>, boot: BootCount) -> CarriedCuts {
        let (cuts, kept_at) = match held {
            Held::Present(record) => (record.cuts.rebased(), record.boot.map_or(0, BootCount::get)),
            Held::Absent => (RecentCuts::NONE, 0),
            Held::Corrupt | Held::Malformed(_) => return CarriedCuts::FULL,
        };
        match boot
            .get()
            .checked_sub(kept_at)
            .and_then(|after| after.checked_sub(1))
        {
            Some(missed) => CarriedCuts { cuts, missed },
            None => CarriedCuts::FULL,
        }
    }
}

impl Body<CUTS_RECORD_BYTES> for CutsRecord {
    fn encode(&self) -> [u8; CUTS_RECORD_BYTES] {
        let mut bytes = [0u8; CUTS_RECORD_BYTES];
        let (boot, cuts) = bytes.split_at_mut(4);
        boot.copy_from_slice(&self.boot.map_or(0, BootCount::get).to_le_bytes());
        cuts.copy_from_slice(&self.cuts.encode());
        bytes
    }

    /// A boot count of zero is none; the cuts decode as [`RecentCuts`] do.
    fn decode(bytes: &[u8; CUTS_RECORD_BYTES]) -> Result<Self, Malformed> {
        let (boot, cuts) = bytes.split_first_chunk::<4>().ok_or(Malformed { at: 0 })?;
        let boot = match u32::from_le_bytes(*boot) {
            0 => None,
            _ => Some(BootCount::decode(boot)?),
        };
        let cuts = cuts
            .first_chunk::<RECENT_CUTS_BYTES>()
            .ok_or(Malformed { at: 4 })?;
        let cuts = RecentCuts::decode(cuts).map_err(|malformed| Malformed {
            at: malformed.at.saturating_add(4),
        })?;
        Ok(Self { boot, cuts })
    }
}

/// What a boot carries of the ladder (F-017, F-018): the cuts the part
/// kept, as made at this boot's start, and how many boots since the one
/// that kept them began with a reset whose own record never landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CarriedCuts {
    /// The cuts the part kept, at this boot's tick zero.
    pub cuts: RecentCuts,
    /// The boots between the one that kept them and this one.
    pub missed: u32,
}

impl CarriedCuts {
    /// The full ladder: what a record that does not read, or a boot with
    /// no store, carries.
    pub const FULL: Self = Self {
        cuts: RecentCuts::FULL,
        missed: 0,
    };
}

/// How long after a write of the cuts that did not land the next is tried.
pub const KEEP_RETRY: Millis = Millis::from_millis(1_000);

/// What the FRAM holds of the ladder's cuts, as far as this boot knows,
/// and so when to write them again (F-017).
///
/// A write that failed, or was abandoned late, leaves the part's content
/// unknown: a late write may still land, a count for a cut that was never
/// made. So after one the cuts go out again whatever they are, a retry
/// later, and whatever landed late is overwritten by the count this boot
/// holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CutsOnPart {
    held: Option<RecentCuts>,
    retry_at: Option<Tick>,
}

impl CutsOnPart {
    /// The part as the boot read it, carried to this boot.
    #[must_use]
    pub const fn read(held: RecentCuts) -> Self {
        Self {
            held: Some(held),
            retry_at: None,
        }
    }

    /// Whether `cuts` should be written at `now`: they are not what the
    /// part is known to hold, and no retry is still waiting.
    #[must_use]
    pub fn due(&self, cuts: RecentCuts, now: Tick) -> bool {
        self.held != Some(cuts) && self.retry_at.is_none_or(|at| now >= at)
    }

    /// The write of `cuts` landed.
    pub fn landed(&mut self, cuts: RecentCuts) {
        self.held = Some(cuts);
        self.retry_at = None;
    }

    /// The write at `now` failed or was abandoned: what the part holds is
    /// not known, and the cuts go out again [`KEEP_RETRY`] later.
    pub fn unknown(&mut self, now: Tick) {
        self.held = None;
        self.retry_at = Some(now.after(KEEP_RETRY).unwrap_or(now));
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
    /// the reset that began this boot cut the rail too, and so did the one
    /// that began every boot the record missed; each is a cut at `now`
    /// (F-018).
    pub fn carry(&mut self, carried: CarriedCuts, now: Tick) {
        self.cycles = carried.cuts.0;
        match self.revision.rail_through_reset() {
            RailThroughReset::Off => {
                // Bounded by the ladder's slots: past them, every slot
                // already holds a cut at `now`.
                let missed = usize::try_from(carried.missed)
                    .unwrap_or(usize::MAX)
                    .min(CYCLES_BEFORE_THE_THIRD_RUNG);
                for _ in 0..=missed {
                    self.remember_cut(now);
                }
            }
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

    /// The ladder asks for a recovery at `now`: a cut, or the third rung.
    /// Nothing moves here; a cut is made by [`PlannedCut::make`] once the
    /// count it adds is on the FRAM (F-017).
    pub fn plan_recovery(&self, now: Tick) -> Plan {
        if let Phase::Cut { .. } | Phase::Rising { .. } | Phase::Strapping { .. } = self.phase {
            return Plan::Busy;
        }
        let off_for = if self.cycles_within(HOUR, now) >= CYCLES_BEFORE_THE_THIRD_RUNG {
            match self.revision.third_rung() {
                ThirdRung::LeaveOnAndRaise => return Plan::LeftOnAndRaised,
                ThirdRung::Cut(off_for) => off_for,
            }
        } else {
            CUT
        };
        Plan::Cut(PlannedCut {
            asked: *self,
            at: now,
            off_for,
        })
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
            Phase::Cut { until, .. } if now >= until => {
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

    /// The cut at `now`, and the count of the last hour with it.
    fn cut(&mut self, now: Tick, off_for: Millis) -> (u8, Millis) {
        // The cap is the board's, whatever the rung asked for.
        let off_for = if off_for > self.revision.longest_rail_off() {
            self.revision.longest_rail_off()
        } else {
            off_for
        };
        self.remember_cut(now);
        self.phase = Phase::Cut {
            until: now.after(off_for).unwrap_or(now),
            off_for,
        };
        let count = self.cycles_within(HOUR, now);
        (u8::try_from(count).unwrap_or(u8::MAX), off_for)
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

    /// A recovery whose count lands at once: planned and made at `now`.
    fn recover(seq: &mut RailSequencer, now: Tick) -> Recovery {
        match seq.plan_recovery(now) {
            Plan::Cut(cut) => cut.make(seq, now),
            Plan::LeftOnAndRaised => Recovery::LeftOnAndRaised,
            Plan::Busy => Recovery::Busy,
        }
    }

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
            recover(&mut seq, at(1_000)),
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
        assert!(matches!(
            recover(&mut seq, at(10_000)),
            Recovery::Cycling { .. }
        ));
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
                recover(&mut seq, at(now)),
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
            recover(&mut seq, at(now)),
            Recovery::Cycling {
                count: 3,
                off_for: CUT
            }
        );
        run(&mut seq, now, now + 6_000);
        now += 60_000;
        // A fourth request inside the hour is the third rung: nothing moves.
        let before = seq.lines();
        assert_eq!(recover(&mut seq, at(now)), Recovery::LeftOnAndRaised);
        assert_eq!(seq.lines(), before);
        assert_eq!(seq.lines().rail, RailLine::On);
        assert_eq!(run(&mut seq, now, now + 1_000), NONE);
        // An hour after the first cycle it has aged out and cycling resumes.
        let later = 60_000 + 3_600_001;
        assert!(matches!(
            recover(&mut seq, at(later)),
            Recovery::Cycling { count: 3, .. }
        ));
    }

    #[test]
    fn f_005_revision_b_executes_the_third_rung_inside_its_own_cap() {
        let mut seq = RailSequencer::new(Revision::B);
        let mut now = 60_000;
        for _ in 0..3 {
            assert!(matches!(
                recover(&mut seq, at(now)),
                Recovery::Cycling { .. }
            ));
            run(&mut seq, now, now + 6_000);
            now += 60_000;
        }
        assert_eq!(
            recover(&mut seq, at(now)),
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
        assert_eq!(recover(&mut seq, at(50)), Recovery::Busy);
        run(&mut seq, 0, 200);
        assert!(matches!(
            recover(&mut seq, at(1_000)),
            Recovery::Cycling { .. }
        ));
        assert_eq!(recover(&mut seq, at(2_000)), Recovery::Busy);
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
            recover(&mut rail, Tick::from_millis(1_060)),
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
        let cycling = recover(&mut rail, Tick::from_millis(200));
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
            recover(&mut rail, Tick::from_millis(7_000)),
            Recovery::Cycling { count: 2, .. }
        ));
    }

    /// A sequencer on `revision` at the start of a boot that carries
    /// `kept`, powered and settled.
    fn booted(revision: Revision, kept: RecentCuts) -> RailSequencer {
        carried(
            revision,
            CarriedCuts {
                cuts: kept.rebased(),
                missed: 0,
            },
        )
    }

    /// A sequencer on `revision` at the start of a boot that carries
    /// `carried`, powered and settled.
    fn carried(revision: Revision, carried: CarriedCuts) -> RailSequencer {
        let mut seq = RailSequencer::new(revision);
        seq.carry(carried, at(0));
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
            let Recovery::Cycling { count, off_for } = recover(&mut seq, at(60_000)) else {
                panic!("boot {boot}: a cut");
            };
            assert_eq!(count, boot, "the count carries across the reset");
            assert_eq!(off_for, CUT);
            kept = seq.recent_cuts(at(60_000));
        }
        let mut seq = booted(Revision::B, kept);
        let Recovery::Cycling { off_for, .. } = recover(&mut seq, at(60_000)) else {
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

    fn boot(count: u32) -> BootCount {
        BootCount::decode(&count.to_le_bytes()).expect("not zero")
    }

    #[test]
    fn f_017_a_record_that_does_not_read_counts_as_the_full_ladder() {
        assert_eq!(
            CutsRecord::carried(&Held::Corrupt, boot(9)),
            CarriedCuts::FULL
        );
        assert_eq!(
            CutsRecord::carried(&Held::Malformed(Malformed { at: 0 }), boot(9)),
            CarriedCuts::FULL
        );
        let one = RecentCuts([Some(at(7)), None, None]);
        let record = CutsRecord {
            boot: Some(boot(8)),
            cuts: one,
        };
        assert_eq!(
            CutsRecord::carried(&Held::Present(record), boot(9)),
            CarriedCuts {
                cuts: one.rebased(),
                missed: 0
            }
        );
        // Full, a revision A boot's first request is the third rung.
        let mut seq = carried(Revision::A, CutsRecord::carried(&Held::Corrupt, boot(9)));
        assert_eq!(recover(&mut seq, at(60_000)), Recovery::LeftOnAndRaised);
    }

    #[test]
    fn f_018_a_record_counts_the_boots_since_it_was_written_and_one_that_names_a_later_boot_is_full()
     {
        let none_at = |kept_at: Option<BootCount>| {
            Held::Present(CutsRecord {
                boot: kept_at,
                cuts: RecentCuts::NONE,
            })
        };
        let missed = |held: &Held<CutsRecord>, count: u32| CutsRecord::carried(held, boot(count));
        // Written at boot 5: boots 6 and 7 wrote nothing that landed.
        assert_eq!(missed(&none_at(Some(boot(5))), 8).missed, 2);
        // Written by a boot whose own count did not land, under the count
        // before it, which this boot takes again.
        assert_eq!(missed(&none_at(Some(boot(5))), 6).missed, 0);
        // Never written: every boot before this one missed it; a fresh
        // unit's first boot missed none.
        assert_eq!(
            missed(&Held::Absent, 1),
            CarriedCuts {
                cuts: RecentCuts::NONE,
                missed: 0
            }
        );
        assert_eq!(missed(&Held::Absent, 4).missed, 3);
        assert_eq!(missed(&none_at(None), 3).missed, 2);
        // A record from this boot's count or a later one: the counts
        // disagree, and the ladder is full.
        assert_eq!(missed(&none_at(Some(boot(6))), 6), CarriedCuts::FULL);
        assert_eq!(missed(&none_at(Some(boot(9))), 6), CarriedCuts::FULL);
    }

    #[test]
    fn f_018_on_revision_a_every_boot_the_record_missed_is_a_cut() {
        // Two boots whose writes never landed, then this one: the third
        // rung at the first request.
        let carried_cuts = CarriedCuts {
            cuts: RecentCuts::NONE,
            missed: 2,
        };
        let mut seq = carried(Revision::A, carried_cuts);
        assert_eq!(seq.recent_cuts(at(0)).count(), 3);
        assert_eq!(recover(&mut seq, at(60_000)), Recovery::LeftOnAndRaised);
        // Revision B keeps its rail through a reset: no boot is a cut.
        let seq = carried(Revision::B, carried_cuts);
        assert_eq!(seq.recent_cuts(at(0)), RecentCuts::NONE);
        // However many were missed, the ladder holds three.
        let seq = carried(
            Revision::A,
            CarriedCuts {
                cuts: RecentCuts::NONE,
                missed: u32::MAX,
            },
        );
        assert_eq!(seq.recent_cuts(at(0)).count(), 3);
    }

    #[test]
    fn f_017_the_cuts_round_trip_through_their_record_and_a_count_past_three_is_refused() {
        for cuts in [
            RecentCuts::NONE,
            RecentCuts([Some(at(1_000)), None, None]),
            RecentCuts([Some(at(1)), Some(at(2)), Some(at(u64::MAX))]),
        ] {
            for kept_at in [None, Some(BootCount::FIRST), Some(boot(u32::MAX))] {
                let record = CutsRecord {
                    boot: kept_at,
                    cuts,
                };
                assert_eq!(CutsRecord::decode(&record.encode()), Ok(record));
            }
        }
        let mut bytes = CutsRecord {
            boot: Some(boot(3)),
            cuts: RecentCuts::FULL,
        }
        .encode();
        bytes[4] = 4;
        assert_eq!(CutsRecord::decode(&bytes), Err(Malformed { at: 4 }));
    }

    #[test]
    fn f_017_a_boot_carries_every_cut_as_made_at_its_start_and_keeps_them_oldest_first() {
        let cuts = RecentCuts([Some(at(5_000)), Some(at(900)), None]);
        assert_eq!(
            cuts.rebased(),
            RecentCuts([Some(Tick::ZERO), Some(Tick::ZERO), None])
        );
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let _ = recover(&mut seq, at(5_000));
        let _ = run(&mut seq, 5_001, 10_200);
        let _ = recover(&mut seq, at(20_000));
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
        assert_eq!(recover(&mut seq, at(60_000)), Recovery::LeftOnAndRaised);
    }

    #[test]
    fn f_018_revision_b_keeps_its_rail_through_a_reset_and_counts_no_cut_for_it() {
        let seq = booted(Revision::B, RecentCuts::NONE);
        assert_eq!(seq.recent_cuts(at(0)), RecentCuts::NONE);
    }

    #[test]
    fn l_111_the_rail_is_off_for_the_whole_cut_from_when_its_lines_move() {
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let Plan::Cut(cut) = seq.plan_recovery(at(1_000)) else {
            panic!("a cut");
        };
        // The count took a second and a half to land; the lines move then.
        assert!(matches!(
            cut.make(&mut seq, at(2_500)),
            Recovery::Cycling { count: 1, .. }
        ));
        assert_eq!(run(&mut seq, 2_501, 7_499), [None; 4], "still off");
        assert_eq!(
            run(&mut seq, 7_500, 7_500)[0],
            Some((7_500, RailEvent::PowerCycled { count: 1 }))
        );
    }

    #[test]
    fn l_112_a_cut_counts_for_the_hour_from_when_its_lines_moved() {
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let Plan::Cut(cut) = seq.plan_recovery(at(1_000)) else {
            panic!("a cut");
        };
        // Kept as planned at the request; made when the count landed.
        assert_eq!(cut.cuts(), RecentCuts([Some(at(1_000)), None, None]));
        let _ = cut.make(&mut seq, at(2_500));
        assert_eq!(
            seq.recent_cuts(at(3_601_000)).count(),
            1,
            "an hour from the request"
        );
        assert_eq!(
            seq.recent_cuts(at(3_602_500)).count(),
            1,
            "an hour from the lines"
        );
        assert_eq!(seq.recent_cuts(at(3_602_501)), RecentCuts::NONE);
    }

    #[test]
    fn f_017_a_planned_cut_moves_nothing_until_it_is_made_and_keeps_the_count_it_makes() {
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let before = seq;
        let Plan::Cut(cut) = seq.plan_recovery(at(1_000)) else {
            panic!("a cut");
        };
        // Planned: the rail on, no cut counted, and the count to keep is
        // the one the cut will make.
        assert_eq!(seq, before);
        assert_eq!(seq.lines().rail, RailLine::On);
        assert_eq!(seq.recent_cuts(at(1_000)), RecentCuts::NONE);
        assert_eq!(cut.cuts(), RecentCuts([Some(at(1_000)), None, None]));
        assert_eq!(
            cut.make(&mut seq, at(1_000)),
            Recovery::Cycling {
                count: 1,
                off_for: CUT
            }
        );
        assert_eq!(seq.lines().rail, RailLine::Off);
        assert_eq!(
            seq.recent_cuts(at(1_000)),
            RecentCuts([Some(at(1_000)), None, None]),
            "what was kept is what the sequencer counts"
        );
    }

    #[test]
    fn f_017_a_cut_planned_before_a_module_reset_is_not_made_after_it() {
        let mut seq = booted(Revision::B, RecentCuts::NONE);
        let Plan::Cut(cut) = seq.plan_recovery(at(1_000)) else {
            panic!("a cut");
        };
        // A download's reset is served while the count goes out.
        assert_eq!(
            seq.reset_module(at(1_020), ModuleBoot::Download),
            ModuleReset::Holding
        );
        let reset = seq;
        assert_eq!(cut.make(&mut seq, at(1_500)), Recovery::Deferred);
        assert_eq!(seq, reset, "the reset stands, strap and all");
        assert_eq!(
            seq.recent_cuts(at(1_500)),
            RecentCuts::NONE,
            "no cut counted"
        );
        assert_eq!(seq.lines().rail, RailLine::On);
    }

    #[test]
    fn f_017_a_plan_that_moves_nothing_needs_no_count_kept() {
        // During a cut, and at a third rung revision A does not execute:
        // nothing to keep, and the answer at once.
        let mut seq = booted(Revision::A, RecentCuts::NONE);
        assert!(matches!(
            recover(&mut seq, at(60_000)),
            Recovery::Cycling { count: 2, .. }
        ));
        assert_eq!(seq.plan_recovery(at(60_020)), Plan::Busy);
        let full = booted(Revision::A, RecentCuts::FULL);
        assert_eq!(full.plan_recovery(at(60_000)), Plan::LeftOnAndRaised);
    }

    #[test]
    fn f_017_the_cuts_go_to_the_part_when_they_differ_from_what_it_is_known_to_hold() {
        let one = RecentCuts([Some(at(1)), None, None]);
        let mut part = CutsOnPart::read(RecentCuts::NONE);
        assert!(!part.due(RecentCuts::NONE, at(0)));
        assert!(part.due(one, at(0)));
        part.landed(one);
        assert!(!part.due(one, at(10)));
    }

    #[test]
    fn f_017_after_a_write_that_did_not_land_the_cuts_go_out_again_a_retry_later() {
        let one = RecentCuts([Some(at(1)), None, None]);
        let mut part = CutsOnPart::read(RecentCuts::NONE);
        // A late write of a planned cut that was then not made: the part
        // may hold it, so the count this boot holds, none, goes out again.
        part.unknown(at(100));
        assert!(
            !part.due(RecentCuts::NONE, at(1_099)),
            "not before the retry"
        );
        assert!(part.due(RecentCuts::NONE, at(1_100)), "even the same cuts");
        part.landed(RecentCuts::NONE);
        assert!(!part.due(RecentCuts::NONE, at(1_200)));
        assert!(part.due(one, at(1_200)));
    }
}
