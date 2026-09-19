//! The rail task's turn: the sequencer, what the FRAM holds of the
//! ladder's cuts, and the cut waiting on its count (F-017), decided here so
//! their order runs on the host. The adapter turns [`Rail`] every period
//! with the link's request and the recorder's answer it holds, and does
//! what the [`Turn`] says: the words to the link, the keep to hand the
//! recorder, and the lines.

use crate::{
    CutsOnPart, Lines, ModuleBoot, ModuleReset, Plan, PlannedCut, RailEvent, RailSequencer,
    RecentCuts, Recovery, Tick,
};

/// What the link asks of the rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RailRequest {
    /// Recover, by whatever rung the sequencer is at.
    Recover,
    /// Reset the module with the rail on: `EN` held and released, which is
    /// the boot the download window opens in, or with the strap held for
    /// the ROM's own download mode (F-038).
    ResetModule(ModuleBoot),
}

/// The ladder's cuts, for the recorder to keep on the FRAM (F-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Keep {
    /// A planned cut's count: it supersedes any keep in flight, because
    /// the recorder writes in order and the part ends with these, and the
    /// cut waits on its answer.
    Cut(RecentCuts),
    /// Cuts the part is not known to hold: one that aged out, a cut's
    /// instant corrected to when its lines moved, or a write that did not
    /// land. Started only when no other keep is in flight.
    Changed(RecentCuts),
}

impl Keep {
    /// The cuts to keep.
    #[must_use]
    pub const fn cuts(self) -> RecentCuts {
        match self {
            Self::Cut(cuts) | Self::Changed(cuts) => cuts,
        }
    }
}

/// Why a keep did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NotKept {
    /// This boot has no store: the FRAM did not answer at boot.
    NoStore,
    /// The part refused the write.
    Refused,
    /// The recorder did not answer inside the adapter's deadline.
    Late,
}

/// A keep and what became of it, as the recorder answered.
pub type KeepAnswer = (Keep, Result<(), NotKept>);

/// What one turn asks of the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a turn nobody performs is a word the link never hears and a count the part never gets"]
pub struct Turn {
    /// What the link's recovery request came to, to tell it.
    pub recovered: Option<Recovery>,
    /// What its module reset came to, to tell it.
    pub reset: Option<ModuleReset>,
    /// What the sequencer did by time.
    pub event: Option<RailEvent>,
    /// The cuts to hand the recorder.
    pub keep: Option<Keep>,
}

/// The rail task's state: the sequencer, what the part holds of the
/// ladder's cuts, or nothing on a boot with no store, and the cut planned
/// and waiting on its count.
#[derive(Debug)]
pub struct Rail {
    sequencer: RailSequencer,
    on_part: Option<CutsOnPart>,
    planned: Option<PlannedCut>,
}

impl Rail {
    /// The rail as `main` leaves it: powered, its cuts carried and kept.
    #[must_use]
    pub const fn new(sequencer: RailSequencer, on_part: Option<CutsOnPart>) -> Self {
        Self {
            sequencer,
            on_part,
            planned: None,
        }
    }

    /// One turn at `now`, with the link's request and the recorder's
    /// answer the adapter holds.
    ///
    /// A module reset comes first: it is served whatever the recorder
    /// answered, and a cut planned before it is not made after it, so a
    /// download never finds its module cut from under it. Then the answer:
    /// what the part holds, and the planned cut made once its own count
    /// has landed, deferred otherwise. Then a recovery, planned and its
    /// count handed out; a second one while a cut waits is the same
    /// request, and the cut's answer answers it. Then time, and the cuts
    /// the part is not known to hold, while no cut waits.
    pub fn turn(
        &mut self,
        now: Tick,
        request: Option<RailRequest>,
        answer: Option<KeepAnswer>,
    ) -> Turn {
        let mut turn = Turn {
            recovered: None,
            reset: None,
            event: None,
            keep: None,
        };
        let waiting = self.planned.is_some();
        match request {
            Some(RailRequest::ResetModule(boot)) => {
                if self.planned.take().is_some() {
                    turn.recovered = Some(Recovery::Deferred);
                }
                turn.reset = Some(self.sequencer.reset_module(now, boot));
            }
            Some(RailRequest::Recover) | None => {}
        }
        if let Some((keep, kept)) = answer {
            if let Some(on_part) = self.on_part.as_mut() {
                match kept {
                    Ok(()) => on_part.landed(keep.cuts()),
                    Err(_) => on_part.unknown(now),
                }
            }
            match keep {
                Keep::Cut(_) => {
                    if let Some(cut) = self.planned.take() {
                        turn.recovered = Some(match kept {
                            Ok(()) => cut.make(&mut self.sequencer, now),
                            Err(_) => Recovery::Deferred,
                        });
                    }
                }
                Keep::Changed(_) => {}
            }
        }
        match request {
            Some(RailRequest::Recover) if !waiting => match self.sequencer.plan_recovery(now) {
                Plan::Cut(cut) => {
                    turn.keep = Some(Keep::Cut(cut.cuts()));
                    self.planned = Some(cut);
                }
                Plan::LeftOnAndRaised => turn.recovered = Some(Recovery::LeftOnAndRaised),
                Plan::Busy => turn.recovered = Some(Recovery::Busy),
            },
            Some(RailRequest::Recover | RailRequest::ResetModule(_)) | None => {}
        }
        turn.event = self.sequencer.tick(now);
        let cuts = self.sequencer.recent_cuts(now);
        if self.planned.is_none()
            && let Some(on_part) = self.on_part.as_ref()
            && on_part.due(cuts, now)
        {
            turn.keep = Some(Keep::Changed(cuts));
        }
        turn
    }

    /// How the lines should be driven now.
    #[must_use]
    pub const fn lines(&self) -> Lines {
        self.sequencer.lines()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootLine, CUT, CarriedCuts, KEEP_RETRY, RailLine, Revision};

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    /// A revision B rail, settled, whose part holds no cut.
    fn rail() -> Rail {
        let mut seq = RailSequencer::new(Revision::B);
        seq.carry(
            CarriedCuts {
                cuts: RecentCuts::NONE,
                missed: 0,
            },
            at(0),
        );
        let _ = seq.power_on(at(0));
        Rail::new(seq, Some(CutsOnPart::read(RecentCuts::NONE)))
    }

    /// Asked to recover at `now`: the count handed out and the cut waiting.
    fn asked(rail: &mut Rail, now: u64) -> RecentCuts {
        let turn = rail.turn(at(now), Some(RailRequest::Recover), None);
        assert_eq!(turn.recovered, None, "nothing moves before the count lands");
        let Some(Keep::Cut(cuts)) = turn.keep else {
            panic!("the count goes out: {turn:?}");
        };
        cuts
    }

    #[test]
    fn f_017_a_cut_is_made_on_the_turn_its_count_lands_and_its_instant_is_then_rewritten() {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        assert_eq!(cuts, RecentCuts::one_at(at(1_000)));
        assert_eq!(rail.lines().rail, RailLine::On);
        let turn = rail.turn(at(1_020), None, None);
        assert_eq!((turn.recovered, turn.keep), (None, None), "still waiting");
        let turn = rail.turn(at(1_500), None, Some((Keep::Cut(cuts), Ok(()))));
        assert_eq!(
            turn.recovered,
            Some(Recovery::Cycling {
                count: 1,
                off_for: CUT
            })
        );
        assert_eq!(rail.lines().rail, RailLine::Off);
        // The cut counts from when its lines moved (L-112), which the part
        // is told next.
        assert_eq!(
            turn.keep,
            Some(Keep::Changed(RecentCuts::one_at(at(1_500))))
        );
    }

    #[test]
    fn f_017_a_module_reset_asked_as_the_count_lands_is_served_and_the_cut_is_not_made() {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        let turn = rail.turn(
            at(1_020),
            Some(RailRequest::ResetModule(ModuleBoot::Download)),
            Some((Keep::Cut(cuts), Ok(()))),
        );
        assert_eq!(turn.reset, Some(ModuleReset::Holding));
        assert_eq!(turn.recovered, Some(Recovery::Deferred));
        assert_eq!(rail.lines().rail, RailLine::On);
        assert_eq!(rail.lines().boot, BootLine::HeldLow, "the download's strap");
        // The part holds a cut that was never made; the count this boot
        // holds goes back out.
        assert_eq!(turn.keep, Some(Keep::Changed(RecentCuts::NONE)));
    }

    #[test]
    fn f_017_a_module_reset_while_the_count_goes_out_drops_the_cut_and_its_late_answer_moves_nothing()
     {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        let turn = rail.turn(
            at(1_020),
            Some(RailRequest::ResetModule(ModuleBoot::Normal)),
            None,
        );
        assert_eq!(turn.reset, Some(ModuleReset::Holding));
        assert_eq!(turn.recovered, Some(Recovery::Deferred));
        assert_eq!(turn.keep, None, "the cut's count is still in flight");
        let turn = rail.turn(at(1_100), None, Some((Keep::Cut(cuts), Ok(()))));
        assert_eq!(turn.recovered, None);
        assert_eq!(rail.lines().rail, RailLine::On);
        assert_eq!(turn.keep, Some(Keep::Changed(RecentCuts::NONE)));
    }

    #[test]
    fn f_017_a_count_that_does_not_land_defers_the_cut_and_the_part_is_rewritten_a_retry_later() {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        let turn = rail.turn(at(3_000), None, Some((Keep::Cut(cuts), Err(NotKept::Late))));
        assert_eq!(turn.recovered, Some(Recovery::Deferred));
        assert_eq!(rail.lines().rail, RailLine::On);
        assert_eq!(turn.keep, None, "not before the retry");
        let retry = at(3_000).after(KEEP_RETRY).expect("fits").as_millis();
        let turn = rail.turn(at(retry), None, None);
        assert_eq!(turn.keep, Some(Keep::Changed(RecentCuts::NONE)));
    }

    #[test]
    fn f_017_a_second_recovery_while_a_cut_waits_is_the_same_request() {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        let turn = rail.turn(at(1_020), Some(RailRequest::Recover), None);
        assert_eq!((turn.recovered, turn.keep), (None, None));
        let turn = rail.turn(
            at(1_040),
            Some(RailRequest::Recover),
            Some((Keep::Cut(cuts), Ok(()))),
        );
        assert!(matches!(
            turn.recovered,
            Some(Recovery::Cycling { count: 1, .. })
        ));
    }

    #[test]
    fn f_017_an_answer_to_another_keep_is_never_taken_for_the_cuts() {
        let mut rail = rail();
        let _ = asked(&mut rail, 1_000);
        let turn = rail.turn(
            at(1_020),
            None,
            Some((Keep::Changed(RecentCuts::NONE), Ok(()))),
        );
        assert_eq!(turn.recovered, None);
        assert_eq!(rail.lines().rail, RailLine::On);
        assert_eq!(turn.keep, None, "nothing else starts while a cut waits");
    }

    #[test]
    fn f_017_a_boot_with_no_store_defers_the_cut_it_cannot_keep() {
        let mut seq = RailSequencer::new(Revision::B);
        let _ = seq.power_on(at(0));
        let mut rail = Rail::new(seq, None);
        let cuts = asked(&mut rail, 1_000);
        let turn = rail.turn(
            at(1_020),
            None,
            Some((Keep::Cut(cuts), Err(NotKept::NoStore))),
        );
        assert_eq!(turn.recovered, Some(Recovery::Deferred));
        assert_eq!(rail.lines().rail, RailLine::On);
        assert_eq!(turn.keep, None, "nowhere to keep anything");
    }

    #[test]
    fn f_017_a_recovery_that_moves_nothing_is_answered_at_once_with_nothing_to_keep() {
        let mut rail = rail();
        let cuts = asked(&mut rail, 1_000);
        let _ = rail.turn(at(1_020), None, Some((Keep::Cut(cuts), Ok(()))));
        let turn = rail.turn(at(1_040), Some(RailRequest::Recover), None);
        assert_eq!(turn.recovered, Some(Recovery::Busy));
    }
}
