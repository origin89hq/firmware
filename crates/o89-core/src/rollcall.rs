//! The roll every task answers to, and whether the watchdog has earned its
//! next feed.
//!
//! A watchdog fed from a timer is a watchdog that does not work: the timer
//! fires whatever else is wedged, so the part is petted, the reset never
//! comes, and the controller looks alive with a generator running and
//! nothing polling the tank. The executor is cooperative, so one task that
//! never yields starves every other one and nothing about the outside of the
//! board changes. So the feed is earned: every task checks in on its own
//! schedule, and this answers one question, may the part be fed. It never
//! feeds anything. The adapter holds the peripheral and this holds the
//! decision, which is what lets a wedged task be simulated on a laptop.
//!
//! cites: F-007

use crate::{Blame, Millis, Tick};

/// Every task the controller runs, each owning a peripheral and declaring
/// how long it may go without checking in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Task {
    /// The rollcall itself, the lamp, and the feed.
    Supervisor = 0,
    /// The 1 Hz control tick.
    Control = 1,
    /// The link to the comms processor.
    Link = 2,
    /// The only owner of the FRAM and NOR buses.
    Recorder = 3,
    /// RS-485 on CN2.
    Rs485One = 4,
    /// RS-485 on CN3.
    Rs485Two = 5,
    /// RS-485 on CN4.
    Rs485Three = 6,
    /// FDCAN on CN5.
    Can = 7,
    /// VE.Direct on CN6.
    VeDirectOne = 8,
    /// VE.Direct on CN7.
    VeDirectTwo = 9,
    /// The 1-Wire bus.
    OneWire = 10,
    /// The ADC channels.
    Adc = 11,
    /// The selector on CN10.
    Selector = 12,
    /// The lamp pattern.
    Lamp = 13,
    /// The module rail sequence.
    Rail = 14,
    /// The boot itself, before the supervisor runs: the store read off the
    /// FRAM under the 3 s budget (F-016). Never on the roll; the boot
    /// writes it to the last words as a provisional blame and clears it
    /// once the store is read, so a boot the watchdog cuts short is still
    /// named by the boot after.
    Boot = 15,
    /// Key agreement, on the executor below every other task's so that a
    /// second of X25519 never delays the control tick (P-243).
    Agreement = 16,
}

/// How many tasks the roll holds.
pub const TASKS: usize = 17;
const _: () = assert!(
    TASKS <= 256,
    "a task's place must fit the boot record's byte"
);

impl Task {
    /// Every task, in roll order, which is the order a late one is named in.
    pub const ALL: [Task; TASKS] = [
        Task::Supervisor,
        Task::Control,
        Task::Link,
        Task::Recorder,
        Task::Rs485One,
        Task::Rs485Two,
        Task::Rs485Three,
        Task::Can,
        Task::VeDirectOne,
        Task::VeDirectTwo,
        Task::OneWire,
        Task::Adc,
        Task::Selector,
        Task::Lamp,
        Task::Rail,
        Task::Boot,
        Task::Agreement,
    ];

    /// The task's place on the roll, which is what the last words carry.
    #[must_use]
    pub const fn index(self) -> u32 {
        self as u32
    }

    /// The task's place on the roll as one byte, which is how the boot
    /// record carries it.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    const fn slot(self) -> usize {
        self as usize
    }

    /// The reverse of [`Task::index`], for a value read back from RAM.
    #[must_use]
    pub const fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::Supervisor),
            1 => Some(Self::Control),
            2 => Some(Self::Link),
            3 => Some(Self::Recorder),
            4 => Some(Self::Rs485One),
            5 => Some(Self::Rs485Two),
            6 => Some(Self::Rs485Three),
            7 => Some(Self::Can),
            8 => Some(Self::VeDirectOne),
            9 => Some(Self::VeDirectTwo),
            10 => Some(Self::OneWire),
            11 => Some(Self::Adc),
            12 => Some(Self::Selector),
            13 => Some(Self::Lamp),
            14 => Some(Self::Rail),
            15 => Some(Self::Boot),
            16 => Some(Self::Agreement),
            _ => None,
        }
    }

    /// How long the task may go without checking in before the feed is
    /// withheld. Generous next to each task's own period: this catches a
    /// hang, not jitter, and a window that is too tight resets a healthy
    /// controller at an unattended site.
    #[must_use]
    pub const fn window(self) -> Millis {
        let millis = match self {
            Self::Supervisor | Self::Control | Self::Selector | Self::Lamp => 5_000,
            // The agreement's longest job, a `Hello`, measured 2.46 s on
            // board A; ten covers it and a check-in either side.
            Self::Link
            | Self::Rs485One
            | Self::Rs485Two
            | Self::Rs485Three
            | Self::Can
            | Self::Agreement => 10_000,
            Self::VeDirectOne | Self::VeDirectTwo | Self::Adc => 15_000,
            Self::Recorder | Self::OneWire | Self::Rail => 30_000,
            Self::Boot => 3_000,
        };
        Millis::from_millis(millis)
    }
}

/// Whether the next feed has been earned.
///
/// Three answers and not two, because *nothing is on the roll* is not
/// health: a firmware that started nothing would otherwise feed forever on
/// an empty table, which is the timer-fed watchdog wearing a different hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "discarding this feeds the part unconditionally, which is the bug this exists to prevent"]
pub enum Feed {
    /// Every task on the roll has checked in inside its window.
    Earned,
    /// One has not. The name is the point: this is what the supervisor
    /// writes to the last words before it stops feeding.
    Withheld(Blame),
    /// No task has started. Not health, and not starvation either.
    NobodyOnTheRoll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Answer {
    /// Not started, or retired: not waited for.
    Off,
    /// When it last checked in.
    At(Tick),
}

/// The roll: when each task last checked in.
///
/// A task is on the roll from its first check-in, which the adapter makes
/// right before it spawns the task, so there is no *never reported* state
/// that has to read as either healthy, a task that never ran fed forever,
/// or starving, a reset before the first task gets a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Rollcall {
    answers: [Answer; TASKS],
}

impl Default for Rollcall {
    fn default() -> Self {
        Self::new()
    }
}

impl Rollcall {
    /// Nobody on the roll yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            answers: [Answer::Off; TASKS],
        }
    }

    /// A task has completed one pass of its work, or is about to start.
    pub fn check_in(&mut self, task: Task, now: Tick) {
        if let Some(answer) = self.answers.get_mut(task.slot()) {
            *answer = Answer::At(now);
        }
    }

    /// A task that will never run, because its peripheral would not
    /// configure, stops being waited for. What it owned reports the fault
    /// itself; a hang is what the watchdog is for, and this is not one.
    pub fn retire(&mut self, task: Task) {
        if let Some(answer) = self.answers.get_mut(task.slot()) {
            *answer = Answer::Off;
        }
    }

    /// May the part be fed at `now`? The first task on the roll that is past
    /// its window is the one named.
    pub fn verdict(&self, now: Tick) -> Feed {
        let mut anyone = false;
        for task in Task::ALL {
            let Some(Answer::At(last)) = self.answers.get(task.slot()) else {
                continue;
            };
            anyone = true;
            // A tick never runs backwards; a last check-in after `now` is
            // the same boot's future, which cannot be late.
            let Some(silent) = now.since(*last) else {
                continue;
            };
            if silent > task.window() {
                let overdue = Millis::from_millis(
                    silent.as_millis().saturating_sub(task.window().as_millis()),
                );
                return Feed::Withheld(Blame { task, overdue });
            }
        }
        if anyone {
            Feed::Earned
        } else {
            Feed::NobodyOnTheRoll
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(millis: u64) -> Tick {
        Tick::from_millis(millis)
    }

    #[test]
    fn f_007_the_feed_is_earned_only_while_every_task_on_the_roll_is_inside_its_window() {
        let mut roll = Rollcall::new();
        roll.check_in(Task::Supervisor, at(0));
        roll.check_in(Task::OneWire, at(0));
        assert_eq!(roll.verdict(at(4_000)), Feed::Earned);
        // The supervisor's window is 5 s; at exactly 5 s it is still inside.
        assert_eq!(roll.verdict(at(5_000)), Feed::Earned);
        // One millisecond past it, the feed is withheld and the name is
        // the supervisor's, with how far past the window it is.
        assert_eq!(
            roll.verdict(at(5_001)),
            Feed::Withheld(Blame {
                task: Task::Supervisor,
                overdue: Millis::from_millis(1),
            })
        );
        // A check-in earns it back.
        roll.check_in(Task::Supervisor, at(5_001));
        assert_eq!(roll.verdict(at(5_001)), Feed::Earned);
    }

    #[test]
    fn f_007_the_first_late_task_on_the_roll_is_the_one_named() {
        let mut roll = Rollcall::new();
        roll.check_in(Task::Control, at(0));
        roll.check_in(Task::Adc, at(0));
        // Both late: Control (5 s) and Adc (15 s). Control comes first.
        assert_eq!(
            roll.verdict(at(20_000)),
            Feed::Withheld(Blame {
                task: Task::Control,
                overdue: Millis::from_millis(15_000),
            })
        );
        // Only Adc late, once Control has checked in.
        roll.check_in(Task::Control, at(20_000));
        assert_eq!(
            roll.verdict(at(20_000)),
            Feed::Withheld(Blame {
                task: Task::Adc,
                overdue: Millis::from_millis(5_000),
            })
        );
    }

    #[test]
    fn f_007_nobody_on_the_roll_is_not_health() {
        let roll = Rollcall::new();
        assert_eq!(roll.verdict(at(0)), Feed::NobodyOnTheRoll);
        assert_eq!(roll.verdict(at(1_000_000)), Feed::NobodyOnTheRoll);
        let mut retired = Rollcall::new();
        retired.check_in(Task::Can, at(0));
        retired.retire(Task::Can);
        assert_eq!(retired.verdict(at(60_000)), Feed::NobodyOnTheRoll);
    }

    #[test]
    fn f_007_a_retired_task_is_not_waited_for_and_a_returning_one_is() {
        let mut roll = Rollcall::new();
        roll.check_in(Task::Supervisor, at(0));
        roll.check_in(Task::VeDirectOne, at(0));
        roll.retire(Task::VeDirectOne);
        roll.check_in(Task::Supervisor, at(30_000));
        assert_eq!(roll.verdict(at(30_000)), Feed::Earned);
        // A port that came back is on the roll again from that moment.
        roll.check_in(Task::VeDirectOne, at(30_000));
        roll.check_in(Task::Supervisor, at(46_000));
        assert_eq!(
            roll.verdict(at(46_000)),
            Feed::Withheld(Blame {
                task: Task::VeDirectOne,
                overdue: Millis::from_millis(1_000),
            })
        );
    }

    #[test]
    fn a_check_in_from_the_future_is_not_late() {
        let mut roll = Rollcall::new();
        roll.check_in(Task::Lamp, at(10_000));
        assert_eq!(roll.verdict(at(9_000)), Feed::Earned);
    }

    #[test]
    fn every_task_has_a_window_and_survives_the_round_trip_through_its_index() {
        for task in Task::ALL {
            assert!(task.window() > Millis::ZERO, "{task:?}");
            assert_eq!(Task::from_index(task.index()), Some(task));
        }
        assert_eq!(Task::from_index(u32::try_from(TASKS).expect("fits")), None);
    }
}
