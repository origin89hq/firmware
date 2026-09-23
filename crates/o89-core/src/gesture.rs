//! Physical authorisation on the selector (F-040, P-066, P-117.1).
//!
//! Start in Off for two seconds. Make three excursions, returning through
//! Off each time: Auto/Auto/Auto opens pairing, Manual/Manual/Manual arms
//! the floor override, Auto/Manual/Auto resets. Hold each outer position
//! for at least 300 ms and complete each leg within three seconds. Finish
//! in Off for two seconds (pairing/override) or ten seconds (reset).
//! Samples must arrive within 100 ms; a gap or invalid contact cancels the
//! gesture. Debounce requires 50 ms of unchanged samples. No sequence is a
//! prefix of another, and a completed sequence produces exactly one event.

use crate::{Millis, Tick};

/// Stable time required before accepting a selector position.
pub const SELECTOR_DEBOUNCE: Millis = Millis::from_millis(50);
/// Longest permitted interval between samples; a missed interval cancels intent.
pub const SELECTOR_SAMPLE_LIMIT: Millis = Millis::from_millis(100);
const ARM: Millis = Millis::from_millis(2_000);
const DWELL: Millis = Millis::from_millis(300);
const LEG: Millis = Millis::from_millis(3_000);
const RESET_HOLD: Millis = Millis::from_millis(10_000);
/// P-066's window, measured on the monotonic tick.
pub const PAIRING_WINDOW: Millis = Millis::from_millis(120_000);

/// A selector position. Conflicting contacts are represented by `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SelectorPosition {
    /// Automatic control may be considered by the control policy.
    Auto,
    /// No generator command is permitted.
    Off,
    /// The operator controls the equipment.
    Manual,
}

impl SelectorPosition {
    /// Pulled-up contacts: neither closed is Off; both closed is invalid.
    #[must_use]
    pub const fn from_contacts(auto_high: bool, manual_high: bool) -> Option<Self> {
        match (auto_high, manual_high) {
            (true, true) => Some(Self::Off),
            (false, true) => Some(Self::Auto),
            (true, false) => Some(Self::Manual),
            (false, false) => None,
        }
    }
}

/// One completed physical act. These never grant two permissions at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Gesture {
    /// Open enrolment for 120 seconds.
    Pairing,
    /// Arm a single floor-crossing time write while Off remains held.
    FloorOverride,
    /// Advance the epoch before clearing enrolments.
    FactoryReset,
}

#[derive(Debug, Clone, Copy)]
enum Stage {
    Idle,
    Armed,
    First(SelectorPosition),
    FirstOff(SelectorPosition),
    Second(Gesture),
    SecondOff(Gesture),
    Third(Gesture),
    Confirm(Gesture),
    Spent,
}

/// Fixed-size recognizer; owns no output or persistence.
#[derive(Debug, Clone, Copy)]
pub struct SelectorGestures {
    last: Option<Tick>,
    candidate: Option<(SelectorPosition, Tick)>,
    stable: Option<SelectorPosition>,
    stage: Stage,
    since: Tick,
}

impl Default for SelectorGestures {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectorGestures {
    /// Boot carries no physical permission, even with a contact held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: None,
            candidate: None,
            stable: None,
            stage: Stage::Idle,
            since: Tick::ZERO,
        }
    }

    /// Debounced position, or unknown while the input is changing or invalid.
    #[must_use]
    pub const fn position(&self) -> Option<SelectorPosition> {
        self.stable
    }

    /// Sample once. Invalid input and stale or reversed time cancel progress.
    pub fn sample(&mut self, position: Option<SelectorPosition>, now: Tick) -> Option<Gesture> {
        if self.last.is_some_and(|last| {
            now.since(last)
                .is_none_or(|gap| gap > SELECTOR_SAMPLE_LIMIT)
        }) {
            *self = Self::new();
        }
        self.last = Some(now);
        let Some(position) = position else {
            self.candidate = None;
            self.stable = None;
            self.stage = Stage::Idle;
            self.since = now;
            return None;
        };
        let candidate_since = match self.candidate {
            Some((candidate, since)) if candidate == position => since,
            Some(_) | None => {
                if matches!(self.stage, Stage::Idle | Stage::Confirm(_)) {
                    self.since = now;
                }
                self.candidate = Some((position, now));
                self.stable = None;
                return None;
            }
        };
        if now
            .since(candidate_since)
            .is_none_or(|age| age < SELECTOR_DEBOUNCE)
        {
            return None;
        }
        self.stable = Some(position);
        let elapsed = now.since(self.since)?;
        let (stage, event) = self.advance(position, elapsed);
        if let Some(stage) = stage {
            self.stage = stage;
            self.since = now;
        }
        event
    }

    fn confirm(
        gesture: Gesture,
        position: SelectorPosition,
        elapsed: Millis,
    ) -> (Option<Stage>, Option<Gesture>) {
        if position != SelectorPosition::Off {
            return (Some(Stage::Idle), None);
        }
        let hold = match gesture {
            Gesture::Pairing | Gesture::FloorOverride => ARM,
            Gesture::FactoryReset => RESET_HOLD,
        };
        if elapsed >= hold {
            (Some(Stage::Spent), Some(gesture))
        } else {
            (None, None)
        }
    }

    fn advance(
        &self,
        position: SelectorPosition,
        elapsed: Millis,
    ) -> (Option<Stage>, Option<Gesture>) {
        use SelectorPosition::{Auto, Manual, Off};
        let cancel = (Some(Stage::Idle), None);
        let next = match self.stage {
            Stage::Idle => {
                if position != Off {
                    return cancel;
                }
                if elapsed >= ARM {
                    Some(Stage::Armed)
                } else {
                    None
                }
            }
            Stage::Armed => match position {
                Off => None,
                Auto | Manual => Some(Stage::First(position)),
            },
            Stage::First(first) => {
                if elapsed > LEG {
                    return cancel;
                }
                if position == first {
                    None
                } else if position == Off && elapsed >= DWELL {
                    Some(Stage::FirstOff(first))
                } else {
                    return cancel;
                }
            }
            Stage::FirstOff(first) => {
                if elapsed > LEG {
                    return cancel;
                }
                match (first, position) {
                    (Auto | Manual | Off, Off) => None,
                    (Auto, Auto) => Some(Stage::Second(Gesture::Pairing)),
                    (Auto, Manual) => Some(Stage::Second(Gesture::FactoryReset)),
                    (Manual, Manual) => Some(Stage::Second(Gesture::FloorOverride)),
                    (Manual | Off, Auto) | (Off, Manual) => return cancel,
                }
            }
            Stage::Second(gesture) | Stage::Third(gesture) => {
                if elapsed > LEG {
                    return cancel;
                }
                let expected = match gesture {
                    Gesture::Pairing => Auto,
                    Gesture::FloorOverride => Manual,
                    Gesture::FactoryReset => {
                        if matches!(self.stage, Stage::Second(_)) {
                            Manual
                        } else {
                            Auto
                        }
                    }
                };
                if position == expected {
                    None
                } else if position == Off && elapsed >= DWELL {
                    match self.stage {
                        Stage::Second(_) => Some(Stage::SecondOff(gesture)),
                        Stage::Third(_) => Some(Stage::Confirm(gesture)),
                        Stage::Idle
                        | Stage::Armed
                        | Stage::First(_)
                        | Stage::FirstOff(_)
                        | Stage::SecondOff(_)
                        | Stage::Confirm(_)
                        | Stage::Spent => return cancel,
                    }
                } else {
                    return cancel;
                }
            }
            Stage::SecondOff(gesture) => {
                if elapsed > LEG {
                    return cancel;
                }
                let expected = match gesture {
                    Gesture::Pairing | Gesture::FactoryReset => Auto,
                    Gesture::FloorOverride => Manual,
                };
                if position == Off {
                    None
                } else if position == expected {
                    Some(Stage::Third(gesture))
                } else {
                    return cancel;
                }
            }
            Stage::Confirm(gesture) => return Self::confirm(gesture, position, elapsed),
            Stage::Spent => {
                if position == Off {
                    None
                } else {
                    return cancel;
                }
            }
        };
        (next, None)
    }
}

/// Expiring enrolment permission. Only a completed pairing gesture opens it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PairingWindow {
    opened: Option<Tick>,
}

impl PairingWindow {
    /// Closed at every boot.
    #[must_use]
    pub const fn new() -> Self {
        Self { opened: None }
    }

    /// Apply one physical act; reset closes a previously open window.
    pub fn gesture(&mut self, gesture: Gesture, now: Tick) {
        match gesture {
            Gesture::Pairing => self.opened = Some(now),
            Gesture::FloorOverride => {}
            Gesture::FactoryReset => self.close(),
        }
    }

    /// Test at the instant an operation is processed, never from a cached flag.
    #[must_use]
    pub fn is_open(&self, now: Tick) -> bool {
        self.opened
            .and_then(|opened| now.since(opened))
            .is_some_and(|age| age < PAIRING_WINDOW)
    }

    /// Close on reset or a persistence fault.
    pub fn close(&mut self) {
        self.opened = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SelectorPosition::{Auto, Manual, Off};

    struct Hand {
        gestures: SelectorGestures,
        now: u64,
        events: [Option<Gesture>; 4],
        count: usize,
    }

    impl Hand {
        fn new() -> Self {
            Self {
                gestures: SelectorGestures::new(),
                now: 50_000,
                events: [None; 4],
                count: 0,
            }
        }

        fn hold(&mut self, position: Option<SelectorPosition>, ms: u64) {
            for _ in 0..ms / 10 {
                if let Some(event) = self.gestures.sample(position, Tick::from_millis(self.now)) {
                    self.events[self.count] = Some(event);
                    self.count = self.count.checked_add(1).expect("bounded events");
                }
                self.now = self.now.checked_add(10).expect("test time fits");
            }
        }

        fn sequence(&mut self, positions: [SelectorPosition; 3]) {
            self.hold(Some(Off), 2_100);
            for position in positions {
                self.hold(Some(position), 500);
                self.hold(Some(Off), 200);
            }
        }
    }

    #[test]
    fn f_053_contact_truth_table_keeps_conflict_unknown() {
        assert_eq!(SelectorPosition::from_contacts(true, true), Some(Off));
        assert_eq!(SelectorPosition::from_contacts(false, true), Some(Auto));
        assert_eq!(SelectorPosition::from_contacts(true, false), Some(Manual));
        assert_eq!(SelectorPosition::from_contacts(false, false), None);
    }

    #[test]
    fn p_117_1_each_sequence_emits_only_its_own_gesture_once() {
        for (positions, expected) in [
            ([Auto, Auto, Auto], Gesture::Pairing),
            ([Manual, Manual, Manual], Gesture::FloorOverride),
            ([Auto, Manual, Auto], Gesture::FactoryReset),
        ] {
            let mut hand = Hand::new();
            hand.sequence(positions);
            hand.hold(Some(Off), 130_000);
            assert_eq!(hand.count, 1);
            assert_eq!(hand.events[0], Some(expected));
        }
    }

    #[test]
    fn f_040_every_other_three_excursion_sequence_is_refused() {
        for positions in [
            [Auto, Auto, Manual],
            [Auto, Manual, Manual],
            [Manual, Auto, Auto],
            [Manual, Auto, Manual],
            [Manual, Manual, Auto],
        ] {
            let mut hand = Hand::new();
            hand.sequence(positions);
            hand.hold(Some(Off), 11_000);
            assert_eq!(hand.count, 0, "{positions:?}");
        }
    }

    #[test]
    fn f_040_reset_waits_ten_seconds_and_never_opens_pairing_first() {
        let mut hand = Hand::new();
        hand.sequence([Auto, Manual, Auto]);
        let since = hand.gestures.since.as_millis();
        hand.hold(Some(Off), 9_000);
        assert_eq!(hand.count, 0);
        hand.hold(Some(Off), since + 10_000 - hand.now);
        assert_eq!(hand.count, 0);
        hand.hold(Some(Off), 10);
        assert_eq!(hand.events[0], Some(Gesture::FactoryReset));
    }

    #[test]
    fn f_053_bounce_does_not_supply_an_excursion_or_bypass_the_final_hold() {
        let mut hand = Hand::new();
        hand.hold(Some(Off), 2_100);
        for _ in 0..3 {
            hand.hold(Some(Auto), 40);
            hand.hold(Some(Off), 100);
        }
        hand.hold(Some(Off), 11_000);
        assert_eq!(hand.count, 0);
        hand.sequence([Auto, Auto, Auto]);
        hand.hold(Some(Off), 1_700);
        hand.hold(Some(Auto), 10);
        hand.hold(Some(Off), 1_990);
        assert_eq!(hand.count, 0);
        hand.hold(Some(Off), 20);
        assert_eq!(hand.events[0], Some(Gesture::Pairing));
    }

    #[test]
    fn f_040_gap_conflict_reverse_time_and_missing_off_cancel_intent() {
        for fault in 0..4 {
            let mut hand = Hand::new();
            hand.sequence([Auto, Auto, Auto]);
            match fault {
                0 => hand.now += 101,
                1 => hand.hold(None, 10),
                2 => hand.now -= 1_000,
                3 => hand.hold(Some(Manual), 100),
                _ => panic!("unknown test fault"),
            }
            hand.hold(Some(Off), 11_000);
            assert_eq!(hand.count, 0);
        }
        let mut hand = Hand::new();
        hand.hold(Some(Off), 2_100);
        hand.hold(Some(Auto), 500);
        hand.hold(Some(Manual), 500);
        hand.hold(Some(Off), 11_000);
        assert_eq!(hand.count, 0);
    }

    #[test]
    fn f_040_short_detent_and_expired_leg_are_refused_and_can_recover() {
        for dwell in [100, 3_100] {
            let mut hand = Hand::new();
            hand.hold(Some(Off), 2_100);
            hand.hold(Some(Auto), dwell);
            hand.hold(Some(Off), 200);
            for _ in 0..2 {
                hand.hold(Some(Auto), 500);
                hand.hold(Some(Off), 200);
            }
            hand.hold(Some(Off), 11_000);
            assert_eq!(hand.count, 0);
            hand.sequence([Auto, Auto, Auto]);
            hand.hold(Some(Off), 2_100);
            assert_eq!(hand.events[0], Some(Gesture::Pairing));
        }
    }

    #[test]
    fn p_066_window_expires_at_120_seconds_and_boot_is_closed() {
        let mut window = PairingWindow::new();
        assert!(!window.is_open(Tick::ZERO));
        let start = Tick::from_millis(5_000);
        window.gesture(Gesture::FloorOverride, start);
        assert!(!window.is_open(start));
        window.gesture(Gesture::Pairing, start);
        assert!(window.is_open(start));
        assert!(!window.is_open(Tick::from_millis(4_999)));
        assert!(window.is_open(Tick::from_millis(124_999)));
        assert!(!window.is_open(Tick::from_millis(125_000)));
        window.gesture(Gesture::Pairing, Tick::from_millis(u64::MAX - 1));
        assert!(window.is_open(Tick::from_millis(u64::MAX)));
        window.gesture(Gesture::FactoryReset, Tick::from_millis(u64::MAX));
        assert!(!window.is_open(Tick::from_millis(u64::MAX)));
    }
}

/// Permissions held by the physical panel. Reset failures block enrolment
/// until a later reset succeeds; time permission is consumed only by an
/// accepted floor-crossing write, never by a refused request.
#[derive(Debug, Clone, Copy)]
pub struct Panel {
    recognizer: SelectorGestures,
    window: PairingWindow,
    floor: Option<Tick>,
    reset_blocked: bool,
}

impl Default for Panel {
    fn default() -> Self {
        Self::new()
    }
}

impl Panel {
    /// No permission survives boot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recognizer: SelectorGestures::new(),
            window: PairingWindow::new(),
            floor: None,
            reset_blocked: false,
        }
    }

    /// Read the panel. Raw departure from Off releases a floor override,
    /// even before debounce; missing samples also release it.
    pub fn sample(&mut self, position: Option<SelectorPosition>, now: Tick) -> Option<Gesture> {
        if position != Some(SelectorPosition::Off)
            || self.recognizer.last.is_none_or(|last| {
                now.since(last)
                    .is_none_or(|age| age > SELECTOR_SAMPLE_LIMIT)
            })
        {
            self.floor = None;
        }
        let gesture = self.recognizer.sample(position, now)?;
        match gesture {
            Gesture::Pairing => {
                if !self.reset_blocked {
                    self.window.gesture(gesture, now);
                }
            }
            Gesture::FloorOverride => self.floor = Some(now),
            Gesture::FactoryReset => {
                self.reset_blocked = true;
                self.window.close();
                self.floor = None;
            }
        }
        Some(gesture)
    }

    /// Window state at the moment of processing a Pair.
    #[must_use]
    pub fn pairing_open(&self, now: Tick) -> bool {
        !self.reset_blocked && self.window.is_open(now)
    }

    /// Permission at the moment a time operation is processed (P-117).
    #[must_use]
    pub fn floor_override(&self, now: Tick) -> bool {
        self.floor
            .and_then(|armed| now.since(armed))
            .is_some_and(|age| age < PAIRING_WINDOW)
            && self
                .recognizer
                .last
                .and_then(|last| now.since(last))
                .is_some_and(|age| age <= SELECTOR_SAMPLE_LIMIT)
    }

    /// Consume only after accepting a floor-crossing time write.
    pub fn floor_used(&mut self) {
        self.floor = None;
    }

    /// Persistence acknowledgement. Failure keeps enrolment blocked, and
    /// success still requires a new physical gesture to open its window.
    pub fn reset_finished(&mut self, succeeded: bool) {
        self.reset_blocked = !succeeded;
    }
}

#[cfg(test)]
mod panel_tests {
    use super::*;

    fn gesture(panel: &mut Panel, sequence: [SelectorPosition; 3], now: &mut u64) {
        let mut hold = |position, duration| {
            for _ in 0..duration / 10 {
                panel.sample(Some(position), Tick::from_millis(*now));
                *now = now.checked_add(10).expect("test time fits");
            }
        };
        hold(SelectorPosition::Off, 2_100);
        for position in sequence {
            hold(position, 500);
            hold(SelectorPosition::Off, 200);
        }
        hold(SelectorPosition::Off, 10_100);
    }

    #[test]
    fn p_117_pairing_never_arms_floor_and_floor_is_single_use() {
        use SelectorPosition::{Auto, Manual};
        let mut panel = Panel::new();
        let mut now = 0;
        gesture(&mut panel, [Auto; 3], &mut now);
        assert!(panel.pairing_open(Tick::from_millis(now)));
        assert!(!panel.floor_override(Tick::from_millis(now)));
        panel = Panel::new();
        gesture(&mut panel, [Manual; 3], &mut now);
        assert!(!panel.pairing_open(Tick::from_millis(now)));
        assert!(panel.floor_override(Tick::from_millis(now)));
        panel.floor_used();
        assert!(!panel.floor_override(Tick::from_millis(now)));
    }

    #[test]
    fn p_117_release_stale_input_and_timeout_remove_floor_permission() {
        for fault in 0..4 {
            let mut panel = Panel::new();
            let mut now = 0;
            gesture(&mut panel, [SelectorPosition::Manual; 3], &mut now);
            match fault {
                0 => {
                    panel.sample(Some(SelectorPosition::Auto), Tick::from_millis(now));
                }
                1 => {
                    panel.sample(None, Tick::from_millis(now));
                }
                2 => now += 101,
                3 => {
                    for _ in 0..12_000 {
                        panel.sample(Some(SelectorPosition::Off), Tick::from_millis(now));
                        now += 10;
                    }
                }
                _ => panic!("unknown test fault"),
            }
            assert!(!panel.floor_override(Tick::from_millis(now)));
        }
    }

    #[test]
    fn p_085_failed_reset_blocks_pairing_until_success_and_a_new_gesture() {
        use SelectorPosition::{Auto, Manual};
        let mut panel = Panel::new();
        let mut now = 0;
        gesture(&mut panel, [Auto, Manual, Auto], &mut now);
        panel.reset_finished(false);
        // Leave the spent gesture before beginning another.
        panel.sample(Some(Auto), Tick::from_millis(now));
        now += 110;
        gesture(&mut panel, [Auto; 3], &mut now);
        assert!(!panel.pairing_open(Tick::from_millis(now)));
        panel.reset_finished(true);
        assert!(!panel.pairing_open(Tick::from_millis(now)));
        now += 110;
        gesture(&mut panel, [Auto; 3], &mut now);
        assert!(panel.pairing_open(Tick::from_millis(now)));
    }
}
