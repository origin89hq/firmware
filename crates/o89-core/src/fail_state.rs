//! Every output declares its fail state, here, before it exists anywhere.
//!
//! What an output is at reset, through a brown-out, while the processor is
//! unresponsive and before firmware runs is not the same for a generator's
//! run contact and a heater, and the answer is not a default a misread
//! configuration falls into. This is the table `ARCHITECTURE.md`'s safety
//! architecture states; the adapter reads it and drives the pins, and a line
//! with no row here does not compile.
//!
//! cites: F-001, F-002, F-003, F-011

use crate::Revision;

/// An RS-485 bus, by the connector it leaves the board on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Bus {
    /// CN2: EPEver-class devices at 115200.
    One,
    /// CN3: the PZEM DC meters at 9600.
    Two,
    /// CN4: PZEM-016 and remote modules.
    Three,
}

/// A VE.Direct port, by connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Port {
    /// CN6.
    One,
    /// CN7.
    Two,
}

/// Every line the firmware drives, or deliberately does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Line {
    /// `RUN` to board B: the generator's maintained contact.
    Run,
    /// `KICK` to board B: the run-enable watchdog's feed.
    Kick,
    /// The transmit line of one RS-485 transceiver.
    Rs485Tx(Bus),
    /// The controller's transmit line into the module's UART0.
    ModuleTx,
    /// The controller's RTS into the module.
    ModuleRts,
    /// The module's `EN`.
    ModuleEn,
    /// The module's `BOOT` strap.
    ModuleBoot,
    /// The module's 3.3 V rail, `V3V3_ESP`.
    ModuleRail,
    /// The receive pull-up of one VE.Direct port.
    VeDirectPullUp(Port),
    /// The status and fault lamps, seen as one lamp.
    Lamp,
}

/// What a line is when nobody is deciding for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FailState {
    /// Driven low, push-pull.
    DrivenLow,
    /// Driven high, push-pull.
    DrivenHigh,
    /// An input, high-impedance, or driven low; never driven high.
    InputOrLow,
    /// On: the rail powers the module. L-114, and the reasons that hold are
    /// in `ARCHITECTURE.md`.
    On,
    /// Off: nothing is pulled up.
    Off,
    /// Whatever the board leaves it through reset; no hazard.
    LeftToTheBoard,
}

impl Line {
    /// The declared fail state of this line, the same on every revision the
    /// firmware supports: the board may fail to deliver it, which
    /// [`Revision`] reports, but the declaration does not move.
    #[must_use]
    pub const fn fail_state(self, revision: Revision) -> FailState {
        // Both revisions declare the same states; the parameter is here so
        // that a revision which changes one has to say so in this match.
        match (self, revision) {
            (Line::Run | Line::Kick, Revision::A | Revision::B) => FailState::DrivenLow,
            (Line::Rs485Tx(_), Revision::A | Revision::B) => FailState::DrivenHigh,
            (
                Line::ModuleTx | Line::ModuleRts | Line::ModuleEn | Line::ModuleBoot,
                Revision::A | Revision::B,
            ) => FailState::InputOrLow,
            (Line::ModuleRail, Revision::A | Revision::B) => FailState::On,
            (Line::VeDirectPullUp(_), Revision::A | Revision::B) => FailState::Off,
            (Line::Lamp, Revision::A | Revision::B) => FailState::LeftToTheBoard,
        }
    }
}

/// Whether a behaviour may drive an output yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Authority {
    /// Sense, evaluate and write down what would have been done; the output
    /// stays at its fail state and the hardware is never written.
    Shadow,
    /// The behaviour drives it. Granted one output at a time, and asked for.
    Granted,
}

impl Authority {
    /// What every output has when it arrives: nobody has asked yet.
    #[must_use]
    pub const fn at_boot() -> Self {
        Self::Shadow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_001_run_and_kick_are_driven_low_on_every_revision() {
        for revision in [Revision::A, Revision::B] {
            assert_eq!(Line::Run.fail_state(revision), FailState::DrivenLow);
            assert_eq!(Line::Kick.fail_state(revision), FailState::DrivenLow);
        }
    }

    #[test]
    fn f_002_every_rs485_transmit_line_idles_high() {
        for bus in [Bus::One, Bus::Two, Bus::Three] {
            assert_eq!(
                Line::Rs485Tx(bus).fail_state(Revision::A),
                FailState::DrivenHigh
            );
        }
    }

    #[test]
    fn f_003_no_line_into_the_module_is_ever_driven_high() {
        for line in [
            Line::ModuleTx,
            Line::ModuleRts,
            Line::ModuleEn,
            Line::ModuleBoot,
        ] {
            for revision in [Revision::A, Revision::B] {
                assert_eq!(line.fail_state(revision), FailState::InputOrLow);
                assert_ne!(line.fail_state(revision), FailState::DrivenHigh);
            }
        }
    }

    #[test]
    fn f_011_each_declaration_is_the_safety_architectures_and_authority_starts_in_shadow() {
        // That every line has a row is the compiler's: the match in
        // `fail_state` is exhaustive, so a new line without one does not
        // build. What a test adds is that each row says what the safety
        // architecture's table says, read line by line rather than through
        // a list a new variant could be left off.
        let architecture = [
            (Line::Run, FailState::DrivenLow),
            (Line::Kick, FailState::DrivenLow),
            (Line::Rs485Tx(Bus::One), FailState::DrivenHigh),
            (Line::Rs485Tx(Bus::Two), FailState::DrivenHigh),
            (Line::Rs485Tx(Bus::Three), FailState::DrivenHigh),
            (Line::ModuleTx, FailState::InputOrLow),
            (Line::ModuleRts, FailState::InputOrLow),
            (Line::ModuleEn, FailState::InputOrLow),
            (Line::ModuleBoot, FailState::InputOrLow),
            (Line::ModuleRail, FailState::On),
            (Line::VeDirectPullUp(Port::One), FailState::Off),
            (Line::VeDirectPullUp(Port::Two), FailState::Off),
            (Line::Lamp, FailState::LeftToTheBoard),
        ];
        for (line, declared) in architecture {
            for revision in [Revision::A, Revision::B] {
                assert_eq!(
                    line.fail_state(revision),
                    declared,
                    "{line:?} on revision {revision:?}"
                );
            }
        }
        assert_eq!(Authority::at_boot(), Authority::Shadow);
    }
}
