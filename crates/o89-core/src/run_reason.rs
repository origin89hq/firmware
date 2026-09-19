//! Why the generator is running, written before the output moves.
//!
//! Power-on, watchdog and brown-out are three different situations, and a
//! generator that was running through one of them is a fourth. The run
//! reason in FRAM is what tells the boot which: an automatic start whose
//! condition still holds resumes inside board B's ride-through window, a
//! manual start is stopped deliberately, and a maximum run time backstops
//! both (F-061, M8). None of that is possible unless the reason was on the
//! part before the contact closed, so it is written on every start and
//! every stop, before the output moves (F-022).
//!
//! That order is a type here. The output driver moves the contact on a
//! [`Declared`], and a `Declared` comes out of [`Kept::declare`] only after
//! the part has the reason.
//!
//! cites: F-022

use crate::body::{Body, Kept, Malformed, Reader, Writer};
use crate::fram::{Fram, Refused};
use crate::tick::UnixMillis;

/// The bytes the reason takes in its record.
pub const RUN_REASON_BYTES: usize = 16;

/// The behaviour that asked for the generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Behaviour {
    /// The generator behaviour: bank voltage or state of charge.
    Generator,
    /// Frost protection.
    Frost,
    /// The schedule.
    Schedule,
    /// Load shedding.
    LoadShed,
}

impl Behaviour {
    const fn code(self) -> u8 {
        match self {
            Self::Generator => 1,
            Self::Frost => 2,
            Self::Schedule => 3,
            Self::LoadShed => 4,
        }
    }

    const fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Generator),
            2 => Some(Self::Frost),
            3 => Some(Self::Schedule),
            4 => Some(Self::LoadShed),
            _ => None,
        }
    }
}

/// Whose decision the start was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartKind {
    /// A person, at the selector or over a command.
    Manual,
    /// A behaviour whose condition held.
    Automatic(Behaviour),
}

/// A run in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Running {
    /// Whose decision it was.
    pub kind: StartKind,
    /// When it started on the wall clock, if a clock was set; the backstop
    /// on a run that outlives a reset is measured from here.
    pub started: Option<UnixMillis>,
}

/// What the generator is doing, as the part holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RunReason {
    /// The contact is open, on purpose.
    Stopped,
    /// The contact is closed, and this is why.
    Running(Running),
}

const STOPPED: u8 = 0;
const RUNNING: u8 = 1;
const NONE: u8 = 0;
const MANUAL: u8 = 1;
const AUTOMATIC: u8 = 2;

impl Body<RUN_REASON_BYTES> for RunReason {
    fn encode(&self) -> [u8; RUN_REASON_BYTES] {
        let mut out = [0u8; RUN_REASON_BYTES];
        let mut writer = Writer::over(&mut out);
        match self {
            Self::Stopped => {
                writer.u8(STOPPED);
            }
            Self::Running(running) => {
                writer.u8(RUNNING);
                match running.kind {
                    StartKind::Manual => {
                        writer.u8(MANUAL);
                        writer.u8(NONE);
                    }
                    StartKind::Automatic(behaviour) => {
                        writer.u8(AUTOMATIC);
                        writer.u8(behaviour.code());
                    }
                }
                writer.skip(5);
                writer.u64(running.started.map_or(0, UnixMillis::as_millis));
            }
        }
        out
    }

    fn decode(bytes: &[u8; RUN_REASON_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let state = reader.u8()?;
        if state == STOPPED {
            return Ok(Self::Stopped);
        }
        if state != RUNNING {
            return Err(reader.malformed(1));
        }
        let kind = reader.u8()?;
        let behaviour = reader.u8()?;
        let kind = match kind {
            MANUAL if behaviour == NONE => StartKind::Manual,
            MANUAL => return Err(reader.malformed(1)),
            AUTOMATIC => StartKind::Automatic(Behaviour::of(behaviour).ok_or(reader.malformed(1))?),
            _ => return Err(reader.malformed(2)),
        };
        reader.skip(5);
        let started = UnixMillis::new(reader.u64()?);
        Ok(Self::Running(Running { kind, started }))
    }
}

/// A reason the part holds, which is the only thing the output moves on.
/// There is no public constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a reason declared and not acted on is a contact left where it was"]
pub struct Declared {
    reason: RunReason,
}

impl Declared {
    /// The reason the part holds, and so the state the output may take.
    #[must_use]
    pub const fn reason(&self) -> RunReason {
        self.reason
    }
}

impl Kept<RunReason, RUN_REASON_BYTES> {
    /// Write `reason` and, once the part has it, hand out the permission
    /// to move the output to it. A write that is refused moves nothing.
    pub async fn declare<F: Fram>(
        &mut self,
        fram: &mut F,
        reason: RunReason,
    ) -> Result<Declared, Refused<F::Error>> {
        self.write(fram, reason).await?;
        Ok(Declared { reason })
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;

    use super::*;
    use crate::fram::Address;
    use crate::map::RUN_REASON;

    struct Part {
        bytes: [u8; 512],
        falling: bool,
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            let start = usize::from(at.0);
            into.copy_from_slice(&self.bytes[start..][..into.len()]);
            core::future::ready(Ok(()))
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            let outcome = if self.falling {
                Err(Refused::SupplyFalling)
            } else {
                let start = usize::from(at.0);
                self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
                Ok(())
            };
            core::future::ready(outcome)
        }
    }

    fn part() -> Part {
        Part {
            bytes: [0; 512],
            falling: false,
        }
    }

    fn automatic() -> RunReason {
        RunReason::Running(Running {
            kind: StartKind::Automatic(Behaviour::Frost),
            started: UnixMillis::new(1_790_000_000_000),
        })
    }

    #[test]
    fn f_022_the_output_moves_only_on_a_reason_the_part_holds() {
        let mut part = part();
        let mut kept = block_on(Kept::<RunReason, RUN_REASON_BYTES>::read(
            RUN_REASON, &mut part,
        ))
        .expect("reads");
        let declared = block_on(kept.declare(&mut part, automatic())).expect("the supply is fine");
        assert_eq!(declared.reason(), automatic());
        let found = block_on(Kept::<RunReason, RUN_REASON_BYTES>::read(
            RUN_REASON, &mut part,
        ))
        .expect("reads");
        assert_eq!(found.present(), Some(&automatic()));
        // A stop is declared the same way.
        let stopped =
            block_on(kept.declare(&mut part, RunReason::Stopped)).expect("the supply is fine");
        assert_eq!(stopped.reason(), RunReason::Stopped);
    }

    #[test]
    fn f_022_a_write_that_is_refused_declares_nothing() {
        let mut part = part();
        let mut kept = block_on(Kept::<RunReason, RUN_REASON_BYTES>::read(
            RUN_REASON, &mut part,
        ))
        .expect("reads");
        let _stopped =
            block_on(kept.declare(&mut part, RunReason::Stopped)).expect("the supply is fine");
        part.falling = true;
        assert_eq!(
            block_on(kept.declare(&mut part, automatic())),
            Err(Refused::SupplyFalling)
        );
        assert_eq!(kept.present(), Some(&RunReason::Stopped));
    }

    #[test]
    fn every_reason_survives_the_round_trip() {
        let reasons = [
            RunReason::Stopped,
            RunReason::Running(Running {
                kind: StartKind::Manual,
                started: None,
            }),
            automatic(),
            RunReason::Running(Running {
                kind: StartKind::Automatic(Behaviour::LoadShed),
                started: None,
            }),
        ];
        for reason in reasons {
            assert_eq!(
                RunReason::decode(&reason.encode()),
                Ok(reason),
                "{reason:?}"
            );
        }
        assert_eq!(RunReason::Stopped.encode(), [0; RUN_REASON_BYTES]);
    }

    #[test]
    fn a_state_authority_or_behaviour_nobody_named_is_malformed() {
        let mut state = automatic().encode();
        state[0] = 2;
        assert_eq!(RunReason::decode(&state), Err(Malformed { at: 0 }));
        let mut kind = automatic().encode();
        kind[1] = 3;
        assert_eq!(RunReason::decode(&kind), Err(Malformed { at: 1 }));
        let mut behaviour = automatic().encode();
        behaviour[2] = 5;
        assert_eq!(RunReason::decode(&behaviour), Err(Malformed { at: 2 }));
        // Manual with a behaviour named is two decisions at once.
        let mut both = automatic().encode();
        both[1] = 1;
        assert_eq!(RunReason::decode(&both), Err(Malformed { at: 2 }));
        // Running under nobody.
        let mut nobody = automatic().encode();
        nobody[1] = 0;
        nobody[2] = 0;
        assert_eq!(RunReason::decode(&nobody), Err(Malformed { at: 1 }));
    }
}
