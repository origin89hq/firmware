//! A simulated FM24W256 whose power can be cut at any byte, and the harness
//! that cuts it at every one.
//!
//! The part lands a write one byte at a time, each acknowledged, so a power
//! cut mid-transaction leaves a prefix of the bytes and nothing else. The
//! step counter counts the bytes landed since the last power-up; a cut at
//! step k lands k bytes of whatever the path writes, then every bus
//! operation fails until the part is rebooted. The bytes survive the reboot,
//! as they do in the part, which is the whole point of FRAM and the whole
//! problem: what a boot finds is exactly what the cut left.
//!
//! cites: F-025

use core::future::Future;

use o89_core::{Address, FRAM_BYTES, Fram, Refused};

/// What the simulated bus reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimError {
    /// The power was cut; nothing answers until the part is rebooted.
    PowerLost,
    /// An address past the end of the part: a map that is wrong, which the
    /// map's own assertion should have caught first.
    OutOfRange,
}

/// The supply as the adapter's voltage detector would see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supply {
    /// Above the threshold: transactions may start.
    Steady,
    /// Below it: no transaction starts, one in flight completes.
    Falling,
}

/// The simulated part.
#[derive(Debug, Clone)]
pub struct SimFram {
    bytes: Vec<u8>,
    supply: Supply,
    /// Bytes landed since the last power-up.
    written: usize,
    /// The step at which the power is cut, if a cut is scheduled.
    cut_at: Option<usize>,
    dead: bool,
}

impl Default for SimFram {
    fn default() -> Self {
        Self::fresh()
    }
}

impl SimFram {
    /// A part out of the box: every byte zero.
    #[must_use]
    pub fn fresh() -> Self {
        Self {
            bytes: vec![0; FRAM_BYTES],
            supply: Supply::Steady,
            written: 0,
            cut_at: None,
            dead: false,
        }
    }

    /// Cut the power after `step` more bytes land. Zero cuts it before the
    /// next byte.
    pub fn cut_after(&mut self, step: usize) {
        self.cut_at = Some(step);
        self.written = 0;
    }

    /// Power back on: the bytes stay, the bus answers again, the step counter
    /// restarts, and no cut is scheduled.
    pub fn reboot(&mut self) {
        self.dead = false;
        self.written = 0;
        self.cut_at = None;
    }

    /// Whether the power is out.
    #[must_use]
    pub const fn is_dead(&self) -> bool {
        self.dead
    }

    /// Bytes landed since the last power-up.
    #[must_use]
    pub const fn bytes_written(&self) -> usize {
        self.written
    }

    /// What the supply reads.
    pub fn set_supply(&mut self, supply: Supply) {
        self.supply = supply;
    }

    /// The part's bytes, for an invariant that reads them directly.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn slot(&mut self, at: Address, len: usize) -> Result<&mut [u8], SimError> {
        let start = usize::from(at.0);
        let end = start.checked_add(len).ok_or(SimError::OutOfRange)?;
        self.bytes.get_mut(start..end).ok_or(SimError::OutOfRange)
    }
}

impl Fram for SimFram {
    type Error = SimError;

    fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), SimError>> {
        let outcome = if self.dead {
            Err(SimError::PowerLost)
        } else {
            self.slot(at, into.len())
                .map(|bytes| into.copy_from_slice(bytes))
        };
        core::future::ready(outcome)
    }

    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<SimError>>> {
        let outcome = if self.dead {
            Err(Refused::Bus(SimError::PowerLost))
        } else if self.supply == Supply::Falling {
            Err(Refused::SupplyFalling)
        } else {
            self.land(at, bytes)
        };
        core::future::ready(outcome)
    }
}

impl SimFram {
    /// Land `bytes` one at a time, cutting the power at the scheduled step.
    fn land(&mut self, at: Address, bytes: &[u8]) -> Result<(), Refused<SimError>> {
        let cut_at = self.cut_at;
        let mut written = self.written;
        let target = self.slot(at, bytes.len()).map_err(Refused::Bus)?;
        for (slot, byte) in target.iter_mut().zip(bytes) {
            if cut_at == Some(written) {
                self.written = written;
                self.dead = true;
                return Err(Refused::Bus(SimError::PowerLost));
            }
            *slot = *byte;
            written = written.saturating_add(1);
        }
        self.written = written;
        Ok(())
    }
}

/// What the harness found: how many steps the path takes uncut, and so how
/// many cuts it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a harness whose count nobody reads may have cut nothing"]
pub struct Crashes {
    /// The bytes the path lands when nothing cuts it, which is the number of
    /// cuts run: one before each byte.
    pub steps: usize,
}

/// Why the harness could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uncut {
    /// The path failed with no cut scheduled, so there is nothing to cut.
    PathFailed,
    /// The path landed nothing, so a cut could not change anything.
    NothingWritten,
}

/// Run `path` on a copy of `start` with nothing cut, to count its steps;
/// then, for every step, on a fresh copy with the power cut there, reboot
/// the part and hand it to `invariant` with the step it was cut at.
///
/// The path is expected to fail under a cut; what it returns then is not
/// judged, because a path that noticed the cut and one that did not both
/// leave the same bytes, and the bytes are what the invariant reads.
pub fn crash_at_every_step<P, I>(
    start: &SimFram,
    mut path: P,
    mut invariant: I,
) -> Result<Crashes, Uncut>
where
    P: FnMut(&mut SimFram) -> Result<(), ()>,
    I: FnMut(&mut SimFram, usize),
{
    let mut whole = start.clone();
    whole.reboot();
    path(&mut whole).map_err(|()| Uncut::PathFailed)?;
    let steps = whole.bytes_written();
    if steps == 0 {
        return Err(Uncut::NothingWritten);
    }
    for step in 0..steps {
        let mut cut = start.clone();
        cut.reboot();
        cut.cut_after(step);
        let _ = path(&mut cut);
        cut.reboot();
        invariant(&mut cut, step);
    }
    Ok(Crashes { steps })
}

#[cfg(test)]
mod tests {
    use embassy_futures::block_on;
    use o89_core::{Current, Record, Slot};

    use super::*;

    const COUNTER: Record<4> = Record::at(0x5453_4554, Address(64));

    /// The part with one record written, which every write path here
    /// starts from.
    fn with_one_record() -> (SimFram, Current<4>) {
        let mut part = SimFram::fresh();
        let current = block_on(COUNTER.write(&mut part, &Current::Empty, &1u32.to_le_bytes()))
            .expect("the supply is steady")
            .current;
        (part, current)
    }

    #[test]
    fn f_025_every_cut_of_a_record_write_leaves_the_previous_or_the_new_record() {
        let (start, first) = with_one_record();
        let crashes = crash_at_every_step(
            &start,
            |part| {
                block_on(COUNTER.write(part, &first, &2u32.to_le_bytes()))
                    .map(|_| ())
                    .map_err(|_| ())
            },
            |part, step| {
                let found = block_on(COUNTER.read(part)).expect("the part is back");
                match found {
                    Current::Valid { seq: 1, body, .. } => assert_eq!(body, 1u32.to_le_bytes()),
                    Current::Valid { seq: 2, body, .. } => assert_eq!(body, 2u32.to_le_bytes()),
                    other => panic!("cut at {step}: {other:?} is neither record"),
                }
            },
        )
        .expect("the path runs uncut");
        // A 4-byte body: 8 bytes of head, 4 of body, 4 of CRC.
        assert_eq!(crashes.steps, 16);
    }

    #[test]
    fn f_025_a_cut_before_the_crc_leaves_the_first_record_and_only_the_last_byte_flips_it() {
        let (start, first) = with_one_record();
        let crashes = crash_at_every_step(
            &start,
            |part| {
                block_on(COUNTER.write(part, &first, &2u32.to_le_bytes()))
                    .map(|_| ())
                    .map_err(|_| ())
            },
            |part, step| {
                let found = block_on(COUNTER.read(part)).expect("the part is back");
                // Sixteen bytes; the cut is before byte `step`, so only a cut
                // that let all sixteen land is the new record, and that one
                // is not in the loop: every cut keeps the first.
                assert_eq!(found, first, "cut before byte {step}");
            },
        )
        .expect("the path runs uncut");
        assert_eq!(crashes.steps, 16);
    }

    #[test]
    fn the_2026_09_16_loss_is_reproduced_in_place_and_gone_across_slots() {
        // The old firmware updated its counter slot in place. Cut anywhere
        // inside the write, the only copy is half old and half new, its CRC
        // matches neither, and the counter is gone: a client's replay is
        // accepted and a start happens twice.
        let (start, first) = with_one_record();
        let in_place = |part: &mut SimFram| -> Result<(), ()> {
            // The same bytes the record would write, over slot A itself.
            let mut scratch = SimFram::fresh();
            let _ = block_on(COUNTER.write(&mut scratch, &Current::Empty, &2u32.to_le_bytes()));
            let image: Vec<u8> = scratch.bytes()[64..80].to_vec();
            block_on(part.write(Address(64), &image)).map_err(|_| ())
        };
        let mut lost = 0;
        let in_place_cuts = crash_at_every_step(&start, in_place, |part, _| {
            if block_on(COUNTER.read(part)) != Ok(first) {
                lost += 1;
            }
        })
        .expect("the path runs uncut");
        assert_eq!(in_place_cuts.steps, 16);
        assert!(
            lost > 0,
            "the in-place write survived every cut, which the bench says it does not"
        );

        // Across slots, the first record stays in effect under every cut.
        let mut lost = 0;
        let across_slots = crash_at_every_step(
            &start,
            |part| {
                block_on(COUNTER.write(part, &first, &2u32.to_le_bytes()))
                    .map(|_| ())
                    .map_err(|_| ())
            },
            |part, _| {
                if block_on(COUNTER.read(part)) != Ok(first) {
                    lost += 1;
                }
            },
        )
        .expect("the path runs uncut");
        assert_eq!(across_slots.steps, in_place_cuts.steps);
        assert_eq!(lost, 0);
        assert_eq!(
            first,
            Current::Valid {
                seq: 1,
                body: 1u32.to_le_bytes(),
                slot: Slot::A
            }
        );
    }

    #[test]
    fn a_falling_supply_refuses_and_a_dead_part_answers_nothing() {
        let (mut part, first) = with_one_record();
        part.set_supply(Supply::Falling);
        assert_eq!(
            block_on(COUNTER.write(&mut part, &first, &2u32.to_le_bytes())),
            Err(Refused::SupplyFalling)
        );
        part.set_supply(Supply::Steady);
        part.cut_after(0);
        assert_eq!(
            block_on(COUNTER.write(&mut part, &first, &2u32.to_le_bytes())),
            Err(Refused::Bus(SimError::PowerLost))
        );
        assert!(part.is_dead());
        let mut byte = [0u8; 1];
        assert_eq!(
            block_on(part.read(Address(0), &mut byte)),
            Err(SimError::PowerLost)
        );
        part.reboot();
        assert_eq!(block_on(COUNTER.read(&mut part)), Ok(first));
    }

    #[test]
    fn the_harness_refuses_a_path_that_fails_or_writes_nothing() {
        let start = SimFram::fresh();
        assert_eq!(
            crash_at_every_step(&start, |_| Err(()), |_, _| {}),
            Err(Uncut::PathFailed)
        );
        assert_eq!(
            crash_at_every_step(&start, |_| Ok(()), |_, _| {}),
            Err(Uncut::NothingWritten)
        );
        let mut past = SimFram::fresh();
        assert_eq!(
            block_on(past.write(Address(u16::MAX), &[1, 2])),
            Err(Refused::Bus(SimError::OutOfRange))
        );
    }
}
