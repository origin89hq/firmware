//! Signed requests in P-080's order: the sealed body opened under the
//! session's key with P-022's window, the dedup table, one FRAM write, and
//! only then the operation.
//!
//! **The order is the types.** `km43` hands out a [`SignedWrite`] only out of
//! a body whose tag verified and whose `req_id` its window accepted, and
//! this file continues the chain. A [`Permit`] is the only thing that
//! carries an operation to a handler, and the only way to get one is
//! through [`admit`], which returns it, for a `Command`, only after the part
//! holds the in-flight dedup entry. A write that does not land is error 7
//! and nothing executes (P-079): the RAM copy stays where the part is.
//!
//! **The client is the session's.** A write carries no client of its own;
//! the dedup entry is keyed by the slot the session was bound to at
//! `Hello`, which is the only statement of who sent it.
//!
//! **A command is remembered only once it has executed or committed to.**
//! A match on `(client_id, cmd_id)` is answered without executing: with the
//! outcome recorded when the operation bytes agree, and `rejected` when a
//! client reused the id for a different command (P-120, P-124). An entry a
//! reset left in flight cannot say which side of the execution the reset
//! landed on, and is handed back as [`InFlight`] for the state store to
//! settle.
//!
//! What executes a command, and what the state store says about a contact,
//! belong to the behaviour an output is granted to; this file stops at the
//! permit and takes the outcome back.
//!
//! cites: P-079, P-080, P-082, P-120, P-124

use km43::{
    ClientId, Command, CommandAck, CommandError, CommandOperation, Condition, ErrorCode, Header,
    MessageType, Refusal as Code, SignedWrite,
};

use crate::body::{Kept, Unchanged};
use crate::dedup::{COMMANDS_BYTES, Commands, Fingerprint, Recorded, Reserved, Settling, Verdict};
use crate::fram::Fram;
use crate::tick::Tick;

/// The dedup table as the session layer keeps it.
pub type Dedups = Kept<Commands, COMMANDS_BYTES>;

/// What a retry of a command that executed is told.
pub const DUPLICATE: &str = "already executed under this cmd_id";

/// What a retry of a command that ran in shadow is told: nothing was
/// actuated, and `duplicate` would say something was.
pub const SHADOWED: &str = "already run in shadow; nothing was actuated";

/// What a `cmd_id` reused for a different command is told (P-124).
pub const REUSED: &str = "cmd_id reused for a different command";

/// Why a signed request was refused. Nothing executed, and nothing was
/// remembered for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refusal nobody answers is a client waiting on a timeout"]
pub enum Refusal<E> {
    /// A `Command` whose operation does not read: error 1, before any entry
    /// is reserved.
    Operation(CommandError),
    /// No room in the dedup table, or in this client's half of it: error 7,
    /// rather than evicting (P-122).
    Busy,
    /// The same command is still executing under a permit this boot handed
    /// out: error 7, so the client retries once it has run, and no second
    /// permit is issued beside the first.
    Running,
    /// The dedup entry did not land: error 7, and the command does not run
    /// (P-079).
    NotKept(Unchanged<E>),
}

impl<E> Refusal<E> {
    /// The code the refusal is answered with.
    #[must_use]
    pub const fn code(&self) -> Code {
        match self {
            Self::Operation(why) => why.refusal(),
            Self::Busy | Self::Running | Self::NotKept(_) => Code::Client(ErrorCode::BusyRetry),
        }
    }

    /// The class A concern this refusal raises: an entry the part would not
    /// keep is the controller losing its record of what it ran, and the
    /// error code alone can be dropped by the comms processor (P-079).
    #[must_use]
    pub const fn raises(&self) -> Option<Condition> {
        match self {
            Self::NotKept(_) => Some(Condition::DEDUP_WRITE_FAILED),
            Self::Operation(_) | Self::Busy | Self::Running => None,
        }
    }
}

/// What a signed request is to become.
#[derive(Debug)]
#[must_use = "an admission nobody acts on is a write nobody answered"]
pub enum Admission<'a, E> {
    /// Execute: for a `Command`, its entry is on the part.
    Execute(Permit<'a>),
    /// A command the dedup table answered without executing (P-080 step 2).
    Answered(CommandAck<'static>),
    /// A command whose entry a reset left in flight: the state store decides.
    InFlight(InFlight<'a>),
    /// Refused before anything executed.
    Refused(Refusal<E>),
}

/// An operation cleared to run.
#[derive(Debug)]
#[must_use = "a permit dropped is an operation nobody ran"]
pub enum Permit<'a> {
    /// `SetConfig`, `Firmware` or `Time`.
    Write(Write<'a>),
    /// A `Command`: its in-flight entry landed.
    Command(Reservation<'a>),
}

/// A signed write that is not a command, ready for its handler.
#[derive(Debug)]
#[must_use = "a permit dropped is an operation nobody ran"]
pub struct Write<'a>(SignedWrite<'a>);

impl<'a> Write<'a> {
    /// The three scalars the tag covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.0.header()
    }

    /// The operation body, exactly as it opened.
    #[must_use]
    pub const fn operation(&self) -> &'a [u8] {
        self.0.operation()
    }
}

/// A command whose entry is reserved in flight on the part.
///
/// Consumed by [`finished`](Self::finished), which is P-080 step 5. While it
/// is held, a retry of the same command is [`Refusal::Running`]: the state
/// store would see the hardware not moved yet and run it a second time.
/// Dropped unfinished, its entry stays held until it expires or the next
/// boot hands it to the state store.
#[derive(Debug)]
#[must_use = "a reserved command never finished is a retry answered from the state store"]
pub struct Reservation<'a> {
    header: Header,
    client: ClientId,
    command: CommandOperation<'a>,
    seat: Reserved,
}

impl<'a> Reservation<'a> {
    /// The three scalars the tag covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The command to execute.
    #[must_use]
    pub const fn command(&self) -> CommandOperation<'a> {
        self.command
    }

    /// P-080 step 5: record what the command did and build its ack. An
    /// accepted or shadowed command completes its entry; any other outcome
    /// discards it, because the client is expected to retry past it and a
    /// leftover entry would answer that retry `duplicate` (P-120).
    ///
    /// The ack is what the command did whether or not the record landed. A
    /// write that fails leaves the entry in flight, on the part and in RAM,
    /// released from this permit, which is the case the state store answers
    /// on the next retry.
    pub async fn finished<'d, F: Fram>(
        self,
        dedups: &mut Dedups,
        fram: &mut F,
        executed: Executed,
        detail: &'d str,
    ) -> Finished<'d, F::Error> {
        let seat = self.seat;
        let recorded = dedups
            .update(fram, |table| {
                table.dedup_mut().finished(seat, executed.recorded());
            })
            .await;
        if recorded.is_err()
            && let Some(table) = dedups.present()
        {
            // The part never held that a permit had the entry, so this
            // moves RAM nowhere the part is not.
            let mut released = table.clone();
            released.dedup_mut().released(seat);
            dedups.rebase(released);
        }
        Finished {
            ack: CommandAck {
                cmd_id: self.command.cmd_id,
                outcome: executed.outcome(),
                detail,
            },
            recorded,
        }
    }

    /// The client whose entry it is.
    #[must_use]
    pub const fn client(&self) -> ClientId {
        self.client
    }
}

/// What a command did, as its handler reports it. `duplicate` is not here:
/// it is the dedup table's answer, never an execution's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Executed {
    /// Outcome 1: it executed.
    Accepted,
    /// Outcome 2: the handler refused it.
    Rejected,
    /// Outcome 4: the selector or a lockout forbade it.
    Inhibited,
    /// Outcome 5: the client's mask does not reach it.
    Unauthorised,
    /// Outcome 6: the behaviour ran and the hardware was not written.
    Shadowed,
    /// Outcome 7: it named a topology revision that has moved.
    StaleTopology,
    /// Outcome 8: it named something that cannot take it.
    WrongTarget,
}

impl Executed {
    /// What the entry records: only an execution, or a commitment to one,
    /// is remembered (P-120).
    const fn recorded(self) -> Option<Recorded> {
        match self {
            Self::Accepted => Some(Recorded::Accepted),
            Self::Shadowed => Some(Recorded::Shadowed),
            Self::Rejected
            | Self::Inhibited
            | Self::Unauthorised
            | Self::StaleTopology
            | Self::WrongTarget => None,
        }
    }

    const fn outcome(self) -> Command {
        match self {
            Self::Accepted => Command::Accepted,
            Self::Rejected => Command::Rejected,
            Self::Inhibited => Command::Inhibited,
            Self::Unauthorised => Command::Unauthorised,
            Self::Shadowed => Command::Shadowed,
            Self::StaleTopology => Command::StaleTopology,
            Self::WrongTarget => Command::WrongTarget,
        }
    }
}

/// A command answered, and whether the part recorded the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an ack nobody sends is a client that retries a command that ran"]
pub struct Finished<'d, E> {
    /// What to answer.
    pub ack: CommandAck<'d>,
    /// Whether the entry's new state landed. A refusal is for the probe: the
    /// answer stands, and the entry left in flight is the state store's.
    pub recorded: Result<(), Unchanged<E>>,
}

/// A retry of a command whose entry says only that it was started.
///
/// The entry cannot say whether the reset landed before or after the
/// execution, so the controller must not assume either (P-080). The state
/// store can: it reads the hardware at boot rather than remembering it.
/// [`already`](Self::already) is its answer when the contact is where the
/// command asked; [`again`](Self::again) when it is not.
#[derive(Debug)]
#[must_use = "a retry nobody settles is a command neither run nor refused"]
pub struct InFlight<'a> {
    header: Header,
    client: ClientId,
    command: CommandOperation<'a>,
    fingerprint: Fingerprint,
    seat: Reserved,
}

impl<'a> InFlight<'a> {
    /// The command the entry was reserved for, for the state store to judge.
    #[must_use]
    pub const fn command(&self) -> CommandOperation<'a> {
        self.command
    }

    /// The hardware is already where the command asked: the entry completes
    /// as accepted and the retry is answered `duplicate`. Nothing executes.
    ///
    /// Another retry handed the same entry may have settled it first. If it
    /// ran the command again, the entry is that permit's, and this retry is
    /// [`Refusal::Running`] rather than a `duplicate` of a command still
    /// executing.
    pub async fn already<F: Fram>(
        self,
        dedups: &mut Dedups,
        fram: &mut F,
    ) -> Result<Finished<'static, F::Error>, Refusal<F::Error>> {
        let seat = self.seat;
        let recorded = match dedups
            .update(fram, |table| {
                table.dedup_mut().settled(seat, Some(Recorded::Accepted))
            })
            .await
        {
            Ok(Settling::Held) => return Err(Refusal::Running),
            Ok(Settling::Settled | Settling::Gone) => Ok(()),
            Err(why) => Err(why),
        };
        Ok(Finished {
            ack: CommandAck {
                cmd_id: self.command.cmd_id,
                outcome: Command::Duplicate,
                detail: DUPLICATE,
            },
            recorded,
        })
    }

    /// The hardware is not where the command asked: the entry is discarded
    /// and the retry runs as a fresh command, a new entry landing in the
    /// same one write as the discard. An entry another retry settled first
    /// is left as that retry left it, and this one is answered from it:
    /// running, or the outcome it recorded.
    pub async fn again<F: Fram>(
        self,
        dedups: &mut Dedups,
        fram: &mut F,
        now: Tick,
    ) -> Admission<'a, F::Error> {
        let Self {
            header,
            client,
            command,
            fingerprint,
            seat,
        } = self;
        let verdict = dedups
            .update(fram, |table| match table.dedup_mut().settled(seat, None) {
                Settling::Held => Verdict::Running,
                Settling::Settled | Settling::Gone => {
                    table
                        .dedup_mut()
                        .admit(client, command.cmd_id, fingerprint, now)
                }
            })
            .await;
        Asked {
            header,
            client,
            command,
            fingerprint,
        }
        .reserved(verdict)
    }
}

/// P-080 steps 2 and 3 for a write that opened on a session bound to
/// `bound`: a `Command`'s dedup lookup and, for a fresh one, its in-flight
/// entry landed before the [`Permit`] comes back. The other three writes
/// have nothing to land and are permitted as they are.
pub async fn admit<'a, F: Fram>(
    write: SignedWrite<'a>,
    bound: ClientId,
    dedups: &mut Dedups,
    fram: &mut F,
    now: Tick,
) -> Admission<'a, F::Error> {
    let header = write.header();
    if header.kind != MessageType::Command {
        return Admission::Execute(Permit::Write(Write(write)));
    }
    let command = match CommandOperation::decode(write.operation()) {
        Ok(command) => command,
        Err(why) => return Admission::Refused(Refusal::Operation(why)),
    };
    let fingerprint = Fingerprint::of(write.operation());
    let verdict = dedups
        .update(fram, |table| {
            table
                .dedup_mut()
                .admit(bound, command.cmd_id, fingerprint, now)
        })
        .await;
    Asked {
        header,
        client: bound,
        command,
        fingerprint,
    }
    .reserved(verdict)
}

/// A command past the lookup, with what the table said.
struct Asked<'a> {
    header: Header,
    client: ClientId,
    command: CommandOperation<'a>,
    fingerprint: Fingerprint,
}

impl<'a> Asked<'a> {
    /// What the table's answer becomes.
    fn reserved<E>(self, verdict: Result<Verdict, Unchanged<E>>) -> Admission<'a, E> {
        let Self {
            header,
            client,
            command,
            fingerprint,
        } = self;
        let answered = |outcome, detail| {
            Admission::Answered(CommandAck {
                cmd_id: command.cmd_id,
                outcome,
                detail,
            })
        };
        match verdict {
            Ok(Verdict::Fresh(seat)) => Admission::Execute(Permit::Command(Reservation {
                header,
                client,
                command,
                seat,
            })),
            Ok(Verdict::Already(Recorded::Accepted)) => answered(Command::Duplicate, DUPLICATE),
            Ok(Verdict::Already(Recorded::Shadowed)) => answered(Command::Shadowed, SHADOWED),
            Ok(Verdict::ReusedId) => answered(Command::Rejected, REUSED),
            Ok(Verdict::InFlight(seat)) => Admission::InFlight(InFlight {
                header,
                client,
                command,
                fingerprint,
                seat,
            }),
            Ok(Verdict::Busy) => Admission::Refused(Refusal::Busy),
            Ok(Verdict::Running) => Admission::Refused(Refusal::Running),
            Err(why) => Admission::Refused(Refusal::NotKept(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{
        ClientChannel, CommandKind, ControllerChannel, DeviceId, Enrolment, Entropy, Envelope,
        Epoch, Generation, HelloArrival, HelloOffer, HelloPending, HelloReport, MAX_PAYLOAD,
        Prologue, PrologueFields, ReqId, Sealed, SessionId, Signed, StaticKey, Suite, Version,
    };

    use super::*;
    use crate::body::Held;
    use crate::dedup::PER_CLIENT;
    use crate::fram::{Address, FRAM_BYTES, Refused};
    use crate::map::COMMANDS;

    /// The bus writes one record takes: the magic cleared, the sequence,
    /// the body, the CRC, the magic.
    const RECORD: usize = 5;

    const DEVICE_ID: [u8; 16] = *b"ORIGIN89 TEST 01";
    const HANDLE: u16 = 3;

    /// The whole part, a supply that can fall, and a power cut that lands
    /// before the n-th write from now.
    struct Part {
        bytes: [u8; FRAM_BYTES],
        falling: bool,
        writes: usize,
        cut_before: Option<usize>,
    }

    impl Part {
        #[expect(
            clippy::large_stack_arrays,
            reason = "the whole map, as the boot reads it; a test thread's stack holds it"
        )]
        fn fresh() -> Self {
            Self {
                bytes: [0xFF; FRAM_BYTES],
                falling: false,
                writes: 0,
                cut_before: None,
            }
        }
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
            if self.falling {
                return core::future::ready(Err(Refused::SupplyFalling));
            }
            if let Some(left) = self.cut_before {
                if left == 0 {
                    // Dead from here: nothing lands until the reboot.
                    return core::future::ready(Err(Refused::Bus(())));
                }
                self.cut_before = left.checked_sub(1);
            }
            self.writes = self.writes.saturating_add(1);
            let start = usize::from(at.0);
            self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
            core::future::ready(Ok(()))
        }
    }

    fn client(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    fn controller() -> StaticKey {
        StaticKey::from_stored([0x40; 32])
    }

    fn enrolment() -> Enrolment {
        Enrolment::new(
            DeviceId::new(DEVICE_ID),
            controller().public(),
            StaticKey::from_stored([0x60; 32]),
            Suite::X25519ChachapolySha256,
            Epoch::FIRST,
        )
    }

    /// A real `Hello` between km43's two ends: the channels a session on
    /// slot 1 seals and opens under, so every write here is one that opened.
    fn session() -> (ClientChannel, ControllerChannel) {
        let prologue = Prologue::new(&PrologueFields {
            suite: Suite::X25519ChachapolySha256,
            version: Version::V1_0,
            device_id: DeviceId::new(DEVICE_ID),
            epoch: Epoch::FIRST,
            challenge: &[0xC0; 16],
            handle: SessionId::from(HANDLE),
        });
        let header = |kind| km43::Header {
            kind,
            session: SessionId::from(HANDLE),
            req_id: ReqId(1),
        };
        let offer = HelloOffer {
            version: Version::V1_0,
            client_version: "test",
        };
        let mut frame = [0u8; 256];
        let (pending, len) = HelloPending::start(
            &prologue,
            &enrolment(),
            Entropy::new([2; 32]),
            &offer,
            header(MessageType::Hello),
            &mut frame,
        )
        .expect("message 1");
        let admit = controller()
            .admit_key(DeviceId::new(DEVICE_ID), &enrolment().static_key().public())
            .expect("contributory");
        let mut plain = [0u8; 256];
        let proved = HelloArrival::decode(Envelope::decode(&frame[..len]).expect("envelope"))
            .expect("a Hello")
            .admit(&prologue, [((), &admit)])
            .expect("admitted")
            .prove(
                &prologue,
                &controller(),
                (
                    &enrolment().static_key().public(),
                    Suite::X25519ChachapolySha256,
                ),
                &mut plain,
            )
            .expect("proved");
        let report = HelloReport {
            version: Version::V1_0,
            session: SessionId::from(HANDLE),
            fw_controller: "fw",
            fw_comms: "comms",
            capabilities: 0,
            log_oldest_seq: km43::LogSeq(0),
            log_newest_seq: km43::LogSeq(0),
            state_seq: km43::StateSeq(0),
            time_known: false,
            caps: km43::Caps::THIS_CONTROLLER,
            topology: km43::Topology::THIS_CONTROLLER,
            client_id: client(1),
            generation: Generation::FIRST,
        };
        let mut answer = [0u8; 512];
        let (controller, len) = proved
            .reply(Entropy::new([4; 32]), &report, &mut answer)
            .expect("answered");
        let mut report_buf = [0u8; 512];
        let session = pending
            .finish(
                &enrolment(),
                Envelope::decode(&answer[..len]).expect("envelope"),
                &mut report_buf,
            )
            .expect("opens");
        (session.into_channel(), controller)
    }

    /// A sealed write, as it arrives.
    struct Frame {
        bytes: [u8; MAX_PAYLOAD + 64],
        len: usize,
    }

    impl Frame {
        fn bytes(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    /// The part, the dedup record on it, and one session's two ends.
    struct Rig {
        part: Part,
        dedups: Dedups,
        client: ClientChannel,
        controller: ControllerChannel,
        bound: ClientId,
    }

    impl Rig {
        fn new() -> Self {
            let mut part = Part::fresh();
            let mut dedups = block_on(Dedups::read(COMMANDS, &mut part)).expect("reads");
            block_on(dedups.write(&mut part, Commands::cleared(Epoch::FIRST))).expect("written");
            part.writes = 0;
            let (channel, controller) = session();
            Self {
                part,
                dedups,
                client: channel,
                controller,
                bound: client(1),
            }
        }

        /// A write of `kind` the client seals under its next `req_id`.
        fn seal(&mut self, kind: MessageType, operation: &[u8]) -> Frame {
            let mut frame = Frame {
                bytes: [0; MAX_PAYLOAD + 64],
                len: 0,
            };
            let (_, len) = Signed::new(kind, operation)
                .expect("signed")
                .seal(
                    &mut self.client.tx,
                    SessionId::from(HANDLE),
                    &mut frame.bytes,
                )
                .expect("sealed");
            frame.len = len;
            frame
        }

        fn start(&mut self, cmd_id: u32) -> Frame {
            let (op, len) = operation(cmd_id, CommandKind::StartGenerator);
            self.seal(MessageType::Command, &op[..len])
        }

        fn stop(&mut self, cmd_id: u32) -> Frame {
            let (op, len) = operation(cmd_id, CommandKind::StopGenerator);
            self.seal(MessageType::Command, &op[..len])
        }

        /// Step 1 at the controller, then [`admit`].
        fn admit<'b>(
            &mut self,
            frame: &Frame,
            plain: &'b mut [u8; MAX_PAYLOAD],
            now: u64,
        ) -> Admission<'b, ()> {
            self.admit_as(self.bound, frame, plain, now)
        }

        fn admit_as<'b>(
            &mut self,
            bound: ClientId,
            frame: &Frame,
            plain: &'b mut [u8; MAX_PAYLOAD],
            now: u64,
        ) -> Admission<'b, ()> {
            let opened = Sealed::decode(Envelope::decode(frame.bytes()).expect("envelope"))
                .expect("sealed")
                .open(&mut self.controller.rx, plain)
                .expect("opens");
            let write = SignedWrite::read(&opened).expect("a write");
            block_on(admit(
                write,
                bound,
                &mut self.dedups,
                &mut self.part,
                Tick::from_millis(now),
            ))
        }

        fn finish(
            &mut self,
            reservation: Reservation<'_>,
            executed: Executed,
        ) -> Finished<'static, ()> {
            block_on(reservation.finished(&mut self.dedups, &mut self.part, executed, ""))
        }

        /// What the part holds, as the next boot reads it: rebased (P-121).
        fn reboot(&mut self) {
            self.part.cut_before = None;
            self.part.falling = false;
            let mut dedups = block_on(Dedups::read(COMMANDS, &mut self.part)).expect("reads");
            let rebased = dedups.present().expect("a table").clone().rebased();
            dedups.rebase(rebased);
            self.dedups = dedups;
        }

        fn live(&self) -> usize {
            self.dedups
                .present()
                .expect("held")
                .dedup()
                .live(Tick::ZERO)
        }
    }

    /// A command's operation body.
    fn operation(cmd_id: u32, kind: CommandKind) -> ([u8; 16], usize) {
        let mut out = [0; 16];
        let len = CommandOperation {
            cmd_id,
            kind,
            args: &[0xa0],
        }
        .encode(&mut out)
        .expect("fits");
        (out, len)
    }

    fn permitted(admission: Admission<'_, ()>) -> Reservation<'_> {
        match admission {
            Admission::Execute(Permit::Command(reservation)) => reservation,
            other => panic!("a command permit, not {other:?}"),
        }
    }

    fn refusal(admission: Admission<'_, ()>) -> Refusal<()> {
        match admission {
            Admission::Refused(why) => why,
            other => panic!("a refusal, not {other:?}"),
        }
    }

    fn answer(admission: Admission<'_, ()>) -> CommandAck<'static> {
        match admission {
            Admission::Answered(ack) => ack,
            other => panic!("an answer from the table, not {other:?}"),
        }
    }

    fn in_flight(admission: Admission<'_, ()>) -> InFlight<'_> {
        match admission {
            Admission::InFlight(retry) => retry,
            other => panic!("an entry in flight, not {other:?}"),
        }
    }

    #[test]
    fn p_080_a_fresh_command_is_permitted_only_once_the_part_holds_its_entry() {
        let mut rig = Rig::new();
        let frame = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&frame, &mut plain, 1_000));
        assert_eq!(reservation.command().cmd_id, 42);
        assert_eq!(reservation.command().kind, CommandKind::StartGenerator);
        assert_eq!(reservation.client(), client(1));
        assert_eq!(rig.part.writes, RECORD, "the entry is one record");
        // The next boot finds the entry, in flight.
        let mut found = block_on(Dedups::read(COMMANDS, &mut rig.part)).expect("reads");
        let (op, len) = operation(42, CommandKind::StartGenerator);
        let verdict = found
            .present()
            .expect("held")
            .clone()
            .rebased()
            .dedup_mut()
            .admit(client(1), 42, Fingerprint::of(&op[..len]), Tick::ZERO);
        assert!(matches!(verdict, Verdict::InFlight(_)), "{verdict:?}");
        let _ = &mut found;
        let finished = rig.finish(reservation, Executed::Accepted);
        assert_eq!(finished.recorded, Ok(()));
        assert_eq!(finished.ack.cmd_id, 42);
        assert_eq!(finished.ack.outcome, Command::Accepted);
        assert_eq!(rig.part.writes, 2 * RECORD, "step 5 is its own record");
    }

    #[test]
    fn p_080_a_write_that_is_not_a_command_reaches_its_handler_and_writes_nothing() {
        for kind in [
            MessageType::Time,
            MessageType::SetConfig,
            MessageType::Firmware,
        ] {
            let mut rig = Rig::new();
            let operation = [0xa1, 1, 0];
            let frame = rig.seal(kind, &operation);
            let mut plain = [0; MAX_PAYLOAD];
            match rig.admit(&frame, &mut plain, 0) {
                Admission::Execute(Permit::Write(write)) => {
                    assert_eq!(write.header().kind, kind);
                    assert_eq!(write.operation(), &operation);
                }
                other => panic!("{kind:?} permitted as a write, not {other:?}"),
            }
            assert_eq!(rig.part.writes, 0, "{kind:?}: nothing to land");
            // Even with the part refusing every write.
            rig.part.falling = true;
            let frame = rig.seal(kind, &operation);
            let mut plain = [0; MAX_PAYLOAD];
            assert!(matches!(
                rig.admit(&frame, &mut plain, 0),
                Admission::Execute(Permit::Write(_))
            ));
        }
    }

    #[test]
    fn p_079_an_entry_the_part_will_not_keep_is_busy_raises_its_concern_and_does_not_execute() {
        let mut rig = Rig::new();
        rig.part.falling = true;
        let frame = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let why = refusal(rig.admit(&frame, &mut plain, 0));
        assert_eq!(
            why,
            Refusal::NotKept(Unchanged::Refused(Refused::SupplyFalling))
        );
        assert_eq!(why.code(), Code::Client(ErrorCode::BusyRetry));
        assert_eq!(why.raises(), Some(Condition::DEDUP_WRITE_FAILED));
        // RAM is where the part is: nothing was reserved, so the retry is
        // judged as a first attempt.
        assert_eq!(rig.live(), 0);
        // The supply recovers; the retry carries a new req_id and the same
        // cmd_id (P-082), and runs.
        rig.part.falling = false;
        let retry = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let _ = permitted(rig.admit(&retry, &mut plain, 1));
    }

    /// A power cut before every write the reservation makes: a permit comes
    /// back only when the whole record landed, and a boot after any cut
    /// finds either no entry, or the entry in flight — never a table it
    /// cannot read.
    #[test]
    fn p_080_a_reservation_cut_at_every_write_is_permitted_only_once_it_landed() {
        for cut in 0..=RECORD {
            let mut rig = Rig::new();
            rig.part.cut_before = Some(cut);
            let frame = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            let admission = rig.admit(&frame, &mut plain, 0);
            let landed = cut >= RECORD;
            match admission {
                Admission::Execute(Permit::Command(_)) => assert!(landed, "cut {cut}"),
                Admission::Refused(Refusal::NotKept(_)) => assert!(!landed, "cut {cut}"),
                other => panic!("cut {cut}: {other:?}"),
            }
            rig.reboot();
            assert!(
                matches!(rig.dedups.held(), Held::Present(_)),
                "cut {cut}: the previous record stands"
            );
            let retry = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            let admission = rig.admit(&retry, &mut plain, 1);
            if landed {
                let _ = in_flight(admission);
            } else {
                let _ = permitted(admission);
            }
        }
    }

    /// Conformance 13, the first direction.
    #[test]
    fn p_120_a_retry_with_identical_operation_bytes_is_answered_duplicate_and_not_executed() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&first, &mut plain, 0));
        let _ = rig.finish(reservation, Executed::Accepted);
        let writes = rig.part.writes;
        // The ack was lost; the retry carries a new req_id and the same
        // operation bytes (P-082).
        let retry = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let ack = answer(rig.admit(&retry, &mut plain, 5_000));
        assert_eq!(
            ack,
            CommandAck {
                cmd_id: 42,
                outcome: Command::Duplicate,
                detail: DUPLICATE
            }
        );
        assert_eq!(rig.part.writes, writes, "a match moves nothing");
    }

    #[test]
    fn p_120_a_retry_of_a_command_that_ran_in_shadow_is_answered_shadowed() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&first, &mut plain, 0));
        let _ = rig.finish(reservation, Executed::Shadowed);
        let retry = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let ack = answer(rig.admit(&retry, &mut plain, 5_000));
        assert_eq!(ack.outcome, Command::Shadowed);
        assert_eq!(ack.detail, SHADOWED);
    }

    #[test]
    fn p_120_a_command_that_did_not_execute_leaves_no_entry_and_its_retry_runs() {
        for executed in [
            Executed::Rejected,
            Executed::Inhibited,
            Executed::Unauthorised,
            Executed::StaleTopology,
            Executed::WrongTarget,
        ] {
            let mut rig = Rig::new();
            let first = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            let reservation = permitted(rig.admit(&first, &mut plain, 0));
            let finished = rig.finish(reservation, executed);
            assert_eq!(finished.recorded, Ok(()));
            assert_eq!(rig.live(), 0, "{executed:?}");
            let retry = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            let _ = permitted(rig.admit(&retry, &mut plain, 1));
        }
    }

    /// Conformance 13, the second direction. Drop the operation hash from
    /// the key and the second command is answered `duplicate`: this fails.
    #[test]
    fn p_124_the_same_cmd_id_with_different_bytes_is_rejected_and_not_executed() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&first, &mut plain, 0));
        let _ = rig.finish(reservation, Executed::Accepted);
        let writes = rig.part.writes;
        let other = rig.stop(42);
        let mut plain = [0; MAX_PAYLOAD];
        let ack = answer(rig.admit(&other, &mut plain, 1_000));
        assert_eq!(
            ack,
            CommandAck {
                cmd_id: 42,
                outcome: Command::Rejected,
                detail: REUSED
            }
        );
        assert_eq!(rig.part.writes, writes, "nothing reserved, nothing moved");
    }

    /// Two clients numbering from zero are two commands (P-120's key), and
    /// one at its half of the table leaves the other's untouched (P-122).
    #[test]
    fn p_122_a_client_at_its_half_of_the_table_is_busy_and_another_is_not() {
        let mut rig = Rig::new();
        let half = u32::try_from(PER_CLIENT).expect("fits");
        for cmd_id in 0..half {
            let frame = rig.start(cmd_id);
            let mut plain = [0; MAX_PAYLOAD];
            let reservation = permitted(rig.admit(&frame, &mut plain, 0));
            let _ = rig.finish(reservation, Executed::Accepted);
        }
        let writes = rig.part.writes;
        let frame = rig.start(half);
        let mut plain = [0; MAX_PAYLOAD];
        let why = refusal(rig.admit(&frame, &mut plain, 1));
        assert_eq!(why, Refusal::Busy);
        assert_eq!(why.code(), Code::Client(ErrorCode::BusyRetry));
        assert_eq!(why.raises(), None, "a full half is not a failing part");
        assert_eq!(rig.part.writes, writes);
        // Another client's command 0 is not the first client's.
        let frame = rig.start(0);
        let mut plain = [0; MAX_PAYLOAD];
        let _ = permitted(rig.admit_as(client(2), &frame, &mut plain, 1));
    }

    #[test]
    fn p_080_a_command_whose_operation_does_not_read_is_error_1_and_writes_nothing() {
        let mut rig = Rig::new();
        for op in [
            &[0xa0][..],
            &[0xa3, 1, 7, 2, 0x19, 0x80, 0, 3, 0xa0],
            &[0xa3, 1, 7, 2, 0x19, 1, 1, 3, 0x80],
            &[0x07],
        ] {
            let frame = rig.seal(MessageType::Command, op);
            let mut plain = [0; MAX_PAYLOAD];
            let why = refusal(rig.admit(&frame, &mut plain, 0));
            assert!(matches!(why, Refusal::Operation(_)), "{op:02x?}: {why:?}");
            assert_eq!(why.code(), Code::Client(ErrorCode::MalformedFrame));
        }
        assert_eq!(rig.part.writes, 0);
        assert_eq!(rig.live(), 0);
    }

    /// A reset between steps 3 and 5: the entry says only that the command
    /// started. The retry is handed to the state store, never answered
    /// from the entry, and both of its answers are exercised (P-080, P-121).
    #[test]
    fn p_121_a_retry_meeting_an_entry_left_in_flight_is_settled_by_the_state_store() {
        for hardware_already_there in [true, false] {
            let mut rig = Rig::new();
            let first = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            drop(permitted(rig.admit(&first, &mut plain, 0)));
            rig.reboot();
            let retry = rig.start(42);
            let mut plain = [0; MAX_PAYLOAD];
            let admission = rig.admit(&retry, &mut plain, 10);
            let retry = in_flight(admission);
            assert_eq!(retry.command().cmd_id, 42);
            if hardware_already_there {
                let finished = block_on(retry.already(&mut rig.dedups, &mut rig.part))
                    .expect("nothing else settled it");
                assert_eq!(finished.recorded, Ok(()));
                assert_eq!(finished.ack.outcome, Command::Duplicate);
                // Completed on the part: a third try is the plain duplicate.
                let third = rig.start(42);
                let mut plain = [0; MAX_PAYLOAD];
                assert_eq!(
                    answer(rig.admit(&third, &mut plain, 20)).outcome,
                    Command::Duplicate
                );
            } else {
                let again = block_on(retry.again(&mut rig.dedups, &mut rig.part, Tick::ZERO));
                let reservation = permitted(again);
                let finished = rig.finish(reservation, Executed::Accepted);
                assert_eq!(finished.ack.outcome, Command::Accepted);
            }
        }
    }

    /// The retry that arrives while its command is still executing on this
    /// boot. Handed to the state store, it would find the hardware not moved
    /// yet and permit the command a second time, beside the first.
    #[test]
    fn p_080_a_retry_while_its_command_still_executes_is_busy_and_gets_no_second_permit() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&first, &mut plain, 0));
        let writes = rig.part.writes;
        let retry = rig.start(42);
        let mut retry_plain = [0; MAX_PAYLOAD];
        let why = refusal(rig.admit(&retry, &mut retry_plain, 100));
        assert_eq!(why, Refusal::Running);
        assert_eq!(why.code(), Code::Client(ErrorCode::BusyRetry));
        assert_eq!(why.raises(), None);
        assert_eq!(rig.part.writes, writes, "the retry moved nothing");
        // Once the first has run, the next retry is its duplicate.
        let _ = rig.finish(reservation, Executed::Accepted);
        let third = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        assert_eq!(
            answer(rig.admit(&third, &mut plain, 200)).outcome,
            Command::Duplicate
        );
    }

    /// A reset left an entry in flight and two retries of it arrive before
    /// either is settled. Whichever settles second meets the entry the first
    /// settled, not the one both were handed, and must not discard it for a
    /// second permit or answer it `duplicate` while its command still runs.
    #[test]
    fn p_121_two_retries_of_one_entry_left_in_flight_never_get_two_permits() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        drop(permitted(rig.admit(&first, &mut plain, 0)));
        rig.reboot();
        let (a, b, c) = (rig.start(42), rig.start(42), rig.start(42));
        let (mut pa, mut pb, mut pc) = ([0; MAX_PAYLOAD], [0; MAX_PAYLOAD], [0; MAX_PAYLOAD]);
        let a = in_flight(rig.admit(&a, &mut pa, 10));
        let b = in_flight(rig.admit(&b, &mut pb, 11));
        let c = in_flight(rig.admit(&c, &mut pc, 12));
        let running = permitted(block_on(a.again(
            &mut rig.dedups,
            &mut rig.part,
            Tick::ZERO,
        )));
        let writes = rig.part.writes;
        // Told the hardware has not moved either, the second finds the
        // first one's command running.
        match block_on(b.again(&mut rig.dedups, &mut rig.part, Tick::ZERO)) {
            Admission::Refused(why) => assert_eq!(why, Refusal::Running),
            other => panic!("a second permit beside the first: {other:?}"),
        }
        // Told the hardware is there, the third may not complete it.
        match block_on(c.already(&mut rig.dedups, &mut rig.part)) {
            Err(why) => assert_eq!(why, Refusal::Running),
            Ok(finished) => panic!("answered while it runs: {finished:?}"),
        }
        assert_eq!(rig.part.writes, writes, "nothing was settled for either");
        let _ = rig.finish(running, Executed::Accepted);
        let last = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        assert_eq!(
            answer(rig.admit(&last, &mut plain, 13)).outcome,
            Command::Duplicate
        );
    }

    /// The same race settled the other way: the first retry finds the
    /// hardware already there, and the second, handed the same entry, is
    /// answered from what the first recorded.
    #[test]
    fn p_121_a_retry_settling_an_entry_another_already_completed_is_its_duplicate() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        drop(permitted(rig.admit(&first, &mut plain, 0)));
        rig.reboot();
        let (a, b) = (rig.start(42), rig.start(42));
        let (mut pa, mut pb) = ([0; MAX_PAYLOAD], [0; MAX_PAYLOAD]);
        let a = in_flight(rig.admit(&a, &mut pa, 10));
        let b = in_flight(rig.admit(&b, &mut pb, 11));
        let settled = block_on(a.already(&mut rig.dedups, &mut rig.part)).expect("settled");
        assert_eq!(settled.ack.outcome, Command::Duplicate);
        match block_on(b.again(&mut rig.dedups, &mut rig.part, Tick::ZERO)) {
            Admission::Answered(ack) => assert_eq!(ack.outcome, Command::Duplicate),
            other => panic!("the completed command ran again: {other:?}"),
        }
    }

    #[test]
    fn p_080_a_step_5_that_does_not_land_still_answers_and_leaves_the_entry_in_flight() {
        let mut rig = Rig::new();
        let first = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let reservation = permitted(rig.admit(&first, &mut plain, 0));
        rig.part.falling = true;
        let finished = rig.finish(reservation, Executed::Accepted);
        assert_eq!(finished.ack.outcome, Command::Accepted, "it ran");
        assert_eq!(
            finished.recorded,
            Err(Unchanged::Refused(Refused::SupplyFalling))
        );
        rig.part.falling = false;
        let retry = rig.start(42);
        let mut plain = [0; MAX_PAYLOAD];
        let _ = in_flight(rig.admit(&retry, &mut plain, 1));
    }

    #[test]
    fn p_079_every_refusal_names_its_code_and_only_an_entry_not_kept_raises() {
        let cases: [(Refusal<()>, ErrorCode); 4] = [
            (
                Refusal::Operation(CommandError::UnknownKind(0)),
                ErrorCode::MalformedFrame,
            ),
            (Refusal::Busy, ErrorCode::BusyRetry),
            (Refusal::Running, ErrorCode::BusyRetry),
            (
                Refusal::NotKept(Unchanged::NothingHeld),
                ErrorCode::BusyRetry,
            ),
        ];
        for (why, code) in cases {
            assert_eq!(why.code(), Code::Client(code), "{why:?}");
            assert_eq!(
                why.raises(),
                matches!(why, Refusal::NotKept(_)).then_some(Condition::DEDUP_WRITE_FAILED),
                "{why:?}"
            );
        }
    }
}
