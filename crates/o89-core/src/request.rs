//! Signed requests in P-080's order: the MAC, the session's client, the
//! counter, the dedup table, one FRAM write, and only then the operation.
//!
//! **The order is the types.** `km43` refuses to hand out a counter before
//! the MAC and the session's `client_id` have both checked out, and the
//! operation before the counter has; this file continues the chain. A
//! [`Permit`] is the only thing that carries an operation to a handler, and
//! the only way to get one is through [`admit`], which returns it after the
//! part holds the new counter and, for a `Command`, the in-flight dedup
//! entry, in one record and so in one transaction. A write that does not
//! land is error 7 and nothing executes (P-079): the RAM copy stays where
//! the part is, so the next request is judged against what the controller
//! can prove it accepted.
//!
//! **The row is the session's.** The counter checked and moved is the row
//! of the client the session was bound to at `Hello`, never one named by
//! the body (P-084); a body naming another client is refused before any
//! row is read.
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
//! cites: P-079, P-080, P-084, P-120, P-124

use km43::{
    ClientId, Command, CommandAck, CommandError, CommandOperation, Condition, Counter, ErrorCode,
    FreshWrite, Header, MessageType, Refusal as Code, SessionKey, SignedClaim, SignedError,
};

use crate::body::{Kept, Unchanged};
use crate::clients::{Admitted, CLIENT_TABLE_BYTES, Check, ClientTable};
use crate::dedup::{Fingerprint, Recorded, Reserved};
use crate::fram::Fram;
use crate::tick::Tick;

/// The client table as the session layer keeps it.
pub type Clients = Kept<ClientTable, CLIENT_TABLE_BYTES>;

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
    /// What `km43` refused: the MAC (error 10), a body naming another
    /// client than the session's (12, P-084), or a counter not ahead of the
    /// row (11).
    Signed(SignedError),
    /// A `Command` whose operation does not read: error 1, before any entry
    /// is reserved or any counter moves.
    Operation(CommandError),
    /// No row at the slot the session is bound to: error 12. A factory reset
    /// cleared it under a session that is still open.
    NoSuchClient,
    /// No room in the dedup table, or in this client's half of it: error 7,
    /// rather than evicting (P-122).
    Busy,
    /// The counter did not land: error 7, and the operation does not run
    /// (P-079).
    NotKept(Unchanged<E>),
}

impl<E> Refusal<E> {
    /// The code the refusal is answered with.
    #[must_use]
    pub const fn code(&self) -> Code {
        match self {
            Self::Signed(why) => why.refusal(),
            Self::Operation(why) => why.refusal(),
            Self::NoSuchClient => Code::Client(ErrorCode::UnknownClient),
            Self::Busy | Self::NotKept(_) => Code::Client(ErrorCode::BusyRetry),
        }
    }

    /// The class A concern this refusal raises: a counter the part would not
    /// keep is the controller losing its record of what it accepted, and the
    /// error code alone can be dropped by the comms processor (P-079).
    #[must_use]
    pub const fn raises(&self) -> Option<Condition> {
        match self {
            Self::NotKept(_) => Some(Condition::COUNTER_WRITE_FAILED),
            Self::Signed(_) | Self::Operation(_) | Self::NoSuchClient | Self::Busy => None,
        }
    }
}

/// What a signed request is to become.
#[derive(Debug)]
#[must_use = "an admission nobody acts on is a counter spent on nothing"]
pub enum Admission<'a, E> {
    /// Steps 1 to 4 passed and the part holds their result: execute.
    Execute(Permit<'a>),
    /// A command the dedup table answered without executing (P-080 step 3).
    Answered(CommandAck<'static>),
    /// A command whose entry a reset left in flight: the state store decides.
    InFlight(InFlight<'a>),
    /// Refused before anything executed.
    Refused(Refusal<E>),
}

/// An operation the part has already recorded the counter for.
#[derive(Debug)]
#[must_use = "a permit dropped is a counter spent and an operation nobody ran"]
pub enum Permit<'a> {
    /// `SetConfig`, `Firmware` or `Time`: the counter landed.
    Write(Write<'a>),
    /// A `Command`: the counter and the in-flight entry landed together.
    Command(Reservation<'a>),
}

/// A signed write that is not a command, ready for its handler.
#[derive(Debug)]
#[must_use = "a permit dropped is a counter spent and an operation nobody ran"]
pub struct Write<'a>(FreshWrite<'a>);

impl<'a> Write<'a> {
    /// The three scalars the MAC covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.0.header()
    }

    /// The operation body, exactly as it arrived.
    #[must_use]
    pub const fn operation(&self) -> &'a [u8] {
        self.0.operation()
    }
}

/// A command whose entry is reserved in flight on the part.
///
/// Consumed by [`finished`](Self::finished), which is P-080 step 6; dropped,
/// it leaves an entry a retry will meet as [`InFlight`].
#[derive(Debug)]
#[must_use = "a reserved command never finished is a retry answered from the state store"]
pub struct Reservation<'a> {
    header: Header,
    client: ClientId,
    command: CommandOperation<'a>,
    seat: Reserved,
}

impl<'a> Reservation<'a> {
    /// The three scalars the MAC covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The command to execute.
    #[must_use]
    pub const fn command(&self) -> CommandOperation<'a> {
        self.command
    }

    /// P-080 step 6: record what the command did and build its ack. An
    /// accepted or shadowed command completes its entry; any other outcome
    /// discards it, because the client is expected to retry past it and a
    /// leftover entry would answer that retry `duplicate` (P-120).
    ///
    /// The ack is what the command did whether or not the record landed. A
    /// write that fails leaves the entry in flight, on the part and in RAM,
    /// which is the case the state store answers on the next retry.
    pub async fn finished<'d, F: Fram>(
        self,
        clients: &mut Clients,
        fram: &mut F,
        executed: Executed,
        detail: &'d str,
    ) -> Finished<'d, F::Error> {
        let seat = self.seat;
        let recorded = clients
            .update(fram, |table| table.finished(seat, executed.recorded()))
            .await;
        Finished {
            ack: CommandAck {
                cmd_id: self.command.cmd_id,
                outcome: executed.outcome(),
                detail,
            },
            recorded,
        }
    }

    /// The client whose row holds the entry.
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
    counter: Counter,
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
    pub async fn already<F: Fram>(
        self,
        clients: &mut Clients,
        fram: &mut F,
    ) -> Finished<'static, F::Error> {
        let seat = self.seat;
        let recorded = clients
            .update(fram, |table| {
                table.finished(seat, Some(Recorded::Accepted));
            })
            .await;
        Finished {
            ack: CommandAck {
                cmd_id: self.command.cmd_id,
                outcome: Command::Duplicate,
                detail: DUPLICATE,
            },
            recorded,
        }
    }

    /// The hardware is not where the command asked: the entry is discarded
    /// and the retry runs as a fresh command, its counter and a new entry
    /// landing in the same one write as the discard.
    pub async fn again<F: Fram>(
        self,
        clients: &mut Clients,
        fram: &mut F,
        now: Tick,
    ) -> Admission<'a, F::Error> {
        let Self {
            header,
            client,
            counter,
            command,
            fingerprint,
            seat,
        } = self;
        let Some(last) = clients.present().and_then(|table| table.accepted(client)) else {
            return Admission::Refused(Refusal::NoSuchClient);
        };
        let admitted = clients
            .update(fram, |table| {
                table.finished(seat, None);
                table.admit(client, counter, command.cmd_id, fingerprint, now)
            })
            .await;
        let asked = Asked {
            header,
            client,
            last,
            counter,
            command,
            fingerprint,
        };
        asked.reserved(admitted)
    }
}

/// P-080 steps 1 to 4 for one signed request on a session bound to
/// `bound` under `key`.
///
/// The MAC is checked before anything else and the counter before any
/// table is consulted; nothing is written for a request refused at either.
/// A request that passes both lands its counter, and a command its
/// in-flight entry with it, in one write; the [`Permit`] comes back only
/// once the part has them.
pub async fn admit<'a, F: Fram>(
    claim: SignedClaim<'a>,
    key: &SessionKey,
    bound: ClientId,
    clients: &mut Clients,
    fram: &mut F,
    now: Tick,
) -> Admission<'a, F::Error> {
    let signed = match claim.verify(key, bound) {
        Ok(signed) => signed,
        Err(why) => return Admission::Refused(Refusal::Signed(why)),
    };
    let Some(last) = clients.present().and_then(|table| table.accepted(bound)) else {
        return Admission::Refused(Refusal::NoSuchClient);
    };
    let fresh = match signed.fresh(last) {
        Ok(fresh) => fresh,
        Err(why) => return Admission::Refused(Refusal::Signed(why)),
    };
    let header = fresh.header();
    let counter = fresh.counter();
    let stale = SignedError::StaleCounter {
        last,
        sent: counter,
    };
    match header.kind {
        MessageType::Command => {
            let command = match CommandOperation::decode(fresh.operation()) {
                Ok(command) => command,
                Err(why) => return Admission::Refused(Refusal::Operation(why)),
            };
            let fingerprint = Fingerprint::of(fresh.operation());
            let admitted = clients
                .update(fram, |table| {
                    table.admit(bound, counter, command.cmd_id, fingerprint, now)
                })
                .await;
            let asked = Asked {
                header,
                client: bound,
                last,
                counter,
                command,
                fingerprint,
            };
            asked.reserved(admitted)
        }
        MessageType::SetConfig | MessageType::Firmware | MessageType::Time => {
            match clients
                .update(fram, |table| table.accept(bound, counter))
                .await
            {
                Ok(Check::Ahead) => Admission::Execute(Permit::Write(Write(fresh))),
                Ok(Check::Stale) => Admission::Refused(Refusal::Signed(stale)),
                Ok(Check::NoSuchClient) => Admission::Refused(Refusal::NoSuchClient),
                Err(why) => Admission::Refused(Refusal::NotKept(why)),
            }
        }
        // `SignedClaim::decode` refuses every other type before a claim
        // exists; answered as it would have been, never guessed at.
        MessageType::Discover
        | MessageType::DiscoverResponse
        | MessageType::Hello
        | MessageType::HelloResponse
        | MessageType::Inventory
        | MessageType::InventoryResponse
        | MessageType::Readings
        | MessageType::ReadingsResponse
        | MessageType::Concerns
        | MessageType::ConcernsResponse
        | MessageType::History
        | MessageType::HistoryResponse
        | MessageType::Subscribe
        | MessageType::SubscribeResponse
        | MessageType::EventResponse
        | MessageType::ReadLog
        | MessageType::ReadLogResponse
        | MessageType::GetConfig
        | MessageType::GetConfigResponse
        | MessageType::SetConfigResponse
        | MessageType::CommandResponse
        | MessageType::FirmwareResponse
        | MessageType::TimeResponse
        | MessageType::Pair
        | MessageType::PairResponse
        | MessageType::Goodbye
        | MessageType::GoodbyeResponse
        | MessageType::ErrorResponse => {
            Admission::Refused(Refusal::Signed(SignedError::NotSigned(header.kind)))
        }
    }
}

/// A command that passed steps 1 and 2, with what the table is asked.
struct Asked<'a> {
    header: Header,
    client: ClientId,
    /// The row's counter before this request.
    last: Counter,
    counter: Counter,
    command: CommandOperation<'a>,
    fingerprint: Fingerprint,
}

impl<'a> Asked<'a> {
    /// What the table's answer becomes: steps 3 and 4 read back.
    fn reserved<E>(self, admitted: Result<Admitted, Unchanged<E>>) -> Admission<'a, E> {
        let Self {
            header,
            client,
            last,
            counter,
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
        match admitted {
            Ok(Admitted::Fresh(seat)) => Admission::Execute(Permit::Command(Reservation {
                header,
                client,
                command,
                seat,
            })),
            Ok(Admitted::Already(Recorded::Accepted)) => answered(Command::Duplicate, DUPLICATE),
            Ok(Admitted::Already(Recorded::Shadowed)) => answered(Command::Shadowed, SHADOWED),
            Ok(Admitted::ReusedId) => answered(Command::Rejected, REUSED),
            Ok(Admitted::InFlight(seat)) => Admission::InFlight(InFlight {
                header,
                client,
                counter,
                command,
                fingerprint,
                seat,
            }),
            Ok(Admitted::Busy) => Admission::Refused(Refusal::Busy),
            Ok(Admitted::Stale) => Admission::Refused(Refusal::Signed(SignedError::StaleCounter {
                last,
                sent: counter,
            })),
            Ok(Admitted::NoSuchClient) => Admission::Refused(Refusal::NoSuchClient),
            Err(why) => Admission::Refused(Refusal::NotKept(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::{
        CommandKind, DeviceId, DeviceSecret, Envelope, Epoch, Handshake, PrintedSecret, ReqId,
        SessionId, Signed,
    };

    use super::*;
    use crate::body::Held;
    use crate::clients::{Because, Booted, Label, Paired};
    use crate::dedup::PER_CLIENT;
    use crate::fram::{Address, Refused};
    use crate::map::CLIENT_TABLE;

    const PART_BYTES: usize = 4096;
    const _: () = assert!(CLIENT_TABLE.end().0 as usize <= PART_BYTES);

    /// The bus writes one record takes: the magic cleared, the sequence,
    /// the body, the CRC, the magic.
    const RECORD: usize = 5;

    /// Enough of the part for the client table, and a supply that can fall.
    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        writes: usize,
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
            self.writes = self.writes.saturating_add(1);
            let start = usize::from(at.0);
            self.bytes[start..][..bytes.len()].copy_from_slice(bytes);
            core::future::ready(Ok(()))
        }
    }

    fn client(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    /// The session key a client and this controller both derive.
    fn key(of: ClientId) -> SessionKey {
        let secret = DeviceSecret::new(DeviceId::new([7; 16]), PrintedSecret::new([9; 32]));
        let handshake = Handshake {
            challenge: [1; 16],
            client_nonce: [2; 16],
        };
        secret
            .enrolment(Epoch::FIRST, of)
            .session_key(&handshake, SessionId::from(1))
    }

    /// A unit with a phone at slot 1 and a laptop at slot 2, both at
    /// counter zero, and a session bound to the phone.
    struct Rig {
        part: Part,
        clients: Clients,
        key: SessionKey,
        bound: ClientId,
    }

    impl Rig {
        fn new() -> Self {
            let mut part = Part {
                bytes: [0; PART_BYTES],
                falling: false,
                writes: 0,
            };
            let mut clients = block_on(Clients::read(CLIENT_TABLE, &mut part)).expect("reads");
            assert_eq!(
                block_on(clients.booted(&mut part, Epoch::FIRST)),
                Ok(Booted::Cleared(Because::Absent))
            );
            for (text, kind, slot) in [
                ("phone", km43::ClientKind::App, 1),
                ("laptop", km43::ClientKind::Cli, 2),
            ] {
                let label = Label::new(text).expect("a label under the cap");
                let paired = block_on(clients.update(&mut part, |table| table.pair(label, kind)));
                assert_eq!(paired, Ok(Ok(Paired::Enrolled(client(slot)))));
            }
            part.writes = 0;
            Self {
                part,
                clients,
                key: key(client(1)),
                bound: client(1),
            }
        }

        fn table(&self) -> &ClientTable {
            self.clients.present().expect("a table")
        }

        /// The table the part holds, as the next boot would read it.
        fn on_the_part(&mut self) -> ClientTable {
            let read = block_on(Clients::read(CLIENT_TABLE, &mut self.part)).expect("reads");
            match read.held() {
                Held::Present(table) => table.clone(),
                other => panic!("the part holds no table: {other:?}"),
            }
        }

        fn admit<'a>(&mut self, frame: &'a [u8], now: u64) -> Admission<'a, ()> {
            let claim = SignedClaim::decode(Envelope::decode(frame).expect("an envelope"))
                .expect("a signed body");
            block_on(admit(
                claim,
                &self.key,
                self.bound,
                &mut self.clients,
                &mut self.part,
                Tick::from_millis(now),
            ))
        }

        fn finish(
            &mut self,
            reservation: Reservation<'_>,
            executed: Executed,
        ) -> Finished<'static, ()> {
            block_on(reservation.finished(&mut self.clients, &mut self.part, executed, "done"))
        }
    }

    /// A signed request as the client sends it, signed under `key`.
    struct Frame {
        bytes: [u8; 256],
        len: usize,
    }

    impl Frame {
        fn signed(
            kind: MessageType,
            from: ClientId,
            counter: u64,
            operation: &[u8],
            key: &SessionKey,
        ) -> Self {
            let header = Header {
                kind,
                session: SessionId::from(1),
                req_id: ReqId(17),
            };
            let signed = Signed::over(header, from, Counter(counter), operation, key)
                .expect("a signed type");
            let mut bytes = [0; 256];
            let len = signed.write(&mut bytes).expect("fits");
            Self { bytes, len }
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    /// A start command's operation body.
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

    fn command(rig: &Rig, counter: u64, cmd_id: u32, kind: CommandKind) -> Frame {
        let (op, len) = operation(cmd_id, kind);
        Frame::signed(
            MessageType::Command,
            rig.bound,
            counter,
            &op[..len],
            &rig.key,
        )
    }

    fn start(rig: &Rig, counter: u64, cmd_id: u32) -> Frame {
        command(rig, counter, cmd_id, CommandKind::StartGenerator)
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

    #[test]
    fn p_080_a_fresh_command_is_permitted_only_once_the_part_holds_its_counter_and_entry() {
        let mut rig = Rig::new();
        let frame = start(&rig, 1, 42);
        let reservation = permitted(rig.admit(frame.bytes(), 1_000));
        assert_eq!(reservation.command().cmd_id, 42);
        assert_eq!(reservation.command().kind, CommandKind::StartGenerator);
        assert_eq!(reservation.client(), client(1));
        assert_eq!(rig.part.writes, RECORD, "one record for both");
        // The next boot finds both: the counter, and the entry in flight.
        let mut found = rig.on_the_part().rebased();
        assert_eq!(found.accepted(client(1)), Some(Counter(1)));
        let (op, len) = operation(42, CommandKind::StartGenerator);
        assert!(matches!(
            found.admit(
                client(1),
                Counter(2),
                42,
                Fingerprint::of(&op[..len]),
                Tick::ZERO
            ),
            Admitted::InFlight(_)
        ));
        let finished = rig.finish(reservation, Executed::Accepted);
        assert_eq!(finished.recorded, Ok(()));
        assert_eq!(finished.ack.cmd_id, 42);
        assert_eq!(finished.ack.outcome, Command::Accepted);
        assert_eq!(rig.part.writes, 2 * RECORD, "step 6 is its own record");
    }

    #[test]
    fn p_080_a_signed_write_that_is_not_a_command_lands_its_counter_and_reaches_its_handler() {
        let mut rig = Rig::new();
        let time = [0xa1, 1, 0x1b, 0, 0, 1, 0x8b, 0xcf, 0xe5, 0x68, 0];
        for (counter, kind) in [
            (1, MessageType::Time),
            (2, MessageType::SetConfig),
            (3, MessageType::Firmware),
        ] {
            let frame = Frame::signed(kind, rig.bound, counter, &time, &rig.key);
            let Admission::Execute(Permit::Write(write)) = rig.admit(frame.bytes(), 0) else {
                panic!("a write permit for {kind:?}");
            };
            assert_eq!(write.header().kind, kind);
            assert_eq!(write.operation(), time);
            assert_eq!(
                rig.on_the_part().accepted(client(1)),
                Some(Counter(counter))
            );
        }
        assert_eq!(rig.part.writes, 3 * RECORD);
        // Nothing reserved an entry: only a command is deduplicated.
        assert_eq!(rig.table().dedup().live(Tick::ZERO), 0);
    }

    #[test]
    fn p_080_a_replayed_request_is_refused_by_the_counter_and_writes_nothing() {
        let mut rig = Rig::new();
        let frame = start(&rig, 5, 42);
        let reservation = permitted(rig.admit(frame.bytes(), 0));
        let _ = rig.finish(reservation, Executed::Accepted);
        let writes = rig.part.writes;
        // The same bytes again: equal is the replay (P-081).
        let why = refusal(rig.admit(frame.bytes(), 1));
        assert_eq!(
            why,
            Refusal::Signed(SignedError::StaleCounter {
                last: Counter(5),
                sent: Counter(5)
            })
        );
        assert_eq!(why.code(), Code::Client(ErrorCode::CounterNotFresh));
        // An older counter is refused the same way, and a non-command too.
        let older = start(&rig, 4, 43);
        assert!(matches!(
            refusal(rig.admit(older.bytes(), 2)),
            Refusal::Signed(SignedError::StaleCounter { .. })
        ));
        let time = Frame::signed(MessageType::Time, rig.bound, 5, &[0xa1, 1, 0], &rig.key);
        assert!(matches!(
            refusal(rig.admit(time.bytes(), 3)),
            Refusal::Signed(SignedError::StaleCounter { .. })
        ));
        assert_eq!(rig.part.writes, writes, "a replay costs the part nothing");
    }

    /// Conformance 9: a single check of the tag removed, anywhere, and this
    /// fails. Every bit of the frame flipped in turn: nothing is permitted,
    /// no answer comes from the table, and the part is never written.
    #[test]
    fn p_080_every_single_bit_flip_of_a_signed_command_is_refused_and_writes_nothing() {
        let mut rig = Rig::new();
        let frame = start(&rig, 1, 42);
        let mut refused_by_the_mac = 0;
        for at in 0..frame.len {
            for bit in 0..8 {
                let mut bytes = frame.bytes;
                bytes[at] ^= 1 << bit;
                let flipped = &bytes[..frame.len];
                let Ok(envelope) = Envelope::decode(flipped) else {
                    continue;
                };
                let Ok(claim) = SignedClaim::decode(envelope) else {
                    continue;
                };
                let admission = block_on(admit(
                    claim,
                    &rig.key,
                    rig.bound,
                    &mut rig.clients,
                    &mut rig.part,
                    Tick::ZERO,
                ));
                match admission {
                    Admission::Refused(Refusal::Signed(SignedError::Mac(_))) => {
                        refused_by_the_mac += 1;
                    }
                    Admission::Refused(Refusal::Signed(SignedError::WrongClient { .. })) => {}
                    other => panic!("byte {at} bit {bit}: {other:?}"),
                }
            }
        }
        assert!(refused_by_the_mac > 100, "{refused_by_the_mac}");
        assert_eq!(rig.part.writes, 0);
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(0)));
        // The unflipped frame is still good: the refusals spent nothing.
        let _ = permitted(rig.admit(frame.bytes(), 0));
    }

    #[test]
    fn p_080_a_request_under_another_key_is_error_10_and_reads_no_row() {
        let mut rig = Rig::new();
        let forged = {
            let (op, len) = operation(42, CommandKind::StartGenerator);
            Frame::signed(
                MessageType::Command,
                client(1),
                1,
                &op[..len],
                &key(client(2)),
            )
        };
        let why = refusal(rig.admit(forged.bytes(), 0));
        assert!(
            matches!(why, Refusal::Signed(SignedError::Mac(_))),
            "{why:?}"
        );
        assert_eq!(why.code(), Code::Client(ErrorCode::BadMAC));
        assert_eq!(why.raises(), None);
        assert_eq!(rig.part.writes, 0);
    }

    #[test]
    fn p_084_a_body_naming_another_client_is_error_12_and_moves_neither_row() {
        let mut rig = Rig::new();
        // The phone's session, signing correctly, claims to be the laptop:
        // the counter it would move is the laptop's.
        let (op, len) = operation(42, CommandKind::StopGenerator);
        let frame = Frame::signed(
            MessageType::Command,
            client(2),
            u64::MAX,
            &op[..len],
            &rig.key,
        );
        let why = refusal(rig.admit(frame.bytes(), 0));
        assert_eq!(
            why,
            Refusal::Signed(SignedError::WrongClient {
                bound: client(1),
                body: client(2)
            })
        );
        assert_eq!(why.code(), Code::Client(ErrorCode::UnknownClient));
        assert_eq!(rig.part.writes, 0);
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(0)));
        assert_eq!(rig.table().accepted(client(2)), Some(Counter(0)));
    }

    #[test]
    fn p_079_a_counter_the_part_will_not_keep_is_busy_raises_its_concern_and_does_not_execute() {
        let mut rig = Rig::new();
        rig.part.falling = true;
        let frame = start(&rig, 1, 42);
        let why = refusal(rig.admit(frame.bytes(), 0));
        assert_eq!(
            why,
            Refusal::NotKept(Unchanged::Refused(Refused::SupplyFalling))
        );
        assert_eq!(why.code(), Code::Client(ErrorCode::BusyRetry));
        assert_eq!(why.raises(), Some(Condition::COUNTER_WRITE_FAILED));
        // RAM is where the part is: the counter was not accepted and no
        // entry was reserved, so the retry is judged as a first attempt.
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(0)));
        assert_eq!(rig.table().dedup().live(Tick::ZERO), 0);
        // The same for a write that is not a command.
        let time = Frame::signed(MessageType::Time, rig.bound, 1, &[0xa1, 1, 0], &rig.key);
        assert!(matches!(
            refusal(rig.admit(time.bytes(), 0)),
            Refusal::NotKept(_)
        ));
        // The supply recovers; the client's retry carries a new counter and
        // the same cmd_id, and runs.
        rig.part.falling = false;
        let retry = start(&rig, 2, 42);
        let _ = permitted(rig.admit(retry.bytes(), 1));
        assert_eq!(rig.on_the_part().accepted(client(1)), Some(Counter(2)));
    }

    /// Conformance 13, the first direction.
    #[test]
    fn p_120_a_retry_with_identical_operation_bytes_is_answered_duplicate_and_not_executed() {
        let mut rig = Rig::new();
        let first = start(&rig, 1, 42);
        let reservation = permitted(rig.admit(first.bytes(), 0));
        let _ = rig.finish(reservation, Executed::Accepted);
        let writes = rig.part.writes;
        // The ack was lost; the retry carries a new counter and the same
        // operation bytes (P-082).
        let retry = start(&rig, 2, 42);
        let ack = answer(rig.admit(retry.bytes(), 5_000));
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
        let first = start(&rig, 1, 42);
        let reservation = permitted(rig.admit(first.bytes(), 0));
        let _ = rig.finish(reservation, Executed::Shadowed);
        let retry = start(&rig, 2, 42);
        let ack = answer(rig.admit(retry.bytes(), 5_000));
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
            let first = start(&rig, 1, 42);
            let reservation = permitted(rig.admit(first.bytes(), 0));
            let finished = rig.finish(reservation, executed);
            assert_eq!(finished.recorded, Ok(()));
            assert_eq!(
                rig.on_the_part().dedup().live(Tick::ZERO),
                0,
                "{executed:?}"
            );
            let retry = start(&rig, 2, 42);
            let _ = permitted(rig.admit(retry.bytes(), 1));
        }
    }

    /// Conformance 13, the second direction. Drop the operation hash from
    /// the key and the second command is answered `duplicate`: this fails.
    #[test]
    fn p_124_the_same_cmd_id_with_different_bytes_is_rejected_and_not_executed() {
        let mut rig = Rig::new();
        let first = start(&rig, 1, 42);
        let reservation = permitted(rig.admit(first.bytes(), 0));
        let _ = rig.finish(reservation, Executed::Accepted);
        let writes = rig.part.writes;
        let other = command(&rig, 2, 42, CommandKind::StopGenerator);
        let ack = answer(rig.admit(other.bytes(), 1_000));
        assert_eq!(
            ack,
            CommandAck {
                cmd_id: 42,
                outcome: Command::Rejected,
                detail: REUSED
            }
        );
        assert_eq!(rig.part.writes, writes, "nothing reserved, nothing moved");
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(1)));
    }

    #[test]
    fn p_122_a_client_at_its_half_of_the_table_is_busy_and_its_counter_does_not_move() {
        let mut rig = Rig::new();
        let half = u32::try_from(PER_CLIENT).expect("fits");
        for cmd_id in 0..half {
            let frame = start(&rig, u64::from(cmd_id) + 1, cmd_id);
            let reservation = permitted(rig.admit(frame.bytes(), 0));
            let _ = rig.finish(reservation, Executed::Accepted);
        }
        let writes = rig.part.writes;
        let next = u64::from(half) + 1;
        let frame = start(&rig, next, half);
        let why = refusal(rig.admit(frame.bytes(), 1));
        assert_eq!(why, Refusal::Busy);
        assert_eq!(why.code(), Code::Client(ErrorCode::BusyRetry));
        assert_eq!(why.raises(), None, "a full table is not a failing part");
        assert_eq!(rig.part.writes, writes);
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(next - 1)));
    }

    #[test]
    fn a_command_whose_operation_does_not_read_is_error_1_and_spends_no_counter() {
        let mut rig = Rig::new();
        for op in [
            &[0xa0][..],
            &[0xa3, 1, 7, 2, 0x19, 0x80, 0, 3, 0xa0],
            &[0xa3, 1, 7, 2, 0x19, 1, 1, 3, 0x80],
            &[0x07],
        ] {
            let frame = Frame::signed(MessageType::Command, rig.bound, 1, op, &rig.key);
            let why = refusal(rig.admit(frame.bytes(), 0));
            assert!(matches!(why, Refusal::Operation(_)), "{op:02x?}: {why:?}");
            assert_eq!(why.code(), Code::Client(ErrorCode::MalformedFrame));
        }
        assert_eq!(rig.part.writes, 0);
        assert_eq!(rig.table().accepted(client(1)), Some(Counter(0)));
    }

    #[test]
    fn a_session_bound_to_a_slot_with_no_row_is_error_12_and_writes_nothing() {
        let mut rig = Rig::new();
        rig.bound = client(3);
        rig.key = key(client(3));
        let frame = start(&rig, 1, 42);
        let why = refusal(rig.admit(frame.bytes(), 0));
        assert_eq!(why, Refusal::NoSuchClient);
        assert_eq!(why.code(), Code::Client(ErrorCode::UnknownClient));
        assert_eq!(rig.part.writes, 0);
    }

    /// A reset between steps 4 and 6: the entry says only that the command
    /// started. The retry is handed to the state store, never answered
    /// from the entry, and both of its answers are exercised.
    #[test]
    fn p_080_a_retry_meeting_an_entry_left_in_flight_is_settled_by_the_state_store() {
        for hardware_already_there in [true, false] {
            let mut rig = Rig::new();
            let first = start(&rig, 1, 42);
            let reservation = permitted(rig.admit(first.bytes(), 0));
            drop(reservation);
            // The reset: the boot reads the table back and rebases it.
            let mut clients = block_on(Clients::read(CLIENT_TABLE, &mut rig.part)).expect("reads");
            assert_eq!(
                block_on(clients.booted(&mut rig.part, Epoch::FIRST)),
                Ok(Booted::Rebased)
            );
            rig.clients = clients;
            let retry = start(&rig, 2, 42);
            let Admission::InFlight(in_flight) = rig.admit(retry.bytes(), 10) else {
                panic!("an entry in flight");
            };
            assert_eq!(in_flight.command().cmd_id, 42);
            if hardware_already_there {
                let finished = block_on(in_flight.already(&mut rig.clients, &mut rig.part));
                assert_eq!(finished.recorded, Ok(()));
                assert_eq!(finished.ack.outcome, Command::Duplicate);
                // Completed on the part: a third try is the plain duplicate.
                let third = start(&rig, 3, 42);
                assert_eq!(
                    answer(rig.admit(third.bytes(), 20)).outcome,
                    Command::Duplicate
                );
            } else {
                let again = block_on(in_flight.again(&mut rig.clients, &mut rig.part, Tick::ZERO));
                let reservation = permitted(again);
                assert_eq!(rig.on_the_part().accepted(client(1)), Some(Counter(2)));
                let finished = rig.finish(reservation, Executed::Accepted);
                assert_eq!(finished.ack.outcome, Command::Accepted);
            }
        }
    }

    #[test]
    fn p_080_a_step_6_that_does_not_land_still_answers_and_leaves_the_entry_in_flight() {
        let mut rig = Rig::new();
        let first = start(&rig, 1, 42);
        let reservation = permitted(rig.admit(first.bytes(), 0));
        rig.part.falling = true;
        let finished = rig.finish(reservation, Executed::Accepted);
        assert_eq!(finished.ack.outcome, Command::Accepted, "it ran");
        assert_eq!(
            finished.recorded,
            Err(Unchanged::Refused(Refused::SupplyFalling))
        );
        rig.part.falling = false;
        let retry = start(&rig, 2, 42);
        assert!(matches!(
            rig.admit(retry.bytes(), 1),
            Admission::InFlight(_)
        ));
    }

    #[test]
    fn every_refusal_names_its_code_and_only_a_counter_not_kept_raises() {
        let cases: [(Refusal<()>, ErrorCode); 5] = [
            (
                Refusal::Signed(SignedError::StaleCounter {
                    last: Counter(1),
                    sent: Counter(1),
                }),
                ErrorCode::CounterNotFresh,
            ),
            (
                Refusal::Operation(CommandError::UnknownKind(0)),
                ErrorCode::MalformedFrame,
            ),
            (Refusal::NoSuchClient, ErrorCode::UnknownClient),
            (Refusal::Busy, ErrorCode::BusyRetry),
            (
                Refusal::NotKept(Unchanged::NothingHeld),
                ErrorCode::BusyRetry,
            ),
        ];
        for (why, code) in cases {
            assert_eq!(why.code(), Code::Client(code), "{why:?}");
            assert_eq!(
                why.raises().is_some(),
                matches!(why, Refusal::NotKept(_)),
                "{why:?}"
            );
        }
    }
}
