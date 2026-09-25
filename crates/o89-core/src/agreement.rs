//! Key agreement, kept off the control loop (P-243).
//!
//! A `Hello` costs the controller four X25519 operations and a key
//! generation, a pairing three at message 2 and two at message 3: about a
//! quarter of a second each on a Cortex-M0+ at 64 MHz. Nothing that takes
//! that long may run on the executor the control loop runs on. So the
//! sessions never compute one: everything cheap is done where the frame
//! arrived — the decode, the challenge, the pre-shared key's tag, the
//! admission tags, the draws — and what is left is a [`Job`], handed to
//! whoever runs [`Agreement::run`] on an executor of its own, and taken back
//! as a [`Done`].
//!
//! **A job owns everything it needs.** The frame is copied into it, the
//! draws are in it, and the controller key is the worker's, so a job can
//! cross to another executor and nothing it touches is shared. The worker
//! writes nothing: every FRAM write a handshake needs happens where the
//! answer is sent, before it is sent.
//!
//! **One at a time, in turn.** The sessions hand out a job only when none is
//! computing, and pick the next connection after the last one served, so a
//! connection that keeps asking waits behind every other one (P-243). A
//! peer reaches the queue only once something it sent verified: the label's
//! tag on pairing message 1, a slot's admission tag on a `Hello` (P-238).
//!
//! **A result may come back for nothing.** A connection that dropped, a
//! second handshake on the same one, a factory reset: each abandons the
//! handshake (P-229), and its result is recognised by its [`Ticket`] and
//! discarded.
//!
//! cites: P-064, P-228, P-229, P-238, P-241, P-243

use km43::{
    AdmitKey, ClientId, ControllerChannel, DeviceId, EnrolAwaiting, Enrolling, Entropy, Envelope,
    Generation, HelloArrival, HelloError, HelloReport, KEY_BYTES, Label, MAX_HELLO_MESSAGE_1,
    MAX_PAIR_MESSAGE_1, PAIR_MESSAGE_3, PairArrival, PairError, Prologue, PublicKey, StaticKey,
    Suite, Version,
};

use crate::secret::{ControllerKey, Secret};
use crate::text::Text;

/// The largest handshake frame a job carries: pairing message 1 with the
/// widest offer, or a `Hello` with its admission tag, and the envelope
/// around it. A frame past this is refused before it is queued.
pub const HANDSHAKE_FRAME: usize = max(MAX_PAIR_MESSAGE_1, MAX_HELLO_MESSAGE_1) + 64;

const _: () = assert!(PAIR_MESSAGE_3 < HANDSHAKE_FRAME);

/// The largest answer a job writes: pairing message 2, or `Hello 0x81`
/// with the widest report.
pub const HANDSHAKE_ANSWER: usize = km43::MAX_HELLO_MESSAGE_2 + 64;

const _: () = assert!(km43::PAIR_MESSAGE_2 < HANDSHAKE_ANSWER);

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Text a `HelloReport` carries, as the link bounds it.
pub type ReportText = Text<{ km43::MAX_LINK_TEXT }>;

/// Which handshake on which connection a job belongs to. A result whose
/// ticket is not the one the connection is waiting on is discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ticket {
    pub(crate) conn: km43::Conn,
    pub(crate) attempt: u32,
    /// The request the answer echoes (P-026).
    pub(crate) req_id: km43::ReqId,
}

/// Bytes a job carries, and how many of them are meant.
#[derive(Clone, Copy)]
pub(crate) struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Bytes<N> {
    /// `source`, or nothing if it does not fit.
    pub(crate) fn copied(source: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; N];
        bytes.get_mut(..source.len())?.copy_from_slice(source);
        Some(Self {
            bytes,
            len: source.len(),
        })
    }

    fn written(write: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<Self> {
        let mut bytes = [0u8; N];
        let len = write(&mut bytes)?;
        (len <= N).then_some(Self { bytes, len })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// What a `Hello 0x81`'s report says that the worker cannot know: taken
/// when the `Hello` was queued, so the answer describes the controller as
/// it was when the client asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) session: km43::SessionId,
    pub(crate) fw_controller: ReportText,
    pub(crate) fw_comms: ReportText,
    pub(crate) log: crate::LogSpan,
    pub(crate) time_known: bool,
    pub(crate) client_id: ClientId,
    pub(crate) generation: Generation,
}

/// A handshake step too slow for the control loop's executor.
///
/// No `Debug`: it holds the draws the step will turn into keys.
pub struct Job {
    ticket: Ticket,
    task: Task,
}

impl Job {
    pub(crate) const fn new(ticket: Ticket, task: Task) -> Self {
        Self { ticket, task }
    }

    /// Which handshake it belongs to.
    #[must_use]
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
}

pub(crate) enum Task {
    /// Pairing message 1 opened, the window was open and P-240 would
    /// allocate: message 2, which costs a key generation and two DHs.
    Proceed {
        frame: Bytes<HANDSHAKE_FRAME>,
        prologue: Prologue,
        ephemeral: Entropy,
    },
    /// Message 3, then the admission key the slot will hold (P-238): two
    /// DHs, then a third.
    Enrol {
        frame: Bytes<HANDSHAKE_FRAME>,
        awaiting: EnrolAwaiting,
    },
    /// A `Hello` a slot's admission key vouched for: `es`, `ss`, a key
    /// generation, `ee` and `se`.
    Hello {
        frame: Bytes<HANDSHAKE_FRAME>,
        prologue: Prologue,
        admit: [u8; KEY_BYTES],
        enrolled: PublicKey,
        suite: Suite,
        ephemeral: Entropy,
        report: Report,
    },
}

/// A job's result, to hand back to the sessions.
///
/// No `Debug`: it holds a session's keys or a pairing's.
pub struct Done {
    ticket: Ticket,
    pub(crate) result: Computed,
}

impl Done {
    /// Which handshake it belongs to.
    #[must_use]
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
}

pub(crate) enum Computed {
    /// Message 2 is written; the controller waits for message 3.
    Proceeded {
        awaiting: EnrolAwaiting,
        answer: Bytes<HANDSHAKE_ANSWER>,
    },
    /// Message 3 opened: the client key it proved, the admission key for its
    /// slot, and the keys the answer is sealed under.
    Enrolled {
        enrolling: Enrolling,
        admit: [u8; KEY_BYTES],
    },
    /// `Hello 0x81` is written; the session's keys go with it.
    Bound {
        channel: ControllerChannel,
        answer: Bytes<HANDSHAKE_ANSWER>,
        client_id: ClientId,
        generation: Generation,
    },
    /// A pairing step failed, and the handshake with it.
    PairFailed(PairError),
    /// A `Hello` failed.
    HelloFailed(HelloError),
    /// The frame did not re-read as the one that was queued, or an answer
    /// did not fit: a bug here, never the peer's.
    Unwritable,
}

/// The worker: the controller key and the label, and nothing else.
///
/// No `Debug`: it holds both.
pub struct Agreement {
    controller: StaticKey,
    label: Label,
    device_id: DeviceId,
}

impl Agreement {
    /// The worker for a unit with this secret and this controller key.
    #[must_use]
    pub fn new(secret: &Secret, controller: &ControllerKey) -> Self {
        Self {
            controller: controller.key(),
            label: secret.label(),
            device_id: secret.device_id(),
        }
    }

    /// Run one job. Deterministic, and long: call it where nothing else
    /// waits on it.
    #[must_use]
    pub fn run(&self, job: Job) -> Done {
        let Job { ticket, task } = job;
        let result = match task {
            Task::Proceed {
                frame,
                prologue,
                ephemeral,
            } => self.proceed(frame.as_slice(), &prologue, ephemeral),
            Task::Enrol { frame, awaiting } => self.enrol(frame.as_slice(), awaiting),
            Task::Hello {
                frame,
                prologue,
                admit,
                enrolled,
                suite,
                ephemeral,
                report,
            } => self.hello(
                frame.as_slice(),
                &prologue,
                (&AdmitKey::from_stored(admit), &enrolled, suite),
                ephemeral,
                &report,
            ),
        };
        Done { ticket, result }
    }

    /// Message 1 is opened again, which costs one HKDF chain and a tag, and
    /// message 2 written.
    fn proceed(&self, frame: &[u8], prologue: &Prologue, ephemeral: Entropy) -> Computed {
        let Ok(envelope) = Envelope::decode(frame) else {
            return Computed::Unwritable;
        };
        let mut offer = [0u8; km43::MAX_PAIR_OFFER];
        let offered = match PairArrival::decode(envelope)
            .and_then(|arrival| arrival.open(prologue, &self.label.pair_psk(), &mut offer))
        {
            Ok(offered) => offered,
            Err(why) => return Computed::PairFailed(why),
        };
        let mut awaiting = None;
        let answer = Bytes::written(|dst| {
            let (waiting, len) = offered.proceed(&self.controller, ephemeral, dst).ok()?;
            awaiting = Some(waiting);
            Some(len)
        });
        match (awaiting, answer) {
            (Some(awaiting), Some(answer)) => Computed::Proceeded { awaiting, answer },
            (Some(_) | None, Some(_) | None) => Computed::Unwritable,
        }
    }

    /// Message 3 opened, then the slot's admission key: `X25519(cs, IS)`,
    /// which refuses a low-order client key (P-228).
    fn enrol(&self, frame: &[u8], awaiting: EnrolAwaiting) -> Computed {
        let Ok(envelope) = Envelope::decode(frame) else {
            return Computed::Unwritable;
        };
        let enrolling = match awaiting.read(envelope) {
            Ok(enrolling) => enrolling,
            Err(why) => return Computed::PairFailed(why),
        };
        match self
            .controller
            .admit_key(self.device_id, &enrolling.client())
        {
            Ok(admit) => Computed::Enrolled {
                enrolling,
                admit: *admit.to_stored(),
            },
            Err(why) => Computed::PairFailed(PairError::from(why)),
        }
    }

    /// The `Hello` read again under the one admission key that matched
    /// (one HMAC), proved, and answered.
    fn hello(
        &self,
        frame: &[u8],
        prologue: &Prologue,
        slot: (&AdmitKey, &PublicKey, Suite),
        ephemeral: Entropy,
        report: &Report,
    ) -> Computed {
        let (admit, enrolled, suite) = slot;
        let Ok(envelope) = Envelope::decode(frame) else {
            return Computed::Unwritable;
        };
        let mut offer = [0u8; km43::MAX_HELLO_OFFER];
        let proved = HelloArrival::decode(envelope)
            .and_then(|arrival| arrival.admit(prologue, [((), admit)]))
            .and_then(|admitted| {
                admitted.prove(prologue, &self.controller, (enrolled, suite), &mut offer)
            });
        let proved = match proved {
            Ok(proved) => proved,
            Err(why) => return Computed::HelloFailed(why),
        };
        let version = match Version::V1_0.agreed(proved.offer().version) {
            Ok(version) => version,
            Err(why) => return Computed::HelloFailed(HelloError::Report(why)),
        };
        let written = HelloReport {
            version,
            session: report.session,
            fw_controller: report.fw_controller.as_str(),
            fw_comms: report.fw_comms.as_str(),
            capabilities: 1 << 8,
            log_oldest_seq: report.log.oldest,
            log_newest_seq: report.log.newest,
            // The state store does not exist yet; its counter starts here.
            state_seq: km43::StateSeq(0),
            time_known: report.time_known,
            caps: km43::Caps::THIS_CONTROLLER,
            topology: km43::Topology::THIS_CONTROLLER,
            client_id: report.client_id,
            generation: report.generation,
        };
        let mut channel = None;
        let mut failed = None;
        let answer = Bytes::written(|dst| match proved.reply(ephemeral, &written, dst) {
            Ok((keys, len)) => {
                channel = Some(keys);
                Some(len)
            }
            Err(why) => {
                failed = Some(why);
                None
            }
        });
        match (channel, answer, failed) {
            (Some(channel), Some(answer), _) => Computed::Bound {
                channel,
                answer,
                client_id: report.client_id,
                generation: report.generation,
            },
            (_, _, Some(why)) => Computed::HelloFailed(why),
            (Some(_) | None, Some(_) | None, None) => Computed::Unwritable,
        }
    }
}
