//! Key agreement, on the thread executor and nothing else there (P-243).
//!
//! A `Hello` costs this part about a second and a half of X25519, which
//! cannot be split: each DH is a quarter of a second nobody else runs in if
//! it shares their executor. So every task that times anything runs on the
//! control executor, from an interrupt above thread mode, and this worker
//! is the only thing left below it. A job preempted by the control tick,
//! the link or the rail loses nothing; they never wait for it.
//!
//! The link task hands a job over when the sessions say one is due and
//! takes the result back to answer with it. One of each in flight: the
//! sessions never hand out a second job before the first comes back. The
//! worker holds the controller key and the label, and writes nothing: every
//! FRAM write a handshake needs is the link task's, before it answers.
//!
//! cites: P-243

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, with_timeout};
use o89_core::{Agreement, Done, Job, Task};

use crate::supervisor::check_in;

/// The job the sessions handed out, waiting for the worker.
pub static JOBS: Channel<CriticalSectionRawMutex, Job, 1> = Channel::new();

/// The worker's result, waiting for the link task.
pub static DONE: Channel<CriticalSectionRawMutex, Done, 1> = Channel::new();

/// How long the worker waits for a job before it checks in anyway.
const IDLE: Duration = Duration::from_secs(1);

/// The worker. A unit with no controller key has no worker: the sessions
/// hand out no job without one, and a task that is never spawned is never
/// on the roll.
#[embassy_executor::task]
pub async fn run(agreement: Agreement) {
    loop {
        if let Ok(job) = with_timeout(IDLE, JOBS.receive()).await {
            let done = agreement.run(job);
            check_in(Task::Agreement);
            // No deadline: a result dropped would leave the sessions waiting
            // on it for good. The link takes one every tick, powered or not;
            // a link that stops taking them stops checking in first, and
            // the roll names it.
            DONE.send(done).await;
        }
        check_in(Task::Agreement);
    }
}
