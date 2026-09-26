//! `firmwares/frozen-watchdog.sh`, run against a fake `probe-rs` that logs
//! its arguments: the IWDG freeze a controller flash sets is cleared however
//! the flash ends, and a flash never runs with the freeze unset (#125); the
//! vector catches a probe session leaves armed are disarmed before the
//! command and after it (#155).

use std::fmt;
use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const FREEZE: &str = "write --chip STM32G0B1RETx b32 0x40015808 0x1000";
const THAW: &str = "write --chip STM32G0B1RETx b32 0x40015808 0";
const DISARM: &str = "write --chip STM32G0B1RETx b32 0xE000EDFC 0";

/// How long the script may take, from its spawn, to have its command
/// running with the command's TERM trap in place (#200). The script runs
/// two probe calls and starts a third. On an M2 Max, 750 starts in four
/// runs, at load averages from 8 to about 160 and one run beside three cold
/// workspace builds, took 1.08 s at most. This is ten times that, and twice
/// the 5 s wait that ran out once in #200 for a cause not reproduced. A
/// script that exits fails at once, so the budget only bounds a hang.
const STARTUP_BUDGET: Duration = Duration::from_secs(10);

/// How long the script may take to end once signalled: the command stopped,
/// the watchdog thawed and the catches disarmed (#133, #169). Timed from
/// the signal, so a slow start never spends it.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(5);

/// How often the start is looked at.
const POLL: Duration = Duration::from_millis(10);

/// How long a killed group's orphans may take to be reaped by init.
const REAP_BOUND: Duration = Duration::from_secs(2);

/// A directory holding the fake `probe-rs` and the log of its calls.
struct Bench {
    dir: PathBuf,
}

impl Bench {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("o89-frozen-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        // Fails when its arguments end in $FAKE_FAIL; runs until stopped,
        // as `probe-rs run` does, when they end in $FAKE_SLEEP, and logs
        // `stopped` when a signal ends it, stopping its own sleep. Logs
        // every call first. A run sleeps $FAKE_STALL seconds between its log
        // line and its trap, and creates $FAKE_READY once the trap is in
        // place.
        let fake = "#!/bin/sh\n\
            echo \"$*\" >> \"$FAKE_LOG\"\n\
            case \"$*\" in *\"$FAKE_SLEEP\") [ -n \"$FAKE_SLEEP\" ] && [ -n \"$FAKE_STALL\" ] && sleep \"$FAKE_STALL\";; esac\n\
            trap 'kill $! 2>/dev/null; echo stopped >> \"$FAKE_LOG\"; exit 143' TERM\n\
            case \"$*\" in *\"$FAKE_SLEEP\") [ -n \"$FAKE_SLEEP\" ] && { : > \"$FAKE_READY\"; sleep 60 & wait $!; };; esac\n\
            case \"$*\" in *\"$FAKE_FAIL\") [ -n \"$FAKE_FAIL\" ] && exit 3;; esac\n\
            exit 0\n";
        let path = dir.join("probe-rs");
        fs::write(&path, fake).expect("the fake probe-rs");
        let status = Command::new("chmod")
            .arg("+x")
            .arg(&path)
            .status()
            .expect("chmod");
        assert!(status.success());
        Self { dir }
    }

    fn command(&self, fail: &str, sleep: &str, args: &[&str]) -> Command {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../firmwares/frozen-watchdog.sh");
        let path = std::env::var("PATH").unwrap_or_default();
        let mut command = Command::new(script);
        command
            .args(args)
            .env("PATH", format!("{}:{path}", self.dir.display()))
            .env("FAKE_LOG", self.log_path())
            .env("FAKE_FAIL", fail)
            .env("FAKE_SLEEP", sleep)
            .env("FAKE_STALL", "")
            .env("FAKE_READY", self.ready_path());
        command
    }

    fn run(&self, fail: &str, args: &[&str]) -> ExitStatus {
        self.command(fail, "", args)
            .status()
            .expect("the script runs")
    }

    /// Starts `probe-rs run image` through the script, in a process group
    /// of its own so that everything it starts can be killed at once.
    fn launch(&self, fail: &str, stall: &str) -> Launched<'_> {
        let stderr = File::create(self.dir.join("stderr")).expect("the script's stderr");
        let child = self
            .command(fail, "image", &["probe-rs", "run", "image"])
            .env("FAKE_STALL", stall)
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .expect("the script starts");
        Launched {
            bench: self,
            child,
            spawned: Instant::now(),
        }
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("calls.log")
    }

    fn ready_path(&self) -> PathBuf {
        self.dir.join("ready")
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.log_path())
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// What one look at a starting script found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Pending,
    Ready,
    Exited(ExitStatus),
}

/// How a start ended, and how long after the spawn it was seen to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Startup {
    Ready(Duration),
    Failed(Cause, Duration),
}

/// Why a start never reached readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    Exited(ExitStatus),
    NeverReady,
}

/// Looks at a start until it is ready, has exited, or has used `budget`.
/// The clock is read before each look, so readiness seen at the budget
/// counts; the loop ends at most one `pause` after the budget.
fn await_startup(
    budget: Duration,
    mut elapsed: impl FnMut() -> Duration,
    mut probe: impl FnMut() -> Probe,
    mut pause: impl FnMut(),
) -> Startup {
    loop {
        let now = elapsed();
        match probe() {
            Probe::Ready => return Startup::Ready(now),
            Probe::Exited(status) => return Startup::Failed(Cause::Exited(status), now),
            Probe::Pending if now >= budget => return Startup::Failed(Cause::NeverReady, now),
            Probe::Pending => pause(),
        }
    }
}

/// A start that did not reach readiness, with what the script did.
#[derive(Debug)]
struct StartupFailure {
    cause: Cause,
    after: Duration,
    calls: Vec<String>,
    stderr: String,
}

impl fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let after = self.after;
        match self.cause {
            Cause::Exited(status) => write!(
                f,
                "the script ended with {status} after {after:?}, before its command was ready"
            )?,
            Cause::NeverReady => write!(f, "the command was not ready after {after:?}")?,
        }
        write!(f, "; calls {:?}; stderr {:?}", self.calls, self.stderr)
    }
}

/// The script, spawned. Dropping it terminates it, before the bench it
/// borrows removes their directory.
struct Launched<'a> {
    bench: &'a Bench,
    child: Child,
    spawned: Instant,
}

impl Launched<'_> {
    /// Waits for the command to be ready for a signal, or says why not.
    fn ready(&mut self, budget: Duration) -> Result<Duration, StartupFailure> {
        let ready_path = self.bench.ready_path();
        let spawned = self.spawned;
        let child = &mut self.child;
        let startup = await_startup(
            budget,
            || spawned.elapsed(),
            || match child.try_wait().expect("the script's status") {
                Some(status) => Probe::Exited(status),
                None if ready_path.exists() => Probe::Ready,
                None => Probe::Pending,
            },
            || std::thread::sleep(POLL),
        );
        match startup {
            Startup::Ready(after) => Ok(after),
            Startup::Failed(cause, after) => Err(StartupFailure {
                cause,
                after,
                calls: self.bench.calls(),
                stderr: fs::read_to_string(self.bench.dir.join("stderr")).unwrap_or_default(),
            }),
        }
    }

    /// The script leads its own group, so its pid names the group.
    fn pgid(&self) -> u32 {
        self.child.id()
    }

    /// Kills the script's process group and reaps the script, waiting at
    /// most `REAP_BOUND` for it. A script already reaped is left alone: its
    /// group id may since name someone else's group.
    fn terminate(&mut self) {
        if !matches!(self.child.try_wait(), Ok(None)) {
            return;
        }
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.pgid())])
            .stderr(Stdio::null())
            .status();
        let started = Instant::now();
        while matches!(self.child.try_wait(), Ok(None)) && started.elapsed() < REAP_BOUND {
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Launched<'_> {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Whether any process of group `pgid` is left, once init has had
/// `REAP_BOUND` to reap the orphans of a kill.
fn group_survives(pgid: u32) -> bool {
    let started = Instant::now();
    loop {
        let alive = Command::new("kill")
            .args(["-0", "--", &format!("-{pgid}")])
            .stderr(Stdio::null())
            .status()
            .expect("kill")
            .success();
        if !alive || started.elapsed() >= REAP_BOUND {
            return alive;
        }
        std::thread::sleep(POLL);
    }
}

#[test]
fn a_flash_runs_between_the_freeze_and_the_thaw() {
    let bench = Bench::new("order");
    let status = bench.run("", &["probe-rs", "download", "image"]);
    assert!(status.success());
    assert_eq!(
        bench.calls(),
        [DISARM, FREEZE, "download image", THAW, DISARM]
    );
}

#[test]
fn a_failed_flash_still_thaws_the_watchdog_and_keeps_its_status() {
    let bench = Bench::new("failed");
    let status = bench.run("image", &["probe-rs", "download", "image"]);
    assert_eq!(status.code(), Some(3));
    assert_eq!(
        bench.calls(),
        [DISARM, FREEZE, "download image", THAW, DISARM]
    );
}

#[test]
fn a_freeze_that_fails_flashes_nothing() {
    let bench = Bench::new("no-freeze");
    let status = bench.run("0x1000", &["probe-rs", "download", "image"]);
    assert!(!status.success());
    assert_eq!(bench.calls(), [DISARM, FREEZE]);
}

#[test]
fn a_thaw_that_fails_fails_a_flash_that_worked() {
    let bench = Bench::new("no-thaw");
    let status = bench.run("0x40015808 0", &["probe-rs", "download", "image"]);
    assert_eq!(status.code(), Some(1));
    assert_eq!(
        bench.calls(),
        [DISARM, FREEZE, "download image", THAW, DISARM]
    );
}

#[test]
fn a_reset_runs_only_once_the_vector_catches_are_disarmed() {
    let bench = Bench::new("reset");
    let status = bench.run("", &["probe-rs", "reset"]);
    assert!(status.success());
    assert_eq!(bench.calls(), [DISARM, FREEZE, "reset", THAW, DISARM]);
}

#[test]
fn a_disarm_that_fails_runs_nothing() {
    let bench = Bench::new("no-disarm");
    let status = bench.run("0xE000EDFC 0", &["probe-rs", "reset"]);
    assert!(!status.success());
    assert_eq!(bench.calls(), [DISARM]);
}

/// Signals the script once its command runs with its trap in place, as
/// `probe-rs run` does until it is stopped, and returns the exit status and
/// how long the script took to end after the signal. `stall` delays the
/// command between its log line and its trap, and extends the budget.
/// The script sets its own INT and TERM traps just after it starts the
/// command, which nothing outside it can see.
fn interrupt(name: &str, signal: &str, stall: Duration) -> (Option<i32>, Duration, Vec<String>) {
    let bench = Bench::new(name);
    let stall_secs = if stall.is_zero() {
        String::new()
    } else {
        stall.as_secs().to_string()
    };
    let mut launched = bench.launch("", &stall_secs);
    if let Err(failure) = launched.ready(STARTUP_BUDGET.saturating_add(stall)) {
        panic!("{failure}");
    }
    let signalled = Instant::now();
    let kill = Command::new("kill")
        .args([signal, &launched.child.id().to_string()])
        .status()
        .expect("kill");
    assert!(kill.success());
    let status = launched.child.wait().expect("the script ends");
    let took = signalled.elapsed();
    assert!(
        !group_survives(launched.pgid()),
        "the command outlived the script"
    );
    (status.code(), took, bench.calls())
}

#[test]
fn a_terminated_run_is_stopped_before_the_watchdog_thaws() {
    let (code, took, calls) = interrupt("terminated", "-TERM", Duration::ZERO);
    assert_eq!(code, Some(143));
    assert!(took < SHUTDOWN_BOUND, "the script waited {took:?}");
    assert_eq!(
        calls,
        [DISARM, FREEZE, "run image", "stopped", THAW, DISARM]
    );
}

#[test]
fn an_interrupted_run_is_stopped_before_the_watchdog_thaws() {
    let (code, took, calls) = interrupt("interrupted", "-INT", Duration::ZERO);
    assert_eq!(code, Some(130));
    assert!(took < SHUTDOWN_BOUND, "the script waited {took:?}");
    assert_eq!(
        calls,
        [DISARM, FREEZE, "run image", "stopped", THAW, DISARM]
    );
}

#[test]
fn a_command_slow_to_trap_is_signalled_only_once_it_has() {
    // Longer than the shutdown bound, which a slow start must not spend.
    let stall = SHUTDOWN_BOUND.saturating_add(Duration::from_secs(1));
    let (code, took, calls) = interrupt("slow", "-TERM", stall);
    assert_eq!(code, Some(143));
    assert!(took < SHUTDOWN_BOUND, "the script waited {took:?}");
    assert_eq!(
        calls,
        [DISARM, FREEZE, "run image", "stopped", THAW, DISARM]
    );
}

#[test]
fn a_script_that_ends_before_its_command_fails_at_once_and_says_how() {
    let bench = Bench::new("early-exit");
    let mut launched = bench.launch("0x1000", "");
    let failure = launched
        .ready(STARTUP_BUDGET)
        .expect_err("the freeze failed, so nothing ran");
    let Cause::Exited(status) = failure.cause else {
        panic!("{failure}");
    };
    assert_eq!(status.code(), Some(3));
    assert!(failure.after < STARTUP_BUDGET, "{failure}");
    assert_eq!(failure.calls, [DISARM, FREEZE]);
    let message = failure.to_string();
    assert!(message.contains("exit status: 3"), "{message}");
    assert!(message.contains(FREEZE), "{message}");
    launched.terminate();
    assert!(!group_survives(launched.pgid()));
}

#[test]
fn a_command_never_ready_fails_at_its_budget_and_leaves_nothing_running() {
    let bench = Bench::new("never-ready");
    let mut launched = bench.launch("", "60");
    // The budget runs out half a second after the command logs its call,
    // however long the script took to get there.
    while !bench.calls().iter().any(|call| call == "run image") {
        assert!(
            launched.spawned.elapsed() < STARTUP_BUDGET,
            "the command never ran: {:?}",
            bench.calls()
        );
        std::thread::sleep(POLL);
    }
    let budget = launched
        .spawned
        .elapsed()
        .saturating_add(Duration::from_millis(500));
    let failure = launched
        .ready(budget)
        .expect_err("the command stalls before its trap");
    assert_eq!(failure.cause, Cause::NeverReady, "{failure}");
    // A look and a pause past the budget, with room for a loaded host.
    let prompt = budget.saturating_add(Duration::from_secs(2));
    assert!(
        failure.after >= budget && failure.after < prompt,
        "{failure}"
    );
    assert_eq!(failure.calls, [DISARM, FREEZE, "run image"]);
    assert!(failure.to_string().contains("not ready"), "{failure}");
    launched.terminate();
    assert!(!group_survives(launched.pgid()));
}

/// A clock that moves one `POLL` per reading, and a probe that answers
/// from a script of looks, `Pending` once the script runs out.
fn scripted(looks: &[Probe], budget: Duration) -> (Startup, usize) {
    let mut ticks = 0_u32;
    let mut pauses = 0_usize;
    let mut looks = looks.iter().copied();
    let startup = await_startup(
        budget,
        || {
            let now = POLL.saturating_mul(ticks);
            ticks = ticks.saturating_add(1);
            now
        },
        || looks.next().unwrap_or(Probe::Pending),
        || pauses = pauses.saturating_add(1),
    );
    (startup, pauses)
}

/// A status that exited with code 1, as `wait` encodes it.
fn exited_with_1() -> ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(0x100)
}

#[test]
fn a_ready_start_is_seen_on_the_first_look() {
    assert_eq!(
        scripted(&[Probe::Ready], STARTUP_BUDGET),
        (Startup::Ready(Duration::ZERO), 0)
    );
}

#[test]
fn a_start_ready_at_its_budget_is_ready() {
    let looks = [Probe::Pending, Probe::Pending, Probe::Pending, Probe::Ready];
    assert_eq!(scripted(&looks, POLL * 3), (Startup::Ready(POLL * 3), 3));
}

#[test]
fn a_start_that_exits_ends_the_wait_with_its_status() {
    let looks = [Probe::Pending, Probe::Exited(exited_with_1())];
    assert_eq!(
        scripted(&looks, STARTUP_BUDGET),
        (Startup::Failed(Cause::Exited(exited_with_1()), POLL), 1)
    );
}

#[test]
fn a_start_never_ready_ends_at_its_budget() {
    assert_eq!(
        scripted(&[], POLL * 3),
        (Startup::Failed(Cause::NeverReady, POLL * 3), 3)
    );
}
