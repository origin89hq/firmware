//! `firmwares/frozen-watchdog.sh`, run against a fake `probe-rs` that logs
//! its arguments: the IWDG freeze a controller flash sets is cleared however
//! the flash ends, and a flash never runs with the freeze unset (#125).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

const FREEZE: &str = "write --chip STM32G0B1RETx b32 0x40015808 0x1000";
const THAW: &str = "write --chip STM32G0B1RETx b32 0x40015808 0";

/// A directory holding the fake `probe-rs` and the log of its calls.
struct Bench {
    dir: PathBuf,
}

impl Bench {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("o89-frozen-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        // Fails when its arguments end in $FAKE_FAIL, sleeps when they end
        // in $FAKE_SLEEP; logs every call first.
        let fake = "#!/bin/sh\n\
            echo \"$*\" >> \"$FAKE_LOG\"\n\
            case \"$*\" in *\"$FAKE_SLEEP\") [ -n \"$FAKE_SLEEP\" ] && sleep 2;; esac\n\
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
            .env("FAKE_SLEEP", sleep);
        command
    }

    fn run(&self, fail: &str, args: &[&str]) -> ExitStatus {
        self.command(fail, "", args)
            .status()
            .expect("the script runs")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("calls.log")
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

#[test]
fn a_flash_runs_between_the_freeze_and_the_thaw() {
    let bench = Bench::new("order");
    let status = bench.run("", &["probe-rs", "download", "image"]);
    assert!(status.success());
    assert_eq!(bench.calls(), [FREEZE, "download image", THAW]);
}

#[test]
fn a_failed_flash_still_thaws_the_watchdog_and_keeps_its_status() {
    let bench = Bench::new("failed");
    let status = bench.run("image", &["probe-rs", "download", "image"]);
    assert_eq!(status.code(), Some(3));
    assert_eq!(bench.calls(), [FREEZE, "download image", THAW]);
}

#[test]
fn a_freeze_that_fails_flashes_nothing() {
    let bench = Bench::new("no-freeze");
    let status = bench.run("0x1000", &["probe-rs", "download", "image"]);
    assert!(!status.success());
    assert_eq!(bench.calls(), [FREEZE]);
}

#[test]
fn a_thaw_that_fails_fails_a_flash_that_worked() {
    let bench = Bench::new("no-thaw");
    let status = bench.run("0x40015808 0", &["probe-rs", "download", "image"]);
    assert_eq!(status.code(), Some(1));
    assert_eq!(bench.calls(), [FREEZE, "download image", THAW]);
}

#[test]
fn an_interrupted_flash_still_thaws_the_watchdog() {
    let bench = Bench::new("interrupted");
    let mut child = bench
        .command("", "image", &["probe-rs", "download", "image"])
        .spawn()
        .expect("the script starts");
    let started = Instant::now();
    while !bench.calls().iter().any(|call| call == "download image") {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the flash never started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let kill = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(kill.success());
    let status = child.wait().expect("the script ends");
    assert_eq!(status.code(), Some(143));
    assert_eq!(bench.calls(), [FREEZE, "download image", THAW]);
}
