//! `firmwares/boot-matches.sh`, run against a fake `probe-rs` whose `read`
//! writes a given file where it was asked to: a controller flash goes ahead
//! only onto a part whose bootloader is byte for byte the built one (#185).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A directory holding the fake `probe-rs`, the bytes it reads back and the
/// built bootloader.
struct Bench {
    dir: PathBuf,
}

impl Bench {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("o89-boot-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        // Logs its arguments, fails when $FAKE_FAIL is set, and otherwise
        // copies $FAKE_PART to the path after `--output`.
        let fake = "#!/bin/sh\n\
            echo \"$*\" >> \"$FAKE_LOG\"\n\
            [ -n \"$FAKE_FAIL\" ] && exit 3\n\
            while [ $# -gt 0 ]; do\n\
              if [ \"$1\" = --output ]; then cp \"$FAKE_PART\" \"$2\"; fi\n\
              shift\n\
            done\n\
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

    /// The script, with `built` as the checkout's bootloader and `part` as
    /// what the part reads back.
    fn run(&self, built: Option<&[u8]>, part: &[u8], fail: bool) -> Output {
        let bin = self.dir.join("o89-boot.bin");
        if let Some(built) = built {
            fs::write(&bin, built).expect("the built bootloader");
        }
        let read_back = self.dir.join("part.bin");
        fs::write(&read_back, part).expect("the part's bytes");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../firmwares/boot-matches.sh");
        let path = std::env::var("PATH").unwrap_or_default();
        Command::new(script)
            .arg(&bin)
            .env("PATH", format!("{}:{path}", self.dir.display()))
            .env("FAKE_LOG", self.dir.join("calls.log"))
            .env("FAKE_PART", &read_back)
            .env("FAKE_FAIL", if fail { "1" } else { "" })
            .output()
            .expect("the script runs")
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The start of a bootloader: a stack pointer and a reset vector.
const BOOT: &[u8] = &[0x00, 0x40, 0x02, 0x20, 0xC1, 0x00, 0x00, 0x08];

#[test]
fn the_built_bootloader_on_the_part_lets_the_flash_go_ahead() {
    let bench = Bench::new("same");
    let out = bench.run(Some(BOOT), BOOT, false);
    assert!(out.status.success(), "{out:?}");
    // It reads exactly the built image's length from the bottom of flash.
    assert!(
        bench.calls().contains("b8 0x08000000 8"),
        "{}",
        bench.calls()
    );
}

#[test]
fn another_bootloader_on_the_part_refuses_the_flash_and_names_the_recipe() {
    let bench = Bench::new("other");
    // The pre-#185 bootloader starts the same and differs later.
    let mut old = BOOT.to_vec();
    if let Some(last) = old.last_mut() {
        *last = 0x09;
    }
    let out = bench.run(Some(BOOT), &old, false);
    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("just flash-boot"), "{error}");
}

#[test]
fn an_erased_part_refuses_the_flash() {
    let bench = Bench::new("erased");
    let out = bench.run(Some(BOOT), &[0xFF; 8], false);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_read_that_fails_refuses_the_flash() {
    let bench = Bench::new("unread");
    let out = bench.run(Some(BOOT), BOOT, true);
    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("could not be read back"), "{error}");
}

#[test]
fn no_built_bootloader_refuses_before_touching_the_probe() {
    let bench = Bench::new("unbuilt");
    let out = bench.run(None, BOOT, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(bench.calls().is_empty(), "{}", bench.calls());
}
