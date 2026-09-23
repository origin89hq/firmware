//! Build the three images in release and measure what reaches the part.
//!
//! The number is the `.bin`, never the ELF: an ELF here is mostly DWARF, which
//! stays on the laptop, and reading `ls -l` on it reports an image four times
//! the flash it goes into. The controller's budget is one dual-bank slot less
//! the bootloader's 8 KB, which is 248 KB and not the part's 512; a firmware
//! that fits the part and not the slot builds, flashes, ships, and fails its
//! first update in a cabin.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use cargo_metadata::Artifact;

use crate::repo::{CORTEX_M0, RISCV, Repo, artifacts, llvm_tool, run, sysroot};

/// How the bytes that reach the part are produced from the ELF.
#[derive(Clone, Copy)]
enum Kind {
    /// `llvm-objcopy -O binary`: the flash contents exactly.
    RawBinary,
    /// `espflash save-image`: the ESP-IDF application image the bootloader
    /// loads, header and segments included.
    EspAppImage,
}

/// One image the gate builds.
struct Image {
    package: &'static str,
    target: &'static str,
    kind: Kind,
    /// The slot the image has to fit, in bytes.
    budget: u64,
    /// The margin under the budget the gate insists on, in bytes. The slot is
    /// full at the budget; the gate refuses earlier so that the release that
    /// crosses the line is the one being reviewed, not the one already flashed.
    margin: u64,
}

const KIB: u64 = 1024;

/// The three images, their targets and their budgets.
///
/// The comms budget is the OTA slot the partition table will give it; the
/// table is settled in M3 and this number moves with it.
const IMAGES: &[Image] = &[
    Image {
        package: "o89-boot",
        target: CORTEX_M0,
        kind: Kind::RawBinary,
        budget: 8 * KIB,
        margin: KIB,
    },
    Image {
        package: "o89-controller",
        target: CORTEX_M0,
        kind: Kind::RawBinary,
        budget: 248 * KIB,
        margin: 24 * KIB,
    },
    Image {
        package: "o89-comms",
        target: RISCV,
        kind: Kind::EspAppImage,
        budget: 2 * KIB * KIB,
        margin: 200 * KIB,
    },
];

/// A measured image.
pub struct Measured {
    package: &'static str,
    bytes: u64,
    budget: u64,
    margin: u64,
}

impl Measured {
    fn percent(&self) -> u64 {
        self.bytes
            .saturating_mul(100)
            .checked_div(self.budget)
            .unwrap_or(u64::MAX)
    }
}

/// Build every image in release and measure it.
pub fn build_and_measure(repo: &Repo) -> Result<Vec<Measured>> {
    let mut out = Vec::with_capacity(IMAGES.len());
    for image in IMAGES {
        let built = build(repo, image)?;
        let elf = built
            .iter()
            .filter(|artifact| artifact.target.name == image.package)
            .find_map(|artifact| artifact.executable.as_deref())
            .with_context(|| format!("{} built but reported no executable", image.package))?;
        let bytes = measure(image, elf.as_std_path())?;
        out.push(Measured {
            package: image.package,
            bytes,
            budget: image.budget,
            margin: image.margin,
        });
    }
    Ok(out)
}

/// Build every image in release and return what those builds compiled.
pub fn compile(repo: &Repo) -> Result<Vec<Artifact>> {
    let mut built = Vec::new();
    for image in IMAGES {
        built.extend(build(repo, image)?);
    }
    Ok(built)
}

/// Where the build machine's paths go in an image (#74).
///
/// A panic's location is `file!()`, which for this checkout's `crates/`, the
/// registry and the standard library is an absolute path, so without this
/// the bytes and the size of an image depend on where it was built, and the
/// panic handler's hash of the file names the machine as well as the file.
/// Every image is measured and flashed from this build, so this is the one
/// place the flags are set; each prefix maps to a fixed one.
fn remapped(root: &Path, cargo_home: &Path, sysroot: &Path) -> Result<String> {
    let pairs = [(root, "/o89"), (cargo_home, "/cargo"), (sysroot, "/rustc")];
    let mut flags = Vec::with_capacity(pairs.len());
    for (from, to) in pairs {
        let from = from
            .to_str()
            .with_context(|| format!("{} is not UTF-8", from.display()))?;
        flags.push(format!("--remap-path-prefix={from}={to}"));
    }
    // `CARGO_ENCODED_RUSTFLAGS` separates by 0x1f, so a path with a space
    // survives; with `--target` it reaches the image and not build scripts.
    Ok(flags.join("\u{1f}"))
}

/// Cargo's home, where the registry's sources are unpacked.
fn cargo_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var_os("HOME").context("neither CARGO_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".cargo"))
}

fn build(repo: &Repo, image: &Image) -> Result<Vec<Artifact>> {
    let manifest = repo.firmware_manifest();
    let mut command = repo.cargo();
    command.env(
        "CARGO_ENCODED_RUSTFLAGS",
        remapped(repo.root(), &cargo_home()?, &sysroot()?)?,
    );
    command.args(["build", "--locked", "--release", "--manifest-path"]);
    command.arg(&manifest);
    command.args(["-p", image.package, "--target", image.target]);
    artifacts(
        &mut command,
        &format!(
            "cargo build --release -p {} --target {}",
            image.package, image.target
        ),
    )
}

fn measure(image: &Image, elf: &Path) -> Result<u64> {
    let bin: PathBuf = elf.with_extension("bin");
    match image.kind {
        Kind::RawBinary => {
            let objcopy = llvm_tool("llvm-objcopy")?;
            let mut command = Command::new(objcopy);
            command.args(["-O", "binary"]).arg(elf).arg(&bin);
            run(
                &mut command,
                &format!("llvm-objcopy -O binary {}", image.package),
            )?;
        }
        Kind::EspAppImage => {
            let mut command = Command::new("espflash");
            command
                .args(["save-image", "--chip", "esp32c6"])
                .arg(elf)
                .arg(&bin);
            run(
                &mut command,
                &format!(
                    "espflash save-image {} (install with `cargo install espflash --locked`)",
                    image.package
                ),
            )?;
        }
    }
    let bytes = fs::metadata(&bin)
        .with_context(|| format!("measuring {}", bin.display()))?
        .len();
    Ok(bytes)
}

/// Print the table.
pub fn report(measured: &[Measured]) {
    println!(
        "{:<16} {:>10} {:>10} {:>5}",
        "image", "bytes", "budget", "used"
    );
    for m in measured {
        println!(
            "{:<16} {:>10} {:>10} {:>4}%",
            m.package,
            m.bytes,
            m.budget,
            m.percent()
        );
    }
}

/// Refuse an image inside its margin.
pub fn enforce(measured: &[Measured]) -> Result<()> {
    for m in measured {
        let limit = m.budget.saturating_sub(m.margin);
        if m.bytes > limit {
            bail!(
                "{} is {} bytes, over the {}-byte line ({} budget less a {} margin)",
                m.package,
                m.bytes,
                limit,
                m.budget,
                m.margin
            );
        }
    }
    Ok(())
}

/// Append a row per image to `docs/sizes.tsv`, with the commit it measures.
///
/// Run on `main` after a merge: a branch's commits are rewritten by the
/// squash, and a row naming one of them names nothing afterwards.
pub fn record(repo: &Repo, measured: &[Measured]) -> Result<()> {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo.root())
        .output()
        .context("running git rev-parse")?;
    if !sha.status.success() {
        bail!(
            "git rev-parse failed ({}): a row with no commit is a row nobody can trace",
            sha.status
        );
    }
    let sha = String::from_utf8(sha.stdout).context("git output is not UTF-8")?;
    let path = repo.root().join("docs").join("sizes.tsv");
    let mut rows = String::new();
    if !path.exists() {
        rows.push_str("commit\timage\tbytes\tbudget\n");
    }
    for m in measured {
        writeln!(
            rows,
            "{}\t{}\t{}\t{}",
            sha.trim(),
            m.package,
            m.bytes,
            m.budget
        )
        .context("formatting a row")?;
    }
    let mut existing = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
    } else {
        String::new()
    };
    existing.push_str(&rows);
    fs::write(&path, existing).with_context(|| format!("writing {}", path.display()))?;
    println!("recorded in {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    #[test]
    fn each_build_path_maps_to_a_fixed_prefix_in_one_flag_each() {
        let flags = remapped(
            Path::new("/home/a/firmware"),
            Path::new("/home/a/.cargo"),
            Path::new("/home/a/.rustup/toolchains/1.98.1"),
        )
        .expect("UTF-8 paths");
        let flags: Vec<&str> = flags.split('\u{1f}').collect();
        assert_eq!(
            flags,
            [
                "--remap-path-prefix=/home/a/firmware=/o89",
                "--remap-path-prefix=/home/a/.cargo=/cargo",
                "--remap-path-prefix=/home/a/.rustup/toolchains/1.98.1=/rustc",
            ]
        );
    }

    #[test]
    fn a_checkout_path_with_a_space_stays_one_flag() {
        let flags = remapped(
            Path::new("/Users/a b/firmware"),
            Path::new("/c"),
            Path::new("/s"),
        )
        .expect("UTF-8 paths");
        assert_eq!(
            flags.split('\u{1f}').next(),
            Some("--remap-path-prefix=/Users/a b/firmware=/o89")
        );
    }

    #[test]
    fn a_path_that_is_not_utf_8_is_refused_rather_than_mangled() {
        let bad = Path::new(OsStr::from_bytes(b"/home/\xff/firmware"));
        let error = remapped(bad, Path::new("/c"), Path::new("/s")).expect_err("refused");
        assert!(format!("{error:#}").contains("is not UTF-8"), "{error:#}");
    }
}
