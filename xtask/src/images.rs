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
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::repo::{CORTEX_M0, RISCV, Repo, llvm_tool, run};

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
        let elf = build(repo, image)?;
        let bytes = measure(image, &elf)?;
        out.push(Measured {
            package: image.package,
            bytes,
            budget: image.budget,
            margin: image.margin,
        });
    }
    Ok(out)
}

fn build(repo: &Repo, image: &Image) -> Result<PathBuf> {
    let manifest = repo.firmware_manifest();
    let mut command = repo.cargo();
    command.args(["build", "--locked", "--release", "--manifest-path"]);
    command.arg(&manifest);
    command.args(["-p", image.package, "--target", image.target]);
    run(
        &mut command,
        &format!(
            "cargo build --release -p {} --target {}",
            image.package, image.target
        ),
    )?;
    let elf = repo
        .firmware_target_dir()
        .join(image.target)
        .join("release")
        .join(image.package);
    if !elf.is_file() {
        bail!(
            "{} built but produced no ELF at {}",
            image.package,
            elf.display()
        );
    }
    Ok(elf)
}

fn measure(image: &Image, elf: &PathBuf) -> Result<u64> {
    let bin = elf.with_extension("bin");
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
pub fn record(repo: &Repo, measured: &[Measured]) -> Result<()> {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo.root())
        .output()
        .context("running git rev-parse")?;
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
