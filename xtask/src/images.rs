//! Build the three images in release and measure what reaches the part.
//!
//! The number is the `.bin`, never the ELF: an ELF here is mostly DWARF, which
//! stays on the laptop, and reading `ls -l` on it reports an image four times
//! the flash it goes into. The controller's budget is one dual-bank slot less
//! the bootloader's 8 KB, which is 248 KB and not the part's 512; a firmware
//! that fits the part and not the slot builds, flashes, ships, and fails its
//! first update in a cabin.

use std::ffi::OsStr;
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

/// What every image is compiled with beyond the environment's flags.
///
/// SHA-256's compact software backend: the same algorithm as the unrolled
/// default, rolled into a loop. On the controller, which has no hash
/// peripheral and hashes at most a frame's worth at a time, the unrolled
/// `compress256` was 9.4 KB of the slot and the loop is 488 bytes. A `cfg`
/// sha2 reads, and only a flag can set it. The recipes that build an image
/// with `cargo run` take the same flags from `cargo xtask rustflags`, so a
/// bench run exercises the backend that ships.
const IMAGE_FLAGS: &[&str] = &["--cfg=sha2_backend_soft=\"compact\""];

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
///
/// `inherited` are the flags the environment already asked for, kept in
/// front. rustc applies the last prefix that matches, so the prefixes go
/// from the shortest to the longest: a checkout inside cargo's home is
/// still mapped to `/o89` and not to `/cargo/...` with its own path after.
fn remapped(
    inherited: &[String],
    root: &Path,
    cargo_home: &Path,
    sysroot: &Path,
) -> Result<String> {
    let mut pairs = [(root, "/o89"), (cargo_home, "/cargo"), (sysroot, "/rustc")];
    pairs.sort_by_key(|(from, _)| from.as_os_str().len());
    let mut flags = inherited.to_vec();
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

/// The flags cargo would have taken from the environment: the encoded
/// form when it is set, as cargo reads it first, else `RUSTFLAGS` split on
/// whitespace.
fn inherited(encoded: Option<&OsStr>, plain: Option<&OsStr>) -> Result<Vec<String>> {
    let text = |value: &OsStr| {
        value
            .to_str()
            .map(str::to_owned)
            .context("the rustflags in the environment are not UTF-8")
    };
    if let Some(encoded) = encoded {
        let encoded = text(encoded)?;
        return Ok(encoded
            .split('\u{1f}')
            .filter(|flag| !flag.is_empty())
            .map(str::to_owned)
            .collect());
    }
    if let Some(plain) = plain {
        return Ok(text(plain)?.split_whitespace().map(str::to_owned).collect());
    }
    Ok(Vec::new())
}

/// Refuse a cargo config that sets `rustflags` for a build run from `root`.
///
/// Cargo takes rustflags from one source, and the environment variable this
/// build sets outranks every config file, so flags written in one would be
/// dropped without a word. None of this repository's configs sets any; one
/// that does is a flag to carry here instead.
fn no_config_rustflags(root: &Path, cargo_home: &Path) -> Result<()> {
    let mut files: Vec<PathBuf> = root
        .ancestors()
        .flat_map(|dir| [dir.join(".cargo/config.toml"), dir.join(".cargo/config")])
        .collect();
    files.push(cargo_home.join("config.toml"));
    files.push(cargo_home.join("config"));
    for file in files.iter().filter(|file| file.is_file()) {
        let text =
            fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        if sets_rustflags(&text).with_context(|| format!("parsing {}", file.display()))? {
            bail!(
                "{} sets rustflags, which the images' remapped build would drop (#74): carry them in xtask/src/images.rs",
                file.display()
            );
        }
    }
    Ok(())
}

/// Whether a cargo config sets `build.rustflags` or any `target.*.rustflags`.
fn sets_rustflags(config: &str) -> Result<bool> {
    let table: toml::Table = config.parse()?;
    let in_build = table
        .get("build")
        .and_then(toml::Value::as_table)
        .is_some_and(|build| build.contains_key("rustflags"));
    let in_target = table
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| {
            targets.values().any(|target| {
                target
                    .as_table()
                    .is_some_and(|target| target.contains_key("rustflags"))
            })
        });
    Ok(in_build || in_target)
}

/// Cargo's home, where the registry's sources are unpacked.
fn cargo_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var_os("HOME").context("neither CARGO_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".cargo"))
}

/// Every flag an image is built with, as `CARGO_ENCODED_RUSTFLAGS` takes
/// them: the environment's, the images' own, then the path remapping.
fn image_flags(
    inherited: &[String],
    root: &Path,
    cargo_home: &Path,
    sysroot: &Path,
) -> Result<String> {
    let mut asked = inherited.to_vec();
    asked.extend(IMAGE_FLAGS.iter().map(|flag| (*flag).to_owned()));
    remapped(&asked, root, cargo_home, sysroot)
}

/// The flags every image is built with here, for the gate's builds and for
/// a recipe that builds an image with `cargo run`: one source, so what a
/// bench flashes is what the gate measured.
pub fn rustflags(repo: &Repo) -> Result<String> {
    let cargo_home = cargo_home()?;
    no_config_rustflags(repo.root(), &cargo_home)?;
    let inherited = inherited(
        std::env::var_os("CARGO_ENCODED_RUSTFLAGS").as_deref(),
        std::env::var_os("RUSTFLAGS").as_deref(),
    )?;
    image_flags(&inherited, repo.root(), &cargo_home, &sysroot()?)
}

fn build(repo: &Repo, image: &Image) -> Result<Vec<Artifact>> {
    let manifest = repo.firmware_manifest();
    let mut command = repo.cargo();
    command.env("CARGO_ENCODED_RUSTFLAGS", rustflags(repo)?);
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
            &[],
            Path::new("/home/a/firmware"),
            Path::new("/home/a/.cargo"),
            Path::new("/home/a/.rustup/toolchains/1.98.1"),
        )
        .expect("UTF-8 paths");
        let flags: Vec<&str> = flags.split('\u{1f}').collect();
        assert_eq!(
            flags,
            [
                "--remap-path-prefix=/home/a/.cargo=/cargo",
                "--remap-path-prefix=/home/a/firmware=/o89",
                "--remap-path-prefix=/home/a/.rustup/toolchains/1.98.1=/rustc",
            ]
        );
    }

    /// rustc takes the last prefix that matches, so a checkout inside cargo's
    /// home or the sysroot has to come after it, or its own path survives
    /// under `/cargo`.
    #[test]
    fn a_checkout_inside_cargos_home_still_maps_to_its_own_prefix() {
        let flags = remapped(
            &[],
            Path::new("/c/checkouts/firmware"),
            Path::new("/c"),
            Path::new("/c/checkouts/firmware/toolchain"),
        )
        .expect("UTF-8 paths");
        let flags: Vec<&str> = flags.split('\u{1f}').collect();
        assert_eq!(
            flags,
            [
                "--remap-path-prefix=/c=/cargo",
                "--remap-path-prefix=/c/checkouts/firmware=/o89",
                "--remap-path-prefix=/c/checkouts/firmware/toolchain=/rustc",
            ]
        );
    }

    /// The images' own flags sit between the environment's and the remapping,
    /// so a bench build asked for through `cargo xtask rustflags` compiles the
    /// SHA-256 backend the gate measured.
    #[test]
    fn an_image_is_built_with_its_own_flags_after_the_environments() {
        let asked = ["-Cforce-frame-pointers=yes".to_owned()];
        let flags = image_flags(&asked, Path::new("/r"), Path::new("/c"), Path::new("/s"))
            .expect("UTF-8 paths");
        let flags: Vec<&str> = flags.split('\u{1f}').collect();
        assert_eq!(
            flags,
            [
                "-Cforce-frame-pointers=yes",
                "--cfg=sha2_backend_soft=\"compact\"",
                "--remap-path-prefix=/r=/o89",
                "--remap-path-prefix=/c=/cargo",
                "--remap-path-prefix=/s=/rustc",
            ]
        );
    }

    #[test]
    fn the_flags_the_environment_asked_for_are_kept_in_front() {
        let asked = ["-Cforce-frame-pointers=yes".to_owned()];
        let flags = remapped(&asked, Path::new("/r"), Path::new("/c"), Path::new("/s"))
            .expect("UTF-8 paths");
        assert_eq!(
            flags.split('\u{1f}').next(),
            Some("-Cforce-frame-pointers=yes")
        );
        assert_eq!(flags.split('\u{1f}').count(), 4);
    }

    #[test]
    fn the_environments_flags_are_read_as_cargo_reads_them() {
        // The encoded form wins over `RUSTFLAGS`, as it does in cargo, and an
        // empty piece is no flag.
        let encoded = OsStr::new("-Ca\u{1f}\u{1f}--cfg x y");
        assert_eq!(
            inherited(Some(encoded), Some(OsStr::new("-Cignored"))).expect("UTF-8"),
            ["-Ca", "--cfg x y"]
        );
        assert_eq!(
            inherited(None, Some(OsStr::new("  -Ca   -Cb "))).expect("UTF-8"),
            ["-Ca", "-Cb"]
        );
        assert!(inherited(None, None).expect("nothing set").is_empty());
        assert!(
            inherited(Some(OsStr::new("")), None)
                .expect("set empty")
                .is_empty()
        );
        let bad = OsStr::from_bytes(b"-C\xff");
        assert!(inherited(None, Some(bad)).is_err());
    }

    #[test]
    fn a_config_that_sets_rustflags_anywhere_is_found() {
        assert!(sets_rustflags("[build]\nrustflags = [\"-Ca\"]\n").expect("parses"));
        assert!(
            sets_rustflags("[target.thumbv6m-none-eabi]\nrustflags = [\"-Ca\"]\n").expect("parses")
        );
        // What the repository's own configs hold: a target, a runner, an alias.
        assert!(
            !sets_rustflags(
                "[build]\ntarget = \"thumbv6m-none-eabi\"\n[target.thumbv6m-none-eabi]\nrunner = \"probe-rs run\"\n[alias]\nxtask = \"run\"\n"
            )
            .expect("parses")
        );
        assert!(
            sets_rustflags("[build\n").is_err(),
            "a config cargo cannot read either"
        );
    }

    /// The configs cargo reads for this repository's builds, from the root
    /// or from a crate's directory, none of which may set flags the remap
    /// would drop. The machine's own are the build's refusal to make, not a
    /// test's.
    #[test]
    fn the_repositorys_own_configs_set_no_rustflags() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the repository");
        let configs = [
            ".cargo/config.toml",
            "firmwares/o89-boot/.cargo/config.toml",
            "firmwares/o89-comms/.cargo/config.toml",
            "firmwares/o89-controller/.cargo/config.toml",
        ];
        for config in configs {
            let text = fs::read_to_string(root.join(config)).expect("the config is there");
            assert!(
                !sets_rustflags(&text).expect("parses"),
                "{config} sets rustflags"
            );
        }
    }

    #[test]
    fn a_config_setting_rustflags_refuses_the_build_and_names_the_file() {
        let dir = std::env::temp_dir().join(format!("o89-xtask-{}", std::process::id()));
        let checkout = dir.join("checkout");
        fs::create_dir_all(checkout.join(".cargo")).expect("a scratch checkout");
        fs::write(
            checkout.join(".cargo/config.toml"),
            "[build]\nrustflags = [\"-Ca\"]\n",
        )
        .expect("written");
        let refused = no_config_rustflags(&checkout, &dir.join("home"));
        let clean = no_config_rustflags(&dir.join("home"), &dir.join("home"));
        fs::remove_dir_all(&dir).expect("cleaned up");
        let error = format!("{:#}", refused.expect_err("refused"));
        assert!(error.contains("checkout/.cargo/config.toml"), "{error}");
        assert!(error.contains("#74"), "{error}");
        clean.expect("nothing to refuse where no config exists");
    }

    #[test]
    fn a_checkout_path_with_a_space_stays_one_flag() {
        let flags = remapped(
            &[],
            Path::new("/Users/a b/firmware"),
            Path::new("/c"),
            Path::new("/s"),
        )
        .expect("UTF-8 paths");
        assert!(
            flags
                .split('\u{1f}')
                .any(|flag| flag == "--remap-path-prefix=/Users/a b/firmware=/o89"),
            "{flags:?}"
        );
    }

    #[test]
    fn a_path_that_is_not_utf_8_is_refused_rather_than_mangled() {
        let bad = Path::new(OsStr::from_bytes(b"/home/\xff/firmware"));
        let error = remapped(&[], bad, Path::new("/c"), Path::new("/s")).expect_err("refused");
        assert!(format!("{error:#}").contains("is not UTF-8"), "{error:#}");
    }
}
