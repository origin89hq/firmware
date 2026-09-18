//! Where things are: the repository, the two workspaces, the toolchain's tools.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The two targets, named once.
pub const CORTEX_M0: &str = "thumbv6m-none-eabi";
/// The comms processor's target.
pub const RISCV: &str = "riscv32imac-unknown-none-elf";

/// The repository root and what lives under it.
pub struct Repo {
    root: PathBuf,
}

impl Repo {
    /// Find the root from this crate's manifest directory.
    pub fn locate() -> Result<Self> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .parent()
            .context("xtask sits one level below the repository root")?
            .to_path_buf();
        Ok(Self { root })
    }

    /// The repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The host workspace manifest.
    pub fn host_manifest(&self) -> PathBuf {
        self.root.join("Cargo.toml")
    }

    /// The firmware workspace manifest.
    pub fn firmware_manifest(&self) -> PathBuf {
        self.root.join("firmwares").join("Cargo.toml")
    }

    /// The firmware workspace's target directory.
    pub fn firmware_target_dir(&self) -> PathBuf {
        self.root.join("firmwares").join("target")
    }

    /// A `cargo` invocation using the toolchain this repository pins.
    pub fn cargo(&self) -> Command {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command.current_dir(&self.root);
        command
    }
}

/// A tool from the toolchain's `llvm-tools` component, by name.
///
/// They live in the sysroot under the host triple and are not on the
/// path; asking `rustc` for both is what keeps this independent of how
/// the toolchain was installed.
pub fn llvm_tool(name: &str) -> Result<PathBuf> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .context("running rustc --print sysroot")?;
    if !sysroot.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let sysroot = String::from_utf8(sysroot.stdout).context("sysroot path is not UTF-8")?;
    let version = Command::new(&rustc)
        .arg("-vV")
        .output()
        .context("running rustc -vV")?;
    let version = String::from_utf8(version.stdout).context("rustc -vV is not UTF-8")?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc -vV names no host")?;
    let tool = Path::new(sysroot.trim())
        .join("lib")
        .join("rustlib")
        .join(host.trim())
        .join("bin")
        .join(name);
    if !tool.is_file() {
        bail!(
            "{} is not installed: `rustup component add llvm-tools` (expected at {})",
            name,
            tool.display()
        );
    }
    Ok(tool)
}

/// Run a command and fail with its name when it does not succeed.
pub fn run(command: &mut Command, what: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("starting {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}
