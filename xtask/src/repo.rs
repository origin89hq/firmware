//! Where things are: the repository, the two workspaces, the toolchain's tools.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use cargo_metadata::{Artifact, Message};

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

    /// The firmware workspace's root, which its manifest and `target` sit in.
    pub fn firmware_root(&self) -> PathBuf {
        self.root.join("firmwares")
    }

    /// The firmware workspace manifest.
    pub fn firmware_manifest(&self) -> PathBuf {
        self.firmware_root().join("Cargo.toml")
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
    let sysroot = sysroot()?;
    let version = Command::new(&rustc)
        .arg("-vV")
        .output()
        .context("running rustc -vV")?;
    let version = String::from_utf8(version.stdout).context("rustc -vV is not UTF-8")?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc -vV names no host")?;
    let tool = sysroot
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

/// The toolchain's sysroot, as the `rustc` this repository pins reports it.
pub fn sysroot() -> Result<PathBuf> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .context("running rustc --print sysroot")?;
    if !sysroot.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let sysroot = String::from_utf8(sysroot.stdout).context("sysroot path is not UTF-8")?;
    Ok(PathBuf::from(sysroot.trim()))
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

/// Run a cargo build command and return every artifact it reports.
///
/// Diagnostics still reach the terminal rendered; only the artifact stream
/// is read, so a check that wants to know what cargo compiled asks cargo.
pub fn artifacts(command: &mut Command, what: &str) -> Result<Vec<Artifact>> {
    command.arg("--message-format=json-render-diagnostics");
    command.stdout(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {what}"))?;
    let stdout = child.stdout.take().context("stdout is piped")?;
    let mut found = Vec::new();
    for message in Message::parse_stream(BufReader::new(stdout)) {
        if let Message::CompilerArtifact(artifact) =
            message.with_context(|| format!("reading what {what} built"))?
        {
            found.push(artifact);
        }
    }
    let status = child
        .wait()
        .with_context(|| format!("waiting for {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(found)
}
