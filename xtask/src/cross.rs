//! Cross-compile every `#![no_std]` crate of the host workspace for both
//! targets.
//!
//! `cargo test` and `cargo clippy` build for the laptop, where `usize` is 64
//! bits and `std` is present. A size assertion written in the host's units,
//! or a dependency that quietly pulls `std`, only fails here. The crates are
//! found by reading their sources rather than from a list, because a list of
//! names is checked against nothing.

use std::fs;

use anyhow::{Context, Result};
use cargo_metadata::{Artifact, MetadataCommand};

use crate::repo::{CORTEX_M0, RISCV, Repo, artifacts};

/// The names of the host workspace's `#![no_std]` library crates.
pub fn no_std_crates(repo: &Repo) -> Result<Vec<String>> {
    let metadata = MetadataCommand::new()
        .manifest_path(repo.host_manifest())
        .no_deps()
        .exec()
        .context("reading the host workspace")?;
    let mut found = Vec::new();
    for package in metadata.workspace_packages() {
        let Some(lib) = package.targets.iter().find(|target| target.is_lib()) else {
            continue;
        };
        let source = fs::read_to_string(&lib.src_path)
            .with_context(|| format!("reading {}", lib.src_path))?;
        if source.lines().any(|line| line.trim() == "#![no_std]") {
            found.push(package.name.to_string());
        }
    }
    found.sort();
    Ok(found)
}

/// `cargo check` each `no_std` crate for the Cortex-M0+ and the RISC-V
/// target, and return what those checks compiled.
pub fn compile(repo: &Repo) -> Result<Vec<Artifact>> {
    let crates = no_std_crates(repo)?;
    anyhow::ensure!(
        !crates.is_empty(),
        "no #![no_std] crate found in the host workspace; the gate would check nothing"
    );
    let mut built = Vec::new();
    for name in &crates {
        for target in [CORTEX_M0, RISCV] {
            built.extend(artifacts(
                repo.cargo()
                    .args(["check", "--locked", "-p", name, "--target", target]),
                &format!("cargo check -p {name} --target {target}"),
            )?);
        }
    }
    Ok(built)
}

/// The check: every `no_std` crate compiles for both targets.
pub fn check(repo: &Repo) -> Result<()> {
    compile(repo)?;
    println!(
        "cross-compiled for both targets: {}",
        no_std_crates(repo)?.join(", ")
    );
    Ok(())
}
