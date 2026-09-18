//! The boundaries the dependency graph must keep.
//!
//! Two rules from the design, checked rather than remembered. The comms
//! processor must never depend on the crate that decides: a comms processor
//! able to reach a decision is one able to make one, and the site would have
//! two things deciding when the generator runs. And a domain crate must never
//! name a peripheral or an allocator: if logic needs hardware to test, the
//! seam is in the wrong place, and an allocator is how a bound stops being
//! named.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use cargo_metadata::{CargoOpt, MetadataCommand, PackageId};

use crate::cross::no_std_crates;
use crate::repo::Repo;

/// The crate that decides.
const CORE: &str = "o89-core";
/// The crate that forwards bytes and never inspects them.
const COMMS: &str = "o89-comms";

/// Crates that name a peripheral. A domain crate depending on any of these
/// has a seam in the wrong place.
const HAL_PREFIXES: &[&str] = &[
    "embassy-stm32",
    "stm32-metapac",
    "cortex-m",
    "esp-hal",
    "esp32c6",
    "esp-riscv-rt",
    "riscv",
];

/// Every package reachable from `from` in the resolved graph, by name.
fn reachable(metadata: &cargo_metadata::Metadata, from: &PackageId) -> Result<BTreeSet<String>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .context("cargo metadata carried no resolve graph")?;
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([from.clone()]);
    while let Some(id) = queue.pop_front() {
        let Some(node) = resolve.nodes.iter().find(|node| node.id == id) else {
            continue;
        };
        for dep in &node.deps {
            let name = metadata
                .packages
                .iter()
                .find(|package| package.id == dep.pkg)
                .map(|package| package.name.to_string())
                .with_context(|| format!("dependency {} is not in the package list", dep.pkg))?;
            if seen.insert(name) {
                queue.push_back(dep.pkg.clone());
            }
        }
    }
    Ok(seen)
}

/// Whether any source file under `dir` reaches for the allocator.
fn uses_alloc(dir: &Path) -> Result<bool> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                if source.contains("extern crate alloc") || source.contains("alloc::") {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Apply both rules.
pub fn check(repo: &Repo) -> Result<()> {
    let firmware = MetadataCommand::new()
        .manifest_path(repo.firmware_manifest())
        .features(CargoOpt::AllFeatures)
        .exec()
        .context("reading the firmware workspace")?;
    let comms = firmware
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == COMMS)
        .with_context(|| format!("{COMMS} is not a member of the firmware workspace"))?;
    let comms_deps = reachable(&firmware, &comms.id)?;
    if comms_deps.contains(CORE) {
        bail!(
            "{COMMS} depends on {CORE}: the comms processor must never be able to reach a decision"
        );
    }

    let host = MetadataCommand::new()
        .manifest_path(repo.host_manifest())
        .features(CargoOpt::AllFeatures)
        .exec()
        .context("reading the host workspace")?;
    for name in no_std_crates(repo)? {
        let package = host
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == name)
            .with_context(|| format!("{name} vanished from the host workspace"))?;
        let deps = reachable(&host, &package.id)?;
        if let Some(hal) = deps
            .iter()
            .find(|dep| HAL_PREFIXES.iter().any(|prefix| dep.starts_with(prefix)))
        {
            bail!("{name} depends on {hal}: a domain crate names no peripheral");
        }
        let src = package
            .manifest_path
            .parent()
            .context("a manifest has a directory")?
            .join("src");
        if uses_alloc(src.as_std_path())? {
            bail!("{name} reaches for the allocator: every collection here has a named capacity");
        }
    }
    println!(
        "dependency boundaries kept: {COMMS} never sees {CORE}; domain crates name no peripheral and no allocator"
    );
    Ok(())
}
