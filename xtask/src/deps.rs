//! The boundaries the dependency graph must keep.
//!
//! Two rules from the design, checked rather than remembered. The comms
//! processor must never depend on the crate that decides: a comms processor
//! able to reach a decision is one able to make one, and the site would have
//! two things deciding when the generator runs. And a domain crate must never
//! name a peripheral or an allocator: if logic needs hardware to test, the
//! seam is in the wrong place, and an allocator is how a bound stops being
//! named.
//!
//! The allocator rule is read from the sources as text, with comments
//! stripped, over `src/` and `tests/` alike, because the domain tests are held
//! to it too — a test that allocates is a test that cannot disagree with the
//! target about a bound. It is a marker list and not a parser, so it errs
//! towards refusing: a name in a string literal counts.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, PackageId};

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

/// What reaching for the allocator, or for `std`, looks like in a source
/// that has neither.
const ALLOC_MARKERS: &[&str] = &[
    "extern crate alloc",
    "alloc::",
    "extern crate std",
    "std::",
    "Vec<",
    "vec![",
    "String",
    "Box<",
    "format!",
    "to_owned(",
    "to_string(",
    "BTreeMap",
    "BTreeSet",
    "HashMap",
    "HashSet",
];

/// The resolved graph as adjacency by package id, with each id's name.
struct Graph {
    edges: BTreeMap<PackageId, Vec<PackageId>>,
    names: BTreeMap<PackageId, String>,
}

impl Graph {
    fn from_metadata(metadata: &Metadata) -> Result<Self> {
        let resolve = metadata
            .resolve
            .as_ref()
            .context("cargo metadata carried no resolve graph")?;
        let names = metadata
            .packages
            .iter()
            .map(|package| (package.id.clone(), package.name.to_string()))
            .collect();
        let edges = resolve
            .nodes
            .iter()
            .map(|node| {
                (
                    node.id.clone(),
                    node.deps.iter().map(|dep| dep.pkg.clone()).collect(),
                )
            })
            .collect();
        Ok(Self { edges, names })
    }

    /// Every package name reachable from `from`.
    ///
    /// Visited is kept by id and the result by name, separately: two ids can
    /// share a name — two versions of `embassy-sync` on two paths — and a walk
    /// that marked the name visited would skip the second one's subtree, and
    /// with it whatever forbidden crate sat there.
    fn reachable(&self, from: &PackageId) -> Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        let mut visited = BTreeSet::from([from.clone()]);
        let mut queue = VecDeque::from([from.clone()]);
        while let Some(id) = queue.pop_front() {
            let Some(deps) = self.edges.get(&id) else {
                continue;
            };
            for dep in deps {
                let name = self
                    .names
                    .get(dep)
                    .with_context(|| format!("dependency {dep} is not in the package list"))?;
                names.insert(name.clone());
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
        Ok(names)
    }
}

/// The first allocation marker in a source, with comments stripped.
fn allocation_in(source: &str) -> Option<&'static str> {
    source
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .find_map(|line| {
            ALLOC_MARKERS
                .iter()
                .copied()
                .find(|marker| line.contains(marker))
        })
}

/// The first allocation marker under `dir`, and the file it sits in.
fn uses_alloc(dir: &Path) -> Result<Option<(String, &'static str)>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                if let Some(marker) = allocation_in(&source) {
                    return Ok(Some((path.display().to_string(), marker)));
                }
            }
        }
    }
    Ok(None)
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
    if Graph::from_metadata(&firmware)?
        .reachable(&comms.id)?
        .contains(CORE)
    {
        bail!(
            "{COMMS} depends on {CORE}: the comms processor must never be able to reach a decision"
        );
    }

    let host = MetadataCommand::new()
        .manifest_path(repo.host_manifest())
        .features(CargoOpt::AllFeatures)
        .exec()
        .context("reading the host workspace")?;
    let graph = Graph::from_metadata(&host)?;
    for name in no_std_crates(repo)? {
        let package = host
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == name)
            .with_context(|| format!("{name} vanished from the host workspace"))?;
        let deps = graph.reachable(&package.id)?;
        if let Some(hal) = deps
            .iter()
            .find(|dep| HAL_PREFIXES.iter().any(|prefix| dep.starts_with(prefix)))
        {
            bail!("{name} depends on {hal}: a domain crate names no peripheral");
        }
        let crate_dir = package
            .manifest_path
            .parent()
            .context("a manifest has a directory")?;
        for sub in ["src", "tests"] {
            if let Some((file, marker)) = uses_alloc(crate_dir.join(sub).as_std_path())? {
                bail!(
                    "{name} reaches for the allocator ({marker:?} in {file}): every collection here has a named capacity, in the tests too"
                );
            }
        }
    }
    println!(
        "dependency boundaries kept: {COMMS} never sees {CORE}; domain crates name no peripheral and no allocator"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(repr: &str) -> PackageId {
        PackageId {
            repr: repr.to_owned(),
        }
    }

    /// `app` depends on two versions of `sync`; the second version is the
    /// only path to `hal`. A walk visited by name never reaches `hal`.
    fn diamond() -> Graph {
        let names = [
            ("app", "app"),
            ("sync-a", "sync"),
            ("sync-b", "sync"),
            ("hal", "embassy-stm32"),
        ]
        .into_iter()
        .map(|(repr, name)| (id(repr), name.to_owned()))
        .collect();
        let edges = [
            ("app", vec!["sync-a", "sync-b"]),
            ("sync-a", vec![]),
            ("sync-b", vec!["hal"]),
            ("hal", vec![]),
        ]
        .into_iter()
        .map(|(from, to)| (id(from), to.into_iter().map(id).collect()))
        .collect();
        Graph { edges, names }
    }

    #[test]
    fn f_081_a_second_package_with_the_same_name_is_still_walked() {
        let reached = diamond().reachable(&id("app")).expect("a complete graph");
        assert!(reached.contains("embassy-stm32"));
        assert_eq!(reached.len(), 2);
    }

    #[test]
    fn a_package_with_no_dependencies_reaches_nothing() {
        let reached = diamond().reachable(&id("hal")).expect("a complete graph");
        assert!(reached.is_empty());
    }

    #[test]
    fn a_dependency_missing_from_the_package_list_is_refused() {
        let mut graph = diamond();
        graph.names.remove(&id("hal"));
        assert!(graph.reachable(&id("app")).is_err());
    }

    #[test]
    fn f_081_an_allocation_is_found_past_a_comment_that_names_one() {
        let clean =
            "//! there is no `Vec<u8>` here\n/// nor a String\nfn f() -> [u8; 4] { [0; 4] }\n";
        assert_eq!(allocation_in(clean), None);
        let vec = "fn f() -> Vec<u8> { Vec::new() }\n";
        assert_eq!(allocation_in(vec), Some("Vec<"));
        let test_std = "#[cfg(test)]\nmod t { extern crate std; }\n";
        assert_eq!(allocation_in(test_std), Some("extern crate std"));
    }
}
