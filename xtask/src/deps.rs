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
//! What makes an allocator reachable in a `no_std` crate is the `alloc` or
//! `std` crate root, and nothing else: in the crate's own sources, or through
//! a dependency resolved with an `alloc` or `std` feature that re-exports one.
//! Type names cannot be the rule, because `heapless::Vec` and
//! `heapless::String` are exactly what the house asks for. So the sources are
//! read as identifier tokens with comments stripped — spacing, generics and a
//! comment inside a path change nothing — over `src/` and `tests/` alike,
//! because the domain tests are held to the rule too, and the resolved
//! features of every reachable dependency are read from cargo. A `Vec` with
//! neither root in reach does not compile, which is the compiler holding the
//! other half.

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

/// The crate roots that bring an allocator with them.
const ALLOC_ROOTS: &[&str] = &["alloc", "std"];

/// The resolved graph as adjacency by package id, with each id's name and
/// the features it was resolved with.
struct Graph {
    edges: BTreeMap<PackageId, Vec<PackageId>>,
    names: BTreeMap<PackageId, String>,
    features: BTreeMap<PackageId, Vec<String>>,
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
        let features = resolve
            .nodes
            .iter()
            .map(|node| {
                (
                    node.id.clone(),
                    node.features.iter().map(ToString::to_string).collect(),
                )
            })
            .collect();
        Ok(Self {
            edges,
            names,
            features,
        })
    }

    /// Every package id reachable from `from`, in the order found.
    ///
    /// Visited is kept by id: two ids can share a name — two versions of
    /// `embassy-sync` on two paths — and a walk that marked the name visited
    /// would skip the second one's subtree, and with it whatever forbidden
    /// crate sat there.
    fn reachable_ids(&self, from: &PackageId) -> Vec<PackageId> {
        let mut visited = BTreeSet::from([from.clone()]);
        let mut order = Vec::new();
        let mut queue = VecDeque::from([from.clone()]);
        while let Some(id) = queue.pop_front() {
            let Some(deps) = self.edges.get(&id) else {
                continue;
            };
            for dep in deps {
                if visited.insert(dep.clone()) {
                    order.push(dep.clone());
                    queue.push_back(dep.clone());
                }
            }
        }
        order
    }

    /// Every package name reachable from `from`.
    fn reachable(&self, from: &PackageId) -> Result<BTreeSet<String>> {
        self.reachable_ids(from)
            .iter()
            .map(|id| {
                self.names
                    .get(id)
                    .cloned()
                    .with_context(|| format!("dependency {id} is not in the package list"))
            })
            .collect()
    }

    /// The first reachable dependency resolved with an `alloc` or `std`
    /// feature, and the feature.
    fn alloc_feature_reachable(&self, from: &PackageId) -> Option<(String, String)> {
        self.reachable_ids(from).into_iter().find_map(|id| {
            let feature = self
                .features
                .get(&id)?
                .iter()
                .find(|feature| ALLOC_ROOTS.contains(&feature.as_str()))?;
            let name = self
                .names
                .get(&id)
                .cloned()
                .unwrap_or_else(|| id.to_string());
            Some((name, feature.clone()))
        })
    }
}

/// The source with every comment removed, line and block alike, block
/// comments nested as Rust nests them.
fn without_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut depth = 0usize;
    while let Some(c) = chars.next() {
        if depth > 0 {
            match (c, chars.peek()) {
                ('*', Some('/')) => {
                    chars.next();
                    depth = depth.saturating_sub(1);
                }
                ('/', Some('*')) => {
                    chars.next();
                    depth = depth.saturating_add(1);
                }
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('*')) => {
                chars.next();
                depth = 1;
                out.push(' ');
            }
            ('/', Some('/')) => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// The first identifier token in a source that is an allocator's crate root.
fn alloc_root_in(source: &str) -> Option<&'static str> {
    let text = without_comments(source);
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find_map(|token| ALLOC_ROOTS.iter().copied().find(|root| *root == token))
}

/// The first allocator root under `dir`, and the file it sits in.
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
                if let Some(root) = alloc_root_in(&source) {
                    return Ok(Some((path.display().to_string(), root)));
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
        if let Some((dep, feature)) = graph.alloc_feature_reachable(&package.id) {
            bail!(
                "{name} reaches {dep} with its {feature:?} feature on: an allocator arriving through a dependency is still an allocator"
            );
        }
        let crate_dir = package
            .manifest_path
            .parent()
            .context("a manifest has a directory")?;
        for sub in ["src", "tests"] {
            if let Some((file, root)) = uses_alloc(crate_dir.join(sub).as_std_path())? {
                bail!(
                    "{name} names the {root} crate in {file}: every collection here has a named capacity, in the tests too"
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
        let features = [("sync-b", vec!["alloc"])]
            .into_iter()
            .map(|(repr, features)| (id(repr), features.into_iter().map(str::to_owned).collect()))
            .collect();
        Graph {
            edges,
            names,
            features,
        }
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
    fn f_081_an_allocator_arriving_through_a_dependency_feature_is_found() {
        let found = diamond().alloc_feature_reachable(&id("app"));
        assert_eq!(found, Some(("sync".to_owned(), "alloc".to_owned())));
        assert_eq!(diamond().alloc_feature_reachable(&id("sync-a")), None);
    }

    #[test]
    fn f_081_a_crate_root_is_found_whatever_the_spacing_or_comments() {
        assert_eq!(alloc_root_in("extern crate /* test */ std;"), Some("std"));
        assert_eq!(
            alloc_root_in("let v = std :: vec::Vec::<u8>::with_capacity(1);"),
            Some("std")
        );
        assert_eq!(alloc_root_in("use alloc::boxed::Box;"), Some("alloc"));
        assert_eq!(alloc_root_in("#[cfg(test)] extern crate std;"), Some("std"));
    }

    #[test]
    fn a_comment_naming_a_crate_root_is_not_a_use_of_it() {
        let commented =
            "//! no `alloc` and no `std` here\n/* nor /* nested std */ here */\nfn f() {}\n";
        assert_eq!(alloc_root_in(commented), None);
        let stdio = "fn stdio() -> u8 { 0 }\nlet allocation = 1;\n";
        assert_eq!(alloc_root_in(stdio), None);
    }

    #[test]
    fn a_type_name_without_a_crate_root_is_the_compilers_to_refuse() {
        // `Vec::with_capacity` with neither `alloc` nor `std` in reach does
        // not compile in a `no_std` crate, and `heapless::Vec` is allowed;
        // the scan looks for the root, not the name.
        assert_eq!(alloc_root_in("let v = Vec::with_capacity(4);"), None);
        assert_eq!(alloc_root_in("let b = Box::new(1);"), None);
        assert_eq!(
            alloc_root_in("let v: heapless::Vec<u8, 8> = heapless::Vec::new();"),
            None
        );
    }
}
