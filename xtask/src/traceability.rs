//! Every rule has a test standing behind it, a written reason none can, or
//! the gate fails.
//!
//! The denominator is read from the documents — `**F-nnn**` in
//! `docs/REQUIREMENTS.md`, and KM43's `P-`/`L-` from the pinned index — so it
//! moves when the documents move, and a number allocated twice is refused.
//! The numerator is read from the sources as Rust syntax: a `#[test]` function
//! named `f_012_...`, `p_004_...` or `l_110_...` whose body invokes an
//! assertion macro, or a `//! cites:` header on a file that has such a test.
//! A test that cannot fail is not a test, and a citation on a body with no
//! assertion is the failure mode of every traceability matrix ever built, so
//! the assertion is what is looked for — and a comment, a string, a helper
//! that merely carries the name, or an assertion inside a nested function the
//! test never calls, is not one.
//!
//! The sources are the files cargo compiles: every target root of both
//! workspaces and every file its `mod` declarations reach. A `.rs` file
//! outside that graph is refused rather than read, because a test nobody
//! compiles is a citation nobody runs.
//!
//! `F` rules ratchet by identity, not by count. `traceability.toml` lists the
//! uncovered rules by name: a rule leaves the list when its test lands, joins
//! it only when the rule itself is added, and a rule that loses its test is a
//! failure the count alone would hide. KM43 rules are reported, because which
//! of them bind this controller rather than a client is what
//! origin89hq/km43#31 will say.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use cargo_metadata::MetadataCommand;
use serde::Deserialize;
use syn::visit::Visit;
use syn::{Attribute, Expr, ExprLit, Item, Lit, Meta};

use crate::repo::Repo;

/// The checks of the gate an untestable rule may nominate as its test.
const GATE_CHECKS: &[&str] = &["cross", "deps", "images", "traceability"];

/// The macros whose invocation makes a test able to fail.
const ASSERTIONS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "assert_matches",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

#[derive(Deserialize)]
struct Declared {
    /// The rules with neither a test nor a declaration, by name.
    #[serde(default)]
    uncovered: Vec<String>,
    #[serde(default)]
    untestable: Vec<Untestable>,
}

#[derive(Deserialize)]
struct Untestable {
    id: String,
    kind: Kind,
    #[serde(default)]
    check: Option<String>,
    reason: String,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Hardware,
    SpecCheck,
    Deferred,
    Judgement,
}

/// A rule identifier such as `F-012` or `P-004`.
fn is_rule_id(word: &str) -> bool {
    let mut parts = word.splitn(2, '-');
    let prefix = parts.next().unwrap_or_default();
    let digits = parts.next().unwrap_or_default();
    matches!(prefix, "F" | "P" | "L")
        && digits.len() == 3
        && digits.chars().all(|c| c.is_ascii_digit())
}

/// Collect identifiers, refusing one that appears twice.
fn unique(ids: impl Iterator<Item = String>, what: &str) -> Result<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    for id in ids {
        ensure!(
            seen.insert(id.clone()),
            "{id} is allocated twice in {what}: two obligations under one number are one test covering both"
        );
    }
    Ok(seen)
}

/// Every `**X-nnn**` at the start of a line in a document.
fn rules_in_markdown(text: &str, what: &str) -> Result<BTreeSet<String>> {
    unique(
        text.lines().filter_map(|line| {
            let rest = line.strip_prefix("**")?;
            let end = rest.find("**")?;
            let id = rest.get(..end)?;
            is_rule_id(id).then(|| id.to_owned())
        }),
        what,
    )
}

/// The identifiers in the pinned KM43 index.
fn rules_in_index(text: &str, what: &str) -> Result<BTreeSet<String>> {
    unique(
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.starts_with("id\t"))
            .filter_map(|line| line.split('\t').next())
            .filter(|id| is_rule_id(id))
            .map(str::to_owned),
        what,
    )
}

/// A test function name's rule citation: `f_012_the_failure` cites `F-012`.
fn cited_by_name(name: &str) -> Option<String> {
    let (prefix, rest) = name.split_at(name.len().min(2));
    let letter = match prefix {
        "f_" => 'F',
        "p_" => 'P',
        "l_" => 'L',
        _ => return None,
    };
    let digits = rest.get(..3)?;
    if !digits.chars().all(|c| c.is_ascii_digit()) || !rest.get(3..)?.starts_with('_') {
        return None;
    }
    Some(format!("{letter}-{digits}"))
}

/// Whether a function body invokes an assertion macro in code it runs.
struct Asserts(bool);

impl<'ast> Visit<'ast> for Asserts {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(last) = node.path.segments.last()
            && ASSERTIONS.contains(&last.ident.to_string().as_str())
        {
            self.0 = true;
        }
        syn::visit::visit_macro(self, node);
    }

    /// A function, struct or impl declared inside the body is not run by the
    /// body; an assertion in one is a declaration, not an invocation.
    fn visit_item(&mut self, _: &'ast Item) {}
}

fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("test"))
}

/// The string of a `#[name = "..."]` attribute.
fn string_attr(attrs: &[Attribute], name: &str) -> Option<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident(name))
        .find_map(|attr| match &attr.meta {
            Meta::NameValue(value) => match &value.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            Meta::Path(_) | Meta::List(_) => None,
        })
}

/// What one source file cites: by test name with an assertion, and by header.
#[derive(Default)]
struct Citations {
    asserting: BTreeSet<String>,
    header: BTreeSet<String>,
    hollow: BTreeSet<String>,
}

impl Citations {
    fn merge(&mut self, other: Self) {
        self.asserting.extend(other.asserting);
        self.header.extend(other.header);
        self.hollow.extend(other.hollow);
    }

    fn visit_items(&mut self, items: &[Item], any_asserting_test: &mut bool) {
        for item in items {
            match item {
                Item::Fn(function) if is_test(&function.attrs) => {
                    let mut asserts = Asserts(false);
                    asserts.visit_block(&function.block);
                    *any_asserting_test |= asserts.0;
                    if let Some(id) = cited_by_name(&function.sig.ident.to_string()) {
                        if asserts.0 {
                            self.asserting.insert(id);
                        } else {
                            self.hollow.insert(id);
                        }
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        self.visit_items(items, any_asserting_test);
                    }
                }
                // `Item` is `#[non_exhaustive]` and not ours; nothing else
                // declares a test.
                _ => {}
            }
        }
    }
}

/// The `cites:` identifiers in a file's inner doc comments.
fn header_cites(attrs: &[Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(value) => match &value.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            Meta::Path(_) | Meta::List(_) => None,
        })
        .filter_map(|line| line.trim().strip_prefix("cites:").map(str::to_owned))
        .flat_map(|cites| {
            cites
                .split(',')
                .map(|word| word.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|id| is_rule_id(id))
        .collect()
}

/// Parse a source and read what it cites.
fn citations_in(source: &str) -> Result<Citations> {
    let file = syn::parse_file(source).context("parsing a Rust source")?;
    let mut found = Citations::default();
    let mut any_asserting_test = false;
    found.visit_items(&file.items, &mut any_asserting_test);
    // A header is a claim by a whole file, and it stands only over a file
    // that has a test which can fail.
    if any_asserting_test {
        found.header.extend(header_cites(&file.attrs));
    }
    Ok(found)
}

/// Every `.rs` under `dir`, skipping build output.
fn rust_files(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "target" {
                rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.insert(path);
        }
    }
    Ok(())
}

/// The source roots of a workspace: every Cargo target's file.
fn target_roots(manifest: &Path) -> Result<Vec<PathBuf>> {
    let metadata = MetadataCommand::new()
        .manifest_path(manifest)
        .no_deps()
        .exec()
        .with_context(|| format!("reading {}", manifest.display()))?;
    Ok(metadata
        .workspace_packages()
        .iter()
        .flat_map(|package| package.targets.iter())
        .map(|target| target.src_path.clone().into_std_path_buf())
        .collect())
}

/// Follow the `mod` declarations of the items under `dir`, the directory
/// child modules of this scope live in; `declared_in` is the directory of
/// the file itself, which a `#[path]` is relative to.
fn follow_mods(
    items: &[Item],
    dir: &Path,
    declared_in: &Path,
    reached: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for item in items {
        let Item::Mod(module) = item else {
            continue;
        };
        let name = module.ident.to_string();
        if let Some((_, inner)) = &module.content {
            follow_mods(inner, &dir.join(&name), declared_in, reached)?;
        } else {
            let file = if let Some(path) = string_attr(&module.attrs, "path") {
                declared_in.join(path)
            } else {
                let flat = dir.join(format!("{name}.rs"));
                if flat.is_file() {
                    flat
                } else {
                    dir.join(&name).join("mod.rs")
                }
            };
            ensure!(
                file.is_file(),
                "`mod {name};` declared under {} names no file",
                declared_in.display()
            );
            let owns_dir = file.file_name().is_some_and(|n| n == "mod.rs");
            follow_file(&file, owns_dir, reached)?;
        }
    }
    Ok(())
}

/// Read one file into the reached set and follow its modules. A target root
/// or a `mod.rs` owns its directory; a `name.rs` module owns `name/`.
fn follow_file(file: &Path, owns_dir: bool, reached: &mut BTreeSet<PathBuf>) -> Result<()> {
    if !reached.insert(file.to_path_buf()) {
        return Ok(());
    }
    let source = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let parsed = syn::parse_file(&source).with_context(|| format!("parsing {}", file.display()))?;
    let declared_in = file.parent().context("a file has a directory")?;
    let dir = if owns_dir {
        declared_in.to_path_buf()
    } else {
        let stem = file.file_stem().context("a file has a stem")?;
        declared_in.join(stem)
    };
    follow_mods(&parsed.items, &dir, declared_in, reached)
}

/// The files cargo compiles, from the target roots through their modules.
fn compiled_sources(roots: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    let mut reached = BTreeSet::new();
    for root in roots {
        follow_file(root, true, &mut reached)?;
    }
    Ok(reached)
}

/// Every citation in the sources, and the file each hollow one sits in.
fn citations_in_repo(repo: &Repo) -> Result<(Citations, BTreeMap<String, PathBuf>)> {
    let mut roots = target_roots(&repo.host_manifest())?;
    roots.extend(target_roots(&repo.firmware_manifest())?);
    let compiled = compiled_sources(&roots)?;
    let mut present = BTreeSet::new();
    for dir in ["crates", "firmwares", "xtask"] {
        let dir = repo.root().join(dir);
        if dir.is_dir() {
            rust_files(&dir, &mut present)?;
        }
    }
    let orphans: Vec<&PathBuf> = present.difference(&compiled).collect();
    if let Some(first) = orphans.first() {
        bail!(
            "{} Rust file(s) that no Cargo target reaches, starting with {}: a test nobody compiles is a citation nobody runs",
            orphans.len(),
            first.display()
        );
    }
    let mut all = Citations::default();
    let mut hollow_in = BTreeMap::new();
    for file in &compiled {
        let source =
            fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let found = citations_in(&source).with_context(|| format!("reading {}", file.display()))?;
        for id in &found.hollow {
            hollow_in.insert(id.clone(), file.clone());
        }
        all.merge(found);
    }
    Ok((all, hollow_in))
}

/// The declarations, checked against the rules they name and the checks they nominate.
fn declarations(docs: &Path, f_rules: &BTreeSet<String>, cited: &Citations) -> Result<Declared> {
    let declared: Declared = toml::from_str(
        &fs::read_to_string(docs.join("traceability.toml"))
            .context("reading docs/traceability.toml")?,
    )
    .context("parsing docs/traceability.toml")?;
    for entry in &declared.untestable {
        ensure!(
            f_rules.contains(&entry.id),
            "traceability.toml declares {}, which REQUIREMENTS.md does not name",
            entry.id
        );
        ensure!(
            !entry.reason.trim().is_empty(),
            "{} is declared untestable with no reason",
            entry.id
        );
        if entry.kind == Kind::SpecCheck {
            let check = entry.check.as_deref().unwrap_or_default();
            ensure!(
                GATE_CHECKS.contains(&check),
                "{} nominates gate check {check:?}, which does not exist; the checks are {}",
                entry.id,
                GATE_CHECKS.join(", ")
            );
        }
        if cited.asserting.contains(&entry.id) {
            println!(
                "note: {} is declared untestable and has a test named after it; the declaration can go",
                entry.id
            );
        }
    }
    Ok(declared)
}

/// The ratchet: every uncovered rule is listed by name, and only by name.
fn ratchet(
    f_rules: &BTreeSet<String>,
    covered: &BTreeSet<String>,
    untestable: &BTreeSet<String>,
    listed: &[String],
) -> Result<()> {
    let listed: BTreeSet<&String> = listed.iter().collect();
    for id in &listed {
        ensure!(
            f_rules.contains(*id),
            "traceability.toml lists {id} as uncovered, and REQUIREMENTS.md does not name it"
        );
        ensure!(
            !untestable.contains(*id),
            "{id} is listed as uncovered and declared untestable; it is one or the other"
        );
        ensure!(
            !covered.contains(*id),
            "{id} has a test named after it now: take it off the uncovered list, which only shrinks"
        );
    }
    for id in f_rules {
        if !covered.contains(id) && !untestable.contains(id) && !listed.contains(id) {
            bail!(
                "{id} has no test and no declaration and is not on the uncovered list: if the rule is new, list it, and if it had a test, the test went missing"
            );
        }
    }
    Ok(())
}

fn list(ids: &[&String]) -> String {
    ids.iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Walk the documents and the sources, sort every rule, and enforce the ratchet.
pub fn check(repo: &Repo) -> Result<()> {
    let docs = repo.root().join("docs");
    let requirements =
        fs::read_to_string(docs.join("REQUIREMENTS.md")).context("reading docs/REQUIREMENTS.md")?;
    let f_rules = rules_in_markdown(&requirements, "docs/REQUIREMENTS.md")?;
    ensure!(
        !f_rules.is_empty(),
        "docs/REQUIREMENTS.md names no **F-nnn** rule"
    );
    let index = fs::read_to_string(docs.join("km43").join("requirements.tsv"))
        .context("reading docs/km43/requirements.tsv")?;
    let km43_rules = rules_in_index(&index, "docs/km43/requirements.tsv")?;
    ensure!(!km43_rules.is_empty(), "the KM43 index names no rule");

    let (cited, hollow_in) = citations_in_repo(repo)?;
    for (id, file) in &hollow_in {
        if !cited.asserting.contains(id) {
            bail!(
                "{} is cited by a test with no assertion in {}: a test that cannot fail covers nothing",
                id,
                file.display()
            );
        }
    }
    for id in cited.asserting.iter().chain(cited.header.iter()) {
        ensure!(
            f_rules.contains(id) || km43_rules.contains(id),
            "a test cites {id}, which no document allocates"
        );
    }
    let declared = declarations(&docs, &f_rules, &cited)?;
    let untestable: BTreeSet<String> = declared.untestable.iter().map(|e| e.id.clone()).collect();
    let covered: BTreeSet<String> = f_rules
        .iter()
        .chain(km43_rules.iter())
        .filter(|id| cited.asserting.contains(*id) || cited.header.contains(*id))
        .cloned()
        .collect();
    let f_covered: Vec<&String> = f_rules.iter().filter(|id| covered.contains(*id)).collect();
    let km43_cited: Vec<&String> = km43_rules
        .iter()
        .filter(|id| covered.contains(*id))
        .collect();
    let header_only: Vec<&String> = f_rules
        .iter()
        .chain(km43_rules.iter())
        .filter(|id| cited.header.contains(*id) && !cited.asserting.contains(*id))
        .collect();

    println!(
        "traceability: {} F rules — {} covered, {} declared untestable, {} listed uncovered",
        f_rules.len(),
        f_covered.len(),
        untestable.len(),
        declared.uncovered.len()
    );
    println!(
        "traceability: {} KM43 rules pinned — {} cited by an asserting test here: {}",
        km43_rules.len(),
        km43_cited.len(),
        list(&km43_cited)
    );
    if !header_only.is_empty() {
        println!(
            "note: {} rule(s) covered by a `cites:` header alone, which is a claim by a whole file: {}",
            header_only.len(),
            list(&header_only)
        );
    }
    ratchet(&f_rules, &covered, &untestable, &declared.uncovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|id| (*id).to_owned()).collect()
    }

    // The fixtures are assembled at run time so this file's own text never
    // reads as a declaration to the walk, which parses every file here.
    fn test_fn(name: &str, body: &str) -> String {
        format!("#[test]\nfn {name}() {{ {body} }}\n")
    }

    /// A throwaway directory tree, removed when dropped.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("o89-xtask-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("a temp dir");
            Self(dir)
        }

        fn file(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
            fs::write(&path, text).expect("a file");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_rule_is_read_from_the_start_of_a_line_only() {
        let doc = "**F-001** — first.\nSee **F-002** inline.\n**P-004** — a km43 rule.\n**F-12** — too short.\n";
        let rules = rules_in_markdown(doc, "doc").expect("no duplicates");
        assert_eq!(rules, ids(&["F-001", "P-004"]));
    }

    #[test]
    fn a_number_allocated_twice_is_refused() {
        let doc = "**F-001** — one obligation.\n\n**F-001** — another.\n";
        let error = rules_in_markdown(doc, "doc").expect_err("a duplicate");
        assert!(error.to_string().contains("F-001 is allocated twice"));
        let index = "id\tdocument\nP-001\ta\nP-001\tb\n";
        assert!(rules_in_index(index, "index").is_err());
    }

    #[test]
    fn a_test_name_cites_the_rule_it_is_named_after() {
        assert_eq!(
            cited_by_name("f_012_the_rail_is_off").as_deref(),
            Some("F-012")
        );
        assert_eq!(
            cited_by_name("p_004_a_tick_never_runs_backwards").as_deref(),
            Some("P-004")
        );
        assert_eq!(
            cited_by_name("l_110_control_is_unaffected").as_deref(),
            Some("L-110")
        );
        assert_eq!(cited_by_name("f_12_short"), None);
        assert_eq!(cited_by_name("frost_below_zero"), None);
        assert_eq!(cited_by_name("f_012"), None);
    }

    #[test]
    fn f_082_a_citation_without_an_assertion_is_hollow() {
        let source = test_fn(&format!("{}_runs_low", "f_001"), "let _ = 1;")
            + &test_fn(&format!("{}_idles_high", "f_002"), "assert!(true);");
        let found = citations_in(&source).expect("parses");
        assert!(found.hollow.contains("F-001"));
        assert!(found.asserting.contains("F-002"));
        assert!(!found.asserting.contains("F-001"));
    }

    #[test]
    fn f_082_only_a_test_with_a_real_assertion_counts() {
        // A helper carrying the name, a commented-out test, the word in a
        // string or a comment, and an assertion in a nested function the test
        // never calls are the ways a lesser scan lies.
        let helper = format!("fn {}_helper() {{ assert!(true); }}\n", "f_003");
        let commented = format!(
            "// #[test]\n// fn {}_gone() {{ assert!(true); }}\n",
            "f_004"
        );
        let in_string = test_fn(&format!("{}_quoted", "f_005"), "let _ = \"assert!(x)\";");
        let in_comment = test_fn(
            &format!("{}_remarked", "f_006"),
            "// assert!(x)\nlet _ = 1;",
        );
        let nested = format!(
            "#[cfg(test)]\nmod tests {{\n{}}}\n",
            test_fn(&format!("{}_deep", "f_007"), "assert_eq!(1, 1);")
        );
        let declared_inside = test_fn(
            &format!("{}_declares_one", "f_008"),
            "fn never_called() { assert!(false); } let _ = 1;",
        );
        let source = helper + &commented + &in_string + &in_comment + &nested + &declared_inside;
        let found = citations_in(&source).expect("parses");
        assert_eq!(found.asserting, ids(&["F-007"]));
        assert_eq!(found.hollow, ids(&["F-005", "F-006", "F-008"]));
    }

    #[test]
    fn a_header_counts_only_on_a_file_with_an_asserting_test() {
        let with = "//! cites: P-004, L-110\n".to_owned() + &test_fn("x_y", "assert_eq!(1, 1);");
        let without = "//! cites: P-004\nfn nothing() {}\n";
        let hollow_test = "//! cites: P-004\n".to_owned() + &test_fn("x_y", "let _ = 1;");
        assert_eq!(
            citations_in(&with).expect("parses").header,
            ids(&["P-004", "L-110"])
        );
        assert!(citations_in(without).expect("parses").header.is_empty());
        assert!(
            citations_in(&hollow_test)
                .expect("parses")
                .header
                .is_empty()
        );
    }

    #[test]
    fn the_index_yields_its_identifiers_and_skips_its_comments() {
        let index =
            "# pinned\nid\tdocument\nP-001\tdocs/PROTOCOL.md\nL-010\tdocs/protocol/LINK.md\n";
        let rules = rules_in_index(index, "index").expect("no duplicates");
        assert_eq!(rules, ids(&["P-001", "L-010"]));
    }

    #[test]
    fn f_082_the_module_graph_reaches_what_cargo_compiles_and_nothing_else() {
        let tree = Tree::new("modules");
        let root = tree.file("src/lib.rs", "mod a;\nmod c;\nmod inline { mod e; }\n");
        let a_mod = tree.file("src/a/mod.rs", "mod b;\n");
        let a_b = tree.file("src/a/b.rs", "");
        let c_file = tree.file("src/c.rs", "#[cfg(test)] mod d;\n");
        let c_d = tree.file("src/c/d.rs", "");
        let inline_e = tree.file("src/inline/e.rs", "");
        let orphan = tree.file(
            "src/orphan.rs",
            &format!(
                "#[test] fn {}_from_nowhere() {{ assert!(true); }}\n",
                "f_099"
            ),
        );
        let reached = compiled_sources(std::slice::from_ref(&root)).expect("a complete graph");
        assert_eq!(
            reached,
            [root, a_mod, a_b, c_file, c_d, inline_e]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(!reached.contains(&orphan));
        let mut present = BTreeSet::new();
        rust_files(&tree.0, &mut present).expect("a listing");
        let orphans: Vec<_> = present.difference(&reached).collect();
        assert_eq!(orphans, vec![&orphan]);
    }

    #[test]
    fn a_path_attribute_and_a_missing_module_are_both_read() {
        let tree = Tree::new("paths");
        let root = tree.file("src/main.rs", "#[path = \"elsewhere.rs\"]\nmod named;\n");
        let elsewhere = tree.file("src/elsewhere.rs", "");
        let reached = compiled_sources(std::slice::from_ref(&root)).expect("a complete graph");
        assert_eq!(reached, [root, elsewhere].into_iter().collect());
        let broken = tree.file("src/broken.rs", "mod ghost;\n");
        let error = compiled_sources(&[broken]).expect_err("no file for ghost");
        assert!(error.to_string().contains("mod ghost"));
    }

    #[test]
    fn f_082_the_ratchet_holds_by_name() {
        let rules = ids(&["F-001", "F-002", "F-003", "F-004"]);
        let untestable = ids(&["F-004"]);
        let listed = |l: &[&str]| l.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
        // Consistent: F-001 covered, F-004 declared, the other two listed.
        assert!(
            ratchet(
                &rules,
                &ids(&["F-001"]),
                &untestable,
                &listed(&["F-002", "F-003"])
            )
            .is_ok()
        );
        // A rule lost its test and nothing else moved: the count of uncovered
        // rules would read three against a list of two, but what the gate
        // says is which rule.
        let lost = ratchet(&rules, &ids(&[]), &untestable, &listed(&["F-002", "F-003"]));
        assert!(
            lost.expect_err("F-001 lost coverage")
                .to_string()
                .contains("F-001")
        );
        // A rule gained a test and is still listed: the list only shrinks.
        let stale = ratchet(
            &rules,
            &ids(&["F-001", "F-002"]),
            &untestable,
            &listed(&["F-002", "F-003"]),
        );
        assert!(
            stale
                .expect_err("F-002 is stale on the list")
                .to_string()
                .contains("F-002")
        );
        // A new rule nobody listed.
        let unlisted = ratchet(&rules, &ids(&["F-001"]), &untestable, &listed(&["F-002"]));
        assert!(
            unlisted
                .expect_err("F-003 is unlisted")
                .to_string()
                .contains("F-003")
        );
        // Listed and declared at once.
        let both = ratchet(
            &rules,
            &ids(&["F-001"]),
            &untestable,
            &listed(&["F-002", "F-003", "F-004"]),
        );
        assert!(
            both.expect_err("F-004 is both")
                .to_string()
                .contains("F-004")
        );
    }
}
