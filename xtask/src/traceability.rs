//! Every rule has a test standing behind it, a written reason none can, or
//! the gate fails.
//!
//! The denominator is read from the documents — `**F-nnn**` in
//! `docs/REQUIREMENTS.md`, and KM43's `P-`/`L-` from the pinned index — so it
//! moves when the documents move. The numerator is read from the sources: a
//! test named `f_012_...`, `p_004_...` or `l_110_...` whose body carries an
//! assertion, or a `//! cites:` header on a file that has an asserting test
//! in it. A test that cannot fail is not a test, and a citation on a body
//! with no assertion is the failure mode of every traceability matrix ever
//! built, so the assertion is what is looked for.
//!
//! `F` rules ratchet: the uncovered count may not rise, and may not fall
//! without the number in `traceability.toml` falling with it. KM43 rules are
//! reported, because which of them bind this controller rather than a client
//! is what origin89hq/km43#31 will say.
//!
//! The scanner reads text, not syntax: a string literal that looks like a
//! test declaration counts. That is the price of not parsing Rust here, and
//! it errs towards refusing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::repo::Repo;

/// The checks of the gate an untestable rule may nominate as its test.
const GATE_CHECKS: &[&str] = &["cross", "deps", "images", "traceability"];

#[derive(Deserialize)]
struct Declared {
    uncovered_at_most: usize,
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

/// Every `**X-nnn**` at the start of a line in a document.
fn rules_in_markdown(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("**")?;
            let end = rest.find("**")?;
            let id = rest.get(..end)?;
            is_rule_id(id).then(|| id.to_owned())
        })
        .collect()
}

/// The identifiers in the pinned KM43 index.
fn rules_in_index(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with("id\t"))
        .filter_map(|line| line.split('\t').next())
        .filter(|id| is_rule_id(id))
        .map(str::to_owned)
        .collect()
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

/// The body of the function that starts at `open`, by brace counting.
fn body_after(source: &str, open: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut started = false;
    for (offset, ch) in source.get(open..)?.char_indices() {
        match ch {
            '{' => {
                depth = depth.saturating_add(1);
                started = true;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if started && depth == 0 {
                    return source.get(open..open.saturating_add(offset));
                }
            }
            _ => {}
        }
    }
    None
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
}

fn citations_in(source: &str) -> Citations {
    let mut found = Citations::default();
    let mut any_asserting_fn = false;
    let mut search = 0;
    while let Some(at) = source.get(search..).and_then(|rest| rest.find("fn ")) {
        let at = search.saturating_add(at).saturating_add(3);
        search = at;
        let Some(rest) = source.get(at..) else { break };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let asserts = body_after(source, at).is_some_and(|body| body.contains("assert"));
        any_asserting_fn |= asserts;
        if let Some(id) = cited_by_name(&name) {
            if asserts {
                found.asserting.insert(id);
            } else {
                found.hollow.insert(id);
            }
        }
    }
    // A header is a claim by a whole file, and it stands only over a file
    // that has a test which can fail.
    if source.contains("#[test]") && any_asserting_fn {
        for line in source.lines() {
            let Some(cites) = line.strip_prefix("//! cites:") else {
                continue;
            };
            for word in cites.split(',') {
                let id = word.trim();
                if is_rule_id(id) {
                    found.header.insert(id.to_owned());
                }
            }
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
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
            out.push(path);
        }
    }
    Ok(())
}

/// Every citation in the sources, and the file each hollow one sits in.
fn citations_in_repo(repo: &Repo) -> Result<(Citations, BTreeMap<String, PathBuf>)> {
    let mut files = Vec::new();
    for dir in ["crates", "firmwares", "xtask"] {
        let dir = repo.root().join(dir);
        if dir.is_dir() {
            rust_files(&dir, &mut files)?;
        }
    }
    let mut all = Citations::default();
    let mut hollow_in = BTreeMap::new();
    for file in &files {
        let source =
            fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let found = citations_in(&source);
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
    let f_rules = rules_in_markdown(&requirements);
    ensure!(
        !f_rules.is_empty(),
        "docs/REQUIREMENTS.md names no **F-nnn** rule"
    );
    let index = fs::read_to_string(docs.join("km43").join("requirements.tsv"))
        .context("reading docs/km43/requirements.tsv")?;
    let km43_rules = rules_in_index(&index);
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
    let untestable: BTreeSet<&String> = declared.untestable.iter().map(|e| &e.id).collect();
    let is_covered = |id: &String| cited.asserting.contains(id) || cited.header.contains(id);

    let covered: Vec<&String> = f_rules.iter().filter(|id| is_covered(id)).collect();
    let uncovered: Vec<&String> = f_rules
        .iter()
        .filter(|id| !is_covered(id) && !untestable.contains(id))
        .collect();
    let km43_cited: Vec<&String> = km43_rules.iter().filter(|id| is_covered(id)).collect();
    let header_only: Vec<&String> = f_rules
        .iter()
        .chain(km43_rules.iter())
        .filter(|id| cited.header.contains(*id) && !cited.asserting.contains(*id))
        .collect();

    println!(
        "traceability: {} F rules — {} covered, {} declared untestable, {} uncovered (at most {})",
        f_rules.len(),
        covered.len(),
        untestable.len(),
        uncovered.len(),
        declared.uncovered_at_most
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
    if uncovered.len() > declared.uncovered_at_most {
        bail!(
            "{} F rules have no test and no declaration, above the {} traceability.toml allows: {}",
            uncovered.len(),
            declared.uncovered_at_most,
            list(&uncovered)
        );
    }
    if uncovered.len() < declared.uncovered_at_most {
        bail!(
            "{} F rules are uncovered and traceability.toml still allows {}: lower `uncovered_at_most` to {} so the ratchet holds",
            uncovered.len(),
            declared.uncovered_at_most,
            uncovered.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fixtures are assembled at run time so this file's own text never
    // reads as a citation to the scanner, which scans text and not syntax.
    fn declaration(name: &str, body: &str) -> String {
        format!("#[test]\nfn {name}() {{ {body} }}\n")
    }

    #[test]
    fn a_rule_is_read_from_the_start_of_a_line_only() {
        let doc = "**F-001** — first.\nSee **F-002** inline.\n**P-004** — a km43 rule.\n**F-12** — too short.\n";
        let rules = rules_in_markdown(doc);
        assert_eq!(rules.len(), 2);
        assert!(rules.contains("F-001"));
        assert!(rules.contains("P-004"));
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
        let source = declaration(&format!("{}_runs_low", "f_001"), "let _ = 1;")
            + &declaration(&format!("{}_idles_high", "f_002"), "assert!(true);");
        let found = citations_in(&source);
        assert!(found.hollow.contains("F-001"));
        assert!(found.asserting.contains("F-002"));
        assert!(!found.asserting.contains("F-001"));
    }

    #[test]
    fn a_header_counts_only_on_a_file_with_an_asserting_test() {
        let with =
            "//! cites: P-004, L-110\n".to_owned() + &declaration("x_y", "assert_eq!(1, 1);");
        let without = "//! cites: P-004\nfn nothing() {}\n";
        let hollow_test = "//! cites: P-004\n".to_owned() + &declaration("x_y", "let _ = 1;");
        assert_eq!(citations_in(&with).header.len(), 2);
        assert!(citations_in(without).header.is_empty());
        assert!(citations_in(&hollow_test).header.is_empty());
    }

    #[test]
    fn the_index_yields_its_identifiers_and_skips_its_comments() {
        let index =
            "# pinned\nid\tdocument\nP-001\tdocs/PROTOCOL.md\nL-010\tdocs/protocol/LINK.md\n";
        let rules = rules_in_index(index);
        assert_eq!(rules.len(), 2);
        assert!(rules.contains("L-010"));
    }
}
