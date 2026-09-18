//! Every pin lives in exactly two places that cannot disagree.
//!
//! `docs/BOARD-A.md` carries the pin map from the netlist, with the sources;
//! the controller's board module names every pin the image takes, and says
//! by name which pins it leaves alone on purpose. This reads both, the
//! document as its pin-map table and the module as Rust syntax, and refuses
//! a row nobody takes or leaves alone, a pin taken that no row documents,
//! and a pin both taken and left alone. A pin the code takes that the
//! document does not know is a wire somebody will trace from the wrong
//! table; a row the code never reaches is a function the board offers and
//! the firmware forgot.
//!
//! cites: F-083

use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, bail, ensure};
use syn::visit::Visit;
use syn::{Attribute, Expr, ExprField, ExprLit, Lit, Member, Meta};

use crate::repo::Repo;

/// The pin map, from the netlist.
const DOCUMENT: &str = "docs/BOARD-A.md";
/// The section of it that is the table.
const SECTION: &str = "## Revision A pin map";
/// The one file in the controller that names a pin.
const MODULE: &str = "firmwares/o89-controller/src/board.rs";
/// The header line in the module's doc that names the pins left alone.
const LEAVES_ALONE: &str = "leaves alone:";

/// A pin name such as `PB6`: a port letter A to F and a number under sixteen.
fn is_pin(word: &str) -> bool {
    let Some(rest) = word.strip_prefix('P') else {
        return false;
    };
    let mut chars = rest.chars();
    let Some(port) = chars.next() else {
        return false;
    };
    let number = chars.as_str();
    ('A'..='F').contains(&port)
        && !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit())
        && number.parse::<u8>().is_ok_and(|n| n < 16)
}

/// The pins in the first cell of every row of the pin-map table.
fn documented(markdown: &str) -> Result<BTreeSet<String>> {
    let section = markdown
        .split_once(SECTION)
        .with_context(|| format!("{DOCUMENT} has no `{SECTION}` section"))?
        .1;
    let table = section.split("\n## ").next().unwrap_or_default();
    let pins: BTreeSet<String> = table
        .lines()
        .filter_map(|line| line.strip_prefix('|'))
        .filter_map(|row| row.split('|').next())
        .flat_map(|cell| {
            cell.split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| is_pin(word))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    ensure!(!pins.is_empty(), "{DOCUMENT}'s pin map names no pin");
    Ok(pins)
}

/// Every `p.PXn` in a source: what the module takes from `Peripherals`.
struct Taken(BTreeSet<String>);

impl<'ast> Visit<'ast> for Taken {
    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let Expr::Path(base) = &*node.base
            && base.path.is_ident("p")
            && let Member::Named(field) = &node.member
            && is_pin(&field.to_string())
        {
            self.0.insert(field.to_string());
        }
        syn::visit::visit_expr_field(self, node);
    }
}

/// The pins named on the module's `leaves alone:` header line.
fn left_alone(attrs: &[Attribute]) -> Result<BTreeSet<String>> {
    let line = attrs
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
        .find_map(|text| text.trim().strip_prefix(LEAVES_ALONE).map(str::to_owned))
        .with_context(|| format!("{MODULE} has no `//! {LEAVES_ALONE}` line"))?;
    let mut pins = BTreeSet::new();
    for word in line
        .split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
    {
        ensure!(
            is_pin(word),
            "{MODULE} leaves alone `{word}`, which is not a pin name"
        );
        pins.insert(word.to_owned());
    }
    Ok(pins)
}

/// Parse the module: what it takes, and what it leaves alone.
fn module(source: &str) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let file = syn::parse_file(source).with_context(|| format!("parsing {MODULE}"))?;
    let mut taken = Taken(BTreeSet::new());
    taken.visit_file(&file);
    let alone = left_alone(&file.attrs)?;
    Ok((taken.0, alone))
}

/// Hold the three sets against each other, naming every disagreement.
fn reconcile(
    documented: &BTreeSet<String>,
    taken: &BTreeSet<String>,
    alone: &BTreeSet<String>,
) -> Result<()> {
    let mut faults = Vec::new();
    for pin in alone {
        if !documented.contains(pin) {
            faults.push(format!(
                "{pin} is left alone by the board module and {DOCUMENT} has no row for it"
            ));
        }
        if taken.contains(pin) {
            faults.push(format!("{pin} is both taken and left alone"));
        }
    }
    for pin in taken {
        if !documented.contains(pin) {
            faults.push(format!(
                "the board module takes {pin}, which {DOCUMENT} does not list"
            ));
        }
    }
    for pin in documented {
        if !taken.contains(pin) && !alone.contains(pin) {
            faults.push(format!(
                "{DOCUMENT} lists {pin} and the board module neither takes it nor leaves it alone"
            ));
        }
    }
    if !faults.is_empty() {
        bail!(
            "the pin table and the board module disagree:\n  {}",
            faults.join("\n  ")
        );
    }
    Ok(())
}

/// Read the document and the module, and hold them together.
pub fn check(repo: &Repo) -> Result<()> {
    let markdown = fs::read_to_string(repo.root().join(DOCUMENT))
        .with_context(|| format!("reading {DOCUMENT}"))?;
    let source = fs::read_to_string(repo.root().join(MODULE))
        .with_context(|| format!("reading {MODULE}"))?;
    let documented = documented(&markdown)?;
    let (taken, alone) = module(&source)?;
    reconcile(&documented, &taken, &alone)?;
    println!(
        "pin table held: {} pins documented, {} taken by the board module, {} left alone",
        documented.len(),
        taken.len(),
        alone.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|pin| (*pin).to_owned()).collect()
    }

    #[test]
    fn a_pin_name_is_a_port_letter_and_a_number_under_sixteen() {
        assert!(is_pin("PA0"));
        assert!(is_pin("PF1"));
        assert!(is_pin("PC15"));
        assert!(!is_pin("PC16"));
        assert!(!is_pin("PG0"));
        assert!(!is_pin("P0"));
        assert!(!is_pin("PA"));
        assert!(!is_pin("IWDG"));
        assert!(!is_pin("CN9"));
    }

    #[test]
    fn the_pin_map_is_read_from_its_own_section_and_first_cells_only() {
        let markdown = "# Board\n\n## Revision A pin map\n\n| Pin | Net |\n| --- | --- |\n| PB6 | `ESP_TX` |\n| PA2 / PA3 | RS-485 #1 |\n| PA4, PA5, PA6, PA7 | NOR |\n| PC0 | through R14 to PB9 |\n\n## Connectors\n\n| CN9 | PD0 and PD1 |\n";
        let found = documented(markdown).expect("a table");
        assert_eq!(
            found,
            pins(&["PB6", "PA2", "PA3", "PA4", "PA5", "PA6", "PA7", "PC0"])
        );
        assert!(documented("# nothing here\n").is_err());
        assert!(documented("## Revision A pin map\n\n| Pin |\n| --- |\n").is_err());
    }

    #[test]
    fn the_module_yields_what_split_takes_and_what_it_leaves_alone() {
        let source = "//! The board.\n//!\n//! leaves alone: PA13, PA14\n\nstruct Board { a: u8 }\nimpl Board {\n    fn split(p: Peripherals) -> Self {\n        let q = other();\n        let _ = q.PB1;\n        Self { a: p.PD0, b: p.PA2, c: p.IWDG, d: p.PA2 }\n    }\n}\n";
        let (taken, alone) = module(source).expect("parses");
        assert_eq!(taken, pins(&["PD0", "PA2"]));
        assert_eq!(alone, pins(&["PA13", "PA14"]));
        let no_header = "//! The board.\nfn f() {}\n";
        assert!(module(no_header).is_err());
        let not_a_pin = "//! leaves alone: PA13, SWCLK\nfn f() {}\n";
        assert!(module(not_a_pin).is_err());
    }

    #[test]
    fn f_083_a_table_and_a_module_that_agree_pass() {
        let documented = pins(&["PD0", "PD1", "PA13"]);
        let taken = pins(&["PD0", "PD1"]);
        let alone = pins(&["PA13"]);
        assert!(reconcile(&documented, &taken, &alone).is_ok());
    }

    #[test]
    fn f_083_a_row_nobody_takes_or_leaves_alone_is_refused() {
        let error = reconcile(&pins(&["PD0", "PD1"]), &pins(&["PD0"]), &pins(&[]))
            .expect_err("PD1 is unaccounted for");
        assert!(error.to_string().contains("lists PD1"));
    }

    #[test]
    fn f_083_a_pin_taken_that_no_row_documents_is_refused() {
        let error = reconcile(&pins(&["PD0"]), &pins(&["PD0", "PC9"]), &pins(&[]))
            .expect_err("PC9 is undocumented");
        assert!(error.to_string().contains("takes PC9"));
    }

    #[test]
    fn f_083_a_pin_left_alone_is_neither_taken_nor_undocumented() {
        let both = reconcile(&pins(&["PA13"]), &pins(&["PA13"]), &pins(&["PA13"]))
            .expect_err("taken and left alone");
        assert!(both.to_string().contains("both taken and left alone"));
        let unknown = reconcile(&pins(&["PD0"]), &pins(&["PD0"]), &pins(&["PA13"]))
            .expect_err("left alone with no row");
        assert!(unknown.to_string().contains("no row"));
        // Every disagreement is named, not only the first.
        let many = reconcile(
            &pins(&["PD0", "PD1"]),
            &pins(&["PD0", "PC9"]),
            &pins(&["PA13"]),
        )
        .expect_err("three faults");
        let text = many.to_string();
        assert!(text.contains("PD1") && text.contains("PC9") && text.contains("PA13"));
    }
}
