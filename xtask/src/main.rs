//! The gate: what `cargo test` and `cargo clippy` cannot check because they
//! build for the laptop.
//!
//! `cargo xtask check` cross-compiles every `#![no_std]` crate for both
//! targets, builds the three images in release and measures the bytes that
//! reach the part, and refuses a dependency that crosses a boundary the
//! design draws. Each check here is one that has been watched go red.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cross;
mod deps;
mod images;
mod repo;

#[derive(Parser)]
#[command(about = "The firmware gate")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Everything CI runs that `cargo test` does not: cross-compiles, the
    /// dependency rules, the three images and their sizes.
    Check,
    /// Build the three images and print their sizes against the budgets.
    Sizes {
        /// Append a row per image to `docs/sizes.tsv`.
        #[arg(long)]
        record: bool,
    },
}

fn main() -> Result<()> {
    let repo = repo::Repo::locate()?;
    match Cli::parse().command {
        Command::Check => {
            cross::check(&repo)?;
            deps::check(&repo)?;
            let measured = images::build_and_measure(&repo)?;
            images::report(&measured);
            images::enforce(&measured)?;
            println!("xtask check: clear");
        }
        Command::Sizes { record } => {
            let measured = images::build_and_measure(&repo)?;
            images::report(&measured);
            if record {
                images::record(&repo, &measured)?;
            }
        }
    }
    Ok(())
}
