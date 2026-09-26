//! The gate: what `cargo test` and `cargo clippy` cannot check because they
//! build for the laptop.
//!
//! `cargo xtask check` cross-compiles every `#![no_std]` crate for both
//! targets, refuses a dependency that crosses a boundary the design draws,
//! holds the pin table against the board module, sorts every numbered rule
//! into covered, declared untestable or uncovered and holds the ratchet on
//! the last, and builds the three images in release and measures the bytes
//! that reach the part. Each check here is one that has been watched go red.

use anyhow::Result;
use clap::{Parser, Subcommand};

/// The firmwares' build-time version text, compiled here for its tests: a
/// build script cannot hold any.
#[cfg(test)]
#[path = "../../firmwares/link_version.rs"]
#[expect(
    dead_code,
    reason = "the build scripts call `emit`; the gate tests the pure half"
)]
mod link_version;
#[cfg(test)]
mod link_version_tests;

#[cfg(test)]
mod boot_matches_tests;
#[cfg(test)]
mod frozen_watchdog_tests;

mod bootloader;
mod cross;
mod deps;
mod images;
mod pins;
mod repo;
mod traceability;

#[derive(Parser)]
#[command(about = "The firmware gate")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Everything CI runs that `cargo test` does not: cross-compiles, the
    /// dependency rules, the pin table, the module's bootloader against its
    /// inputs, the rules' coverage, the three images and their sizes.
    Check,
    /// Build the three images and print their sizes against the budgets.
    Sizes {
        /// Append a row per image to `docs/sizes.tsv`.
        #[arg(long)]
        record: bool,
    },
    /// Print the flags every image is built with, as
    /// `CARGO_ENCODED_RUSTFLAGS` takes them, for a recipe that builds an
    /// image with `cargo run`.
    Rustflags,
}

fn main() -> Result<()> {
    let repo = repo::Repo::locate()?;
    match Cli::parse().command {
        Command::Check => {
            cross::check(&repo)?;
            deps::check(&repo)?;
            pins::check(&repo)?;
            bootloader::check(&repo)?;
            traceability::check(&repo)?;
            let measured = images::build_and_measure(&repo)?;
            images::report(&measured);
            images::enforce(&measured)?;
            println!("xtask check: clear");
        }
        Command::Rustflags => print!("{}", images::rustflags(&repo)?),
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
