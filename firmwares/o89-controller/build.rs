//! Put the memory map where the linker looks, name the scripts, and fix the
//! log level the image is built with.
//!
//! Three things have to be true or the build fails naming none of them: the
//! regions exist, `link.x` is the script, and `defmt.x` is there so the log
//! strings have a section to live in off the part. All three are here and not
//! in `.cargo/config.toml`, because cargo finds that file by walking up from
//! the working directory and the gate builds from the repository root.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[path = "../link_version.rs"]
mod link_version;

fn main() -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(env::var("OUT_DIR")?);
    link_version::emit(
        &env::var("CARGO_PKG_VERSION")?,
        &[
            ".",
            "../link_version.rs",
            "../Cargo.toml",
            "../Cargo.lock",
            "../../crates/o89-core",
            "../../crates/o89-link",
            "../../Cargo.toml",
            "../../rust-toolchain.toml",
        ],
    )?;

    // `bench` moves where the image links and nothing else.
    let bench = env::var_os("CARGO_FEATURE_BENCH").is_some();
    let map: &[u8] = if bench {
        include_bytes!("memory-bench.x")
    } else {
        include_bytes!("memory.x")
    };
    if bench {
        println!(
            "cargo:warning=building with the BENCH memory map: links at 0x08000000 and must never be flashed onto a unit that will take an update"
        );
    }
    fs::write(out.join("memory.x"), map)?;
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rustc-link-arg=-Tdefmt.x");
    // A SHA-1 of the linked image, placed after the vector table by memory.x.
    println!("cargo:rustc-link-arg=--build-id=sha1");

    // `defmt` filters at compile time, so this decides what is in the image
    // rather than what is printed. Set in the environment to change it;
    // `info` otherwise, so a build from any directory carries the same log.
    let level = env::var("DEFMT_LOG").unwrap_or_else(|_| "info".to_owned());
    println!("cargo:rustc-env=DEFMT_LOG={level}");

    println!("cargo:rerun-if-env-changed=DEFMT_LOG");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-bench.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../link_version.rs");
    Ok(())
}
