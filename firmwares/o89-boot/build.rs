//! Put `memory.x` where the linker looks, and name the script that lays the
//! image out.
//!
//! Here and not in `.cargo/config.toml`: cargo finds that file by walking up
//! from the working directory, so a build from the repository root would
//! never read it. Without `-Tlink.x` the cortex-m-rt layout is never applied
//! and the build succeeds with a two-byte image that has no vector table.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out.join("memory.x"), include_bytes!("memory.x"))?;
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
