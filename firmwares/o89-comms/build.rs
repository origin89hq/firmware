//! Name the linker script esp-hal's runtime needs, and state the version
//! the link carries (KM43 L-034).
//!
//! Here and not in `.cargo/config.toml`, for the reason the controller's
//! build script gives: cargo finds that file by walking up from the working
//! directory, and the gate builds from the repository root.

use std::env;
use std::error::Error;

#[path = "../link_version.rs"]
mod link_version;

fn main() -> Result<(), Box<dyn Error>> {
    link_version::emit(
        &env::var("CARGO_PKG_VERSION")?,
        &[
            ".",
            "../link_version.rs",
            "../Cargo.toml",
            "../Cargo.lock",
            "../../crates/o89-comms-core",
            "../../crates/o89-link",
            "../../Cargo.toml",
            "../../rust-toolchain.toml",
        ],
    )?;
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../link_version.rs");
    Ok(())
}
