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
    let package_version = env::var("CARGO_PKG_VERSION")?;
    // The acceptance image that omits its window says so on the link, so
    // the controller's log names what it is talking to. Two letters leave
    // room for `.dirty` within L-034's eight-byte cap.
    let version = if env::var_os("CARGO_FEATURE_NO_WINDOW").is_some() {
        format!("{package_version}-nw")
    } else {
        package_version
    };
    link_version::emit(
        &version,
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
