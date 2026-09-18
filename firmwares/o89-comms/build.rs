//! Name the linker script esp-hal's runtime needs.
//!
//! Here and not in `.cargo/config.toml`, for the reason the controller's
//! build script gives: cargo finds that file by walking up from the working
//! directory, and the gate builds from the repository root.

fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rerun-if-changed=build.rs");
}
