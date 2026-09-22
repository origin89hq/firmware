//! The module's bootloader is the one its build inputs describe.
//!
//! `firmwares/o89-comms/bootloader/esp32c6-bootloader.bin` is a binary a
//! review cannot read, and it is what the whole route writes and the slot
//! route requires (F-088). So the gate holds it to three things beside it
//! that a review can read: the SHA-256 `build.sh` writes next to it, the
//! rollback option in `sdkconfig.defaults`, and the ESP-IDF release the
//! script names, which the binary states in its own text. A binary that
//! moved without its hash, a configuration that lost the option, or a
//! script that moved the release without a rebuild each fail here.
//!
//! cites: F-088

use std::fs;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::repo::Repo;

/// Where the bootloader and its inputs live.
const DIR: &str = "firmwares/o89-comms/bootloader";
/// The binary the whole route writes.
const BINARY: &str = "esp32c6-bootloader.bin";
/// Its hash, as `shasum -a 256` writes it.
const HASH: &str = "esp32c6-bootloader.sha256";
/// The configuration it was built from.
const CONFIG: &str = "sdkconfig.defaults";
/// The script that built it, which names the ESP-IDF release.
const SCRIPT: &str = "build.sh";
/// The option that makes the bootloader roll an unconfirmed slot back.
const ROLLBACK: &str = "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y";
/// The line of the script that pins the release, up to the tag.
const IMAGE: &str = "idf=espressif/idf:";
/// The first byte of an ESP image.
const MAGIC: u8 = 0xE9;

/// Check the bootloader against its inputs.
pub fn check(repo: &Repo) -> Result<()> {
    let dir = repo.root().join(DIR);
    let read =
        |name: &str| fs::read(dir.join(name)).with_context(|| format!("reading {DIR}/{name}"));
    let binary = read(BINARY)?;
    let hash = String::from_utf8(read(HASH)?).context("the hash file is text")?;
    let config = String::from_utf8(read(CONFIG)?).context("the configuration is text")?;
    let script = String::from_utf8(read(SCRIPT)?).context("the script is text")?;
    verify(&binary, &hash, &config, &script)?;
    println!("bootloader: {BINARY} matches its hash, its configuration and its release");
    Ok(())
}

/// The binary against the three texts beside it.
fn verify(binary: &[u8], hash: &str, config: &str, script: &str) -> Result<()> {
    ensure!(
        binary.first() == Some(&MAGIC),
        "{BINARY} does not start with an ESP image header"
    );
    let recorded = hash
        .split_whitespace()
        .next()
        .with_context(|| format!("{HASH} is empty"))?;
    let actual = hex::encode(Sha256::digest(binary));
    if recorded != actual {
        bail!(
            "{BINARY} hashes to {actual}, and {HASH} records {recorded}: the binary or the hash \
             moved without the other. `just comms-bootloader` rebuilds both"
        );
    }
    ensure!(
        config.lines().any(|line| line.trim() == ROLLBACK),
        "{CONFIG} does not set {ROLLBACK}, which is what makes an unconfirmed slot roll back \
         (F-088)"
    );
    let tag = script
        .lines()
        .find_map(|line| line.trim().strip_prefix(IMAGE))
        .with_context(|| format!("{SCRIPT} has no `{IMAGE}<tag>` line naming the release"))?
        .trim();
    ensure!(!tag.is_empty(), "{SCRIPT} names an empty release");
    // The bootloader states its release in its own text, `ESP-IDF v5.5.1`
    // as a version string the log line formats in; the tag is that string.
    ensure!(
        contains(binary, tag.as_bytes()),
        "{BINARY} does not carry the release text `{tag}` that {SCRIPT} names: the script moved \
         without a rebuild"
    );
    Ok(())
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "#!/bin/sh\nset -eu\nidf=espressif/idf:v5.5.1\ndocker run \"$idf\"\n";
    const CONFIG: &str = "CONFIG_IDF_TARGET=\"esp32c6\"\nCONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n";

    fn binary() -> Vec<u8> {
        let mut bytes = vec![MAGIC, 0x03, 0x02, 0x30];
        bytes.extend_from_slice(b"I (%lu) %s: ESP-IDF %s 2nd stage bootloader\0v5.5.1\0");
        bytes
    }

    fn hash_of(bytes: &[u8]) -> String {
        format!(
            "{}  esp32c6-bootloader.bin\n",
            hex::encode(Sha256::digest(bytes))
        )
    }

    #[test]
    fn f_088_the_checkouts_bootloader_matches_its_hash_configuration_and_release() {
        let repo = Repo::locate().expect("the repository");
        check(&repo).expect("the committed bootloader passes its own gate");
    }

    #[test]
    fn f_088_a_bootloader_matching_its_hash_configuration_and_release_passes() {
        let binary = binary();
        verify(&binary, &hash_of(&binary), CONFIG, SCRIPT).expect("passes");
    }

    #[test]
    fn f_088_a_binary_that_moved_without_its_hash_is_refused() {
        let binary = binary();
        let mut moved = binary.clone();
        moved.push(0x00);
        let error = verify(&moved, &hash_of(&binary), CONFIG, SCRIPT)
            .expect_err("refused")
            .to_string();
        assert!(error.contains("moved without the other"), "{error}");
    }

    #[test]
    fn f_088_a_configuration_without_the_rollback_option_is_refused() {
        let binary = binary();
        let without =
            "CONFIG_IDF_TARGET=\"esp32c6\"\n# CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is not set\n";
        let error = verify(&binary, &hash_of(&binary), without, SCRIPT)
            .expect_err("refused")
            .to_string();
        assert!(error.contains("ROLLBACK_ENABLE"), "{error}");
    }

    #[test]
    fn f_088_a_script_naming_a_release_the_binary_does_not_carry_is_refused() {
        let binary = binary();
        let moved = SCRIPT.replace("v5.5.1", "v5.6.0");
        let error = verify(&binary, &hash_of(&binary), CONFIG, &moved)
            .expect_err("refused")
            .to_string();
        assert!(error.contains("v5.6.0"), "{error}");
    }

    #[test]
    fn f_088_a_file_that_is_not_an_esp_image_is_refused() {
        let binary = b"not an image".to_vec();
        assert!(verify(&binary, &hash_of(&binary), CONFIG, SCRIPT).is_err());
    }
}
