//! The firmware's version as the link states it (KM43 L-034), for both
//! firmwares' build scripts: the package version with the commit it was
//! built from, `MAJOR.MINOR.PATCH[-PRE]+gXXXXXXXX`.
//!
//! The commit is the one `HEAD` names when the build script runs. A build
//! with uncommitted changes under the paths the image is made from says so:
//! its pre-release gains `dirty`, `0.0.0-dirty+g0123abcd`, so the text never
//! claims a commit the image was not built from alone. Anything that would
//! make a text KM43 refuses to write fails the
//! build instead: a package version outside L-034's limits, a `HEAD` that
//! is not a commit, or a tree git cannot read. An image that cannot state
//! itself is a link that never comes up, and the build is the cheaper place
//! to find out.
//!
//! [`link_version`] is the whole of the format and is tested by the gate,
//! which includes this file, against KM43's own encoder.

use std::error::Error;
use std::process::Command;

/// Hex digits of the commit L-034 puts after the `+g`.
const COMMIT_DIGITS: usize = 8;
/// The widest `MAJOR`, `MINOR` or `PATCH` L-034 allows.
const COMPONENT_DIGITS: usize = 3;
/// The longest pre-release L-034 allows, without its hyphen.
const PRE_RELEASE_LONGEST: usize = 8;
/// The pre-release identifier a build of uncommitted source carries.
const DIRTY: &str = "dirty";

/// Set `O89_LINK_VERSION` for the crate being built, and rerun the build
/// script when the commit `HEAD` names changes or anything under `sources`
/// does. `sources` are the paths, relative to the crate, that the image is
/// made from: the crate, the path crates it builds, and the manifests and
/// lockfiles that pin the rest.
pub fn emit(package_version: &str, sources: &[&str]) -> Result<(), Box<dyn Error>> {
    let head = git(&["rev-parse", "HEAD"])?;
    let mut status = vec!["status", "--porcelain", "--"];
    status.extend_from_slice(sources);
    let dirty = !git(&status)?.is_empty();
    let version = link_version(package_version, &head, dirty)?;
    println!("cargo:rustc-env=O89_LINK_VERSION={version}");
    for source in sources {
        println!("cargo:rerun-if-changed={source}");
    }
    println!(
        "cargo:rerun-if-changed={}",
        git(&["rev-parse", "--git-path", "HEAD"])?
    );
    // On a branch, the commit moves in the branch's ref; detached, in HEAD.
    if let Ok(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        println!(
            "cargo:rerun-if-changed={}",
            git(&["rev-parse", "--git-path", &branch])?
        );
    }
    Ok(())
}

/// The link's version text from the package's version, the full commit id
/// `HEAD` names and whether the sources carry uncommitted changes, or why
/// they cannot make one.
pub fn link_version(package_version: &str, head: &str, dirty: bool) -> Result<String, String> {
    let commit = head
        .get(..COMMIT_DIGITS)
        .filter(|_| head.len() >= COMMIT_DIGITS)
        .filter(|digits| {
            digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| format!("{head:?} is not a lowercase commit id"))?;
    let (core, pre) = match package_version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (package_version, None),
    };
    let components: Vec<&str> = core.split('.').collect();
    let component = |part: &&str| {
        (1..=COMPONENT_DIGITS).contains(&part.len())
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'))
    };
    if components.len() != 3 || !components.iter().all(component) {
        return Err(format!(
            "{package_version:?} is not MAJOR.MINOR.PATCH with at most {COMPONENT_DIGITS} digits each (L-034)"
        ));
    }
    let pre = match (pre, dirty) {
        (Some(pre), true) => Some(format!("{pre}.{DIRTY}")),
        (None, true) => Some(DIRTY.to_owned()),
        (Some(pre), false) => Some(pre.to_owned()),
        (None, false) => None,
    };
    if let Some(pre) = &pre {
        let identifier = |id: &str| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (!id.bytes().all(|b| b.is_ascii_digit())
                    || id.len() == 1
                    || !id.starts_with('0'))
        };
        if !(1..=PRE_RELEASE_LONGEST).contains(&pre.len()) || !pre.split('.').all(identifier) {
            let marked = if dirty {
                ", with `dirty` marking the uncommitted changes; commit them"
            } else {
                ""
            };
            return Err(format!(
                "{package_version:?} has a pre-release L-034 does not allow{marked}: at most {PRE_RELEASE_LONGEST} bytes of dot-separated identifiers"
            ));
        }
    }
    Ok(match pre {
        Some(pre) => format!("{core}-{pre}+g{commit}"),
        None => format!("{core}+g{commit}"),
    })
}

fn git(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let out = Command::new("git").args(args).output().map_err(|error| {
        format!("the firmware states its commit on the link (L-034), and git did not run: {error}")
    })?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
