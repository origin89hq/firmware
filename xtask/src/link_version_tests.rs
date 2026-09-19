//! The firmwares' build-time version text (`firmwares/link_version.rs`),
//! tested here because a build script cannot hold tests: every text it
//! makes is one KM43 writes, and every input that would make one KM43
//! refuses fails instead (L-034).

use km43::{LinkHeader, LinkMessageType, LinkUp, ReqId, SessionId, Side, Version};

use crate::link_version::link_version;

const HEAD: &str = "25be7cfc0ede2d860cf8ce7278c7ead246db0273";

/// Whether KM43's encoder writes a statement carrying `fw`.
fn km43_writes(fw: &str) -> bool {
    let statement = LinkUp {
        version: Version::V1_0,
        role: Side::Controller,
        fw,
        boot_id: 1,
        hw: "controller-a rev A",
        net_version: None,
    };
    let header = LinkHeader {
        kind: LinkMessageType::LinkUp,
        session: SessionId::None,
        req_id: ReqId(1),
    };
    statement.write(header, &mut [0u8; 256]).is_ok()
}

#[test]
fn l_034_the_version_is_the_package_version_with_the_commit_and_km43_writes_it() {
    let text = link_version("0.0.0", HEAD, false).expect("a version");
    assert_eq!(text, "0.0.0+g25be7cfc");
    assert!(km43_writes(&text));
    let pre = link_version("0.1.0-rc.1", HEAD, false).expect("a pre-release");
    assert_eq!(pre, "0.1.0-rc.1+g25be7cfc");
    assert!(km43_writes(&pre));
}

#[test]
fn l_034_the_widest_version_l_034_allows_is_made_and_written() {
    let widest = link_version("999.999.999-abcdefgh", HEAD, false).expect("at the limits");
    assert_eq!(widest.len(), 30, "under the field's 32 bytes");
    assert!(km43_writes(&widest));
    // An exactly eight-digit id is enough.
    assert!(link_version("1.2.3", "0123abcd", false).is_ok());
}

#[test]
fn l_034_a_version_km43_would_refuse_fails_the_build_instead() {
    for bad in [
        "1000.0.0",
        "0.0",
        "0.0.0.0",
        "01.0.0",
        "a.b.c",
        "0.0.0-toolongpre",
        "0.0.0-",
        "0.0.0-01",
    ] {
        let made = link_version(bad, HEAD, false);
        assert!(made.is_err(), "{bad} was accepted as {made:?}");
    }
    for head in ["", "25be7cf", "25BE7CFC0EDE", "zzzzzzzzzzzz"] {
        assert!(
            link_version("0.0.0", head, false).is_err(),
            "{head:?} was taken for a commit"
        );
    }
}

#[test]
fn l_034_a_build_of_uncommitted_source_says_so_and_km43_writes_it() {
    let text = link_version("0.0.0", HEAD, true).expect("a version");
    assert_eq!(text, "0.0.0-dirty+g25be7cfc");
    assert!(km43_writes(&text));
    let pre = link_version("0.1.0-rc", HEAD, true).expect("a pre-release");
    assert_eq!(pre, "0.1.0-rc.dirty+g25be7cfc");
    assert!(km43_writes(&pre));
}

#[test]
fn l_034_a_pre_release_with_no_room_for_dirty_fails_the_build() {
    let refused = link_version("0.1.0-rc.1", HEAD, true).expect_err("no room");
    assert!(refused.contains("dirty"), "{refused}");
    assert_eq!(
        link_version("0.1.0-rc.1", HEAD, false).expect("clean"),
        "0.1.0-rc.1+g25be7cfc"
    );
}
