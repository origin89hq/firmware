use crate::SimFram;
use embassy_futures::block_on;
use km43::{ConfigAnswer, ConfigSection, SetConfig, SetConfigOperation};
use o89_core::{Configuration, Kept, Network, map};

#[test]
fn p_100_version_mismatch_precedes_body_validation() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let result = block_on(config.set(
        SetConfigOperation {
            section: ConfigSection::IdentityAndSite,
            expected_version: 1,
            body: &[0xa0],
        },
        &mut network,
        &mut part,
    ))
    .expect("ack");
    assert_eq!(result.outcome, SetConfig::StaleVersion);
    assert_eq!(part.bytes_written(), 0);
}

#[test]
fn p_108_never_written_has_zero_version_and_no_body() {
    let mut part = SimFram::fresh();
    let config = block_on(Configuration::read(&mut part)).expect("read");
    let network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let mut bytes = [0; 100];
    let len = config
        .answer(ConfigSection::IdentityAndSite, &network, &mut bytes)
        .expect("answer");
    let answer = ConfigAnswer::decode(&bytes[..len]).expect("decode");
    assert_eq!((answer.version(), answer.body()), (0, None));
}

#[test]
fn p_101_bad_values_and_bad_structure_have_distinct_refusals() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let operation = SetConfigOperation {
        section: ConfigSection::IdentityAndSite,
        expected_version: 0,
        body: &[0xa1, 1, 0x60],
    };
    assert_eq!(
        block_on(config.set(operation, &mut network, &mut part))
            .expect("ack")
            .outcome,
        SetConfig::Invalid
    );
    assert_eq!(
        block_on(config.set(
            SetConfigOperation {
                body: &[0xa0],
                ..operation
            },
            &mut network,
            &mut part
        )),
        Err(km43::ErrorCode::MalformedFrame)
    );
    assert_eq!(part.bytes_written(), 0);
}

#[test]
fn p_103_each_behaviour_preserves_its_explicit_shadow_flag() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    for section in [
        ConfigSection::GeneratorBehaviour,
        ConfigSection::FrostBehaviour,
        ConfigSection::ScheduleBehaviour,
        ConfigSection::LoadShedBehaviour,
    ] {
        for (version, shadow) in [(0, true), (1, false)] {
            let mut body = [0; km43::MAX_BEHAVIOUR_BYTES];
            let len = km43::BehaviourSection { shadow }
                .encode(&mut body)
                .expect("body");
            let ack = block_on(config.set(
                SetConfigOperation {
                    section,
                    expected_version: version,
                    body: &body[..len],
                },
                &mut network,
                &mut part,
            ))
            .expect("ack");
            assert_eq!(ack.outcome, SetConfig::Accepted);
            let mut bytes = [0; 100];
            let len = config
                .answer(section, &network, &mut bytes)
                .expect("answer");
            let answer = ConfigAnswer::decode(&bytes[..len]).expect("answer");
            assert_eq!(
                km43::BehaviourSection::decode(answer.body().expect("body"))
                    .expect("body")
                    .shadow,
                shadow
            );
        }
    }
}

#[test]
fn p_102_set_config_cut_at_every_storage_byte_keeps_old_or_new_section() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let first = SetConfigOperation {
        section: ConfigSection::IdentityAndSite,
        expected_version: 0,
        body: &[0xa1, 1, 0x61, b'a'],
    };
    assert_eq!(
        block_on(config.set(first, &mut network, &mut part))
            .expect("ack")
            .outcome,
        SetConfig::Accepted
    );
    part.reboot();
    let seed = part.clone();
    let second = SetConfigOperation {
        expected_version: 1,
        body: &[0xa1, 1, 0x61, b'b'],
        ..first
    };
    assert_eq!(
        block_on(config.set(second, &mut network, &mut part))
            .expect("ack")
            .outcome,
        SetConfig::Accepted
    );
    let steps = part.bytes_written();
    assert!(steps > 0);
    for cut in 0..=steps {
        let mut torn = seed.clone();
        let mut config = block_on(Configuration::read(&mut torn)).expect("read");
        let mut network =
            block_on(Kept::<Network, 160>::read(map::NETWORK, &mut torn)).expect("read");
        torn.cut_after(cut);
        let _ = block_on(config.set(second, &mut network, &mut torn));
        torn.reboot();
        let config = block_on(Configuration::read(&mut torn)).expect("reboot");
        let mut bytes = [0; 100];
        let len = config
            .answer(first.section, &network, &mut bytes)
            .expect("answer");
        let answer = ConfigAnswer::decode(&bytes[..len]).expect("decode");
        assert!(
            matches!(
                (answer.version(), answer.body()),
                (1, Some([0xa1, 1, 0x61, b'a'])) | (2, Some([0xa1, 1, 0x61, b'b']))
            ),
            "cut {cut}"
        );
    }
}

#[test]
fn p_106_debug_of_owned_network_and_credentials_redacts_passphrase() {
    let credentials = o89_core::Credentials {
        ssid: o89_core::Text::new("cabin").expect("ssid"),
        psk: o89_core::Psk::new("correct horse").expect("psk"),
        country: o89_core::Country::new(*b"CA").expect("country"),
        hostname: o89_core::Text::new("origin89").expect("hostname"),
    };
    let mut network = Network::NONE;
    network.set(credentials).expect("set");
    let rendered = format!("{credentials:?} {network:?}");
    assert!(!rendered.contains("correct horse"));
    assert!(!rendered.contains("99, 111, 114, 114, 101, 99, 116"));
    assert!(rendered.contains("Psk(13 bytes)"));
}
