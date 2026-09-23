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
    for section in [
        ConfigSection::IdentityAndSite,
        ConfigSection::Network,
        ConfigSection::GeneratorBehaviour,
        ConfigSection::FrostBehaviour,
        ConfigSection::ScheduleBehaviour,
        ConfigSection::LoadShedBehaviour,
    ] {
        let len = config
            .answer(section, &network, &mut bytes)
            .expect("answer");
        let answer = ConfigAnswer::decode(&bytes[..len]).expect("decode");
        assert_eq!((answer.version(), answer.body()), (0, None));
    }
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

#[test]
fn p_102_network_set_cut_at_every_byte_keeps_the_previous_or_new_credentials() {
    let mut seed = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut seed)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut seed)).expect("read");
    let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
    let write = km43::NetworkWrite {
        join: Some(km43::JoinWrite {
            ssid: km43::Ssid::new("cabin").expect("ssid"),
            psk: Some(km43::Passphrase::new("old secret").expect("psk")),
        }),
        country: km43::Country::new("CA").expect("country"),
        hostname: km43::Hostname::new("origin89").expect("host"),
    };
    let len = write.encode(&mut body).expect("body");
    let operation = SetConfigOperation {
        section: ConfigSection::Network,
        expected_version: 0,
        body: &body[..len],
    };
    assert_eq!(
        block_on(config.set(operation, &mut network, &mut seed))
            .expect("ack")
            .outcome,
        SetConfig::Accepted
    );
    let old = *network.present().expect("old");
    let write = km43::NetworkWrite {
        join: Some(km43::JoinWrite {
            ssid: km43::Ssid::new("new-cabin").expect("ssid"),
            psk: Some(km43::Passphrase::new("new secret").expect("psk")),
        }),
        ..write
    };
    let len = write.encode(&mut body).expect("body");
    let operation = SetConfigOperation {
        section: ConfigSection::Network,
        expected_version: 1,
        body: &body[..len],
    };
    let mut whole = seed.clone();
    whole.reboot();
    assert_eq!(
        block_on(config.set(operation, &mut network, &mut whole))
            .expect("ack")
            .outcome,
        SetConfig::Accepted
    );
    let new = *network.present().expect("new");
    let steps = whole.bytes_written();
    for cut in 0..=steps {
        let mut part = seed.clone();
        let mut network =
            block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
        part.cut_after(cut);
        let _ = block_on(config.set(operation, &mut network, &mut part));
        part.reboot();
        let network =
            block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("recover");
        assert!(
            network.present() == Some(&old) || network.present() == Some(&new),
            "cut {cut}"
        );
    }
}

#[test]
fn p_101_unsupported_sections_and_exhausted_versions_refuse_without_writes() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let operation = SetConfigOperation {
        section: ConfigSection::Cloud,
        expected_version: 0,
        body: &[0xa0],
    };
    let mut bytes = [0; 100];
    assert_eq!(
        config.answer(ConfigSection::Cloud, &network, &mut bytes),
        Err(km43::ErrorCode::UnknownSection)
    );
    assert_eq!(
        block_on(config.set(operation, &mut network, &mut part)),
        Err(km43::ErrorCode::UnknownSection)
    );
    assert_eq!(part.bytes_written(), 0);
    let mut encoded = [0; o89_core::IDENTITY_RECORD_BYTES];
    encoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    encoded[4..9].copy_from_slice(&[4, 0xa1, 1, 0x61, b'a']);
    let _ = block_on(map::SITE_CONFIG.prefix().write(
        &mut part,
        o89_core::Position::Start,
        &encoded,
    ))
    .expect("seed ceiling");
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    part.reboot();
    let result = block_on(config.set(
        SetConfigOperation {
            section: ConfigSection::IdentityAndSite,
            expected_version: u32::MAX,
            body: &[0xa0],
        },
        &mut network,
        &mut part,
    ))
    .expect("ack");
    assert_eq!(result.outcome, SetConfig::ExceedsCap);
    assert_eq!(part.bytes_written(), 0);
}

fn damaged_config(section: ConfigSection, malformed: bool) -> SimFram {
    use o89_core::{Fram, Position};
    let mut part = SimFram::fresh();
    match section {
        ConfigSection::Network => {
            if malformed {
                let _ = block_on(map::NETWORK.write(&mut part, Position::Start, &[0x42; 160]))
                    .expect("malformed");
            } else {
                block_on(part.write(map::COMMS_RELEASE.end(), &[0x42; 344]))
                    .expect("corrupt both slots");
            }
        }
        ConfigSection::IdentityAndSite => {
            if malformed {
                let _ = block_on(map::SITE_CONFIG.prefix().write(
                    &mut part,
                    Position::Start,
                    &[0x42; o89_core::IDENTITY_RECORD_BYTES],
                ))
                .expect("malformed");
            } else {
                block_on(part.write(map::RECENT_CUTS.end(), &[0x42; 64])).expect("corrupt A");
                block_on(part.write(
                    map::RECENT_CUTS.end().plus(o89_core::slot_bytes(2048)),
                    &[0x42; 64],
                ))
                .expect("corrupt B");
            }
        }
        ConfigSection::Channels
        | ConfigSection::BusesAndDevices
        | ConfigSection::GeneratorBehaviour
        | ConfigSection::FrostBehaviour
        | ConfigSection::ScheduleBehaviour
        | ConfigSection::LoadShedBehaviour
        | ConfigSection::Cloud => panic!("fixture only supports identity and network"),
    }
    part.reboot();
    part
}

#[test]
fn p_102_damaged_sections_accept_only_version_zero_and_keep_reads_refused_until_replaced() {
    for section in [ConfigSection::Network, ConfigSection::IdentityAndSite] {
        for malformed in [false, true] {
            let mut part = damaged_config(section, malformed);
            let mut config = block_on(Configuration::read(&mut part)).expect("read");
            let mut network =
                block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
            let mut encoded = [0; km43::MAX_NETWORK_WRITE_BYTES];
            let len = km43::NetworkWrite {
                join: None,
                country: km43::Country::new("CA").expect("country"),
                hostname: km43::Hostname::new("origin89").expect("host"),
            }
            .encode(&mut encoded)
            .expect("body");
            let body = if section == ConfigSection::Network {
                &encoded[..len]
            } else {
                &[0xa1, 1, 0x61, b'a'][..]
            };
            let mut answer = [0; 160];
            assert_eq!(
                config.answer(section, &network, &mut answer),
                Err(km43::ErrorCode::BusyRetry)
            );
            let operation = SetConfigOperation {
                section,
                expected_version: 7,
                body,
            };
            assert_eq!(
                block_on(config.set(operation, &mut network, &mut part))
                    .expect("ack")
                    .outcome,
                SetConfig::StaleVersion
            );
            assert_eq!(part.bytes_written(), 0);
            assert_eq!(
                block_on(config.set(
                    SetConfigOperation {
                        expected_version: 0,
                        ..operation
                    },
                    &mut network,
                    &mut part
                ))
                .expect("replacement")
                .outcome,
                SetConfig::Accepted
            );
            part.reboot();
            let config = block_on(Configuration::read(&mut part)).expect("read");
            let network =
                block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
            let len = config
                .answer(section, &network, &mut answer)
                .expect("read replacement");
            assert_eq!(
                ConfigAnswer::decode(&answer[..len])
                    .expect("answer")
                    .version(),
                1
            );
        }
    }
}
