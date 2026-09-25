use super::*;
use km43::{ConfigAnswer, ConfigSection, SetConfig, SetConfigAck, SetConfigOperation};

#[test]
fn p_108_p_100_damaged_sections_read_zero_then_repair_through_signed_session() {
    // Capabilities: none; damage is injected into FRAM before session creation.
    for section in [
        ConfigSection::IdentityAndSite,
        ConfigSection::Network,
        ConfigSection::GeneratorBehaviour,
        ConfigSection::FrostBehaviour,
        ConfigSection::ScheduleBehaviour,
        ConfigSection::LoadShedBehaviour,
    ] {
        for malformed in [false, true] {
            let mut bench = linked();
            crate::configuration::damage_config(&mut bench.fram, section, malformed);
            let keys = reread(&mut bench.fram).expect("boot");
            bench.endpoint.sessions = Sessions::new(keys);
            announce(&mut bench, 1);
            let mut client = Client::on(1);
            let _ = client.open(&mut bench);
            let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
            let len = match section {
                ConfigSection::IdentityAndSite => {
                    body[..4].copy_from_slice(&[0xa1, 1, 0x61, b'a']);
                    4
                }
                ConfigSection::Network => km43::NetworkWrite {
                    join: Some(km43::JoinWrite {
                        ssid: km43::Ssid::new("cabin").expect("ssid"),
                        psk: Some(km43::Passphrase::new("correct horse").expect("psk")),
                    }),
                    country: km43::Country::new("CA").expect("country"),
                    hostname: km43::Hostname::new("origin89").expect("host"),
                }
                .encode(&mut body)
                .expect("network"),
                ConfigSection::GeneratorBehaviour
                | ConfigSection::FrostBehaviour
                | ConfigSection::ScheduleBehaviour
                | ConfigSection::LoadShedBehaviour => km43::BehaviourSection { shadow: true }
                    .encode(&mut body)
                    .expect("behaviour"),
                ConfigSection::Channels | ConfigSection::BusesAndDevices | ConfigSection::Cloud => {
                    panic!("unsupported section")
                }
            };
            let written = &body[..len];
            for (expected_version, outcome, version) in
                [(1, SetConfig::StaleVersion, 0), (0, SetConfig::Accepted, 1)]
            {
                let payload = read_config(&mut client, &mut bench, section);
                let answer = ConfigAnswer::decode(&payload).expect("config answer, not BusyRetry");
                assert_eq!(
                    (answer.section(), answer.version(), answer.body()),
                    (section, 0, None)
                );
                if section == ConfigSection::Network {
                    assert!(
                        !bench
                            .comms
                            .heard
                            .iter()
                            .any(|heard| matches!(heard, Heard::NetConfig { .. }))
                    );
                }
                let ack = write_config(
                    &mut client,
                    &mut bench,
                    SetConfigOperation {
                        section,
                        expected_version,
                        body: written,
                    },
                );
                assert_eq!((ack.version, ack.outcome), (version, outcome));
            }
            let payload = read_config(&mut client, &mut bench, section);
            let answer = ConfigAnswer::decode(&payload).expect("config answer");
            assert_eq!(answer.version(), 1);
            if section == ConfigSection::Network {
                let read =
                    km43::NetworkRead::decode(answer.body().expect("body")).expect("network");
                assert_eq!(read.country, km43::Country::new("CA").expect("country"));
                assert_eq!(
                    read.hostname,
                    km43::Hostname::new("origin89").expect("hostname")
                );
                let join = read.join.expect("join");
                assert_eq!(join.ssid, km43::Ssid::new("cabin").expect("ssid"));
                assert!(join.psk_set);
                assert!(!payload.windows(13).any(|bytes| bytes == b"correct horse"));
            } else {
                assert_eq!(answer.body(), Some(written));
            }
        }
    }
}

fn read_config(client: &mut Client, bench: &mut Bench, section: ConfigSection) -> Vec<u8> {
    let mut request = [0; 160];
    let len = km43::GetConfigRequest { section }
        .encode(&mut request)
        .expect("get");
    let frame = client.sealed(MessageType::GetConfig, &request[..len]);
    let answers = client.send(bench, &frame);
    client
        .opened(answers.last().expect("answer"))
        .expect("sealed")
        .1
}

fn write_config(
    client: &mut Client,
    bench: &mut Bench,
    operation: SetConfigOperation<'_>,
) -> SetConfigAck {
    let mut request = [0; 160];
    let len = operation.encode(&mut request).expect("operation");
    let frame = client.signed(MessageType::SetConfig, &request[..len]);
    let answers = client.send(bench, &frame);
    let (_, body) = client
        .opened(answers.last().expect("answer"))
        .expect("sealed");
    SetConfigAck::decode(&body).expect("ack")
}
