//! The published `NetConfig` with its origin token, and the `LinkUp` of the
//! module that stored it, through the codecs both firmwares use (L-132,
//! L-133, L-138).
#[cfg(test)]
mod vectors {
    use km43::{LinkEnvelope, LinkMessageType, LinkUp, NetStamp, ReqId, VECTORS_JSON};
    use serde_json::Value;

    fn bytes(value: &Value, key: &str) -> Vec<u8> {
        let hex = value[key].as_str().expect("published hex");
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
            })
            .collect()
    }

    fn published(name: &str) -> Vec<u8> {
        let vectors: Value = serde_json::from_str(VECTORS_JSON).expect("published JSON");
        bytes(&vectors["link_local"][name], "envelope_cbor")
    }

    /// The controller's section the published `NetConfig` was sent from:
    /// created under the token, then written twice more.
    fn master(origin: km43::NetOrigin) -> o89_core::Network {
        let credentials = o89_core::Credentials {
            ssid: o89_core::Text::new("cabin").expect("ssid"),
            psk: o89_core::Psk::new("correct horse battery").expect("psk"),
            country: o89_core::Country::new(*b"CA").expect("country"),
            hostname: o89_core::Text::new("o89").expect("hostname"),
        };
        let mut network = o89_core::Network::NONE;
        for _ in 0..3 {
            network
                .set(credentials, origin)
                .expect("room in the version");
        }
        network
    }

    #[test]
    fn l_138_the_published_net_config_is_the_one_the_controller_sends_and_the_module_stores() {
        let envelope = published("net_config_set_0x65");
        let change = km43::NetChange::decode(LinkEnvelope::decode(&envelope).expect("envelope"))
            .expect("a written NetConfig");
        let km43::NetChange::Set { origin, .. } = change else {
            panic!("the published NetConfig is a set");
        };
        assert_eq!(origin.bytes(), b"home-sec");
        // The controller encodes its own section to the same bytes.
        let network = master(origin);
        let mut ours = [0; 256];
        let len = network
            .change()
            .expect("a written section")
            .write(
                km43::LinkHeader {
                    kind: LinkMessageType::NetConfig,
                    session: km43::SessionId::None,
                    req_id: ReqId(15),
                },
                &mut ours,
            )
            .expect("encodes");
        assert_eq!(&ours[..len], envelope.as_slice());
        // The module stores version and token in one record.
        let stored = o89_comms_core::Credential::decode(&envelope).expect("stored");
        assert_eq!(stored.stamp(), network.stamp());
        assert_eq!(
            o89_comms_core::Network::new(Some(stored)).stored(),
            network.stamp()
        );
    }

    #[test]
    fn l_133_the_published_link_up_of_the_module_that_stored_it_needs_no_push() {
        let envelope = published("link_up_0x60_written");
        let cache = LinkUp::decode(LinkEnvelope::decode(&envelope).expect("envelope"))
            .expect("a comms statement");
        let origin = cache.net_origin.expect("a written cache states its token");
        assert_eq!(cache.net_version, Some(3));
        let network = master(origin);
        assert!(!network.needs_push(&cache), "its own section, stored");
        let mut foreign = *origin.bytes();
        foreign[0] ^= 1;
        assert!(
            master(km43::NetOrigin::new(foreign)).needs_push(&cache),
            "the same version under any other token is pushed"
        );
        assert!(!matches!(network.stamp(), NetStamp::Unwritten));
    }
}
