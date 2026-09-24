//! Published Wi-Fi bodies through the codecs used by both firmware hops.
#[cfg(test)]
mod vectors {
    use km43::*;
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
    #[test]
    fn p_217_p_219_p_220_l_200_l_201_l_202_l_204_published_wifi_bodies_round_trip_and_relay() {
        let vectors: Value = serde_json::from_str(VECTORS_JSON).expect("published JSON");
        let mut output = [0; MAX_PAYLOAD];
        let mut count = 0;
        for (name, value) in vectors["bodies"].as_object().expect("bodies") {
            if !name.starts_with("wifi") {
                continue;
            }
            let body = bytes(value, "body_cbor");
            let len = match name.as_str() {
                "wifiscan_0x11" => ScanRequest::decode(&body)
                    .expect("request")
                    .encode(&mut output),
                "wifiscan_0x91" | "wifiscan_refused_0x91" => ScanAnswer::decode(&body)
                    .expect("answer")
                    .encode(&mut output),
                "wifistatus_0x92" | "wifistatus_unknown_0x92" => WifiStatus::decode(&body)
                    .expect("status")
                    .encode(&mut output),
                "wifistatuschanged_0x0806" => WifiStatusChanged::decode(&body)
                    .expect("record")
                    .encode(&mut output),
                _ => panic!("new published Wi-Fi body {name}"),
            }
            .expect("encode");
            assert_eq!(&output[..len], body, "{name}");
            count += 1;
        }
        assert_eq!(count, 6);
        let mut count = 0;
        for (name, value) in vectors["link_local"].as_object().expect("link vectors") {
            if !name.starts_with("wifi_") {
                continue;
            }
            let body = bytes(value, "envelope_cbor");
            let envelope = LinkEnvelope::decode(&body).expect("envelope");
            let kind = LinkMessageType::try_from(envelope.opcode()).expect("kind");
            let header = LinkHeader {
                kind,
                session: SessionId::None,
                req_id: envelope.req_id(),
            };
            let len = match kind {
                LinkMessageType::WifiScan => ScanOrder::decode(envelope)
                    .expect("order")
                    .write(header, &mut output),
                LinkMessageType::WifiScanAck => ScanOrderVerdict::decode(envelope)
                    .expect("verdict")
                    .write(header, &mut output),
                LinkMessageType::WifiScanResult => {
                    let result = ScanResult::decode(envelope).expect("result");
                    // Relay the decoded rows unchanged through the same client codec.
                    if let Some(list) = result.list {
                        let len = ScanAnswer::new(
                            ScanState::Complete,
                            None,
                            Some(HeldList { age_ms: 0, list }),
                        )
                        .expect("held")
                        .encode(&mut output)
                        .expect("relay");
                        let answer = ScanAnswer::decode(&output[..len]).expect("client response");
                        assert_eq!(
                            answer.held().expect("rows").list.iter().collect::<Vec<_>>(),
                            list.iter().collect::<Vec<_>>()
                        );
                    }
                    result.write(header, &mut output)
                }
                LinkMessageType::WifiScanResultAck => ScanResultAck::decode(envelope)
                    .expect("result ack")
                    .write(header, &mut output),
                LinkMessageType::WifiState => RadioReport::decode(envelope)
                    .expect("report")
                    .write(header, &mut output),
                _ => panic!("new published Wi-Fi link body {name}"),
            }
            .expect("encode");
            assert_eq!(&output[..len], body, "{name}");
            count += 1;
        }
        assert_eq!(count, 7);
    }
}
