//! Canonical BLE traces against the adapter used by the radio firmware.
//! JSON allocation belongs in this host harness, never in domain tests.

#[cfg(test)]
mod vectors {
    use km43::MAX_PAYLOAD;
    use km43::{BleError, BleMtu};
    use o89_comms_core::BlePipe;
    use serde_json::Value;

    fn decode(hex: &str, bytes: &mut [u8]) -> usize {
        assert!(hex.len().is_multiple_of(2));
        let len = hex.len() / 2;
        assert!(len <= bytes.len());
        for (pair, out) in hex.as_bytes().as_chunks::<2>().0.iter().zip(bytes) {
            let text = core::str::from_utf8(pair).expect("hex text");
            *out = u8::from_str_radix(text, 16).expect("hex byte");
        }
        len
    }

    fn error(error: BleError) -> &'static str {
        match error {
            BleError::Mtu => "mtu",
            BleError::ValueLimit => "value_limit",
            BleError::Length => "length",
            BleError::Sequence => "sequence",
            BleError::Busy => "busy",
            BleError::Buffer => "buffer",
            BleError::Idle => "idle",
        }
    }

    #[test]
    fn p_036_p_037_p_039_shared_ble_vectors_exercise_the_radio_adapter_codecs() {
        let mut pipe = BlePipe::new();
        let mut input = [0; MAX_PAYLOAD + 1];
        let mut expected = [0; MAX_PAYLOAD];
        let mut fragment = [0; km43::BLE_MAX_VALUE];
        let mut count = 0;
        let vectors: Value = serde_json::from_str(km43::VECTORS_JSON)
            .expect("the pinned crate ships valid canonical JSON");
        let steps = vectors
            .get("ble")
            .and_then(Value::as_array)
            .expect("the published vectors contain BLE steps");
        assert_eq!(steps.len(), 2_758, "consume every published step");
        for (index, step) in steps.iter().enumerate() {
            count += 1;
            let text = |key| {
                step.get(key)
                    .and_then(Value::as_str)
                    .expect("required text field")
            };
            let action = text("action");
            let mtu = BleMtu::new(
                step.get("mtu")
                    .and_then(Value::as_u64)
                    .expect("mtu")
                    .try_into()
                    .expect("mtu fits u16"),
            )
            .expect("valid mtu");
            let now = step.get("now_ms").and_then(Value::as_u64).expect("tick");
            let input_len = decode(text("input"), &mut input);
            let outcome = text("expected");
            let expected_len = decode(text("output"), &mut expected);
            let limit = match step.get("value_limit") {
                None => mtu.value_limit(),
                Some(limit) => mtu
                    .select(
                        limit
                            .as_u64()
                            .expect("value limit")
                            .try_into()
                            .expect("limit fits usize"),
                    )
                    .expect("valid limit"),
            };
            let actual = match action {
                "reset" => {
                    // Reset rows name scenarios rather than carry verdicts.
                    assert!(!outcome.is_empty(), "scenario name at step {index}");
                    pipe.reset();
                    continue;
                }
                "disconnect" => {
                    pipe.reset();
                    "ok"
                }
                "expire" => {
                    pipe.expire(now);
                    "ok"
                }
                "enqueue" => pipe
                    .enqueue(&input[..input_len], limit)
                    .map_or_else(error, |()| "ok"),
                "accepted" => pipe.accepted(true).map_or_else(error, |()| "ok"),
                "fragment" | "small_buffer" => {
                    let size = if action == "small_buffer" {
                        1
                    } else {
                        fragment.len()
                    };
                    match pipe.fragment(true, &mut fragment[..size]) {
                        Ok(len) => {
                            assert_eq!(&fragment[..len], &expected[..expected_len], "step {index}");
                            "ok"
                        }
                        Err(e) => error(e),
                    }
                }
                "receive" => match pipe.receive(&input[..input_len], mtu, now) {
                    Ok(Some(bytes)) => {
                        assert_eq!(bytes, &expected[..expected_len], "step {index}");
                        "message"
                    }
                    Ok(None) => "pending",
                    Err(e) => error(e),
                },
                _ => panic!("unknown action {action}"),
            };
            assert_eq!(actual, outcome, "step {index}");
        }
        assert_eq!(count, 2_758, "consume every published step");
    }
}
