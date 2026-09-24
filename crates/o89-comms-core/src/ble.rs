//! BLE admission and KM43 codec use, independent of the radio and GATT host.
use crate::{Link, Peer, Refused, Tick};
use km43::{
    BleError, BleMtu, BleReceiver, BleSender, BleValueLimit, Conn, DisconnectReason, LinkTransport,
};

/// Two phones can use setup concurrently; raising this needs F-037 heap evidence.
pub const BLE_CONNECTIONS: usize = 2;
/// Selected ATT MTU; 244 value bytes leave the ATT and L2CAP headers in 251 bytes.
pub const BLE_ATT_MTU: usize = 247;
/// Maximum characteristic value we offer.
pub const BLE_VALUE_BYTES: usize = BLE_ATT_MTU - 3;

/// BLE worker slots only. Every occupied slot also owns a row of the shared table.
pub struct BleAdmission {
    slots: [Option<Conn>; BLE_CONNECTIONS],
}

impl BleAdmission {
    /// No transport exists at boot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; BLE_CONNECTIONS],
        }
    }

    /// Advertising grants no authorization; only a linked controller permits
    /// it. Once the station holds an address, a phone reaches the controller
    /// over the site network, so BLE advertises only while the pairing
    /// window is open. Clients already connected are kept (F-044).
    #[must_use]
    pub fn advertising(&self, link: &Link, now: Tick) -> bool {
        link.is_linked()
            && self.slots.iter().any(Option::is_none)
            && (!link.wifi.joined() || link.pairing_window(now).is_some())
    }

    /// Refuse at the BLE cap or shared table cap, without evicting a connection.
    pub fn connect(&mut self, link: &mut Link, peer: Peer) -> Result<(usize, Conn), Refused> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Refused::TableFull)?;
        let conn = link.connect(LinkTransport::Ble, peer)?;
        if let Some(owner) = self.slots.get_mut(slot) {
            *owner = Some(conn);
        }
        Ok((slot, conn))
    }

    /// Forget only the matching BLE worker after its transport has been torn down.
    pub fn release(&mut self, conn: Conn) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| **slot == Some(conn)) {
            *slot = None;
        }
    }
    /// Release exactly this transport. The shared table retains L-080's handle reservation.
    pub fn gone(&mut self, link: &mut Link, conn: Conn, reason: DisconnectReason) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| **slot == Some(conn)) {
            *slot = None;
            link.gone(conn, reason);
        }
    }
}

impl Default for BleAdmission {
    fn default() -> Self {
        Self::new()
    }
}

/// One bounded assembly and one pending message per connection. KM43 owns all fragmentation.
pub struct BlePipe {
    rx: BleReceiver,
    tx: BleSender,
}
impl Default for BlePipe {
    fn default() -> Self {
        Self::new()
    }
}
impl BlePipe {
    /// Empty buffers and transmit ID zero for a new connection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx: BleReceiver::new(),
            tx: BleSender::new(),
        }
    }
    /// Receive one characteristic value; invalid fragments discard the partial assembly.
    pub fn receive(
        &mut self,
        value: &[u8],
        mtu: BleMtu,
        now_ms: u64,
    ) -> Result<Option<&[u8]>, BleError> {
        self.rx.receive(value, mtu, now_ms)
    }
    /// Expire even if no further writes arrive.
    pub fn expire(&mut self, now_ms: u64) {
        self.rx.expire(now_ms);
    }
    /// Refuse a second pending message without replacing the first.
    pub fn enqueue(&mut self, bytes: &[u8], limit: BleValueLimit) -> Result<(), BleError> {
        self.tx.enqueue(bytes, limit)
    }
    /// Never offer a notification while its CCCD is disabled.
    pub fn fragment(&mut self, subscribed: bool, out: &mut [u8]) -> Result<usize, BleError> {
        if !subscribed {
            return Err(BleError::Busy);
        }
        self.tx.fragment(out)
    }
    /// Advance only after subscription was checked and the ordered host queue accepted it.
    pub fn accepted(&mut self, subscribed: bool) -> Result<(), BleError> {
        if !subscribed {
            return Err(BleError::Busy);
        }
        self.tx.accepted()
    }
    /// The adapter must purge host queues/disconnect too; no codec state survives reuse.
    pub fn reset(&mut self) {
        self.rx.reset();
        self.tx.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km43::{BLE_LAST_FLAG, BLE_TIMEOUT_MS, MAX_PAYLOAD};

    #[test]
    fn p_039_no_subscription_or_busy_queue_can_advance_the_sender() {
        let mut pipe = BlePipe::new();
        let mtu = BleMtu::new(23).expect("minimum");
        let mut value = [0; 20];
        pipe.enqueue(&[42; 30], mtu.value_limit()).expect("first");
        assert_eq!(pipe.enqueue(&[99], mtu.value_limit()), Err(BleError::Busy));
        assert_eq!(pipe.fragment(false, &mut value), Err(BleError::Busy));
        let len = pipe.fragment(true, &mut value).expect("fragment");
        assert_eq!(&value[..2], &[0, 0]);
        assert_eq!(pipe.accepted(false), Err(BleError::Busy));
        let before = value;
        assert_eq!(pipe.fragment(true, &mut value), Ok(len));
        assert_eq!(value, before);
        pipe.accepted(true).expect("admitted");
        let len = pipe.fragment(true, &mut value).expect("last");
        assert_eq!(&value[..2], &[0, BLE_LAST_FLAG | 1]);
        assert_eq!(len, 14);
        pipe.accepted(true).expect("last admitted");
        assert_eq!(pipe.fragment(true, &mut value), Err(BleError::Idle));
        pipe.enqueue(&[99], mtu.value_limit()).expect("next");
        let _ = pipe.fragment(true, &mut value).expect("next value");
        assert_eq!(&value[..3], &[1, BLE_LAST_FLAG, 99]);
    }

    #[test]
    fn p_036_malformed_timeout_and_disconnect_clear_partial_assemblies() {
        let mtu = BleMtu::new(23).expect("minimum");
        let mut pipe = BlePipe::new();
        for cleanup in 0..3 {
            assert_eq!(pipe.receive(&[0, 0, 42], mtu, 0), Ok(None));
            match cleanup {
                0 => {
                    assert_eq!(pipe.receive(&[0, 0, 7], mtu, 1), Err(BleError::Sequence));
                }
                1 => pipe.expire(BLE_TIMEOUT_MS),
                2 => pipe.reset(),
                _ => panic!("bounded loop"),
            }
            assert_eq!(
                pipe.receive(&[0, BLE_LAST_FLAG | 1, 7], mtu, 1),
                Err(BleError::Sequence)
            );
            assert_eq!(
                pipe.receive(&[1, BLE_LAST_FLAG, 8], mtu, 1),
                Ok(Some(&[8][..]))
            );
        }
        assert_eq!(
            pipe.receive(&[0, BLE_LAST_FLAG], mtu, 6000),
            Err(BleError::Length)
        );
    }

    #[test]
    fn p_037_full_envelopes_round_trip_at_minimum_and_negotiated_mtu() {
        for att in [23, 247, 517] {
            let mtu = BleMtu::new(att).expect("supported");
            let mut pipe = BlePipe::new();
            let mut rx = BlePipe::new();
            let body = [42; MAX_PAYLOAD];
            let mut value = [0; 512];
            pipe.enqueue(&body, mtu.value_limit())
                .expect("maximum message");
            let mut complete = false;
            for n in 0..128 {
                let len = match pipe.fragment(true, &mut value) {
                    Ok(len) => len,
                    Err(BleError::Idle) => break,
                    Err(e) => panic!("{e:?}"),
                };
                if let Some(bytes) = rx.receive(&value[..len], mtu, n).expect("valid") {
                    assert_eq!(bytes, body);
                    complete = true;
                }
                pipe.accepted(true).expect("admitted");
            }
            assert!(complete);
            pipe.reset();
            pipe.enqueue(&[1], mtu.value_limit())
                .expect("new connection");
            let _ = pipe.fragment(true, &mut value).expect("value");
            assert_eq!(&value[..3], &[0, BLE_LAST_FLAG, 1]);
        }
    }
}

/// Convert canonical registry UUID text to Bluetooth's little-endian 128-bit field.
#[must_use]
pub fn ble_uuid(text: &str) -> Option<[u8; 16]> {
    if text.len() != 36 {
        return None;
    }
    let mut value = 0u128;
    for (index, byte) in text.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else {
            let digit = char::from(byte).to_digit(16)?;
            value = value.checked_mul(16)?.checked_add(u128::from(digit))?;
        }
    }
    Some(value.to_le_bytes())
}

#[cfg(test)]
mod uuid_tests {
    use super::*;
    #[test]
    fn p_036_registry_uuid_is_little_endian_and_invalid_text_is_refused() {
        assert_eq!(
            ble_uuid(km43::BLE_SERVICE_UUID),
            Some([
                1, 0, 0, 48, 228, 25, 98, 155, 93, 74, 33, 124, 154, 232, 67, 171
            ])
        );
        assert_eq!(ble_uuid(""), None);
        assert_eq!(ble_uuid("ab43e89ax7c21-4a5d-9b62-19e430000001"), None);
        assert_eq!(ble_uuid("zb43e89a-7c21-4a5d-9b62-19e430000001"), None);
        assert_ne!(ble_uuid(km43::BLE_RX_UUID), ble_uuid(km43::BLE_TX_UUID));
    }
}
