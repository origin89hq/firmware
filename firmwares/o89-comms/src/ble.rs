//! Two BLE setup clients, each admitted through the shared link table.
//! The host and codecs use static buffers. Only the vendor radio/HCI adapter
//! allocates, from the existing radio heap after the recovery window.
//!
//! Advertising cancellation is requested within 100 ms of controller loss. Each worker owns
//! one GATT connection and one KM43 codec pair; Drop releases its shared row.
//! Writes and disconnects have deadlines. Idle reads wait at most one status
//! tick. A periodic HCI command must complete even while nobody is connected.
use crate::{clients, link::LINK};
use core::cell::RefCell;
use embassy_futures::{
    join::join_array,
    select::{Either, Either3, select, select3},
};
use embassy_sync::{
    blocking_mutex::{
        Mutex as Blocking,
        raw::{CriticalSectionRawMutex, NoopRawMutex},
    },
    mutex::Mutex,
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_radio::ble::controller::BleConnector;
use km43::{BleError, BleMtu, Conn, DisconnectReason, MAX_PAYLOAD};
use o89_comms_core::{
    BLE_ATT_MTU, BLE_CONNECTIONS, BLE_VALUE_BYTES, BleAdmission, BlePipe, Inbound, Peer, Status,
};
use trouble_host::prelude::*;

const PACKETS: usize = BLE_CONNECTIONS * 8;
const QUEUE: usize = BLE_CONNECTIONS * 4;
const ATTRIBUTES: usize = 16;
const COMMANDS: usize = BLE_CONNECTIONS * 2;
const STATUS: Duration = Duration::from_millis(100);
const WRITE: Duration = Duration::from_secs(1);
const CLOSE: Duration = Duration::from_secs(2);
const ANNOUNCE: Duration = Duration::from_secs(3);
const _: () = {
    assert!(trouble_host::config::DEFAULT_PACKET_POOL_SIZE == PACKETS);
    assert!(trouble_host::config::DEFAULT_PACKET_POOL_MTU == BLE_ATT_MTU + 4);
    assert!(trouble_host::config::L2CAP_RX_QUEUE_SIZE == QUEUE);
    assert!(trouble_host::config::L2CAP_TX_QUEUE_SIZE == QUEUE);
    assert!(trouble_host::config::CONNECTION_EVENT_QUEUE_SIZE == BLE_CONNECTIONS);
    assert!(BLE_VALUE_BYTES <= km43::BLE_MAX_VALUE);
    assert!(ATTRIBUTES >= 11); // GAP + GATT + KM43 service, RX, TX and CCCD.
};

type Controller = bt_hci::controller::ExternalController<BleConnector<'static>, COMMANDS>;
type Pool = DefaultPacketPool;
type Server<'a> = AttributeServer<'a, NoopRawMutex, Pool, ATTRIBUTES, BLE_CONNECTIONS>;
static ADMISSION: Blocking<CriticalSectionRawMutex, RefCell<BleAdmission>> =
    Blocking::new(RefCell::new(BleAdmission::new()));

fn reset() -> ! {
    esp_hal::system::software_reset()
}

/// Parse only the registry's canonical UUID text; Bluetooth carries it least-significant byte first.
fn uuid(text: &str) -> Option<[u8; 16]> {
    o89_comms_core::ble_uuid(text)
}

#[embassy_executor::task]
pub async fn run(bt: esp_hal::peripherals::BT<'static>) {
    let Ok(max_connections) = u16::try_from(BLE_CONNECTIONS) else {
        reset()
    };
    let Ok(connector) = BleConnector::new(
        bt,
        esp_radio::ble::Config::default().with_max_connections(max_connections),
    ) else {
        reset()
    };
    let controller = Controller::new(connector);
    let mut resources: HostResources<_, Pool, BLE_CONNECTIONS, BLE_CONNECTIONS> =
        HostResources::new();
    // A random static address is transport metadata only, never KM43 identity.
    let random = esp_hal::rng::Rng::new().random().to_le_bytes();
    let [a, b, c, d] = random;
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random([a, b, c, d, 0x89, 0xc0]))
        .build();
    let mut runner = stack.runner();
    let peripheral = Mutex::<NoopRawMutex, _>::new(stack.peripheral());
    let Some(service_uuid) = uuid(km43::BLE_SERVICE_UUID) else {
        reset()
    };
    let Some(rx_uuid) = uuid(km43::BLE_RX_UUID) else {
        reset()
    };
    let Some(tx_uuid) = uuid(km43::BLE_TX_UUID) else {
        reset()
    };
    let mut rx = [0; BLE_VALUE_BYTES];
    let mut tx = [0; BLE_VALUE_BYTES];
    let appearance = [0u8; 2];
    let mut table: AttributeTable<'_, NoopRawMutex, ATTRIBUTES> = AttributeTable::new();
    let mut gap = table.add_service(Service::new(0x1800u16));
    let _name = gap.add_characteristic_ro(0x2a00u16, b"Origin89");
    let _appearance = gap.add_characteristic_ro(0x2a01u16, &appearance);
    gap.build();
    table.add_service(Service::new(0x1801u16)).build();
    let empty: &[u8] = &[];
    let mut service = table.add_service(Service::new(Uuid::new_long(service_uuid)));
    let rx: Characteristic<&[u8]> = service
        .add_characteristic(
            Uuid::new_long(rx_uuid),
            [CharacteristicProp::WriteWithoutResponse],
            empty,
            &mut rx,
        )
        .build();
    let tx: Characteristic<&[u8]> = service
        .add_characteristic(
            Uuid::new_long(tx_uuid),
            [CharacteristicProp::Notify],
            empty,
            &mut tx,
        )
        .build();
    service.build();
    let server = Server::new(table);
    let mut advertising = [0; 31];
    let Ok(len) = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids128(&[service_uuid]),
        ],
        &mut advertising,
    ) else {
        reset()
    };
    let Some(advertising) = advertising.get(..len) else {
        reset()
    };
    let mut pipes = [const { BlePipe::new() }; BLE_CONNECTIONS];
    let workers = pipes
        .each_mut()
        .map(|pipe| worker(&peripheral, &server, rx, tx, advertising, pipe));
    // Any host error or worker termination resets; no unowned transport survives.
    let _ = select3(runner.run(), join_array(workers), health(&stack)).await;
    reset();
}

async fn health(stack: &Stack<'_, Controller, Pool>) {
    loop {
        if !matches!(
            with_timeout(
                CLOSE,
                stack.command(bt_hci::cmd::info::ReadLocalVersionInformation::new())
            )
            .await,
            Ok(Ok(_))
        ) {
            reset();
        }
        crate::radio::ble_progress();
        Timer::after_secs(1).await;
    }
}

async fn advertising_allowed() -> bool {
    let link = LINK.lock().await;
    ADMISSION.lock(|state| state.borrow().advertising(&link))
}

async fn controller_lost() {
    loop {
        if !LINK.lock().await.is_linked() {
            return;
        }
        Timer::after(STATUS).await;
    }
}

/// Keeps mailbox ownership and the BLE cap aligned for every exit, including cancellation.
struct Row {
    _shared: clients::Row,
    conn: Conn,
}
impl Drop for Row {
    fn drop(&mut self) {
        ADMISSION.lock(|state| state.borrow_mut().release(self.conn));
    }
}

async fn worker(
    peripheral: &Mutex<NoopRawMutex, Peripheral<'_, Controller, Pool>>,
    server: &Server<'_>,
    rx: Characteristic<&[u8]>,
    tx: Characteristic<&[u8]>,
    advertising: &[u8],
    pipe: &mut BlePipe,
) {
    loop {
        pipe.reset();
        if !advertising_allowed().await {
            Timer::after(STATUS).await;
            continue;
        }
        // Only one advertiser at a time; the other worker may already carry a client.
        // Its lock wait owns no connection and the gate is checked again after acquisition.
        let mut peripheral = peripheral.lock().await;
        if !advertising_allowed().await {
            drop(peripheral);
            Timer::after(STATUS).await;
            continue;
        }
        let accepted = select(
            async {
                let acceptor = peripheral
                    .advertise(
                        &AdvertisementParameters::default(),
                        Advertisement::ConnectableScannableUndirected {
                            adv_data: advertising,
                            scan_data: &[],
                        },
                    )
                    .await
                    .map_err(|_| ())?;
                acceptor.accept().await.map_err(|_| ())
            },
            controller_lost(),
        )
        .await;
        drop(peripheral);
        let connection = match accepted {
            Either::First(Ok(conn)) => conn,
            Either::First(Err(())) => {
                Timer::after(STATUS).await;
                continue;
            }
            Either::Second(()) => continue,
        };
        let mut address = connection.peer_address().addr.into_inner();
        address.reverse();
        let admitted = {
            let mut link = LINK.lock().await;
            ADMISSION.lock(|state| state.borrow_mut().connect(&mut link, Peer::Ble(address)))
        };
        if let Ok((slot, conn)) = admitted {
            let index = clients::BLE_FIRST.saturating_add(slot);
            let row = Row {
                _shared: clients::Row::hold(index, conn),
                conn,
            };
            if let Ok(gatt) = connection.clone().with_attribute_server(server) {
                if matches!(with_timeout(ANNOUNCE, announced(conn)).await, Ok(true)) {
                    session(&gatt, rx, tx, conn, index, pipe).await;
                }
                // Cancel all local values before asking the controller to end the connection.
                pipe.reset();
                let reason = if gatt.raw().is_connected() {
                    DisconnectReason::TransportError
                } else {
                    DisconnectReason::ClosedByClient
                };
                LINK.lock().await.gone(conn, reason);
                disconnect(&gatt).await;
            } else {
                connection.disconnect();
                reset();
            }
            drop(row);
        } else {
            connection.disconnect();
            if !matches!(
                with_timeout(CLOSE, connection.next()).await,
                Ok(ConnectionEvent::Disconnected { .. })
            ) {
                reset();
            }
        }
        // Give the host runner a turn before advertising again.
        Timer::after(STATUS).await;
    }
}

async fn announced(conn: Conn) -> bool {
    loop {
        match LINK.lock().await.status(conn) {
            Some(Status::Open) => return true,
            Some(Status::Announcing) => {}
            Some(Status::Close(_)) | None => return false,
        }
        Timer::after(STATUS).await;
    }
}

async fn disconnect(gatt: &GattConnection<'_, '_, Pool>) {
    if !gatt.raw().is_connected() {
        return;
    }
    gatt.raw().disconnect();
    let stopped = with_timeout(CLOSE, async {
        loop {
            if matches!(gatt.next().await, GattConnectionEvent::Disconnected { .. }) {
                return;
            }
        }
    })
    .await;
    if stopped.is_err() {
        reset();
    }
}

async fn session(
    gatt: &GattConnection<'_, '_, Pool>,
    rx: Characteristic<&[u8]>,
    tx: Characteristic<&[u8]>,
    conn: Conn,
    index: usize,
    pipe: &mut BlePipe,
) {
    let mut stamped = [0; MAX_PAYLOAD];
    let mut subscribed = false;
    loop {
        pipe.expire(Instant::now().as_millis());
        let turn = select3(gatt.next(), clients::receive(index), Timer::after(STATUS)).await;
        if LINK.lock().await.status(conn) != Some(Status::Open) {
            return;
        }
        // GATT processes Exchange MTU inside next(); read the result after that wait.
        let Ok(mtu) = BleMtu::new(gatt.raw().att_mtu()) else {
            return;
        };
        match turn {
            Either3::First(GattConnectionEvent::Disconnected { .. }) | Either3::Second(None) => {
                return;
            }
            Either3::First(GattConnectionEvent::Gatt { event }) => {
                let mut inbound = None;
                if let GattEvent::Write(write) = &event
                    && write.handle() == rx.handle
                {
                    // A phone must subscribe before sending Discover. No permission is inferred.
                    if !tx.should_notify(gatt) {
                        return;
                    }
                    let link = LINK.lock().await;
                    inbound = write
                        .with_data(|offset, value| {
                            if offset != 0 {
                                return Err(());
                            }
                            let message = pipe
                                .receive(value, mtu, Instant::now().as_millis())
                                .map_err(|_| ())?;
                            match message {
                                Some(bytes) => link
                                    .from_client(conn, bytes, &mut stamped)
                                    .ok_or(())?
                                    .map(Some)
                                    .map_err(|_| ()),
                                None => Ok(None),
                            }
                        })
                        .ok();
                    if inbound.is_none() {
                        return;
                    }
                }
                let reply = match event {
                    GattEvent::Write(write) if write.handle() == rx.handle => {
                        write.accept_unprocessed()
                    }
                    other => other.accept(),
                };
                let Ok(reply) = reply else {
                    return;
                };
                if with_timeout(WRITE, reply.send()).await.is_err() {
                    return;
                }
                // Subscription loss clears both directions and closes before reuse.
                let now_subscribed = tx.should_notify(gatt);
                if subscribed && !now_subscribed {
                    pipe.reset();
                    return;
                }
                subscribed = now_subscribed;
                let carried = match inbound.flatten() {
                    Some(Inbound::Forward(len)) => {
                        clients::forward(conn, stamped.get(..len).unwrap_or(&[])).await
                    }
                    Some(Inbound::Answer(len)) => {
                        send(gatt, tx, pipe, stamped.get(..len).unwrap_or(&[]), mtu).await
                    }
                    None => true,
                };
                if !carried {
                    return;
                }
            }
            Either3::First(_) | Either3::Third(()) => {}
            Either3::Second(Some(envelope)) => {
                if !send(gatt, tx, pipe, envelope.bytes(), mtu).await {
                    return;
                }
            }
        }
        embassy_futures::yield_now().await;
    }
}

async fn send(
    gatt: &GattConnection<'_, '_, Pool>,
    tx: Characteristic<&[u8]>,
    pipe: &mut BlePipe,
    bytes: &[u8],
    mtu: BleMtu,
) -> bool {
    if pipe.enqueue(bytes, mtu.value_limit()).is_err() {
        return false;
    }
    let mut fragment = [0; BLE_VALUE_BYTES];
    let sent = with_timeout(WRITE, async {
        // At MTU 23 a full KM43 envelope takes 57 fragments; bound the whole message by WRITE.
        for _ in 0..128 {
            let len = match pipe.fragment(tx.should_notify(gatt), &mut fragment) {
                Ok(len) => len,
                Err(BleError::Idle) => return true,
                Err(_) => return false,
            };
            let Some(value) = fragment.get(..len) else {
                return false;
            };
            if tx.notify_raw(gatt, value, false).await.is_err()
                || pipe.accepted(tx.should_notify(gatt)).is_err()
            {
                return false;
            }
        }
        false
    })
    .await;
    matches!(sent, Ok(true))
}
