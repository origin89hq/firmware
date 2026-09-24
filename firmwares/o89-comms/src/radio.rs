//! Radio ownership is independent of the controller handshake and association.
//! One desired configuration replaces the previous value; there is no queue.
use core::cell::RefCell;
use embassy_futures::select::{select, select4};
use embassy_net::{Config, DhcpConfig, Runner, Stack, StackResources};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_hal::{peripherals::WIFI, rng::Rng};
use esp_radio::wifi::{
    AuthenticationMethodConfig, Config as WifiConfig, ControllerConfig, Interface, WifiController,
    sta::StationConfig,
};
use o89_comms_core::{Credential, NTP_BYTES, NtpRequest, NtpSchedule, Tick};

use crate::clients::{Buffers, STATION_WORKERS};
use static_cell::{ConstStaticCell, StaticCell};

static DESIRED: Mutex<CriticalSectionRawMutex, RefCell<Option<Credential>>> =
    Mutex::new(RefCell::new(None));
/// DHCP, DNS and NTP, and one TCP socket per WebSocket worker.
const SOCKETS: usize = 3 + crate::clients::STATION_WORKERS;
static RESOURCES: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
/// The station's WebSocket workers' buffers, lent to each session.
static CLIENTS: ConstStaticCell<[Buffers; STATION_WORKERS]> =
    ConstStaticCell::new([const { Buffers::EMPTY }; STATION_WORKERS]);
/// One sample in flight; full means drop the fresh sample, never evict a queued one.
pub static SAMPLES: Channel<CriticalSectionRawMutex, Sample, 1> = Channel::new();
/// A sample is used only during the next link turn and never adjusts a local clock.
pub struct Sample {
    pub unix_ms: u64,
    pub accuracy_ms: u32,
    pub at: Instant,
}
pub const SERVER: &str = "pool.ntp.org";

static NTP_SCHEDULE: Mutex<CriticalSectionRawMutex, RefCell<NtpSchedule>> =
    Mutex::new(RefCell::new(NtpSchedule::READY));

/// Pace the next query from the link's fresh offer, even if its UART write fails.
pub fn time_offered(now: Tick) {
    NTP_SCHEDULE.lock(|schedule| schedule.borrow_mut().offered(now));
}

/// Each concurrent operation reports progress within bounded waits. The idle
/// radio still turns once a second; a hang cannot borrow the link's watchdog feed.
static PROGRESS: Mutex<CriticalSectionRawMutex, RefCell<[u64; 3]>> =
    Mutex::new(RefCell::new([0; 3]));
fn progress(task: usize) {
    PROGRESS.lock(|state| {
        if let Some(tick) = state.borrow_mut().get_mut(task) {
            *tick = Instant::now().as_millis();
        }
    });
}
pub fn healthy() -> bool {
    PROGRESS.lock(|state| {
        state
            .borrow()
            .iter()
            .all(|last| Instant::now().as_millis().saturating_sub(*last) < 6_000)
    })
}
pub fn configure(credential: Option<Credential>) {
    DESIRED.lock(|state| *state.borrow_mut() = credential);
}
fn desired() -> Option<Credential> {
    DESIRED.lock(|state| *state.borrow())
}

pub fn start(spawner: embassy_executor::Spawner, wifi: WIFI<'static>) -> Result<(), ()> {
    let resources = RESOURCES.try_init(StackResources::new()).ok_or(())?;
    let clients = CLIENTS.try_take().ok_or(())?;
    spawner.spawn(radio(wifi, resources, clients).map_err(|_| ())?);
    Ok(())
}

#[embassy_executor::task]
async fn radio(
    mut wifi: WIFI<'static>,
    resources: &'static mut StackResources<SOCKETS>,
    clients: &'static mut [Buffers; STATION_WORKERS],
) {
    loop {
        for task in 0..3 {
            progress(task);
        }
        if let Some(record) = desired() {
            match record.change() {
                Ok(km43::NetChange::Set { .. }) => {
                    // The session owns every Wi-Fi resource. Returning drops the
                    // runner/interface before the controller, whose guard stops
                    // and deinitializes the driver. Reborrow keeps WIFI here for
                    // the next configured network without duplicating ownership.
                    session(wifi.reborrow(), resources, clients, record).await;
                }
                Ok(km43::NetChange::Clear { .. } | km43::NetChange::ClearUnwritten) => {}
                Err(_) => esp_hal::system::software_reset(),
            }
        }
        // Idle and failed setup both yield, keeping watchdog progress bounded.
        Timer::after_secs(1).await;
    }
}

async fn session(
    wifi: WIFI<'_>,
    resources: &mut StackResources<SOCKETS>,
    clients: &mut [Buffers; STATION_WORKERS],
    record: Credential,
) {
    let Ok(km43::NetChange::Set {
        ssid,
        psk,
        country,
        hostname,
        ..
    }) = record.change()
    else {
        return;
    };
    let (Ok(ssid), Ok(password), Ok(hostname)) =
        (ssid.try_into(), psk.try_into(), hostname.try_into())
    else {
        return;
    };
    let Ok(mut controller) = WifiController::new(wifi, ControllerConfig::default()) else {
        return;
    };
    let config = StationConfig::default()
        .with_ssid(ssid)
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(password));
    if country_code(country).is_err()
        || controller.set_config(&WifiConfig::Station(config)).is_err()
    {
        return;
    }
    let Some(interface) = Interface::try_station() else {
        return;
    };
    let mut dhcp = DhcpConfig::default();
    dhcp.hostname = Some(hostname);
    let seed = (u64::from(Rng::new().random()) << 32) | u64::from(Rng::new().random());
    let (stack, runner) = embassy_net::new(interface, Config::dhcpv4(dhcp), resources, seed);
    // All four futures are polled concurrently. Station returns when the
    // desired record changes; cancellation drops the client connections,
    // releasing their rows, then NTP sockets and the runner, before
    // controller teardown. The first three report watchdog progress.
    let _finished = select4(
        network(runner),
        ntp(stack),
        station(&mut controller, record),
        crate::clients::serve(stack, 0, clients),
    )
    .await;
}

async fn network(mut runner: Runner<'_, Interface>) {
    loop {
        // Runner keeps its state in the stack. Cancellation only ends this poll
        // loop; packets already submitted to the driver remain its responsibility.
        let _result = select(runner.run(), Timer::after_secs(1)).await;
        progress(0);
    }
}

/// Use the blob's regulatory lookup, not esp-radio's fixed 13-channel `CountryInfo`.
#[expect(
    unsafe_code,
    reason = "the pinned radio exposes no country-code lookup; the sole Wi-Fi owner calls the matching blob before connecting"
)]
fn country_code(country: &str) -> Result<(), ()> {
    let code: [u8; 2] = country.as_bytes().try_into().map_err(|_| ())?;
    let [first, second] = code;
    let terminated = [first, second, 0];
    // SAFETY: a live, exclusively owned WifiController initialized this blob;
    // the three-byte NUL-terminated input remains alive for this synchronous
    // call. The blob copies it. False keeps AP advertisements from changing it.
    let result = unsafe {
        esp_wifi_sys_esp32c6::include::esp_wifi_set_country_code(terminated.as_ptr().cast(), false)
    };
    if result == 0 { Ok(()) } else { Err(()) }
}

async fn disconnect(controller: &mut WifiController<'_>) {
    let result = with_timeout(Duration::from_secs(4), controller.disconnect_async()).await;
    if !matches!(
        result,
        Ok(Ok(_) | Err(esp_radio::wifi::WifiError::NotConnected))
    ) {
        // A cancelled waiter does not prove the blob stopped. Re-enter the
        // recovery window rather than leave an uncertain association running.
        esp_hal::system::software_reset();
    }
}

async fn station(controller: &mut WifiController<'_>, applied: Credential) {
    loop {
        progress(1);
        if desired() != Some(applied) {
            return;
        }
        if !controller.is_connected() {
            let result = with_timeout(Duration::from_secs(4), controller.connect_async()).await;
            if result.is_err() {
                // Explicitly abort the blob operation after cancelling its waiter.
                progress(1);
                disconnect(controller).await;
            }
        }
        progress(1);
        Timer::after_secs(1).await;
    }
}

async fn ntp(stack: Stack<'_>) {
    loop {
        progress(2);
        let due = NTP_SCHEDULE.lock(|schedule| {
            schedule
                .borrow()
                .ready(Tick::from_millis(Instant::now().as_millis()))
        });
        if stack.is_config_up() && due {
            if let Ok(Some(sample)) = with_timeout(Duration::from_secs(4), query(stack)).await {
                let _queued = SAMPLES.try_send(sample);
            }
            NTP_SCHEDULE.lock(|schedule| {
                schedule
                    .borrow_mut()
                    .queried(Tick::from_millis(Instant::now().as_millis()));
            });
        }
        progress(2);
        Timer::after_secs(1).await;
    }
}

async fn query(stack: Stack<'_>) -> Option<Sample> {
    let addresses = stack
        .dns_query(SERVER, embassy_net::dns::DnsQueryType::A)
        .await
        .ok()?;
    let address = *addresses.first()?;
    let mut rx_meta = [embassy_net::udp::PacketMetadata::EMPTY; 1];
    let mut tx_meta = [embassy_net::udp::PacketMetadata::EMPTY; 1];
    let mut rx = [0; NTP_BYTES];
    let mut tx = [0; NTP_BYTES];
    let mut socket =
        embassy_net::udp::UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    socket.bind(0).ok()?;
    let nonce = (u64::from(Rng::new().random()) << 32) | u64::from(Rng::new().random());
    let request = NtpRequest::new(nonce.to_be_bytes());
    let started = Instant::now();
    socket
        .send_to(&request.packet(), (address, 123))
        .await
        .ok()?;
    let mut response = [0; NTP_BYTES];
    let (len, peer) = socket.recv_from(&mut response).await.ok()?;
    if peer.endpoint.addr != address || peer.endpoint.port != 123 {
        return None;
    }
    let unix_ms = request.unix_ms(response.get(..len)?)?;
    let accuracy_ms = u32::try_from(started.elapsed().as_millis()).ok()?;
    Some(Sample {
        unix_ms,
        accuracy_ms,
        at: Instant::now(),
    })
}
