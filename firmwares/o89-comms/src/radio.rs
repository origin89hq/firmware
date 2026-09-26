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
use o89_comms_core::{
    Country, Credential, NTP_BYTES, NtpRequest, NtpSchedule, Plan, Task, Tick, WifiProgress,
    sockets,
};

use crate::clients::{Buffers, STATION_WORKERS};
use crate::link::LINK;
use static_cell::{ConstStaticCell, StaticCell};

static DESIRED: Mutex<CriticalSectionRawMutex, RefCell<Option<Credential>>> =
    Mutex::new(RefCell::new(None));
/// The station's sockets, each slot named in `o89_comms_core::sockets`:
/// embassy-net's DNS and DHCP client, NTP, and one TCP socket per WebSocket
/// worker. A socket added past the budget panics in smoltcp.
const SOCKETS: usize = sockets::STATION;
static RESOURCES: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
/// The station's WebSocket workers' buffers, lent to each session.
static CLIENTS: ConstStaticCell<[Buffers; STATION_WORKERS]> =
    ConstStaticCell::new([const { Buffers::EMPTY }; STATION_WORKERS]);
/// The station's mDNS responder's buffers, lent to each session.
static MDNS: ConstStaticCell<crate::mdns::Buffers> =
    ConstStaticCell::new(crate::mdns::Buffers::EMPTY);
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
static PROGRESS: Mutex<CriticalSectionRawMutex, RefCell<WifiProgress>> =
    Mutex::new(RefCell::new(WifiProgress::at(0)));

fn progress(task: Task) {
    PROGRESS.lock(|state| {
        state
            .borrow_mut()
            .progress(task, Instant::now().as_millis());
    });
}
pub fn healthy() -> bool {
    let now = Instant::now().as_millis();
    PROGRESS.lock(|state| state.borrow().healthy(now)) && crate::ble::healthy(now)
}
pub fn configure(credential: Option<Credential>) {
    DESIRED.lock(|state| *state.borrow_mut() = credential);
}
fn desired() -> Option<Credential> {
    DESIRED.lock(|state| *state.borrow())
}

pub fn start(spawner: embassy_executor::Spawner, wifi: WIFI<'static>) -> Result<(), ()> {
    let held = Held {
        resources: RESOURCES.try_init(StackResources::new()).ok_or(())?,
        clients: CLIENTS.try_take().ok_or(())?,
        mdns: MDNS.try_take().ok_or(())?,
    };
    spawner.spawn(radio(wifi, held).map_err(|_| ())?);
    Ok(())
}

/// What every station session borrows: the stack's resources, its
/// WebSocket workers' buffers, and the mDNS responder's.
struct Held {
    resources: &'static mut StackResources<SOCKETS>,
    clients: &'static mut [Buffers; STATION_WORKERS],
    mdns: &'static mut crate::mdns::Buffers,
}

#[embassy_executor::task]
async fn radio(mut wifi: WIFI<'static>, mut held: Held) {
    loop {
        let now = Instant::now().as_millis();
        PROGRESS.lock(|state| state.borrow_mut().reset(now));
        if desired().is_some_and(|record| record.change().is_err()) {
            esp_hal::system::software_reset();
        }
        // Wi-Fi waits for the controller's first word on its pairing window,
        // so a window open at boot keeps it off from the start rather than
        // taking a station down (L-195). Without a controller there is no
        // client to serve.
        if !diagnostics().await.pairing_known() {
            Timer::after_secs(1).await;
            continue;
        }
        let plan = plan().await;
        observe_plan(plan).await;
        match plan {
            Plan::Off => {}
            Plan::Station | Plan::Scan { .. } => {
                if !session(wifi.reborrow(), &mut held, plan).await {
                    // Nothing was started, so nothing needs taking down:
                    // try again on the next turn.
                    Timer::after_secs(1).await;
                    continue;
                }
                // A session ends when the record, the plan or a stuck scan
                // says the radio must stop. On the pinned radio, stopping,
                // disconnecting or deinitializing a started station each left
                // BLE advertising nothing and taking no connection until the
                // module rebooted (bench 2026-09-24). So the module reboots,
                // through the recovery window, and comes up in the new plan;
                // the station has already said its mDNS goodbye.
                esp_hal::system::software_reset();
            }
        }
        // Idle and failed setup both yield, keeping watchdog progress bounded.
        Timer::after_secs(1).await;
    }
}

/// What the radio should run now: the record held, the controller's
/// pairing window as the link measures it (L-196), and whether a client
/// wants a scan with no network cached (#166).
async fn plan() -> Plan {
    let now = Tick::from_millis(Instant::now().as_millis());
    let (pairing_open, scan_wanted) = {
        let link = diagnostics().await;
        (link.pairing_window(now).is_some(), link.scan_wanted())
    };
    Plan::of(desired().as_ref(), pairing_open, scan_wanted)
}

/// The station's configuration, its DHCP configuration, the country and the
/// hostname, which DHCP and mDNS both carry, from a `set` record.
fn station_config(record: &Credential) -> Option<(StationConfig, DhcpConfig, &str, &str)> {
    let Ok(km43::NetChange::Set {
        ssid,
        psk,
        country,
        hostname,
        ..
    }) = record.change()
    else {
        return None;
    };
    let (Ok(ssid), Ok(password)) = (ssid.try_into(), psk.try_into()) else {
        return None;
    };
    let config = StationConfig::default()
        .with_ssid(ssid)
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(password));
    let dhcp = o89_comms_net::station_dhcp(hostname).ok()?;
    Some((config, dhcp, country, hostname))
}

fn seed() -> u64 {
    (u64::from(Rng::new().random()) << 32) | u64::from(Rng::new().random())
}

/// Run `plan` until it has to end, and whether it created the Wi-Fi driver:
/// only a created driver needs the reboot to be taken down. A record the
/// station cannot use is refused before the driver exists, so it retries
/// quietly rather than rebooting the module at every boot.
async fn session(wifi: WIFI<'_>, held: &mut Held, plan: Plan) -> bool {
    let Some(record) = desired() else {
        return false;
    };
    if matches!(plan, Plan::Station) && station_config(&record).is_none() {
        return false;
    }
    let Ok(mut controller) = WifiController::new(wifi, ControllerConfig::default()) else {
        return false;
    };
    match plan {
        Plan::Off => {}
        Plan::Station => station_session(&mut controller, held, record).await,
        Plan::Scan { country } => scan_session(&mut controller, country).await,
    }
    true
}

/// The cached network alone.
async fn station_session(controller: &mut WifiController<'_>, held: &mut Held, record: Credential) {
    let Some((config, dhcp, country, hostname)) = station_config(&record) else {
        return;
    };
    if country_code(country).is_err()
        || controller.set_config(&WifiConfig::Station(config)).is_err()
    {
        return;
    }
    let Some(interface) = Interface::try_station() else {
        return;
    };
    let (stack, runner) = embassy_net::new(
        interface,
        Config::dhcpv4(dhcp),
        &mut *held.resources,
        seed(),
    );
    // All five futures are polled concurrently. Station returns when the
    // record or the plan changes, once the responder has said goodbye;
    // cancellation drops the client connections, releasing their rows,
    // then the mDNS and NTP sockets and the runner, before controller
    // teardown. The first three report watchdog progress.
    let _finished = select(
        select4(
            network(runner),
            ntp(stack),
            station(controller, stack, record, Plan::Station),
            crate::clients::serve(stack, 0, held.clients),
        ),
        crate::mdns::respond(stack, hostname, held.mdns),
    )
    .await;
}

/// No network cached: the station interface up without joining, for scans
/// alone, until the record changes or no client is left who wants one.
/// Reports progress for the network, station and NTP it does not run.
async fn scan_session(controller: &mut WifiController<'_>, country: Country) {
    if country_code_of(country).is_err()
        || controller
            .set_config(&WifiConfig::Station(StationConfig::default()))
            .is_err()
    {
        return;
    }
    let plan = Plan::Scan { country };
    loop {
        progress(Task::Network);
        progress(Task::Station);
        progress(Task::Ntp);
        if self::plan().await != plan {
            return;
        }
        if scan(controller).await {
            return;
        }
        progress(Task::Network);
        progress(Task::Ntp);
        Timer::after_secs(1).await;
    }
}

async fn network(mut runner: Runner<'_, Interface>) {
    loop {
        // Runner keeps its state in the stack. Cancellation only ends this poll
        // loop; packets already submitted to the driver remain its responsibility.
        let _result = select(runner.run(), Timer::after_secs(1)).await;
        progress(Task::Network);
    }
}

/// The regulatory country the plan carries, applied as a record's is.
fn country_code_of(country: Country) -> Result<(), ()> {
    let [first, second] = country.as_bytes();
    let code = [first, second];
    country_code(core::str::from_utf8(&code).map_err(|_| ())?)
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
    // call. The blob copies it. False keeps a network's advertisements from
    // changing it.
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

async fn station(
    controller: &mut WifiController<'_>,
    stack: Stack<'_>,
    applied: Credential,
    plan: Plan,
) {
    loop {
        progress(Task::Station);
        if desired() != Some(applied) {
            // The goodbye goes out on the network being left (P-224).
            crate::mdns::leave().await;
            return;
        }
        if self::plan().await != plan {
            crate::mdns::leave().await;
            return;
        }
        if scan(controller).await {
            crate::mdns::leave().await;
            return;
        }
        let connected = controller.is_connected();
        let address = if connected {
            stack
                .config_v4()
                .map(|config| config.address.address().octets())
        } else {
            None
        };
        station_observed(applied.version(), connected, address, None).await;
        if !connected {
            let result = with_timeout(Duration::from_secs(4), controller.connect_async()).await;
            match result {
                Ok(Ok(_)) => station_observed(applied.version(), true, None, None).await,
                Ok(Err(error)) => {
                    station_observed(
                        applied.version(),
                        false,
                        None,
                        Some(connection_failure(&error)),
                    )
                    .await;
                }
                Err(_) => {
                    progress(Task::Station);
                    disconnect(controller).await;
                    station_observed(
                        applied.version(),
                        false,
                        None,
                        Some(km43::WifiFailure::Other),
                    )
                    .await;
                }
            }
        }
        progress(Task::Station);
        Timer::after_secs(1).await;
    }
}

async fn ntp(stack: Stack<'_>) {
    loop {
        progress(Task::Ntp);
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
        progress(Task::Ntp);
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

/// Link ownership never waits on the radio; a stalled lock resets through the
/// recovery window rather than stranding an accepted scan indefinitely.
pub(crate) async fn diagnostics() -> embassy_sync::mutex::MutexGuard<
    'static,
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    o89_comms_core::Link,
> {
    match with_timeout(Duration::from_millis(100), LINK.lock()).await {
        Ok(link) => link,
        Err(_) => esp_hal::system::software_reset(),
    }
}

async fn observe(version: u32, radio: km43::Radio) {
    diagnostics()
        .await
        .radio_report(km43::RadioReport { version, radio });
}

async fn station_observed(
    version: u32,
    connected: bool,
    ipv4: Option<[u8; 4]>,
    failure: Option<km43::WifiFailure>,
) {
    diagnostics().await.station_observed(
        version,
        connected,
        ipv4,
        failure,
        Tick::from_millis(Instant::now().as_millis()),
    );
}

async fn observe_plan(plan: Plan) {
    let version = desired().map_or(0, |credential| credential.version());
    let radio = match plan {
        Plan::Off | Plan::Scan { .. } => km43::Radio::Off,
        Plan::Station => km43::Radio::Joining,
    };
    observe(version, radio).await;
}

/// Returns true only when the cancelled scan requires session teardown.
async fn scan(controller: &mut WifiController<'_>) -> bool {
    let Some(number) = diagnostics().await.wifi.take_scan() else {
        return false;
    };
    // No max: truncation before SSID deduplication would lose strong choices
    // and the exact unlisted count. Only the vendor crate allocates this Vec.
    let config = esp_radio::wifi::scan::ScanConfig::default().with_show_hidden(true);
    let (rows, timed_out) =
        match with_timeout(Duration::from_secs(4), controller.scan_async(&config)).await {
            Ok(Ok(mut heard)) => {
                // Allocation-free in-place sort; count is the vendor u16 AP count.
                heard.sort_unstable_by(|left, right| {
                    right.signal_strength.cmp(&left.signal_strength)
                });
                let rows =
                    o89_comms_core::ScanRows::collect(&heard, |ap| o89_comms_core::HeardAp {
                        ssid: (ap.ssid.as_str().len() == ap.ssid.len()).then_some(ap.ssid.as_str()),
                        rssi: ap.signal_strength,
                        security: security(ap.auth_method),
                        channel: ap.channel,
                    })
                    .ok();
                // Vendor allocation dies before the next await.
                drop(heard);
                (rows, false)
            }
            Ok(Err(_)) => (None, false),
            Err(_) => (None, true),
        };
    progress(Task::Station);
    diagnostics().await.wifi.finished(number, rows.as_ref());
    // Dropping the scan future releases the AP list; dropping the session
    // additionally stops/deinitializes the driver before another scan or join.
    timed_out
}

fn connection_failure(error: &esp_radio::wifi::ConnectionError) -> km43::WifiFailure {
    use esp_radio::wifi::{ConnectionError, DisconnectReason};
    match error {
        ConnectionError::Failed(info) => match info.reason {
            DisconnectReason::AuthenticationFailed
            | DisconnectReason::FourWayHandshakeTimeout
            | DisconnectReason::HandshakeTimeout
            | DisconnectReason::_802_1xAuthenticationFailed => km43::WifiFailure::AuthFailed,
            DisconnectReason::NoAccessPointFound => km43::WifiFailure::NotFound,
            _ => km43::WifiFailure::Other,
        },
        _ => km43::WifiFailure::Other,
    }
}

fn security(method: Option<esp_radio::wifi::AuthenticationMethod>) -> km43::WifiSecurity {
    use esp_radio::wifi::AuthenticationMethod;
    match method {
        Some(AuthenticationMethod::None) => km43::WifiSecurity::Open,
        Some(AuthenticationMethod::Wpa2Personal | AuthenticationMethod::WpaWpa2Personal) => {
            km43::WifiSecurity::Wpa2Personal
        }
        Some(AuthenticationMethod::Wpa3Personal) => km43::WifiSecurity::Wpa3Personal,
        Some(AuthenticationMethod::Wpa2Wpa3Personal) => km43::WifiSecurity::Wpa2Personal,
        _ => km43::WifiSecurity::Other,
    }
}
