//! Radio ownership is independent of the controller handshake and association.
//! One desired configuration replaces the previous value; there is no queue.
use core::cell::RefCell;
use embassy_futures::join::join3;
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
    Country, Credential, NTP_BYTES, NtpRequest, NtpSchedule, Plan, Tick, sockets,
};

use crate::access_point;
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
/// The access point's sockets: embassy-net's DNS, which every stack of
/// this build carries, its DHCP server, and one TCP socket per WebSocket
/// worker.
const AP_SOCKETS: usize = sockets::ACCESS_POINT;
static AP_RESOURCES: StaticCell<StackResources<AP_SOCKETS>> = StaticCell::new();
/// The access point's WebSocket workers' buffers.
static AP_CLIENTS: ConstStaticCell<[Buffers; access_point::WORKERS]> =
    ConstStaticCell::new([const { Buffers::EMPTY }; access_point::WORKERS]);
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
static PROGRESS: Mutex<CriticalSectionRawMutex, RefCell<Progress>> =
    Mutex::new(RefCell::new(Progress::at(0)));

/// The operations the link's watchdog feed waits on.
#[derive(Clone, Copy)]
enum Task {
    Network,
    Station,
    Ntp,
}

/// When each [`Task`] last reported, in milliseconds since boot: a field
/// per task, which `at` and `healthy` name without `..`, so a new task
/// cannot go unwatched the way a slot past a hand-counted array would.
struct Progress {
    network: u64,
    station: u64,
    ntp: u64,
}

impl Progress {
    /// Every task reported at `ms`.
    const fn at(ms: u64) -> Self {
        Self {
            network: ms,
            station: ms,
            ntp: ms,
        }
    }
}

fn progress(task: Task) {
    PROGRESS.lock(|state| {
        let mut state = state.borrow_mut();
        let last = match task {
            Task::Network => &mut state.network,
            Task::Station => &mut state.station,
            Task::Ntp => &mut state.ntp,
        };
        *last = Instant::now().as_millis();
    });
}
pub fn healthy() -> bool {
    PROGRESS.lock(|state| {
        let Progress {
            network,
            station,
            ntp,
        } = *state.borrow();
        let now = Instant::now().as_millis();
        [network, station, ntp]
            .iter()
            .all(|last| now.saturating_sub(*last) < 6_000)
    })
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
        ap_resources: AP_RESOURCES.try_init(StackResources::new()).ok_or(())?,
        ap_clients: AP_CLIENTS.try_take().ok_or(())?,
    };
    spawner.spawn(radio(wifi, held).map_err(|_| ())?);
    Ok(())
}

/// What every session borrows: each network's stack resources and its
/// WebSocket workers' buffers.
struct Held {
    resources: &'static mut StackResources<SOCKETS>,
    clients: &'static mut [Buffers; STATION_WORKERS],
    ap_resources: &'static mut StackResources<AP_SOCKETS>,
    ap_clients: &'static mut [Buffers; access_point::WORKERS],
}

#[embassy_executor::task]
async fn radio(mut wifi: WIFI<'static>, mut held: Held) {
    loop {
        let now = Instant::now().as_millis();
        PROGRESS.lock(|state| *state.borrow_mut() = Progress::at(now));
        if desired().is_some_and(|record| record.change().is_err()) {
            esp_hal::system::software_reset();
        }
        let plan = plan().await;
        match plan {
            Plan::Off => {}
            // The session owns every Wi-Fi resource. Returning drops the
            // runner/interface before the controller, whose guard stops and
            // deinitializes the driver. Reborrow keeps WIFI here for the
            // next plan without duplicating ownership.
            Plan::Station | Plan::AccessPoint { .. } | Plan::Both { .. } => {
                session(wifi.reborrow(), &mut held, plan).await;
            }
        }
        // Idle and failed setup both yield, keeping watchdog progress bounded.
        Timer::after_secs(1).await;
    }
}

/// What the radio should run now: the record held, and the controller's
/// pairing window as the link measures it (L-196).
async fn plan() -> Plan {
    let now = Tick::from_millis(Instant::now().as_millis());
    let pairing_open = LINK.lock().await.pairing_window(now).is_some();
    Plan::of(desired().as_ref(), pairing_open)
}

/// The station's configuration, hostname and country from a `set` record.
fn station_config(record: &Credential) -> Option<(StationConfig, DhcpConfig, &str)> {
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
    let (Ok(ssid), Ok(password), Ok(hostname)) =
        (ssid.try_into(), psk.try_into(), hostname.try_into())
    else {
        return None;
    };
    let config = StationConfig::default()
        .with_ssid(ssid)
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(password));
    let mut dhcp = DhcpConfig::default();
    dhcp.hostname = Some(hostname);
    Some((config, dhcp, country))
}

fn seed() -> u64 {
    (u64::from(Rng::new().random()) << 32) | u64::from(Rng::new().random())
}

async fn session(wifi: WIFI<'_>, held: &mut Held, plan: Plan) {
    let Some(record) = desired() else {
        return;
    };
    let Ok(mut controller) = WifiController::new(wifi, ControllerConfig::default()) else {
        return;
    };
    match plan {
        Plan::Off => {}
        Plan::Station => station_session(&mut controller, held, record).await,
        Plan::AccessPoint { country } => access_point_session(&mut controller, held, country).await,
        Plan::Both { country } => both_session(&mut controller, held, record, country).await,
    }
}

/// The cached network alone.
async fn station_session(controller: &mut WifiController<'_>, held: &mut Held, record: Credential) {
    let Some((config, dhcp, country)) = station_config(&record) else {
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
    // All four futures are polled concurrently. Station returns when the
    // record or the plan changes; cancellation drops the client connections,
    // releasing their rows, then NTP sockets and the runner, before
    // controller teardown. The first three report watchdog progress.
    let _finished = select4(
        network(runner),
        ntp(stack),
        station(controller, record, Plan::Station),
        crate::clients::serve(stack, 0, held.clients),
    )
    .await;
}

/// The access point alone: no network cached, a country known.
async fn access_point_session(
    controller: &mut WifiController<'_>,
    held: &mut Held,
    country: Country,
) {
    let Some(interface) = Interface::try_access_point() else {
        return;
    };
    let Some(config) = access_point::config(interface.mac_address()) else {
        return;
    };
    if country_code_of(country).is_err()
        || controller
            .set_config(&WifiConfig::AccessPoint(config))
            .is_err()
    {
        return;
    }
    crate::clients::open_access_point();
    let (stack, runner) = embassy_net::new(
        interface,
        access_point::network(),
        &mut *held.ap_resources,
        seed(),
    );
    let _finished = select4(
        network(runner),
        access_point::dhcp(stack),
        crate::clients::serve(stack, STATION_WORKERS, held.ap_clients),
        hold(Plan::AccessPoint { country }),
    )
    .await;
}

/// The cached network, and the access point while the pairing window is
/// open.
async fn both_session(
    controller: &mut WifiController<'_>,
    held: &mut Held,
    record: Credential,
    country: Country,
) {
    let Some((station_config, dhcp, _)) = station_config(&record) else {
        return;
    };
    let (Some(station_interface), Some(ap_interface)) =
        (Interface::try_station(), Interface::try_access_point())
    else {
        return;
    };
    let Some(ap_config) = access_point::config(ap_interface.mac_address()) else {
        return;
    };
    if country_code_of(country).is_err()
        || controller
            .set_config(&WifiConfig::AccessPointStation(station_config, ap_config))
            .is_err()
    {
        return;
    }
    crate::clients::open_access_point();
    let Held {
        resources,
        clients,
        ap_resources,
        ap_clients,
    } = held;
    let (stack, runner) = embassy_net::new(
        station_interface,
        Config::dhcpv4(dhcp),
        &mut **resources,
        seed(),
    );
    let (ap_stack, ap_runner) = embassy_net::new(
        ap_interface,
        access_point::network(),
        &mut **ap_resources,
        seed(),
    );
    // Station returns when the record or the plan changes, after draining
    // the access point if the window closed (L-196).
    let _finished = select(
        select4(
            network(runner),
            ntp(stack),
            station(controller, record, Plan::Both { country }),
            crate::clients::serve(stack, 0, clients),
        ),
        join3(
            network(ap_runner),
            access_point::dhcp(ap_stack),
            crate::clients::serve(ap_stack, STATION_WORKERS, ap_clients),
        ),
    )
    .await;
}

/// The access point alone: report progress for the station and NTP it does
/// not run, and return when the plan changes.
async fn hold(plan: Plan) {
    loop {
        progress(Task::Station);
        progress(Task::Ntp);
        if self::plan().await != plan {
            return;
        }
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

async fn station(controller: &mut WifiController<'_>, applied: Credential, plan: Plan) {
    loop {
        progress(Task::Station);
        if desired() != Some(applied) {
            return;
        }
        let next = self::plan().await;
        if next != plan {
            if plan.window_closes(next) {
                // The phone on the access point takes what is already on its
                // way before the access point goes (L-196).
                crate::clients::drain_access_point().await;
            }
            return;
        }
        if !controller.is_connected() {
            let result = with_timeout(Duration::from_secs(4), controller.connect_async()).await;
            if result.is_err() {
                // Explicitly abort the blob operation after cancelling its waiter.
                progress(Task::Station);
                disconnect(controller).await;
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
