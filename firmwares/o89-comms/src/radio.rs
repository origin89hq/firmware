//! Radio ownership is independent of the controller handshake and association.
//! One desired configuration replaces the previous value; there is no queue.
use core::cell::RefCell;
use embassy_futures::select::select;
use embassy_net::{Config, ConfigV4, DhcpConfig, Runner, Stack, StackResources};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_hal::{peripherals::WIFI, rng::Rng};
use esp_radio::wifi::{
    AuthenticationMethodConfig, Config as WifiConfig, ControllerConfig, Interface, WifiController,
    sta::StationConfig,
};
use o89_comms_core::{Credential, NTP_BYTES, NtpRequest};
use static_cell::StaticCell;

static DESIRED: Mutex<CriticalSectionRawMutex, RefCell<Option<Credential>>> =
    Mutex::new(RefCell::new(None));
/// Three sockets: DHCP, DNS, and NTP. No client transport sockets in this slice.
const SOCKETS: usize = 3;
static RESOURCES: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
/// One sample in flight; full means drop the fresh sample, never evict a queued one.
pub static SAMPLES: Channel<CriticalSectionRawMutex, Sample, 1> = Channel::new();
/// A sample is used only during the next link turn and never adjusts a local clock.
pub struct Sample {
    pub unix_ms: u64,
    pub accuracy_ms: u32,
    pub at: Instant,
}
pub const SERVER: &str = "pool.ntp.org";

/// Each task reports progress within bounded waits. Idle radio and network tasks
/// still turn once a second; a hung task cannot borrow the link's watchdog feed.
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
    let controller = WifiController::new(wifi, ControllerConfig::default()).map_err(|_| ())?;
    let resources = RESOURCES.try_init(StackResources::new()).ok_or(())?;
    let seed = (u64::from(Rng::new().random()) << 32) | u64::from(Rng::new().random());
    let (stack, runner) = embassy_net::new(
        Interface::station(),
        Config::dhcpv4(DhcpConfig::default()),
        resources,
        seed,
    );
    spawner.spawn(network(runner).map_err(|_| ())?);
    spawner.spawn(station(controller, stack).map_err(|_| ())?);
    spawner.spawn(ntp(stack).map_err(|_| ())?);
    Ok(())
}

#[embassy_executor::task]
async fn network(mut runner: Runner<'static, Interface>) {
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

async fn disconnect(controller: &mut WifiController<'static>) {
    let result = with_timeout(Duration::from_secs(4), controller.disconnect_async()).await;
    if !matches!(
        result,
        Ok(Ok(_) | Err(esp_radio::wifi::WifiError::NotConnected))
    ) {
        // A cancelled waiter does not prove the blob stopped. Re-enter the
        // recovery window rather than apply a country while still connected.
        esp_hal::system::software_reset();
    }
}

#[embassy_executor::task]
async fn station(mut controller: WifiController<'static>, stack: Stack<'static>) {
    let mut applied = None;
    let mut enabled = false;
    loop {
        progress(1);
        let next = desired();
        if next != applied {
            disconnect(&mut controller).await;
            enabled = false;
            if let Some(record) = next {
                match record.change() {
                    Ok(km43::NetChange::Set {
                        ssid,
                        psk,
                        country,
                        hostname,
                        ..
                    }) => {
                        if let (Ok(ssid), Ok(password), Ok(hostname)) =
                            (ssid.try_into(), psk.try_into(), hostname.try_into())
                        {
                            let config = StationConfig::default()
                                .with_ssid(ssid)
                                .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
                                    password,
                                ));
                            let mut dhcp = DhcpConfig::default();
                            dhcp.hostname = Some(hostname);
                            stack.set_config_v4(ConfigV4::Dhcp(dhcp));
                            enabled = country_code(country).is_ok()
                                && controller.set_config(&WifiConfig::Station(config)).is_ok();
                        }
                    }
                    Ok(km43::NetChange::Clear { .. }) => {
                        let blank = StationConfig::default()
                            .with_authentication(AuthenticationMethodConfig::Open);
                        if controller.set_config(&WifiConfig::Station(blank)).is_err() {
                            esp_hal::system::software_reset();
                        }
                        stack.set_config_v4(ConfigV4::None);
                    }
                    Err(_) => esp_hal::system::software_reset(),
                }
            }
            // Failed setup is retried, without logging credentials.
            if enabled
                || matches!(
                    next.as_ref().map(Credential::change),
                    None | Some(Ok(km43::NetChange::Clear { .. }))
                )
            {
                applied = next;
            }
        }
        progress(1);
        if enabled && !controller.is_connected() {
            let result = with_timeout(Duration::from_secs(4), controller.connect_async()).await;
            if result.is_err() {
                // Explicitly abort the blob operation after cancelling its waiter.
                progress(1);
                disconnect(&mut controller).await;
            }
        }
        progress(1);
        Timer::after_secs(1).await;
    }
}

#[embassy_executor::task]
async fn ntp(stack: Stack<'static>) {
    let mut due = Instant::now();
    loop {
        progress(2);
        if stack.is_config_up() && Instant::now() >= due {
            if let Ok(Some(sample)) = with_timeout(Duration::from_secs(4), query(stack)).await {
                let _queued = SAMPLES.try_send(sample);
                due = Instant::from_millis(Instant::now().as_millis().saturating_add(900_000));
            } else {
                due = Instant::from_millis(Instant::now().as_millis().saturating_add(30_000));
            }
        }
        progress(2);
        Timer::after_secs(1).await;
    }
}

async fn query(stack: Stack<'static>) -> Option<Sample> {
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
