//! One task per bus, each on the roll with its own check-in window, each
//! writing the one site (`ARCHITECTURE.md`, tasks and the watchdog).
//!
//! A task owns its port and the devices configuration put on it, polls each
//! at its period through the entry for its kind of bus, stages what the
//! poll wrote and hands it to the site in one call with what the poll heard
//! of the device ([`land`]): the site is never held across a poll's
//! awaits. Nothing here decides: what a device publishes, its presence, and
//! how long the bus stays quiet after a timeout are `o89-drivers`' and
//! `o89-core`'s. A bus that hangs is a task that misses its check-in, which
//! is a reset.
//!
//! Every await has a deadline: an exchange's is its response bound, a
//! listen's and a CAN read's are below, a 1-Wire slot is microseconds and
//! yields between slots, and the pacing waits are timers.

use embassy_executor::{SendSpawner, SpawnError, SpawnToken};
use embassy_stm32::Peri;
use embassy_stm32::adc::{Adc, Config as AdcConfig};
use embassy_stm32::can::CanConfigurator;
use embassy_stm32::gpio::{Flex, Pull};
use embassy_stm32::peripherals as p;
use embassy_stm32::usart::{self, BufferedUart, RingBufferedUartRx, UartRx};
use embassy_time::{Duration, Timer};
use o89_core::{
    Bus, Clock, Connector, Heard, ONEWIRE_DEVICES, Port, RS485_DEVICES, SiteBusy, SiteCell, Staged,
    Task,
};
use o89_drivers::plan::{LOCAL_PERIOD, Plan, Planned, RESPONSE, Settings};
use o89_drivers::serial::{Framed, Framing};
use o89_drivers::vedirect::Parser;
use o89_drivers::{Device, ds18b20, probe_heard, quiet_after, vedirect_heard};
use static_cell::StaticCell;

use crate::board::{self, REVISION};
use crate::serial::{Rs485Line, VeDirectLine, duration};
use crate::site::Shared;
use crate::supervisor::{Uptime, check_in};

/// The most writes one poll stages: a charger's nine signals, a BMS frame's
/// four, or the one block a 64-byte VE.Direct burst can end, three signals.
pub const STAGED: usize = o89_drivers::DEVICE_SIGNALS;

/// A poll's writes.
pub type Batch = Staged<STAGED>;

/// How often an idle bus's task checks in, and a busy one paces its turns.
const TURN: Duration = Duration::from_millis(100);

/// How long a VE.Direct port waits for a burst: a product sends a block a
/// second, so a second and a half of silence is one it missed.
const LISTEN: o89_core::Millis = o89_core::Millis::from_millis(1_500);

/// How long the CAN task waits for a frame: a BMS sends each once a second.
const FRAME: o89_core::Millis = o89_core::Millis::from_millis(2_000);

/// A device as its bus task polls it: its id, its driver and its period.
#[derive(Clone, Copy)]
pub struct Entry {
    dev: u16,
    device: Device,
    period: o89_core::Millis,
}

impl From<&Planned> for Entry {
    fn from(planned: &Planned) -> Self {
        Self {
            dev: planned.dev,
            device: planned.device,
            period: planned.period,
        }
    }
}

/// Hand `staged` to the site, and what the poll `heard` of device `dev`.
pub fn land(site: Shared, dev: u16, staged: &Batch, heard: Option<Heard>) {
    let landed = site.with(|site, _| {
        let landed = site.commit(staged);
        let presence = heard.map(|heard| site.heard(dev, heard));
        (landed, presence)
    });
    match landed {
        Ok((Ok(_), None | Some(Ok(_)))) => {}
        Ok((Err(error), _)) => {
            defmt::error!("bus: dev {}: the site refused the poll: {}", dev, error);
        }
        Ok((Ok(_), Some(Err(error)))) => {
            defmt::error!("bus: dev {}: no presence: {}", dev, error);
        }
        Err(SiteBusy) => defmt::error!("bus: dev {}: the site was held; the poll is lost", dev),
    }
}

/// One RS-485 channel: every device on it polled at its period, one
/// exchange at a time, and the bus left quiet for a response bound after
/// an exchange that heard nothing.
#[embassy_executor::task(pool_size = 3)]
pub async fn rs485(
    task: Task,
    mut port: Option<Framed<Rs485Line>>,
    devices: [Option<Entry>; RS485_DEVICES],
    site: Shared,
) -> ! {
    let mut due = [o89_core::Tick::ZERO; RS485_DEVICES];
    let mut staged = Batch::new();
    loop {
        check_in(task);
        if let Some(port) = port.as_mut() {
            for (planned, due) in devices.iter().zip(due.iter_mut()) {
                let Some(planned) = planned else { continue };
                let now = Uptime.now();
                if now < *due {
                    continue;
                }
                staged.clear();
                let polled = planned
                    .device
                    .poll_rs485(port, RESPONSE, now, &mut staged)
                    .await;
                let heard = match &polled {
                    Ok(_) => Some(Heard::Answered),
                    Err(error) => error.heard(),
                };
                land(site, planned.dev, &staged, heard);
                if let Err(error) = &polled {
                    defmt::warn!("rs485: dev {}: {}", planned.dev, error);
                }
                *due = now.after(planned.period).unwrap_or(now);
                let quiet = quiet_after(&polled, RESPONSE);
                if quiet.as_millis() > 0 {
                    Timer::after(duration(quiet)).await;
                }
                check_in(task);
            }
        }
        Timer::after(TURN).await;
    }
}

/// One VE.Direct port: every burst the product sends, parsed and written.
#[embassy_executor::task(pool_size = 2)]
pub async fn vedirect(
    task: Task,
    mut port: Option<Framed<VeDirectLine>>,
    device: Option<Entry>,
    site: Shared,
) -> ! {
    let mut parser = Parser::new();
    let mut staged = Batch::new();
    loop {
        check_in(task);
        let (Some(port), Some(planned)) = (port.as_mut(), device) else {
            Timer::after(TURN).await;
            continue;
        };
        staged.clear();
        let now = Uptime.now();
        let heard = planned
            .device
            .listen_vedirect(port, &mut parser, LISTEN, now, &mut staged, |_| {})
            .await;
        let presence = match &heard {
            Ok(heard) => vedirect_heard(heard),
            Err(error) => error.heard(),
        };
        land(site, planned.dev, &staged, presence);
        if let Err(error) = heard {
            defmt::warn!("vedirect: dev {}: {}", planned.dev, error);
        }
    }
}

/// The CAN bus: the BMS's frames, as they come.
#[embassy_executor::task]
pub async fn can(mut port: Option<crate::can::Port>, device: Option<Entry>, site: Shared) -> ! {
    let mut staged = Batch::new();
    loop {
        check_in(Task::Can);
        let (Some(port), Some(planned)) = (port.as_mut(), device) else {
            Timer::after(TURN).await;
            continue;
        };
        staged.clear();
        let now = Uptime.now();
        let read = planned.device.read_can(port, FRAME, now, &mut staged).await;
        let heard = match &read {
            Ok(_) => Some(Heard::Answered),
            Err(error) => error.heard(),
        };
        land(site, planned.dev, &staged, heard);
        if let Err(error) = read {
            defmt::debug!("can: dev {}: {}", planned.dev, error);
        }
    }
}

/// The 1-Wire line: one conversion on every probe, then each probe read.
#[embassy_executor::task]
pub async fn onewire(
    mut line: Option<crate::onewire::Line>,
    mut devices: [Option<Entry>; ONEWIRE_DEVICES],
    period: o89_core::Millis,
    site: Shared,
) -> ! {
    let mut staged = Batch::new();
    loop {
        check_in(Task::OneWire);
        let Some(line) = line.as_mut() else {
            Timer::after(TURN).await;
            continue;
        };
        if devices.iter().all(Option::is_none) {
            Timer::after(TURN).await;
            continue;
        }
        match ds18b20::convert_all(line, &Uptime).await {
            Ok(conversion) => {
                let wait = conversion.ready().since(Uptime.now());
                Timer::after(duration(wait.unwrap_or(o89_core::Millis::ZERO))).await;
                check_in(Task::OneWire);
                for planned in devices.iter_mut().flatten() {
                    staged.clear();
                    let read = planned
                        .device
                        .read_probe(line, &conversion, Uptime.now(), &mut staged)
                        .await;
                    let heard = match &read {
                        Ok(read) => Some(probe_heard(read)),
                        Err(error) => error.heard(),
                    };
                    land(site, planned.dev, &staged, heard);
                    if let Err(error) = read {
                        defmt::warn!("onewire: dev {}: {}", planned.dev, error);
                    }
                }
            }
            Err(ds18b20::ConvertError::Absent) => {
                for planned in devices.iter_mut().flatten() {
                    staged.clear();
                    if let Device::Ds18b20(probe) = &mut planned.device
                        && let Err(error) = probe.absent(Uptime.now(), &mut staged)
                    {
                        defmt::error!("onewire: dev {}: {}", planned.dev, error);
                    }
                    land(site, planned.dev, &staged, Some(Heard::Silent));
                }
            }
            Err(error) => defmt::warn!("onewire: no conversion: {}", error),
        }
        // A period may be longer than the task's window, so the wait is
        // turns, each checked in: at most the period over a turn of them.
        let due = Uptime.now().after(period);
        while due.is_some_and(|due| Uptime.now() < due) {
            check_in(Task::OneWire);
            Timer::after(TURN).await;
        }
    }
}

/// The controller's own inputs, read every [`LOCAL_PERIOD`].
#[embassy_executor::task]
pub async fn adc(mut sampler: crate::adc::Sampler, site: Shared) -> ! {
    let mut staged = Batch::new();
    loop {
        check_in(Task::Adc);
        staged.clear();
        let read = sampler.read(Uptime.now(), &mut staged).await;
        // What a pass wrote before it stopped stands.
        land(site, 0, &staged, None);
        if let Err(error) = read {
            defmt::warn!("adc: {}", error);
        }
        Timer::after(duration(LOCAL_PERIOD)).await;
    }
}

/// The bus interrupts: above every executor, as `ARCHITECTURE.md` puts
/// them.
mod irqs {
    use embassy_stm32::peripherals::{
        DMA1_CH1, DMA1_CH2, FDCAN1, LPUART1, LPUART2, USART2, USART3, USART4,
    };
    use embassy_stm32::{bind_interrupts, can, dma, usart};

    bind_interrupts!(pub struct Irqs {
        USART2_LPUART2 => usart::BufferedInterruptHandler<USART2>, usart::InterruptHandler<LPUART2>;
        USART3_4_5_6_LPUART1 => usart::BufferedInterruptHandler<USART3>, usart::BufferedInterruptHandler<USART4>, usart::InterruptHandler<LPUART1>;
        DMA1_CHANNEL1 => dma::InterruptHandler<DMA1_CH1>;
        DMA1_CHANNEL2_3 => dma::InterruptHandler<DMA1_CH2>;
        TIM16_FDCAN_IT0 => can::IT0InterruptHandler<FDCAN1>;
        TIM17_FDCAN_IT1 => can::IT1InterruptHandler<FDCAN1>;
    });
}

/// What an RS-485 channel's UART receives into: an echo and the largest
/// reply, with room for a late byte behind them.
const RS485_RX: usize = o89_drivers::modbus::RECEIVE_BYTES + 32;
/// What it sends from: a request is eight bytes.
const RS485_TX: usize = 32;
/// A VE.Direct port's DMA ring: 66 ms of the line at 19200 bit/s, which
/// the task, reading as bytes come, empties in far less.
const VEDIRECT_RING: usize = 128;

static RS485_RINGS: [StaticCell<([u8; RS485_TX], [u8; RS485_RX])>; 3] =
    [StaticCell::new(), StaticCell::new(), StaticCell::new()];
static VEDIRECT_RINGS: [StaticCell<[u8; VEDIRECT_RING]>; 2] =
    [StaticCell::new(), StaticCell::new()];

/// The line a channel runs at when the configuration sets none: its
/// transmit line idles high under the UART all the same, which is what the
/// transceiver needs (F-002).
const IDLE_FRAMING: Framing = Framing {
    rate: match core::num::NonZeroU32::new(9_600) {
        Some(rate) => rate,
        None => core::num::NonZeroU32::MIN,
    },
    data_bits: km43::DataBits::Eight,
    parity: km43::Parity::None,
    stop_bits: km43::StopBits::One,
};

/// The board's buses, as `main` hands them over.
pub struct Peripherals {
    /// RS-485 #1.
    pub rs485_1: board::Rs485<p::USART2, p::PA2, p::PA3>,
    /// RS-485 #2.
    pub rs485_2: board::Rs485<p::USART3, p::PB10, p::PB11>,
    /// RS-485 #3.
    pub rs485_3: board::Rs485<p::USART4, p::PA0, p::PA1>,
    /// VE.Direct 1.
    pub vedirect_1: board::VeDirect<p::LPUART1, p::PC0, p::DMA1_CH1>,
    /// VE.Direct 2.
    pub vedirect_2: board::VeDirect<p::LPUART2, p::PC1, p::DMA1_CH2>,
    /// FDCAN1 and its pins.
    pub can: (
        Peri<'static, p::FDCAN1>,
        Peri<'static, p::PB8>,
        Peri<'static, p::PB9>,
    ),
    /// The 1-Wire pin.
    pub onewire: Peri<'static, p::PC4>,
    /// ADC1 and its inputs.
    pub adc: (Peri<'static, p::ADC1>, board::AdcPins),
}

/// Bring every bus up as `plan` says, and spawn its task onto `tasks`.
///
/// Every RS-485 UART is configured, configured or not, so its transmit
/// line idles high under the UART (F-002); a VE.Direct port, the CAN bus
/// and the 1-Wire line are configured only when the plan puts a device on
/// them, and stay in their reset state otherwise. Each task is checked in
/// before it is spawned, so one that does not spawn is one that stops
/// checking in: the watchdog resets the part.
pub fn start(buses: Peripherals, plan: &Plan, site: Shared, tasks: SendSpawner) {
    let Peripherals {
        rs485_1,
        rs485_2,
        rs485_3,
        vedirect_1,
        vedirect_2,
        can,
        onewire,
        adc,
    } = buses;
    let [ring_1, ring_2, ring_3] = &RS485_RINGS;
    let lines = [
        rs485_line(plan, Bus::One, ring_1, |config, (tx_ring, rx_ring)| {
            BufferedUart::new(
                rs485_1.usart,
                rs485_1.tx,
                rs485_1.rx,
                irqs::Irqs,
                tx_ring,
                rx_ring,
                config,
            )
        }),
        rs485_line(plan, Bus::Two, ring_2, |config, (tx_ring, rx_ring)| {
            BufferedUart::new(
                rs485_2.usart,
                rs485_2.tx,
                rs485_2.rx,
                irqs::Irqs,
                tx_ring,
                rx_ring,
                config,
            )
        }),
        rs485_line(plan, Bus::Three, ring_3, |config, (tx_ring, rx_ring)| {
            BufferedUart::new(
                rs485_3.usart,
                rs485_3.tx,
                rs485_3.rx,
                irqs::Irqs,
                tx_ring,
                rx_ring,
                config,
            )
        }),
    ];
    for (bus, line) in [Bus::One, Bus::Two, Bus::Three].into_iter().zip(lines) {
        let connector = Connector::Rs485(bus);
        let mut devices = [None; RS485_DEVICES];
        for (slot, planned) in devices.iter_mut().zip(plan.devices_on(connector)) {
            *slot = Some(Entry::from(planned));
        }
        check_in(connector.task());
        spawn(
            tasks,
            connector.task(),
            rs485(connector.task(), line, devices, site),
        );
    }

    start_vedirect(vedirect_1, vedirect_2, plan, site, tasks);
    start_can(can, plan, site, tasks);
    start_onewire(onewire, plan, site, tasks);
    start_adc(adc, site, tasks);
}

/// The two VE.Direct ports, each configured only when the plan puts a
/// product on it.
fn start_vedirect(
    vedirect_1: board::VeDirect<p::LPUART1, p::PC0, p::DMA1_CH1>,
    vedirect_2: board::VeDirect<p::LPUART2, p::PC1, p::DMA1_CH2>,
    plan: &Plan,
    site: Shared,
    tasks: SendSpawner,
) {
    let [vring_1, vring_2] = &VEDIRECT_RINGS;
    let ports = [
        vedirect_line(plan, Port::One, |config| {
            UartRx::new(
                vedirect_1.usart,
                vedirect_1.rx,
                vedirect_1.dma,
                irqs::Irqs,
                config,
            )
            .map(|rx| rx.into_ring_buffered(vring_1.init([0; VEDIRECT_RING])))
        }),
        vedirect_line(plan, Port::Two, |config| {
            UartRx::new(
                vedirect_2.usart,
                vedirect_2.rx,
                vedirect_2.dma,
                irqs::Irqs,
                config,
            )
            .map(|rx| rx.into_ring_buffered(vring_2.init([0; VEDIRECT_RING])))
        }),
    ];
    for (port, line) in [Port::One, Port::Two].into_iter().zip(ports) {
        let connector = Connector::VeDirect(port);
        let device = plan.devices_on(connector).next().map(Entry::from);
        check_in(connector.task());
        spawn(
            tasks,
            connector.task(),
            vedirect(connector.task(), line, device, site),
        );
    }
}

/// The CAN bus, configured only when the plan puts a device on it.
fn start_can(
    (fdcan, can_rx, can_tx): (
        Peri<'static, p::FDCAN1>,
        Peri<'static, p::PB8>,
        Peri<'static, p::PB9>,
    ),
    plan: &Plan,
    site: Shared,
    tasks: SendSpawner,
) {
    let can_port = match plan.settings(Connector::Can) {
        Settings::Can(rate) => {
            let configurator = CanConfigurator::new(fdcan, can_rx, can_tx, irqs::Irqs);
            Some(crate::can::Port::new(configurator, rate.get()))
        }
        Settings::Idle | Settings::Serial(_) => None,
    };
    let device = plan.devices_on(Connector::Can).next().map(Entry::from);
    check_in(Task::Can);
    spawn(tasks, Task::Can, self::can(can_port, device, site));
}

/// The 1-Wire line, calibrated only when the plan puts a probe on it.
fn start_onewire(onewire: Peri<'static, p::PC4>, plan: &Plan, site: Shared, tasks: SendSpawner) {
    let mut probes = [None; ONEWIRE_DEVICES];
    for (slot, planned) in probes.iter_mut().zip(plan.devices_on(Connector::OneWire)) {
        *slot = Some(Entry::from(planned));
    }
    let period = plan
        .devices_on(Connector::OneWire)
        .map(|planned| planned.period)
        .min()
        .unwrap_or(LOCAL_PERIOD);
    let line = if probes.iter().any(Option::is_some) {
        match crate::onewire::Line::new(Flex::new(onewire)) {
            Ok(line) => Some(line),
            Err(error) => {
                defmt::error!("onewire: the delays did not calibrate: {}", error);
                None
            }
        }
    } else {
        None
    };
    check_in(Task::OneWire);
    spawn(
        tasks,
        Task::OneWire,
        self::onewire(line, probes, period, site),
    );
}

/// The ADC and the controller's own inputs, always.
fn start_adc(
    (adc1, pins): (Peri<'static, p::ADC1>, board::AdcPins),
    site: Shared,
    tasks: SendSpawner,
) {
    if let Some(inputs) = local_inputs() {
        let sampler =
            crate::adc::Sampler::new(Adc::new_blocking(adc1, AdcConfig::default()), pins, inputs);
        check_in(Task::Adc);
        spawn(tasks, Task::Adc, self::adc(sampler, site));
    } else {
        defmt::error!("adc: the board's inputs did not build; the watchdog will reset the part");
    }
}

/// An RS-485 channel's line at the plan's framing, or at the idle one.
fn rs485_line(
    plan: &Plan,
    bus: Bus,
    rings: &'static StaticCell<([u8; RS485_TX], [u8; RS485_RX])>,
    build: impl FnOnce(
        usart::Config,
        (&'static mut [u8], &'static mut [u8]),
    ) -> Result<BufferedUart<'static>, usart::ConfigError>,
) -> Option<Framed<Rs485Line>> {
    let framing = match plan.settings(Connector::Rs485(bus)) {
        Settings::Serial(framing) => framing,
        Settings::Idle | Settings::Can(_) => IDLE_FRAMING,
    };
    let (tx_ring, rx_ring) = rings.init(([0; RS485_TX], [0; RS485_RX]));
    // The transceivers drive the receive line; nothing pulls it.
    match build(
        crate::serial::config(framing, Pull::None),
        (tx_ring, rx_ring),
    ) {
        Ok(uart) => Some(Framed::new(Rs485Line::new(uart, framing), framing.gap())),
        Err(error) => {
            defmt::error!("rs485: {} did not configure: {}", bus, error);
            None
        }
    }
}

/// A VE.Direct port's line, when the plan runs the port.
fn vedirect_line(
    plan: &Plan,
    port: Port,
    build: impl FnOnce(usart::Config) -> Result<RingBufferedUartRx<'static>, usart::ConfigError>,
) -> Option<Framed<VeDirectLine>> {
    let Settings::Serial(framing) = plan.settings(Connector::VeDirect(port)) else {
        return None;
    };
    let pull = crate::serial::vedirect_pull(REVISION.vedirect_input(plan.three_volt(port)));
    match build(crate::serial::config(framing, pull)) {
        Ok(mut rx) => {
            rx.start_uart();
            Some(Framed::new(VeDirectLine::new(rx), framing.gap()))
        }
        Err(error) => {
            defmt::error!("vedirect: {} did not configure: {}", port, error);
            None
        }
    }
}

/// The controller's own inputs: the board's channels and scalings, and the
/// signals `o89-drivers` gives `dev 0`.
fn local_inputs() -> Option<[o89_drivers::adc::Input; 3]> {
    use o89_drivers::adc::{Input, Scaling};
    use o89_drivers::plan::LocalInput;
    Some([
        Input {
            channel: board::HOUSE_CHANNEL,
            scaling: Scaling::Divider(board::HOUSE_DIVIDER?),
            signal: LocalInput::House.signal()?,
        },
        Input {
            channel: board::START_CHANNEL,
            scaling: Scaling::Divider(board::START_DIVIDER?),
            signal: LocalInput::Start.signal()?,
        },
        Input {
            channel: board::TANK_CHANNEL,
            scaling: Scaling::Loop(board::TANK_LOOP?),
            signal: LocalInput::Tank.signal()?,
        },
    ])
}

/// Spawn one bus task, or say that the watchdog will reset the part.
fn spawn<S: Send>(tasks: SendSpawner, task: Task, token: Result<SpawnToken<S>, SpawnError>) {
    if let Ok(token) = token {
        tasks.spawn(token);
    } else {
        defmt::error!("{} did not spawn; the watchdog will reset the part", task);
    }
}
