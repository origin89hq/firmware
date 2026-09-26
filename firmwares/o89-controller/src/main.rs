//! The controller firmware: an adapter, and nothing that decides.
//!
//! Nothing here may contain an `if` about a generator, a threshold or a
//! timeout policy. Those live in `o89-core`, where a simulated winter can
//! drive them. This crate reads pins and writes pins, and the day it stops
//! being able to say that is the day a decision has escaped somewhere no test
//! can reach.
//!
//! Boot runs in the order the hazards dictate (`ARCHITECTURE.md`): the
//! generator and bus lines through the registers as the first statement;
//! the reset cause read and cleared and the last words taken, both before
//! the HAL; the clocks, with the LSE asserted; the watchdog, fed only by the
//! rollcall; the voltage detector; the module rail back on, with `EN` held,
//! before any bus; the store read off the FRAM; every output to its
//! declared fail state; the rail task and the link; the recorder with the
//! NOR; then the control tick. Every one of those runs on the control
//! executor, from an interrupt above thread mode, and thread mode is left
//! to key agreement alone (P-243). The other buses arrive with the
//! milestones that name them. The `bench` build adds
//! the one-shot proofs: a starvation on a boot the watchdog did not cause,
//! and a panic on the boot that follows, so three boots in a row show the
//! watchdog, the blame it leaves, the panic path and the site it leaves.

#![no_std]
#![no_main]

mod agreement;
mod board;
mod clock;
#[expect(
    unsafe_code,
    reason = "the control executor is polled from the interrupt started for it; the one call is under a SAFETY line"
)]
mod control;
#[expect(
    unsafe_code,
    reason = "cortex-m-rt requires the hard fault handler to be an unsafe fn; it reads the frame it is handed and resets"
)]
mod fault;
mod first;
mod fram;
mod last_words;
mod link;
mod mailbox;
mod nor;
mod panic;
mod pvd;
mod rail;
mod recorder;
mod reset;
mod rtc;
mod selector;
mod site;
#[expect(
    unsafe_code,
    reason = "the supervisor's executor is polled from the interrupt started for it; the one call is under a SAFETY line"
)]
mod supervisor;

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Flex, Input, Level, Output, Pull, Speed};
use embassy_stm32::i2c::I2c;
use embassy_stm32::spi::Spi;
use embassy_stm32::time::Hertz;
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_stm32::{i2c, spi};
use embassy_time::{Duration, Timer};
use o89_core::{
    Agreement, Blame, BootId, BootRecord, Bus, CarriedCuts, Clock, ControllerKey, CutsOnPart,
    CutsRecord, FailState, Feedback, Generator, Identity, Keys, LastWords, Line, LinkText, Millis,
    Pull as DeclaredPull, Rail, RailSequencer, ResetCause, Revision, RtcClock, SETTLE, Secret,
    Store, Task,
};

use crate::board::{Board, REVISION};
use crate::fram::Fram;
use crate::nor::Nor;
use crate::supervisor::Uptime;

// Every log line carries the tick, so a bench reads intervals off the log:
// the withheld feed to the watchdog reset, the reset to the first output.
defmt::timestamp!("{=u64:ms}", embassy_time::Instant::now().as_millis());

/// The level a driven line is held at, from the table `o89-core` declares.
///
/// Only lines the table declares driven are passed here; the assertions
/// below hold that at compile time for each one this image drives.
const fn driven(line: Line) -> Level {
    match line.fail_state(REVISION) {
        FailState::DrivenHigh | FailState::On => Level::High,
        FailState::DrivenLow
        | FailState::InputOrLow
        | FailState::Off
        | FailState::LeftToTheBoard => Level::Low,
    }
}

const _: () = {
    assert!(matches!(
        Line::Run.fail_state(REVISION),
        FailState::DrivenLow
    ));
    assert!(matches!(
        Line::Kick.fail_state(REVISION),
        FailState::DrivenLow
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::One).fail_state(REVISION),
        FailState::DrivenHigh
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::Two).fail_state(REVISION),
        FailState::DrivenHigh
    ));
    assert!(matches!(
        Line::Rs485Tx(Bus::Three).fail_state(REVISION),
        FailState::DrivenHigh
    ));
};

/// This firmware, as key 4 of every `LinkUp`: its version with the commit
/// it was built from, which the build script reads from git (KM43 L-034).
const FW: &str = env!("O89_LINK_VERSION");
/// The board, as key 6: its name and revision as origin89hq/hardware
/// writes them (KM43 L-034).
const HW: &str = match REVISION {
    Revision::A => "controller-a rev A",
    Revision::B => "controller-a rev B",
};
const _: () = {
    assert!(FW.len() <= km43::MAX_LINK_TEXT);
    assert!(HW.len() <= km43::MAX_LINK_TEXT);
};

/// A link text from a constant the assertion above has bounded.
fn link_text(text: &str) -> LinkText {
    match LinkText::new(text) {
        Ok(text) => text,
        Err(_) => LinkText::EMPTY,
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // 1. The lines with a hazard, before anything else.
    first::generator_and_bus_lines();
    // The bench tool's mailbox is not there until the recorder serves it.
    mailbox::clear();

    // 2. Why the part reset, and what the previous run said last.
    let cause = ResetCause::from_flags(reset::take_flags());
    let words = last_words::take();

    // 3. The clocks.
    let mut config = embassy_stm32::Config::default();
    config.rcc = clock::config();
    let p = embassy_stm32::init(config);
    let rtc = reset::rtc_clock();
    let backup = reset::backup_domain();

    if let Some(LastWords::Panicked(site)) = words {
        defmt::error!(
            "the previous run panicked at file {=u32:#x} line {=u32}",
            site.file,
            site.line
        );
    }
    if let RtcClock::Fault { lse_ready, source } = rtc {
        defmt::error!(
            "the RTC is not on the LSE: lse_ready={} source={}; a fault, not a fallback",
            lse_ready,
            source
        );
    }

    let b = Board::split(p);

    // 4. The watchdog, armed now and fed only by the rollcall.
    let mut wdg = IndependentWatchdog::new(b.iwdg, supervisor::WATCHDOG_US);
    wdg.unleash();

    let calendar = rtc::CalendarClock::new(b.rtc, b.tamp, rtc, backup);
    let backup = if calendar.now().is_some() {
        o89_core::BackupDomain::Valid
    } else {
        o89_core::BackupDomain::Invalid
    };
    let record = BootRecord::new(cause, words, rtc, backup, REVISION);
    defmt::info!("boot: {}", record);

    // 5. The voltage detector.
    pvd::arm();

    // 5a. The module rail, before any bus, with EN held low from the
    // instant the pins are taken so the rail never rises with the module's
    // reset released. Revision A drops the rail through every reset, so
    // the path from reset to here is how long a reset keeps the module
    // off, and one that lands inside a five-second cut adds exactly this
    // to it (F-005): no bus and no store on the way, only the clocks, the
    // watchdog and the detector. The boot then waits the rail's settling
    // before the FRAM is touched, so that on a cold boot, the switch-on
    // after a long off that corrupted the part within milliseconds on the
    // bench (origin89hq/hardware#5), nothing that writes is running.
    let mut rail = rail::Pins::new(
        Output::new(b.module.rail, Level::Low, Speed::Low),
        Flex::new(b.module.en),
        Flex::new(b.module.boot),
    );
    let mut sequencer = RailSequencer::new(REVISION);
    rail.apply(sequencer.power_on(Uptime.now()));
    defmt::info!("rail: powering the module, EN held low");
    Timer::after(Duration::from_millis(SETTLE.as_millis())).await;

    // 6. The store, off the FRAM, before any other output moves: the run
    // reason is what the boot decides on, and the boot count and the last
    // words are written down here. A bus that does not answer leaves no store,
    // and the boot goes on to the fail state as it would with one.
    // The supervisor is not running yet, so this phase bounds itself: every
    // transfer is cut by the driver's timeout, three times the longest one
    // the store makes, and the phase is written to the last words as a
    // provisional blame until the store is read, so a boot the watchdog
    // cuts short here is still named by the boot after (F-016).
    let mut i2c_config = i2c::Config::default();
    i2c_config.frequency = Hertz::khz(400);
    i2c_config.timeout = Duration::from_millis(100);
    last_words::write(LastWords::Starved(Blame {
        task: Task::Boot,
        overdue: Millis::ZERO,
    }));
    let mut fram = Fram::new(I2c::new_blocking(
        b.i2c2, b.fram_scl, b.fram_sda, i2c_config,
    ));
    let mut boot_count = None;
    // The epoch keys derive under, if the boot established one (P-085).
    let mut epoch = None;
    // With no store the ladder starts full, since a count the part lost is
    // never zero.
    let mut carried = CarriedCuts::FULL;
    let mut store = match Store::boot(&mut fram, words).await {
        Ok((store, report)) => {
            defmt::info!("store: {}", report);
            selector::at_power_on(report.enrolment);
            if let Some(reason) = store.run.present() {
                defmt::info!("run reason: {}", reason);
            } else {
                defmt::info!("run reason: none on the part");
            }
            // A count that did not land on the part is the same count
            // again next boot, which is the `boot_id` L-040 forbids; only
            // a written one names this boot (F-039).
            boot_count = report.boot_recorded.is_ok().then_some(report.boot);
            epoch = report.epoch.epoch();
            carried = CutsRecord::carried(store.cuts.held(), report.boot);
            if boot_count.is_none() {
                defmt::error!("store: the boot count was not written; no boot_id this boot");
            }
            Some(store)
        }
        Err(error) => {
            defmt::error!(
                "store: read or secret recovery failed: {}; booting without it",
                error
            );
            None
        }
    };
    last_words::clear();

    // 6a. The ladder's cuts: carried from the part as made at this boot's
    // start, this boot's own reset counted where it cut the rail, and kept
    // before anything else can fail, so a boot that never gets further
    // still counts toward the third rung (F-017, F-018); every boot since
    // the record was written, whose own record never landed, counts too.
    // With no store there is nowhere to keep them.
    sequencer.carry(carried, Uptime.now());
    let cuts = sequencer.recent_cuts(Uptime.now());
    let on_part = match store.as_mut() {
        Some(store) => {
            let mut on_part = CutsOnPart::read(carried.cuts);
            let record = CutsRecord {
                boot: store.boots.present().copied(),
                cuts,
            };
            match store.cuts.write(&mut fram, record).await {
                Ok(()) => on_part.landed(cuts),
                Err(error) => {
                    defmt::error!("rail: this boot's cuts not kept: {}", error);
                    on_part.unknown(Uptime.now());
                }
            }
            Some(on_part)
        }
        None => None,
    };
    defmt::info!(
        "rail: {} cuts in the last hour, carried and this boot's",
        cuts.count()
    );
    // What this side says about itself on the link (F-039). No boot count
    // is no `boot_id`: a hash over the unique id alone would come back the
    // same after the reboot L-040 exists to make visible, so a part whose
    // FRAM did not answer, or whose new count did not land, has no
    // identity and no link. Its module is powered all the same: on revision
    // A, a rail kept off and switched on at a later boot is what F-005
    // forbids.
    // Key 8 is the secret's id (L-035). Without a secret the link task runs
    // and serves the bench, but the link stays down for the boot and the
    // ladder leaves the module alone: a new cycle would not write a secret
    // (origin89hq/km43#127).
    let device_id = store
        .as_ref()
        .and_then(|store| store.secret.present())
        .map(Secret::device_id_bytes);
    if device_id.is_none() {
        defmt::error!("link: no device secret, so no device_id (L-035); the link stays down");
    }
    let identity = boot_count.map(|boot| Identity {
        fw: link_text(FW),
        hw: link_text(HW),
        boot_id: BootId::derive(embassy_stm32::uid::uid(), boot),
        device_id,
    });

    // 7. Every output this image drives, to its declared fail state. Held
    // by the control tick for the life of the part; a bus takes its
    // transmit line from there when it comes up.
    let held = control::Held {
        run: Output::new(b.gen_run, driven(Line::Run), Speed::Low),
        kick: Output::new(b.gen_kick, driven(Line::Kick), Speed::Low),
        rs485_tx: [
            Output::new(b.rs485_1.tx, driven(Line::Rs485Tx(Bus::One)), Speed::Low),
            Output::new(b.rs485_2.tx, driven(Line::Rs485Tx(Bus::Two)), Speed::Low),
            Output::new(b.rs485_3.tx, driven(Line::Rs485Tx(Bus::Three)), Speed::Low),
        ],
    };
    let status = Output::new(b.led_status, Level::Low, Speed::Low);
    let fault = Output::new(b.led_fault, Level::Low, Speed::Low);
    // The generator's FEEDBACK, read under the contract o89-core declares:
    // the internal pull-up, because neither board has one, and low is both
    // relays closed. Nothing decides on it yet; the control tick logs it,
    // and the first read is the first tick's: a read in the microsecond
    // after the pull-up is configured sees the line before it has risen,
    // and the bench logged a contact that was never closed.
    let feedback = Input::new(
        b.gen_feedback,
        match Feedback::PULL {
            DeclaredPull::Up => Pull::Up,
            DeclaredPull::None => Pull::None,
        },
    );
    let selector = selector::Selector {
        auto: Input::new(b.sel_auto, Pull::Up),
        manual: Input::new(b.sel_manual, Pull::Up),
    };

    supervisor::check_in(Task::Supervisor);
    // The pool holds one supervisor and this is its only spawn; an unfed
    // watchdog is the answer if it ever refuses. It runs from its own
    // interrupt, so a task that blocks this executor is still named.
    if supervisor::start(wdg, status, fault).is_err() {
        defmt::error!("the supervisor did not spawn; the watchdog will reset the part");
    }

    // 9. The module rail sequence, powered since 5a: the task releases EN
    // once the rail has settled, which it already has, and runs the ladder
    // from the cuts carried and kept at 6a.
    if identity.is_none() {
        defmt::error!(
            "link: no boot count, so no boot_id (F-039); the module is powered and the link stays down"
        );
    }
    // Every task that times anything, on the control executor above
    // thread mode (P-243).
    let tasks = control::start();
    supervisor::check_in(Task::Rail);
    // The rail is on the roll from the check-in above, so a task that did
    // not spawn is one that stops checking in: the watchdog resets the part.
    if let Ok(token) = rail::run(rail, Rail::new(sequencer, on_part)) {
        tasks.spawn(token);
    } else {
        defmt::error!("the rail task did not spawn; the watchdog will reset the part");
    }

    // The store splits here: the client protocol's records to the link task,
    // which keeps them, the ladder's cuts and the boot count to the recorder,
    // and the part itself to both, a transfer at a time.
    // The worker holds the controller key and the label, and nothing else
    // on this side does (P-235).
    let (keys, cuts, worker) = match store {
        Some(Store {
            secret,
            controller,
            drbg,
            epoch: epoch_record,
            clients,
            configuration,
            network,
            cuts,
            boots,
            ..
        }) => (
            Some(Keys {
                configuration,
                network,
                secret: secret.present().copied(),
                controller: controller.present().map(ControllerKey::public),
                epoch,
                epoch_record,
                clients,
                generator: Generator::new(drbg),
            }),
            recorder::Cuts {
                kept: Some(cuts),
                boot: boots.present().copied(),
            },
            secret
                .present()
                .zip(controller.present())
                .map(|(secret, controller)| Agreement::new(secret, controller)),
        ),
        None => (
            None,
            recorder::Cuts {
                kept: None,
                boot: None,
            },
            None,
        ),
    };
    let fram = fram::share(fram);

    // 9. The one site the reading plane reads, at its boot revision, before
    // the link can answer a client out of it or the recorder announce it.
    let site = site::boot();

    // 9a. The link, which builds its UART only once the rail task says the
    // rail has settled (F-006), and drops it before every cut (F-003).
    supervisor::check_in(Task::Link);
    let link_pins = link::Pins {
        usart: b.module.usart,
        tx: b.module.tx,
        rx: b.module.rx,
        rts: b.module.rts,
        cts: b.module.cts,
    };
    if let Ok(token) = link::run(link_pins, identity.zip(keys), fram, site) {
        tasks.spawn(token);
    } else {
        defmt::error!("the link task did not spawn; the watchdog will reset the part");
    }

    // 9b. The recorder, with the NOR: the ring is opened and the boot
    // record written once the outputs are where they must be.
    let mut spi_config = spi::Config::default();
    spi_config.frequency = Hertz::mhz(8);
    let spi = Spi::new_blocking(b.spi1, b.nor_sck, b.nor_mosi, b.nor_miso, spi_config);
    let nor = Nor::new(spi, Output::new(b.nor_cs, Level::High, Speed::VeryHigh));
    supervisor::check_in(Task::Recorder);
    if let Ok(token) = recorder::run(cuts, fram, nor, record.body(), calendar, site) {
        tasks.spawn(token);
    } else {
        defmt::error!("the recorder did not spawn; the watchdog will reset the part");
    }

    // 10. The control tick, 1 Hz, holding every output.
    supervisor::check_in(Task::Control);
    if let Ok(token) = control::run(held, feedback, selector, words) {
        tasks.spawn(token);
    } else {
        defmt::error!("the control tick did not spawn; the watchdog will reset the part");
    }

    // 11. Key agreement, alone in thread mode, below every task above
    // (P-243). A unit with no controller key has none, and nothing on the
    // roll waits for it.
    if let Some(worker) = worker {
        supervisor::check_in(Task::Agreement);
        if let Ok(token) = agreement::run(worker) {
            spawner.spawn(token);
        } else {
            defmt::error!("the agreement worker did not spawn; the watchdog will reset the part");
        }
    }
}
