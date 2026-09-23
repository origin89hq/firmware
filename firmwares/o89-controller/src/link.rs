//! The link to the module: USART1 at 921600 with RTS/CTS on the pins the
//! board wires (F-030), the driver's interrupt-fed ring behind `km43`'s
//! reader, and `o89_core`'s state machine deciding.
//!
//! The UART exists only while the module is powered. It is built when the
//! rail task says the rail has settled (F-006), and dropped, its pins back
//! to inputs, before the rail task is asked to cut (F-003); the state
//! machine outlives every such episode. Every await has a deadline: a read
//! waits one tick at most, a write two hundred milliseconds, which is
//! twenty frames at this rate. A module that holds `CTS` past that has
//! stalled the transmitter with the frame's bytes still in its ring, and
//! there is no clearing a `BufferedUartTx`: the UART is dropped and built
//! again, which is the one way its ring starts empty, and the state
//! machine's ladder decides from the silence what happens next. Never a
//! task that stops checking in.
//!
//! The UART is interrupt-driven, a byte at a time into a ring the driver
//! owns. The DMA ring was tried first, on `DMA1` channels with interrupt
//! lines of their own, and overran from the first byte on board A as the
//! recorder's DMA had (#39): the bench decided this, and the note under
//! `docs/bench/` carries it. At 921600 that is a byte every eleven
//! microseconds at the busiest, which the part can take and the log shows
//! it taking. The pinned buffered driver does not return hardware errors
//! from reads and silently discards bytes when its software ring is full;
//! zero read errors therefore do not establish a lossless link (#63).

use embassy_futures::yield_now;
use embassy_stm32::gpio::{Flex, Pull};
use embassy_stm32::usart::{BufferedUart, BufferedUartTx, Config, Error};
use embassy_stm32::{Peri, bind_interrupts, usart};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{Read, Write};
use km43::{
    DownloadReason, DownloadRequest, FrameReader, FrameWriter, LinkEnvelope, LinkHeader,
    LinkMessageType, MAX_FRAME, Received, ReqId, SessionId,
};
use o89_core::mailbox::DownloadEntry;
use o89_core::{
    Action, Actions, Clock, Identity, KnockAnswer, Link, ModuleBoot, ModuleReset, Note, Recovery,
    Task, knock_answer,
};
use portable_atomic::{AtomicU32, Ordering};
use static_cell::StaticCell;

use crate::board::{EspCts, EspRts, EspRx, EspTx, EspUsart};
use crate::mailbox;
use crate::rail::{self, RailWord};
use crate::recorder;
use crate::supervisor::{Uptime, check_in};

/// What the bench asks of the link, through the mailbox (F-038).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Put the module into its ROM's download mode and bridge its UART to
    /// the mailbox's rings, for the reason the controller logs (L-192).
    Download {
        /// Why, as the registry names it: the mailbox refuses a number it
        /// does not name rather than guess one.
        reason: DownloadReason,
        /// The route in: the window, the strap, or a reset to listen to.
        entry: DownloadEntry,
    },
    /// End the bridge: the module reset normally, the link back.
    Normal,
}

/// What the link answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Report {
    /// The module answered `entering` and the bridge is up.
    Bridging,
    /// The module did not answer inside the window.
    NoAnswer,
    /// The module answered `refused_outside_window` (L-191).
    Refused,
    /// The rail is not up, or a request is already being served.
    Busy,
    /// The bridge is over and the module is booting normally.
    Normal,
    /// This boot has no store, so no link, and the bench is not served
    /// (F-039).
    NoStore,
    /// USART1 refused the ROM's configuration; the module was reset
    /// normally and nothing was bridged.
    BridgeRefused,
}

/// A request and the number that names it, so a report is read only by
/// the asker it answers: a request that timed out in the mailbox may be
/// reported later, and that report must not answer the next one.
static REQUEST: Signal<CriticalSectionRawMutex, (u32, Request)> = Signal::new();
static REPORT: Signal<CriticalSectionRawMutex, (u32, Report)> = Signal::new();
static SEQ: AtomicU32 = AtomicU32::new(0);

/// Ask the link task; one request at a time. The number to wait on.
pub fn request(request: Request) -> u32 {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    REQUEST.signal((seq, request));
    seq
}

/// What the link task did with request `seq`. Bounded by the caller's
/// deadline: reports for other requests are passed over.
pub async fn report(seq: u32) -> Report {
    loop {
        let (answered, report) = REPORT.wait().await;
        if answered == seq {
            return report;
        }
    }
}

/// How long a bridge stays open with its lease unrenewed before it is
/// closed as abandoned. The host renews the lease about once a second
/// while it holds the bridge, so a host that died, lost power or lost its
/// probe lets it lapse; the module's own bytes do not count, because a
/// module talks whether anyone listens or not.
const BRIDGE_IDLE: Duration = Duration::from_secs(60);

/// The ROM's serial download rate, with no flow control (F-038).
const ROM_BAUD: u32 = 115_200;
/// How long the module has to settle after a reset the bridge asked for.
const RESET_DEADLINE: Duration = Duration::from_millis(2_000);
/// L-192: the first statement within 200 ms of `EN` released, then every
/// 100 ms, until 3 000 ms have passed.
const KNOCK_PERIOD: Duration = Duration::from_millis(100);
const KNOCK_DEADLINE: Duration = Duration::from_millis(3_000);
/// How often the bridge turns when nothing arrives.
const BRIDGE_TICK: Duration = Duration::from_millis(5);

bind_interrupts!(struct Irqs {
    USART1 => usart::BufferedInterruptHandler<EspUsart>;
});

/// The link's rate (F-030).
pub const BAUD: u32 = 921_600;

/// The receive ring: two frames at their largest, so a whole frame can
/// arrive while the previous one is being read out.
const RING: usize = 2 * MAX_FRAME;
static RX_RING: StaticCell<[u8; RING]> = StaticCell::new();
/// The transmit ring: one frame; a second waits for the first.
static TX_RING: StaticCell<[u8; MAX_FRAME]> = StaticCell::new();

/// How long a read waits before the tick is served.
const TICK: Duration = Duration::from_millis(100);
/// How long a frame may take to leave. Twenty frames' worth at the rate:
/// past it the module is holding `CTS`, and the frame is abandoned.
const WRITE_DEADLINE: Duration = Duration::from_millis(200);

/// What the task owns for the life of the part, and hands to each UART.
pub struct Pins {
    /// USART1.
    pub usart: Peri<'static, EspUsart>,
    /// `ESP_TX`.
    pub tx: Peri<'static, EspTx>,
    /// `ESP_RX`.
    pub rx: Peri<'static, EspRx>,
    /// `ESP_RTS`.
    pub rts: Peri<'static, EspRts>,
    /// `ESP_CTS`.
    pub cts: Peri<'static, EspCts>,
}

/// Why an episode ended.
enum Ended {
    /// The state machine asked for the rail to be cut; the UART is gone.
    Cut,
    /// The UART would not configure; nothing to do but wait and try again.
    Refused,
    /// A frame did not leave within its deadline: the module holds `CTS`.
    /// The UART is gone with the bytes stuck in its ring, and the next
    /// episode starts at once with nothing new to say.
    Stalled,
    /// The bench asked for the module's download mode; the UART is gone.
    Download(Asked),
}

/// The link task. No identity is a boot without a written count (F-039):
/// the link never comes up, though the module is powered as on every boot
/// (F-005), and this task keeps its place on the roll for the life of the
/// part and nothing more.
#[embassy_executor::task]
pub async fn run(mut pins: Pins, identity: Option<Identity>) {
    let Some(identity) = identity else {
        // The bench's requests are answered, not served: a unit without
        // its store has no link, and the FRAM is what is serviced first.
        loop {
            match with_timeout(TICK, REQUEST.wait()).await {
                Ok((seq, Request::Download { .. } | Request::Normal)) => {
                    REPORT.signal((seq, Report::NoStore));
                }
                Err(_) => {}
            }
            check_in(Task::Link);
        }
    };
    let rings = Rings {
        rx: RX_RING.init([0; RING]),
        tx: TX_RING.init([0; MAX_FRAME]),
    };
    let mut rings = rings;
    let mut link = Link::new(identity, Uptime.now());
    let mut reader = FrameReader::new();
    let mut writer = FrameWriter::new();
    #[cfg(feature = "frames")]
    let mut counts = frames::Counts::new();
    let mut resume = false;
    check_in(Task::Link);
    loop {
        // The bench first: a request while the module is off is served the
        // same way, and one for the normal state answers at once.
        match REQUEST.try_take() {
            Some((seq, Request::Download { reason, entry })) => {
                perform_quiet(&link.module_taken());
                download(
                    &mut pins,
                    &mut rings,
                    &mut reader,
                    &mut writer,
                    Asked { seq, reason, entry },
                )
                .await;
                continue;
            }
            Some((seq, Request::Normal)) => REPORT.signal((seq, Report::Normal)),
            None => {}
        }
        // The module is off, or being cut: nothing to say, the words to hear.
        // After a stall the module is still powered and the UART comes
        // straight back with nothing new to say.
        let first = if core::mem::take(&mut resume) {
            Some(Actions::NONE)
        } else {
            match with_timeout(TICK, rail::words().receive()).await {
                Ok(RailWord::Settled) => {
                    defmt::info!("link: the rail settled; USART1 up");
                    Some(link.module_settled(Uptime.now()))
                }
                Ok(RailWord::Reset(_)) => None,
                Ok(RailWord::Recovered(recovery)) => {
                    let actions = link.rail(recovery, Uptime.now());
                    perform_quiet(&actions);
                    match recovery {
                        Recovery::Cycling { .. } => None,
                        Recovery::LeftOnAndRaised | Recovery::Busy | Recovery::Deferred => {
                            // The rail did not move: the module is still
                            // powered, and the UART comes back with no new
                            // statement.
                            defmt::info!("link: the rail stays on; USART1 up again");
                            Some(Actions::NONE)
                        }
                    }
                }
                Err(_) => {
                    let actions = link.tick(Uptime.now(), install_in_flight());
                    perform_quiet(&actions);
                    None
                }
            }
        };
        if let Some(first) = first {
            // Bounded: an episode ends on a cut or a refusal, and a refusal
            // is tried again after the next word.
            let ended = episode(
                &mut link,
                &mut pins,
                &mut rings,
                &mut reader,
                &mut writer,
                first,
                #[cfg(feature = "frames")]
                &mut counts,
            )
            .await;
            match ended {
                Ended::Cut => {
                    park(&mut pins);
                    rail::request_recovery();
                }
                Ended::Stalled => resume = true,
                Ended::Refused => {
                    // The rail settled and said so once; a UART that will
                    // not configure is a module nobody can hear, and the
                    // recovery ladder is the bounded way out: a cycle, then
                    // the third rung.
                    park(&mut pins);
                    rail::request_recovery();
                }
                Ended::Download(asked) => {
                    perform_quiet(&link.module_taken());
                    download(&mut pins, &mut rings, &mut reader, &mut writer, asked).await;
                }
            }
        }
        check_in(Task::Link);
    }
}

/// L-113: a comms release being written suspends the ladder. No release
/// exists before M7; the store's `release.live(now)` answers this then.
const fn install_in_flight() -> bool {
    false
}

/// F-003, read where the rule binds: `ESP_TX` and `ESP_RTS` are inputs before the
/// rail task hears a request that ends with the module unpowered. The
/// UART's halves already left them so, because a `Flex` in this HAL
/// disconnects its pin when dropped; this is the line that does not rest
/// on that, and the one to read against the requirement.
fn park(pins: &mut Pins) {
    Flex::new(pins.tx.reborrow()).set_as_input(Pull::None);
    Flex::new(pins.rts.reborrow()).set_as_input(Pull::None);
}

/// The driver's rings, owned for the life of the part and lent to each
/// UART.
struct Rings {
    rx: &'static mut [u8; RING],
    tx: &'static mut [u8; MAX_FRAME],
}

/// One episode of the module being powered: the UART built, the frames
/// pumped, the tick served, until the state machine asks for a cut or a
/// frame stalls in the transmitter. The UART is dropped on the way out,
/// which puts its pins back to inputs before the rail task hears the
/// request (F-003) and empties the ring before the next episode's.
/// The bench's request while the link runs: a download, which ends the
/// episode, or a request for the normal state, which is answered at once.
fn bench_download() -> Option<Asked> {
    match REQUEST.try_take() {
        Some((seq, Request::Download { reason, entry })) => Some(Asked { seq, reason, entry }),
        Some((seq, Request::Normal)) => {
            REPORT.signal((seq, Report::Normal));
            None
        }
        None => None,
    }
}

async fn episode(
    link: &mut Link,
    pins: &mut Pins,
    rings: &mut Rings,
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    first: Actions,
    #[cfg(feature = "frames")] counts: &mut frames::Counts,
) -> Ended {
    // A new UART starts a new run: the tail of a frame cut off by the last
    // episode's end, by a cut or by a stall, would merge into this one's
    // first frame and count its noise against the wrong boot (F-031).
    reader.discard();
    let uart = match open(pins, rings) {
        Ok(uart) => uart,
        Err(ended) => return ended,
    };
    let (mut tx, mut rx) = uart.split();
    if let Some(ended) = perform(link, &mut tx, writer, &first).await {
        return ended;
    }
    let mut chunk = [0u8; 64];
    let mut last_byte = Instant::now();
    // Bytes pushed since the reader last handed up a frame, a refusal or an
    // abandoned run: what a refused run cost, for the boot noise (F-031).
    let mut run: u32 = 0;
    // Bounded by the cut the state machine asks for, and every turn by the
    // tick: the read waits `TICK` at most.
    let ended = 'episode: loop {
        // Every call below reads the clock itself: a read can wait a whole
        // tick, and a frame stamped before the wait is heard a tick early.
        match with_timeout(TICK, rx.read(&mut chunk)).await {
            Ok(Ok(count)) => {
                last_byte = Instant::now();
                for byte in chunk.get(..count).unwrap_or(&[]) {
                    run = run.saturating_add(1);
                    let ended = match reader.push(*byte) {
                        Received::Frame(frame) => {
                            // A frame's bytes, malformed or not, are not
                            // noise (F-031).
                            run = 0;
                            #[cfg(feature = "frames")]
                            counts.frame(frame);
                            if let Ok(envelope) = LinkEnvelope::decode(frame) {
                                let was_up = link.is_up();
                                let actions = link.received(envelope, Uptime.now());
                                // The peer's own statement records it without
                                // linking (L-033): only the transition is news.
                                if !was_up
                                    && link.is_up()
                                    && let Some(peer) = link.peer()
                                {
                                    defmt::info!("link: up; the module is {}", peer);
                                    #[cfg(feature = "frames")]
                                    counts.linked();
                                }
                                perform(link, &mut tx, writer, &actions).await
                            } else {
                                None
                            }
                        }
                        refused @ (Received::Dropped(_) | Received::Abandoned) => {
                            #[cfg(feature = "frames")]
                            counts.refused(refused);
                            #[cfg(not(feature = "frames"))]
                            let _ = refused;
                            link.noise(run);
                            run = 0;
                            None
                        }
                        Received::Nothing => None,
                    };
                    if let Some(ended) = ended {
                        break 'episode ended;
                    }
                }
            }
            Ok(Err(error)) => {
                // An overrun or a line error: the bytes it lost are noise.
                // The bytes it lost were never read, so they are not counted
                // as non-frames; the error is on the probe's log.
                #[cfg(feature = "frames")]
                counts.error(error);
                note_rx_error(error);
            }
            Err(_) => {
                // The incomplete-frame timeout is the reader's, fed with
                // how long the line has been quiet.
                let quiet = u32::try_from(last_byte.elapsed().as_millis()).unwrap_or(u32::MAX);
                if let Received::Abandoned = reader.tick(None, quiet) {
                    #[cfg(feature = "frames")]
                    counts.abandoned();
                    link.noise(run);
                    run = 0;
                }
            }
        }
        #[cfg(feature = "frames")]
        counts.report();
        if let Some(asked) = bench_download() {
            break 'episode Ended::Download(asked);
        }
        while let Ok(word) = rail::words().try_receive() {
            match word {
                RailWord::Reset(_) => {}
                RailWord::Settled => {
                    // Cannot happen while the UART is up: the rail only
                    // settles after a cut this task asked for.
                    defmt::warn!("link: the rail settled while the link was up");
                }
                RailWord::Recovered(recovery) => {
                    let actions = link.rail(recovery, Uptime.now());
                    if let Some(ended) = perform(link, &mut tx, writer, &actions).await {
                        break 'episode ended;
                    }
                }
            }
        }
        if let Some(ended) = service_tick(link, &mut tx, writer).await {
            break 'episode ended;
        }
        check_in(Task::Link);
        // A ready read never yields: the other tasks get every turn's end.
        yield_now().await;
    };
    // The run the reader holds when the episode ends is thrown away with the
    // UART, whatever ended it, so its bytes are this attempt's noise and are
    // counted now, before the caller can close the attempt (F-031).
    link.noise(run);
    ended
}

/// A download request with the number that names it. Every report goes
/// out under the number of the request it answers, from one place, because
/// the signal holds one value and a second report before the mailbox task
/// runs would replace the first.
#[derive(Debug, Clone, Copy)]
struct Asked {
    seq: u32,
    reason: DownloadReason,
    entry: DownloadEntry,
}

/// Why a bridge closed.
enum Closed {
    /// The host gave the module back, under this request number.
    Normal { seq: u32 },
    /// Another download was asked while this one's host held the bridge:
    /// that host is gone, and the new one gets the bridge for its own.
    Reclaimed(Asked),
    /// The host's lease lapsed for [`BRIDGE_IDLE`]: the host is gone.
    Idle,
    /// USART1 refused the ROM's configuration: the host is told so and
    /// never bridged.
    Refused,
}

/// The bench's way into the module's ROM (F-038, L-192): a reset this
/// side performs, the statement knocked inside the window, and the UART
/// handed to the mailbox's rings at the ROM's rate until the bench gives
/// the module back. The state machine sits this out: it is told the module
/// settled when the link resumes.
async fn download(
    pins: &mut Pins,
    rings: &mut Rings,
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    mut asked: Asked,
) {
    // Bounded by the host: a bridge closes when the host gives the module
    // back, when another download reclaims it, or when the host's lease on
    // it lapses for `BRIDGE_IDLE`.
    loop {
        let reason = asked.reason;
        // The reason on every route, so the log tells a bench flash from a
        // recovery whether the module is knocked or strapped (L-192).
        defmt::info!("link: download ({}) by {}", reason, asked.entry);
        let boot = match asked.entry {
            DownloadEntry::Strap => ModuleBoot::Download,
            DownloadEntry::Knock | DownloadEntry::Reset => ModuleBoot::Normal,
        };
        rail::request_module_reset(boot);
        if !settled_after_reset().await {
            // The reset may still finish after the deadline, and a strapped
            // one must not leave the module in its ROM with no bridge.
            rail::request_module_reset(ModuleBoot::Normal);
            REPORT.signal((asked.seq, Report::Busy));
            return;
        }
        if let DownloadEntry::Knock = asked.entry {
            let report = match knock(pins, rings, reader, writer, reason).await {
                Knocked::Entering => None,
                Knocked::Refused => Some(Report::Refused),
                Knocked::Unanswered => {
                    defmt::warn!("link: the module did not answer EnterDownload inside the window");
                    Some(Report::NoAnswer)
                }
            };
            if let Some(report) = report {
                rail::request_module_reset(ModuleBoot::Normal);
                REPORT.signal((asked.seq, report));
                return;
            }
        }
        defmt::info!(
            "link: the module is entering download mode; bridging at {} baud",
            ROM_BAUD
        );
        match bridge(pins, rings, asked.seq).await {
            Closed::Normal { seq } => {
                REPORT.signal((seq, Report::Normal));
                break;
            }
            Closed::Idle => {
                defmt::warn!(
                    "link: the host's lease on the bridge lapsed {} s ago; the host is gone",
                    BRIDGE_IDLE.as_secs()
                );
                break;
            }
            Closed::Refused => {
                REPORT.signal((asked.seq, Report::BridgeRefused));
                break;
            }
            Closed::Reclaimed(next) => {
                defmt::warn!("link: another download reclaims the bridge");
                asked = next;
            }
        }
    }
    defmt::info!("link: the bridge is closed; the module reset normally");
    rail::request_module_reset(ModuleBoot::Normal);
}

/// Wait for the rail task to say the module settled after the reset asked
/// for, or that there was nothing to reset.
async fn settled_after_reset() -> bool {
    let until = Instant::now().checked_add(RESET_DEADLINE);
    // A `Settled` still queued from an earlier power-up or reset is not
    // this reset's: only one after this reset's `Holding` counts.
    let mut holding = false;
    // Bounded by the deadline: every turn waits a tick at most.
    loop {
        match with_timeout(TICK, rail::words().receive()).await {
            Ok(RailWord::Settled) if holding => return true,
            Ok(RailWord::Reset(ModuleReset::Holding)) => holding = true,
            Ok(RailWord::Reset(ModuleReset::NotPowered)) => return false,
            Ok(RailWord::Settled | RailWord::Recovered(_)) | Err(_) => {}
        }
        check_in(Task::Link);
        if until.is_none_or(|until| Instant::now() >= until) {
            return false;
        }
    }
}

/// How a knock ended.
enum Knocked {
    /// `entering`: the module is resetting into its ROM.
    Entering,
    /// `refused_outside_window`: the module runs an image whose window had
    /// closed, a verdict of its own and not silence.
    Refused,
    /// Nothing under the knock's id in three seconds.
    Unanswered,
}

/// `EnterDownload` every 100 ms under one `req_id` until `entering` comes
/// back or three seconds have passed (L-192).
async fn knock(
    pins: &mut Pins,
    rings: &mut Rings,
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    reason: DownloadReason,
) -> Knocked {
    let mut config = Config::default();
    config.baudrate = BAUD;
    let Ok(uart) = BufferedUart::new_with_rtscts(
        pins.usart.reborrow(),
        pins.tx.reborrow(),
        pins.rx.reborrow(),
        pins.rts.reborrow(),
        pins.cts.reborrow(),
        Irqs,
        &mut rings.tx[..],
        &mut rings.rx[..],
        config,
    ) else {
        return Knocked::Unanswered;
    };
    let (mut tx, mut rx) = uart.split();
    // The reset cut the module off mid-frame, perhaps: that tail would merge
    // with the only `entering` the module sends before it resets.
    reader.discard();
    let req_id = ReqId(0x5A5A_0001);
    let mut envelope = [0u8; 64];
    let Ok(len) = (DownloadRequest { reason }).write(
        LinkHeader {
            kind: LinkMessageType::EnterDownload,
            session: SessionId::None,
            req_id,
        },
        &mut envelope,
    ) else {
        return Knocked::Unanswered;
    };
    let mut frame = [0u8; MAX_FRAME];
    let Ok(len) = writer.write(envelope.get(..len).unwrap_or(&[]), &mut frame) else {
        return Knocked::Unanswered;
    };
    let frame = frame.get(..len).unwrap_or(&[]);
    let started = Instant::now();
    let mut next_knock = started;
    let mut chunk = [0u8; 64];
    // Bounded by the deadline: every turn knocks or reads for a tick.
    while started.elapsed() < KNOCK_DEADLINE {
        if Instant::now() >= next_knock {
            next_knock = Instant::now()
                .checked_add(KNOCK_PERIOD)
                .unwrap_or(next_knock);
            let _ = with_timeout(WRITE_DEADLINE, send(&mut tx, frame)).await;
        }
        if let Ok(Ok(count)) = with_timeout(KNOCK_PERIOD, rx.read(&mut chunk)).await {
            for byte in chunk.get(..count).unwrap_or(&[]) {
                let Received::Frame(bytes) = reader.push(*byte) else {
                    continue;
                };
                let Ok(envelope) = LinkEnvelope::decode(bytes) else {
                    continue;
                };
                match knock_answer(envelope, req_id) {
                    KnockAnswer::Entering => {
                        defmt::info!("link: EnterDownload ({}) answered entering", reason);
                        return Knocked::Entering;
                    }
                    KnockAnswer::Refused => {
                        defmt::warn!(
                            "link: EnterDownload ({}) answered refused_outside_window",
                            reason
                        );
                        return Knocked::Refused;
                    }
                    KnockAnswer::NotOurs => {}
                }
            }
        }
        check_in(Task::Link);
        yield_now().await;
    }
    defmt::warn!(
        "link: EnterDownload ({}) unanswered after {} ms",
        reason,
        KNOCK_DEADLINE.as_millis()
    );
    Knocked::Unanswered
}

/// The UART at the ROM's rate with no flow control, its bytes moved to
/// and from the mailbox's rings until the bench asks for the module back.
/// The bridge is reported up to request `seq` only once its UART is: a host
/// told `Bridging` always has a bridge to talk to.
async fn bridge(pins: &mut Pins, rings: &mut Rings, seq: u32) -> Closed {
    let mut config = Config::default();
    config.baudrate = ROM_BAUD;
    let Ok(uart) = BufferedUart::new(
        pins.usart.reborrow(),
        pins.tx.reborrow(),
        pins.rx.reborrow(),
        Irqs,
        &mut rings.tx[..],
        &mut rings.rx[..],
        config,
    ) else {
        defmt::error!("link: USART1 refused the ROM's configuration");
        return Closed::Refused;
    };
    mailbox::bridge_reset();
    REPORT.signal((seq, Report::Bridging));
    let (mut tx, mut rx) = uart.split();
    let mut chunk = [0u8; 256];
    let mut lost: u32 = 0;
    let mut lease = mailbox::bridge_lease();
    let mut leased = Instant::now();
    // Bounded by the bench's request for the normal state, by another
    // download reclaiming the bridge, or by the host's lease lapsing for
    // `BRIDGE_IDLE`; every turn waits a bridge tick at most and checks in.
    let closed = loop {
        match REQUEST.try_take() {
            Some((seq, Request::Normal)) => break Closed::Normal { seq },
            Some((seq, Request::Download { reason, entry })) => {
                break Closed::Reclaimed(Asked { seq, reason, entry });
            }
            None => {}
        }
        let renewed = mailbox::bridge_lease();
        if renewed != lease {
            lease = renewed;
            leased = Instant::now();
        }
        if leased.elapsed() >= BRIDGE_IDLE {
            break Closed::Idle;
        }
        if let Ok(Ok(count)) = with_timeout(BRIDGE_TICK, rx.read(&mut chunk)).await {
            let mut bytes = chunk.get(..count).unwrap_or(&[]);
            // Bounded: the host drains the ring, and a host that does not
            // is given a write deadline's worth before the bytes are lost.
            let until = Instant::now().checked_add(WRITE_DEADLINE);
            while !bytes.is_empty() {
                let taken = mailbox::bridge_push(bytes);
                bytes = bytes.get(taken..).unwrap_or(&[]);
                if bytes.is_empty() || until.is_none_or(|until| Instant::now() >= until) {
                    break;
                }
                Timer::after(BRIDGE_TICK).await;
            }
            if !bytes.is_empty() {
                lost = lost.saturating_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
            }
        }
        let count = mailbox::bridge_pull(&mut chunk);
        if count > 0 {
            let _ = with_timeout(
                WRITE_DEADLINE,
                send(&mut tx, chunk.get(..count).unwrap_or(&[])),
            )
            .await;
        }
        check_in(Task::Link);
        // Ready reads do not yield: the module streaming at the ROM's rate
        // would otherwise hold the executor through the whole flash.
        yield_now().await;
    };
    if lost > 0 {
        defmt::warn!(
            "link: {} bytes from the module were lost on a full ring",
            lost
        );
    }
    closed
}

/// Perform actions with a UART in hand. Answers how the episode ends, if
/// it does: a cut the state machine asked for, which the caller performs
/// after dropping the UART, or a frame that stalled in the transmitter.
/// A cut outranks a stall, and after a stall nothing more is sent: the
/// ring is full of a frame that is not leaving.
async fn perform(
    link: &Link,
    tx: &mut BufferedUartTx<'_>,
    writer: &mut FrameWriter,
    actions: &Actions,
) -> Option<Ended> {
    // The cut outranks every frame in its batch, before it or after it: the
    // module is about to lose its power, and a send could hold the cut back
    // by a whole write deadline.
    let cut = actions
        .iter()
        .any(|action| matches!(action, Action::CutRail));
    let mut stalled = false;
    for action in actions {
        match action {
            Action::Send(outgoing) if cut => {
                defmt::info!("link: {} not sent; the rail is being cut", outgoing);
            }
            Action::Send(outgoing) if stalled => {
                defmt::warn!("link: {} not sent; the transmitter is stalled", outgoing);
            }
            Action::Send(outgoing) => {
                stalled = send_outgoing(link, tx, writer, *outgoing).await;
            }
            Action::CutRail => defmt::warn!("link: asking the rail for a cut"),
            Action::DropConnections(why) => {
                recorder::cancel_offers();
                // No connection rows before M4; the drop is the log line.
                defmt::info!("link: every connection dropped: {}", why);
            }
            Action::OfferTime { req_id, unix_ms } => {
                if let Some(outgoing) = recorder::offer(*req_id, *unix_ms)
                    && !cut
                    && !stalled
                {
                    stalled = send_outgoing(link, tx, writer, outgoing).await;
                }
            }
            Action::Log(event) => log(*event),
            Action::Note(note) => note_line(*note),
        }
    }
    if actions.dropped() > 0 {
        defmt::error!("link: {} actions did not fit", actions.dropped());
    }
    if cut {
        Some(Ended::Cut)
    } else if stalled {
        Some(Ended::Stalled)
    } else {
        None
    }
}

/// The whole frame into the driver's ring and out of the pin.
async fn send(tx: &mut BufferedUartTx<'_>, bytes: &[u8]) -> Result<(), Error> {
    tx.write_all(bytes).await?;
    tx.flush().await
}

/// Perform what can be performed with no UART: records and notes. A frame
/// asked for while the module is off is a bug in the state machine, and is
/// said so.
fn perform_quiet(actions: &Actions) {
    for action in actions {
        match action {
            Action::Send(outgoing) => {
                defmt::error!("link: {} asked for with the module off", outgoing);
            }
            Action::CutRail => defmt::error!("link: a cut asked for with the module off"),
            Action::DropConnections(why) => {
                recorder::cancel_offers();
                defmt::info!("link: every connection dropped: {}", why);
            }
            Action::OfferTime { .. } => defmt::error!("clock: offer while UART is off"),
            Action::Log(event) => log(*event),
            Action::Note(note) => note_line(*note),
        }
    }
}

fn log(event: o89_core::LinkEvent) {
    defmt::warn!("link: {}", event);
    if recorder::post(event).is_err() {
        defmt::error!("link: the event queue is full; {} not recorded", event);
    }
}

fn note_line(note: Note) {
    match note {
        Note::UnexpectedAck(_) => defmt::info!("link: {}", note),
        Note::Refused(_)
        | Note::RequestFailed(_)
        | Note::Malformed(_)
        | Note::PeerRefused(_)
        | Note::WrongRole => {
            defmt::warn!("link: {}", note);
        }
    }
}

fn note_rx_error(error: Error) {
    // Not our enum, and marked non-exhaustive by its crate.
    match error {
        Error::Overrun => defmt::warn!("link: receive overrun"),
        Error::Framing | Error::Noise | Error::Parity => {
            defmt::debug!("link: line error {}", error);
        }
        Error::BufferTooLong => defmt::error!("link: read buffer too long"),
        _ => defmt::warn!("link: receive error {}", error),
    }
}

/// USART1 at the link's rate with its flow control, or why not.
///
/// Its own function because the episode that runs on it is long enough
/// without it, and because the one place the pins and the rings are handed
/// to the driver is worth being able to find.
fn open<'a>(pins: &'a mut Pins, rings: &'a mut Rings) -> Result<BufferedUart<'a>, Ended> {
    let mut config = Config::default();
    config.baudrate = BAUD;
    #[cfg(not(feature = "no-flow"))]
    let opened = BufferedUart::new_with_rtscts(
        pins.usart.reborrow(),
        pins.tx.reborrow(),
        pins.rx.reborrow(),
        pins.rts.reborrow(),
        pins.cts.reborrow(),
        Irqs,
        &mut rings.tx[..],
        &mut rings.rx[..],
        config,
    );
    // The bench's other half: the lines left alone, so nothing holds the
    // module off and the ring is all there is between it and the task.
    #[cfg(feature = "no-flow")]
    let opened = {
        defmt::warn!(
            "link: USART1 without flow control; this is the bench that has to lose frames"
        );
        BufferedUart::new(
            pins.usart.reborrow(),
            pins.tx.reborrow(),
            pins.rx.reborrow(),
            Irqs,
            &mut rings.tx[..],
            &mut rings.rx[..],
            config,
        )
    };
    opened.map_err(|error| {
        defmt::error!("link: USART1 refused its configuration: {}", error);
        Ended::Refused
    })
}

/// The frames bench: what the link read, counted (F-087).
///
/// Four numbers, kept apart because they mean different things. A frame is
/// one whose CRC held between two delimiters; a drop is bytes between two
/// delimiters that were not a frame, which is what a CRC failure looks
/// like from here; an abandon is a part-frame nothing followed; an overrun
/// is an error returned by the read API. The pinned buffered driver does
/// not propagate hardware errors or software ring overflow through that API.
/// Passing F-087 needs every numbered frame and no framing failures; zero
/// read errors alone cannot establish either.
#[cfg(feature = "frames")]
mod frames {
    use embassy_stm32::usart::Error;
    use embassy_time::{Duration, Instant};
    use km43::{MAX_PAYLOAD, Received};
    use o89_link::{Arrivals, PER_CUT, stamped};

    /// The minimum interval between changed tallies.
    const EVERY: Duration = Duration::from_secs(1);

    pub struct Counts {
        frames: u32,
        dropped: u32,
        abandoned: u32,
        overruns: u32,
        others: u32,
        next: Instant,
        dirty: bool,
        /// The numbered frames that arrived: how many and the highest,
        /// which together say what a count alone cannot (a run that stops
        /// short with no gap never left the module, one with a gap lost
        /// frames on the wire); and whether they came in order and in
        /// which position of a pull, which is what proves a cut run
        /// delivered every third frame and nothing else (F-086).
        arrivals: Arrivals,
        /// How many times the link came up. More than one means it went
        /// down, and a run measured across that is a different run.
        ups: u32,
        /// The tally when the link came up, so the run can be read apart
        /// from what came before it. The ROM's boot text arrives at the
        /// wrong baud and is refused by the hundred (F-031); counting it
        /// against the wire would make a sound link look like a faulty
        /// one, and hide a real refusal among a thousand expected ones.
        at_link: Option<(u32, u32, u32, u32, u32)>,
    }

    impl Counts {
        pub fn new() -> Self {
            defmt::warn!(
                "frames: UART error counts are read errors only; the buffered driver does not expose hardware errors or ring overflow"
            );
            Self {
                frames: 0,
                dropped: 0,
                abandoned: 0,
                overruns: 0,
                others: 0,
                next: Instant::now(),
                dirty: false,
                arrivals: Arrivals::new(),
                ups: 0,
                at_link: None,
            }
        }

        /// The link came up: what follows is the run.
        ///
        /// Only the first sets the baseline. A link that comes up again
        /// mid-run is a link that went down, which is news in itself and
        /// is counted; re-baselining there would make the tally smaller
        /// than the run it is supposed to contain, and the two lines would
        /// stop being comparable.
        pub fn linked(&mut self) {
            self.dirty = true;
            self.ups = self.ups.saturating_add(1);
            if self.at_link.is_some() {
                defmt::warn!(
                    "frames: the link came up again mid-run; this is the {}th",
                    self.ups
                );
                return;
            }
            self.at_link = Some((
                self.frames,
                self.dropped,
                self.abandoned,
                self.overruns,
                self.others,
            ));
            self.next = Instant::now();
        }

        /// A frame whose CRC held, and the number it carries when it is
        /// one of the bench's own.
        pub fn frame(&mut self, frame: &[u8]) {
            self.dirty = true;
            self.frames = self.frames.saturating_add(1);
            // The bench's frames are the only ones that fill the payload,
            // and the link's own are far shorter, so a stamp is read only
            // from one of the run's.
            if frame.len() < MAX_PAYLOAD {
                return;
            }
            let Some(number) = stamped(frame) else {
                return;
            };
            self.arrivals.arrived(number);
        }

        pub fn refused(&mut self, received: Received<'_>) {
            match received {
                Received::Dropped(_) => {
                    self.dirty = true;
                    self.dropped = self.dropped.saturating_add(1);
                }
                Received::Abandoned => self.abandoned(),
                Received::Frame(_) | Received::Nothing => {}
            }
        }

        pub fn abandoned(&mut self) {
            self.dirty = true;
            self.abandoned = self.abandoned.saturating_add(1);
        }

        /// An overrun counted apart from every other line error: it is the
        /// one that says the flow control was not holding the peer off.
        pub fn error(&mut self, error: Error) {
            self.dirty = true;
            // Not our enum, and marked non-exhaustive by its crate, as
            // `note_rx_error` says above.
            match error {
                Error::Overrun => self.overruns = self.overruns.saturating_add(1),
                _ => self.others = self.others.saturating_add(1),
            }
        }

        /// Changed tallies at most once a second, even after the line goes
        /// quiet: the final frame and timeouts must not need another byte
        /// to be reported. An unchanged tally stays quiet.
        pub fn report(&mut self) {
            let now = Instant::now();
            if !self.dirty || now < self.next {
                return;
            }
            self.dirty = false;
            self.next = now.checked_add(EVERY).unwrap_or(now);
            if let Some((frames, dropped, abandoned, overruns, others)) = self.at_link {
                defmt::info!(
                    "frames since the link came up: {} read, {} refused, {} abandoned, {} overruns, {} other line errors",
                    self.frames.saturating_sub(frames),
                    self.dropped.saturating_sub(dropped),
                    self.abandoned.saturating_sub(abandoned),
                    self.overruns.saturating_sub(overruns),
                    self.others.saturating_sub(others)
                );
                if self.arrivals.highest > 0 {
                    let [first, second, third] = self.arrivals.by_position;
                    defmt::info!(
                        "frames of the run: {} arrived, highest numbered {}, {} missing, {} not increasing, by position in a pull of {}: {} {} {}, link up {} time(s)",
                        self.arrivals.count,
                        self.arrivals.highest,
                        self.arrivals.missing(),
                        self.arrivals.not_increasing,
                        PER_CUT,
                        first,
                        second,
                        third,
                        self.ups
                    );
                }
            } else {
                defmt::info!(
                    "frames before the link came up: {} read, {} refused, {} abandoned, {} overruns, {} other line errors",
                    self.frames,
                    self.dropped,
                    self.abandoned,
                    self.overruns,
                    self.others
                );
            }
        }
    }
}

/// Service recorder replies and the link's monotonic deadlines each turn.
async fn service_tick(
    link: &mut Link,
    tx: &mut BufferedUartTx<'_>,
    writer: &mut FrameWriter,
) -> Option<Ended> {
    if let Some((req_id, outcome)) = recorder::time_answer()
        && let Some(ended) = perform(link, tx, writer, &link.time_verdict(req_id, outcome)).await
    {
        return Some(ended);
    }
    let actions = link.tick(Uptime.now(), install_in_flight());
    perform(link, tx, writer, &actions).await
}

/// Encode and send one answer. True means CTS held the transmitter past its deadline.
async fn send_outgoing(
    link: &Link,
    tx: &mut BufferedUartTx<'_>,
    writer: &mut FrameWriter,
    outgoing: o89_core::Outgoing,
) -> bool {
    let mut frame = [0u8; MAX_FRAME];
    let len = match link.encode(outgoing, Uptime.now(), writer, &mut frame) {
        Ok(len) => len,
        Err(error) => {
            defmt::error!("link: {} did not encode: {}", outgoing, error);
            return false;
        }
    };
    let bytes = frame.get(..len).unwrap_or(&[]);
    match with_timeout(WRITE_DEADLINE, send(tx, bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => defmt::warn!("link: {} not sent: {}", outgoing, error),
        Err(_) => {
            defmt::warn!(
                "link: {} stalled after {} ms; the module holds CTS",
                outgoing,
                WRITE_DEADLINE.as_millis()
            );
            return true;
        }
    }
    false
}
