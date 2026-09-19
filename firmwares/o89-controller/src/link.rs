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
//! it taking; the count of overruns is what says otherwise.

use embassy_futures::yield_now;
use embassy_stm32::gpio::{Flex, Pull};
use embassy_stm32::usart::{BufferedUart, BufferedUartTx, Config, Error};
use embassy_stm32::{Peri, bind_interrupts, usart};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{Read, Write};
use km43::{FrameReader, FrameWriter, LinkEnvelope, MAX_FRAME, Received};
use o89_core::{Action, Actions, Clock, Identity, Link, Note, Recovery, Task};
use static_cell::StaticCell;

use crate::board::{EspCts, EspRts, EspRx, EspTx, EspUsart};
use crate::rail::{self, RailWord};
use crate::recorder;
use crate::supervisor::{Uptime, check_in};

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
}

/// The link task. No identity is a boot without a written count (F-039):
/// the link never comes up, though the module is powered as on every boot
/// (F-005), and this task keeps its place on the roll for the life of the
/// part and nothing more.
#[embassy_executor::task]
pub async fn run(mut pins: Pins, identity: Option<Identity>) {
    let Some(identity) = identity else {
        loop {
            Timer::after(TICK).await;
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
    let mut resume = false;
    check_in(Task::Link);
    loop {
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
                Ok(RailWord::Recovered(recovery)) => {
                    let actions = link.rail(recovery, Uptime.now());
                    perform_quiet(&actions);
                    match recovery {
                        Recovery::Cycling { .. } => None,
                        Recovery::LeftOnAndRaised | Recovery::Busy => {
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
async fn episode(
    link: &mut Link,
    pins: &mut Pins,
    rings: &mut Rings,
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    first: Actions,
) -> Ended {
    // A new UART starts a new run: the tail of a frame cut off by the last
    // episode's end, by a cut or by a stall, would merge into this one's
    // first frame and count its noise against the wrong boot (F-031).
    reader.discard();
    let mut config = Config::default();
    config.baudrate = BAUD;
    let uart = match BufferedUart::new_with_rtscts(
        pins.usart.reborrow(),
        pins.rx.reborrow(),
        pins.tx.reborrow(),
        pins.rts.reborrow(),
        pins.cts.reborrow(),
        Irqs,
        &mut rings.tx[..],
        &mut rings.rx[..],
        config,
    ) {
        Ok(uart) => uart,
        Err(error) => {
            defmt::error!("link: USART1 refused its configuration: {}", error);
            return Ended::Refused;
        }
    };
    let (mut tx, mut rx) = uart.split();
    if let Some(ended) = perform(link, &mut tx, writer, &first).await {
        return ended;
    }
    let mut chunk = [0u8; 64];
    let mut last_byte = Instant::now();
    // Bounded by the cut the state machine asks for, and every turn by the
    // tick: the read waits `TICK` at most.
    loop {
        // Every call below reads the clock itself: a read can wait a whole
        // tick, and a frame stamped before the wait is heard a tick early.
        match with_timeout(TICK, rx.read(&mut chunk)).await {
            Ok(Ok(count)) => {
                last_byte = Instant::now();
                for byte in chunk.get(..count).unwrap_or(&[]) {
                    let ended = match reader.push(*byte) {
                        Received::Frame(frame) => {
                            if let Ok(envelope) = LinkEnvelope::decode(frame) {
                                let actions = link.received(envelope, Uptime.now());
                                perform(link, &mut tx, writer, &actions).await
                            } else {
                                link.noise();
                                None
                            }
                        }
                        Received::Dropped(_) | Received::Abandoned => {
                            link.noise();
                            None
                        }
                        Received::Nothing => None,
                    };
                    if let Some(ended) = ended {
                        return ended;
                    }
                }
            }
            Ok(Err(error)) => {
                // An overrun or a line error: the bytes it lost are noise.
                note_rx_error(error);
                link.noise();
            }
            Err(_) => {
                // The incomplete-frame timeout is the reader's, fed with
                // how long the line has been quiet.
                let quiet = u32::try_from(last_byte.elapsed().as_millis()).unwrap_or(u32::MAX);
                if let Received::Abandoned = reader.tick(None, quiet) {
                    link.noise();
                }
            }
        }
        while let Ok(word) = rail::words().try_receive() {
            match word {
                RailWord::Settled => {
                    // Cannot happen while the UART is up: the rail only
                    // settles after a cut this task asked for.
                    defmt::warn!("link: the rail settled while the link was up");
                }
                RailWord::Recovered(recovery) => {
                    let actions = link.rail(recovery, Uptime.now());
                    if let Some(ended) = perform(link, &mut tx, writer, &actions).await {
                        return ended;
                    }
                }
            }
        }
        let actions = link.tick(Uptime.now(), install_in_flight());
        if let Some(ended) = perform(link, &mut tx, writer, &actions).await {
            return ended;
        }
        check_in(Task::Link);
        // A read that is ready at once does not yield, and a module that
        // keeps the ring full would hold the executor through every turn:
        // the control, rail and recorder tasks run between two turns.
        yield_now().await;
    }
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
                let mut frame = [0u8; MAX_FRAME];
                let len = match link.encode(*outgoing, Uptime.now(), writer, &mut frame) {
                    Ok(len) => len,
                    Err(error) => {
                        defmt::error!("link: {} did not encode: {}", outgoing, error);
                        continue;
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
                        stalled = true;
                    }
                }
            }
            Action::CutRail => defmt::warn!("link: asking the rail for a cut"),
            Action::DropConnections(why) => {
                // No connection rows before M4; the drop is the log line.
                defmt::info!("link: every connection dropped: {}", why);
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
                defmt::info!("link: every connection dropped: {}", why);
            }
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
        Note::RomText { .. } | Note::UnexpectedAck(_) => defmt::info!("link: {}", note),
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
