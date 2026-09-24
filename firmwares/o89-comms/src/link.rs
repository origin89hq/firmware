//! The link's wire on the comms processor's side, for the rest of the run.
//!
//! The rules are `o89-comms-core`'s, where the host tests them: `LinkUp`
//! until the controller answers one, a heartbeat every two seconds, the
//! link dropped six seconds after the controller last answered a request
//! of ours, and only the first answer to one of our own requests counted
//! (L-033, L-100, L-120). This file reads UART0 and the clock, hands both
//! in, and writes what comes back.
//!
//! The link and its table are shared with the client transports
//! (`clients.rs`) through [`LINK`], an async mutex no task holds across an
//! await, so a lock is free whenever a task runs. A frame from the
//! controller goes to the link, to the client its session names, or
//! nowhere (`o89_comms_core::route`). A client's frame, already stamped,
//! arrives on `clients::UPSTREAM` and goes out as it stands, one a turn
//! after the UART has been read; it never reaches the link (L-194).
//!
//! Every await has a deadline: a read waits one tick, a write two hundred
//! milliseconds. The watchdog is fed only when this loop and the radio,
//! network runner and NTP tasks have all made progress.

use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, with_timeout};
use esp_hal::Async;
use esp_hal::rtc_cntl::Rwdt;
use esp_hal::uart::{Uart, UartTx};
use km43::{FrameReader, FrameWriter, LinkEnvelope, MAX_FRAME, Received};
use o89_comms_core::{Frame, Identity, Link, Route, Tick};

/// The link, with its connection table, shared with the client transports.
/// Never held across an await.
pub static LINK: Mutex<CriticalSectionRawMutex, Link> = Mutex::new(Link::new(Tick::ZERO));

/// This firmware, as key 4 of every `LinkUp`: its version with the commit
/// it was built from, which the build script reads from git (L-034). The
/// controller reports it as `fw_comms` (L-031).
const FW: &str = env!("O89_LINK_VERSION");
/// The board the module sits on, as key 6: its name and revision as
/// origin89hq/hardware writes them (L-034). Revision A is the only board
/// this firmware has run on.
#[cfg(not(feature = "devkit"))]
const HW: &str = "controller-a rev A";
/// The board the module sits on, as key 6: an Espressif devkit on its own
/// USB serial, which no hardware repository names (L-034).
#[cfg(feature = "devkit")]
const HW: &str = "esp32-c6 devkit";
const _: () = {
    assert!(FW.len() <= km43::MAX_LINK_TEXT);
    assert!(HW.len() <= km43::MAX_LINK_TEXT);
};

/// How long a read waits before the tick is served.
const TICK: Duration = Duration::from_millis(100);
/// How long a frame may take to leave.
const WRITE_DEADLINE: Duration = Duration::from_millis(200);

/// Run the link on `uart`, forever.
#[embassy_executor::task]
pub async fn run(
    uart: Uart<'static, Async>,
    mut reader: FrameReader,
    mut writer: FrameWriter,
    mut rwdt: Rwdt,
    boot_id: u32,
    mut store: crate::credentials::Store,
    credential: Option<o89_comms_core::Credential>,
) {
    let (mut rx, mut tx) = uart.split();
    let me = Identity {
        fw: FW,
        hw: HW,
        boot_id,
    };
    {
        let mut link = LINK.lock().await;
        *link = Link::new(now());
        link.restore_network(credential);
    }
    let mut chunk = [0u8; 64];
    #[cfg(feature = "frames")]
    let mut frames = frames::Blast::new();
    // Bounded per turn: a read waits `TICK` at most, a client's frame one
    // write deadline, and the tick follows.
    loop {
        if crate::radio::healthy() {
            rwdt.feed();
        }
        let turn = select(
            with_timeout(TICK, rx.read_async(&mut chunk)),
            crate::clients::UPSTREAM.receive(),
        )
        .await;
        match turn {
            Either::First(Ok(Ok(count))) => {
                for byte in chunk.get(..count).unwrap_or(&[]) {
                    let Received::Frame(frame) = reader.push(*byte) else {
                        continue;
                    };
                    let (answer, credential) = {
                        let mut link = LINK.lock().await;
                        let answer = match link.route(frame) {
                            Route::Link => LinkEnvelope::decode(frame).ok().and_then(|envelope| {
                                link.received_with_store(envelope, now(), |record| {
                                    o89_comms_core::store_credential(&mut store, record).is_ok()
                                })
                            }),
                            Route::Client(conn) => {
                                crate::clients::deliver(&mut link, conn, frame);
                                None
                            }
                            Route::Nowhere => None,
                        };
                        (answer, link.credential().copied())
                    };
                    if let Some(answer) = answer {
                        crate::radio::configure(credential);
                        #[cfg(feature = "frames")]
                        frames.start.observe(answer);
                        send(&me, answer, &mut tx, &mut writer).await;
                    }
                }
            }
            Either::First(Ok(Err(_)) | Err(_)) => {}
            Either::Second(stamped) => {
                send_client(&stamped, &mut tx, &mut writer).await;
            }
        }
        let frame = LINK.lock().await.tick(now());
        if let Some(frame) = frame {
            #[cfg(feature = "frames")]
            frames.start.observe(frame);
            send(&me, frame, &mut tx, &mut writer).await;
        }
        if let Ok(sample) = crate::radio::SAMPLES.try_receive()
            && sample.at.elapsed() < Duration::from_secs(1)
        {
            let offer = km43::ClockOffer {
                unix_ms: sample.unix_ms,
                source: 1,
                accuracy_ms: sample.accuracy_ms,
                server: crate::radio::SERVER,
            };
            let mut bytes = [0; MAX_FRAME];
            let offered = LINK
                .lock()
                .await
                .time_offer(offer, now(), &mut writer, &mut bytes);
            if let Ok(Some(len)) = offered {
                crate::radio::time_offered(now());
                let _sent = with_timeout(
                    WRITE_DEADLINE,
                    write_all(&mut tx, bytes.get(..len).unwrap_or(&[])),
                )
                .await;
            }
        }
        // Between turns, not inside one: the link's own frames go first,
        // so the controller's heartbeats are answered through the run and
        // its ladder never cuts the rail (F-087).
        #[cfg(feature = "frames")]
        frames.batch(&mut tx, &mut writer).await;
        // A read that is ready at once does not yield: a controller that
        // floods the UART would otherwise hold the executor every turn.
        yield_now().await;
    }
}

/// The part's clock as the link reads it.
fn now() -> Tick {
    Tick::from_millis(Instant::now().as_millis())
}

/// Build `frame` and put it on the wire within the write deadline; a frame
/// that does not build or does not leave is one the controller retries or
/// the ladder counts.
async fn send(
    me: &Identity<'_>,
    frame: Frame,
    tx: &mut UartTx<'static, Async>,
    writer: &mut FrameWriter,
) {
    let mut bytes = [0u8; MAX_FRAME];
    let built = LINK
        .lock()
        .await
        .build(frame, me, now(), writer, &mut bytes);
    let Ok(len) = built else {
        return;
    };
    // A frame that does not leave is one the controller retries or the
    // ladder counts, so nothing here acts on the answer.
    let _left = with_timeout(
        WRITE_DEADLINE,
        write_all(tx, bytes.get(..len).unwrap_or(&[])),
    )
    .await;
}

/// The whole frame out of the pin, in as many writes as the FIFO takes.
/// Whether all of it left: a caller that counts what it put on the wire
/// must not count a frame the pin refused.
async fn write_all(tx: &mut UartTx<'static, Async>, mut bytes: &[u8]) -> bool {
    // Bounded by the bytes: every turn writes at least one or stops.
    while !bytes.is_empty() {
        match tx.write_async(bytes).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => bytes = bytes.get(n..).unwrap_or(&[]),
        }
    }
    tx.flush_async().await.is_ok()
}

/// The frames bench: worst-case frames at the link's rate, counted at the
/// controller (F-087).
#[cfg(feature = "frames")]
mod frames {
    use super::{LINK, UartTx, WRITE_DEADLINE, write_all};
    use embassy_time::with_timeout;
    use km43::{FrameWriter, MAX_FRAME, MAX_PAYLOAD};
    use o89_comms_core::FrameBenchStart;
    use o89_link::{CUT_RUN, PER_CUT, cut_point, stamp, worst_case};

    /// How many the run sends: ten thousand worst-case frames (F-087), or
    /// the cut run's three a pull (F-086).
    const TOTAL: u32 = if cfg!(feature = "cuts") {
        CUT_RUN
    } else {
        10_000
    };
    /// At most 800 ms of blocked writes per batch, below both heartbeat
    /// cadence and the eight-second watchdog, even under sustained CTS.
    /// The cut run sends a pull a batch: a fragment that waits a turn for
    /// the frame it runs into is abandoned by the reader across the gap,
    /// or merged into a heartbeat that goes out first, and either is the
    /// other shape of the fault, not the one this run measures (F-086).
    const PER_TURN: u32 = if cfg!(feature = "cuts") { PER_CUT } else { 4 };
    const _: () = assert!(CUT_RUN.is_multiple_of(PER_CUT));
    const _: () = assert!(PER_TURN as u64 * WRITE_DEADLINE.as_millis() < 1000);

    /// The start gate and how many numbered frames have left.
    pub struct Blast {
        sent: u32,
        failed: bool,
        pub start: FrameBenchStart,
    }

    impl Blast {
        pub const fn new() -> Self {
            Self {
                sent: 0,
                failed: false,
                start: FrameBenchStart::new(cfg!(feature = "no-flow")),
            }
        }

        /// One batch, once the controller has sent a valid heartbeat and
        /// until the run is done. Its heartbeat proves its own handshake
        /// completed, and its firmware identity must match this bench mode.
        ///
        /// The payload is the worst case for the wire and is not an
        /// envelope, so the controller reads each as a frame whose CRC
        /// held and refuses it above: that is the point, since what is
        /// being measured is the wire and not the protocol.
        pub async fn batch(
            &mut self,
            tx: &mut UartTx<'static, esp_hal::Async>,
            writer: &mut FrameWriter,
        ) {
            let (mode, linked) = {
                let link = LINK.lock().await;
                (link.controller_bench_mode(), link.is_linked())
            };
            self.start.controller(mode);
            if !self.start.ready(linked) || self.sent >= TOTAL || self.failed {
                return;
            }
            let mut payload = [0u8; MAX_PAYLOAD];
            let mut wire = [0u8; MAX_FRAME];
            // Bounded: `PER_TURN` frames, or the rest of the run.
            for _ in 0..PER_TURN.min(TOTAL.saturating_sub(self.sent)) {
                let number = self.sent.wrapping_add(1);
                worst_case(&mut payload, number);
                // Its own number in it, so the controller reports which
                // frames arrived rather than how many, and a run short of
                // its total says whether the wire lost them or the pin
                // never took them.
                stamp(&mut payload, number);
                let Ok(len) = writer.write(&payload, &mut wire) else {
                    return;
                };
                // The cut bench pulls the pair here: the first frame of a
                // pull leaves the pin short of its delimiter, and the
                // controller's reader has to find its footing at the next
                // one (F-086).
                let len = if cfg!(feature = "cuts") {
                    cut_point(number, len).unwrap_or(len)
                } else {
                    len
                };
                // Counted only once it is on the wire. A frame the pin
                // refused is one the controller never sees, and counting
                // it would make the run look longer than it was and the
                // wire look worse than it is.
                let left = with_timeout(
                    WRITE_DEADLINE,
                    write_all(tx, wire.get(..len).unwrap_or(&[])),
                )
                .await;
                if !matches!(left, Ok(true)) {
                    // A timed-out flush may still leave bytes in the FIFO.
                    // End this run rather than retrying a possibly sent number.
                    self.failed = true;
                    return;
                }
                self.sent = self.sent.saturating_add(1);
            }
        }
    }
}

/// A canceled connection cannot leave a queued envelope for the next link generation.
async fn send_client(
    stamped: &crate::clients::Upstream,
    tx: &mut UartTx<'static, Async>,
    writer: &mut FrameWriter,
) {
    if LINK.lock().await.status(stamped.conn) != Some(o89_comms_core::Status::Open) {
        return;
    }
    let mut bytes = [0u8; MAX_FRAME];
    if let Ok(len) = writer.write(stamped.bytes(), &mut bytes) {
        let _left = with_timeout(
            WRITE_DEADLINE,
            write_all(tx, bytes.get(..len).unwrap_or(&[])),
        )
        .await;
    }
}
