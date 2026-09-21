//! The link's wire on the comms processor's side, for the rest of the run.
//!
//! The rules are `o89-comms-core`'s, where the host tests them: `LinkUp`
//! until the controller answers one, a heartbeat every two seconds, the
//! link dropped six seconds after the controller last answered a request
//! of ours, and only the first answer to one of our own requests counted
//! (L-033, L-100, L-120). This file reads UART0 and the clock, hands both
//! in, and writes what comes back.
//!
//! Every await has a deadline: a read waits one tick, a write two hundred
//! milliseconds. The watchdog is fed once per turn of the loop, which is
//! the whole of this side's liveness.

use embassy_futures::yield_now;
use embassy_time::{Duration, Instant, with_timeout};
use esp_hal::Async;
use esp_hal::rtc_cntl::Rwdt;
use esp_hal::uart::{Uart, UartTx};
use km43::{FrameReader, FrameWriter, LinkEnvelope, MAX_FRAME, Received};
use o89_comms_core::{Frame, Identity, Link, Tick};

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
) {
    let (mut rx, mut tx) = uart.split();
    let me = Identity {
        fw: FW,
        hw: HW,
        boot_id,
    };
    let mut link = Link::new(now());
    let mut chunk = [0u8; 64];
    #[cfg(feature = "frames")]
    let mut frames = frames::Blast::new();
    // Bounded per turn: a read waits `TICK` at most, and the tick follows.
    loop {
        rwdt.feed();
        if let Ok(Ok(count)) = with_timeout(TICK, rx.read_async(&mut chunk)).await {
            for byte in chunk.get(..count).unwrap_or(&[]) {
                if let Received::Frame(frame) = reader.push(*byte)
                    && let Ok(envelope) = LinkEnvelope::decode(frame)
                    && let Some(answer) = link.received(envelope, now())
                {
                    #[cfg(feature = "frames")]
                    frames.start.observe(answer);
                    send(&link, &me, answer, &mut tx, &mut writer).await;
                }
            }
        }
        if let Some(frame) = link.tick(now()) {
            #[cfg(feature = "frames")]
            frames.start.observe(frame);
            send(&link, &me, frame, &mut tx, &mut writer).await;
        }
        // Between turns, not inside one: the link's own frames go first,
        // so the controller's heartbeats are answered through the run and
        // its ladder never cuts the rail (F-087).
        #[cfg(feature = "frames")]
        frames.batch(&link, &mut tx, &mut writer).await;
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
    link: &Link,
    me: &Identity<'_>,
    frame: Frame,
    tx: &mut UartTx<'static, Async>,
    writer: &mut FrameWriter,
) {
    let mut bytes = [0u8; MAX_FRAME];
    let Ok(len) = link.build(frame, me, now(), writer, &mut bytes) else {
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
    use super::{UartTx, WRITE_DEADLINE, write_all};
    use embassy_time::with_timeout;
    use km43::{FrameWriter, MAX_FRAME, MAX_PAYLOAD};
    use o89_comms_core::{FrameBenchStart, Link};
    use o89_link::{stamp, worst_case};

    /// How many the run sends.
    const TOTAL: u32 = 10_000;
    /// At most 800 ms of blocked writes per batch, below both heartbeat
    /// cadence and the eight-second watchdog, even under sustained CTS.
    const PER_TURN: u32 = 4;
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
            link: &Link,
            tx: &mut UartTx<'static, esp_hal::Async>,
            writer: &mut FrameWriter,
        ) {
            self.start.controller(link.controller_bench_mode());
            if !self.start.ready(link.is_linked()) || self.sent >= TOTAL || self.failed {
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
