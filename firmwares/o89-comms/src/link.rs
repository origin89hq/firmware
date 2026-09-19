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
    // Bounded per turn: a read waits `TICK` at most, and the tick follows.
    loop {
        rwdt.feed();
        if let Ok(Ok(count)) = with_timeout(TICK, rx.read_async(&mut chunk)).await {
            for byte in chunk.get(..count).unwrap_or(&[]) {
                if let Received::Frame(frame) = reader.push(*byte)
                    && let Ok(envelope) = LinkEnvelope::decode(frame)
                    && let Some(answer) = link.received(envelope, now())
                {
                    send(&link, &me, answer, &mut tx, &mut writer).await;
                }
            }
        }
        if let Some(frame) = link.tick(now()) {
            send(&link, &me, frame, &mut tx, &mut writer).await;
        }
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
    let _ = with_timeout(
        WRITE_DEADLINE,
        write_all(tx, bytes.get(..len).unwrap_or(&[])),
    )
    .await;
}

/// The whole frame out of the pin, in as many writes as the FIFO takes.
async fn write_all(tx: &mut UartTx<'static, Async>, mut bytes: &[u8]) {
    // Bounded by the bytes: every turn writes at least one or stops.
    while !bytes.is_empty() {
        match tx.write_async(bytes).await {
            Ok(0) | Err(_) => return,
            Ok(n) => bytes = bytes.get(n..).unwrap_or(&[]),
        }
    }
    let _ = tx.flush_async().await;
}
