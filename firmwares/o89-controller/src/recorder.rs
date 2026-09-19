//! The one task that owns the FRAM and the NOR.
//!
//! The store was read in `main`, before any output moved, because the run
//! reason has to be known before the contact is (F-022, F-016); this task
//! takes it from there. It identifies the NOR, opens the ring, writes the
//! boot record, and from then on holds both parts for whoever asks: the
//! requests arrive with the milestones that make them (M4's counters, M5's
//! configuration, the event queue). A board whose NOR does not answer
//! still has its store; the ring is simply absent and says so.
//!
//! cites: F-023

use embassy_time::{Duration, Ticker};
use km43::{Event, EventKind, LogSeq};
use o89_core::{Class, Ring, SCRATCH, Store, Task};

use crate::nor::{JEDEC, Nor, SECTOR};
use crate::supervisor::check_in;

/// The ring's span: 14.5 MiB of the 16, in sectors. The rest is for the
/// aggregates and, later, the last authorised comms image.
pub const RING_BLOCKS: u32 = 3712;
const _: () = assert!((RING_BLOCKS as usize) * SECTOR <= 16 * 1024 * 1024);

/// How often the task checks in; its window on the roll is thirty seconds.
const PERIOD: Duration = Duration::from_secs(10);

/// The recorder task.
#[embassy_executor::task]
pub async fn run(store: Option<Store>, mut nor: Nor) {
    let mut scratch = [0u8; SCRATCH];
    defmt::info!("recorder: identifying the NOR");
    let jedec = nor.jedec().await;
    defmt::info!("recorder: identification answered {}", jedec);
    let ring = match jedec {
        Ok(JEDEC) => {
            defmt::info!("recorder: opening the ring");
            let opened = Ring::open(nor, 0, RING_BLOCKS, &mut scratch).await;
            match opened {
                Ok(ring) => {
                    defmt::info!(
                        "ring: open at block {} offset {}, next seq {}, oldest {}, damage {}",
                        ring.head().block,
                        ring.head().at,
                        ring.head().next_seq,
                        ring.head().oldest,
                        ring.damage()
                    );
                    Some(ring)
                }
                Err(error) => {
                    defmt::error!("ring: not opened: {}", error);
                    None
                }
            }
        }
        Ok(other) => {
            defmt::error!(
                "nor: JEDEC id {=[u8]:#x} is not the W25Q128JV's {=[u8]:#x}; no ring",
                other,
                JEDEC
            );
            None
        }
        Err(error) => {
            defmt::error!("nor: no answer to the identification: {}; no ring", error);
            None
        }
    };
    let mut ring = ring;
    if let Some(ring) = ring.as_mut() {
        defmt::info!("recorder: writing the boot record");
        boot_record(ring, &mut scratch).await;
    }
    let boot = store
        .as_ref()
        .and_then(|store| store.boots.present().map(|count| count.get()));
    let mut ticker = Ticker::every(PERIOD);
    check_in(Task::Recorder);
    loop {
        ticker.next().await;
        defmt::debug!("recorder: boot {} alive", boot);
        check_in(Task::Recorder);
    }
}

/// The class A boot record, with the body the schema will give it once
/// origin89hq/km43#32 settles what a boot record carries: an empty map
/// until then, which is a record that says a boot happened at this
/// sequence and nothing it should not.
async fn boot_record(ring: &mut Ring<Nor>, scratch: &mut [u8]) {
    let mut payload = [0u8; 32];
    let Ok(event) = Event::new(LogSeq(ring.next_seq()), None, EventKind::BOOT, &[0xA0]) else {
        defmt::error!("boot record: the event did not build");
        return;
    };
    let Ok(len) = event.encode(&mut payload) else {
        defmt::error!("boot record: the event did not encode");
        return;
    };
    match ring
        .append(Class::A, payload.get(..len).unwrap_or(&[]), scratch)
        .await
    {
        Ok(seq) => defmt::info!("boot record: seq {}", seq),
        Err(error) => defmt::error!("boot record: not appended: {}", error),
    }
}
