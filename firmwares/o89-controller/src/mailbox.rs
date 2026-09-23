//! The bench tool's mailbox in RAM, served by the recorder, and the two
//! rings the bridge to the module runs on, served by the link task.
//!
//! The words are atomics because the host writes them over SWD while the
//! part runs, and the region is one the runtime never loads or zeroes, so
//! a reset leaves the last run's magic there. The boot clears it as its
//! first act and the recorder writes it back when it is ready to serve:
//! a host that attaches in between sees no mailbox, rather than a request
//! nobody answers until its deadline. The recorder polls the request
//! sequence; a request is served through the same seams the store and the
//! ring use, so a write from the bench meets the voltage detector's
//! refusal exactly as the firmware's own would. The layout and the address
//! are `o89_core::mailbox`'s, shared with the host.
//!
//! The bridge rings carry the ROM's download protocol between the host's
//! flashing tool and the module's UART while the link task holds the UART
//! for it (F-038): one ring each way, one writer and one reader each, the
//! arithmetic `o89_core::mailbox::Ring`'s on both sides.

use core::sync::atomic::Ordering;

use cortex_m::peripheral::SCB;
use embassy_time::{Duration, with_timeout};
use km43::DownloadReason;
use o89_core::mailbox::{
    DATA_BYTES, DownloadEntry, DropAnswer, MAGIC, Op, RING_BYTES, Ring, RingPage, Status, VERSION,
};
use o89_core::{Address, FRAM_BYTES, Fram as FramSeam, Refused, Ring as NorRing, RingError, Wants};
use portable_atomic::{AtomicU8, AtomicU32};

use crate::fram::Lease;
use crate::link::{self, Report, Request};
use crate::nor::{CAPACITY, Nor};

/// The mailbox, laid out as `o89_core::mailbox::offset` says.
#[repr(C)]
struct Mailbox {
    magic: AtomicU32,
    version: AtomicU32,
    request_seq: AtomicU32,
    response_seq: AtomicU32,
    op: AtomicU32,
    arg0: AtomicU32,
    arg1: AtomicU32,
    status: AtomicU32,
    length: AtomicU32,
    data: [AtomicU8; DATA_BYTES],
    to_module_write: AtomicU32,
    to_module_read: AtomicU32,
    to_module: [AtomicU8; RING_BYTES],
    from_module_write: AtomicU32,
    from_module_read: AtomicU32,
    from_module: [AtomicU8; RING_BYTES],
    bridge_lease: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<Mailbox>() == o89_core::mailbox::offset::END as usize);

#[expect(
    unsafe_code,
    reason = "`link_section` is an unsafe attribute on this edition; `.o89_mailbox` is the region memory.x keeps for the host, never loaded and never zeroed"
)]
#[unsafe(link_section = ".o89_mailbox")]
static MAILBOX: Mailbox = Mailbox {
    magic: AtomicU32::new(0),
    version: AtomicU32::new(0),
    request_seq: AtomicU32::new(0),
    response_seq: AtomicU32::new(0),
    op: AtomicU32::new(0),
    arg0: AtomicU32::new(0),
    arg1: AtomicU32::new(0),
    status: AtomicU32::new(0),
    length: AtomicU32::new(0),
    data: [const { AtomicU8::new(0) }; DATA_BYTES],
    to_module_write: AtomicU32::new(0),
    to_module_read: AtomicU32::new(0),
    to_module: [const { AtomicU8::new(0) }; RING_BYTES],
    from_module_write: AtomicU32::new(0),
    from_module_read: AtomicU32::new(0),
    from_module: [const { AtomicU8::new(0) }; RING_BYTES],
    bridge_lease: AtomicU32::new(0),
};

/// How long the recorder waits for the link task to answer a request that
/// puts the module into download mode: a module reset, the window, and
/// the three seconds of attempts L-192 allows.
const LINK_DEADLINE: Duration = Duration::from_secs(6);

/// No mailbox: the first thing the boot does, so that the magic a reset
/// left in RAM does not invite a request before anyone serves one.
pub fn clear() {
    MAILBOX.magic.store(0, Ordering::Release);
}

/// Write the magic and the version, and answer nothing outstanding: a
/// request the host left across a reset is stale.
pub fn init() {
    MAILBOX.request_seq.store(0, Ordering::Relaxed);
    MAILBOX.response_seq.store(0, Ordering::Relaxed);
    MAILBOX.length.store(0, Ordering::Relaxed);
    MAILBOX.status.store(Status::Ok.code(), Ordering::Relaxed);
    MAILBOX.version.store(VERSION, Ordering::Relaxed);
    MAILBOX.magic.store(MAGIC, Ordering::Release);
}

/// What the recorder holds for the mailbox to serve.
pub struct Parts<'a> {
    /// The FRAM, through the seam.
    pub fram: &'a mut Lease,
    /// The ring on the NOR, if it opened.
    pub ring: Option<&'a mut NorRing<Nor>>,
    /// The ring's scratch, for the head search after an erase.
    pub scratch: &'a mut [u8],
    /// The boot count, for a ping.
    pub boot: u32,
}

/// Serve one request if the host has landed one. Answers with the same
/// sequence, landed last.
pub async fn serve(parts: Parts<'_>) {
    let seq = MAILBOX.request_seq.load(Ordering::Acquire);
    if seq == MAILBOX.response_seq.load(Ordering::Relaxed) {
        return;
    }
    let op = MAILBOX.op.load(Ordering::Relaxed);
    let arg0 = MAILBOX.arg0.load(Ordering::Relaxed);
    let arg1 = MAILBOX.arg1.load(Ordering::Relaxed);
    let (status, length) = match Op::of(op) {
        Some(Op::Ping) => {
            put(&parts.boot.to_le_bytes());
            (Status::Ok, 4)
        }
        Some(Op::ReadFram) => read_fram(parts.fram, arg0, arg1).await,
        Some(Op::WriteFram) => write_fram(parts.fram, arg0, arg1).await,
        Some(Op::ReadNor) => match parts.ring {
            Some(ring) => read_nor(ring, arg0, arg1).await,
            None => (Status::NoNor, 0),
        },
        Some(Op::ReadRing) => match parts.ring {
            Some(ring) => read_ring(ring, arg0, arg1, parts.scratch).await,
            None => (Status::NoNor, 0),
        },
        Some(Op::EraseNorBlock) => match parts.ring {
            Some(ring) => erase_nor(ring, arg0).await,
            None => (Status::NoNor, 0),
        },
        Some(Op::DropOldest) => match parts.ring {
            Some(ring) => drop_oldest(ring, parts.scratch).await,
            None => (Status::NoNor, 0),
        },
        Some(Op::Reboot) => {
            defmt::warn!("mailbox: the host asked for a reset");
            answer(seq, Status::Ok, 0);
            SCB::sys_reset()
        }
        Some(Op::Download) => {
            let reason = u8::try_from(arg0)
                .ok()
                .and_then(|code| DownloadReason::try_from(code).ok());
            let status = match (reason, DownloadEntry::of(arg1)) {
                (Some(reason), Some(entry)) => {
                    defmt::warn!(
                        "mailbox: the host asks for the module's download mode, by {}",
                        entry
                    );
                    ask_link(Request::Download { reason, entry }).await
                }
                (None, _) | (_, None) => Status::OutOfRange,
            };
            (status, 0)
        }
        Some(Op::Normal) => {
            defmt::info!("mailbox: the host gives the module back");
            (ask_link(Request::Normal).await, 0)
        }
        None => (Status::UnknownOp, 0),
    };
    answer(seq, status, length);
}

/// Hand a request to the link task and wait for what it did.
async fn ask_link(request: Request) -> Status {
    let seq = link::request(request);
    match with_timeout(LINK_DEADLINE, link::report(seq)).await {
        Ok(Report::Bridging | Report::Normal) => Status::Ok,
        Ok(Report::NoAnswer) => Status::NoModuleAnswer,
        Ok(Report::NoStore) => Status::NoStore,
        Ok(Report::BridgeRefused) => Status::BridgeRefused,
        Ok(Report::Refused) => Status::ModuleRefused,
        Ok(Report::Busy) | Err(_) => Status::LinkBusy,
    }
}

fn answer(seq: u32, status: Status, length: u32) {
    MAILBOX.length.store(length, Ordering::Relaxed);
    MAILBOX.status.store(status.code(), Ordering::Relaxed);
    MAILBOX.response_seq.store(seq, Ordering::Release);
}

/// Copy `bytes` into the data, as many as fit.
fn put(bytes: &[u8]) {
    for (slot, byte) in MAILBOX.data.iter().zip(bytes) {
        slot.store(*byte, Ordering::Relaxed);
    }
}

/// Copy `bytes` into the data from `at`, as many as fit.
fn put_at(at: usize, bytes: &[u8]) {
    for (slot, byte) in MAILBOX.data.iter().skip(at).zip(bytes) {
        slot.store(*byte, Ordering::Relaxed);
    }
}

/// Copy the first `len` bytes of the data out.
fn take(into: &mut [u8]) {
    for (byte, slot) in into.iter_mut().zip(&MAILBOX.data) {
        *byte = slot.load(Ordering::Relaxed);
    }
}

/// Both rings emptied, before the host is told the bridge is up.
pub fn bridge_reset() {
    MAILBOX.to_module_read.store(0, Ordering::Relaxed);
    MAILBOX.to_module_write.store(0, Ordering::Relaxed);
    MAILBOX.from_module_read.store(0, Ordering::Relaxed);
    MAILBOX.from_module_write.store(0, Ordering::Release);
}

/// Bytes the host left for the module, into `into`; how many.
/// The host's lease on the bridge, as it last wrote it.
pub fn bridge_lease() -> u32 {
    MAILBOX.bridge_lease.load(Ordering::Acquire)
}

pub fn bridge_pull(into: &mut [u8]) -> usize {
    let write = MAILBOX.to_module_write.load(Ordering::Acquire);
    let read = MAILBOX.to_module_read.load(Ordering::Relaxed);
    let count = Ring::available(write, read).min(into.len());
    let mut index = read;
    for byte in into.iter_mut().take(count) {
        *byte = MAILBOX
            .to_module
            .get(Ring::index(index))
            .map_or(0, |slot| slot.load(Ordering::Relaxed));
        index = Ring::advanced(index, 1);
    }
    MAILBOX.to_module_read.store(index, Ordering::Release);
    count
}

/// Bytes from the module for the host, as many as the ring has room for;
/// how many were taken. The rest is the caller's to offer again.
pub fn bridge_push(bytes: &[u8]) -> usize {
    let write = MAILBOX.from_module_write.load(Ordering::Relaxed);
    let read = MAILBOX.from_module_read.load(Ordering::Acquire);
    let count = Ring::room(write, read).min(bytes.len());
    let mut index = write;
    for byte in bytes.iter().take(count) {
        if let Some(slot) = MAILBOX.from_module.get(Ring::index(index)) {
            slot.store(*byte, Ordering::Relaxed);
        }
        index = Ring::advanced(index, 1);
    }
    MAILBOX.from_module_write.store(index, Ordering::Release);
    count
}

fn span(at: u32, len: u32, part: usize) -> Option<(usize, usize)> {
    let at = usize::try_from(at).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = at.checked_add(len)?;
    (len <= DATA_BYTES && end <= part).then_some((at, len))
}

async fn read_fram(fram: &mut Lease, at: u32, len: u32) -> (Status, u32) {
    let Some((at, len)) = span(at, len, FRAM_BYTES) else {
        return (Status::OutOfRange, 0);
    };
    let Ok(address) = u16::try_from(at) else {
        return (Status::OutOfRange, 0);
    };
    let mut buffer = [0u8; DATA_BYTES];
    let Some(room) = buffer.get_mut(..len) else {
        return (Status::OutOfRange, 0);
    };
    match fram.read(Address(address), room).await {
        Ok(()) => {
            put(room);
            (Status::Ok, u32::try_from(len).unwrap_or(0))
        }
        Err(_) => (Status::Bus, 0),
    }
}

async fn write_fram(fram: &mut Lease, at: u32, len: u32) -> (Status, u32) {
    let Some((at, len)) = span(at, len, FRAM_BYTES) else {
        return (Status::OutOfRange, 0);
    };
    let Ok(address) = u16::try_from(at) else {
        return (Status::OutOfRange, 0);
    };
    let mut buffer = [0u8; DATA_BYTES];
    let Some(bytes) = buffer.get_mut(..len) else {
        return (Status::OutOfRange, 0);
    };
    take(bytes);
    match fram.write(Address(address), bytes).await {
        Ok(()) => (Status::Ok, 0),
        Err(Refused::SupplyFalling) => (Status::SupplyFalling, 0),
        Err(Refused::AtTheCeiling | Refused::Bus(_)) => (Status::Bus, 0),
    }
}

/// The ring's records from the sequence `hi:lo`, walked by the ring's own
/// reader and laid out as a `RingPage`. A record goes in only while one
/// more at its largest still fits, so the ring's answer of what to ask
/// next never passes a record the page left out.
async fn read_ring(ring: &mut NorRing<Nor>, lo: u32, hi: u32, scratch: &mut [u8]) -> (Status, u32) {
    let from = RingPage::from_args(lo, hi);
    let oldest = ring.head().oldest;
    let mut at = RingPage::HEADER;
    let walked = ring
        .read_from(from, scratch, |found| {
            // The ring holds nothing longer than a record carries, so the
            // head always builds; a page cut here says so by its length.
            let Some(head) = RingPage::entry_head(found.seq, found.class, found.payload.len())
            else {
                return Wants::Enough;
            };
            put_at(at, &head);
            put_at(at.saturating_add(RingPage::ENTRY_HEAD), found.payload);
            at = at
                .saturating_add(RingPage::ENTRY_HEAD)
                .saturating_add(found.payload.len());
            if RingPage::room_after(at) {
                Wants::More
            } else {
                Wants::Enough
            }
        })
        .await;
    match walked {
        Ok(next) => {
            let page = RingPage {
                ring_next: ring.next_seq(),
                oldest,
                next,
            };
            put_at(0, &page.header());
            (Status::Ok, u32::try_from(at).unwrap_or(0))
        }
        Err(error) => {
            defmt::error!("mailbox: the ring could not be read: {}", error);
            (Status::Bus, 0)
        }
    }
}

async fn read_nor(ring: &mut NorRing<Nor>, at: u32, len: u32) -> (Status, u32) {
    let Some((_, len)) = span(at, len, CAPACITY) else {
        return (Status::OutOfRange, 0);
    };
    let mut buffer = [0u8; DATA_BYTES];
    let Some(room) = buffer.get_mut(..len) else {
        return (Status::OutOfRange, 0);
    };
    match ring.read_raw(at, room).await {
        Ok(()) => {
            put(room);
            (Status::Ok, u32::try_from(len).unwrap_or(0))
        }
        Err(_) => (Status::Bus, 0),
    }
}

/// A block outside the ring, erased; one of the ring's is refused (#78).
async fn erase_nor(ring: &mut NorRing<Nor>, block: u32) -> (Status, u32) {
    match ring.erase_block(block).await {
        Ok(()) => (Status::Ok, 0),
        Err(RingError::OutOfRange) => (Status::OutOfRange, 0),
        Err(RingError::InsideTheRing(_)) => (Status::InsideTheRing, 0),
        Err(error) => {
            defmt::error!("mailbox: the erase failed: {}", error);
            (Status::Bus, 0)
        }
    }
}

/// The ring's oldest block, erased, and what it left.
async fn drop_oldest(ring: &mut NorRing<Nor>, scratch: &mut [u8]) -> (Status, u32) {
    match ring.drop_oldest(scratch).await {
        Ok(dropped) => {
            defmt::warn!(
                "mailbox: the host dropped the ring's oldest block: {}",
                dropped
            );
            match DropAnswer::encode(dropped) {
                Some(bytes) => {
                    put(&bytes);
                    (Status::Ok, u32::try_from(bytes.len()).unwrap_or(0))
                }
                None => (Status::Ok, 0),
            }
        }
        Err(error) => {
            defmt::error!("mailbox: the drop failed: {}", error);
            (Status::Bus, 0)
        }
    }
}
