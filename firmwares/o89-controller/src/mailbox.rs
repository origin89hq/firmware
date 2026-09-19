//! The bench tool's mailbox in RAM, served by the recorder.
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

use core::sync::atomic::Ordering;

use cortex_m::peripheral::SCB;
use o89_core::mailbox::{DATA_BYTES, MAGIC, Op, Status, VERSION};
use o89_core::{Address, FRAM_BYTES, Fram as FramSeam, Refused, Ring};
use portable_atomic::{AtomicU8, AtomicU32};

use crate::fram::Fram;
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
}

const _: () = assert!(core::mem::size_of::<Mailbox>() == 36 + DATA_BYTES);

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
};

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
    pub fram: &'a mut Fram,
    /// The ring on the NOR, if it opened.
    pub ring: Option<&'a mut Ring<Nor>>,
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
        Some(Op::EraseNorBlock) => match parts.ring {
            Some(ring) => erase_nor(ring, arg0, parts.scratch).await,
            None => (Status::NoNor, 0),
        },
        Some(Op::Reboot) => {
            defmt::warn!("mailbox: the host asked for a reset");
            answer(seq, Status::Ok, 0);
            SCB::sys_reset()
        }
        None => (Status::UnknownOp, 0),
    };
    answer(seq, status, length);
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

/// Copy the first `len` bytes of the data out.
fn take(into: &mut [u8]) {
    for (byte, slot) in into.iter_mut().zip(&MAILBOX.data) {
        *byte = slot.load(Ordering::Relaxed);
    }
}

fn span(at: u32, len: u32, part: usize) -> Option<(usize, usize)> {
    let at = usize::try_from(at).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = at.checked_add(len)?;
    (len <= DATA_BYTES && end <= part).then_some((at, len))
}

async fn read_fram(fram: &mut Fram, at: u32, len: u32) -> (Status, u32) {
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

async fn write_fram(fram: &mut Fram, at: u32, len: u32) -> (Status, u32) {
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

async fn read_nor(ring: &mut Ring<Nor>, at: u32, len: u32) -> (Status, u32) {
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

async fn erase_nor(ring: &mut Ring<Nor>, block: u32, scratch: &mut [u8]) -> (Status, u32) {
    match ring.erase_block(block, scratch).await {
        Ok(()) => (Status::Ok, 0),
        Err(o89_core::RingError::OutOfRange) => (Status::OutOfRange, 0),
        Err(_) => (Status::Bus, 0),
    }
}
