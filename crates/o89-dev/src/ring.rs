//! The event ring, decoded: the newest records first, each one's event and,
//! for a boot, why the part came up.
//!
//! The firmware walks the ring with its own reader and hands back verified
//! records a page at a time (`Op::ReadRing`); this reads them with KM43's
//! event and boot codecs. Nothing here knows where the ring starts or how a
//! record is framed, so the tool cannot hold a second opinion about either.
//! A record that does not decode is shown as its bytes rather than skipped:
//! the log is evidence, and a record the tool cannot read is still one the
//! part holds.

use std::fmt::Write as _;

use anyhow::{Result, bail};
use km43::{Boot, BootCause, ControllerRecord, ControllerRecordError, Event, EventKind};
use o89_core::mailbox::{RingEntry, RingPage};
use o89_core::{Class, Task};

use crate::link::Link;

/// An empty CBOR map: the body every class A record carried before KM43
/// defined one, which a unit's ring keeps for as long as the ring does.
const EMPTY_MAP: &[u8] = &[0xA0];

/// One record as the page carried it, held past the page.
struct Held {
    seq: u64,
    class: Class,
    payload: Vec<u8>,
}

/// Print the newest `count` sequence numbers the ring holds, newest first.
pub fn newest(link: &mut Link, count: u64) -> Result<()> {
    // A read from past the end answers the header alone: where the ring
    // ends and what it still holds.
    let first = link.read_ring(u64::MAX)?;
    let (page, _) = RingPage::read(&first).map_err(|why| anyhow::anyhow!("{why:?}"))?;
    let Some(from) = window(page.ring_next, page.oldest, count) else {
        println!("the ring holds no records; the next is {}", page.ring_next);
        return Ok(());
    };
    let end = page.ring_next;
    let mut held = Vec::new();
    let mut at = from;
    // Bounded: every page that does not reach the end carries at least one
    // record of the `count` asked for, so there are at most `count` of them.
    for _ in 0..=count {
        let data = link.read_ring(at)?;
        let (page, entries) = RingPage::read(&data).map_err(|why| anyhow::anyhow!("{why:?}"))?;
        let mut carried = 0usize;
        for entry in entries {
            let RingEntry {
                seq,
                class,
                payload,
            } = entry
                .map_err(|why| anyhow::anyhow!("a page the firmware laid out wrong: {why:?}"))?;
            carried = carried.saturating_add(1);
            if seq < end {
                held.push(Held {
                    seq,
                    class,
                    payload: payload.to_vec(),
                });
            }
        }
        if carried == 0 || page.next >= end {
            break;
        }
        if page.next <= at {
            bail!(
                "the ring answered {} after {at}; it did not move",
                page.next
            );
        }
        at = page.next;
    }
    println!(
        "ring: next {end}, oldest {}; newest first",
        page.oldest
            .map_or_else(|| "none".to_owned(), |oldest| oldest.to_string())
    );
    for record in held.iter().rev() {
        println!("{}", describe(record.seq, record.class, &record.payload));
    }
    Ok(())
}

/// The first sequence to ask for when the newest `count` are wanted, or
/// nothing when the ring holds none. Never below the oldest held, which
/// the ring would answer from anyway, and never zero, which is not a
/// sequence.
fn window(ring_next: u64, oldest: Option<u64>, count: u64) -> Option<u64> {
    let oldest = oldest?;
    Some(ring_next.saturating_sub(count).max(oldest).max(1))
}

/// One line for one record: its sequence, class and event, and the boot
/// body spelled out.
fn describe(seq: u64, class: Class, payload: &[u8]) -> String {
    let class = match class {
        Class::A => "A",
        Class::B => "B",
    };
    let mut line = format!("seq {seq:>8}  {class}  ");
    let event = match Event::decode(payload) {
        Ok(event) => event,
        Err(why) => {
            let _ = write!(line, "not an event ({why}): {}", hex::encode(payload));
            return line;
        }
    };
    let _ = write!(line, "{:#06x}  ", event.kind.0);
    match event.at {
        Some(at) => {
            let _ = write!(line, "at {at}  ");
        }
        None => line.push_str("at -  "),
    }
    if event.seq.0 != seq {
        let _ = write!(line, "(the event says seq {}) ", event.seq.0);
    }
    if event.kind == EventKind::BOOT && event.body() == EMPTY_MAP {
        line.push_str("boot, empty body: written before km43 0.3.0 gave the record its fields");
    } else if event.kind == EventKind::BOOT {
        match Boot::decode(event.body()) {
            Ok(boot) => line.push_str(&boot_line(&boot)),
            Err(why) => {
                let _ = write!(
                    line,
                    "boot, body refused ({why}): {}",
                    hex::encode(event.body())
                );
            }
        }
    } else {
        match ControllerRecord::decode(event.kind, event.body()) {
            Ok(record) => line.push_str(&record_line(record)),
            Err(ControllerRecordError::UnknownKind(_)) => {
                let _ = write!(line, "body {}", hex::encode(event.body()));
            }
            Err(_) if event.body() == EMPTY_MAP => {
                line.push_str("empty body: written before km43 0.4.1 gave the record its fields");
            }
            Err(why) => {
                let _ = write!(line, "body refused ({why}): {}", hex::encode(event.body()));
            }
        }
    }
    line
}

/// A controller record in words (P-215).
fn record_line(record: ControllerRecord) -> String {
    match record {
        ControllerRecord::TimeSet { old, new, source } => format!(
            "time set: {} to {new} ms, by {source:?}",
            old.map_or_else(|| "unknown".to_owned(), |old| format!("{old} ms"))
        ),
        ControllerRecord::RecordFailedCrc { count } => {
            format!("record failed CRC: {count} skipped in the boot's scan")
        }
        ControllerRecord::CommsLinkLost => "comms link lost".to_owned(),
        ControllerRecord::CommsPowerCycled { count } => {
            format!("comms power cycled: {count} in the last hour")
        }
        ControllerRecord::CommsUnrecoverable { rail_on } => format!(
            "comms unrecoverable: the rail left {}",
            if rail_on { "on" } else { "off" }
        ),
        ControllerRecord::SessionsShed { count } => {
            format!("sessions shed: {count} in the last hour")
        }
        ControllerRecord::CommsBootNoise { count } => {
            format!("comms boot noise: {count} bytes that were not frames")
        }
    }
}

/// A boot body in words.
fn boot_line(boot: &Boot) -> String {
    let cause = match boot.cause {
        BootCause::Power => "power (on, down or brown-out)".to_owned(),
        BootCause::Watchdog(Some(starved)) => format!(
            "watchdog, {} {} ms past its window",
            task_name(starved.task),
            starved.overdue_ms
        ),
        BootCause::Watchdog(None) => "watchdog, nobody named".to_owned(),
        BootCause::SoftwareReset => "software reset".to_owned(),
        BootCause::Panic(site) => {
            format!("panic at file {:#010x} line {}", site.file, site.line)
        }
        BootCause::PinReset => "pin reset".to_owned(),
        BootCause::OptionByteReload => "option-byte reload".to_owned(),
        BootCause::WindowWatchdog => "window watchdog".to_owned(),
        BootCause::LowPowerEntry => "low-power entry".to_owned(),
    };
    format!(
        "boot: {cause}; backup domain {}; RTC {}; comms rail {}",
        if boot.backup_valid {
            "valid"
        } else {
            "INVALID"
        },
        if boot.rtc_crystal {
            "on its crystal"
        } else {
            "NOT on its crystal"
        },
        if boot.rail_cycled { "cycled" } else { "kept" }
    )
}

/// A task as this build numbers the roll. The number belongs to the image
/// that wrote it, so an unknown one is shown as the number.
fn task_name(task: u8) -> String {
    Task::from_index(u32::from(task))
        .map_or_else(|| format!("task {task}"), |task| format!("{task:?}"))
}

#[cfg(test)]
mod tests {
    use km43::{LogSeq, PanicSite, Starved};

    use super::*;

    fn event(seq: u64, kind: EventKind, body: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 128];
        let event = Event::new(LogSeq(seq), None, kind, body).expect("an event");
        let len = event.encode(&mut out).expect("encodes");
        out[..len].to_vec()
    }

    fn boot_event(seq: u64, boot: Boot) -> Vec<u8> {
        let mut body = [0u8; km43::BOOT_MAX_BYTES];
        let len = boot.encode(&mut body).expect("encodes");
        event(seq, EventKind::BOOT, &body[..len])
    }

    #[test]
    fn the_window_asks_for_the_newest_and_never_below_what_the_ring_holds() {
        assert_eq!(window(1219, Some(1), 3), Some(1216));
        // More asked for than held: from the oldest.
        assert_eq!(window(10, Some(4), 100), Some(4));
        assert_eq!(window(10, Some(4), u64::MAX), Some(4));
        // An empty ring has nothing to show.
        assert_eq!(window(1, None, 20), None);
    }

    #[test]
    fn a_cold_boot_after_a_night_unplugged_reads_as_what_the_registers_said() {
        let line = describe(
            1216,
            Class::A,
            &boot_event(
                1216,
                Boot {
                    cause: BootCause::Power,
                    backup_valid: false,
                    rtc_crystal: true,
                    rail_cycled: true,
                },
            ),
        );
        assert!(line.contains("seq     1216  A  0x0601  at -  "), "{line}");
        assert!(line.contains("boot: power"), "{line}");
        assert!(line.contains("backup domain INVALID"), "{line}");
        assert!(line.contains("RTC on its crystal"), "{line}");
        assert!(line.contains("comms rail cycled"), "{line}");
    }

    #[test]
    fn the_last_words_name_the_task_or_the_panic_site() {
        let starved = describe(
            7,
            Class::A,
            &boot_event(
                7,
                Boot {
                    cause: BootCause::Watchdog(Some(Starved {
                        task: Task::OneWire.byte(),
                        overdue_ms: 31_000,
                    })),
                    backup_valid: true,
                    rtc_crystal: true,
                    rail_cycled: false,
                },
            ),
        );
        assert!(
            starved.contains("watchdog, OneWire 31000 ms past its window"),
            "{starved}"
        );
        let panicked = describe(
            8,
            Class::A,
            &boot_event(
                8,
                Boot {
                    cause: BootCause::Panic(PanicSite {
                        file: 0x9E37_79B9,
                        line: 212,
                    }),
                    backup_valid: true,
                    rtc_crystal: false,
                    rail_cycled: false,
                },
            ),
        );
        assert!(
            panicked.contains("panic at file 0x9e3779b9 line 212"),
            "{panicked}"
        );
        assert!(panicked.contains("RTC NOT on its crystal"), "{panicked}");
        // A task this build does not number is shown as its number.
        assert_eq!(task_name(200), "task 200");
    }

    fn record_event(seq: u64, record: ControllerRecord) -> Vec<u8> {
        let mut body = [0u8; km43::CONTROLLER_RECORD_MAX_BYTES];
        let len = record.encode(&mut body).expect("encodes");
        event(seq, record.kind(), &body[..len])
    }

    #[test]
    fn the_ladders_records_and_the_boot_noise_read_as_what_they_say() {
        let cycled = describe(
            10,
            Class::A,
            &record_event(
                10,
                ControllerRecord::CommsPowerCycled {
                    count: core::num::NonZeroU32::new(3).expect("three"),
                },
            ),
        );
        assert!(
            cycled.ends_with("comms power cycled: 3 in the last hour"),
            "{cycled}"
        );
        let off = describe(
            11,
            Class::A,
            &record_event(11, ControllerRecord::CommsUnrecoverable { rail_on: false }),
        );
        assert!(
            off.ends_with("comms unrecoverable: the rail left off"),
            "{off}"
        );
        let noise = describe(
            12,
            Class::A,
            &record_event(12, ControllerRecord::CommsBootNoise { count: 0 }),
        );
        assert!(
            noise.ends_with("comms boot noise: 0 bytes that were not frames"),
            "{noise}"
        );
        let lost = describe(
            13,
            Class::A,
            &record_event(13, ControllerRecord::CommsLinkLost),
        );
        assert!(lost.ends_with("comms link lost"), "{lost}");
    }

    #[test]
    fn a_ladder_record_from_before_its_body_existed_is_named_as_old() {
        // The empty map the firmware wrote for a power cycle before km43
        // 0.4.1: a count is required now, and the record is old, not bad.
        let old = describe(
            14,
            Class::A,
            &event(14, EventKind::COMMS_POWER_CYCLED, &[0xA0]),
        );
        assert!(
            old.ends_with("empty body: written before km43 0.4.1 gave the record its fields"),
            "{old}"
        );
        // A body that is neither empty nor valid is refused with its bytes.
        let bad = describe(
            15,
            Class::A,
            &event(15, EventKind::COMMS_POWER_CYCLED, &[0xA1, 0x01, 0x00]),
        );
        assert!(bad.contains("body refused"), "{bad}");
        assert!(bad.ends_with("a10100"), "{bad}");
    }

    #[test]
    fn a_record_the_tool_cannot_read_is_shown_as_its_bytes_not_skipped() {
        let garbage = describe(3, Class::B, &[0xFF, 0x00]);
        assert!(
            garbage.starts_with("seq        3  B  not an event"),
            "{garbage}"
        );
        assert!(garbage.ends_with("ff00"), "{garbage}");
        // The empty body the firmware wrote before the boot schema existed is
        // named as old, not as damage.
        let old = describe(4, Class::A, &event(4, EventKind::BOOT, &[0xA0]));
        assert!(
            old.ends_with("boot, empty body: written before km43 0.3.0 gave the record its fields"),
            "{old}"
        );
        // A boot body that is neither empty nor valid is refused, with its bytes.
        let bad = describe(4, Class::A, &event(4, EventKind::BOOT, &[0xA1, 0x01, 0x03]));
        assert!(
            bad.contains("boot, body refused (boot reason 3 is not allocated): a10103"),
            "{bad}"
        );
        // A kind KM43 has no body for: its number and its bytes.
        let other = describe(
            5,
            Class::A,
            &event(5, EventKind::GENERATOR_STATE_CHANGED, &[0xA0]),
        );
        assert!(other.contains("0x0201  at -  body a0"), "{other}");
        // A payload whose event names another sequence says so.
        let moved = describe(
            6,
            Class::A,
            &event(9, EventKind::GENERATOR_STATE_CHANGED, &[0xA0]),
        );
        assert!(moved.contains("(the event says seq 9)"), "{moved}");
    }
}
