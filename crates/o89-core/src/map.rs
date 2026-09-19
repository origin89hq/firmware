//! Where every record sits in the FRAM, decided once, with the part's size
//! holding the total.
//!
//! Each entry is an A/B [`Record`] with a body size that is the budget for
//! what the record will encode; a body that grows past it moves the map,
//! which moves every record after it, which is a migration and is meant to
//! be visible. The encodings land with the milestones that own them; the
//! sizes are decided here so the part's 32 KiB is allocated once. The last
//! line is the assertion: a map that does not fit does not build.

use crate::boot_count::BOOT_COUNT_BYTES;
use crate::challenge::CHALLENGE_COUNTER_BYTES;
use crate::clients::CLIENT_TABLE_BYTES;
use crate::epoch::EPOCH_BYTES;
use crate::fram::{Address, FRAM_BYTES, Record};
use crate::network::NETWORK_BYTES;
use crate::panic_record::PANIC_RECORD_BYTES;
use crate::rail::CUTS_RECORD_BYTES;
use crate::release::COMMS_RELEASE_BYTES;
use crate::run_reason::RUN_REASON_BYTES;
use crate::secret::SECRET_BYTES;
use crate::write_volume::WRITE_VOLUME_BYTES;

/// The epoch: a `u32` that only ever increments (P-085).
pub const EPOCH: Record<EPOCH_BYTES> = Record::at(magic(*b"EPOC"), Address(0));

/// The challenge counter, written before the challenge it names leaves: a
/// `u64`, the width the derivation takes (F-041).
pub const CHALLENGE_COUNTER: Record<CHALLENGE_COUNTER_BYTES> =
    Record::at(magic(*b"CHAL"), EPOCH.end());

/// The boot count.
pub const BOOT_COUNT: Record<BOOT_COUNT_BYTES> =
    Record::at(magic(*b"BOOT"), CHALLENGE_COUNTER.end());

/// The rolling 24-hour write-volume counter: the count and its window
/// (F-024).
pub const WRITE_VOLUME: Record<WRITE_VOLUME_BYTES> = Record::at(magic(*b"VOLU"), BOOT_COUNT.end());

/// The device secret every key derives from: the sixteen bytes of the
/// device id and the thirty-two of the printed secret (P-038, P-044).
pub const DEVICE_SECRET: Record<SECRET_BYTES> = Record::at(magic(*b"SECR"), WRITE_VOLUME.end());

/// Why the generator is running, written before the output moves (F-022).
pub const RUN_REASON: Record<RUN_REASON_BYTES> = Record::at(magic(*b"RUNR"), DEVICE_SECRET.end());

/// The panic record: the boot it happened at and what the last words
/// carry, kept past a power cut.
pub const PANIC_RECORD: Record<PANIC_RECORD_BYTES> = Record::at(magic(*b"PANI"), RUN_REASON.end());

/// The authorised comms release (L-170): the version text, the image
/// length, the digest and the tick it was authorised at.
pub const COMMS_RELEASE: Record<COMMS_RELEASE_BYTES> =
    Record::at(magic(*b"RELS"), PANIC_RECORD.end());

/// The network master copy (L-130): one network, a value not a table, with
/// its version, the credentials, the country and the hostname.
pub const NETWORK: Record<NETWORK_BYTES> = Record::at(magic(*b"NETW"), COMMS_RELEASE.end());

/// The client table: every enrolled client's label, kind, mask and counter,
/// and the dedup table beside them, in one record because P-080 lands a
/// counter and an in-flight entry in one transaction (P-081, P-105,
/// P-121).
pub const CLIENT_TABLE: Record<CLIENT_TABLE_BYTES> = Record::at(magic(*b"CLNT"), NETWORK.end());

/// The recovery ladder's cuts of the last hour, kept before the rail goes
/// off so a controller reset does not lower the count L-112 is judged on
/// (F-017). Before the configuration sections, which nothing has written
/// yet, so that adding it moved nothing a part holds.
pub const RECENT_CUTS: Record<CUTS_RECORD_BYTES> = Record::at(magic(*b"LADR"), CLIENT_TABLE.end());

/// The site configuration section (P-102).
pub const SITE_CONFIG: Record<2048> = Record::at(magic(*b"SITE"), RECENT_CUTS.end());

/// The generator behaviour's section.
pub const GENERATOR_CONFIG: Record<1024> = Record::at(magic(*b"GENR"), SITE_CONFIG.end());

/// The frost behaviour's section.
pub const FROST_CONFIG: Record<1024> = Record::at(magic(*b"FRST"), GENERATOR_CONFIG.end());

/// The schedule behaviour's section.
pub const SCHEDULE_CONFIG: Record<1024> = Record::at(magic(*b"SCHD"), FROST_CONFIG.end());

/// The load-shed behaviour's section.
pub const LOAD_SHED_CONFIG: Record<1024> = Record::at(magic(*b"SHED"), SCHEDULE_CONFIG.end());

/// The first address nothing in the map uses.
pub const END: Address = LOAD_SHED_CONFIG.end();

// The budget: the whole map, both slots of every record, inside the part.
const _: () = assert!((END.0 as usize) <= FRAM_BYTES);

/// Four ASCII bytes as the record's magic, so a dump reads.
const fn magic(word: [u8; 4]) -> u32 {
    u32::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fram::slot_bytes;

    #[test]
    fn the_map_fits_the_part_with_room_for_the_ring_of_records_to_grow() {
        let used = usize::from(END.0);
        assert!(used <= FRAM_BYTES);
        // Under two thirds of the part: the sections above are budgets, and
        // a budget with no headroom is a migration waiting to happen.
        assert!(used < 2 * FRAM_BYTES / 3, "{used} bytes used");
    }

    #[test]
    fn records_follow_each_other_without_overlap_or_gap() {
        // A four-byte body is a 16-byte slot, two slots a record; an
        // eight-byte body is a 20-byte slot.
        assert_eq!(slot_bytes(4), 16);
        assert_eq!(EPOCH.end(), Address(32));
        assert_eq!(CHALLENGE_COUNTER.end(), Address(72));
        assert_eq!(
            usize::from(RECENT_CUTS.end().0),
            usize::from(CLIENT_TABLE.end().0) + 2 * slot_bytes(CUTS_RECORD_BYTES)
        );
        assert_eq!(
            usize::from(SITE_CONFIG.end().0),
            usize::from(RECENT_CUTS.end().0) + 2 * slot_bytes(2048)
        );
    }

    #[test]
    fn f_020_every_magic_is_distinct_and_none_is_zero() {
        let magics = [
            magic(*b"EPOC"),
            magic(*b"CHAL"),
            magic(*b"BOOT"),
            magic(*b"VOLU"),
            magic(*b"SECR"),
            magic(*b"RUNR"),
            magic(*b"PANI"),
            magic(*b"RELS"),
            magic(*b"NETW"),
            magic(*b"CLNT"),
            magic(*b"SITE"),
            magic(*b"GENR"),
            magic(*b"FRST"),
            magic(*b"SCHD"),
            magic(*b"SHED"),
            magic(*b"LADR"),
        ];
        for (i, a) in magics.iter().enumerate() {
            // Never zero: zero is a slot's magic while a record lands over
            // it, and a record could not tell its own slot from one being
            // written.
            assert_ne!(*a, 0);
            for b in &magics[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
