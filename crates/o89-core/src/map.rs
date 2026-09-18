//! Where every record sits in the FRAM, decided once, with the part's size
//! holding the total.
//!
//! Each entry is an A/B [`Record`] with a body size that is the budget for
//! what the record will encode; a body that grows past it moves the map,
//! which moves every record after it, which is a migration and is meant to
//! be visible. The encodings land with the milestones that own them; the
//! sizes are decided here so the part's 32 KiB is allocated once. The last
//! line is the assertion: a map that does not fit does not build.

use crate::fram::{Address, FRAM_BYTES, Record};

/// The epoch: a `u32` that only ever increments (P-085).
pub const EPOCH: Record<4> = Record::at(magic(*b"EPOC"), Address(0));

/// The challenge counter, written before the challenge it names leaves.
pub const CHALLENGE_COUNTER: Record<4> = Record::at(magic(*b"CHAL"), EPOCH.end());

/// The boot counter.
pub const BOOT_COUNTER: Record<4> = Record::at(magic(*b"BOOT"), CHALLENGE_COUNTER.end());

/// The rolling 24-hour write-volume counter: the count and its window.
pub const WRITE_VOLUME: Record<16> = Record::at(magic(*b"VOLU"), BOOT_COUNTER.end());

/// The device-unique secret every key derives from.
pub const DEVICE_SECRET: Record<32> = Record::at(magic(*b"SECR"), WRITE_VOLUME.end());

/// Why the generator is running, written before the output moves.
pub const RUN_REASON: Record<16> = Record::at(magic(*b"RUNR"), DEVICE_SECRET.end());

/// The panic record: what the last words carry, kept past a power cut.
pub const PANIC_RECORD: Record<20> = Record::at(magic(*b"PANI"), RUN_REASON.end());

/// The authorised comms release (L-170).
pub const COMMS_RELEASE: Record<64> = Record::at(magic(*b"RELS"), PANIC_RECORD.end());

/// The network master copy (L-130): one network, a value not a table.
pub const NETWORK: Record<128> = Record::at(magic(*b"NETW"), COMMS_RELEASE.end());

/// The client table: masks and counters for every enrolled client (P-081,
/// P-105).
pub const CLIENT_TABLE: Record<256> = Record::at(magic(*b"CLNT"), NETWORK.end());

/// The dedup table (P-121).
pub const DEDUP_TABLE: Record<1024> = Record::at(magic(*b"DEDU"), CLIENT_TABLE.end());

/// The site configuration section (P-102).
pub const SITE_CONFIG: Record<2048> = Record::at(magic(*b"SITE"), DEDUP_TABLE.end());

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
        // A four-byte body is a 16-byte slot, two slots a record.
        assert_eq!(slot_bytes(4), 16);
        assert_eq!(EPOCH.end(), Address(32));
        assert_eq!(CHALLENGE_COUNTER.end(), Address(64));
        assert_eq!(
            usize::from(SITE_CONFIG.end().0),
            usize::from(DEDUP_TABLE.end().0) + 2 * slot_bytes(2048)
        );
    }

    #[test]
    fn every_magic_is_distinct() {
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
            magic(*b"DEDU"),
            magic(*b"SITE"),
            magic(*b"GENR"),
            magic(*b"FRST"),
            magic(*b"SCHD"),
            magic(*b"SHED"),
        ];
        for (i, a) in magics.iter().enumerate() {
            for b in &magics[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
