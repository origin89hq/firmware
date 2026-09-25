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
use crate::clients::{KEY_RECORD_BYTES, MARK_BYTES, SLOTS};
use crate::dedup::COMMANDS_BYTES;
use crate::drbg::DRBG_BYTES;
use crate::epoch::EPOCH_BYTES;
use crate::fram::{Address, FRAM_BYTES, Record};
use crate::network::NETWORK_BYTES;
use crate::panic_record::PANIC_RECORD_BYTES;
use crate::rail::CUTS_RECORD_BYTES;
use crate::release::COMMS_RELEASE_BYTES;
use crate::run_reason::RUN_REASON_BYTES;
use crate::secret::{CONTROLLER_KEY_BYTES, SECRET_BYTES};
use crate::write_volume::WRITE_VOLUME_BYTES;

/// The epoch: a `u32` that only ever increments (P-085).
pub const EPOCH: Record<EPOCH_BYTES> = Record::at(magic(*b"EPOC"), Address(0));

/// The random bit generator's state, advanced and read back before every
/// draw is used (P-237).
pub const DRBG: Record<DRBG_BYTES> = Record::at(magic(*b"DRBG"), EPOCH.end());

/// The boot count.
pub const BOOT_COUNT: Record<BOOT_COUNT_BYTES> = Record::at(magic(*b"BOOT"), DRBG.end());

/// The rolling 24-hour write-volume counter: the count and its window
/// (F-024).
pub const WRITE_VOLUME: Record<WRITE_VOLUME_BYTES> = Record::at(magic(*b"VOLU"), BOOT_COUNT.end());

/// The device secret every key derives from: the sixteen bytes of the
/// device id and the thirty-two of the printed secret (P-038, P-044).
pub const DEVICE_SECRET: Record<SECRET_BYTES> = Record::at(magic(*b"SECR"), WRITE_VOLUME.end());

/// The controller key's private half, written at manufacture and never
/// again (P-235).
pub const CONTROLLER_KEY: Record<CONTROLLER_KEY_BYTES> =
    Record::at(magic(*b"CKEY"), DEVICE_SECRET.end());

/// Why the generator is running, written before the output moves (F-022).
pub const RUN_REASON: Record<RUN_REASON_BYTES> = Record::at(magic(*b"RUNR"), CONTROLLER_KEY.end());

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

/// Each slot's key record, two copies with a sequence number and a CRC
/// (P-239).
pub const CLIENT_KEYS: [Record<KEY_RECORD_BYTES>; SLOTS] = [
    CLIENT_KEY_1,
    CLIENT_KEY_2,
    CLIENT_KEY_3,
    CLIENT_KEY_4,
    CLIENT_KEY_5,
    CLIENT_KEY_6,
    CLIENT_KEY_7,
    CLIENT_KEY_8,
];
const CLIENT_KEY_1: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY1"), NETWORK.end());
const CLIENT_KEY_2: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY2"), CLIENT_KEY_1.end());
const CLIENT_KEY_3: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY3"), CLIENT_KEY_2.end());
const CLIENT_KEY_4: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY4"), CLIENT_KEY_3.end());
const CLIENT_KEY_5: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY5"), CLIENT_KEY_4.end());
const CLIENT_KEY_6: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY6"), CLIENT_KEY_5.end());
const CLIENT_KEY_7: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY7"), CLIENT_KEY_6.end());
const CLIENT_KEY_8: Record<KEY_RECORD_BYTES> = Record::at(magic(*b"KEY8"), CLIENT_KEY_7.end());

/// Each slot's generation mark: the highest generation it has issued,
/// raised and read back before the slot is re-keyed (P-239).
pub const GENERATION_MARKS: [Record<MARK_BYTES>; SLOTS] = [
    GENERATION_MARK_1,
    GENERATION_MARK_2,
    GENERATION_MARK_3,
    GENERATION_MARK_4,
    GENERATION_MARK_5,
    GENERATION_MARK_6,
    GENERATION_MARK_7,
    GENERATION_MARK_8,
];
const GENERATION_MARK_1: Record<MARK_BYTES> = Record::at(magic(*b"GEN1"), CLIENT_KEY_8.end());
const GENERATION_MARK_2: Record<MARK_BYTES> = Record::at(magic(*b"GEN2"), GENERATION_MARK_1.end());
const GENERATION_MARK_3: Record<MARK_BYTES> = Record::at(magic(*b"GEN3"), GENERATION_MARK_2.end());
const GENERATION_MARK_4: Record<MARK_BYTES> = Record::at(magic(*b"GEN4"), GENERATION_MARK_3.end());
const GENERATION_MARK_5: Record<MARK_BYTES> = Record::at(magic(*b"GEN5"), GENERATION_MARK_4.end());
const GENERATION_MARK_6: Record<MARK_BYTES> = Record::at(magic(*b"GEN6"), GENERATION_MARK_5.end());
const GENERATION_MARK_7: Record<MARK_BYTES> = Record::at(magic(*b"GEN7"), GENERATION_MARK_6.end());
const GENERATION_MARK_8: Record<MARK_BYTES> = Record::at(magic(*b"GEN8"), GENERATION_MARK_7.end());

/// The dedup table, under the epoch its entries were made in (P-080,
/// P-121).
pub const COMMANDS: Record<COMMANDS_BYTES> = Record::at(magic(*b"CMDS"), GENERATION_MARK_8.end());

/// The recovery ladder's cuts of the last hour, kept before the rail goes
/// off so a controller reset does not lower the count L-112 is judged on
/// (F-017).
pub const RECENT_CUTS: Record<CUTS_RECORD_BYTES> = Record::at(magic(*b"LADR"), COMMANDS.end());

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

pub(crate) const SECRET_CHANGE_START: Address = LOAD_SHED_CONFIG.end();

/// The manufacturing transaction: the secret, and on a unit's first one the
/// controller key and the generator's first state, applied at the next boot.
pub const SECRET_CHANGE: Record<{ crate::SECRET_CHANGE_BYTES }> =
    Record::at(magic(*b"SROT"), SECRET_CHANGE_START);

/// The first address nothing in the map uses.
pub const END: Address = SECRET_CHANGE.end();

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
        // A 32-byte body is a 44-byte slot.
        assert_eq!(DRBG.end(), Address(32 + 88));
        assert_eq!(
            usize::from(END.0) - usize::from(LOAD_SHED_CONFIG.end().0),
            2 * slot_bytes(crate::SECRET_CHANGE_BYTES)
        );
        assert_eq!(
            usize::from(GENERATION_MARK_1.end().0) - usize::from(NETWORK.end().0),
            SLOTS * 2 * slot_bytes(KEY_RECORD_BYTES) + 2 * slot_bytes(MARK_BYTES)
        );
        assert_eq!(
            usize::from(RECENT_CUTS.end().0),
            usize::from(COMMANDS.end().0) + 2 * slot_bytes(CUTS_RECORD_BYTES)
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
            magic(*b"DRBG"),
            magic(*b"BOOT"),
            magic(*b"VOLU"),
            magic(*b"SECR"),
            magic(*b"CKEY"),
            magic(*b"RUNR"),
            magic(*b"PANI"),
            magic(*b"RELS"),
            magic(*b"NETW"),
            magic(*b"KEY1"),
            magic(*b"KEY2"),
            magic(*b"KEY3"),
            magic(*b"KEY4"),
            magic(*b"KEY5"),
            magic(*b"KEY6"),
            magic(*b"KEY7"),
            magic(*b"KEY8"),
            magic(*b"GEN1"),
            magic(*b"GEN2"),
            magic(*b"GEN3"),
            magic(*b"GEN4"),
            magic(*b"GEN5"),
            magic(*b"GEN6"),
            magic(*b"GEN7"),
            magic(*b"GEN8"),
            magic(*b"CMDS"),
            magic(*b"SITE"),
            magic(*b"GENR"),
            magic(*b"FRST"),
            magic(*b"SCHD"),
            magic(*b"SHED"),
            magic(*b"LADR"),
            magic(*b"SROT"),
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
