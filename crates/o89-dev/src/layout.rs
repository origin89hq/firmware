//! The module's flash as the bench tool writes it: the partition table it
//! reads from the same CSV the image is built against, and the `otadata`
//! that says which application the bootloader runs (F-084).
//!
//! The bench flash writes an application into an OTA slot and leaves the
//! factory image where it is, because that image is the one that carries
//! the download window and it is the only way back into a module with no
//! wire on it (F-036, #1). The order matters more than the speed: the
//! `otadata` is blanked before the slot is erased and written after the
//! application has landed, so a transfer that dies at any point leaves the
//! module booting an image that honours the window.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The `otadata` partition, both of its sectors.
pub const OTADATA_LEN: u32 = 0x2000;

/// One entry, which is a sector each. Sized so that flash encryption, which
/// this product does not use, would still have whole blocks. A partition
/// table's entries are the same width, which is why this is shared.
const ENTRY_LEN: usize = 32;

/// The flash the module has (F-036), which bounds every partition in a
/// table read off it.
const FLASH_LEN: u32 = 8 * 1024 * 1024;

/// The sector the bootloader reads the partition table out of.
pub const TABLE_AT: u32 = 0x8000;
/// How much of it is read back.
pub const TABLE_LEN: u32 = 0x1000;

/// The erased byte, which is what a sector reads as before anything is
/// programmed into it, and what "no slot chosen" is written as.
const ERASED: u8 = 0xff;

/// The ESP ROM's `crc32_le` seeded with `u32::MAX`, which is the CRC the
/// bootloader recomputes over an entry's `ota_seq` before it trusts the
/// entry. A CRC-32 with the usual polynomial and reflections, but seeded
/// with zero rather than with all ones, because the ROM inverts the seed it
/// is handed. `esp-bootloader-esp-idf` reads entries with these parameters,
/// and it is the code on the module that reads what this writes.
const OTA_SEQ_CRC: crc::Algorithm<u32> = crc::Algorithm {
    width: 32,
    poly: 0x04c1_1db7,
    init: 0,
    refin: true,
    refout: true,
    xorout: 0xffff_ffff,
    check: 0,
    residue: 0,
};

/// The state an entry gives the application it selects.
///
/// `New` is what the bench writes: a bootloader with rollback enabled turns
/// it into pending verification and puts the previous image back unless the
/// application confirms itself, which `o89-comms` does after its download
/// window has run and not before (F-036). A bootloader without rollback
/// ignores the field, and the same bytes mean "run it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ImageState {
    /// Unproven: to be confirmed by the application that boots from it.
    New = 0x0,
}

/// What the bootloader matches a partition on: its type and subtype.
///
/// The name in the table's first column is a label the bootloader never
/// reads. A row called `ota_0` that is not an `app`/`ota_0` row is not the
/// partition the bootloader would boot, so looking a slot up by name is
/// asking a different question from the one that decides where the module
/// starts. This asks the bootloader's question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    /// `app` is 0 and `data` is 1.
    kind: u8,
    /// What kind of app or data, in that type's numbering.
    subtype: u8,
}

impl Role {
    /// `data`/`ota`: the two entries that say which slot runs.
    pub const OTA_DATA: Self = Self {
        kind: 1,
        subtype: 0x00,
    };
    /// `app`/`factory`: the image OTA never writes, which carries the
    /// download window.
    pub const FACTORY: Self = Self {
        kind: 0,
        subtype: 0x00,
    };

    /// `app`/`ota_<slot>`, counted from zero.
    #[must_use]
    pub fn ota(slot: u8) -> Self {
        Self {
            kind: 0,
            subtype: 0x10_u8.saturating_add(slot),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, self.subtype) {
            (1, 0x00) => f.write_str("data/ota"),
            (0, 0x00) => f.write_str("app/factory"),
            (0, sub @ 0x10..=0x1f) => write!(f, "app/ota_{}", sub.saturating_sub(0x10)),
            (kind, subtype) => write!(f, "type {kind:#04x} subtype {subtype:#04x}"),
        }
    }
}

/// A partition, as the table declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// The name in the table's first column, for saying which row this is.
    pub name: String,
    /// The type and subtype, when they are ones this tool knows. A row
    /// whose type or subtype it does not know is `None` and matches
    /// nothing, so an unfamiliar table is refused rather than guessed at.
    pub role: Option<Role>,
    /// The first byte of the partition in the flash.
    pub offset: u32,
    /// How many bytes it spans.
    pub size: u32,
}

/// The partition table the image is built against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    partitions: Vec<Partition>,
}

impl Table {
    /// Read the table from the CSV `espflash` is given, which is the one
    /// copy of it: the bench tool must not hold a second opinion about
    /// where the module's slots are.
    ///
    /// Only the columns this tool uses are read, and a row whose offset or
    /// size is left for `espflash` to compute is refused rather than
    /// guessed at.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the partition table {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// The table the module actually holds, from the sector the bootloader
    /// reads it out of (F-085).
    ///
    /// This is the one that decides where the module's partitions are. The
    /// CSV in the repository says what the next whole flash would install,
    /// which is a different question and the wrong one to answer when
    /// writing a slot on a module somebody else flashed.
    ///
    /// Entries are 32 bytes: `AA 50`, the type and subtype, the offset and
    /// the size, a label and flags. The table ends at its MD5 entry or at
    /// erased bytes; anything else in an entry's place is refused, because
    /// a table this tool cannot read whole is one whose offsets it must
    /// not act on.
    pub fn parse_installed(bytes: &[u8]) -> Result<Self> {
        let mut partitions = Vec::new();
        let mut checksummed = false;
        let mut ended = false;
        // Bounded: one turn per 32-byte entry in the sector.
        for (number, entry) in bytes.as_chunks::<ENTRY_LEN>().0.iter().enumerate() {
            match entry.get(..4).unwrap_or(&[]) {
                // A partition.
                [0xaa, 0x50, _, _] if !checksummed => {
                    let partition = Partition::parse_installed(entry)?;
                    partition.within_the_flash()?;
                    partitions.push(partition);
                }
                // The checksum of everything before it: not a partition.
                [0xeb, 0xeb, _, _] if !checksummed => {
                    verify(bytes, number, entry)?;
                    checksummed = true;
                }
                // The end of the table: magic, type and subtype all erased.
                [ERASED, ERASED, ERASED, ERASED] => {
                    ended = true;
                    break;
                }
                // Anything in an entry's place after the checksum, a second
                // checksum included. The checksum covers what is ahead of
                // it and nothing behind it, so a row here is one nobody
                // signed and one the bootloader counts past the end of the
                // table. Using it would mean writing by a map the module
                // does not boot by; ignoring it would mean saying nothing
                // about a table that is not what it claims to be.
                _ if checksummed => bail!(
                    "entry {number} of the module's partition table comes after the checksum, \
                     which does not cover it"
                ),
                _ => bail!(
                    "entry {number} of the module's partition table is neither a partition, \
                     a checksum nor the end of the table"
                ),
            }
        }
        if !ended {
            bail!("the module's partition table has no terminating entry");
        }
        if partitions.is_empty() {
            bail!("the module's partition table holds no partitions");
        }
        Ok(Self { partitions })
    }

    /// The table's rows, by the text of the file.
    pub fn parse(text: &str) -> Result<Self> {
        let mut partitions = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let line_number = number.saturating_add(1);
            partitions.push(
                Partition::parse(line)
                    .with_context(|| format!("on line {line_number}: {line:?}"))?,
            );
        }
        if partitions.is_empty() {
            bail!("no partitions in the table");
        }
        Ok(Self { partitions })
    }

    /// The partition the bootloader would match for `role`, or an error
    /// naming the rows there are.
    ///
    /// A table declaring the role twice is refused: which of them the
    /// bootloader takes is its business, and a tool that wrote to the
    /// other one would report a success the module did not have.
    pub fn find(&self, role: Role) -> Result<&Partition> {
        let mut matching = self
            .partitions
            .iter()
            .filter(|partition| partition.role == Some(role));
        let found = matching.next().with_context(|| {
            let rows: Vec<String> = self
                .partitions
                .iter()
                .map(|p| match p.role {
                    Some(role) => format!("{} ({role})", p.name),
                    None => format!("{} (a type this tool does not know)", p.name),
                })
                .collect();
            format!("no {role} partition; the table has {}", rows.join(", "))
        })?;
        if let Some(again) = matching.next() {
            bail!(
                "the table declares {role} twice, as {} and as {}",
                found.name,
                again.name
            );
        }
        Ok(found)
    }
}

impl Partition {
    /// One row: `name, type, subtype, offset, size, flags`, of which this
    /// tool reads the name, the offset and the size.
    fn parse(line: &str) -> Result<Self> {
        let mut fields = line.split(',').map(str::trim);
        let name = fields.next().unwrap_or("");
        if name.is_empty() {
            bail!("a row with no name");
        }
        let kind = fields.next().context("a row with no type")?;
        let subtype = fields.next().context("a row with no subtype")?;
        let offset = fields.next().context("a row with no offset")?;
        let size = fields.next().context("a row with no size")?;
        Ok(Self {
            name: name.to_owned(),
            role: role(kind, subtype),
            offset: number(offset).context("the offset")?,
            size: number(size).context("the size")?,
        })
    }

    /// One 32-byte entry of the table the module holds.
    fn parse_installed(entry: &[u8]) -> Result<Self> {
        let field = |at: usize| -> Result<u32> {
            let bytes = entry
                .get(at..at.saturating_add(4))
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .context("a partition entry that is four bytes short")?;
            Ok(u32::from_le_bytes(bytes))
        };
        let kind = *entry.get(2).context("a partition entry with no type")?;
        let subtype = *entry.get(3).context("a partition entry with no subtype")?;
        let label = entry.get(12..28).unwrap_or(&[]);
        let label: String = label
            .iter()
            .take_while(|byte| **byte != 0 && **byte != ERASED)
            .map(|byte| char::from(*byte))
            .collect();
        Ok(Self {
            name: label,
            role: Some(Role { kind, subtype }),
            offset: field(4)?,
            size: field(8)?,
        })
    }

    /// The partition lies inside the flash the module has, which is the
    /// bootloader's own check on a table it reads.
    fn within_the_flash(&self) -> Result<()> {
        let end = self.end()?;
        if self.offset > FLASH_LEN || end > FLASH_LEN {
            bail!(
                "the partition {} runs from {:#x} to {end:#x}, past the module's {FLASH_LEN:#x} \
                 bytes of flash",
                self.name,
                self.offset
            );
        }
        Ok(())
    }

    /// The byte after the partition's last.
    pub fn end(&self) -> Result<u32> {
        self.offset
            .checked_add(self.size)
            .with_context(|| format!("the partition {} ends past the flash", self.name))
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:#x}, {} bytes",
            self.name, self.offset, self.size
        )
    }
}

/// The checksum entry at `number`, against the entries before it.
///
/// The same computation the bootloader makes: MD5 over the bytes of every
/// entry ahead of this one, compared with the sixteen in this entry's
/// second half. A table whose checksum does not match is one the
/// bootloader refuses, and offsets from a table the bootloader refuses are
/// offsets to write nothing at — F-085 rests on this table being the one
/// the module will actually boot by.
///
/// A table with no checksum entry at all is not refused: ESP-IDF makes it
/// optional, and the bootloader accepts one without.
fn verify(bytes: &[u8], number: usize, entry: &[u8; ENTRY_LEN]) -> Result<()> {
    let before = bytes
        .get(..number.saturating_mul(ENTRY_LEN))
        .context("a checksum entry past the end of the table")?;
    let computed = <md5::Md5 as md5::Digest>::digest(before);
    let stated = entry
        .get(ENTRY_LEN / 2..)
        .context("a checksum entry with no checksum in it")?;
    if stated != computed.as_slice() {
        bail!(
            "the module's partition table does not match its own checksum, so the bootloader \
             would refuse it too"
        );
    }
    Ok(())
}

/// The type and subtype of a row, when both are ones this tool knows.
///
/// Only the roles it looks up need to resolve; anything else is `None`,
/// which matches no lookup, so an unknown row can never be mistaken for a
/// slot. Both may be written as the names ESP-IDF uses or as numbers, as
/// the table format allows.
fn role(kind: &str, subtype: &str) -> Option<Role> {
    let kind = match kind {
        "app" => 0,
        "data" => 1,
        other => small(other)?,
    };
    // The two are separate numberings: `app`'s 0 is the factory image and
    // `data`'s 0 is the OTA state, and they are only the same byte.
    let subtype = match kind {
        0 => app_subtype(subtype),
        1 => data_subtype(subtype),
        _ => None,
    }
    .or_else(|| small(subtype))?;
    Some(Role { kind, subtype })
}

/// An `app` subtype by the name ESP-IDF gives it.
fn app_subtype(name: &str) -> Option<u8> {
    match name {
        "factory" => Some(0x00),
        "test" => Some(0x20),
        _ => match name.strip_prefix("ota_")?.parse::<u8>().ok()? {
            slot if slot < 16 => Some(0x10_u8.saturating_add(slot)),
            _ => None,
        },
    }
}

/// A `data` subtype by the name ESP-IDF gives it.
fn data_subtype(name: &str) -> Option<u8> {
    match name {
        "ota" => Some(0x00),
        "phy" => Some(0x01),
        "nvs" => Some(0x02),
        "coredump" => Some(0x03),
        "nvs_keys" => Some(0x04),
        "efuse" => Some(0x05),
        "undefined" => Some(0x06),
        "esphttpd" => Some(0x80),
        "fat" => Some(0x81),
        "spiffs" => Some(0x82),
        "littlefs" => Some(0x83),
        _ => None,
    }
}

/// A field written as a number, when it fits a type or subtype byte.
fn small(field: &str) -> Option<u8> {
    u8::try_from(number(field).ok()?).ok()
}

/// A `0x`-prefixed or decimal number, or one with `K` or `M` after it, as
/// the table writes them. An empty field is refused: `espflash` would fill
/// it by laying the table out itself, and a bench tool that guessed the
/// same layout would be a second implementation of it.
fn number(field: &str) -> Result<u32> {
    if field.is_empty() {
        bail!("left for espflash to compute, which this tool does not do; write it out");
    }
    let (digits, scale) = match field.as_bytes().last() {
        Some(b'K' | b'k') => (field.get(..field.len().saturating_sub(1)), 1024u32),
        Some(b'M' | b'm') => (field.get(..field.len().saturating_sub(1)), 1024 * 1024),
        _ => (Some(field), 1),
    };
    let digits = digits.unwrap_or("").trim();
    let value = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => digits.parse::<u32>(),
    }
    .with_context(|| format!("{field:?} is not a number"))?;
    value
        .checked_mul(scale)
        .with_context(|| format!("{field:?} does not fit"))
}

/// The `otadata` partition with no slot chosen, which is the erased part:
/// the bootloader falls back to the factory image, the one that carries the
/// window.
///
/// This is written **before** the slot is erased. From that write until the
/// entry below lands, every reset boots the factory image, so a transfer
/// that dies in between leaves a module the controller can still knock at.
#[must_use]
pub fn otadata_no_slot() -> Vec<u8> {
    vec![ERASED; OTADATA_LEN as usize]
}

/// The `otadata` partition selecting OTA slot `slot`, counted from zero.
///
/// The first entry carries the sequence and the second is left erased, so
/// the bootloader reads one valid entry and no comparison is needed: the
/// slot is `(seq - 1) % slots`, and the sequence is the smallest that picks
/// the slot asked for. Written **after** the application has landed.
pub fn otadata_selecting(slot: u32, slots: u32, state: ImageState) -> Result<Vec<u8>> {
    if slots == 0 {
        bail!("a table with no OTA slots");
    }
    if slot >= slots {
        bail!("OTA slot {slot} on a table with {slots} of them");
    }
    let seq = slot.checked_add(1).context("a sequence that fits")?;
    let mut bytes = otadata_no_slot();
    let entry = entry(seq, state);
    bytes
        .get_mut(..ENTRY_LEN)
        .context("the otadata holds an entry")?
        .copy_from_slice(&entry);
    Ok(bytes)
}

/// One 32-byte entry: the sequence, an unused label, the state, and the CRC
/// the bootloader recomputes over the sequence alone.
fn entry(seq: u32, state: ImageState) -> [u8; ENTRY_LEN] {
    let mut entry = [ERASED; ENTRY_LEN];
    let seq = seq.to_le_bytes();
    let crc = crc::Crc::<u32>::new(&OTA_SEQ_CRC).checksum(&seq);
    let fields: [(usize, [u8; 4]); 3] = [
        (0, seq),
        (24, (state as u32).to_le_bytes()),
        (28, crc.to_le_bytes()),
    ];
    for (at, value) in fields {
        if let Some(field) = entry.get_mut(at..at.saturating_add(4)) {
            field.copy_from_slice(&value);
        }
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table the comms image is built against, as it stands.
    const BOARD_A: &str = "\
# a comment, and a blank line follow

otadata,   data, ota,     0x9000,   0x2000,
factory,   app,  factory, 0x10000,  0x200000,
ota_0,     app,  ota_0,   0x210000, 0x200000,
ota_1,     app,  ota_1,   0x410000, 0x200000,
creds,     data, nvs,     0x610000, 0x6000,
";

    #[test]
    fn a_table_is_read_past_its_comments_and_blank_lines() {
        let table = Table::parse(BOARD_A).expect("the table parses");
        let slot = table.find(Role::ota(0)).expect("ota_0 is there");
        assert_eq!(slot.offset, 0x0021_0000);
        assert_eq!(slot.size, 0x0020_0000);
        assert_eq!(slot.end().expect("it ends"), 0x0041_0000);
    }

    /// One 32-byte entry of a table as the module holds it.
    fn installed_entry(kind: u8, subtype: u8, offset: u32, size: u32, label: &str) -> Vec<u8> {
        let mut entry = vec![0xaa, 0x50, kind, subtype];
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        let mut name = [0u8; 16];
        for (at, byte) in label.bytes().take(16).enumerate() {
            name[at] = byte;
        }
        entry.extend_from_slice(&name);
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry
    }

    /// The checksum entry ESP-IDF appends: the magic, erased padding, and
    /// the MD5 of everything before it.
    fn checksum_entry(before: &[u8]) -> Vec<u8> {
        let mut entry = vec![0xeb, 0xeb];
        entry.extend_from_slice(&[ERASED; 14]);
        entry.extend_from_slice(&<md5::Md5 as md5::Digest>::digest(before));
        entry
    }

    /// A whole sector: the rows, the checksum entry after them, and erased
    /// bytes to the end.
    fn installed_sector(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes: Vec<u8> = rows.concat();
        let checksum = checksum_entry(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes.resize(TABLE_LEN as usize, ERASED);
        bytes
    }

    #[test]
    fn f_085_the_table_the_module_holds_is_read_from_its_own_sector() {
        let sector = installed_sector(&[
            installed_entry(1, 0x00, 0x9000, 0x2000, "otadata"),
            installed_entry(0, 0x00, 0x0001_0000, 0x0020_0000, "factory"),
            installed_entry(0, 0x10, 0x0021_0000, 0x0020_0000, "ota_0"),
        ]);
        let table = Table::parse_installed(&sector).expect("the table parses");
        let slot = table.find(Role::ota(0)).expect("ota_0");
        assert_eq!(slot.offset, 0x0021_0000);
        assert_eq!(
            slot.name, "ota_0",
            "the label comes back without its padding"
        );
        assert_eq!(
            table.find(Role::FACTORY).expect("factory").offset,
            0x0001_0000
        );
    }

    /// The table `espflash` really lays down for this product, read back
    /// as the tool reads it off a module. See `fixtures/README.md`.
    const REAL_TABLE: &[u8] = include_bytes!("../fixtures/partition-table.bin");

    #[test]
    fn f_085_the_table_espflash_really_writes_is_read_and_its_checksum_agrees() {
        // Against the generator's own bytes, so that the checksum this
        // recomputes is the one ESP-IDF computes and not one this
        // repository invented to match its own reader.
        let table = Table::parse_installed(REAL_TABLE).expect("the real table parses");
        assert_eq!(table.find(Role::OTA_DATA).expect("otadata").offset, 0x9000);
        assert_eq!(
            table.find(Role::FACTORY).expect("factory").offset,
            0x0001_0000
        );
        assert_eq!(table.find(Role::ota(0)).expect("ota_0").offset, 0x0021_0000);
        assert_eq!(table.find(Role::ota(1)).expect("ota_1").offset, 0x0041_0000);
    }

    #[test]
    fn f_085_one_flipped_bit_in_the_real_table_is_refused() {
        let mut corrupted = REAL_TABLE.to_vec();
        // The low byte of ota_0's offset, in the third entry.
        corrupted[64 + 4] ^= 0x10;
        let error = format!(
            "{:#}",
            Table::parse_installed(&corrupted).expect_err("refused")
        );
        assert!(error.contains("own checksum"), "{error}");
    }

    #[test]
    fn f_085_a_table_that_does_not_match_its_own_checksum_is_refused() {
        // A corrupted offset the bootloader would reject is one this tool
        // must not plan from, however consistent the rest of the table
        // looks: it would be writing by a map the module does not use.
        let mut sector = installed_sector(&[
            installed_entry(1, 0x00, 0x9000, 0x2000, "otadata"),
            installed_entry(0, 0x00, 0x0001_0000, 0x0020_0000, "factory"),
            installed_entry(0, 0x10, 0x0021_0000, 0x0020_0000, "ota_0"),
        ]);
        Table::parse_installed(&sector).expect("sound before the corruption");
        // Move ota_0 on top of the factory image, as corruption might.
        sector[64 + 4] = 0x00;
        sector[64 + 5] = 0x00;
        sector[64 + 6] = 0x01;
        let error = format!(
            "{:#}",
            Table::parse_installed(&sector).expect_err("refused")
        );
        assert!(error.contains("own checksum"), "{error}");
    }

    #[test]
    fn f_085_a_table_with_no_checksum_at_all_is_still_read() {
        // ESP-IDF makes the checksum optional and the bootloader accepts a
        // table without one, so refusing it here would refuse a module the
        // bootloader is perfectly happy with.
        let mut bytes: Vec<u8> = [
            installed_entry(1, 0x00, 0x9000, 0x2000, "otadata"),
            installed_entry(0, 0x10, 0x0021_0000, 0x0020_0000, "ota_0"),
        ]
        .concat();
        bytes.resize(TABLE_LEN as usize, ERASED);
        let table = Table::parse_installed(&bytes).expect("read without a checksum");
        assert_eq!(table.find(Role::ota(0)).expect("ota_0").offset, 0x0021_0000);
    }

    #[test]
    fn a_table_with_two_checksums_is_refused() {
        let rows = [installed_entry(1, 0x00, 0x9000, 0x2000, "otadata")];
        let mut bytes: Vec<u8> = rows.concat();
        let checksum = checksum_entry(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes.extend_from_slice(&checksum);
        bytes.resize(TABLE_LEN as usize, ERASED);
        let error = format!("{:#}", Table::parse_installed(&bytes).expect_err("refused"));
        assert!(error.contains("after the checksum"), "{error}");
    }

    #[test]
    fn f_085_a_partition_appended_after_the_checksum_is_refused() {
        // The checksum covers what is ahead of it. A row after it is one
        // nobody signed, and the bootloader counts it past the end of the
        // table, so a tool that used it would erase whatever it pointed at
        // — the credential record, say — and report a slot written that
        // the module never boots from.
        let rows = [
            installed_entry(1, 0x00, 0x9000, 0x2000, "otadata"),
            installed_entry(0, 0x00, 0x0001_0000, 0x0020_0000, "factory"),
        ];
        let mut bytes: Vec<u8> = rows.concat();
        let checksum = checksum_entry(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes.extend_from_slice(&installed_entry(0, 0x10, 0x0061_0000, 0x6000, "ota_0"));
        bytes.resize(TABLE_LEN as usize, ERASED);
        let error = format!("{:#}", Table::parse_installed(&bytes).expect_err("refused"));
        assert!(error.contains("after the checksum"), "{error}");
    }

    #[test]
    fn a_table_that_never_ends_is_refused() {
        let rows = [installed_entry(1, 0x00, 0x9000, 0x2000, "otadata")];
        let mut bytes: Vec<u8> = rows.concat();
        let checksum = checksum_entry(&bytes);
        bytes.extend_from_slice(&checksum);
        // No erased entry after it: the table runs to the end of what was
        // read, which the bootloader calls missing a terminating entry.
        let error = format!("{:#}", Table::parse_installed(&bytes).expect_err("refused"));
        assert!(error.contains("terminating entry"), "{error}");
    }

    #[test]
    fn a_partition_past_the_end_of_the_flash_is_refused() {
        let sector =
            installed_sector(&[installed_entry(0, 0x10, 0x00ff_0000, 0x0020_0000, "ota_0")]);
        let error = format!(
            "{:#}",
            Table::parse_installed(&sector).expect_err("refused")
        );
        assert!(error.contains("past the module's"), "{error}");
    }

    #[test]
    fn an_installed_table_with_nothing_in_it_is_refused() {
        assert!(Table::parse_installed(&[ERASED; 64]).is_err());
    }

    #[test]
    fn an_installed_table_this_tool_cannot_read_whole_is_refused() {
        // Neither a partition, an MD5, nor the end: offsets from a table
        // that is only partly understood are offsets to write nothing at.
        let mut sector = installed_sector(&[installed_entry(1, 0x00, 0x9000, 0x2000, "otadata")]);
        sector[32] = 0x12;
        sector[33] = 0x34;
        let error = format!(
            "{:#}",
            Table::parse_installed(&sector).expect_err("refused")
        );
        assert!(error.contains("entry 1"), "{error}");
    }

    #[test]
    fn a_partition_the_table_does_not_have_names_the_ones_it_does() {
        let table = Table::parse(BOARD_A).expect("the table parses");
        let error = format!("{:#}", table.find(Role::ota(2)).expect_err("no ota_2"));
        assert!(error.contains("app/ota_2"), "{error}");
        assert!(error.contains("ota_0 (app/ota_0)"), "{error}");
        assert!(error.contains("factory (app/factory)"), "{error}");
    }

    #[test]
    fn f_036_a_row_merely_named_like_a_slot_is_not_the_slot_the_bootloader_boots() {
        // The bootloader matches on type and subtype; the name is a label
        // it never reads. A tool that matched the name would write the
        // application into this row and report a success the module did
        // not have, because the bootloader would go on booting elsewhere.
        let table = Table::parse(
            "otadata, data, ota,     0x9000,   0x2000,\n\
             factory, app,  factory, 0x10000,  0x200000,\n\
             ota_0,   data, nvs,     0x210000, 0x6000,\n",
        )
        .expect("the table parses");
        let error = format!("{:#}", table.find(Role::ota(0)).expect_err("not a slot"));
        assert!(error.contains("no app/ota_0 partition"), "{error}");
        assert!(error.contains("ota_0 (type 0x01 subtype 0x02)"), "{error}");
    }

    #[test]
    fn a_table_that_declares_a_role_twice_is_refused() {
        let table = Table::parse(
            "first,  app, ota_0, 0x210000, 0x200000,\n\
             second, app, ota_0, 0x410000, 0x200000,\n",
        )
        .expect("the table parses");
        let error = format!("{:#}", table.find(Role::ota(0)).expect_err("twice"));
        assert!(error.contains("twice"), "{error}");
    }

    #[test]
    fn a_role_is_read_from_names_or_from_numbers() {
        let table = Table::parse(
            "otadata, 1,   0,     0x9000,   0x2000,\n\
             slot,    0,   0x10,  0x210000, 0x200000,\n",
        )
        .expect("the table parses");
        assert_eq!(table.find(Role::OTA_DATA).expect("otadata").offset, 0x9000);
        assert_eq!(table.find(Role::ota(0)).expect("slot").offset, 0x0021_0000);
    }

    #[test]
    fn an_offset_left_for_espflash_to_compute_is_refused() {
        let error = format!(
            "{:#}",
            Table::parse("ota_0, app, ota_0, , 0x200000,").expect_err("no offset")
        );
        assert!(error.contains("write it out"), "{error}");
    }

    #[test]
    fn an_empty_table_is_not_a_table() {
        assert!(Table::parse("# nothing but a comment\n").is_err());
    }

    #[test]
    fn a_row_that_stops_before_its_size_is_refused() {
        assert!(Table::parse("ota_0, app, ota_0, 0x210000\n").is_err());
    }

    #[test]
    fn sizes_are_read_in_hex_decimal_and_with_a_scale() {
        let table = Table::parse(
            "a, data, ota, 0x1000, 0x2000,\nb, data, phy, 4096, 8192,\nc, data, nvs, 0x10000, 2M,\n",
        )
        .expect("the table parses");
        assert_eq!(table.find(Role::OTA_DATA).expect("a").size, 0x2000);
        assert_eq!(
            table
                .find(Role {
                    kind: 1,
                    subtype: 0x01
                })
                .expect("b")
                .size,
            8192
        );
        assert_eq!(
            table
                .find(Role {
                    kind: 1,
                    subtype: 0x02
                })
                .expect("c")
                .size,
            2 * 1024 * 1024
        );
    }

    /// The ROM's `crc32_le(0xffffffff, ..)`, written out the way the ROM
    /// computes it, as a second opinion on the parameters above: the bench
    /// tool's entry is only read by the module's bootloader, and a CRC
    /// nobody checked here would be found on the board or not at all.
    fn rom_crc32_le(seed: u32, bytes: &[u8]) -> u32 {
        let mut crc = !seed;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn the_entrys_crc_is_the_roms_over_the_sequence_alone() {
        for seq in [1u32, 2, 3, 0x0100, u32::MAX - 1] {
            let entry = entry(seq, ImageState::New);
            let written = u32::from_le_bytes(entry[28..32].try_into().expect("four bytes"));
            assert_eq!(
                written,
                rom_crc32_le(u32::MAX, &seq.to_le_bytes()),
                "sequence {seq}"
            );
        }
    }

    #[test]
    fn f_084_the_selected_slot_is_the_one_the_bootloader_computes() {
        // The bootloader's rule, from `esp-bootloader-esp-idf`: an entry
        // whose sequence is not the erased word selects `(seq - 1) % slots`.
        for slot in 0..2u32 {
            let bytes = otadata_selecting(slot, 2, ImageState::New).expect("a slot in the table");
            let seq = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes"));
            assert_ne!(seq, u32::MAX, "an erased sequence selects nothing");
            assert_eq!((seq - 1) % 2, slot);
            let state = u32::from_le_bytes(bytes[24..28].try_into().expect("four bytes"));
            assert_eq!(state, ImageState::New as u32, "unproven until it confirms");
        }
    }

    #[test]
    fn f_084_the_second_entry_is_left_erased_so_it_never_outranks_the_first() {
        let bytes = otadata_selecting(1, 2, ImageState::New).expect("slot 1");
        assert_eq!(bytes.len(), OTADATA_LEN as usize);
        assert!(
            bytes[ENTRY_LEN..].iter().all(|byte| *byte == ERASED),
            "everything after the first entry is erased"
        );
    }

    #[test]
    fn f_084_no_slot_chosen_is_the_erased_part_the_bootloader_reads_as_the_factory_image() {
        let bytes = otadata_no_slot();
        assert_eq!(bytes.len(), OTADATA_LEN as usize);
        assert!(bytes.iter().all(|byte| *byte == ERASED));
    }

    #[test]
    fn a_slot_the_table_does_not_have_is_refused() {
        assert!(otadata_selecting(2, 2, ImageState::New).is_err());
        assert!(otadata_selecting(0, 0, ImageState::New).is_err());
    }
}
