//! The station's public record of each unit it made (P-249): which
//! controller fingerprint belongs to which device id, taken from the key the
//! station drew and never from what a part reports. The format is in
//! `crates/o89-dev/EXPORT.md`.
//!
//! Two files, both public. The export file, named by the operator, holds
//! only records the part confirmed; it is what the cloud imports. Beside it,
//! `<export>.drawn` journals every transaction before it is staged: the pair
//! the station drew for a birth, or the intent of a `--replace`. A
//! `--resume` in a later process confirms against that entry, and refuses a
//! ledger that has none, which is the wrong file. A drawn pair whose key
//! never reached the part stays in the journal and is never exported.
//!
//! Both files change only by a whole new copy renamed over the old one, so a
//! host cut off mid-write leaves the file as it was or as it will be, never
//! a torn line.

use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use km43::{DeviceId, FINGERPRINT_BYTES, Fingerprint};
use o89_core::DEVICE_ID_BYTES;
use serde::{Deserialize, Serialize};

/// Every line's version; a change to any field's meaning is a new one.
const VERSION: u32 = 1;

/// Every line either file holds is at most 145 bytes with its newline;
/// anything past this is not a line the station wrote, and reading stops.
const LINE_BYTES: u64 = 512;

/// What a line says, by its format name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// The export file's record, confirmed by the part.
    Exported,
    /// A key the station drew for a birth, journaled before it was staged.
    Drawn,
    /// A `--replace` journaled before it was staged, with the fingerprint
    /// the part held then: a lookup key for the export file, never a source.
    Replaced,
}

impl Kind {
    const fn format(self) -> &'static str {
        match self {
            Self::Exported => "o89-controller-record",
            // Distinct, so an import handed the journal refuses it.
            Self::Drawn => "o89-controller-drawn",
            Self::Replaced => "o89-controller-replace",
        }
    }
}

const EXPORT_KINDS: &[Kind] = &[Kind::Exported];
const JOURNAL_KINDS: &[Kind] = &[Kind::Drawn, Kind::Replaced];

/// One unit's public record: its device id and its controller key's
/// fingerprint (P-236).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub device_id: DeviceId,
    pub fingerprint: Fingerprint,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {}",
            hex::encode(self.device_id.as_bytes()),
            hex::encode(self.fingerprint.as_bytes())
        )
    }
}

/// A line of either file, as text: strings only at the file boundary.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line<'a> {
    format: &'a str,
    version: u32,
    device_id: &'a str,
    controller_fp: &'a str,
}

/// What confirming a unit did to the export file.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Exported {
    /// The record was appended.
    Appended(Record),
    /// The file already held this exact record; nothing was written.
    AlreadyHeld(Record),
    /// A `--replace` onto a key the station holds no record of, so nothing
    /// was exported: its fingerprint is never taken from the part.
    NoStationRecord,
}

/// What the export file says about one device id and one fingerprint.
struct InExport {
    /// The record for the device id.
    held: Option<Record>,
    /// A record, under any device id, of the fingerprint.
    of_key: Option<Record>,
}

/// The export file and its journal.
pub struct Ledger {
    export: PathBuf,
    journal: PathBuf,
}

impl Ledger {
    /// The ledger for the operator's export file; neither file need exist,
    /// but the name must be a file's.
    pub fn new(export: &Path) -> Result<Self> {
        let text = export.as_os_str().to_string_lossy();
        if export.file_name().is_none()
            || text.ends_with(std::path::MAIN_SEPARATOR)
            || text.ends_with('/')
            || export.is_dir()
        {
            bail!("the export file {} names no file", export.display());
        }
        Ok(Self {
            export: export.to_owned(),
            journal: suffixed(export, ".drawn"),
        })
    }

    /// The export file's path, for what the operator is told.
    pub fn export(&self) -> &Path {
        &self.export
    }

    /// Before a birth is staged: admit the pair, then journal it. Nothing
    /// is staged unless this returns `Ok`.
    pub fn note_drawn(&self, record: Record) -> Result<()> {
        self.admit(record)?;
        commit(&self.journal, Kind::Drawn, record)
    }

    /// Before a `--replace` is staged, with the fingerprint the part holds:
    /// admit the pair, then journal the intent. The fingerprint is compared
    /// and kept as a lookup key, never exported from here.
    pub fn note_replace(&self, record: Record) -> Result<()> {
        self.admit(record)?;
        commit(&self.journal, Kind::Replaced, record)
    }

    /// Refuse a device id the export file gives another fingerprint, or,
    /// unless the export already settles it as this exact pair, one the
    /// journal holds another key for: that key may be on a part awaiting
    /// `--resume`, and `confirm` would refuse only once a second part had
    /// applied this one. Both files are read whole, so a damaged one is
    /// refused before anything is staged.
    fn admit(&self, record: Record) -> Result<()> {
        match self.in_export(record)?.held {
            Some(held) if held == record => {
                // Settled: abandoned draws for the id do not veto it.
                scan(&self.journal, JOURNAL_KINDS, |_, _| Ok(()))?;
                return Ok(());
            }
            Some(held) => bail!(
                "{} already records device id {} with fingerprint {}; a second fingerprint for it \
                 is refused and nothing was staged",
                self.export.display(),
                hex::encode(record.device_id.as_bytes()),
                hex::encode(held.fingerprint.as_bytes())
            ),
            None => {}
        }
        let mut other = false;
        scan(&self.journal, JOURNAL_KINDS, |_, line| {
            other |= line.device_id == record.device_id && line.fingerprint != record.fingerprint;
            Ok(())
        })?;
        if other {
            bail!(
                "{} holds another controller key for device id {}, which may be on a part \
                 awaiting --resume; choose another device id. Nothing was staged",
                self.journal.display(),
                hex::encode(record.device_id.as_bytes())
            );
        }
        Ok(())
    }

    fn in_export(&self, record: Record) -> Result<InExport> {
        let mut found = InExport {
            held: None,
            of_key: None,
        };
        // Sixteen bytes per record, bounded by the file being read.
        let mut seen = std::collections::HashSet::new();
        scan(&self.export, EXPORT_KINDS, |_, line| {
            if !seen.insert(*line.device_id.as_bytes()) {
                bail!(
                    "device id {} is recorded twice",
                    hex::encode(line.device_id.as_bytes())
                );
            }
            if line.device_id == record.device_id {
                found.held = Some(*line);
            }
            if line.fingerprint == record.fingerprint {
                found.of_key = Some(*line);
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// After the part confirmed it applied the key whose fingerprint is
    /// `applied`: export the station's own record for it. The fingerprint is
    /// only a key to look up here. The record's source is the journal's
    /// drawn pair for this device id, or, for a `--replace` that kept the
    /// key, the export file's earlier record of that key.
    pub fn confirm(&self, device_id: DeviceId, applied: Fingerprint) -> Result<Exported> {
        let wanted = Record {
            device_id,
            fingerprint: applied,
        };
        let found = self.in_export(wanted)?;
        match found.held {
            Some(held) if held == wanted => return Ok(Exported::AlreadyHeld(held)),
            Some(held) => bail!(
                "{} records device id {} with fingerprint {}, but the part applied {}; nothing \
                 exported",
                self.export.display(),
                hex::encode(device_id.as_bytes()),
                hex::encode(held.fingerprint.as_bytes()),
                hex::encode(applied.as_bytes())
            ),
            None => {}
        }
        let mut drawn = None;
        let mut drawn_other = false;
        let mut replaced = false;
        scan(&self.journal, JOURNAL_KINDS, |kind, line| {
            if line.device_id == device_id {
                match kind {
                    Kind::Drawn if line.fingerprint == applied => drawn = Some(*line),
                    Kind::Drawn => drawn_other = true,
                    Kind::Replaced if line.fingerprint == applied => replaced = true,
                    // A replace journaled onto another key is not this one's.
                    Kind::Replaced | Kind::Exported => {}
                }
            }
            Ok(())
        })?;
        let source = match (drawn, found.of_key) {
            (Some(record), _) => record,
            // Only a replace this ledger journaled for this key reuses the
            // earlier record; another file's transaction does not.
            (None, Some(earlier)) if replaced => Record {
                device_id,
                fingerprint: earlier.fingerprint,
            },
            (None, _) if drawn_other => bail!(
                "the part applied a controller key with fingerprint {} that this station did not \
                 draw for device id {}; nothing exported. The unit needs a key the station \
                 draws: o89-dev store blank --yes, then write-secret",
                hex::encode(applied.as_bytes()),
                hex::encode(device_id.as_bytes())
            ),
            (None, None) if replaced => return Ok(Exported::NoStationRecord),
            (None, _) => bail!(
                "{} has no entry for device id {}'s transaction; resume with the --export file \
                 the write used. Nothing exported",
                self.journal.display(),
                hex::encode(device_id.as_bytes())
            ),
        };
        commit(&self.export, Kind::Exported, source)?;
        Ok(Exported::Appended(source))
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_owned();
    text.push(suffix);
    PathBuf::from(text)
}

/// Add one line to `path` as a new copy renamed over it, synced before and
/// after the rename. The caller has already read the file whole, so the
/// copy carries only lines the station accepts.
fn commit(path: &Path, kind: Kind, record: Record) -> Result<()> {
    let device_id = hex::encode(record.device_id.as_bytes());
    let controller_fp = hex::encode(record.fingerprint.as_bytes());
    let mut text = serde_json::to_string(&Line {
        format: kind.format(),
        version: VERSION,
        device_id: &device_id,
        controller_fp: &controller_fp,
    })
    .context("encoding a record")?;
    text.push('\n');
    let staging = suffixed(path, ".new");
    let written = (|| -> std::io::Result<()> {
        // A copy a cut-off write left behind is replaced whole.
        let mut copy = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staging)?;
        match File::open(path) {
            Ok(mut old) => {
                std::io::copy(&mut old, &mut copy)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        copy.write_all(text.as_bytes())?;
        copy.sync_all()?;
        std::fs::rename(&staging, path)?;
        sync_directory(path)
    })();
    written.with_context(|| format!("writing {} through {}", path.display(), staging.display()))
}

/// Make the rename durable: the directory's entry, not only the file's bytes.
#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)?.sync_all()
}

/// Windows offers no directory handle to sync; the rename is what there is.
#[cfg(not(unix))]
fn sync_directory(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Every record in `path`, one at a time, refusing the file whole if any
/// line is not one of `kinds`. A file that does not exist holds none.
fn scan(
    path: &Path,
    kinds: &[Kind],
    mut each: impl FnMut(Kind, &Record) -> Result<()>,
) -> Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("opening {}", path.display()));
        }
    };
    let mut reader = BufReader::new(file);
    let mut text = String::new();
    // Bounded by the file: each pass consumes at least one byte or ends.
    let mut number = 0u64;
    loop {
        number = number.saturating_add(1);
        text.clear();
        let read = (&mut reader)
            .take(LINE_BYTES)
            .read_line(&mut text)
            .with_context(|| format!("reading line {number} of {}", path.display()))?;
        if read == 0 {
            return Ok(());
        }
        let Some(body) = text.strip_suffix('\n') else {
            bail!(
                "line {number} of {} is cut short or too long; it is not a record the station \
                 wrote, and nothing is read or written past it",
                path.display()
            );
        };
        let (kind, record) =
            parse(body, kinds).with_context(|| format!("line {number} of {}", path.display()))?;
        each(kind, &record).with_context(|| format!("line {number} of {}", path.display()))?;
    }
}

fn parse(body: &str, kinds: &[Kind]) -> Result<(Kind, Record)> {
    let line: Line<'_> = serde_json::from_str(body).context("not a record")?;
    let Some(kind) = kinds
        .iter()
        .copied()
        .find(|kind| kind.format() == line.format)
    else {
        bail!("format {} is not one this file holds", line.format);
    };
    if line.version != VERSION {
        bail!("version {}, where {VERSION} is expected", line.version);
    }
    let record = Record {
        device_id: DeviceId::new(lower_hex::<DEVICE_ID_BYTES>(line.device_id, "device_id")?),
        fingerprint: Fingerprint::from_label(lower_hex::<FINGERPRINT_BYTES>(
            line.controller_fp,
            "controller_fp",
        )?),
    };
    Ok((kind, record))
}

fn lower_hex<const N: usize>(text: &str, field: &str) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    hex::decode_to_slice(text, &mut bytes)
        .with_context(|| format!("{field} is not {N} bytes of hex"))?;
    if hex::encode(bytes) != text {
        bail!("{field} is not lowercase hex");
    }
    Ok(bytes)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A directory of its own under the system's temporary one, removed
    /// when the test ends.
    pub struct Scratch(pub PathBuf);

    impl Scratch {
        pub fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "o89-dev-ledger-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        pub fn ledger(&self) -> Ledger {
            Ledger::new(&self.0.join("units.jsonl")).expect("a ledger")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn record(id: u8, fp: u8) -> Record {
        Record {
            device_id: DeviceId::new([id; DEVICE_ID_BYTES]),
            fingerprint: Fingerprint::from_label([fp; FINGERPRINT_BYTES]),
        }
    }

    /// The export file's lines, in order.
    pub fn exported(ledger: &Ledger) -> Vec<String> {
        lines(&ledger.export)
    }

    /// The journal's lines, in order.
    pub fn journaled(ledger: &Ledger) -> Vec<String> {
        lines(&ledger.journal)
    }

    fn lines(path: &Path) -> Vec<String> {
        match std::fs::read_to_string(path) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("reading {}: {error}", path.display()),
        }
    }

    fn confirm(ledger: &Ledger, record: Record) -> Result<Exported> {
        ledger.confirm(record.device_id, record.fingerprint)
    }

    #[test]
    fn p_249_a_confirmed_draw_is_exported_as_one_lowercase_json_line() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        let record = Record {
            device_id: DeviceId::new([0xab; 16]),
            fingerprint: Fingerprint::from_label([0x0c; 16]),
        };
        ledger.note_drawn(record).unwrap();
        assert!(exported(&ledger).is_empty(), "a draw alone is not exported");
        assert_eq!(
            journaled(&ledger),
            [
                r#"{"format":"o89-controller-drawn","version":1,"device_id":"abababababababababababababababab","controller_fp":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"}"#
            ]
        );
        assert_eq!(
            confirm(&ledger, record).unwrap(),
            Exported::Appended(record)
        );
        assert_eq!(
            exported(&ledger),
            [
                r#"{"format":"o89-controller-record","version":1,"device_id":"abababababababababababababababab","controller_fp":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"}"#
            ]
        );
        assert!(!scratch.0.join("units.jsonl.new").exists());
    }

    #[test]
    fn p_249_confirming_the_same_record_twice_writes_it_once() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = confirm(&ledger, record(1, 2)).unwrap();
        assert_eq!(
            confirm(&ledger, record(1, 2)).unwrap(),
            Exported::AlreadyHeld(record(1, 2))
        );
        assert_eq!(exported(&ledger).len(), 1);
    }

    #[test]
    fn p_249_a_second_fingerprint_for_an_exported_device_id_is_refused_before_the_file() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = confirm(&ledger, record(1, 2)).unwrap();
        let before = exported(&ledger);
        let journal_before = journaled(&ledger);
        let error = ledger.note_drawn(record(1, 3)).unwrap_err();
        assert!(error.to_string().contains("second fingerprint"), "{error}");
        assert_eq!(journaled(&ledger), journal_before);
        let error = confirm(&ledger, record(1, 3)).unwrap_err();
        assert!(error.to_string().contains("nothing exported"), "{error}");
        assert_eq!(exported(&ledger), before);
    }

    #[test]
    fn p_249_a_birth_on_a_device_id_the_journal_holds_another_key_for_is_refused() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        // Drawn, not yet confirmed: the key may be on a part awaiting resume.
        ledger.note_drawn(record(1, 2)).unwrap();
        let before = journaled(&ledger);
        let error = ledger.note_drawn(record(1, 3)).unwrap_err();
        assert!(
            error.to_string().contains("choose another device id"),
            "{error}"
        );
        assert_eq!(journaled(&ledger), before);
        ledger.note_drawn(record(4, 3)).unwrap();
    }

    #[test]
    fn p_249_a_key_the_station_drew_for_another_fingerprint_is_a_loud_mismatch() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let error = confirm(&ledger, record(1, 9)).unwrap_err();
        assert!(error.to_string().contains("did not draw"), "{error}");
        assert!(exported(&ledger).is_empty());
    }

    #[test]
    fn p_249_a_replace_onto_a_key_with_no_station_record_exports_nothing() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_replace(record(1, 2)).unwrap();
        assert_eq!(
            confirm(&ledger, record(1, 2)).unwrap(),
            Exported::NoStationRecord
        );
        assert!(exported(&ledger).is_empty());
    }

    #[test]
    fn p_249_a_transaction_the_journal_does_not_hold_is_refused_as_the_wrong_file() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        let error = confirm(&ledger, record(1, 2)).unwrap_err();
        assert!(
            error.to_string().contains("resume with the --export"),
            "{error}"
        );
        assert!(exported(&ledger).is_empty());
        // Another unit's entries do not stand in for this one's.
        ledger.note_replace(record(3, 4)).unwrap();
        assert!(confirm(&ledger, record(1, 2)).is_err());
        assert!(exported(&ledger).is_empty());
    }

    #[test]
    fn p_249_a_kept_key_under_a_new_device_id_takes_the_earlier_record_as_its_source() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = confirm(&ledger, record(1, 2)).unwrap();
        ledger.note_replace(record(7, 2)).unwrap();
        assert_eq!(
            confirm(&ledger, record(7, 2)).unwrap(),
            Exported::Appended(record(7, 2))
        );
        assert_eq!(exported(&ledger).len(), 2);
        // The key's record in an export whose journal never saw this
        // transaction is not a source: that is another file's replace.
        let elsewhere = Scratch::new();
        let other = elsewhere.ledger();
        std::fs::copy(&ledger.export, &other.export).unwrap();
        assert!(confirm(&other, record(8, 2)).is_err());
        assert_eq!(exported(&other).len(), 2);
        // The same device id replaced with the key it has: nothing new.
        ledger.note_replace(record(1, 2)).unwrap();
        assert_eq!(
            confirm(&ledger, record(1, 2)).unwrap(),
            Exported::AlreadyHeld(record(1, 2))
        );
        assert!(ledger.note_replace(record(1, 5)).is_err());
    }

    #[test]
    fn p_249_a_replace_onto_a_device_id_drawn_for_another_key_is_refused_before_staging() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        // Drawn, never confirmed: the key may be on another part.
        ledger.note_drawn(record(1, 2)).unwrap();
        let before = journaled(&ledger);
        let error = ledger.note_replace(record(1, 3)).unwrap_err();
        assert!(error.to_string().contains("Nothing was staged"), "{error}");
        assert_eq!(journaled(&ledger), before);
        ledger.note_replace(record(4, 3)).unwrap();
        assert!(exported(&ledger).is_empty());
    }

    #[test]
    fn p_249_abandoned_draws_do_not_veto_a_replace_the_export_settles() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        // A draw cut off before its stage, then a second that the part took.
        ledger.note_drawn(record(1, 2)).unwrap();
        std::fs::write(
            &ledger.journal,
            journaled(&ledger).join("\n")
                + "\n"
                + r#"{"format":"o89-controller-drawn","version":1,"device_id":"01010101010101010101010101010101","controller_fp":"03030303030303030303030303030303"}"#
                + "\n",
        )
        .unwrap();
        let _ = confirm(&ledger, record(1, 3)).unwrap();
        ledger.note_replace(record(1, 3)).unwrap();
        assert_eq!(
            confirm(&ledger, record(1, 3)).unwrap(),
            Exported::AlreadyHeld(record(1, 3))
        );
        assert_eq!(exported(&ledger).len(), 1);
    }

    #[test]
    fn p_249_a_file_holding_anything_but_the_station_s_records_is_refused_whole() {
        let good = r#"{"format":"o89-controller-record","version":1,"device_id":"01010101010101010101010101010101","controller_fp":"02020202020202020202020202020202"}"#;
        for bad in [
            "not json".to_owned(),
            good.replace("\"version\":1", "\"version\":2"),
            good.replace("o89-controller-record", "o89-controller-drawn"),
            good.replace("\"01010101", "\"0101010G"),
            good.replace("\"01010101", "\"0A010101"),
            good.replace("0101\",", "01\","),
            good.replace('}', ",\"secret\":\"00\"}"),
            good.replace("02020202\"", "02020203\""),
            good.replace(
                "01010101010101010101010101010101",
                "05050505050505050505050505050505",
            ) + "\n"
                + &good.replace(
                    "01010101010101010101010101010101",
                    "05050505050505050505050505050505",
                ),
            good.to_owned() + &" ".repeat(600),
        ] {
            let scratch = Scratch::new();
            let ledger = scratch.ledger();
            std::fs::write(&ledger.export, format!("{good}\n{bad}\n")).unwrap();
            let before = std::fs::read(&ledger.export).unwrap();
            // Both would succeed on the good line alone.
            assert!(confirm(&ledger, record(1, 2)).is_err(), "{bad}");
            assert!(ledger.note_drawn(record(1, 2)).is_err(), "{bad}");
            assert_eq!(std::fs::read(&ledger.export).unwrap(), before);
            assert!(journaled(&ledger).is_empty(), "{bad}");
        }
    }

    #[test]
    fn p_249_a_torn_journal_is_refused_before_anything_is_journaled() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        std::fs::write(&ledger.journal, r#"{"format":"#).unwrap();
        let error = ledger.note_drawn(record(1, 2)).unwrap_err();
        assert!(format!("{error:#}").contains("cut short"), "{error:#}");
        assert!(ledger.note_replace(record(1, 2)).is_err());
        assert_eq!(
            std::fs::read_to_string(&ledger.journal).unwrap(),
            r#"{"format":"#
        );
        // A torn export is refused the same way, and nothing follows it.
        std::fs::write(&ledger.journal, "").unwrap();
        std::fs::write(&ledger.export, r#"{"format":"o89-controller-rec"#).unwrap();
        let error = confirm(&ledger, record(1, 2)).unwrap_err();
        assert!(format!("{error:#}").contains("cut short"), "{error:#}");
        assert!(ledger.note_drawn(record(1, 2)).is_err());
    }

    #[test]
    fn p_249_a_copy_left_by_a_cut_off_write_is_replaced_and_never_read() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        // A cut between the copy and the rename leaves a partial copy.
        std::fs::write(scratch.0.join("units.jsonl.new"), "{\"torn").unwrap();
        assert!(exported(&ledger).is_empty());
        assert_eq!(
            confirm(&ledger, record(1, 2)).unwrap(),
            Exported::Appended(record(1, 2))
        );
        assert_eq!(exported(&ledger).len(), 1);
        assert!(!scratch.0.join("units.jsonl.new").exists());
    }

    #[test]
    fn p_249_a_copy_that_cannot_be_written_leaves_the_export_as_it_was() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = confirm(&ledger, record(1, 2)).unwrap();
        ledger.note_drawn(record(3, 4)).unwrap();
        let before = std::fs::read(&ledger.export).unwrap();
        std::fs::create_dir(scratch.0.join("units.jsonl.new")).unwrap();
        assert!(confirm(&ledger, record(3, 4)).is_err());
        assert_eq!(std::fs::read(&ledger.export).unwrap(), before);
        std::fs::remove_dir(scratch.0.join("units.jsonl.new")).unwrap();
        assert_eq!(
            confirm(&ledger, record(3, 4)).unwrap(),
            Exported::Appended(record(3, 4))
        );
        assert_eq!(exported(&ledger).len(), 2);
    }

    #[test]
    fn a_path_naming_no_file_or_a_directory_is_refused() {
        let scratch = Scratch::new();
        assert!(Ledger::new(Path::new("/")).is_err());
        assert!(Ledger::new(Path::new("..")).is_err());
        assert!(Ledger::new(&scratch.0).is_err());
        let slash = format!("{}/", scratch.0.join("out").display());
        assert!(Ledger::new(Path::new(&slash)).is_err());
        let ledger = Ledger::new(&scratch.0.join("out")).unwrap();
        assert_eq!(ledger.journal, scratch.0.join("out.drawn"));
    }
}
