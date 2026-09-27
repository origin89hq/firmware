//! The station's public record of each unit it made (P-249): which
//! controller fingerprint belongs to which device id, taken from the key the
//! station drew and never from what a part reports. The format is in
//! `crates/o89-dev/EXPORT.md`.
//!
//! Two files, both public. The export file, named by the operator, holds
//! only records the part confirmed; it is what the cloud imports. Beside it,
//! `<export>.drawn` holds the pairs the station drew before it staged them,
//! so a `--resume` in a later process still has the station's own
//! fingerprint to confirm against. A drawn pair whose key never reached the
//! part stays there and is never exported.

use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use km43::{DeviceId, FINGERPRINT_BYTES, Fingerprint};
use o89_core::DEVICE_ID_BYTES;
use serde::{Deserialize, Serialize};

/// The export file's format name and version.
const EXPORTED: Format = Format {
    name: "o89-controller-record",
    version: 1,
};

/// The drawn journal's: distinct, so an import handed the journal refuses it.
const DRAWN: Format = Format {
    name: "o89-controller-drawn",
    version: 1,
};

/// Every line either file holds is 144 bytes with its newline; anything past this is
/// not a line the station wrote, and reading stops there.
const LINE_BYTES: u64 = 512;

#[derive(Clone, Copy)]
struct Format {
    name: &'static str,
    version: u32,
}

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
    /// The station holds no record of the key the part carries, so nothing
    /// was exported: its fingerprint is never taken from the part.
    NoStationRecord,
}

/// The export file and its drawn journal.
pub struct Ledger {
    export: PathBuf,
    drawn: PathBuf,
}

impl Ledger {
    /// The ledger for the operator's export file; neither file need exist.
    pub fn new(export: &Path) -> Result<Self> {
        let mut drawn = export.as_os_str().to_owned();
        drawn.push(".drawn");
        if export.file_name().is_none() {
            bail!("the export file {} names no file", export.display());
        }
        Ok(Self {
            export: export.to_owned(),
            drawn: PathBuf::from(drawn),
        })
    }

    /// The export file's path, for what the operator is told.
    pub fn export(&self) -> &Path {
        &self.export
    }

    /// Before a birth is staged: refuse a device id the export file already
    /// gives another fingerprint, then journal the pair durably. Nothing is
    /// staged unless this returns `Ok`.
    pub fn note_drawn(&self, record: Record) -> Result<()> {
        self.refuse_conflict(record)?;
        append(&self.drawn, DRAWN, record)
    }

    /// Before a `--replace` is staged: refuse a device id the export file
    /// already gives a fingerprint other than the one the part holds now,
    /// or one the station drew another key for, which `confirm` would
    /// refuse only once the part had applied it. The part's fingerprint is
    /// compared here, never recorded.
    pub fn check_replace(&self, record: Record) -> Result<()> {
        self.refuse_conflict(record)?;
        let mut drawn_other = false;
        scan(&self.drawn, DRAWN, |line| {
            drawn_other |=
                line.device_id == record.device_id && line.fingerprint != record.fingerprint;
        })?;
        if drawn_other {
            bail!(
                "{} records a key drawn for device id {} other than the one this unit holds; \
                 choose another device id. Nothing was staged",
                self.drawn.display(),
                hex::encode(record.device_id.as_bytes())
            );
        }
        Ok(())
    }

    fn refuse_conflict(&self, record: Record) -> Result<()> {
        let mut held = None;
        scan(&self.export, EXPORTED, |line| {
            if line.device_id == record.device_id {
                held = Some(*line);
            }
        })?;
        match held {
            Some(held) if held.fingerprint != record.fingerprint => bail!(
                "{} already records device id {} with fingerprint {}; a second fingerprint for it \
                 is refused and nothing was staged",
                self.export.display(),
                hex::encode(record.device_id.as_bytes()),
                hex::encode(held.fingerprint.as_bytes())
            ),
            Some(_) | None => Ok(()),
        }
    }

    /// After the part confirmed it applied the key whose fingerprint is
    /// `applied`: export the station's own record for it. The fingerprint is
    /// only a key to look up here. The record's source is the drawn journal
    /// for this device id, or, for a `--replace` that kept the key, the
    /// export file's earlier record of that key.
    pub fn confirm(&self, device_id: DeviceId, applied: Fingerprint) -> Result<Exported> {
        let wanted = Record {
            device_id,
            fingerprint: applied,
        };
        let mut held = None;
        let mut earlier_key = None;
        scan(&self.export, EXPORTED, |line| {
            if line.device_id == device_id {
                held = Some(*line);
            }
            if line.fingerprint == applied {
                earlier_key = Some(*line);
            }
        })?;
        match held {
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
        scan(&self.drawn, DRAWN, |line| {
            if line.device_id == device_id {
                if line.fingerprint == applied {
                    drawn = Some(*line);
                } else {
                    drawn_other = true;
                }
            }
        })?;
        let source = match (drawn, earlier_key) {
            (Some(record), _) => record,
            (None, Some(earlier)) => Record {
                device_id,
                fingerprint: earlier.fingerprint,
            },
            (None, None) if drawn_other => bail!(
                "the part applied a controller key with fingerprint {} that this station did not \
                 draw for device id {}; nothing exported. The unit needs a key the station \
                 draws: o89-dev store blank --yes, then write-secret",
                hex::encode(applied.as_bytes()),
                hex::encode(device_id.as_bytes())
            ),
            (None, None) => return Ok(Exported::NoStationRecord),
        };
        append(&self.export, EXPORTED, source)?;
        Ok(Exported::Appended(source))
    }
}

/// Append one line and make it durable before returning.
fn append(path: &Path, format: Format, record: Record) -> Result<()> {
    let device_id = hex::encode(record.device_id.as_bytes());
    let controller_fp = hex::encode(record.fingerprint.as_bytes());
    let mut text = serde_json::to_string(&Line {
        format: format.name,
        version: format.version,
        device_id: &device_id,
        controller_fp: &controller_fp,
    })
    .context("encoding a record")?;
    text.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("appending to {}", path.display()))
}

/// Every record in `path`, one at a time, refusing the file whole if any
/// line is not one of `format`'s. A file that does not exist holds none.
fn scan(path: &Path, format: Format, mut each: impl FnMut(&Record)) -> Result<()> {
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
    for number in 1u64.. {
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
        let record =
            parse(body, format).with_context(|| format!("line {number} of {}", path.display()))?;
        each(&record);
    }
    Ok(())
}

fn parse(body: &str, format: Format) -> Result<Record> {
    let line: Line<'_> = serde_json::from_str(body).context("not a record")?;
    if line.format != format.name || line.version != format.version {
        bail!(
            "format {} version {}, where {} version {} is expected",
            line.format,
            line.version,
            format.name,
            format.version
        );
    }
    Ok(Record {
        device_id: DeviceId::new(lower_hex::<DEVICE_ID_BYTES>(line.device_id, "device_id")?),
        fingerprint: Fingerprint::from_label(lower_hex::<FINGERPRINT_BYTES>(
            line.controller_fp,
            "controller_fp",
        )?),
    })
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
        match std::fs::read_to_string(&ledger.export) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("reading the export: {error}"),
        }
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
            ledger
                .confirm(record.device_id, record.fingerprint)
                .unwrap(),
            Exported::Appended(record)
        );
        assert_eq!(
            exported(&ledger),
            [
                r#"{"format":"o89-controller-record","version":1,"device_id":"abababababababababababababababab","controller_fp":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"}"#
            ]
        );
    }

    #[test]
    fn p_249_confirming_the_same_record_twice_writes_it_once() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        let record = record(1, 2);
        ledger.note_drawn(record).unwrap();
        let _ = ledger
            .confirm(record.device_id, record.fingerprint)
            .unwrap();
        assert_eq!(
            ledger
                .confirm(record.device_id, record.fingerprint)
                .unwrap(),
            Exported::AlreadyHeld(record)
        );
        assert_eq!(exported(&ledger).len(), 1);
    }

    #[test]
    fn p_249_a_second_fingerprint_for_an_exported_device_id_is_refused_before_the_file() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = ledger.confirm(record(1, 2).device_id, record(1, 2).fingerprint);
        let before = exported(&ledger);
        let drawn_before = std::fs::read(&ledger.drawn).unwrap();
        let error = ledger.note_drawn(record(1, 3)).unwrap_err();
        assert!(error.to_string().contains("second fingerprint"), "{error}");
        assert_eq!(std::fs::read(&ledger.drawn).unwrap(), drawn_before);
        let error = ledger
            .confirm(record(1, 3).device_id, record(1, 3).fingerprint)
            .unwrap_err();
        assert!(error.to_string().contains("nothing exported"), "{error}");
        assert_eq!(exported(&ledger), before);
    }

    #[test]
    fn p_249_a_key_the_station_drew_for_another_fingerprint_is_a_loud_mismatch() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let error = ledger
            .confirm(record(1, 9).device_id, record(1, 9).fingerprint)
            .unwrap_err();
        assert!(error.to_string().contains("did not draw"), "{error}");
        assert!(exported(&ledger).is_empty());
    }

    #[test]
    fn p_249_a_key_with_no_station_record_exports_nothing() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        assert_eq!(
            ledger
                .confirm(record(1, 2).device_id, record(1, 2).fingerprint)
                .unwrap(),
            Exported::NoStationRecord
        );
        assert!(exported(&ledger).is_empty());
        assert!(!ledger.drawn.exists());
    }

    #[test]
    fn p_249_a_kept_key_under_a_new_device_id_takes_the_earlier_record_as_its_source() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        ledger.note_drawn(record(1, 2)).unwrap();
        let _ = ledger.confirm(record(1, 2).device_id, record(1, 2).fingerprint);
        ledger.check_replace(record(7, 2)).unwrap();
        assert_eq!(
            ledger
                .confirm(record(7, 2).device_id, record(7, 2).fingerprint)
                .unwrap(),
            Exported::Appended(record(7, 2))
        );
        assert_eq!(exported(&ledger).len(), 2);
        // The same device id replaced with the key it has: nothing new.
        ledger.check_replace(record(1, 2)).unwrap();
        assert!(ledger.check_replace(record(1, 5)).is_err());
    }

    #[test]
    fn p_249_a_replace_onto_a_device_id_drawn_for_another_key_is_refused_before_staging() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        // Drawn, never confirmed: the key never reached a part.
        ledger.note_drawn(record(1, 2)).unwrap();
        let error = ledger.check_replace(record(1, 3)).unwrap_err();
        assert!(error.to_string().contains("Nothing was staged"), "{error}");
        ledger.check_replace(record(1, 2)).unwrap();
        ledger.check_replace(record(4, 3)).unwrap();
        assert!(exported(&ledger).is_empty());
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
            good.to_owned() + &" ".repeat(600),
        ] {
            let scratch = Scratch::new();
            let ledger = scratch.ledger();
            std::fs::write(&ledger.export, format!("{good}\n{bad}\n")).unwrap();
            let before = std::fs::read(&ledger.export).unwrap();
            assert!(
                ledger
                    .confirm(record(1, 2).device_id, record(1, 2).fingerprint)
                    .is_err(),
                "{bad}"
            );
            assert!(ledger.note_drawn(record(3, 4)).is_err(), "{bad}");
            assert_eq!(std::fs::read(&ledger.export).unwrap(), before);
        }
    }

    #[test]
    fn p_249_a_torn_last_line_is_refused_and_not_appended_after() {
        let scratch = Scratch::new();
        let ledger = scratch.ledger();
        std::fs::write(&ledger.export, r#"{"format":"o89-controller-rec"#).unwrap();
        let error = ledger
            .confirm(record(1, 2).device_id, record(1, 2).fingerprint)
            .unwrap_err();
        assert!(format!("{error:#}").contains("cut short"), "{error:#}");
    }

    #[test]
    fn a_path_naming_no_file_is_refused() {
        assert!(Ledger::new(Path::new("/")).is_err());
        assert!(Ledger::new(Path::new("..")).is_err());
    }
}
