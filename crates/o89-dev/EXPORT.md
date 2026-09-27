# Controller records from the station

`o89-dev store write-secret --export <file>` appends each unit's public
record to `<file>`: which controller fingerprint belongs to which device id.
An operator imports the file through the cloud's authenticated admin
endpoint, and the cloud checks a controller's vouch against it before it
links the unit (P-247, P-249). The file is public, every label prints the
same values, but its integrity is what the check rests on.

## Format

One JSON object per line, each line ending in `\n`, UTF-8, no blank lines.
An example line, with made-up values:

```json
{"format":"o89-controller-record","version":1,"device_id":"0123456789abcdef0123456789abcdef","controller_fp":"8f3c0a1e5b7d9f2468ace13579bdf024"}
```

| Field | Value |
| --- | --- |
| `format` | Always `o89-controller-record`. |
| `version` | Always `1`. A change to any field's meaning is a new version. |
| `device_id` | The unit's 16-byte device id, 32 lowercase hex characters. |
| `controller_fp` | The P-236 fingerprint of the unit's controller key, 16 bytes, 32 lowercase hex characters. |

The station writes the fields in this order and nothing else. An importer
should refuse a line with any other field, format, version, length or case,
and refuse the whole file rather than import part of it.

The station guarantees, for one file:

- A `device_id` appears at most once. The station refuses a second
  fingerprint for a device id before staging anything, so an importer that
  finds one should treat the file as damaged.
- A `controller_fp` can appear under more than one `device_id`. After
  `write-secret --replace` gives a unit a new device id and keeps its key,
  the new id is recorded with the fingerprint the station recorded earlier.
  The old id's printed secret no longer works on the unit.
- A line is written only after the part confirmed it applied the key the
  station drew, and the fingerprint comes from that drawn key, never from
  what the part reports.
- No private key, generator state, printed secret or pairing payload is
  written to it.

The cloud decides what to do when an import would change the fingerprint it
already holds for a device id; P-249 says it refuses and tells a person.

## The journal beside it

`<file>.drawn` is the station's journal, written and synced before anything
is staged, so that `--resume` in a later process can confirm the part against
the station's own entry. It holds the same fields under two format names:

- `o89-controller-drawn`: a key the station drew for a birth, with its
  fingerprint. This is the only source of a new record's fingerprint.
- `o89-controller-replace`: a `--replace`, with the fingerprint the part held
  when it was staged. It is a lookup key for the export file, never exported.

A key that never reached the part stays in the journal and is never exported.
The journal is not for import; its format names make an importer refuse it.
Keep it beside the export file: a `--resume` whose journal has no entry for
the unit's transaction is refused as the wrong file, prints no label, and can
be run again with the right `--export`.

## Writes

Each file changes only by writing a new copy, `<name>.new`, syncing it,
renaming it over the old one and syncing the directory. A host cut off
mid-write leaves the file as it was or with its new line, never a torn line;
a `<name>.new` left behind is replaced by the next write. Before a write the
station reads both files whole and refuses anything but its own lines,
including a device id recorded twice, before a key is staged.

## Refusals and when nothing is exported

- A device id the export file records with another fingerprint is refused
  before anything is staged.
- A device id the journal holds another key for is refused before anything is
  staged, unless the export file already records that device id with this
  unit's key: the other key may be on a part awaiting `--resume`. Choose
  another device id.
- A part that applied a key the station did not draw for that device id is
  refused loudly: no label, nothing exported, and every `--resume` refuses the
  same way. Such a unit needs a key the station draws: `o89-dev store blank
  --yes`, then `write-secret`.
- `write-secret --replace` prints the label and says `record none exported`
  when the export file holds no record of the key the unit carries: a unit
  born before records were kept, or on another station. The part's
  fingerprint is not taken as a record's source, so such a unit has no record
  until its key is drawn again (`o89-dev store blank --yes`, then
  `write-secret`).

One station process writes a file at a time; two processes writing the same
file are not coordinated.
