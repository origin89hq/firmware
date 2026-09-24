#!/usr/bin/env python3
"""Import KM43 docs/protocol/vectors/v1.json BLE traces without a runtime JSON allocator.

Usage: python3 crates/o89-comms-core/tests/import_ble_vectors.py /path/to/v1.json
The source JSON stays owned by KM43; this fixture preserves every BLE action.
"""
import hashlib
import json
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_bytes()
rows = json.loads(source)["ble"]
fields = ("action", "mtu", "now_ms", "input", "expected", "output", "value_limit")
lines = [
    "# Generated from origin89hq/km43 docs/protocol/vectors/v1.json (km43 0.6.0).",
    "# Source SHA-256: " + hashlib.sha256(source).hexdigest(),
    "# Regenerate with tests/import_ble_vectors.py; do not edit traces by hand.",
    "# " + "|".join(fields),
]
for row in rows:
    assert set(row).issubset(fields)
    lines.append("|".join(str(row.get(key, "")) for key in fields))
Path(__file__).with_name("ble-vectors.txt").write_text("\n".join(lines) + "\n")
