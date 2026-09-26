#!/usr/bin/env bash
# Refuses a controller flash onto a part whose bootloader is not the one this
# checkout builds (#185).
#
# A board flashed before #185 has an 8 KB bootloader that jumps to
# 0x08002000. A production image linked at 0x08008000 does not overwrite the
# old image's vector table and startup code below that, so the old
# bootloader would run the old startup into the new image's code. Reading
# the bootloader back and comparing it byte for byte with the built one
# catches that board, and any other bootloader, before anything is written.
# `just flash-boot` writes the right one.
#
# Usage: boot-matches.sh BOOT_BIN
set -euo pipefail

chip=STM32G0B1RETx
bin=${1:?usage: boot-matches.sh BOOT_BIN}

if [ ! -s "$bin" ]; then
    echo "boot-matches: $bin is missing or empty; \`just sizes\` builds it" >&2
    exit 2
fi
len=$(wc -c < "$bin" | tr -d ' ')
read_back=$(mktemp)
trap 'rm -f "$read_back"' EXIT

if ! probe-rs read --chip "$chip" --output "$read_back" --format binary b8 0x08000000 "$len"; then
    echo "boot-matches: the bootloader could not be read back" >&2
    exit 1
fi
if ! cmp -s "$bin" "$read_back"; then
    echo "boot-matches: the bootloader on the part is not this checkout's o89-boot; run \`just flash-boot\` first (#185)" >&2
    exit 1
fi
