# Origin89 firmware. `just` on its own lists every recipe.

firmwares := "--manifest-path firmwares/Cargo.toml"
cortex := "thumbv6m-none-eabi"
riscv := "riscv32imac-unknown-none-elf"

default:
    @just --list --unsorted

# Everything CI runs, in the order it runs it. Run this before pushing.
check: fmt-check lint test gate

# Format both workspaces in place.
fmt:
    cargo fmt --all
    cargo fmt --all {{firmwares}}

fmt-check:
    cargo fmt --all --check
    cargo fmt --all --check {{firmwares}}

# Clippy with -D warnings on the host workspace and on each image for its
# target. Not `--all-targets` for the images: there is no test harness for a
# `no_main` binary, and asking for one fails on `can't find crate for test`.
lint:
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-boot --target {{cortex}} -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-controller --target {{cortex}} -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features devkit -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features frames -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features no-flow -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features cuts -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features crash-at-boot -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-comms --target {{riscv}} --features no-window -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-controller --target {{cortex}} --features frames -- -D warnings
    cargo clippy --locked {{firmwares}} -p o89-controller --target {{cortex}} --features no-flow -- -D warnings

# The host suite, including the compile-fail doctests.
test:
    cargo test --locked --workspace

# The inner-loop subset, without doctests.
test-fast:
    cargo test --locked --workspace --lib --tests

# The gate `cargo test` cannot be: cross-compiles, the dependency rules, the
# three images built in release and measured against their slots.
gate:
    cargo xtask check

# Build the three images and print their sizes. `--record` appends a row per
# image to docs/sizes.tsv named by the commit at HEAD: run it on `main` after
# a merge, because a branch's commits are rewritten by the squash and a row
# naming one of them names nothing. A pull request states its sizes in words.
# `--from <dir>` measures a directory `just reproducible` wrote instead of
# building, and names the commit its manifest names.
[positional-arguments]
sizes *args:
    cargo xtask sizes "$@"

# Build the three images as release artifacts into `out`, which must not
# exist, from the commit at HEAD of a clean checkout: staged at one fixed
# path in the pinned container of `xtask/reproducible/Dockerfile`, with the
# epoch the environment gives, so any clean checkout of the commit makes the
# same bytes (#74). Needs Docker and SOURCE_DATE_EPOCH, usually
# `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`. A release is flashed or
# published from `out` after `reproducible-verify`, never rebuilt. Touches
# no board. Arguments reach the command as they were given, spaces and
# all, never through the shell's parsing.
[positional-arguments]
reproducible out *args:
    out="$1"; shift; cargo xtask reproducible build --out "$out" "$@"

# Check every file in a release directory against its manifest.
[positional-arguments]
reproducible-verify dir:
    cargo xtask reproducible verify "$1"

# Refuse two release directories that differ in any byte or input.
[positional-arguments]
reproducible-compare first second:
    cargo xtask reproducible compare "$1" "$2"

# Refresh the shared skills once at the start of a task.
skills-sync:
    python3 .origin89/sync-engineering.py

# Build the module's second-stage bootloader from the pinned ESP-IDF in
# Espressif's container, with app rollback enabled (F-088), into
# `firmwares/o89-comms/bootloader/`. Needs Docker. Touches no board; the
# whole route of `dev-flash-comms-whole` is what puts it on one.
comms-bootloader:
    firmwares/o89-comms/bootloader/build.sh

# ---------------------------------------------------------------------------
# Flashing, erasing and resetting: never run from `check`. Before any of these
# against a board, name the exact target, the expected effect, the safe setup
# and the recovery path. Board B is plugged and unplugged with 12 V off.
#
# Every controller flash, here and through the crates' `probe-rs run`
# runners, and every attach and reset goes through
# `firmwares/frozen-watchdog.sh`: the IWDG is frozen while the probe holds
# the core halted and thawed when the command ends, and the vector catches
# a probe session leaves armed are disarmed around it (#155). It does not
# stop the watchdog boot record a flash can leave (#125).
# ---------------------------------------------------------------------------

chip := "STM32G0B1RETx"
controller_elf := "firmwares/target/thumbv6m-none-eabi/release/o89-controller"
comms_elf := "firmwares/target/riscv32imac-unknown-none-elf/release/o89-comms"
boot_elf := "firmwares/target/thumbv6m-none-eabi/release/o89-boot"
boot_bin := "firmwares/target/thumbv6m-none-eabi/release/o89-boot.bin"

# Flash the bootloader at 0x08000000, then reset the part, because
# `probe-rs download` leaves the part halted in its flash loader with every
# pin an input, and the transceivers drive their buses low on a floating DI
# (origin89hq/hardware#28). Effect: the part boots through the bootloader,
# which drives RUN and KICK low and jumps to 0x08008000. Recovery:
# `just flash-controller` if the application is not there yet; the part
# waits with the lines low until it is. A board flashed before #185 has an
# 8 KB bootloader that jumps to 0x08002000, and needs this before its first
# production flash; `flash-controller` refuses it until then.
#
# Flash the bootloader into the controller, then reset it.
flash-boot: sizes
    firmwares/frozen-watchdog.sh sh -c '\
      probe-rs download --chip {{chip}} --verify {{boot_elf}} && \
      probe-rs reset --chip {{chip}}'

# Flash the production controller image at 0x08008000, then reset the part:
# `probe-rs download` alone leaves it halted in its flash loader with every
# pin an input, which is a controller that runs nothing and buses driven low
# by floating DIs (origin89hq/hardware#28). Needs the bootloader in front of
# it (`just flash-boot`): the bootloader is read back first and the flash
# refused unless it is this checkout's (`firmwares/boot-matches.sh`), so a
# board with another bootloader is never left jumping into the wrong image.
# Effect: the controller boots in the order the hazards dictate. Recovery:
# `just flash-controller` again, or `just run-controller-bench` to bypass
# the bootloader, after which `just flash-boot` has to come before the next
# production flash.
#
# Flash the production controller image at 0x08008000 and reset the part.
flash-controller: sizes
    firmwares/frozen-watchdog.sh sh -c '\
      firmwares/boot-matches.sh {{boot_bin}} && \
      probe-rs download --chip {{chip}} --verify {{controller_elf}} && \
      probe-rs reset --chip {{chip}}'

# Flash and run the production controller image with the log on the probe.
# The runner is `probe-rs run`, which flashes the ELF's own regions only, so
# the bootloader stays, and it is checked first as `flash-controller` checks
# it. Effect: as `flash-controller`, then the defmt log.
# Every recipe here that builds an image takes the gate's flags from
# `cargo xtask rustflags` (the path remapping, SHA-256's compact backend), so
# the bytes a bench flashes are the bytes the gate measured.
#
# Flash and run the production controller image with the log on the probe.
run-controller: sizes
    firmwares/frozen-watchdog.sh firmwares/boot-matches.sh {{boot_bin}}
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-controller && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release

# Flash and run the BENCH image: linked at 0x08000000 with no bootloader, and
# carrying the one-shot proofs. Effect: overwrites the bootloader's 32 KB,
# starves the watchdog fifteen seconds into a boot the watchdog did
# not cause, panics fifteen seconds into the boot after a watchdog reset, and
# runs from the boot after that. Never on a unit that will take an update.
# Recovery: `just flash-boot` then `just flash-controller` restore the
# production layout. `flash-controller` alone does not: it writes from
# 0x08008000 up, the bench image's vector table stays at the bottom, and every
# reset jumps into the production image's code at the bench image's
# addresses. That reads as a firmware fault: a reset loop or a lockup at a PC
# inside no function's first instruction (bench 2026-09-25). Check with
# `probe-rs read --chip STM32G0B1RETx b32 0x08000000 2`: `o89-boot` is
# `20024000 080000c1`.
#
# Flash and run the BENCH image at 0x08000000 with the one-shot proofs; never on a unit that will take an update.
run-controller-bench:
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-controller && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release --features bench

# As `run-controller-bench`, halting on the panic with its message on the
# probe instead of writing the last words and resetting: for chasing a panic,
# not for proving the path.
#
# The bench image halting on a panic with the message on the probe, for chasing one.
run-controller-bench-halting:
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-controller && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release --features bench,panic-probe

# FLASH and run the comms image on an ESP32-C6 devkit over the devkit's own
# USB serial, with espflash's monitor. Never board A: its module has no
# serial wire but the link, and the image reaches it through the controller.
# Run from the crate's directory, where the runner finds `partitions.csv`,
# with the `devkit` feature, so its `LinkUp` names the devkit as its board.
# Effect: the devkit's flash is replaced, partition table included.
# Recovery: run it again, holding the devkit's BOOT button through its reset
# if the image does not start.
#
# FLASH and run the comms image on a devkit over its own USB serial; never board A.
run-comms-devkit:
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-comms && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release --features devkit

# Read the defmt log of whatever the controller is running, without flashing
# or resetting it: the way to read a boot record after a reset the probe did
# not cause. `elf` is the image on the part, for the log's strings. A reset
# or a hard fault during the attach runs through the firmware as it would
# unattached, rather than ending it with the core held (#155); the runners
# keep the hard-fault catch, which `run-controller-bench-halting` needs.
#
# Read the controller's log without flashing or resetting it.
attach-controller elf=controller_elf:
    firmwares/frozen-watchdog.sh probe-rs attach --chip {{chip}} --no-catch-reset --no-catch-hardfault {{elf}}

# Read the controller's flash option register and refuse a part whose
# banks are swapped. Revision A's layout needs nSWAP_BANK = 1 (bit 20 of
# FLASH_OPTR), which maps bank 1, with the bootloader, at 0x08000000; with
# it 0 the part maps bank 2 there, which may be blank, and a blank bottom of
# flash starts ST's system bootloader (origin89hq/hardware#30, #185). Reads
# only. Run it on a board before it leaves the bench.
#
# Check the controller's flash option bytes; reads only.
check-option-bytes:
    #!/usr/bin/env bash
    set -euo pipefail
    optr=$(firmwares/frozen-watchdog.sh probe-rs read --chip {{chip}} b32 0x40022020 1 | awk 'END {print $2}')
    value=$((16#$optr))
    swap=$(( (value >> 20) & 1 ))
    dual=$(( (value >> 21) & 1 ))
    rdp=$(( value & 0xFF ))
    printf 'FLASH_OPTR %s: nSWAP_BANK %d, DUAL_BANK %d, RDP 0x%02X\n' "$optr" "$swap" "$dual" "$rdp"
    if [ "$swap" -ne 1 ]; then
        echo "check-option-bytes: nSWAP_BANK is 0, so bank 2 is at 0x08000000; revision A needs 1 (#185)" >&2
        exit 1
    fi

# Reset the controller through the probe. Effect: a pin-class reset; the
# boot record on the next attach says so.
#
# Reset the controller through the probe.
reset-controller:
    firmwares/frozen-watchdog.sh probe-rs reset --chip {{chip}}

# MASS ERASE the controller. Effect: an empty flash, on which the ST system
# bootloader runs and can pull RUN to 2.1-2.6 V and pulse KICK
# (origin89hq/hardware#30): only with nothing on board B's CN10, and only on
# a spare board. Recovery: `just flash-boot` then `just flash-controller`.
#
# MASS ERASE the controller: only a spare board, nothing on board B's CN10.
[confirm("Mass erase the connected controller? Only a spare board, with nothing on board B's CN10.")]
erase-controller:
    probe-rs erase --chip {{chip}}

# The bench tool: the controller's FRAM, NOR and rail over the probe, through
# the mailbox the running firmware serves. Nothing below flashes; the part
# keeps running what it runs. `just dev-ping` first: it says whether a
# firmware with a mailbox is there. A second probe session cannot share the
# probe, so `attach-controller` and these take turns.
#
# Ask the running firmware for its boot count.
dev-ping *args:
    cargo run -q -p o89-dev -- {{args}} ping

# Every record of the store, decoded, as the firmware reads them.
dev-store *args:
    cargo run -q -p o89-dev -- {{args}} store

# The module rail: the pin as the registers say and what it means on the revision (a or b).
dev-rail revision *args:
    cargo run -q -p o89-dev -- {{args}} rail --revision {{revision}}

# Bytes of the FRAM in hex, from `at` for `len`.
dev-fram at="0" len="256" *args:
    cargo run -q -p o89-dev -- {{args}} fram --at {{at}} --len {{len}}

# The event ring's newest `count` records, decoded, newest first: a boot's
# reason, backup domain and last words spelled out.
dev-ring count="20" *args:
    cargo run -q -p o89-dev -- {{args}} ring --count {{count}}

# Bytes of the NOR in hex, from `at` for `len`.
dev-nor at="0" len="256" *args:
    cargo run -q -p o89-dev -- {{args}} nor --at {{at}} --len {{len}}

# WRITE the epoch record on the FRAM, only ever upward. Effect: the boot
# after it derives every key under this epoch and clears a client table
# stamped below it. Recovery: none needed; a higher epoch is always allowed.
#
# WRITE the epoch record on the FRAM, only upward.
dev-write-epoch epoch *args:
    cargo run -q -p o89-dev -- {{args}} store write-epoch {{epoch}}

# WRITE the device secret on the FRAM: a fresh id and printed secret from the
# operating system's generator, shown once. Effect: the unit can enrol
# clients. Refused when one is held; `--replace` orphans every client
# enrolled under the old one. Recovery: none; a replaced secret is gone.
#
# WRITE the device secret on the FRAM, shown once; refused when one is held.
dev-write-secret *args:
    cargo run -q -p o89-dev -- store write-secret {{args}}

# DROP the event ring's `count` oldest 4 KiB blocks, one request each, the
# oldest first. Effect: the records in them are gone and the oldest sequence
# moves up; the next sequence is untouched until the last block goes, when
# the ring is empty and starts again at one. Recovery: none; the log is the
# log.
#
# DROP the ring's oldest blocks; the records in them are gone.
dev-drop-ring count="1" *args:
    cargo run -q -p o89-dev -- {{args}} drop-ring --count {{count}}

# ERASE `count` 4 KiB blocks of the NOR outside the event ring from `block`,
# one request each. A block of the ring's is refused: only the oldest goes,
# with `dev-drop-ring` (#78). Effect: what those blocks held is gone.
# Recovery: none.
#
# ERASE NOR blocks outside the ring from `block`.
dev-erase-nor block count="1" *args:
    cargo run -q -p o89-dev -- {{args}} erase-nor {{block}} --count {{count}}

# RESET the controller through the firmware. Effect: a software reset, a
# boot record on the ring and one more on the boot count; the module rail
# does what the revision's policy says through a reset.
#
# RESET the controller through the firmware's mailbox.
dev-reboot *args:
    cargo run -q -p o89-dev -- {{args}} reboot

# FLASH the comms image into an OTA slot of the module, through the
# controller (F-038, F-084): the firmware resets the module, knocks inside its
# download window and bridges the ROM's UART to the mailbox; esptool blanks
# the otadata, writes the application into `ota_0`, and names the slot once it
# has landed. Effect: the module reboots on the new application; the
# bootloader, the partition table and the factory image are untouched.
# Recovery: run it again. A transfer that dies leaves the module booting the
# factory image, which honours the window, so the next run needs no wire.
# Needs `uvx` for esptool. The images are built first, so what is flashed is
# the source as it stands.
#
# FLASH the comms image into an OTA slot; the recovery image is kept.
# `--layout` is fixed here, so `--layout whole` in the arguments is refused
# rather than silently taking the destructive route past this recipe's
# promise; the whole flash is `dev-flash-comms-whole`, behind its confirm.
dev-flash-comms *args: sizes
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# FLASH THE WHOLE MODULE FLASH from address 0: the bootloader, the partition
# table and the factory image with it. For bringing a module up the first
# time, or restoring one whose factory image is gone. Both boot nothing and
# answer no knock, so this enters by the strap, which on revision A needs a
# wire holding IO8 high (hardware#6); pass `--entry knock` to replace the
# factory image of a module that is running. Effect: the bootloader, the
# partition table, the `otadata` and the factory image are replaced, and from
# the first erase until esptool finishes the module boots nothing. It is not
# an erase of the part: the image stops where the factory app ends, so both
# OTA slots, the credential record and the assets are left exactly as they
# were. A module flashed this way still holds the credentials it held before,
# and this is not the way to clear them. Recovery: run it again, with the
# wire. Use `dev-flash-comms` for ordinary work.
#
# FLASH THE WHOLE MODULE FLASH, factory image included; leaves no way back but the strap.
[confirm("Replace the whole module flash, the factory image that carries the download window included? A transfer that dies leaves the strap as the only way in.")]
dev-flash-comms-whole *args: sizes
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout whole --yes {{args}}


# FLASH and run the controller with the frames bench's counters (F-087):
# the production image plus a tally of what the link read — frames whose
# CRC held, frames refused, part-frames abandoned, read-reported errors —
# with changed tallies logged each second, including after traffic stops.
# Effect: as `run-controller`, then the log. Pair it with
# `dev-flash-comms-frames` on the module, which sends the frames.
# Recovery: `just flash-controller` restores the ordinary image.
#
# FLASH and run the controller with the frames bench's counters.
run-controller-frames:
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-controller && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release --features frames

# FLASH and run the controller with the frames bench and NO FLOW CONTROL
# (F-087): USART1 opened without RTS and CTS, which is the half of the rule
# that has to fail. Effect: as `run-controller-frames`, with nothing holding
# the module off; frames are refused and the link may drop. Recovery:
# `just flash-controller` restores the ordinary image.
#
# Pair with `dev-flash-comms-frames-no-flow`: the sender must ignore CTS,
# since this controller leaves that net undriven.
# FLASH and run the controller with the frames bench and no flow control.
run-controller-frames-no-flow:
    flags="$(cargo xtask rustflags)" && cd firmwares/o89-controller && CARGO_ENCODED_RUSTFLAGS="$flags" cargo run --release --features no-flow

# FLASH the comms image built with the frames bench onto the module, into
# its OTA slot (F-087): after a matching bench-controller identity and heartbeat it
# sends ten thousand worst-case frames at the link's rate, in batches
# between turns of its loop so the controller's heartbeats are still
# answered and the ladder never cuts the rail mid-run. Effect: the module replaces its slot image
# and then puts about 10 MB on the link; the batch/read cadence sets the duration. It
# answers the link normally throughout and does nothing else. Recovery:
# `just dev-flash-comms` puts the ordinary image back; the factory image
# is untouched either way. Run `run-controller-frames` first, so something
# is counting.
#
# FLASH the module with the frames bench; it sends 10 000 frames once linked.
dev-flash-comms-frames *args:
    flags="$(cargo xtask rustflags)" && CARGO_ENCODED_RUSTFLAGS="$flags" cargo build --release {{firmwares}} -p o89-comms --target {{riscv}} --features frames
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# FLASH the no-flow bench sender into its OTA slot. CTS is disabled in the
# sender so an undriven controller RTS cannot stall it. Recovery is the same
# as `dev-flash-comms-frames`. Flash this while the controller still has
# flow control, then start `run-controller-frames-no-flow`. The sender waits
# for that controller's matching bench identity and a validated heartbeat.
dev-flash-comms-frames-no-flow *args:
    flags="$(cargo xtask rustflags)" && CARGO_ENCODED_RUSTFLAGS="$flags" cargo build --release {{firmwares}} -p o89-comms --target {{riscv}} --features no-flow
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# FLASH the cut bench into the module's OTA slot (F-086): the frames bench
# with the pair pulled on the wire a thousand times by the sender itself,
# each pull three frames: one cut short of its delimiter, one that runs
# into the fragment and is refused with it, one that must arrive whole.
# Effect: as `dev-flash-comms-frames`, with 3 000 frames; the controller's
# tally must read 1 000 arrived, highest 3 000, 1 000 refused, none
# abandoned, the link up once. Recovery: `just dev-flash-comms`. Run with
# `run-controller-frames`, whose counters read the outcome.
#
# FLASH the module with the cut bench; it pulls the pair a thousand times once linked.
dev-flash-comms-cuts *args:
    flags="$(cargo xtask rustflags)" && CARGO_ENCODED_RUSTFLAGS="$flags" cargo build --release {{firmwares}} -p o89-comms --target {{riscv}} --features cuts
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# FLASH the image #1's acceptance test delivers first: one that panics as
# its first statement, before its window (F-088). Effect: the module boots
# it from `ota_0`, the bootloader marks the slot pending, the panic resets
# the part, and at that reset the bootloader marks the slot aborted and
# boots the factory image, which honours the window; the controller's log
# shows the module linking on the factory image's version. Recovery: none
# needed, that is the test; `just dev-flash-comms` then puts the ordinary
# image back through the window, with no wire. Needs the module to hold the
# rollback bootloader (`dev-flash-comms-whole --entry knock`, once).
#
# FLASH the acceptance image that crashes before its window; the bootloader must roll it back.
dev-flash-comms-crash *args:
    flags="$(cargo xtask rustflags)" && CARGO_ENCODED_RUSTFLAGS="$flags" cargo build --release {{firmwares}} -p o89-comms --target {{riscv}} --features crash-at-boot
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# FLASH the image #1's acceptance test delivers second: one whose window is
# omitted, and with it the proof its slot could be confirmed against
# (F-089). Effect: the module runs it and links, stating `-nw`, and cannot
# confirm the slot; the next reset of the module, which the next flash's
# knock makes, has the bootloader boot the factory image instead, whose
# window answers the knock. Recovery: `just dev-flash-comms`, which is the
# second half of the test. Needs the rollback bootloader as above.
#
# FLASH the acceptance image whose window is omitted; the next reset must roll it back.
dev-flash-comms-no-window *args:
    flags="$(cargo xtask rustflags)" && CARGO_ENCODED_RUSTFLAGS="$flags" cargo build --release {{firmwares}} -p o89-comms --target {{riscv}} --features no-window
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout slot {{args}}

# LISTEN to the module through the bridge: the firmware resets it, by
# `--entry reset` (the default), `knock` or `strap`, and prints what it
# says on its UART0 for a few seconds, then resets it normally. Effect: two
# module resets. Recovery: none needed.
#
# LISTEN to what the module says after a reset, through the controller.
dev-comms-listen *args:
    cargo run -q -p o89-dev -- comms-listen {{args}}
