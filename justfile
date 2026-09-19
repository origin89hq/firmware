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
sizes *args:
    cargo xtask sizes {{args}}

# Refresh the shared skills once at the start of a task.
skills-sync:
    python3 .origin89/sync-engineering.py

# ---------------------------------------------------------------------------
# Flashing, erasing and resetting: never run from `check`. Before any of these
# against a board, name the exact target, the expected effect, the safe setup
# and the recovery path. Board B is plugged and unplugged with 12 V off.
# ---------------------------------------------------------------------------

chip := "STM32G0B1RETx"
controller_elf := "firmwares/target/thumbv6m-none-eabi/release/o89-controller"
comms_elf := "firmwares/target/riscv32imac-unknown-none-elf/release/o89-comms"
boot_elf := "firmwares/target/thumbv6m-none-eabi/release/o89-boot"
boot_bin := "firmwares/target/thumbv6m-none-eabi/release/o89-boot.bin"

# Flash the bootloader into both banks of the controller: the ELF at
# 0x08000000, the same bytes as a `.bin` at 0x08040000, then a reset, because
# `probe-rs download` leaves the part halted in its flash loader with every
# pin an input, and the transceivers drive their buses low on a floating DI
# (origin89hq/hardware#28). Effect: the part boots through the bootloader,
# which drives RUN and KICK low and jumps to 0x08002000. Recovery:
# `just flash-controller` if the application is not there yet; the part
# waits with the lines low until it is.
#
# Flash the bootloader into both banks of the controller, then reset it.
flash-boot: sizes
    probe-rs download --chip {{chip}} --verify {{boot_elf}}
    probe-rs download --chip {{chip}} --verify --binary-format bin --base-address 0x08040000 {{boot_bin}}
    probe-rs reset --chip {{chip}}

# Flash the production controller image at 0x08002000, then reset the part:
# `probe-rs download` alone leaves it halted in its flash loader with every
# pin an input, which is a controller that runs nothing and buses driven low
# by floating DIs (origin89hq/hardware#28). Needs the bootloader in front of
# it (`just flash-boot`); on its own the part waits at the bootloader with
# the lines low. Effect: the controller boots in the order the hazards
# dictate. Recovery: `just flash-controller` again, or
# `just run-controller-bench` to bypass the bootloader.
#
# Flash the production controller image at 0x08002000 and reset the part.
flash-controller: sizes
    probe-rs download --chip {{chip}} --verify {{controller_elf}}
    probe-rs reset --chip {{chip}}

# Flash and run the production controller image with the log on the probe.
# The runner is `probe-rs run`, which flashes the ELF's own regions only, so
# the bootloader stays. Effect: as `flash-controller`, then the defmt log.
#
# Flash and run the production controller image with the log on the probe.
run-controller:
    cd firmwares/o89-controller && cargo run --release

# Flash and run the BENCH image: linked at 0x08000000 with no bootloader, and
# carrying the one-shot proofs. Effect: overwrites the bootloader's 8 KB in
# bank 1, starves the watchdog fifteen seconds into a boot the watchdog did
# not cause, panics fifteen seconds into the boot after a watchdog reset, and
# runs from the boot after that. Never on a unit that will take an update.
# Recovery: `just flash-boot` then `just flash-controller` restore the
# production layout.
#
# Flash and run the BENCH image at 0x08000000 with the one-shot proofs; never on a unit that will take an update.
run-controller-bench:
    cd firmwares/o89-controller && cargo run --release --features bench

# As `run-controller-bench`, halting on the panic with its message on the
# probe instead of writing the last words and resetting: for chasing a panic,
# not for proving the path.
#
# The bench image halting on a panic with the message on the probe, for chasing one.
run-controller-bench-halting:
    cd firmwares/o89-controller && cargo run --release --features bench,panic-probe

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
    cd firmwares/o89-comms && cargo run --release --features devkit

# Read the defmt log of whatever the controller is running, without flashing
# or resetting it: the way to read a boot record after a reset the probe did
# not cause. `elf` is the image on the part, for the log's strings.
#
# Read the controller's log without flashing or resetting it.
attach-controller elf=controller_elf:
    probe-rs attach --chip {{chip}} {{elf}}

# Reset the controller through the probe. Effect: a pin-class reset; the
# boot record on the next attach says so.
#
# Reset the controller through the probe.
reset-controller:
    probe-rs reset --chip {{chip}}

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

# ERASE `count` 4 KiB blocks of the NOR from `block`, one request each, the
# ring finding its head again after each block of its own. Effect: records
# in those blocks are gone; the ring's sequence restarts at one when every
# block of it is erased. Recovery: none; the log is the log.
#
# ERASE NOR blocks from `block`; records there are gone.
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
# factory image of a module that is running. Effect: everything the module
# held is replaced, and from the first erase until esptool finishes it boots
# nothing. Recovery: run it again, with the wire. Use `dev-flash-comms` for
# ordinary work.
#
# FLASH THE WHOLE MODULE FLASH, factory image included; leaves no way back but the strap.
[confirm("Replace the whole module flash, the factory image that carries the download window included? A transfer that dies leaves the strap as the only way in.")]
dev-flash-comms-whole *args: sizes
    cargo run -q -p o89-dev -- flash-comms {{comms_elf}} --layout whole --yes {{args}}


# LISTEN to the module through the bridge: the firmware resets it, by
# `--entry reset` (the default), `knock` or `strap`, and prints what it
# says on its UART0 for a few seconds, then resets it normally. Effect: two
# module resets. Recovery: none needed.
#
# LISTEN to what the module says after a reset, through the controller.
dev-comms-listen *args:
    cargo run -q -p o89-dev -- comms-listen {{args}}
