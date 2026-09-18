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
boot_elf := "firmwares/target/thumbv6m-none-eabi/release/o89-boot"
boot_bin := "firmwares/target/thumbv6m-none-eabi/release/o89-boot.bin"

# Flash the bootloader into both banks of the controller: the ELF at
# 0x08000000, the same bytes as a `.bin` at 0x08040000. Effect: the part boots
# through the bootloader, which drives RUN and KICK low and jumps to
# 0x08002000. Recovery: `just flash-controller` if the application is not
# there yet; the part waits with the lines low until it is.
#
# Flash the bootloader into both banks of the controller.
flash-boot: sizes
    probe-rs download --chip {{chip}} --verify {{boot_elf}}
    probe-rs download --chip {{chip}} --verify --binary-format bin --base-address 0x08040000 {{boot_bin}}

# Flash the production controller image at 0x08002000. Needs the bootloader
# in front of it (`just flash-boot`); on its own the part waits at the
# bootloader with the lines low. Effect: the controller boots in the order
# the hazards dictate. Recovery: `just flash-controller` again, or
# `just run-controller-bench` to bypass the bootloader.
#
# Flash the production controller image at 0x08002000, behind the bootloader.
flash-controller: sizes
    probe-rs download --chip {{chip}} --verify {{controller_elf}}

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
