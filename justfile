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

# Build the three images and print their sizes; `--record` appends to docs/sizes.tsv.
sizes *args:
    cargo xtask sizes {{args}}

# Refresh the shared skills once at the start of a task.
skills-sync:
    python3 .origin89/sync-engineering.py
