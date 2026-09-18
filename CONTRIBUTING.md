# Contributing

Follow the [Origin89 engineering standards](https://github.com/origin89hq/engineering)
for working practices, tests, writing and commits. `AGENTS.md` loads the shared
skills at the start of a task; `just skills-sync` refreshes them from
engineering. The rules specific to this repository are in [AGENTS.md](AGENTS.md)
and apply to everyone, not only to an assistant.

## Setup

- just 1.57 or newer and Python 3.9 or newer, for the recipes and the skill
  bootstrap.
- The Rust toolchain in `rust-toolchain.toml`. rustup installs it, with the
  `thumbv6m-none-eabi` and `riscv32imac-unknown-none-elf` targets, on first use.
- For the bench: `probe-rs` for the STM32 and `espflash` for ESP32 images. A
  probe attaches to board A through a Nucleo's ST-Link; see the board's README
  in [origin89hq/hardware](https://github.com/origin89hq/hardware).

## Before a pull request

`just check` will run everything CI runs once there is a workspace to check.
Until then, the README states what exists.

A change that can affect physical equipment needs the evidence the
[embedded standard](https://github.com/origin89hq/engineering/blob/main/docs/embedded.md)
asks for: the board revision, the firmware hash, what was measured and with
what. A build is not bench evidence. Flashing and actuation are never part of
an ordinary check.

## Protocol

Wire numbers are allocated in [km43](https://github.com/origin89hq/km43) and
nowhere else. A firmware takes them from the crate; a literal here is a second
opinion that agrees until the registry moves.
