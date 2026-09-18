<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/origin89hq/brand/main/logos/origin89-horizontal-white.svg">
  <img src="https://raw.githubusercontent.com/origin89hq/brand/main/logos/origin89-horizontal-blue.svg" alt="Origin89" width="320">
</picture>

# Origin89 firmware

The two firmwares of the Origin89 controller: a box that starts a generator
and manages a battery bank at a site four hours from a road, through a
Canadian winter, with nobody watching it fail.

| Firmware | Part | Owns |
| --- | --- | --- |
| Controller | STM32G0B1RE, Cortex-M0+ | Every decision, all persistence, all timing, all actuation. Runs a full week with the other part unplugged |
| Comms processor | ESP32-C6, RISC-V | BLE, Wi-Fi, cloud transport and update delivery. A pipe the controller does not trust: it forwards bytes and never inspects them |

They run on [controller board A](https://github.com/origin89hq/hardware/tree/main/boards/controller-a)
and drive [generator board B](https://github.com/origin89hq/hardware/tree/main/boards/generator-b)
through its interlock. Both speak [KM43](https://github.com/origin89hq/km43),
whose `no_std` crate is the one wire format shared by both parts and every
client.

## Where this stands

**The plan is agreed and the foundation is being laid.** The plan, its
milestones and the decisions behind them are
[issue #3](https://github.com/origin89hq/firmware/issues/3); each milestone is
a sub-issue with the evidence that closes it. Today the repository holds two
workspaces, the first seam of the controller's core, and three images that
link for their parts and do nothing — they exist so the gate measures linking
and size before code lands. Nothing runs on a board yet. The design the code
implements is [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The earlier firmware in
[origin89hq/origin89](https://github.com/origin89hq/origin89/tree/main/firmwares)
was written against a Nucleo and a devkit, before a board existed, and its
comms side has no radio. Board A revision A is now on the bench with its
self-test passing, and this repository is where the firmware is rewritten for
it rather than adapted. Nothing is carried over by default; a driver proven on
the bench is taken deliberately, with the bench evidence that proved it.

Two things are already decided by the board and filed as the first requirements:

- The ESP32's download path is recovery-critical on revision A. IO8 is
  unconnected, so the only wire-free way into serial download is firmware on
  the ESP32 honouring a request from the STM32. That window must run before
  anything that can crash, and never be triggered from the relayed client
  stream. [#1](https://github.com/origin89hq/firmware/issues/1)
- The controller link is the module's UART0, not UART1: STM32 PB6/PB7 to
  GPIO17/GPIO16, RTS/CTS on GPIO4/GPIO5, and the ROM's boot messages arrive on
  the link after every reset. [#2](https://github.com/origin89hq/firmware/issues/2),
  decided in [hardware#13](https://github.com/origin89hq/hardware/issues/13)

The open hardware issues on revision A, several of which the firmware has to
live with, are in [origin89hq/hardware](https://github.com/origin89hq/hardware/issues).

## Layout and commands

| Path | What it is |
| --- | --- |
| `crates/o89-core` | The controller's decisions: `no_std`, no allocator, names no peripheral, host-tested |
| `xtask/` | The gate `cargo test` cannot be: cross-compiles, dependency rules, the three images measured against their slots |
| `firmwares/` | Its own workspace: `o89-boot` and `o89-controller` for the STM32G0B1RE, `o89-comms` for the ESP32-C6 |
| `docs/sizes.tsv` | What each image cost, per commit, as the `.bin` and never the ELF |

`rust-toolchain.toml` pins the compiler, both targets and `llvm-tools`; rustup
installs them on the first cargo command. `espflash` measures the comms image
(`cargo install espflash --locked`). The comms processor is bare-metal
[`esp-hal`](https://github.com/esp-rs/esp-hal); the controller is
[Embassy](https://embassy.dev/) on `embassy-stm32`.

`just check` runs what CI runs: formatting, Clippy with the restriction lints
that make the house rules build failures, the host tests, and `cargo xtask
check`. `just sizes` prints the three images against their budgets. Flashing
and actuation are never part of `check`; those recipes arrive with the first
image that touches a pin. `just skills-sync` fetches the shared engineering
skills at the start of a task. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Code is licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The Origin89 name and marks are
covered by the [brand repository](https://github.com/origin89hq/brand)'s terms.
