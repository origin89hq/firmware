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

**Set up on 2026-09-18, with no code yet.** The plan comes first; the crates,
the check gate and the CI arrive with it.

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

## Toolchain

`rust-toolchain.toml` pins the compiler and both targets; rustup installs them
on the first cargo command. The comms processor is bare-metal
[`esp-hal`](https://github.com/esp-rs/esp-hal), the controller is
[Embassy](https://embassy.dev/) on `embassy-stm32`. Flashing goes through
`probe-rs` for the STM32 and, on revision A, through the STM32 for the ESP32.

`just --list` shows the recipes. `just skills-sync` fetches the shared
engineering skills at the start of a task. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Code is licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The Origin89 name and marks are
covered by the [brand repository](https://github.com/origin89hq/brand)'s terms.
