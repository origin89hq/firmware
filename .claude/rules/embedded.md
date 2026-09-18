# Embedded

- **Controller:** STM32G0B1RE, Cortex-M0+, no FPU, no compare-and-swap,
  144 KB RAM. Two 256 KB banks swapped by an option bit; the image budget is
  one bank less the bootloader's 8 KB — **248 KB, never 512**. No floating
  point in interrupts or hot paths; software float is fine at 1 Hz.
- **Comms processor:** ESP32-C6, bare-metal `esp-hal`. `esp_hal::init`
  disables every watchdog; the firmware re-arms one as its first statement.
- **The board is a firmware concept.** `docs/BOARD-A.md` carries the pin map
  and the policy per revision; the board module is its only home in code.
  Pins come from the netlist and the hardware repository's decisions, never
  from a devkit or a guess.
- **Safety timing lives in hardware.** The generator board's monostable, the
  independent watchdog fed only by a rollcall. The executor is cooperative and
  must never be the only thing between a maintained contact and a tank
  running dry.
- **Every output declares its state at reset**, and reaches it before any
  bus is up. An output arrives in shadow.
- **Pinned exactly.** Embassy and `esp-hal` move under a caret. Moving a pin
  is a commit that names the release note it read and the bench that
  revalidated it.
- **The `.bin` is the size, never the ELF.** `just sizes` after a change that
  could move one; the pull request says by how much; `just sizes --record`
  on `main` after the merge, so the row names a commit that exists.
- **Build and check are never flashing.** A recipe that flashes, erases or
  actuates says so in its name, and before running one against a board:
  the exact target, the expected effect, the safe setup, the recovery path.
  Board B is plugged and unplugged with 12 V off.
- **A build is not bench evidence.** A bench session is dated under
  `docs/bench/` with the board revision, the firmware hash, the fixture and
  the instrument; every bench finding becomes a simulator fault first, then a
  fix.
