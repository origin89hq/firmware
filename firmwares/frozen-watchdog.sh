#!/usr/bin/env bash
# Runs a probe command against the controller with its independent watchdog
# frozen while the probe holds the core halted, then thaws it however the
# command ends (#125).
#
# The IWDG keeps counting while a debugger halts a running image, so a halt
# of more than 8 s resets the part under the probe. The download itself is
# not such a halt: it begins with a reset that stops the IWDG, and the bench
# of 2026-09-24 found no watchdog reset in one. Freezing does not stop the
# watchdog record #125 reports, whose cause is still open.
#
# DBG_IWDG_STOP is bit 12 of DBGMCU_APB_FZ1 on the STM32G0. It acts only
# while the core is halted by a debugger. It survived `probe-rs reset` on the
# bench, and the reference manual has a power-on reset clear it; the second
# is not yet checked on a board. The thaw writes the register back to 0,
# its value after a power-on reset, and no firmware of ours writes it. A
# unit left frozen by a thaw that failed is cleared by its next power cycle.
#
# It also disarms the vector catches before the command and after it
# (#155). By default `probe-rs attach` and `probe-rs run` arm the reset and
# hard-fault catches in DEMCR and leave them armed when they end, and only a power-on
# reset clears them: every later reset, a watchdog's or the firmware's own,
# then stops the core on its first instruction until a probe runs it, and a
# hard fault halts instead of reaching the firmware's handler. DEMCR is 0
# after a power-on reset, and 0 is what is written back.
#
# Usage: frozen-watchdog.sh COMMAND [ARG...]
set -euo pipefail

chip=STM32G0B1RETx
apb_fz1=0x40015808
iwdg_stop=0x1000
demcr=0xE000EDFC

# Both writes are tried, whichever fails.
thaw() {
    local status=0
    if ! probe-rs write --chip "$chip" b32 "$apb_fz1" 0; then
        echo "frozen-watchdog: the IWDG freeze was not cleared; power-cycle the controller" >&2
        status=1
    fi
    if ! probe-rs write --chip "$chip" b32 "$demcr" 0; then
        echo "frozen-watchdog: the vector catches were not disarmed; power-cycle the controller" >&2
        status=1
    fi
    return "$status"
}

probe-rs write --chip "$chip" b32 "$demcr" 0
probe-rs write --chip "$chip" b32 "$apb_fz1" "$iwdg_stop"
trap 'status=$?; thaw || status=1; exit "$status"' EXIT

# The command runs as a child, not in the foreground: bash runs a trap only
# once a foreground command has exited, and `probe-rs run` runs until it is
# stopped. A signal is passed on as TERM, since a child started this way
# ignores INT, and the thaw waits for the child so that it never meets a
# probe still in use. `<&0` keeps the terminal on the child's input, which
# would otherwise be /dev/null.
"$@" <&0 &
child=$!
stop() {
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" || true
    exit "$1"
}
trap 'stop 130' INT
trap 'stop 143' TERM
wait "$child"
