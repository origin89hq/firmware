#!/usr/bin/env bash
# Runs a probe command against the controller with its independent watchdog
# frozen while the probe holds the core halted, then thaws it however the
# command ends (#125).
#
# The IWDG keeps counting through a halt, and `probe-rs download` holds the
# core halted in its flash loader for the whole transfer: a 175 KB image
# takes longer than the watchdog's 8 s, and the part reset under the probe,
# leaving a boot record that blamed the watchdog.
#
# DBG_IWDG_STOP is bit 12 of DBGMCU_APB_FZ1 on the STM32G0. It acts only
# while the core is halted by a debugger, and only a power-on reset clears
# it, so a system reset keeps it. The thaw writes the register back to 0,
# its value after a power-on reset, and no firmware of ours writes it. A
# unit left frozen by a thaw that failed is cleared by its next power cycle.
#
# Usage: frozen-watchdog.sh COMMAND [ARG...]
set -euo pipefail

chip=STM32G0B1RETx
apb_fz1=0x40015808
iwdg_stop=0x1000

thaw() {
    if ! probe-rs write --chip "$chip" b32 "$apb_fz1" 0; then
        echo "frozen-watchdog: the IWDG freeze was not cleared; power-cycle the controller" >&2
        return 1
    fi
}

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
