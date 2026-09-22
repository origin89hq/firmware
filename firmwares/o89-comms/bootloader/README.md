# The module's bootloader

`esp32c6-bootloader.bin` is ESP-IDF's second-stage bootloader for the
ESP32-C6, built by `build.sh` from the ESP-IDF release it names, in
Espressif's container, with `sdkconfig.defaults` as the whole
configuration. It differs from the one `espflash` ships in one option:
app rollback is enabled (F-088). Under `espflash`'s, the `New` state the
bench writes into `otadata` holds nothing, and a bad image keeps its slot
for good; under this one, a slot that does not confirm itself before its
next reset is put back to the image that was running, which honours the
download window (#1).

`just comms-bootloader` rebuilds it and writes its SHA-256 beside it; the
same source gives the same bytes, and a pull request that changes them
shows the hash moving and says which option moved. `cargo xtask check`
holds the binary to that hash, the configuration to the rollback option
and the binary to the ESP-IDF release `build.sh` names; the bench tool
checks the hash again before it flashes. The whole route of
`dev-flash-comms` writes it; the slot route refuses a module that does not
hold it.

ESP-IDF is Copyright Espressif Systems, licensed under Apache-2.0; the
binary is redistributed under that licence.
