#!/bin/sh
# Build the module's second-stage bootloader from ESP-IDF in Espressif's own
# container, and put it beside this script as `esp32c6-bootloader.bin`
# (F-088). The ESP-IDF release is pinned here; `sdkconfig.defaults` is the
# whole configuration. Needs Docker. Nothing here touches a board.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
idf=espressif/idf:v5.5.1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/sdkconfig.defaults" "$work/"
printf 'cmake_minimum_required(VERSION 3.16)\ninclude($ENV{IDF_PATH}/tools/cmake/project.cmake)\nproject(o89_bootloader)\n' > "$work/CMakeLists.txt"
mkdir "$work/main"
printf 'idf_component_register(SRCS main.c)\n' > "$work/main/CMakeLists.txt"
printf 'void app_main(void) {}\n' > "$work/main/main.c"
docker run --rm -v "$work:/project" -w /project "$idf" \
    sh -c 'idf.py set-target esp32c6 > /dev/null && idf.py bootloader'
# The rollback strings are debug-level and compiled out, so the binary
# cannot say; the configuration the build resolved can, and a build that
# lost the option is refused rather than committed.
grep -x 'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y' "$work/sdkconfig"
cp "$work/build/bootloader/bootloader.bin" "$here/esp32c6-bootloader.bin"
shasum -a 256 "$here/esp32c6-bootloader.bin"
