#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
android_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
fake_sdk=$(mktemp -d)
trap 'rm -rf -- "$fake_sdk"' EXIT
mkdir -p "$fake_sdk/platform-tools"
ln -s "$script_dir/testdata/fake-adb" "$fake_sdk/platform-tools/adb"

expect_failure() {
    local wanted=$1
    shift
    local output
    if output=$(env ANDROID_HOME="$fake_sdk" "$@" "$android_dir/scripts/emulator-smoke.sh" 2>&1); then
        echo "emulator smoke preflight unexpectedly succeeded" >&2
        exit 1
    fi
    grep -Fq "$wanted" <<<"$output"
}

expect_failure "ANDROID_SERIAL" env -u ANDROID_SERIAL
expect_failure "不是 Android Emulator" env ANDROID_SERIAL=usb-device FAKE_QEMU=0
expect_failure "ro.build.version.sdk" env ANDROID_SERIAL=emulator-old FAKE_QEMU=1 FAKE_API=34

