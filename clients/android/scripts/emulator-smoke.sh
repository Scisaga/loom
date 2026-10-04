#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
android_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

: "${ANDROID_HOME:?ANDROID_HOME 未设置}"
: "${ANDROID_SERIAL:?ANDROID_SERIAL 未设置；必须显式指定待验收的 Emulator}"
adb=("$ANDROID_HOME/platform-tools/adb" -s "$ANDROID_SERIAL")
"${adb[@]}" wait-for-device
if [[ "$("${adb[@]}" shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ]]; then
    echo "ANDROID_SERIAL=$ANDROID_SERIAL 不是 Android Emulator；拒绝修改真机或未知设备" >&2
    exit 1
fi
device_api=$("${adb[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
if ! grep -Eq '^(3[5-9]|[4-9][0-9])$' <<<"$device_api"; then
    echo "Emulator 必须使用 API >= 35（ro.build.version.sdk=$device_api）" >&2
    exit 1
fi
cd "$android_dir"
./gradlew --no-daemon assembleDebug assembleDebugAndroidTest
"${adb[@]}" install -r app/build/outputs/apk/debug/app-debug.apk
"${adb[@]}" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
instrument_output=$("${adb[@]}" shell am instrument -w \
    -e class io.github.scisaga.loom.HomeUiInstrumentedTest \
    io.github.scisaga.loom.test/androidx.test.runner.AndroidJUnitRunner)
printf '%s\n' "$instrument_output"
if grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed' <<<"$instrument_output"; then
    exit 1
fi
grep -Eq '^OK \([0-9]+ tests?\)$' <<<"$instrument_output"
