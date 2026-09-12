#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
android_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

: "${ANDROID_HOME:?ANDROID_HOME 未设置}"
: "${ANDROID_SERIAL:?ANDROID_SERIAL 未设置；必须显式指定 API 26–30 Emulator}"
adb=("$ANDROID_HOME/platform-tools/adb" -s "$ANDROID_SERIAL")
"${adb[@]}" wait-for-device
[[ "$("${adb[@]}" shell getprop ro.kernel.qemu | tr -d '\r')" == "1" ]] || {
    echo "低版本 Keystore 验收脚本拒绝真机或未知设备" >&2
    exit 1
}
device_api=$("${adb[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
[[ "$device_api" =~ ^(2[6-9]|30)$ ]] || {
    echo "RSA fallback 只允许 API 26–30（当前 API $device_api）" >&2
    exit 1
}

cd "$android_dir"
./gradlew --no-daemon assembleDebug assembleDebugAndroidTest
"${adb[@]}" install -r app/build/outputs/apk/debug/app-debug.apk
"${adb[@]}" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
instrument_output=$("${adb[@]}" shell am instrument -w \
    -e class io.github.scisaga.loom.V2KeyStoreInstrumentedTest \
    io.github.scisaga.loom.test/androidx.test.runner.AndroidJUnitRunner)
printf '%s\n' "$instrument_output"
if grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed' <<<"$instrument_output"; then
    exit 1
fi
grep -Eq '^OK \([0-9]+ tests?\)$' <<<"$instrument_output"
