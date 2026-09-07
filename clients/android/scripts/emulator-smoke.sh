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
previous_http_proxy=$("${adb[@]}" shell settings get global http_proxy | tr -d '\r')
previous_private_dns=$("${adb[@]}" shell settings get global private_dns_mode | tr -d '\r')

emulator_proxy=false
relay_pid=""
proxy_url=${HTTPS_PROXY:-${https_proxy:-}}
if [[ -n "$proxy_url" ]]; then
    command -v socat >/dev/null || {
        echo "HTTPS_PROXY 环境的 Emulator 验收需要 socat" >&2
        exit 1
    }
    proxy_authority=${proxy_url#*://}
    proxy_authority=${proxy_authority%%/*}
    if [[ "$proxy_authority" == *"@"* || "$proxy_authority" != *":"* ]]; then
        echo "不支持带凭据或缺少端口的 HTTPS_PROXY" >&2
        exit 1
    fi
    proxy_host=${proxy_authority%:*}
    proxy_port=${proxy_authority##*:}
    # 10.0.2.2 is the Emulator's alias for the host loopback interface. Do
    # not expose this unauthenticated test relay on the builder's LAN.
    socat TCP-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork TCP:"$proxy_host":"$proxy_port" &
    relay_pid=$!
    emulator_proxy=true
fi

cleanup() {
    "${adb[@]}" shell appops set io.github.scisaga.loom ACTIVATE_VPN default >/dev/null 2>&1 || true
    if [[ "$previous_http_proxy" == "null" ]]; then
        "${adb[@]}" shell settings delete global http_proxy >/dev/null 2>&1 || true
    else
        "${adb[@]}" shell settings put global http_proxy "$previous_http_proxy" >/dev/null 2>&1 || true
    fi
    if [[ "$previous_private_dns" == "null" ]]; then
        "${adb[@]}" shell settings delete global private_dns_mode >/dev/null 2>&1 || true
    else
        "${adb[@]}" shell settings put global private_dns_mode "$previous_private_dns" >/dev/null 2>&1 || true
    fi
    if [[ -n "$relay_pid" ]]; then kill "$relay_pid" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
"${adb[@]}" shell settings put global http_proxy :0 >/dev/null
"${adb[@]}" shell settings put global private_dns_mode off >/dev/null

cd "$android_dir"
./gradlew --no-daemon assembleDebug assembleDebugAndroidTest
"${adb[@]}" install -r app/build/outputs/apk/debug/app-debug.apk
"${adb[@]}" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
"${adb[@]}" shell appops set io.github.scisaga.loom ACTIVATE_VPN allow
instrument_output=$("${adb[@]}" shell am instrument -w \
    -e emulatorProxy "$emulator_proxy" \
    -e class io.github.scisaga.loom.HomeUiInstrumentedTest,io.github.scisaga.loom.SecurityInstrumentedTest,io.github.scisaga.loom.Stage1ConfigInstrumentedTest,io.github.scisaga.loom.VpnSmokeInstrumentedTest \
    io.github.scisaga.loom.test/androidx.test.runner.AndroidJUnitRunner)
printf '%s\n' "$instrument_output"
if grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed' <<<"$instrument_output"; then
    exit 1
fi
grep -Eq '^OK \([0-9]+ tests?\)$' <<<"$instrument_output"
