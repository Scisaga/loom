#!/usr/bin/env bash
set -euo pipefail

package_name=io.github.scisaga.loom
receiver=$package_name/.debug.DebugVpnControlReceiver

: "${ANDROID_HOME:?ANDROID_HOME 未设置}"
: "${ANDROID_SERIAL:?ANDROID_SERIAL 未设置；必须显式指定待验收真机}"
: "${LOOM_PHYSICAL_ACCEPTANCE:?LOOM_PHYSICAL_ACCEPTANCE 未设置；只有显式设为 1 才会驱动 VPN}"
: "${LOOM_EXPECTED_APK_SHA256:?LOOM_EXPECTED_APK_SHA256 未设置；验收必须绑定 APK bytes}"
: "${EXPECTED_UNDERLAY:?EXPECTED_UNDERLAY 未设置；必须是 wifi 或 cellular}"
[[ "$LOOM_PHYSICAL_ACCEPTANCE" == "1" ]] || { echo "LOOM_PHYSICAL_ACCEPTANCE 必须精确为 1" >&2; exit 2; }
[[ "$LOOM_EXPECTED_APK_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "APK SHA-256 格式错误" >&2; exit 2; }
[[ "$EXPECTED_UNDERLAY" == "wifi" || "$EXPECTED_UNDERLAY" == "cellular" ]] || {
    echo "EXPECTED_UNDERLAY 必须是 wifi 或 cellular" >&2
    exit 2
}

adb=("$ANDROID_HOME/platform-tools/adb" -s "$ANDROID_SERIAL")
[[ -x "${adb[0]}" ]] || { echo "缺少 Android platform-tools/adb" >&2; exit 2; }
"${adb[@]}" wait-for-device
[[ "$("${adb[@]}" shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ]] || {
    echo "真机验收脚本拒绝 Emulator" >&2
    exit 1
}
sdk=$("${adb[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
[[ "$sdk" =~ ^[0-9]+$ && "$sdk" -ge 31 ]] || { echo "本脚本只验收 API 31+ 真机" >&2; exit 1; }

tmp_dir=$(mktemp -d)
cleanup() {
    "${adb[@]}" shell am broadcast -n "$receiver" \
        -a io.github.scisaga.loom.debug.DISCONNECT >/dev/null 2>&1 || true
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

installed_path=$("${adb[@]}" shell pm path "$package_name" | tr -d '\r' |
    sed -n 's/^package://p' | head -n 1)
[[ -n "$installed_path" ]] || { echo "Loom 尚未安装" >&2; exit 1; }
"${adb[@]}" pull "$installed_path" "$tmp_dir/installed.apk" >/dev/null 2>&1
installed_sha=$(sha256sum -- "$tmp_dir/installed.apk" | awk '{print $1}')
[[ "$installed_sha" == "${LOOM_EXPECTED_APK_SHA256,,}" ]] || {
    echo "已安装 APK 与待验收 bytes 不一致" >&2
    exit 1
}
"${adb[@]}" shell run-as "$package_name" true >/dev/null 2>&1 || {
    echo "已安装包不是可验收的 debug APK" >&2
    exit 1
}
# 覆盖安装会把包留在 stopped 状态；显式启动正常 Activity 后才允许验收 receiver 工作。
"${adb[@]}" shell am start -W -n "$package_name/.MainActivity" >/dev/null

status_data() {
    local action=$1 output
    output=$("${adb[@]}" shell am broadcast -n "$receiver" -a "$action" | tr -d '\r')
    sed -n 's/^Broadcast completed: result=0, data="\(.*\)"$/\1/p' <<<"$output"
}

send() {
    "${adb[@]}" shell am broadcast -n "$receiver" -a "$1" >/dev/null
}

wait_runtime() {
    local expected=$1 require_report=${2:-0} status
    for _ in $(seq 1 45); do
        status=$(status_data io.github.scisaga.loom.debug.RUNTIME_STATUS)
        if [[ "$status" == *"phase=$expected"* ]]; then
            if [[ "$require_report" == "0" || "$status" == *'report=成功（HTTP 200）'* ]]; then
                printf '%s\n' "$status"
                return 0
            fi
        fi
        sleep 1
    done
    echo "等待 runtime=$expected 超时" >&2
    return 1
}

wait_route() {
    local status
    for _ in $(seq 1 30); do
        status=$(status_data io.github.scisaga.loom.debug.ROUTE_STATUS)
        if [[ "$status" == *'available=true'* && "$status" == *'running=true'* &&
            "$status" == *'busy=false'* && "$status" == *'blocked=false'* &&
            "$status" != *'paths=0;'* ]]; then
            printf '%s\n' "$status"
            return 0
        fi
        sleep 1
    done
    echo "等待 route readback 超时" >&2
    return 1
}

wait_probe_registry() {
    local status
    for _ in $(seq 1 30); do
        status=$(status_data io.github.scisaga.loom.debug.PROBE_REGISTRY_STATUS)
        if [[ "$status" == *'frozen=true'* && "$status" != *'fingerprint=none'* ]]; then
            printf '%s\n' "$status"
            return 0
        fi
        sleep 1
    done
    echo "等待当前底层网络代入口证据超时" >&2
    return 1
}

# 先释放旧会话，再读取系统当前默认的非 VPN 底层网络。
send io.github.scisaga.loom.debug.DISCONNECT
send io.github.scisaga.loom.debug.DISCONNECT
wait_runtime DISCONNECTED >/dev/null
active_network=$("${adb[@]}" shell dumpsys connectivity | tr -d '\r' |
    sed -n 's/^Active default network: //p' | head -n 1)
[[ "$active_network" =~ ^[0-9]+$ ]] || { echo "无法识别默认底层 Network" >&2; exit 1; }
network_line=$("${adb[@]}" shell dumpsys connectivity | tr -d '\r' |
    grep -F -m 1 "NetworkAgentInfo{network{$active_network}" || true)
case "$EXPECTED_UNDERLAY" in
    wifi) [[ "$network_line" == *' ni{WIFI CONNECTED '* && "$network_line" == *'Transports: WIFI'* ]] ;;
    cellular) [[ "$network_line" == *' ni{MOBILE CONNECTED '* && "$network_line" == *'Transports: CELLULAR'* ]] ;;
esac || { echo "当前默认网络不是声明的 $EXPECTED_UNDERLAY" >&2; exit 1; }

enrollment=$(status_data io.github.scisaga.loom.debug.ENROLLMENT_STATUS)
[[ "$enrollment" == *'phase=READY'* && "$enrollment" == *'snapshot=true'* ]] || {
    echo "真机没有可启动的正式验签配置" >&2
    exit 1
}

send io.github.scisaga.loom.debug.CONNECT
first_runtime=$(wait_runtime CONNECTED 1)
[[ "$first_runtime" == *'dns=未执行（启动不以业务 DNS 为门禁）'* &&
    "$first_runtime" == *'https=未执行（启动不以业务 HTTPS 为门禁）'* ]] || {
    echo "启动路径错误地执行了业务探测" >&2
    exit 1
}
wait_route >/dev/null
first_probe=$(wait_probe_registry)

send io.github.scisaga.loom.debug.DISCONNECT
wait_runtime DISCONNECTED >/dev/null
send io.github.scisaga.loom.debug.CONNECT
second_runtime=$(wait_runtime CONNECTED 1)
wait_route >/dev/null
second_probe=$(status_data io.github.scisaga.loom.debug.PROBE_REGISTRY_STATUS)
[[ "$second_runtime" == *'dns=未执行（启动不以业务 DNS 为门禁）'* &&
    "$second_runtime" == *'https=未执行（启动不以业务 HTTPS 为门禁）'* ]] || {
    echo "重连路径错误地执行了业务探测" >&2
    exit 1
}
[[ "$first_probe" == "$second_probe" ]] || {
    echo "同一底层网络代重连后入口证据发生变化；疑似重复主动探测" >&2
    exit 1
}

send io.github.scisaga.loom.debug.DISCONNECT
send io.github.scisaga.loom.debug.DISCONNECT
wait_runtime DISCONNECTED >/dev/null
trap - EXIT
rm -rf -- "$tmp_dir"

printf 'physical_device=true\n'
printf 'api_31_plus=true\n'
printf 'underlay=%s\n' "$EXPECTED_UNDERLAY"
printf 'managed_v2_runtime=true\n'
printf 'private_report_http_200=true\n'
printf 'business_probe_activation_gate=false\n'
printf 'same_generation_reconnect_reused_entry_evidence=true\n'
printf 'idempotent_disconnect=true\n'
