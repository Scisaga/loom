#!/usr/bin/env bash
set -euo pipefail

package_name=io.github.scisaga.loom
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

: "${ANDROID_HOME:?ANDROID_HOME 未设置}"
: "${ANDROID_SERIAL:?ANDROID_SERIAL 未设置；必须显式指定待安装的真机}"
: "${LOOM_AUTO_CONFIRM_INSTALL:?LOOM_AUTO_CONFIRM_INSTALL 未设置；只有显式设为 1 才会点击安装确认}"
if [[ "$LOOM_AUTO_CONFIRM_INSTALL" != "1" ]]; then
    echo "LOOM_AUTO_CONFIRM_INSTALL 必须精确为 1" >&2
    exit 2
fi
if [[ $# -ne 2 ]]; then
    echo "usage: $0 APK EXPECTED_APK_SHA256" >&2
    exit 2
fi

apk=$(realpath -- "$1")
expected_apk_sha=${2,,}
[[ -f "$apk" ]] || { echo "APK 不存在: $apk" >&2; exit 2; }
[[ "$expected_apk_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "EXPECTED_APK_SHA256 格式错误" >&2; exit 2; }

adb=("$ANDROID_HOME/platform-tools/adb" -s "$ANDROID_SERIAL")
aapt2="$ANDROID_HOME/build-tools/35.0.1/aapt2"
apksigner="$ANDROID_HOME/build-tools/35.0.1/apksigner"
[[ -x "${adb[0]}" && -x "$aapt2" && -x "$apksigner" ]] || {
    echo "缺少固定 Android SDK 工具" >&2
    exit 2
}

actual_apk_sha=$(sha256sum -- "$apk" | awk '{print $1}')
if [[ "$actual_apk_sha" != "$expected_apk_sha" ]]; then
    echo "APK SHA-256 不匹配；拒绝安装" >&2
    exit 1
fi
apk_package=$("$aapt2" dump badging "$apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -n 1)
if [[ "$apk_package" != "$package_name" ]]; then
    echo "APK 包名不是 $package_name；拒绝安装" >&2
    exit 1
fi
"$apksigner" verify "$apk"
apk_cert=$("$apksigner" verify --print-certs "$apk" |
    sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr -d ':' | tr '[:upper:]' '[:lower:]')
[[ "$apk_cert" =~ ^[0-9a-f]{64}$ ]] || { echo "无法读取 APK 签名证书" >&2; exit 1; }

"${adb[@]}" wait-for-device
if [[ "$("${adb[@]}" shell getprop ro.kernel.qemu | tr -d '\r')" == "1" ]]; then
    echo "ANDROID_SERIAL=$ANDROID_SERIAL 是 Emulator；真机安装助手拒绝继续" >&2
    exit 1
fi

tmp_dir=$(mktemp -d)
install_pid=""
cleanup() {
    if [[ -n "$install_pid" ]] && kill -0 "$install_pid" >/dev/null 2>&1; then
        kill "$install_pid" >/dev/null 2>&1 || true
        wait "$install_pid" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

verify_installed_signer() {
    local installed_path pulled_apk installed_cert
    installed_path=$("${adb[@]}" shell pm path "$package_name" | tr -d '\r' |
        sed -n 's/^package://p' | head -n 1)
    [[ -n "$installed_path" ]] || return 1
    pulled_apk="$tmp_dir/installed-base.apk"
    "${adb[@]}" pull "$installed_path" "$pulled_apk" >/dev/null
    installed_cert=$("$apksigner" verify --print-certs "$pulled_apk" |
        sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr -d ':' | tr '[:upper:]' '[:lower:]')
    [[ "$installed_cert" == "$apk_cert" ]]
}

if "${adb[@]}" shell pm path "$package_name" | grep -q '^package:'; then
    if ! verify_installed_signer; then
        echo "已安装 Loom 与待安装 APK 签名不同；拒绝覆盖" >&2
        exit 1
    fi
fi

install_log="$tmp_dir/adb-install.log"
"${adb[@]}" install -r "$apk" >"$install_log" 2>&1 &
install_pid=$!
clicked=0
deadline=$((SECONDS + 35))
last_focus=""

while kill -0 "$install_pid" >/dev/null 2>&1 && (( SECONDS < deadline )); do
    # Android 16/HyperOS no longer emits mCurrentFocus for the legacy
    # `dumpsys window windows` subcommand. Query the full service dump so the
    # allowlist remains fail-closed while still seeing AdbInstallActivity.
    last_focus=$("${adb[@]}" shell dumpsys window 2>/dev/null |
        sed -n '/mCurrentFocus\|mFocusedApp/{p;q}' | tr -d '\r')
    case "$last_focus" in
        *com.miui.securitycenter*|*com.miui.packageinstaller*|*com.android.packageinstaller*|*com.google.android.packageinstaller*|*com.android.permissioncontroller*) ;;
        *) sleep 0.35; continue ;;
    esac

    remote_dump="/data/local/tmp/loom-install-window-$$.xml"
    if ! "${adb[@]}" shell uiautomator dump "$remote_dump" >/dev/null 2>&1; then
        sleep 0.35
        continue
    fi
    ui_dump="$tmp_dir/window.xml"
    "${adb[@]}" exec-out cat "$remote_dump" >"$ui_dump" 2>/dev/null || true
    "${adb[@]}" shell rm -f "$remote_dump" >/dev/null 2>&1 || true

    match=$(python3 "$script_dir/install_confirmation.py" "$ui_dump") || { sleep 0.35; continue; }

    read -r tap_x tap_y tap_label <<<"$match"
    screenshot="$tmp_dir/install-confirmation.png"
    "${adb[@]}" exec-out screencap -p >"$screenshot"
    if [[ -n "${INSTALL_EVIDENCE_DIR:-}" ]]; then
        mkdir -p -- "$INSTALL_EVIDENCE_DIR"
        cp -- "$screenshot" "$INSTALL_EVIDENCE_DIR/install-confirmation.png"
        cp -- "$ui_dump" "$INSTALL_EVIDENCE_DIR/install-confirmation.xml"
    fi
    echo "已验证 Loom 安装页；单次点击: $tap_label"
    "${adb[@]}" shell input tap "$tap_x" "$tap_y"
    clicked=1
    break
done

finish_deadline=$((SECONDS + 60))
while kill -0 "$install_pid" >/dev/null 2>&1 && (( SECONDS < finish_deadline )); do sleep 0.25; done
if kill -0 "$install_pid" >/dev/null 2>&1; then
    echo "ADB 安装在超时前未结束；已停止" >&2
    exit 1
fi
set +e
wait "$install_pid"
install_status=$?
set -e
install_pid=""
install_output=$(<"$install_log")
printf '%s\n' "$install_output"
if (( install_status != 0 )); then
    if (( clicked == 0 )); then
        echo "未找到同时包含 Loom 标识和唯一安装按钮的可信系统窗口" >&2
        echo "最后前台窗口: $last_focus" >&2
    fi
    exit "$install_status"
fi
grep -Fq 'Success' <<<"$install_output" || { echo "ADB 未返回 Success" >&2; exit 1; }
verify_installed_signer || { echo "安装后包名/签名验证失败" >&2; exit 1; }

installed_dump=$("${adb[@]}" shell dumpsys package "$package_name" | tr -d '\r')
installed_version=$(sed -n '/versionCode=/{p;q}' <<<"$installed_dump")
installed_version=$(sed 's/^[[:space:]]*//' <<<"$installed_version")
echo "Loom 安装完成；APK SHA-256=$actual_apk_sha；$installed_version"
