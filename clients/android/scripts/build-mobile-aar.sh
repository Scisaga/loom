#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
android_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_dir=$(CDPATH= cd -- "$android_dir/../.." && pwd)
build_dir="$android_dir/.build"
source_dir="$build_dir/sing-box-patched"
go_bin="$build_dir/go/bin"
go_path="$build_dir/go/path"
go_cache="$build_dir/go/cache"
output="$build_dir/loom-box.aar"

gomobile_version="v0.1.13"
go_toolchain="go1.27.0"
ndk_version="28.0.13004108"
# x/net 0.57 uses a Go 1.27 standard-library wrapper by default. Fixed
# sing-box 1.11.4 requires x/net's own Transport for its existing connection
# reset hook; select the upstream compatibility implementation, same module.
tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy"

android_sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
if [[ -z "$android_sdk" ]]; then
    echo "ANDROID_HOME 或 ANDROID_SDK_ROOT 未设置" >&2
    exit 1
fi
ndk_dir="$android_sdk/ndk/$ndk_version"
if [[ ! -x "$ndk_dir/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ]]; then
    echo "缺少固定 NDK $ndk_version: $ndk_dir" >&2
    exit 1
fi
if ! java --version 2>&1 | head -n 1 | grep -q '17'; then
    echo "libbox 构建必须使用 OpenJDK 17" >&2
    exit 1
fi

mkdir -p "$build_dir" "$go_bin" "$go_path" "$go_cache" "$android_dir/app/libs"
python3 "$repo_dir/scripts/prepare-sing-box.py" "$source_dir"
sing_box_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifact_version"])' "$source_dir/.loom-source-provenance.json")

# Android uses the same schema-3 control/deviceclient source and canonical
# codecs as desktop clients. Never generate a second reduced authority module.
env GOTOOLCHAIN="$go_toolchain" GOBIN="$go_bin" GOPATH="$go_path" GOCACHE="$go_cache" \
    go install "github.com/sagernet/gomobile/cmd/gomobile@$gomobile_version"
env GOTOOLCHAIN="$go_toolchain" GOBIN="$go_bin" GOPATH="$go_path" GOCACHE="$go_cache" \
    go install "github.com/sagernet/gomobile/cmd/gobind@$gomobile_version"
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod tidy
(
    cd "$source_dir"
    env GOTOOLCHAIN="$go_toolchain" GOWORK=off PATH="$go_bin:$PATH" GOPATH="$go_path" GOCACHE="$go_cache" \
        ANDROID_HOME="$android_sdk" ANDROID_NDK_HOME="$ndk_dir" "$go_bin/gomobile" init
)

# 两个 Go package 在同一次 bind 中生成，APK 内因此只有一份 libbox.so
# 和一个 Go runtime。共享核心直接复用唯一的 control/deviceclient 契约与 transport。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod edit \
    -replace="loom/mobile/loomcore=$repo_dir/mobile/loomcore" \
    -replace="loom=$repo_dir"
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" get loom/mobile/loomcore@v0.0.0
# 根模块会在首次上游 tidy 后提高已选 x/* 版本；应用两个本地 replace 后刷新摘要。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod tidy
# tidy 看不到 gomobile 命令行 bind 目标；刷新传递摘要后显式保留两个本地模块。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod edit \
    -require="loom@v0.0.0" \
    -require="loom/mobile/loomcore@v0.0.0"
# The bind targets are outside sing-box sources; retain their complete module
# checksums after tidy prunes packages it does not compile itself.
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod download all

(
    cd "$source_dir"
    env GOTOOLCHAIN="$go_toolchain" GOWORK=off PATH="$go_bin:$PATH" GOPATH="$go_path" GOCACHE="$go_cache" \
        ANDROID_HOME="$android_sdk" ANDROID_NDK_HOME="$ndk_dir" GOFLAGS="-mod=mod" \
        "$go_bin/gomobile" bind \
        -target=android/arm64,android/amd64 \
        -androidapi=26 \
        -javapkg=io.github.scisaga \
        -libname=box \
        -trimpath \
        -buildvcs=false \
        -ldflags="-X github.com/sagernet/sing-box/constant.Version=$sing_box_version -s -w -buildid=" \
        -tags="$tags" \
        -o "$output" \
        github.com/sagernet/sing-box/experimental/libbox loom/mobile/loomcore
)

entries=$(unzip -Z1 "$output")
grep -qx 'jni/arm64-v8a/libbox.so' <<<"$entries"
grep -qx 'jni/x86_64/libbox.so' <<<"$entries"
if grep -Eq '^jni/(armeabi-v7a|x86)/' <<<"$entries"; then
    echo "AAR 含未授权 ABI" >&2
    exit 1
fi
# Carry the existing reviewed source record with these exact native bytes.
# It has no runtime/installation state and introduces no alternate source of
# versions: the caller uses this same record for Libbox's compiled constant.
python3 - "$output" "$source_dir/.loom-source-provenance.json" <<'PY'
import os, pathlib, sys, zipfile
archive, provenance = map(pathlib.Path, sys.argv[1:])
temporary = archive.with_suffix('.with-source.aar')
name = 'assets/loom/source-provenance.json'
with zipfile.ZipFile(archive) as source, zipfile.ZipFile(temporary, 'w') as target:
    assert name not in source.namelist()
    entries = {entry.filename: entry for entry in source.infolist()}
    extra = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    extra.create_system = 3
    extra.external_attr = 0o100644 << 16
    for member in sorted([*entries, name]):
        target.writestr(extra if member == name else entries[member],
                        provenance.read_bytes() if member == name else source.read(member))
    target.comment = source.comment
os.replace(temporary, archive)
PY
cp "$output" "$android_dir/app/libs/loom-box.aar"
sha256sum "$output" | tee "$build_dir/loom-box.sha256"
