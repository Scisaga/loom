#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
android_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_dir=$(CDPATH= cd -- "$android_dir/../.." && pwd)
build_dir="$android_dir/.build"
source_dir="$build_dir/sing-box"
shared_dir="$build_dir/loom-shared"
go_bin="$build_dir/go/bin"
go_path="$build_dir/go/path"
go_cache="$build_dir/go/cache"
output="$build_dir/loom-box.aar"

sing_box_version="1.11.4"
sing_box_commit="eb07c7a79eeca943370eafea601e87da76c0e57e"
gomobile_version="v0.1.13"
go_toolchain="go1.27.0"
ndk_version="28.0.13004108"
tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api"

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
if [[ ! -d "$source_dir/.git" ]]; then
    git clone --filter=blob:none --no-checkout https://github.com/SagerNet/sing-box.git "$source_dir"
fi
git -C "$source_dir" fetch --depth=1 origin "$sing_box_commit"
git -C "$source_dir" checkout --detach "$sing_box_commit"
test "$(git -C "$source_dir" rev-parse HEAD)" = "$sing_box_commit"
if ! git -C "$source_dir" diff --quiet "$sing_box_commit" -- . ':(exclude)go.mod' ':(exclude)go.sum'; then
    echo "sing-box 构建目录含非 go.mod/go.sum 的本地修改；拒绝构建" >&2
    exit 1
fi
if [[ -n "$(git -C "$source_dir" ls-files --others --exclude-standard)" ]]; then
    echo "sing-box 构建目录含未跟踪源码；拒绝构建" >&2
    exit 1
fi
# 前一次构建会为本地 Loom module 改写这两个文件。每次都从固定
# commit 恢复原始输入，再应用同一组 module edits。
git -C "$source_dir" show "$sing_box_commit:go.mod" >"$source_dir/go.mod"
git -C "$source_dir" show "$sing_box_commit:go.sum" >"$source_dir/go.sum"

# §14.1：从精确共享信任/选路源码生成依赖收敛视图。若直接替换整个根模块，
# 无关的新 x/* 版本会经 MVS 覆盖 sing-box 1.11.4 的依赖并破坏钉住的数据面。
case "$shared_dir" in
    "$android_dir"/.build/*) ;;
    *) echo "拒绝清理非 Android 构建目录: $shared_dir" >&2; exit 1 ;;
esac
rm -rf -- "$shared_dir"
mkdir -p "$shared_dir/internal"
cp -a "$repo_dir/internal/attest" "$repo_dir/internal/clientroute" \
    "$repo_dir/internal/observation" "$repo_dir/internal/version" "$shared_dir/internal/"
printf 'module loom\n\ngo 1.27.0\n' >"$shared_dir/go.mod"

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
# 和一个 Go runtime。共享核心复用仓库内 canonical v5 verifier 与客户端
# 分段选路包，因此两个临时 replace 都必须固定到当前 checkout。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod edit \
    -replace="loom/mobile/loomcore=$repo_dir/mobile/loomcore" \
    -replace="loom=$shared_dir"
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" get loom/mobile/loomcore@v0.0.0
# 根模块会在首次上游 tidy 后提高已选 x/* 版本；应用两个本地 replace 后刷新摘要。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod tidy
# tidy 看不到 gomobile 命令行 bind 目标；刷新传递摘要后显式保留两个本地模块。
GOWORK=off GOTOOLCHAIN="$go_toolchain" go -C "$source_dir" mod edit \
    -require="loom@v0.0.0" \
    -require="loom/mobile/loomcore@v0.0.0"

(
    cd "$source_dir"
    env GOTOOLCHAIN="$go_toolchain" GOWORK=off PATH="$go_bin:$PATH" GOPATH="$go_path" GOCACHE="$go_cache" \
        ANDROID_HOME="$android_sdk" ANDROID_NDK_HOME="$ndk_dir" \
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
cp "$output" "$android_dir/app/libs/loom-box.aar"
sha256sum "$output" | tee "$build_dir/loom-box.sha256"
