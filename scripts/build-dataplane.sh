#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir="$repo_root/out/sing-box-patched"
output_dir="$repo_root/out/dataplane"
mkdir -p "$output_dir"
exec 9>"$repo_root/out/.dataplane-build.lock"
flock -n 9 || { echo "another data-plane build is running" >&2; exit 1; }
python3 "$repo_root/scripts/prepare-sing-box.py" "$source_dir"
tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy"
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
    target_os=${target%/*}
    target_arch=${target#*/}
    extension=""
    if [[ "$target_os" == windows ]]; then extension=".exe"; fi
    env GOWORK=off GOTOOLCHAIN=go1.27.0 CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
        go -C "$source_dir" build -trimpath -buildvcs=false -tags "$tags" \
        -ldflags '-X github.com/sagernet/sing-box/constant.Version=1.11.4-loom.1 -s -w -buildid=' \
        -o "$output_dir/sing-box-$target_os-$target_arch$extension" ./cmd/sing-box
    echo "built data plane $target"
done
install -m 0644 "$source_dir/LICENSE" "$output_dir/LICENSE"
install -m 0644 "$source_dir/.loom-source-provenance.json" "$output_dir/source-provenance.json"
install -m 0644 "$repo_root/third_party/sing-box/domain-cache.patch" "$output_dir/domain-cache.patch"
install -m 0644 "$repo_root/scripts/prepare-sing-box.py" "$output_dir/prepare-sing-box.py"
install -m 0644 "$repo_root/scripts/build-dataplane.sh" "$output_dir/build-dataplane.sh"
(
    cd "$output_dir"
    sha256sum LICENSE source-provenance.json domain-cache.patch prepare-sing-box.py build-dataplane.sh sing-box-* > SHA256SUMS
)
