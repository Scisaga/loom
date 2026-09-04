#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
resource_dir="$repo_root/clients/windows"
rsrc_root="$(go env GOPATH)/pkg/mod/github.com/akavel/rsrc@v0.10.2"
stage_dir=$(mktemp -d /tmp/loom-windows-resources.XXXXXX)
cleanup() {
  rm -rf -- "$stage_dir"
}
trap cleanup EXIT HUP INT TERM

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg is required to rasterize the approved SVG assets" >&2
  exit 1
fi
if [[ ! -d "$rsrc_root" ]]; then
  echo "cached github.com/akavel/rsrc@v0.10.2 module is required" >&2
  exit 1
fi

# Render each Windows/DPI size directly from SVG. A single 256 px PNG makes
# USER32 resample the mark at runtime, which visibly softens the fine v4 lines.
icon_sizes=(16 20 24 32 40 48 60 64 72 80 96 128 256)
favicon_pngs=()
brand_pngs=()
for size in "${icon_sizes[@]}"; do
  favicon_png="$stage_dir/favicon-${size}.png"
  brand_png="$stage_dir/brand-v4-${size}.png"
  ffmpeg -loglevel error -i "$repo_root/internal/webui/favicon.svg" \
    -vf "scale=1060:1060:flags=lanczos,crop=1000:1000:30:30,scale=${size}:${size}:flags=lanczos" \
    -frames:v 1 "$favicon_png"
  ffmpeg -loglevel error -i "$repo_root/assets/loom-logo-v4.svg" \
    -vf "crop=1100:1100:77:77,scale=${size}:${size}:flags=lanczos" -frames:v 1 "$brand_png"
  favicon_pngs+=("$favicon_png")
  brand_pngs+=("$brand_png")
done
go run "$repo_root/scripts/windows-ico" "$stage_dir/favicon.ico" "${favicon_pngs[@]}"
go run "$repo_root/scripts/windows-ico" "$stage_dir/brand-v4.ico" "${brand_pngs[@]}"

install -m 0644 "$stage_dir/favicon.ico" "$resource_dir/favicon.ico"
install -m 0644 "$stage_dir/brand-v4.ico" "$resource_dir/loom-brand-v4.ico"
for arch in amd64 arm64; do
  (
    cd "$rsrc_root"
    go run . -arch "$arch" \
      -manifest "$resource_dir/loom.exe.manifest" \
      -ico "$resource_dir/favicon.ico,$resource_dir/loom-brand-v4.ico" \
      -o "$stage_dir/rsrc_windows_${arch}.syso"
  )
  install -m 0644 "$stage_dir/rsrc_windows_${arch}.syso" "$resource_dir/rsrc_windows_${arch}.syso"
done
