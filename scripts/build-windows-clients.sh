#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_root="$repo_root/out"
component_root="${LOOM_WINDOWS_COMPONENT_DIR:-$repo_root/deploy/staging}"
platform_public_key="${PLATFORM_SIGNING_PUB:-$repo_root/deploy/keys/platform-signing.pub}"
cd "$repo_root"
if [[ -n "${LOOM_WINDOWS_SIGN_CERT:-}" || -n "${LOOM_WINDOWS_TIMESTAMP_URL:-}" || "${LOOM_WINDOWS_REQUIRE_SIGNED:-0}" == 1 ]]; then
  if [[ -z "${LOOM_WINDOWS_SIGN_CERT:-}" || -z "${LOOM_WINDOWS_TIMESTAMP_URL:-}" ]]; then
    echo "signed builds require LOOM_WINDOWS_SIGN_CERT and LOOM_WINDOWS_TIMESTAMP_URL" >&2
    exit 1
  fi
  command -v powershell.exe >/dev/null
  command -v wslpath >/dev/null
fi
mkdir -p "$output_root"
if ! command -v flock >/dev/null 2>&1; then
  echo "flock is required to serialize Windows client builds" >&2
  exit 1
fi
exec 9>"$output_root/.windows-build.lock"
if ! flock -n 9; then
  echo "another Windows client build is already running" >&2
  exit 1
fi

if [[ ! -f "$platform_public_key" ]]; then
  echo "missing trusted platform public key: $platform_public_key" >&2
  exit 1
fi
stage_root=$(mktemp -d "$output_root/.windows-build.XXXXXX")
cleanup() {
  rm -rf -- "$stage_root"
}
trap cleanup EXIT HUP INT TERM
artifacts=()
staged_platform_public_key="$stage_root/platform-signing.pub"
install -m 0644 "$platform_public_key" "$staged_platform_public_key"
platform_public_key_value=$(tr -d '\r\n' < "$staged_platform_public_key")

archive_bundle() {
  local source_dir=$1
  local archive=$2
  local executable_name=$3
  local files=(
    "$executable_name"
    windows-dataplane.zip
    PREVIEW-NOTICE.txt
    LICENSE
    NOTICE
    licenses/gozxing-LICENSE
    licenses/golang-x-sys-LICENSE
    licenses/golang-x-sys-PATENTS
    licenses/golang-x-text-LICENSE
    licenses/golang-x-text-PATENTS
    licenses/golang-x-xerrors-LICENSE
    licenses/golang-x-xerrors-PATENTS
    licenses/yaml-v3-LICENSE
  )
  rm -f "$archive"
  if command -v zip >/dev/null 2>&1; then
    (cd "$source_dir" && zip -q -X "$archive" "${files[@]}")
    return
  fi
  if command -v bsdtar >/dev/null 2>&1; then
    bsdtar -a -cf "$archive" -C "$source_dir" "${files[@]}"
    return
  fi
  if [[ -x /mnt/c/Windows/System32/tar.exe ]]; then
    local windows_archive windows_source
    windows_archive=$(wslpath -w "$archive")
    windows_source=$(wslpath -w "$source_dir")
    /mnt/c/Windows/System32/tar.exe -a -cf "$windows_archive" -C "$windows_source" "${files[@]}"
    return
  fi
  echo "cannot create Windows ZIP: install zip or bsdtar" >&2
  return 1
}

install_module_notices() {
  local bundle_dir=$1
  local license_dir="$bundle_dir/licenses"
  if [[ -L "$license_dir" ]]; then
    echo "refusing symlinked license directory: $license_dir" >&2
    return 1
  fi
  mkdir -p "$license_dir"

  local module_dir
  module_dir=$(go list -m -f '{{.Dir}}' github.com/makiuchi-d/gozxing)
  install -m 0644 "$module_dir/LICENSE" "$license_dir/gozxing-LICENSE"
  module_dir=$(go list -m -f '{{.Dir}}' golang.org/x/sys)
  install -m 0644 "$module_dir/LICENSE" "$license_dir/golang-x-sys-LICENSE"
  install -m 0644 "$module_dir/PATENTS" "$license_dir/golang-x-sys-PATENTS"
  module_dir=$(go list -m -f '{{.Dir}}' golang.org/x/text)
  install -m 0644 "$module_dir/LICENSE" "$license_dir/golang-x-text-LICENSE"
  install -m 0644 "$module_dir/PATENTS" "$license_dir/golang-x-text-PATENTS"
  module_dir=$(go list -m -f '{{.Dir}}' golang.org/x/xerrors)
  install -m 0644 "$module_dir/LICENSE" "$license_dir/golang-x-xerrors-LICENSE"
  install -m 0644 "$module_dir/PATENTS" "$license_dir/golang-x-xerrors-PATENTS"
  module_dir=$(go list -m -f '{{.Dir}}' gopkg.in/yaml.v3)
  install -m 0644 "$module_dir/LICENSE" "$license_dir/yaml-v3-LICENSE"
}

for arch in amd64 arm64; do
  component="$component_root/loom-windows-dataplane-1.11.4-${arch}.zip"
  if [[ ! -f "$component" ]]; then
    echo "missing signed Windows data plane: $component" >&2
    exit 1
  fi
  staged_component="$stage_root/windows-dataplane-${arch}.zip"
  install -m 0644 "$component" "$staged_component"
  go run ./cmd/loom client verify-windows -archive "$staged_component" \
    -pubkey "$staged_platform_public_key" -arch "$arch" >/dev/null
  for edition in installed portable-mixed portable-tun; do
    artifact="loom-client-windows-${edition}-${arch}"
    bundle_dir="$stage_root/$artifact"
    target="$bundle_dir/${artifact}.exe"
    bundle="$stage_root/${artifact}.zip"
    subsystem_ldflag="-H=windowsgui"
    echo "building windows/${arch} ${edition}"
    mkdir -p "$bundle_dir"
    CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w ${subsystem_ldflag} -X main.buildEdition=${edition} -X main.buildPlatformPublicKey=${platform_public_key_value} -X loom/internal/version.Tag=windows-${edition}-${arch}" \
      -o "$target" ./clients/windows
    if [[ -n "${LOOM_WINDOWS_SIGN_CERT:-}" ]]; then
      powershell.exe -NoProfile -NonInteractive -File "$(wslpath -w "$repo_root/scripts/sign-windows-artifact.ps1")" \
        -Path "$(wslpath -w "$target")" -CertificateThumbprint "$LOOM_WINDOWS_SIGN_CERT" \
        -TimestampUrl "$LOOM_WINDOWS_TIMESTAMP_URL" -SignTool "${LOOM_WINDOWS_SIGNTOOL:-signtool.exe}"
    fi
    install -m 0644 "$staged_component" "$bundle_dir/windows-dataplane.zip"
    install -m 0644 "$repo_root/clients/windows/PREVIEW-NOTICE.txt" "$bundle_dir/PREVIEW-NOTICE.txt"
    install -m 0644 "$repo_root/LICENSE" "$bundle_dir/LICENSE"
    install -m 0644 "$repo_root/NOTICE" "$bundle_dir/NOTICE"
    install_module_notices "$bundle_dir"
    archive_bundle "$bundle_dir" "$bundle" "${artifact}.exe"
    echo "packaged $bundle"
    artifacts+=("$artifact")
  done
done

(
  cd "$stage_root"
  archives=()
  for artifact in "${artifacts[@]}"; do
    archives+=("${artifact}.zip")
  done
  sha256sum "${archives[@]}" > windows-clients-SHA256SUMS
)

# Build and verification failures before publication leave the previous set
# untouched. ZIPs are published first and the checksum list last; consumers
# treat that list as the set-level commit marker and reject partial publication.
for artifact in "${artifacts[@]}"; do
  mv -f "$stage_root/${artifact}.zip" "$output_root/${artifact}.zip"
  rm -f -- "$output_root/${artifact}.exe"
  old_bundle_dir="$output_root/$artifact"
  if [[ -L "$old_bundle_dir" ]]; then
    rm -f -- "$old_bundle_dir"
  elif [[ -d "$old_bundle_dir" ]]; then
    rm -rf -- "$old_bundle_dir"
  elif [[ -e "$old_bundle_dir" ]]; then
    echo "refusing unexpected legacy bundle path: $old_bundle_dir" >&2
    exit 1
  fi
done
mv -f "$stage_root/windows-clients-SHA256SUMS" "$output_root/windows-clients-SHA256SUMS"
for arch in amd64 arm64; do
  rm -f -- "$output_root/loom-client-windows-${arch}.exe"
done
trap - EXIT HUP INT TERM
cleanup
