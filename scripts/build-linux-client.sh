#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

signing_key=${PLATFORM_SIGNING_KEY:-deploy/keys/platform-signing.key}
signing_pub=${PLATFORM_SIGNING_PUB:-deploy/keys/platform-signing.pub}
[ "$#" -eq 1 ] || { echo "usage: scripts/build-linux-client.sh GENERATION" >&2; exit 2; }
generation=$1
dataplane_dir="$repo/out/dataplane"

[ "${GOOS:-linux}" = linux ] || {
    echo "GOOS must be linux for the Linux client package" >&2
    exit 1
}
[ -f "$signing_key" ] || {
    echo "platform signing key is missing: $signing_key" >&2
    exit 1
}

mkdir -p deploy/staging
packager=$(mktemp deploy/staging/.loom-client-packager.XXXXXX)
trap 'rm -f "$packager"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" go build -trimpath -o "$packager" ./cmd/loom

build_arch() {
    arch=$1
    case "$arch" in
        amd64|arm64) sing_box="$dataplane_dir/sing-box-linux-$arch" ;;
        *) echo "unsupported Linux client architecture: $arch" >&2; exit 1 ;;
    esac
    [ -x "$sing_box" ] || {
        echo "real sing-box binary is missing or not executable for $arch: $sing_box" >&2
        exit 1
    }

    staged="deploy/staging/loom-linux-$arch"
    archive="deploy/staging/loom-client-linux-$arch.tar.gz"
    temporary=$(mktemp "deploy/staging/.loom-linux-$arch.XXXXXX")
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$temporary" ./cmd/loom
    chmod 0755 "$temporary"
    mv -f "$temporary" "$staged"

    set -- client package -loom "$staged" -sing-box "$sing_box" -dataplane-dir "$dataplane_dir" -generation "$generation" -key "$signing_key" -o "$archive"
    if [ "${ALLOW_DIRTY:-0}" = 1 ]; then set -- "$@" -allow-dirty; fi
    "$packager" "$@"
    "$packager" client verify -archive "$archive" -pubkey "$signing_pub" -arch "$arch"

}

if [ -n "${GOARCH:-}" ]; then
    build_arch "$GOARCH"
    echo "Built and verified Linux $GOARCH package."
else
    build_arch amd64
    build_arch arm64
    echo "Built and verified both Linux architectures; no release catalog or installed service was changed."
fi
