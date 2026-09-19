#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

signing_key=${PLATFORM_SIGNING_KEY:-deploy/keys/platform-signing.key}
signing_pub=${PLATFORM_SIGNING_PUB:-deploy/keys/platform-signing.pub}
client_release_root=${CLIENT_RELEASE_ROOT:-/var/lib/loom/client-dist/releases}

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
CGO_ENABLED=0 go build -trimpath -o "$packager" ./cmd/loom

build_arch() {
    arch=$1
    case "$arch" in
        amd64) sing_box=${SING_BOX_AMD64:-${SING_BOX_BINARY:-/usr/local/bin/sing-box}} ;;
        arm64) sing_box=${SING_BOX_ARM64:-deploy/staging/sing-box-linux-arm64} ;;
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

    set -- client package -loom "$staged" -sing-box "$sing_box" -key "$signing_key" -o "$archive"
    if [ "${ALLOW_DIRTY:-0}" = 1 ]; then set -- "$@" -allow-dirty; fi
    "$packager" "$@"
    "$packager" client verify -archive "$archive" -pubkey "$signing_pub" -arch "$arch"

}

[ ! -L "$client_release_root" ] || {
    echo "client release root must not be a symlink: $client_release_root" >&2
    exit 1
}

if [ -n "${GOARCH:-}" ]; then
    build_arch "$GOARCH"
    echo "Built and verified Linux $GOARCH package without changing the two-architecture catalog."
else
    build_arch amd64
    build_arch arm64
    "$packager" client publish-linux \
        -archive deploy/staging/loom-client-linux-amd64.tar.gz \
        -archive deploy/staging/loom-client-linux-arm64.tar.gz \
        -root "$client_release_root" -key "$signing_key"
    echo "Published signed Linux client packages to $client_release_root"
fi
