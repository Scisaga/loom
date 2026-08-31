#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

client_arch=${GOARCH:-$(go env GOARCH)}
sing_box=${SING_BOX_BINARY:-/usr/local/bin/sing-box}
signing_key=${PLATFORM_SIGNING_KEY:-deploy/keys/platform-signing.key}
staged=deploy/staging/loom
archive="deploy/staging/loom-client-linux-${client_arch}.tar.gz"
client_dist_dir=${CLIENT_DIST_DIR:-/var/lib/loom/client-dist}

[ "${GOOS:-linux}" = linux ] || {
    echo "GOOS must be linux for the Linux client package" >&2
    exit 1
}
[ -x "$sing_box" ] || {
    echo "real sing-box binary is missing or not executable: $sing_box" >&2
    exit 1
}
[ -f "$signing_key" ] || {
    echo "platform signing key is missing: $signing_key" >&2
    exit 1
}

mkdir -p deploy/staging
tmp=$(mktemp deploy/staging/.loom-client-build.XXXXXX)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH="$client_arch" go build -trimpath -o "$tmp" ./cmd/loom
chmod 0755 "$tmp"
mv -f "$tmp" "$staged"
trap - EXIT HUP INT TERM

set -- client package -loom "$staged" -sing-box "$sing_box" -key "$signing_key" -o "$archive"
if [ "${ALLOW_DIRTY:-0}" = 1 ]; then
    set -- "$@" -allow-dirty
fi
"$staged" "$@"

"$staged" client verify -archive "$archive" -pubkey "${PLATFORM_SIGNING_PUB:-deploy/keys/platform-signing.pub}"

[ ! -L "$client_dist_dir" ] || {
    echo "client distribution directory must not be a symlink: $client_dist_dir" >&2
    exit 1
}
install -d -m 0755 "$client_dist_dir"
publish_file() {
    source_file=$1
    destination="$client_dist_dir/$(basename -- "$source_file")"
    temporary=$(mktemp "$client_dist_dir/.client-dist.XXXXXX")
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    install -m 0644 "$source_file" "$temporary"
    mv -f "$temporary" "$destination"
    trap - EXIT HUP INT TERM
}

# The archive is the commit marker: verification sidecars become visible first,
# then the fully-written body replaces the previously downloadable generation.
publish_file "$archive.sha256"
publish_file "$archive.sig"
publish_file "$archive.pub"
publish_file "$archive"
echo "Published Linux client package to $client_dist_dir/$(basename -- "$archive")"
