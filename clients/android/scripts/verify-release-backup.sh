#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <encrypted-backup> <passphrase-file>" >&2
    exit 2
fi

backup=$1
passphrase_file=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
android_root=$(cd -- "$script_dir/.." && pwd)
repo_root=$(cd -- "$android_root/../.." && pwd)
live_dir=${LOOM_ANDROID_SIGNING_DIR:-"$repo_root/deploy/android"}
live_store="$live_dir/loom-release.p12"
live_environment="$live_dir/android-signing.env"

for path in "$backup" "$passphrase_file" "$live_store" "$live_environment"; do
    if [[ ! -r "$path" ]]; then
        echo "required recovery input is not readable: $path" >&2
        exit 1
    fi
done

restore_root=$(mktemp -d)
cleanup() {
    chmod -R u+rwX -- "$restore_root" 2>/dev/null || true
    rm -rf -- "$restore_root"
}
trap cleanup EXIT

cd -- "$repo_root"
go run ./cmd/loom restore "$backup" -o "$restore_root" \
    -passphrase-file "$passphrase_file" >/dev/null

recovered_dir="$restore_root/deploy/android"
recovered_store="$recovered_dir/loom-release.p12"
recovered_environment="$recovered_dir/android-signing.env"
for path in "$recovered_store" "$recovered_environment"; do
    if [[ ! -f "$path" ]]; then
        echo "backup is missing Android release signing material" >&2
        exit 1
    fi
done

if ! cmp -s -- "$live_store" "$recovered_store"; then
    echo "recovered Android keystore differs from the live source" >&2
    exit 1
fi
if ! cmp -s -- "$live_environment" "$recovered_environment"; then
    echo "recovered Android signing environment differs from the live source" >&2
    exit 1
fi

# The live and recovered environment files are byte-identical at this point.
# Source the recovered copy so this drill proves the credentials in the archive,
# then force keytool to open the recovered store rather than the live path it names.
set -a
# shellcheck disable=SC1090
source "$recovered_environment"
set +a
for name in \
    LOOM_ANDROID_RELEASE_STORE_PASSWORD \
    LOOM_ANDROID_RELEASE_KEY_ALIAS; do
    if [[ -z "${!name:-}" ]]; then
        echo "recovered signing environment is missing $name" >&2
        exit 1
    fi
done

export LOOM_RECOVERED_STORE_PASSWORD=$LOOM_ANDROID_RELEASE_STORE_PASSWORD
keytool -list \
    -keystore "$recovered_store" \
    -storetype PKCS12 \
    -storepass:env LOOM_RECOVERED_STORE_PASSWORD \
    -alias "$LOOM_ANDROID_RELEASE_KEY_ALIAS" >/dev/null
unset LOOM_RECOVERED_STORE_PASSWORD

echo "verified Android release-signing recovery without modifying the live key"
