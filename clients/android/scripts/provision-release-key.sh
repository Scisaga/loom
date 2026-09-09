#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
android_root=$(cd -- "$script_dir/.." && pwd)
repo_root=$(cd -- "$android_root/../.." && pwd)
target_dir=${LOOM_ANDROID_SIGNING_DIR:-"$repo_root/deploy/android"}
store="$target_dir/loom-release.p12"
environment="$target_dir/android-signing.env"
alias_name=loom-release

mkdir -p -- "$target_dir"
chmod 0700 -- "$target_dir"
if [[ -e "$store" || -e "$environment" ]]; then
    echo "refusing to replace existing Android release signing material in $target_dir" >&2
    exit 1
fi

temporary_environment=$(mktemp "$target_dir/.android-signing.env.XXXXXX")
created_store=false
cleanup() {
    status=$?
    if [[ -e "$temporary_environment" ]]; then unlink "$temporary_environment"; fi
    if [[ $status -ne 0 && "$created_store" == true && -e "$store" ]]; then unlink "$store"; fi
    exit "$status"
}
trap cleanup EXIT

password=$(openssl rand -hex 32)
export LOOM_KEYSTORE_PASSWORD="$password"
keytool -genkeypair -noprompt \
    -keystore "$store" \
    -storetype PKCS12 \
    -storepass:env LOOM_KEYSTORE_PASSWORD \
    -keypass:env LOOM_KEYSTORE_PASSWORD \
    -alias "$alias_name" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 10000 \
    -dname "CN=Loom Android Release,O=Loom"
created_store=true
chmod 0600 -- "$store"

{
    printf 'LOOM_ANDROID_RELEASE_STORE_FILE=%q\n' "$store"
    printf 'LOOM_ANDROID_RELEASE_STORE_PASSWORD=%q\n' "$password"
    printf 'LOOM_ANDROID_RELEASE_KEY_ALIAS=%q\n' "$alias_name"
    printf 'LOOM_ANDROID_RELEASE_KEY_PASSWORD=%q\n' "$password"
} >"$temporary_environment"
chmod 0600 -- "$temporary_environment"
mv -- "$temporary_environment" "$environment"
unset LOOM_KEYSTORE_PASSWORD password

echo "created encrypted Android upgrade key and root-only build environment in $target_dir"
echo "make a separate protected backup before distributing an APK signed by this key"
