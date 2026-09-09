#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
android_root=$(cd -- "$script_dir/.." && pwd)
repo_root=$(cd -- "$android_root/../.." && pwd)
signing_env=${LOOM_ANDROID_SIGNING_ENV_FILE:-"$repo_root/deploy/android/android-signing.env"}

if [[ ! -r "$signing_env" ]]; then
    echo "release signing environment is not readable: $signing_env" >&2
    exit 1
fi

set -a
# This ignored, operator-owned file contains only KEY=VALUE assignments.
# shellcheck disable=SC1090
source "$signing_env"
set +a

required=(
    LOOM_ANDROID_RELEASE_STORE_FILE
    LOOM_ANDROID_RELEASE_STORE_PASSWORD
    LOOM_ANDROID_RELEASE_KEY_ALIAS
    LOOM_ANDROID_RELEASE_KEY_PASSWORD
)
for name in "${required[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        echo "release signing environment is missing $name" >&2
        exit 1
    fi
done

android_sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
if [[ -z "$android_sdk" ]]; then
    echo "ANDROID_HOME or ANDROID_SDK_ROOT is required" >&2
    exit 1
fi
apksigner="$android_sdk/build-tools/35.0.1/apksigner"
if [[ ! -x "$apksigner" ]]; then
    echo "pinned apksigner is unavailable: $apksigner" >&2
    exit 1
fi

workers=${LOOM_ANDROID_GRADLE_WORKERS:-4}
if [[ ! "$workers" =~ ^[1-4]$ ]]; then
    echo "LOOM_ANDROID_GRADLE_WORKERS must be between 1 and 4" >&2
    exit 1
fi

cd -- "$android_root"
./gradlew --no-daemon --max-workers="$workers" testDebugUnitTest lintRelease assembleRelease

apk="$android_root/app/build/outputs/apk/release/app-release.apk"
[[ -f "$apk" ]] || { echo "signed release APK was not produced" >&2; exit 1; }
"$apksigner" verify --verbose --print-certs "$apk"
sha256sum "$apk"
