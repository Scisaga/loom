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

source_commit=$(git -C "$repo_root" rev-parse HEAD)
if ! git -C "$repo_root" diff --quiet -- mobile/loomcore clients/android internal/clientmodel; then
    echo "Android release inputs differ from source commit $source_commit" >&2
    exit 1
fi
if [[ -n "$(git -C "$repo_root" ls-files --others --exclude-standard -- mobile/loomcore clients/android internal/clientmodel)" ]]; then
    echo "Android release inputs contain untracked files" >&2
    exit 1
fi

"$script_dir/build-mobile-aar.sh"
aar="$android_root/app/libs/loom-box.aar"
aar_sha256=$(sha256sum "$aar" | cut -d' ' -f1)
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
./gradlew --no-daemon --max-workers="$workers" \
    -PloomSourceCommit="$source_commit" -PloomAarSha256="$aar_sha256" \
    testDebugUnitTest lintRelease assembleRelease

apk="$android_root/app/build/outputs/apk/release/app-release.apk"
[[ -f "$apk" ]] || { echo "signed release APK was not produced" >&2; exit 1; }
"$apksigner" verify --verbose --print-certs "$apk"
for abi in arm64-v8a x86_64; do
    aar_library=$(unzip -p "$aar" "jni/$abi/libbox.so" | sha256sum | cut -d' ' -f1)
    apk_library=$(unzip -p "$apk" "lib/$abi/libbox.so" | sha256sum | cut -d' ' -f1)
    if [[ "$aar_library" != "$apk_library" ]]; then
        echo "APK $abi libbox.so does not match the audited AAR" >&2
        exit 1
    fi
done
echo "source $source_commit"
echo "aar $aar_sha256"
sha256sum "$apk"
