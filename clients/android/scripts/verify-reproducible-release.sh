#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
android_root=$(cd -- "$script_dir/.." && pwd)
workers=${LOOM_ANDROID_GRADLE_WORKERS:-4}
if [[ ! "$workers" =~ ^[1-4]$ ]]; then
    echo "LOOM_ANDROID_GRADLE_WORKERS must be between 1 and 4" >&2
    exit 1
fi

tmp_dir=$(mktemp -d)
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

clean_build() {
    local label=$1
    (cd -- "$android_root" && ./gradlew --no-daemon --max-workers="$workers" clean)
    "$script_dir/build-release.sh"
    cp -- "$android_root/app/build/outputs/apk/release/app-release.apk" "$tmp_dir/$label.apk"
    cp -- "$android_root/app/build/reports/sbom/loom-android-release.spdx.json" "$tmp_dir/$label.spdx.json"
}

clean_build first
clean_build second
cmp -- "$tmp_dir/first.apk" "$tmp_dir/second.apk" || {
    echo "Android release APK is not reproducible across clean builds" >&2
    exit 1
}
cmp -- "$tmp_dir/first.spdx.json" "$tmp_dir/second.spdx.json" || {
    echo "Android release SBOM is not reproducible across clean builds" >&2
    exit 1
}

sha256sum -- "$tmp_dir/second.apk" "$tmp_dir/second.spdx.json"
echo "verified byte-identical Android release APK and SBOM across two clean builds"
