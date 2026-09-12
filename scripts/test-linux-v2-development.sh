#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

output=${1:-docs/status/linux-v2-development-evidence.json}
case "$output" in
    /*) ;;
    *) output="$repo/$output" ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

LOOM_INSTALLER_NAMESPACE_TEST=1 go test ./cmd/loom ./internal/wire ./internal/clientv2 ./internal/clientcomponent \
    ./internal/clientdist ./internal/clientenroll ./internal/clientruntime \
    ./internal/controlplane ./internal/deploy -count=1

# 在无宿主权限、仅 loopback 的 user+network namespace 中启动固定版本
# sing-box，真实覆盖 TUN 域名恢复、DNS/HTTP/TLS 与停止生命周期。
tun_executable=${LOOM_TUN_ROUTING_EXECUTABLE:-}
if [ -z "$tun_executable" ]; then
    tun_executable=$(command -v sing-box)
fi
test -x "$tun_executable"
command -v unshare >/dev/null
command -v ip >/dev/null
tun_test="$temporary/clientruntime-tun.test"
go test -c -o "$tun_test" ./internal/clientruntime
chmod 0755 "$temporary" "$tun_test"
if [ "$(id -u)" -eq 0 ]; then
    LOOM_TUN_ROUTING_EXECUTABLE="$tun_executable" \
        unshare --user --map-users=65534,0,1 --map-groups=65534,0,1 \
        --setuid 0 --setgid 0 --net "$tun_test" \
        -test.run '^TestOfficialTUNServiceRouting$'
else
    LOOM_TUN_ROUTING_EXECUTABLE="$tun_executable" \
        unshare -Urn "$tun_test" -test.run '^TestOfficialTUNServiceRouting$'
fi

for architecture in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -o "$temporary/loom-linux-$architecture" ./cmd/loom
    test -s "$temporary/loom-linux-$architecture"
done
python3 scripts/check_repository_safety.py

commit=$(git rev-parse HEAD)
dirty=false
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    dirty=true
fi
recorded_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
go_version=$(go version | awk '{print $3}')
mkdir -p "$(dirname -- "$output")"
OUTPUT="$output" COMMIT="$commit" DIRTY="$dirty" RECORDED_AT="$recorded_at" GO_VERSION="$go_version" \
python3 - <<'PY'
import json
import os
import tempfile

output = os.environ["OUTPUT"]
evidence = {
    "schema": 1,
    "kind": "linux_v2_development_evidence",
    "result": "passed",
    "recorded_at": os.environ["RECORDED_AT"],
    "commit": os.environ["COMMIT"],
    "dirty_worktree": os.environ["DIRTY"] == "true",
    "go_version": os.environ["GO_VERSION"],
    "build_targets": ["linux/amd64", "linux/arm64"],
    "test_suites": [
        "loom/internal/wire",
        "loom/internal/clientv2",
        "loom/internal/clientcomponent",
        "loom/internal/clientdist",
        "loom/internal/clientenroll",
        "loom/internal/clientruntime",
        "loom/internal/controlplane",
        "loom/internal/deploy",
        "loom/cmd/loom",
        "loom/internal/clientruntime:TestOfficialTUNServiceRouting(namespace)",
    ],
    "network_namespace_tun": True,
    "scope": "development_only",
    "real_host_acceptance": False,
    "gate_b": False,
}
directory = os.path.dirname(output)
fd, temporary = tempfile.mkstemp(prefix=".linux-v2-evidence-", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY

echo "Linux v2 development checks passed; redacted evidence: $output"
