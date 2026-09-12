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

go test ./internal/wire ./internal/clientv2 ./internal/clientcomponent ./internal/controlplane ./internal/deploy -count=1
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
        "loom/internal/controlplane",
        "loom/internal/deploy",
    ],
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
