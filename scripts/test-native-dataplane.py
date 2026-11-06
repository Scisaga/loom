#!/usr/bin/env python3
"""Rebuild and verify the pinned Linux data plane, without publishing it."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
TAGS = "with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy"
MODULES = (
    (".", "github.com/sagernet/sing-box"),
    (".loom-sing", "github.com/sagernet/sing"),
    (".loom-sing-tun", "github.com/sagernet/sing-tun"),
    (".loom-sing-quic", "github.com/sagernet/sing-quic"),
    (".loom-wireguard", "github.com/sagernet/wireguard-go"),
)
TEST_GROUPS = (
    ("execution-and-transports", ".", (
        "./common/loomprotocol", "./common/execution", "./common/sourcepool",
        "./protocol/wireguard", "./protocol/hysteria2", "./protocol/group",
        "./transport/wireguard")),
    ("quic", ".loom-sing-quic", ("./hysteria2",)),
    ("wireguard", ".loom-wireguard", ("./conn", "./device")),
    ("gvisor-udp", ".loom-sing-tun", (
        "-run=^TestGVisorUDPForwarderPreservesFragmentedPayload$", ".")),
)


def write_workspace(source, workfile, go_version):
    """Use the same pinned dependency graph from every nested module's cwd."""
    paths = []
    for relative, module in MODULES:
        path = source / relative
        declaration = (path / "go.mod").read_text().splitlines()[0]
        if declaration != "module " + module:
            raise ValueError("unexpected native module: " + relative)
        paths.append("\t" + json.dumps(str(path)))
    workfile.write_text("go " + go_version + "\n\nuse (\n" + "\n".join(paths) + "\n)\n")


def run_step(steps, directory, name, command, cwd, env, is_test=False):
    log = directory / "logs" / (name + ".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    step = {"name": name, "command": command, "cwd": str(cwd), "log": str(log), "status": "failed"}
    steps.append(step)
    print("Running " + name, flush=True)
    start = time.monotonic()
    try:
        with log.open("w") as output:
            subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
        if is_test:
            counts = {"pass": 0, "fail": 0, "skip": 0}
            for line in log.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("Test") and event.get("Action") in counts:
                    counts[event["Action"]] += 1
            step["tests"] = counts
            if not counts["pass"]:
                raise ValueError("no tests passed in " + name)
        step["status"] = "passed"
    finally:
        step["seconds"] = round(time.monotonic() - start, 3)
        print(name + ": " + step["status"] + " (" + str(step["seconds"]) + "s); " + str(log), flush=True)


def write_summary(directory, summary):
    (directory / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    lines = ["Native data plane: " + summary["status"], "", "| Step | Result | Seconds | Tests pass/fail/skip |",
             "|---|---|---:|---:|"]
    for step in summary["steps"]:
        tests = step.get("tests")
        counts = "/".join(str(tests[key]) for key in ("pass", "fail", "skip")) if tests else ""
        lines.append("| " + step["name"] + " | " + step["status"] + " | " + str(step["seconds"]) + " | " + counts + " |")
    lines += ["", "Coverage: execution codec, execution, source pool, WG, Hy2, selectors, WG transport;",
              "nested sing-quic/hysteria2, wireguard-go/conn and device, in-memory gVisor UDP; each also with race.",
              "Build: Linux amd64 with production data-plane tags. No signing, publication or deployment.",
              "Excludes host TUN/routes, device acceptance and production traffic."]
    if "error" in summary:
        lines += ["", "Failure: " + summary["error"]]
    (directory / "summary.md").write_text("\n".join(lines) + "\n")


def main():
    output = REPO / "out/native-dataplane-tests"
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    source = directory / "source"
    summary = {"status": "failed", "steps": []}
    steps = summary["steps"]
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("native data-plane verification requires Linux")
        go_version = re.search(r"^go (\S+)$", (REPO / "go.mod").read_text(), re.MULTILINE).group(1)
        env = {**os.environ, "GOWORK": "off", "GOTOOLCHAIN": "go" + go_version}
        run_step(steps, directory, "toolchain", ["go", "version"], REPO, env)
        run_step(steps, directory, "prepare-source", [sys.executable, str(REPO / "scripts/prepare-sing-box.py"), str(source)], REPO, env)
        provenance = (source / ".loom-source-provenance.json").read_bytes()
        (directory / "source-provenance.json").write_bytes(provenance)
        summary["source"] = json.loads(provenance)
        workfile = directory / "go.work"
        write_workspace(source, workfile, go_version)
        env["GOWORK"] = str(workfile)
        env["CGO_ENABLED"] = "1"
        # Ignore a caller's cross-compilation target when executing native tests.
        host = subprocess.check_output(["go", "env", "GOHOSTOS", "GOHOSTARCH"], cwd=source, env=env, text=True).split()
        env["GOOS"], env["GOARCH"] = host
        for race in (False, True):
            for name, module, packages in TEST_GROUPS:
                command = ["go", "test", "-json", "-count=1", "-timeout=5m", "-tags", TAGS]
                if race:
                    command.append("-race")
                command += list(packages)
                run_step(steps, directory, name + ("-race" if race else ""), command, source / module, env, is_test=True)
        binary = directory / "sing-box-linux-amd64"
        version = summary["source"]["artifact_version"]
        build_env = {**env, "GOWORK": "off", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        run_step(steps, directory, "build-linux-amd64", ["go", "build", "-trimpath", "-buildvcs=false", "-tags", TAGS,
                 "-ldflags", "-X github.com/sagernet/sing-box/constant.Version=" + version + " -s -w -buildid=",
                 "-o", str(binary), "./cmd/sing-box"], source, build_env)
        run_step(steps, directory, "build-info", ["go", "version", "-m", str(binary)], REPO, env)
        summary["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        summary["status"] = "passed"
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        summary["error"] = str(error)
        print("Native verification failed: " + str(error), file=sys.stderr)
    finally:
        write_summary(directory, summary)
        print("Summary: " + str(directory / "summary.json"), flush=True)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
