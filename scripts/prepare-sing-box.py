#!/usr/bin/env python3
"""Prepare pinned data-plane sources with the reviewed local patch."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parent.parent
VERSION = "v1.11.4"
COMMIT = "eb07c7a79eeca943370eafea601e87da76c0e57e"
SUM = "h1:Z3xLwVJlTJfJ1p8R9M05aNJLFKRAwGebA5M/DFmr8p8="
TUN_VERSION = "v0.6.1"
TUN_COMMIT = "c8c29842618b186b8eb802345504cc19d3d06872"
TUN_SUM = "h1:4l0+gnEKcGjlWfUVTD+W0BRApqIny/lU2ZliurE+VMo="
QUIC_VERSION = "v0.4.0"
QUIC_COMMIT = "297f0b2a2bb5aa0ba1a20b269ad31b4fede53272"
QUIC_SUM = "h1:E4geazHk/UrJTXMlT+CBCKmn8V86RhtNeczWtfeoEFc="
SING_VERSION = "v0.6.1"
SING_COMMIT = "9eafc7fc62b10528df821cdfbf4e4e8f122f4b7a"
SING_SUM = "h1:mJ6e7Ir2wtCoGLbdnnXWBsNJu5YHtbXmv66inoE0zFA="
MARKER = ".loom-generated-source"


def prepare(destination):
    destination = Path(destination).absolute()
    allowed = [REPO / "out", REPO / "clients/android/.build"]
    if destination.is_symlink() or not any(root in destination.resolve().parents for root in allowed):
        raise ValueError("source destination must be inside a repository build directory")
    if destination.exists() and (destination / MARKER).read_text() != COMMIT:
        raise ValueError("refusing to replace an unowned source directory")
    env = {**os.environ, "GOWORK": "off", "GOTOOLCHAIN": "go1.27.0"}
    module = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", "github.com/sagernet/sing-box@" + VERSION], env=env, cwd=REPO))
    if module["Sum"] != SUM or module["Origin"]["Hash"] != COMMIT:
        raise ValueError("upstream source does not match the reviewed module and commit")
    tun = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", "github.com/sagernet/sing-tun@" + TUN_VERSION], env=env, cwd=REPO))
    if tun["Sum"] != TUN_SUM or tun["Origin"]["Hash"] != TUN_COMMIT:
        raise ValueError("TUN source does not match the reviewed module and commit")
    quic = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", "github.com/sagernet/sing-quic@" + QUIC_VERSION], env=env, cwd=REPO))
    if quic["Sum"] != QUIC_SUM or quic["Origin"]["Hash"] != QUIC_COMMIT:
        raise ValueError("QUIC source does not match the reviewed module and commit")
    sing = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", "github.com/sagernet/sing@" + SING_VERSION], env=env, cwd=REPO))
    if sing["Sum"] != SING_SUM or sing["Origin"]["Hash"] != SING_COMMIT:
        raise ValueError("stream source does not match the reviewed module and commit")
    patch = REPO / "third_party/sing-box/domain-cache.patch"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".loom-source-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "source"
        stage.mkdir()
        for source, module_path, version, directory in (
            (module, "github.com/sagernet/sing-box", VERSION, stage),
            (tun, "github.com/sagernet/sing-tun", TUN_VERSION, stage / ".loom-sing-tun"),
            (quic, "github.com/sagernet/sing-quic", QUIC_VERSION, stage / ".loom-sing-quic"),
            (sing, "github.com/sagernet/sing", SING_VERSION, stage / ".loom-sing"),
        ):
            prefix = module_path + "@" + version + "/"
            with zipfile.ZipFile(source["Zip"]) as archive:
                for member in archive.infolist():
                    if not member.filename.startswith(prefix):
                        raise ValueError("unexpected upstream archive path")
                    relative = Path(member.filename[len(prefix):])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("unsafe upstream archive path")
                    if member.is_dir():
                        continue
                    target = directory / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(member))
        # This disposable tree is not part of the enclosing Loom worktree.
        # Otherwise git-format hunks can be silently skipped as outside its
        # current directory, while traditional unified hunks still apply.
        patch_env = {key: value for key, value in os.environ.items()
                     if key not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}}
        patch_env["GIT_CEILING_DIRECTORIES"] = str(stage.parent)
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=stage, env=patch_env, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=stage, env=patch_env, check=True)
        subprocess.run(["git", "apply", "--reverse", "--check", str(patch)], cwd=stage, env=patch_env, check=True)
        (stage / MARKER).write_text(COMMIT)
        if destination.exists():
            shutil.rmtree(destination)
        stage.rename(destination)
    return {"upstream_version": VERSION, "upstream_commit": COMMIT, "upstream_module_sum": SUM,
            "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
            "artifact_version": "1.11.4-loom.9"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare-sing-box.py BUILD_SOURCE_DIRECTORY")
    provenance = prepare(sys.argv[1])
    (Path(sys.argv[1]) / ".loom-source-provenance.json").write_text(json.dumps(provenance, sort_keys=True))
