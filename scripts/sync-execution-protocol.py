#!/usr/bin/env python3
"""Refresh the read-only native projection of the one execution codec.

Run only against an owned editable native source tree, then refresh the
maintained patch. No native copy is a second editable protocol definition.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent

def sync(destination):
    destination = Path(destination).resolve()
    if ROOT / 'out' not in destination.parents or not (destination / '.git').is_dir():
        raise ValueError('requires an editable native checkout inside out')
    target = destination / 'common/loomprotocol'
    target.mkdir(parents=True, exist_ok=True)
    expected = {source.name: source.read_bytes() for source in sorted((ROOT / 'protocol').glob('*.go'))}
    for old in target.glob('*.go'):
        if old.name not in expected:
            old.unlink()
    for name, body in expected.items():
        (target / name).write_bytes(body)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: sync-execution-protocol.py EDITABLE_NATIVE_SOURCE')
    sync(sys.argv[1])
