#!/usr/bin/env python3
"""Find one Loom-specific install confirmation in an Android UI dump."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LABEL = re.compile(
    r"^(?:继续安装|安装|继续|install|continue)(?:\s*[（(]?\d+[）)]?)?$",
    re.IGNORECASE,
)
BOUNDS = re.compile(r"^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$")


def find_confirmation(xml: str) -> tuple[int, int, str]:
    root = ET.fromstring(xml)
    nodes = list(root.iter())
    parent = {child: owner for owner in nodes for child in owner}
    visible = " ".join(
        value
        for node in nodes
        for key in ("text", "content-desc")
        if (value := node.attrib.get(key, "")).strip()
    )
    if "loom" not in visible.lower() and "io.github.scisaga.loom" not in visible.lower():
        raise ValueError("screen does not identify Loom")

    candidates: set[tuple[int, int, str]] = set()
    for node in nodes:
        label = (node.attrib.get("text") or node.attrib.get("content-desc") or "").strip()
        if not LABEL.fullmatch(label):
            continue
        owner = node
        while owner is not None and owner.attrib.get("clickable") != "true":
            owner = parent.get(owner)
        if owner is None or owner.attrib.get("enabled", "true") != "true":
            continue
        match = BOUNDS.fullmatch(owner.attrib.get("bounds", ""))
        if not match:
            continue
        x1, y1, x2, y2 = map(int, match.groups())
        if x2 <= x1 or y2 <= y1:
            continue
        candidates.add(((x1 + x2) // 2, (y1 + y2) // 2, label))
    if len(candidates) != 1:
        raise ValueError("screen does not contain one unambiguous enabled install action")
    return candidates.pop()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} UI_XML", file=sys.stderr)
        return 2
    try:
        x, y, label = find_confirmation(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, ET.ParseError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"{x} {y} {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

