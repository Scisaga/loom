#!/usr/bin/env python3
"""Find one Loom-specific install confirmation in an Android UI dump."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LABEL = re.compile(
    r"^(?:继续安装|安装|继续|install|continue)$",
    re.IGNORECASE,
)
POSITIVE_COUNTDOWN = re.compile(
    r"^(?:继续安装|安装|继续|install|continue)\s*[（(]\s*(\d+)\s*[）)]$",
    re.IGNORECASE,
)
SAFETY_COUNTDOWN = re.compile(
    r"^(?:拒绝|取消|cancel|deny|reject)\s*[（(]\s*(\d+)\s*[）)]$",
    re.IGNORECASE,
)
BOUNDS = re.compile(r"^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$")


class SafetyCountdown(ValueError):
    def __init__(self, seconds: int, x: int, y: int, label: str):
        super().__init__("安装安全倒计时仍在进行")
        self.seconds = seconds
        self.x = x
        self.y = y
        self.label = label


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
    positive_countdowns: set[int] = set()
    for node in nodes:
        label = (node.attrib.get("text") or node.attrib.get("content-desc") or "").strip()
        countdown_match = POSITIVE_COUNTDOWN.fullmatch(label)
        if not LABEL.fullmatch(label) and countdown_match is None:
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
        if countdown_match is not None:
            positive_countdowns.add(int(countdown_match.group(1)))
    if len(candidates) != 1:
        raise ValueError("screen does not contain one unambiguous enabled install action")
    candidate = candidates.pop()
    countdowns = positive_countdowns | {
        int(match.group(1))
        for node in nodes
        for key in ("text", "content-desc")
        if (value := node.attrib.get(key, "").strip())
        if (match := SAFETY_COUNTDOWN.fullmatch(value))
    }
    if countdowns:
        # HyperOS 会把视觉上仍禁用的确认按钮报告为 enabled；按钮文案中的倒计时才是门禁真值。
        if len(countdowns) != 1:
            raise ValueError("安装安全倒计时互相矛盾")
        x, y, label = candidate
        raise SafetyCountdown(countdowns.pop(), x, y, label)
    return candidate


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} UI_XML", file=sys.stderr)
        return 2
    try:
        x, y, label = find_confirmation(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except SafetyCountdown as error:
        print(f"WAIT {error.x} {error.y} {error.seconds} {error.label}")
        return 3
    except (OSError, ET.ParseError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"{x} {y} {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
