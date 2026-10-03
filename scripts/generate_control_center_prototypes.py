#!/usr/bin/env python3
"""Generate editable target-state Web prototypes from the current UI projection.

All examples are synthetic. The SVGs are design references, not a deployment
readback or a source of control authority. The generator never reads an output
SVG, a screenshot, a clock, a network service, or production configuration.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import re
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
OUTPUT = ASSETS / "control-center"
SVG_NS = "http://www.w3.org/2000/svg"

# Fixture identities stay synthetic. UI labels use the concise names requested
# for the drawings; provenance and fixture semantics belong in the review doc.
DISPLAY_NAMES = {
    "demo-control-a": "control-a", "demo-control-b": "control-b",
    "demo-forward-b": "relay-east", "demo-forward-c": "relay-west",
    "demo-egress-e": "internet-exit", "demo-phone-f": "android-phone",
    "demo-laptop": "workstation", "demo-access-g": "access-g", "demo-network": "Loom network",
    "demo-new-host": "new-host",
    "demo-new-phone": "new-phone", "demo-new-relay": "new-relay", "demo-relay-g": "relay-g",
    "demo-control-c": "control-c", "demo-invite-qr": "join-access-g",
    "demo-invite-ssh": "join-workstation", "demo-invite-script": "join-relay-g",
    "demo-invite-control": "join-control-c",
    "demo-video": "media", "demo-work": "work-apps", "demo-private": "private-app",
    "demo-private-access": "private-access",
    "demo-direct-policy": "direct-access", "demo-office": "office-network",
    "demo-work-access": "work-access", "demo-work-phone": "work-phone",
    "demo-work-phone-invite": "join-work-phone",
    "demo-policy": "media-access", "demo-lan-policy": "office-lan",
    "demo-printer.loom": "printer.loom", "demo-request-001": "request-001",
    "demo-link-wg": "link-wg", "demo-link-hy2": "link-hy2",
    "demo-link-a-b": "link-a-east", "demo-link-a-c": "link-a-west",
    "demo-link-a-cb": "link-a-b", "demo-link-b-cb": "link-east-b",
    "demo-link-c-cb": "link-west-b", "demo-link-e-b": "link-exit-east",
    "demo-link-e-cb": "link-exit-b", "demo-wg-forward-c": "wg-relay-west",
    "demo-linux-agent": "loom-agent", "demo-linux-cli": "loom-cli",
    "demo-linux-ui": "loom-web", "demo-android-app": "loom-android",
    "demo-android-apk": "loom.apk", "demo-android-symbols": "android-symbols",
    "demo-windows-app": "loom-windows", "demo-windows-installer": "loom-installer",
    "demo-windows-portable": "loom-portable", "demo-agent": "loom-agent",
    "demo-1.2.0": "1.2.0", "demo-42": "42",
}

# Pure drawing fixtures: a node selects policies; each policy owns one service.
SERVICE_FIXTURES = {
    "demo-video": {"kind": "internet", "target": "media.example + .cdn.media.example"},
    "demo-office": {"kind": "local_network", "target": "198.51.100.0/24 · gateway demo-forward-c"},
    "demo-private": {"kind": "internet", "target": "private.example"},
}
POLICY_FIXTURES = {
    "demo-policy": {"service": "demo-video", "summary": "Direct, or via internet-exit · entry and transit unrestricted"},
    "demo-direct-policy": {"service": "demo-video", "summary": "Direct only · no routes through Loom"},
    "demo-lan-policy": {"service": "demo-office", "summary": "Via the fixed LAN gateway · entry and transit unrestricted"},
}

# Fixed join scenarios shared by draft, delivery and device-detail drawings.
# These are drawing inputs, not an enrollment store or runtime state machine.
JOIN_SCENES = {
    "qr": {"name": "demo-new-phone", "device": "demo-access-g", "invite": "demo-invite-qr",
           "roles": ("access",), "policies": ("demo-direct-policy",)},
    "ssh": {"name": "demo-laptop", "device": "demo-laptop", "invite": "demo-invite-ssh",
            "roles": ("access", "forward"), "policies": ("demo-policy", "demo-lan-policy")},
    "script": {"name": "demo-new-relay", "device": "demo-relay-g", "invite": "demo-invite-script",
               "roles": ("forward", "internet_egress"), "policies": ()},
    "control": {"name": "demo-control-c", "device": "demo-control-c", "invite": "demo-invite-control",
                "roles": ("forward", "control"), "policies": ()},
}
ACCESS_EDIT_DEVICE = "demo-forward-c"
JOIN_FILES = {
    "qr": "02-nodes-add-qr-delivery.svg",
    "script": "02-nodes-add-script-delivery.svg",
    "ssh": "02-nodes-add-ssh-result.svg",
}

# Fixed, counter-derived chart fixtures. None is an unobserved hour, never zero.
# A link's two series count TX at each endpoint; peer RX is not added again.
TRAFFIC_ACTIVITY = (3, 2, 3, 4, None, 5, 7, 11, 10, 8, 7, 8,
                    10, 12, 15, 13, 16, None, 12, 9, 8, 7, 6, 4)
TRAFFIC_LINKS = (
    ("demo-link-wg", "demo-control-a", "demo-egress-e", 768, 512),
    ("demo-link-a-b", "demo-control-a", "demo-forward-b", 384, 128),
    ("demo-link-a-c", "demo-control-a", "demo-forward-c", 256, 192),
    ("demo-link-a-cb", "demo-control-a", "demo-control-b", 64, 32),
    ("demo-link-e-b", "demo-egress-e", "demo-forward-b", 320, 192),
    ("demo-link-e-cb", "demo-egress-e", "demo-control-b", 96, 64),
    ("demo-link-b-cb", "demo-forward-b", "demo-control-b", 128, 64),
    # demo-link-c-cb changed spec: old-scope counters cannot fill its new series.
)

# Each position is the last valid runtime sample in that hour, not uptime.
# Runtime, interface counters and business probes remain independent inputs.
RUNTIME_HISTORY = {
    "demo-control-a": ("running",) * 4 + (None,) + ("running",) * 12 + (None,) + ("running",) * 6,
    "demo-control-b": ("running",) * 18 + (None,) * 6,
    "demo-forward-b": ("running",) * 12 + ("failed",) * 2 + ("running",) * 6 + (None,) * 4,
    "demo-forward-c": ("running",) * 9 + (None,) + ("running",) * 14,
    "demo-egress-e": ("running",) * 7 + ("failed",) + ("running",) * 16,
    "demo-phone-f": (None,) * 24,
}

# Link observations have their own direction, transport and current spec scope.
# Historical failures and gaps do not infer either endpoint's runtime state.
LINK_HISTORY = {
    "demo-link-wg": ("available",) * 4 + (None,) + ("available",) * 12 + (None,) + ("available",) * 6,
    "demo-link-hy2": (None,) * 24,
    "demo-link-a-b": ("available",) * 9 + ("unavailable",) * 2 + ("available",) * 13,
    "demo-link-a-c": ("available",) * 24,
    "demo-link-a-cb": ("available",) * 18 + (None,) * 6,
    "demo-link-e-b": ("available",) * 14 + (None,) + ("available",) * 9,
    "demo-link-e-cb": ("available",) * 16 + ("unavailable",) * 2 + (None,) * 6,
    "demo-link-b-cb": (None,) * 23 + ("available",),
    "demo-link-c-cb": (None,) * 24,
}

# Synthetic current-scope, directed transport measurements. RTT values are
# retained successful minute summaries in a 15-minute window; None/absence is
# never a zero. TX entries are (bytes, observed seconds) within the last 5m.
# Unknown, expired and old-spec LinkIDs deliberately have no current metrics.
LINK_MEASUREMENTS = {
    "demo-link-wg": {
        "source": "demo-control-a", "target": "demo-egress-e", "age": "18s ago",
        "rtt_ms": (34, 35, 36, 37, 38, 39, 38, 36, 37, 46, 42, 35, 38, 37),
        "tx_deltas": ((240_000_000, 150), (240_000_000, 150)),
    },
    "demo-link-a-b": {
        "source": "demo-control-a", "target": "demo-forward-b", "age": "24s ago",
        "rtt_ms": (18, 19, 20, 22, 21, 24, 20, 20, 18, 19, 22, 21, 20, 22, 21),
        "tx_deltas": ((157_500_000, 150), (157_500_000, 150)),
    },
    "demo-link-a-c": {
        "source": "demo-control-a", "target": "demo-forward-c", "age": "31s ago",
        "rtt_ms": (20, 21, 22, 22, 24, 22, 23, 26, 21, 22, 23, 25, 22),
        "tx_deltas": ((0, 150), (0, 150)),
    },
    "demo-link-e-b": {
        "source": "demo-egress-e", "target": "demo-forward-b", "age": "42s ago",
        "rtt_ms": (28, 29, 30, 31, 32, 38, 35, 30, 29, 33, 31, 32),
        "tx_deltas": ((180_000_000, 150), (180_000_000, 150)),
    },
    "demo-link-b-cb": {
        "source": "demo-control-b", "target": "demo-forward-b", "age": "12s ago",
        "rtt_ms": (15,), "tx_deltas": (),
    },
}

# One device / Service / candidate scope. Successful HTTPS request duration is
# independent of transport RTT, interface counters and device runtime reports.
PATH_CONTEXT = {
    "device": "demo-phone-f", "service": "demo-video", "policy": "demo-policy",
    "candidate": "demo-media-relay-wg", "mode": "Auto", "selection_age": "8s ago",
    "target": "media.example", "probe": "media.example/health", "business_age": "8s ago",
    "first_hop_ms": 12, "first_hop_age": "11s ago",
}
PATH_BUSINESS_SAMPLES = (
    ("available", 164), ("available", 152), ("available", 142), ("unknown", None),
    ("available", 141), ("available", 138), ("available", 134), ("unavailable", None),
    ("unavailable", None), ("available", 173), ("available", 149), ("available", 144),
    ("available", 137), ("available", 132), ("available", 129), ("available", 131),
    ("unknown", None), ("available", 140), ("available", 136), ("available", 128),
    ("available", 130), ("available", 124), ("available", 128), ("available", 126),
)

# A later, synthetic multi-device snapshot for the Live paths summary only.
# These inputs describe assignments and reported selections, not every candidate.
PATH_GROUPS = {
    "wg": {"label": "control-a → internet-exit", "caption": "WG relay · shared entry and link-wg",
           "key": ("demo-wg-entry-a", "WG", ("demo-control-a", "demo-egress-e"),
                   (("demo-link-wg", "demo-current-link-spec"),), "demo-egress-e")},
    "direct": {"label": "Direct", "caption": "No managed nodes", "key": ("direct",)},
    "unconfirmed": {"label": "No confirmed route", "caption": "Missing or unmatched device selection", "key": None},
}
PATH_SUMMARY_SERVICES = (
    ("media", "demo-video", "Internet · media.example + .cdn.media.example"),
    ("office", "demo-office", "LAN · fixed gateway relay-west"),
    ("private", "demo-private", "Internet · private.example"),
    ("work", "demo-work", "Suspended · conflicting service changes"),
)
PATH_ASSIGNMENTS = (
    {"scene": "current", "device": "demo-phone-f", "name": "demo-phone-f", "service": "demo-video", "policy": "demo-policy",
     "group": "wg", "selection": "fresh", "target": "available", "reason": "HTTPS 200 · media.example/health", "age": "8s ago"},
    {"scene": "failed", "device": "demo-laptop", "name": "demo-laptop", "service": "demo-video", "policy": "demo-policy",
     "group": "wg", "selection": "fresh", "target": "unavailable", "reason": "HTTPS 503 · media.example/health", "age": "10s ago"},
    {"scene": "direct", "device": "demo-access-g", "name": "demo-new-phone", "service": "demo-video", "policy": "demo-direct-policy",
     "group": "direct", "selection": "fresh", "target": "unknown", "reason": "No target result · media.example/health", "age": "Selection · 15s ago"},
    {"scene": "pending", "device": "demo-forward-c", "name": "demo-forward-c", "service": "demo-video", "policy": "demo-direct-policy",
     "group": "unconfirmed", "selection": "pending", "target": "unknown", "reason": "Policy changed · waiting for this device", "age": "No matching report"},
    {"scene": "lan", "device": "demo-laptop", "name": "demo-laptop", "service": "demo-office", "policy": "demo-lan-policy",
     "group": "unconfirmed", "selection": "missing", "target": "unknown", "reason": "No selection or target result · 198.51.100.42", "age": "No report received"},
)


def path_members(service: str, group: str = "all") -> tuple[dict, ...]:
    """Filter drawing records; no synthesized device × service combinations."""
    members = [r for r in PATH_ASSIGNMENTS if r["service"] == service]
    if group == "failed":
        members = [r for r in members if r["target"] == "unavailable"]
    elif group == "unknown":
        members = [r for r in members if r["target"] == "unknown"]
    elif group in PATH_GROUPS:
        route_key = PATH_GROUPS[group]["key"]
        members = [r for r in members if (PATH_GROUPS[r["group"]]["key"] if r["selection"] == "fresh" else None) == route_key]
    return tuple(sorted(members, key=lambda r: (r["name"], r["device"])))


def observed_rate_mbps(deltas: tuple[tuple[int, int], ...]) -> float | None:
    if not deltas:
        return None
    if any(value < 0 or not 0 < seconds <= 180 for value, seconds in deltas):
        raise ValueError("rate requires valid adjacent counter deltas")
    duration = sum(seconds for _, seconds in deltas)
    if duration > 300:
        raise ValueError("rate coverage exceeds the five-minute window")
    return sum(value for value, _ in deltas) * 8 / duration / 1_000_000


def rtt_percentiles(values: tuple[int, ...]) -> tuple[int, int] | None:
    if len(values) < 2:
        return None
    ordered = sorted(values)
    return tuple(ordered[math.ceil(len(ordered) * percentile / 100) - 1] for percentile in (50, 95))


def link_stats(link_id: str) -> dict | None:
    measured = LINK_MEASUREMENTS.get(link_id)
    if measured is None:
        return None
    percentiles = rtt_percentiles(measured["rtt_ms"])
    return {
        **measured,
        "latency": measured["rtt_ms"][-1],
        "rate": observed_rate_mbps(measured["tx_deltas"]),
        "coverage": sum(seconds for _, seconds in measured["tx_deltas"]),
        "samples": len(measured["rtt_ms"]),
        "p50": percentiles[0] if percentiles is not None else None,
        "p95": percentiles[1] if percentiles is not None else None,
        "variation": percentiles[1] - percentiles[0] if percentiles is not None else None,
    }


def rate_label(rate: float | None) -> str:
    return "unknown" if rate is None else f"{rate:.1f} Mbps"


def variation_label(variation: int | None) -> str:
    return "unknown" if variation is None else f"Δ {variation} ms"


def traffic_series(*, link_id: str = "", device: str = "", direction: str = "tx") -> tuple[int | None, ...]:
    weight = 0
    for identity, left, right, left_tx, right_tx in TRAFFIC_LINKS:
        if link_id and identity != link_id:
            continue
        if not device:
            weight += left_tx + right_tx
        elif device == left:
            weight += left_tx if direction == "tx" else right_tx
        elif device == right:
            weight += right_tx if direction == "tx" else left_tx
    return tuple(None if value is None or not weight else value * weight * 1024**2 for value in TRAFFIC_ACTIVITY)


def traffic_total(values: tuple[int | None, ...]) -> int | None:
    observed = [value for value in values if value is not None]
    return sum(observed) if observed else None


def byte_size(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value / 1024**3:,.1f} GiB"


def display_text(value: str) -> str:
    for identity in sorted(DISPLAY_NAMES, key=lambda item: (-len(item), item)):
        value = value.replace(identity, DISPLAY_NAMES[identity])
        value = value.replace(identity.upper(), DISPLAY_NAMES[identity].upper())
    return value


def logo_geometry() -> tuple[str, str]:
    source = ASSETS / "loom-logo-v4.svg"
    root = ET.parse(source).getroot()
    group = root.find(f".//{{{SVG_NS}}}g")
    if group is None:
        raise ValueError("approved logo group missing")
    paths = group.findall(f"{{{SVG_NS}}}path")
    if len(paths) < 2:
        raise ValueError("approved logo paths missing")
    return (" ".join(path.attrib["d"].strip() for path in paths), group.attrib["transform"])


STYLE = """
    .ui { font-family: Inter, "Atkinson Hyperlegible Next", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; fill:#1B201D }
    .mono { font-family: "Intel One Mono", "SFMono-Regular", Consolas, monospace }
    .title { font-size:28px; font-weight:700; letter-spacing:-.5px }
    .section { font-size:17px; font-weight:650; letter-spacing:-.2px }
    .metric { font-size:22px; font-weight:650; letter-spacing:-.3px }
    .body { font-size:14px }
    .small { font-size:12px }
    .tiny { font-size:11px }
    .micro { font-size:10px }
    .eyebrow { font-size:11px; font-weight:700; letter-spacing:1px }
    .muted { fill:#6E7771 }
    .faint { fill:#929B95 }
    .green { fill:#218A61 }
    .amber { fill:#A66A14 }
    .red { fill:#B74E4E }
    .blue { fill:#427994 }
    .white { fill:#FFFFFF }
    .nav { font-size:13px }
    .nav-icon { fill:none; stroke:#79837D; stroke-width:1.45; stroke-linecap:round; stroke-linejoin:round }
    .nav-active { fill:none; stroke:#1B201D; stroke-width:1.6; stroke-linecap:round; stroke-linejoin:round }
    .rule { stroke:#E5EAE6; stroke-width:1 }
    .dash { stroke:#ABB7AF; stroke-width:1.5; stroke-dasharray:5 5; fill:none }
    .link { stroke:#B8C4BC; stroke-width:2; fill:none }
    .selected { stroke:#4D78D1; stroke-width:2.3; fill:none; marker-end:url(#route-arrow) }
"""


NAV = (
    ("Overview", "overview", 230, "icon-grid"),
    ("Nodes", "nodes", 344, "icon-node"),
    ("Topology", "topology", 438, "icon-topology"),
    ("Live paths", "live-paths", 552, "icon-path"),
    ("Services", "services", 681, "icon-service"),
    ("Policies", "policies", 789, "icon-service"),
    ("Releases", "releases", 894, "icon-release"),
    ("Events", "events", 1002, "icon-events"),
    ("Administration", "administration", 1095, "icon-signed"),
)

PAGE_STATUS = {
    "overview": "Two verified members · latest local fact still propagating",
    "nodes": "Six stable device identities · three current runtime reports",
    "topology": "Nine explicit relay LinkIDs · five fresh results · four unknown",
    "services": "Four known Services · device assignments select policies independently",
    "deployments": "Signed catalog verified · one of five targets has a matching readback",
    "events": "Verified local history · current state is read independently",
    "releases-linux": "Linux catalog entries verified · demo-forward-c has a matching applied readback",
    "releases-android": "Android catalog entries verified · application depends on device report",
    "releases-windows": "Windows catalog entries verified · no enrolled Windows target",
    "operations": "Device authorization saved locally · application remains unknown",
}


class Canvas:
    def __init__(self, name: str, title: str, subtitle: str, section: str, active: str, *, height: int = 992, content_x: int = 24, show_status: bool = True):
        self.name = name
        self.role = "img"
        self.height = height
        self.parts: list[str] = []
        self.add(f'<rect width="1586" height="{height}" fill="#FCFDFC"/>')
        self.header(active)
        self.txt(content_x, 97, section.upper(), "eyebrow green")
        self.txt(content_x, 134, title, "title")
        self.txt(content_x, 162, subtitle, "body muted")
        if show_status and name in PAGE_STATUS:
            attention = name == "services"
            self.circle(30, 180, 6, "#FFFFFF", "#C4994D" if attention else "#2AA875")
            self.txt(30, 184, "!" if attention else "✓", "tiny amber" if attention else "tiny green", "middle")
            self.txt(47, 184, PAGE_STATUS[name], "small")

    def add(self, svg: str) -> None:
        self.parts.append(svg)

    def fit_height(self, bottom: int) -> None:
        self.height = ((bottom + 7) // 8) * 8
        self.parts[0] = f'<rect width="1586" height="{self.height}" fill="#FCFDFC"/>'

    def rect(self, x: int, y: int, w: int, h: int, fill: str = "#FFFFFF", stroke: str = "#E2E8E3", radius: int = 8, *, panel: bool = False) -> None:
        marker = ' data-ui="panel"' if panel else ''
        self.add(f'<rect{marker} x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>')

    def line(self, x1: int, y1: int, x2: int, y2: int, cls: str = "rule", *, kind: str = "") -> None:
        marker = f' data-ui="{kind}"' if kind else ''
        self.add(f'<line{marker} class="{cls}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')

    def txt(self, x: int, y: int, value: str, cls: str = "body", anchor: str = "start") -> None:
        self.add(f'<text class="ui {cls}" x="{x}" y="{y}" text-anchor="{anchor}">{escape(display_text(str(value)))}</text>')

    def circle(self, x: int, y: int, radius: int, fill: str, stroke: str = "none") -> None:
        self.add(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{fill}" stroke="{stroke}"/>')

    def icon(self, name: str, x: int, y: int, size: int = 16, cls: str = "nav-icon") -> None:
        self.add(f'<use href="#{name}" x="{x}" y="{y}" width="{size}" height="{size}" class="{cls}"/>')

    def pill(self, x: int, y: int, w: int, label: str, tone: str = "neutral", h: int = 28) -> None:
        colors = {
            "green": ("#ECF7F0", "#C8E5D1", "green"),
            "amber": ("#FFF8EA", "#EFDDBA", "amber"),
            "red": ("#FDF1F0", "#EBCACA", "red"),
            "blue": ("#EEF5F8", "#D4E2EA", "blue"),
            "neutral": ("#F4F6F4", "#DEE4DF", "muted"),
        }
        fill, stroke, text_class = colors[tone]
        self.add('<g data-ui="pill">')
        self.rect(x, y, w, h, fill, stroke, 14)
        self.txt(x + w // 2, y + h // 2 + 4, label, f"small {text_class}", "middle")
        self.add('</g>')

    def button(self, x: int, y: int, w: int, label: str, primary: bool = False, *, height: int = 34) -> None:
        self.add('<g data-ui="button">')
        self.rect(x, y, w, height, "#248F64" if primary else "#FFFFFF", "#248F64" if primary else "#DDE4DE", 6)
        self.txt(x + w // 2, y + height // 2 + 4, label, "small white" if primary else "small", "middle")
        self.add('</g>')

    def card(self, x: int, y: int, w: int, h: int, title: str, note: str = "") -> None:
        self.add(f'<rect data-ui="panel" x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#FFFFFF" stroke="#E2E8E3"/>')
        self.txt(x + 20, y + 32, title, "section")
        if note:
            self.txt(x + w - 18, y + 31, note, "small muted", "end")
        self.line(x, y + 48, x + w, y + 48, kind="panel-header")

    def rows(self, x: int, y: int, widths: tuple[int, ...], headings: tuple[str, ...], rows: list[tuple[str, ...]], row_h: int = 55, color_last: bool = False, *, edges: tuple[int, int] | None = None) -> None:
        xpos = [x]
        for width in widths[:-1]:
            xpos.append(xpos[-1] + width)
        for xx, heading in zip(xpos, headings):
            self.txt(xx, y, heading.upper(), "eyebrow muted")
        left, right = edges or (x, x + sum(widths))
        self.line(left, y + 14, right, y + 14, kind="table-rule")
        for i, row in enumerate(rows):
            top = y + 14 + i * row_h
            yy = top + row_h / 2 + 5
            for j, value in enumerate(row):
                cls = "body mono" if j == 0 else ("body amber" if color_last and j == len(row) - 1 and "unknown" in value.lower() else "body")
                self.txt(xpos[j], yy, value, cls)
            self.line(left, top + row_h, right, top + row_h, kind="table-rule")

    def field(self, x: int, y: int, label: str, value: str, w: int = 400, tone: str = "") -> None:
        self.txt(x, y, label.upper(), "eyebrow muted")
        self.add('<g data-ui="input">')
        self.rect(x, y + 10, w, 43, "#FBFCFB", "#E0E7E1", 5)
        self.txt(x + 13, y + 38, value, f"body {tone}".strip())
        self.add('</g>')

    def note(self, x: int, y: int, w: int, lines: tuple[str, ...], tone: str = "blue") -> None:
        colors = {"blue": ("#F2F7F9", "#CFE0E7"), "amber": ("#FFF8EB", "#EBD8B3"), "green": ("#EEF8F2", "#CBE6D3")}
        fill, stroke = colors[tone]
        self.rect(x, y, w, 24 + 19 * len(lines), fill, stroke, 6)
        for i, line in enumerate(lines):
            self.txt(x + 14, y + 23 + i * 19, line, "small")

    def step(self, x: int, y: int, number: int, title: str, detail: str, tone: str = "green") -> None:
        fill = {"green": "#2AA875", "amber": "#D79B3B", "neutral": "#A4AEA7"}[tone]
        self.circle(x + 13, y + 13, 13, fill)
        self.txt(x + 13, y + 18, str(number), "small white", "middle")
        self.txt(x + 37, y + 11, title, "body")
        self.txt(x + 37, y + 31, detail, "small muted")

    def header(self, active: str) -> None:
        compound, transform = logo_geometry()
        self.add('<rect x="0" y="0" width="1586" height="58" fill="#FFFFFF"/>')
        self.line(0, 57, 1586, 57)
        self.add(f'<svg x="18" y="8" width="39" height="39" viewBox="127 112 1000 1000"><g transform="{transform}"><path d="{compound}" fill="#252927" fill-rule="evenodd" clip-rule="evenodd"/></g></svg>')
        self.txt(65, 36, "LOOM", "section")
        for label, key, x, icon in NAV:
            selected = active == key or (active.startswith("releases-") and key == "releases") or (active == "deployments" and key == "releases")
            if key == "administration":
                self.add('<a href="09-administration.svg" data-ui="administration-entry">')
            self.add(f'<use href="#{icon}" x="{x}" y="20" width="15" height="15" class="{"nav-active" if selected else "nav-icon"}"/>')
            self.txt(x + 21, 34, label, "nav" + ("" if selected else " muted"))
            if selected:
                self.add(f'<line x1="{x}" y1="57" x2="{x + 18 + len(label) * 7}" y2="57" stroke="#2AA875" stroke-width="2"/>')
            if key == "administration":
                self.add('</a>')
        self.icon("icon-node", 1285, 22, 14)
        self.txt(1307, 34, "demo-control-a", "small muted")
        self.add('<use href="#icon-lock" x="1450" y="20" width="14" height="14" class="nav-icon"/>')
        self.txt(1470, 34, "Admin view", "small muted")

    def render(self) -> str:
        description = f"Loom control center: {self.name}."
        body = "\n  ".join(self.parts)
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="{SVG_NS}" xmlns:xlink="http://www.w3.org/1999/xlink" width="1586" height="{self.height}" viewBox="0 0 1586 {self.height}" role="{self.role}" aria-labelledby="svg-title svg-desc">
  <title id="svg-title">{escape(self.name)} — Loom control center</title>
  <desc id="svg-desc">{escape(description)}</desc>
  <defs>
    <marker id="route-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth"><path d="M0 0L8 4L0 8Z" fill="#4D78D1"/></marker>
    <symbol id="icon-grid" viewBox="0 0 16 16"><rect x="1.5" y="1.5" width="5" height="5" rx="1"/><rect x="9.5" y="1.5" width="5" height="5" rx="1"/><rect x="1.5" y="9.5" width="5" height="5" rx="1"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/></symbol>
    <symbol id="icon-node" viewBox="0 0 16 16"><rect x="2" y="2" width="12" height="5" rx="1"/><rect x="2" y="9" width="12" height="5" rx="1"/><circle cx="4" cy="4.5" r=".6"/><circle cx="4" cy="11.5" r=".6"/></symbol>
    <symbol id="icon-topology" viewBox="0 0 16 16"><path d="M4 4l4 4 4-4M8 8v4"/><circle cx="3" cy="3" r="1.7"/><circle cx="13" cy="3" r="1.7"/><circle cx="8" cy="13" r="1.7"/></symbol>
    <symbol id="icon-path" viewBox="0 0 16 16"><path d="M2 4h4c3 0 2 8 5 8h3M2 12h3c3 0 2-8 5-8h4"/></symbol>
    <symbol id="icon-service" viewBox="0 0 16 16"><rect x="2" y="2" width="12" height="12" rx="2"/><path d="M5 5h6M5 8h6M5 11h4"/></symbol>
    <symbol id="icon-release" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="10" rx="2"/><path d="M8 5v5m-2-2 2 2 2-2"/></symbol>
    <symbol id="icon-events" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M8 4v4l2.5 1.5"/></symbol>
    <symbol id="icon-signed" viewBox="0 0 16 16"><path d="M8 1.5 13 4v4c0 3-2 5-5 6.5C5 13 3 11 3 8V4Z"/><path d="m5.5 8 1.6 1.6 3.4-3.5"/></symbol>
    <symbol id="icon-lock" viewBox="0 0 16 16"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.2 7V5a2.8 2.8 0 0 1 5.6 0v2"/></symbol>
    <symbol id="icon-search" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/></symbol>
    <symbol id="icon-terminal" viewBox="0 0 16 16"><rect x="1.5" y="2" width="13" height="12" rx="2"/><path d="m4 5 3 3-3 3m5 0h3"/></symbol>
    <symbol id="icon-code" viewBox="0 0 16 16"><path d="m5.5 3-4 5 4 5m5-10 4 5-4 5M9.5 2l-3 12"/></symbol>
    <symbol id="icon-qr" viewBox="0 0 16 16"><path d="M2 2h4v4H2zm8 0h4v4h-4zM2 10h4v4H2zm8 0v2m3-2v4m-3 0h2"/></symbol>
    <symbol id="icon-phone" viewBox="0 0 16 16"><rect x="4" y="1" width="8" height="14" rx="2"/><path d="M7 3h2M7 13h2"/></symbol>
    <symbol id="icon-globe" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><ellipse cx="8" cy="8" rx="2.5" ry="6"/><path d="M2 8h12"/></symbol>
    <symbol id="icon-expand" viewBox="0 0 16 16"><path d="M6 2H2v4m8-4h4v4M2 10v4h4m8-4v4h-4"/></symbol>
    <symbol id="icon-chevron" viewBox="0 0 16 16"><path d="m4 6 4 4 4-4"/></symbol>
    <symbol id="icon-filter" viewBox="0 0 16 16"><path d="M2 4h12M4 8h8m-6 4h4"/></symbol>
    <style><![CDATA[{STYLE}]]></style>
  </defs>
  {body}
</svg>
'''


def status_strip(c: Canvas, metrics: list[tuple[str, str, str]]) -> None:
    c.rect(24, 196, 1538, 83, panel=True)
    width = 1538 / len(metrics)
    for i, (label, value, caption) in enumerate(metrics):
        x = 44 + i * width
        c.txt(x, 219, label.upper(), "eyebrow muted")
        c.txt(x, 244, value, "metric")
        c.txt(x, 264, caption, "small muted")
        if i:
            c.line(24 + i * width, 196, 24 + i * width, 279, kind="panel-column")


def tabs(c: Canvas, items: tuple[str, ...], selected: str, y: int = 305) -> None:
    x = 25
    for item in items:
        c.txt(x, y, item, "body" if item == selected else "body muted")
        if item == selected:
            c.add(f'<line x1="{x}" y1="{y+12}" x2="{x+len(item)*8}" y2="{y+12}" stroke="#2AA875" stroke-width="2"/>')
        x += max(110, len(item) * 9 + 30)
    c.line(24, y + 13, 1562, y + 13)


def network_graph(c: Canvas, x: int, y: int, w: int, h: int, *, large: bool = False, selected_metrics: str = "") -> None:
    """Two concentric rings, using the established six-node composition."""
    cx, cy = x + w / 2, y + h * (.42 if large else .44)
    rx, ry = w * .30, h * (.44 if large else .38)
    inner_rx, inner_ry = rx * .58, ry * .59
    positions = {
        "demo-control-a": (cx, cy - inner_ry),
        "demo-forward-c": (cx - inner_rx * .866, cy + inner_ry * .5),
        "demo-forward-b": (cx + inner_rx * .866, cy + inner_ry * .5),
        "demo-phone-f": (cx - rx * .866, cy - ry * .5),
        "demo-egress-e": (cx + rx * .866, cy - ry * .5),
        "demo-control-b": (cx, cy + ry),
    }
    c.add(f'<ellipse data-ui="topology-ring" cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" fill="none" stroke="#E5ECE7"/>')
    c.add(f'<ellipse data-ui="topology-ring" cx="{cx}" cy="{cy}" rx="{inner_rx}" ry="{inner_ry}" fill="none" stroke="#E5ECE7" stroke-dasharray="3 5"/>')
    edges = (
        ("demo-control-a", "demo-egress-e"),
        ("demo-control-a", "demo-forward-b"),
        ("demo-control-a", "demo-forward-c"),
        ("demo-control-a", "demo-control-b"),
        ("demo-egress-e", "demo-forward-b"),
        ("demo-egress-e", "demo-control-b"),
        ("demo-forward-c", "demo-control-b"),
        ("demo-forward-b", "demo-control-b"),
    )
    for source, target in edges:
        ax, ay = positions[source]; bx, by = positions[target]
        c.add(f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" stroke="#B3C0B8" stroke-width="1.3"/>')
    ax, ay = positions["demo-control-a"]
    ex, ey = positions["demo-egress-e"]
    px, py = positions["demo-phone-f"]
    mid = (ax + ex) / 2
    control_y = ay + (95 if large else 65)
    c.add(f'<path d="M{ax+5} {ay+5} Q{mid} {control_y} {ex-5} {ey+5}" fill="none" stroke="#C39952" stroke-width="1.5" stroke-dasharray="5 4"/>')
    c.add(f'<path d="M{px+8} {py-4} Q{(px+ax)/2} {ay-25} {ax-10} {ay-3}" class="selected" stroke-dasharray="5 4"/>')
    c.add(f'<path d="M{ax+10} {ay-2} L{ex-10} {ey-3}" class="selected"/>')
    c.txt((px+ax)/2, ay-21, "Shared first hop", "tiny blue", "middle")
    if selected_metrics:
        c.add('<g data-ui="link-metric-label">')
        c.txt(mid, (ay+ey)/2 - 25, "media · selected", "tiny blue", "middle")
        c.txt(mid, (ay+ey)/2 - 9, selected_metrics, "tiny blue", "middle")
        c.add('</g>')
    else:
        c.txt(mid, (ay+ey)/2 - 19, "media · selected", "tiny blue", "middle")
    # The parallel transport label sits on its own curve, clear of node names.
    label_y = (ay + ey + 10 + 2 * control_y) / 4
    c.rect(mid - 57, label_y - 12, 114, 24, "#FFFBF4", "#EBDCBC", 5)
    c.txt(mid, label_y + 4, "hy2 · unknown", "tiny amber", "middle")
    labels = (
        ("demo-control-a", "control · forward", "top", True),
        ("demo-phone-f", "access", "left", False),
        ("demo-egress-e", "forward · internet egress", "right", True),
        ("demo-forward-c", "forward · LAN gateway", "left", True),
        ("demo-forward-b", "forward", "right", False),
        ("demo-control-b", "control · forward", "bottom", False),
    )
    for name, role, side, current in labels:
        nx, ny = positions[name]
        c.circle(nx, ny, 7, "#FFFFFF")
        c.circle(nx, ny, 4.5, "#28A472" if current else "#B3BEB6")
        if side == "top":
            tx, name_y, role_y, anchor = nx, ny - 22, ny - 40, "middle"
        elif side == "bottom":
            tx, name_y, role_y, anchor = nx, ny + 24, ny + 42, "middle"
        else:
            tx = nx + (18 if side == "right" else -18)
            name_y, role_y = ny - 2, ny + 18
            anchor = "start" if side == "right" else "end"
        c.txt(tx, name_y, name, "body mono" if large else "small mono", anchor)
        c.txt(tx, role_y, role, "tiny muted", anchor)


def timeline(c: Canvas, x: int, y: int, w: int, labels: tuple[str, ...], complete: int, *, pending: bool = True) -> None:
    spacing = w // (len(labels) - 1)
    c.line(x, y, x + w, y, "rule")
    for i, label in enumerate(labels):
        px = x + i * spacing
        c.circle(px, y, 5, "#2AA875" if i < complete else "#D7A049" if pending and i == complete else "#C5CDC7")
        c.txt(px, y + 25, label, "small muted", "middle")


def search_control(c: Canvas, x: int, y: int, w: int, placeholder: str, *, height: int = 38) -> None:
    c.rect(x, y, w, height, "#F8FAF8", "#E1E7E2", 5)
    c.add(f'<use href="#icon-search" x="{x+11}" y="{y+(height-16)//2}" width="15" height="15" class="nav-icon"/>')
    c.txt(x + 35, y + height // 2 + 5, placeholder, "small muted")


def traffic_chart(c: Canvas, x: int, y: int, w: int, h: int,
                  series: tuple[tuple[tuple[int | None, ...], str], ...]) -> None:
    """Hourly counter increments, with explicit gaps and a shared numeric axis."""
    maximum = max((value for values, _ in series for value in values if value is not None), default=0)
    limit = max(1024**3, math.ceil(maximum / 1024**3) * 1024**3)
    c.add('<g data-ui="traffic-chart">')
    for fraction in (0, .5, 1):
        yy = y + h * (1 - fraction)
        c.add(f'<line x1="{x}" y1="{yy}" x2="{x+w}" y2="{yy}" stroke="#E9EEE9"/>')
    c.txt(x - 8, y + 4, f"{limit / 1024**3:g}", "micro muted", "end")
    c.txt(x - 8, y + h + 3, "0", "micro muted", "end")
    c.txt(x, y - 12, "GiB / hour", "micro muted")
    pitch = w / 24
    group_width = pitch * .72
    bar_width = group_width / len(series)
    for index in range(24):
        xx = x + pitch * index + (pitch - group_width) / 2
        if all(values[index] is None for values, _ in series):
            c.add(f'<rect data-ui="traffic-gap" x="{xx:.2f}" y="{y+4}" width="{group_width:.2f}" height="{h-4}" rx="1" fill="#FAFBFA" stroke="#BFC9C2" stroke-dasharray="2 3"><title>No valid counter deltas · unknown</title></rect>')
            continue
        for offset, (values, color) in enumerate(series):
            value = values[index]
            if value is None:
                continue
            bar_h = h * value / limit
            c.add(f'<rect x="{xx + offset * bar_width:.2f}" y="{y+h-bar_h:.2f}" width="{bar_width-.5:.2f}" height="{bar_h:.2f}" rx="1" fill="{color}"><title>{index:02d}:00 · {byte_size(value)}</title></rect>')
    for xx, label, anchor in ((x, "24h ago", "start"), (x + w / 2, "12h", "middle"), (x + w, "now", "end")):
        c.txt(xx, y + h + 19, label, "micro muted", anchor)
    c.add('</g>')


def runtime_spark(c: Canvas, x: int, y: int, w: int, h: int, device: str) -> None:
    c.add('<g data-ui="runtime-history">')
    for index, state in enumerate(RUNTIME_HISTORY[device]):
        color = {"running": "#64B88E", "failed": "#C87171", None: "#FAFBFA"}[state]
        label = state or "unknown · no valid runtime sample"
        c.add(f'<rect data-ui="runtime-hour" x="{x + index * w / 24:.2f}" y="{y}" width="{w / 24 - 2:.2f}" height="{h}" rx="1.5" fill="{color}" stroke="{color if state else "#BFC9C2"}"><title>{24-index}h–{23-index}h ago · last valid runtime sample: {escape(label)}</title></rect>')
    c.txt(x, y + h + 19, "24h ago", "micro muted")
    c.txt(x + w - 2, y + h + 19, "now", "micro muted", "end")
    c.add('</g>')


def traffic_spark(c: Canvas, x: int, y: int, w: int, h: int, device: str) -> None:
    """Per-device RX/TX trend; paired bars share a scale, gaps stay visible."""
    series = (("RX", traffic_series(device=device, direction="rx"), "#5D89C5"),
              ("TX", traffic_series(device=device), "#61BC92"))
    limit = max((value for _, values, _ in series for value in values if value is not None), default=0) or 1
    c.add('<g data-ui="traffic-sparkline">')
    c.add(f'<line x1="{x}" y1="{y+h}" x2="{x+w}" y2="{y+h}" stroke="#E5EAE6"/>')
    pitch = w / 24
    bar_width = pitch * .34
    for index in range(24):
        for offset, (direction, values, color) in enumerate(series):
            value = values[index]
            xx = x + index * pitch + offset * bar_width
            label = f"{24-index}h–{23-index}h ago · {direction} · "
            if value is None:
                c.add(f'<rect data-ui="traffic-gap" x="{xx:.2f}" y="{y+2}" width="{bar_width-.4:.2f}" height="{h-2}" rx=".7" fill="#FAFBFA" stroke="#BFC9C2" stroke-dasharray="2 3"><title>{label}unknown · no valid deltas</title></rect>')
            elif value == 0:
                c.add(f'<line data-ui="traffic-zero" x1="{xx:.2f}" y1="{y+h}" x2="{xx+bar_width-.4:.2f}" y2="{y+h}" stroke="{color}" stroke-width="1.5"><title>{label}0 bytes observed</title></line>')
            else:
                bar_h = h * value / limit
                c.add(f'<rect x="{xx:.2f}" y="{y+h-bar_h:.2f}" width="{bar_width-.4:.2f}" height="{bar_h:.2f}" rx=".7" fill="{color}"><title>{label}{value:,} bytes observed</title></rect>')
    for offset, (direction, values, color) in enumerate(series):
        xx = x + offset * (w / 2 + 5)
        c.rect(xx, y + h + 13, 6, 6, color, "none", 1)
        c.txt(xx + 12, y + h + 20, f"{direction} {byte_size(traffic_total(values))}", "tiny muted")
    c.add('</g>')


def link_status_spark(c: Canvas, x: int, y: int, w: int, h: int, link_id: str) -> None:
    c.add('<g data-ui="link-status-history">')
    for index, state in enumerate(LINK_HISTORY[link_id]):
        color = {"available": "#64B88E", "unavailable": "#C87171", None: "#FAFBFA"}[state]
        label = state or "unknown · no valid link sample"
        c.add(f'<rect data-ui="link-status-hour" data-state="{state or "unknown"}" x="{x + index * w / 24:.2f}" y="{y}" width="{w / 24 - 2:.2f}" height="{h}" rx="1.5" fill="{color}" stroke="{color if state else "#BFC9C2"}"><title>{24-index}h–{23-index}h ago · last valid link sample: {escape(label)}</title></rect>')
    c.txt(x, y + h + 19, "24h ago", "micro muted")
    c.txt(x + w - 2, y + h + 19, "now", "micro muted", "end")
    c.add('</g>')


def link_traffic_spark(c: Canvas, x: int, y: int, w: int, h: int, link_id: str) -> None:
    """Both endpoints' TX per hour, from the same input as the selected chart."""
    values = traffic_series(link_id=link_id)
    limit = max((value for value in values if value is not None), default=0) or 1
    c.add('<g data-ui="link-traffic-history">')
    c.add(f'<line x1="{x}" y1="{y+h}" x2="{x+w}" y2="{y+h}" stroke="#E5EAE6"/>')
    pitch = w / 24
    bar_width = pitch * .7
    for index, value in enumerate(values):
        xx = x + index * pitch
        label = f"{24-index}h–{23-index}h ago · endpoint TX · "
        if value is None:
            c.add(f'<rect data-ui="traffic-gap" x="{xx:.2f}" y="{y+2}" width="{bar_width:.2f}" height="{h-2}" rx="1" fill="#FAFBFA" stroke="#BFC9C2" stroke-dasharray="2 3"><title>{label}unknown · no valid deltas</title></rect>')
        elif value == 0:
            c.add(f'<line data-ui="traffic-zero" x1="{xx:.2f}" y1="{y+h}" x2="{xx+bar_width:.2f}" y2="{y+h}" stroke="#61BC92" stroke-width="1.5"><title>{label}0 bytes observed</title></line>')
        else:
            bar_h = h * value / limit
            c.add(f'<rect x="{xx:.2f}" y="{y+h-bar_h:.2f}" width="{bar_width:.2f}" height="{bar_h:.2f}" rx="1" fill="#61BC92"><title>{label}{value:,} bytes observed</title></rect>')
    total = traffic_total(values)
    c.txt(x, y + h + 20, f"TX {byte_size(total)}", "tiny muted" if total is not None else "tiny amber")
    coverage = sum(value is not None for value in values)
    c.txt(x + w, y + h + 20, f"{coverage} / 24 h with deltas", "tiny muted", "end")
    c.add('</g>')


def overview() -> Canvas:
    c = Canvas("overview", "Network overview", "Network intent, current observations and application status at a glance.", "live network", "overview", height=1140)
    status_strip(c, [("Devices", "6", "registered identities"), ("Control members", "2", "verified member chain"), ("Business probes", "1 available", "1 unknown"), ("Applied readback", "1 / 5", "matching current reports")])
    c.card(24, 297, 988, 359, "Network topology")
    c.line(647, 324, 676, 324, "link"); c.txt(684, 328, "Relay link", "tiny muted")
    c.add('<path d="M771 324h24" class="selected"/>'); c.txt(806, 328, "Selected", "tiny muted")
    c.add('<path d="M891 324h25" class="dash"/>'); c.txt(927, 328, "First hop", "tiny muted")
    network_graph(c, 44, 370, 946, 225)
    c.line(24, 620, 1012, 620, kind="panel-section")
    c.circle(50, 634, 3, "#28A472"); c.txt(61, 638, "Current runtime report", "tiny muted")
    c.circle(235, 634, 3, "#B3BEB6"); c.txt(246, 638, "Runtime unknown", "tiny muted")
    c.txt(988, 638, "Open topology →", "small green", "end")

    c.card(1028, 297, 534, 174, "WireGuard traffic", "endpoint TX deltas · 24h")
    traffic = traffic_series()
    c.txt(1050, 375, "OBSERVED TX", "eyebrow muted")
    c.txt(1050, 405, byte_size(traffic_total(traffic)), "metric")
    c.txt(1050, 433, "22 / 24 h with deltas", "small muted")
    c.txt(1050, 453, "Unobserved intervals: unknown", "tiny muted")
    traffic_chart(c, 1270, 382, 269, 50, ((traffic, "#61BC92"),))

    c.card(1028, 487, 534, 169, "Release and application")
    c.pill(1400, 501, 140, "1 / 5 applied", "amber", 24)
    c.txt(1050, 568, "demo-agent · catalog verified", "body mono")
    c.txt(1050, 592, "Desired digest  sha256:6b…", "small muted")
    timeline(c, 1082, 610, 419, ("Catalog", "Artifact", "Desired", "Readback"), 3)

    c.card(24, 672, 806, 324, "Devices", "observed interface counters · 24h")
    device_rows = []
    for device, runtime in (("demo-control-a", "running"), ("demo-control-b", "unknown"),
                            ("demo-forward-b", "unknown"), ("demo-forward-c", "running"),
                            ("demo-egress-e", "running"), ("demo-phone-f", "unknown")):
        tx = traffic_total(traffic_series(device=device))
        rx = traffic_total(traffic_series(device=device, direction="rx"))
        pair = f"{rx / 1024**3:.1f} / {tx / 1024**3:.1f} GiB" if tx is not None and rx is not None else "unknown"
        device_rows.append((device, "effective", pair, runtime))
    c.rows(46, 746, (196, 144, 259, 164), ("Device", "Authorization", "WG RX / TX", "Runtime"), device_rows, 36, True, edges=(24, 830))
    c.card(846, 672, 716, 216, "Service paths", "device · demo-phone-f")
    c.rows(868, 746, (172, 212, 162, 128), ("Service", "Selection", "Business", "Intent"), [
        ("demo-video", "via demo-egress-e", "available", "effective"),
        ("demo-work", "none · suspended", "unknown", "conflict"),
        ("demo-private", "none · no grant", "unknown", "effective"),
    ], 36, True, edges=(846, 1562))

    c.card(846, 904, 716, 92, "Known issuer frontiers", "local verified sequences")
    c.txt(868, 979, "demo-control-a · 24", "small mono")
    c.txt(1052, 979, "demo-control-b · 18", "small mono")
    c.txt(1540, 979, "Peer delivery: unknown", "small amber", "end")

    c.card(24, 1012, 1538, 104, "Recent events", "View all events →")
    for xx, text, tone in ((47, "Device access saved · demo-phone-f", "green"),
                           (555, "Member certificate verified · demo-control-b", "green"),
                           (1063, "Service suspended · demo-work conflict", "amber")):
        c.circle(xx + 4, 1088, 3, "#28A472" if tone == "green" else "#C99A46")
        c.txt(xx + 17, 1092, text, "small" if tone == "green" else "small amber")
    return c


def nodes() -> Canvas:
    c = Canvas("nodes", "Devices", "Device status, service access and traffic trends in one place.", "inventory", "nodes", height=1120)
    status_strip(c, [("Device identities", "6", "same ID across roles"), ("Control members", "2", "majority certificate"), ("Observed running", "3", "fresh runtime reports"), ("Runtime unknown", "3", "no inferred process state")])
    tabs(c, ("All devices", "Control members", "Needs attention"), "All devices")
    c.card(24, 335, 1538, 761, "Device inventory", "24h history · hourly samples")
    search_control(c, 46, 399, 356, "Search ID, policy or platform")
    c.pill(422, 404, 101, "All · 6", "green")
    c.pill(536, 404, 135, "Control · 2", "neutral")
    c.pill(684, 404, 145, "Runtime unknown · 3", "amber")
    c.button(1362, 401, 178, "+ Add device", True)
    c.line(24, 453, 1562, 453, kind="panel-section")
    headings = ((47, "DEVICE / PLATFORM"), (276, "ROLES / AUTHORIZATION"),
                (522, "SERVICE / POLICY"), (738, "RUNTIME / EVIDENCE"),
                (969, "STATUS · 24H"), (1210, "TRANSFER · 24H"))
    for xx, label in headings:
        c.txt(xx, 479, label, "eyebrow muted")
    c.line(24, 493, 1562, 493, kind="table-rule")
    inventory = (
        ("demo-control-a", "Linux · member", "control + forward", "none", "effective", "running", "runtime fresh", "resource + LinkID current"),
        ("demo-control-b", "Linux · member", "control + forward", "none", "effective", "unknown", "runtime missing", "no fresh runtime View"),
        ("demo-forward-b", "Linux · relay", "forward", "none", "effective", "unknown", "runtime stale", "link digest changed"),
        ("demo-forward-c", "Linux · gateway", "forward", "none", "effective", "running", "runtime fresh", "LAN ACL current"),
        ("demo-egress-e", "Linux · exit", "forward + internet_egress", "none", "effective", "running", "runtime fresh", "path result is scoped"),
        ("demo-phone-f", "Android · access", "access", "demo-video / demo-policy", "effective", "runtime unknown", "probe fresh", "demo-video available"),
    )
    for i, (name, platform, roles, grant, auth, runtime, age, detail) in enumerate(inventory):
        top = 493 + i * 88
        yy = top + 29
        if i == 3:
            c.rect(25, top, 1536, 88, "#F2F8F4", "none", 0)
        c.circle(53, yy - 5, 4, "#2AA875" if runtime == "running" else "#D79B3B")
        c.txt(66, yy, name, "body mono")
        c.txt(66, yy + 20, platform, "tiny muted")
        if roles == "forward + internet_egress":
            c.txt(276, yy - 4, "forward", "body")
            c.txt(276, yy + 15, "+ internet_egress", "body")
        else:
            c.txt(276, yy + 4, roles, "body")
        c.txt(276, top + 68, f"Authorization · {auth}", "tiny green")
        if grant == "none":
            c.txt(522, yy + 11, "none", "body muted")
        else:
            service, policy = grant.split(" / ")
            c.txt(522, yy, service, "body mono")
            c.txt(522, yy + 21, policy, "small mono muted")
        c.txt(738, yy - 2, runtime, "body green" if runtime == "running" else "body amber")
        c.txt(738, yy + 17, age, "tiny amber" if age not in ("runtime fresh", "probe fresh") else "tiny muted")
        c.txt(738, yy + 36, detail, "tiny muted")
        runtime_spark(c, 969, top + 27, 204, 18, name)
        traffic_spark(c, 1210, top + 16, 280, 33, name)
        c.txt(1534, yy + 16, "›", "metric muted", "middle")
        c.line(24, top + 88, 1562, top + 88, kind="table-rule")
    for xx, label, fill, stroke in ((47, "Running sample", "#64B88E", "#64B88E"),
                                     (181, "Reported failure", "#C87171", "#C87171"),
                                     (325, "Unknown", "#FAFBFA", "#BFC9C2")):
        c.rect(xx, 1040, 7, 12, fill, stroke, 1)
        c.txt(xx + 14, 1050, label, "tiny muted")
    c.txt(457, 1050, "Status: last valid sample each hour, not continuous uptime.", "tiny muted")
    c.txt(1539, 1050, "Traffic: per-device scale · totals in GiB · gaps are unknown", "tiny muted", "end")
    c.txt(47, 1077, "Ordinary grants can be accepted locally; control retirement and whole-node deletion require old-member majority.", "tiny muted")
    return c


def topology() -> Canvas:
    c = Canvas("topology", "Network topology", "Inspect connections, measured link quality and the path reported for a selected Service.", "network / topology", "topology", height=1680)
    selected = link_stats("demo-link-wg")
    c.rect(24, 201, 1080, 571, panel=True)
    c.txt(46, 234, "Connections", "section")
    c.pill(178, 215, 88, "6 devices", "neutral", 25)
    c.txt(834, 234, "View from demo-control-a", "small muted")
    c.line(24, 249, 1104, 249, kind="panel-header")
    search_control(c, 45, 265, 236, "Find a device or LinkID")
    c.rect(293, 265, 231, 38, "#FFFFFF", "#DAE3DC", 5)
    c.txt(306, 289, "Service: demo-video", "small mono")
    c.icon("icon-chevron", 498, 276)
    for xx, label, checked in ((546, "WG", True), (622, "hy2", True), (706, "Selected path", True)):
        c.rect(xx, 277, 13, 13, "#2A9066" if checked else "#FFFFFF", "#2A9066", 3)
        c.txt(xx + 6, 288, "✓", "tiny white", "middle")
        c.txt(xx + 22, 288, label, "small")
    c.rect(999, 268, 82, 32, "#FFFFFF", "#DDE5DF", 5)
    c.icon("icon-expand", 1009, 276)
    c.txt(1034, 289, "Fit", "small")
    selected_label = f'{selected["latency"]} ms · {rate_label(selected["rate"])} · {variation_label(selected["variation"])}'
    network_graph(c, 45, 316, 1039, 405, large=True, selected_metrics=selected_label)
    c.txt(46, 716, "Point to a link to preview its metrics; click to pin the selection.", "tiny muted")
    c.line(24, 732, 1104, 732, kind="panel-section")
    c.add('<path d="M48 751h24" class="selected"/>')
    c.txt(83, 755, "Observed selection", "tiny muted")
    c.add('<path d="M233 751h25" stroke="#BECBC2" stroke-width="1.5"/>')
    c.txt(266, 755, "Declared relay", "tiny muted")
    c.circle(393, 751, 3, "#2AA875"); c.txt(404, 755, "Runtime current", "tiny muted")
    c.circle(515, 751, 3, "#B3BEB6"); c.txt(526, 755, "Runtime unknown", "tiny muted")
    c.txt(1082, 755, "3 / 6 current runtime reports", "tiny muted", "end")

    c.card(1120, 201, 442, 320, "Link observations", "current spec only")
    # One segment per current result; the ring encodes 5 of 9, not volume.
    c.add('<circle cx="1181" cy="302" r="33" fill="none" stroke="#F2E8D6" stroke-width="8"/>')
    c.add('<circle cx="1181" cy="302" r="33" fill="none" stroke="#3BAA79" stroke-width="8" stroke-dasharray="115.19 207.35" transform="rotate(-90 1181 302)"/>')
    c.txt(1181, 303, "5 / 9", "section", "middle")
    c.txt(1181, 319, "current", "tiny muted", "middle")
    c.circle(1245, 280, 4, "#3BAA79"); c.txt(1258, 285, "5 available", "body green")
    c.circle(1245, 308, 4, "#D2A45B"); c.txt(1258, 313, "4 unknown", "body amber")
    c.line(1120, 348, 1562, 348, kind="panel-section")
    c.txt(1141, 378, "demo-link-wg · WG", "body mono")
    c.pill(1431, 360, 109, "available", "green", 25)
    for xx, heading, value, caption in (
        (1141, "LATENCY", f'{selected["latency"]} ms', "RTT · latest"),
        (1269, "BANDWIDTH", rate_label(selected["rate"]), f'TX · {selected["coverage"]}/300s'),
        (1410, "VARIATION", variation_label(selected["variation"]), "P95 − P50 · 15m"),
    ):
        c.txt(xx, 412, heading, "eyebrow muted")
        c.txt(xx, 440, value, "metric")
        c.txt(xx, 461, caption, "tiny muted")
    c.txt(1141, 489, f'P50 {selected["p50"]} ms · P95 {selected["p95"]} ms · {selected["samples"]} successful samples', "tiny muted")
    c.txt(1141, 509, f'{selected["source"]} → {selected["target"]} · {selected["age"]}', "tiny mono muted")

    c.card(1120, 537, 442, 235, "Link traffic", "link-wg · endpoint TX")
    left = traffic_series(link_id="demo-link-wg", device="demo-control-a")
    right = traffic_series(link_id="demo-link-wg", device="demo-egress-e")
    c.txt(1141, 617, "OBSERVED TX", "eyebrow muted")
    c.txt(1141, 648, byte_size(traffic_total(traffic_series(link_id="demo-link-wg"))), "metric")
    c.txt(1141, 674, "2 reporting endpoints", "tiny muted")
    c.txt(1141, 696, "22 / 24 h with deltas", "tiny muted")
    traffic_chart(c, 1320, 619, 219, 79, ((left, "#5D89C5"), (right, "#8CCCB0")))
    c.rect(1141, 736, 8, 8, "#5D89C5", "none", 2); c.txt(1157, 744, "demo-control-a", "tiny mono muted")
    c.rect(1291, 736, 8, 8, "#8CCCB0", "none", 2); c.txt(1307, 744, "demo-egress-e", "tiny mono muted")
    c.txt(1539, 744, "24h", "tiny muted", "end")

    c.card(24, 788, 1538, 868, "Relay link inventory", "9 explicit links · access first hop is a separate resource")
    columns = (47, 450, 903, 1192)
    headings = ("LINK", "CURRENT MEASUREMENTS", "STATUS · 24H", "TRANSFER · 24H")
    for xx, label in zip(columns, headings):
        c.txt(xx, 862, label, "eyebrow muted")
    c.line(24, 876, 1562, 876, kind="table-rule")
    link_rows = (
        ("demo-link-wg", "demo-control-a ↔ demo-egress-e", "WG", "available", "current · demo-control-a"),
        ("demo-link-hy2", "demo-control-a ↔ demo-egress-e", "hy2", "unknown", "no fresh report"),
        ("demo-link-a-b", "demo-control-a ↔ demo-forward-b", "WG", "available", "current · demo-control-a"),
        ("demo-link-a-c", "demo-control-a ↔ demo-forward-c", "WG", "available", "current · demo-control-a"),
        ("demo-link-a-cb", "demo-control-a ↔ demo-control-b", "WG", "unknown", "report missing"),
        ("demo-link-e-b", "demo-egress-e ↔ demo-forward-b", "WG", "available", "current · demo-egress-e"),
        ("demo-link-e-cb", "demo-egress-e ↔ demo-control-b", "WG", "unknown", "report expired"),
        ("demo-link-b-cb", "demo-forward-b ↔ demo-control-b", "WG", "available", "current · demo-control-b"),
        ("demo-link-c-cb", "demo-forward-c ↔ demo-control-b", "WG", "unknown", "spec changed · old report"),
    )
    for i, row in enumerate(link_rows):
        link_id, endpoints, transport, availability, evidence = row
        measured = link_stats(link_id)
        top = 876 + i * 80
        yy = top + 25
        c.add(f'<g data-ui="link-row" data-link-id="{link_id}">')
        if measured is not None:
            tooltip = (f'{measured["source"]} → {measured["target"]} · {measured["age"]}; '
                       f'latest transport RTT {measured["latency"]} ms; '
                       f'5m TX rate {rate_label(measured["rate"])} · {measured["coverage"]}/300 seconds observed; '
                       f'15m RTT: {measured["samples"]} successful samples · {variation_label(measured["variation"])}')
            if measured["variation"] is not None:
                tooltip += f' · P50 {measured["p50"]} ms / P95 {measured["p95"]} ms'
        else:
            tooltip = f'{link_id} · {evidence} · current RTT, rate and variation unknown'
        c.add(f'<title>{escape(display_text(tooltip))}</title>')
        if i == 0:
            c.rect(25, top, 1536, 80, "#EDF4FC", "none", 0)
            c.rect(25, top, 3, 80, "#537FCC", "none", 0)
        c.txt(47, yy, endpoints, "body")
        c.txt(47, yy + 20, f"{link_id} · {transport}", "small mono muted")
        c.txt(47, yy + 39, f'From {measured["source"]} · {measured["age"]}' if measured else "No current measurement", "tiny muted")
        if measured:
            rate = rate_label(measured["rate"]) if measured["rate"] is not None else "rate unknown"
            variation = variation_label(measured["variation"]) if measured["variation"] is not None else "Δ unknown"
            c.txt(450, top + 33, f'{measured["latency"]} ms · {rate} · {variation}', "body")
            caption = "RTT · 5m TX rate · 15m variation" if measured["variation"] is not None else "1 RTT sample · no rate window or variation yet"
            c.txt(450, top + 55, caption, "tiny muted")
        else:
            c.txt(450, top + 33, "unknown", "body amber")
            c.txt(450, top + 55, evidence, "tiny muted")
        c.circle(907, top + 16, 3, "#3BAA79" if availability == "available" else "#D2A45B")
        c.txt(918, top + 20, availability, "small green" if availability == "available" else "small amber")
        link_status_spark(c, 903, top + 34, 225, 16, link_id)
        link_traffic_spark(c, 1192, top + 15, 306, 34, link_id)
        c.txt(1534, top + 45, "›", "small blue" if i == 0 else "small faint", "end")
        c.line(24, top + 80, 1562, top + 80, kind="table-rule")
        c.add('</g>')
    for xx, label, fill, stroke in ((47, "Available", "#64B88E", "#64B88E"),
                                     (165, "Unavailable", "#C87171", "#C87171"),
                                     (305, "Unknown", "#FAFBFA", "#BFC9C2")):
        c.rect(xx, 1612, 7, 12, fill, stroke, 1)
        c.txt(xx + 14, 1622, label, "tiny muted")
    c.txt(450, 1622, "Status: last valid link sample each hour.", "tiny muted")
    c.txt(1192, 1622, "TX: both endpoints · per-link scale", "tiny muted")
    c.txt(47, 1642, "Rate: WG 5m TX / hy2 probe throughput. Variation: 15m P95 − P50. Hover for sample counts, coverage and measurement details.", "tiny muted")
    return c


def business_history_chart(c: Canvas, x: int, y: int, w: int, h: int, *, as_of: str = "now") -> None:
    """Hourly business outcomes and successful request durations, same scope."""
    c.add(f'<g data-ui="business-history" data-device="{PATH_CONTEXT["device"]}" data-service="{PATH_CONTEXT["service"]}" data-policy="{PATH_CONTEXT["policy"]}" data-target="{PATH_CONTEXT["probe"]}" data-candidate="{PATH_CONTEXT["candidate"]}" data-window-end="{as_of}">')
    ceiling = math.ceil(max(ms for _, ms in PATH_BUSINESS_SAMPLES if ms is not None) / 50) * 50
    c.txt(x, y - 18, "HTTPS response · ms", "tiny muted")
    c.txt(x - 12, y + 4, str(ceiling), "micro muted", "end")
    c.txt(x - 12, y + h + 4, "0", "micro muted", "end")
    c.line(x, y, x + w, y)
    c.line(x, y + h, x + w, y + h)
    pitch = w / 24
    for index, (state, ms) in enumerate(PATH_BUSINESS_SAMPLES):
        xx = x + index * pitch + 3
        color = {"available": "#64B88E", "unavailable": "#C87171", "unknown": "#FAFBFA"}[state]
        description = f"{24-index}h–{23-index}h ago · {state}"
        description += f" · HTTPS {ms} ms" if ms is not None else " · no successful response duration" if state == "unavailable" else " · no valid business sample"
        if as_of != "now":
            description += f" · relative to the last report ({as_of}), not now"
        c.add(f'<g data-ui="business-hour" data-state="{state}"><title>{escape(description)}</title>')
        if ms is not None:
            bar_h = h * ms / ceiling
            c.rect(xx + 6, y + h - bar_h, pitch - 18, bar_h, "#7B9BC8", "none", 1.5)
        elif state == "unknown":
            c.add(f'<rect data-ui="business-gap" x="{xx+6:.2f}" y="{y+2}" width="{pitch-18:.2f}" height="{h-2}" rx="1.5" fill="#FAFBFA" stroke="#BFC9C2" stroke-dasharray="2 3"/>')
        else:
            mid = xx + (pitch - 6) / 2
            c.add(f'<path data-ui="business-failure" d="M{mid-4} {y+h-8}l8 8m-8 0 8-8" stroke="#C87171" stroke-width="1.5"/>')
        c.rect(xx, y + h + 22, pitch - 6, 12, color, "#BFC9C2" if state == "unknown" else color, 2)
        c.add('</g>')
    for xx, label, anchor in ((x, "24h ago" if as_of == "now" else "24h before report", "start"), (x+w/2, "12h", "middle"), (x+w, as_of, "end")):
        c.txt(xx, y + h + 62, label, "micro muted", anchor)
    c.add('</g>')


def live_path_diagram(c: Canvas, scene: str, context: dict) -> None:
    """Draw a current selection, historical route or allowed LAN preview."""
    current, lan = scene in ("current", "failed", "direct"), scene == "lan"
    historical = scene in ("pending", "expired")
    route_kind = "current-service-route" if current else "historical-service-route" if historical else "allowed-route-preview"
    candidate = "demo-office-relay-wg" if lan else context["candidate"]
    c.add(f'<g data-ui="{route_kind}" data-candidate="{candidate}" data-policy="{PATH_CONTEXT["policy"] if historical else context["policy"]}">')
    if scene == "direct":
        c.add('<g data-ui="path-segment"><path d="M163 475H1351" class="selected"/>')
        c.txt(758, 435, "Direct · no managed nodes", "tiny blue", "middle")
        c.txt(758, 455, "No target response measurement", "small amber", "middle")
        c.add('</g>')
        for x, name, role, icon in ((134, context["name"], "access", "icon-phone"), (1382, context["target"], "HTTPS target", "icon-globe")):
            c.circle(x, 475, 23, "#F1F6F3", "#D6E1D9")
            c.icon(icon, x - 11, 464, 22)
            c.txt(x, 522, name, "body mono", "middle")
            c.txt(x, 543, role, "tiny muted", "middle")
        c.add('</g>')
        return
    relay = link_stats("demo-link-a-c" if lan else "demo-link-wg")
    relay_metric = f'{relay["latency"]} ms · {rate_label(relay["rate"])} shared · {variation_label(relay["variation"])}'
    segments = (
        (134, 540, "WG · shared entry", "Entry check unknown" if lan or scene == "failed" else f'{PATH_CONTEXT["first_hop_ms"]} ms · available',
         "No matching first-hop observation" if lan or scene == "failed" else f'{context["device"]} → demo-control-a · transport RTT · {PATH_CONTEXT["first_hop_age"]}'),
        (540, 947, "WG · demo-link-a-c" if lan else "WG · demo-link-wg", relay_metric,
         f'Shared link only · {relay["age"]} · WG 5m TX rate; RTT variation is 15m P95 − P50'),
        (947, 1382, "LAN · mapped destination" if lan else "HTTPS · destination", "Target result unknown" if lan else "Segment timing unknown",
         "No matching business observation for this LAN target" if lan else "No separate exit-to-target timing; full HTTPS request shown below"),
    )
    for left, right, label, metric, title in segments:
        c.add('<g data-ui="path-segment">')
        c.add(f'<title>{escape(display_text("Previous route only; no current measurement" if historical else title))}</title>')
        c.add(f'<path d="M{left+29} 475H{right-31}" class="{"selected" if current else "dash"}"/>')
        c.txt((left + right)/2, 435, label, "tiny muted" if historical else "tiny blue", "middle")
        c.txt((left + right)/2, 455, "Previous route" if historical else metric,
              "small muted" if historical else "small amber" if right == 1382 or (lan or scene == "failed") and left == 134 else "small blue", "middle")
        c.add('</g>')
    for x, name, role, icon, kind in (
        (134, context["name"], context["roles"], "icon-node" if context["roles"] == "access + forward" else "icon-phone", "device"),
        (540, "demo-control-a", "entry · control + forward", "icon-signed", "device"),
        (947, "demo-forward-c" if lan else "demo-egress-e", "fixed LAN gateway · forward" if lan else "final exit · internet_egress", "icon-node", "device"),
        (1382, context["target"], "LAN target · 192.0.2.42 behind gateway" if lan else "HTTPS target · one of this service's URLs", "icon-globe", "target"),
    ):
        c.add(f'<g data-ui="path-{kind}">')
        c.circle(x, 475, 23, "#F6F7F6" if historical else "#F1F6F3", "#D6E1D9")
        c.icon(icon, x - 11, 464, 22)
        c.txt(x, 522, name, "body mono muted" if historical else "body mono", "middle")
        c.txt(x, 543, role, "tiny muted", "middle")
        c.add('</g>')
    c.add('</g>')


def live_path_candidates(c: Canvas, scene: str, context: dict) -> None:
    if scene in ("denied", "unassigned"):
        c.txt(47, 754, "No authorized candidates", "section")
        c.txt(47, 788, "This policy denies access to media." if scene == "denied" else "This device has no policy for private-app.", "body muted")
        c.txt(47, 816, "No route or target probe is authorized for this device and service.", "small muted")
        return
    for x, title in ((47, "ROUTE"), (675, "TARGET RESULT"), (1138, "DEVICE SELECTION")):
        c.txt(x, 737, title, "eyebrow muted")
    c.line(24, 754, 1562, 754, kind="table-rule")
    candidates = (
        (PATH_CONTEXT["candidate"], "WG relay", "demo-phone-f → demo-control-a → demo-egress-e → media.example", f"Target succeeded · {PATH_BUSINESS_SAMPLES[-1][1]} ms", f'HTTPS 200 · {PATH_CONTEXT["business_age"]}'),
        ("demo-media-direct", "Direct · no managed nodes", "demo-phone-f → media.example", "Target succeeded · timing unknown", "Reported 25s ago"),
        ("demo-media-one-hop", "One hop · same final exit", "demo-phone-f → demo-egress-e → media.example", "Target unknown · entry unknown", "Entry report expired · details below"),
        ("demo-media-relay-hy2", "hy2 relay · same final exit", "demo-phone-f → demo-control-a → demo-egress-e → media.example", "Target unknown · hy2 unknown", "No current report for link-hy2"),
    )
    if scene in ("pending", "direct"):
        candidates = (("demo-media-direct", "Direct · no managed nodes", context["name"] + " → media.example", "Target unknown", "No report matching the new policy" if scene == "pending" else "No target result received"),)
    elif scene == "failed":
        candidates = tuple((identity, name, chain.replace("demo-phone-f", context["name"]), "Target failed · HTTPS 503" if index == 0 else "Target unknown",
                            "media.example/health · 10s ago" if index == 0 else "No matching target observation")
                           for index, (identity, name, chain, _, _) in enumerate(candidates))
    elif scene == "lan":
        candidates = (
            ("demo-office-relay-wg", "WG relay · fixed LAN gateway", "demo-laptop → demo-control-a → demo-forward-c → 198.51.100.42", "Target unknown", "Shared link available · target unmeasured"),
            ("demo-office-one-hop", "One hop · fixed LAN gateway", "demo-laptop → demo-forward-c → 198.51.100.42", "Target unknown · entry unknown", "No matching first-hop or target observation"),
        )
    top = 754
    for index, (identity, name, chain, result, age) in enumerate(candidates):
        selected = scene in ("current", "failed", "direct") and identity == context["candidate"]
        if scene == "expired":
            result, age = "Target unknown", "No fresh target result for this route"
        c.add(f'<g data-ui="path-candidate" data-candidate="{identity}" data-selected="{str(selected).lower()}">')
        if selected:
            c.rect(25, top, 1536, 80, "#EDF4FC", "none", 0)
            c.rect(25, top, 3, 80, "#537FCC", "none", 0)
        c.txt(47, top + 30, name, "body")
        c.txt(47, top + 55, chain, "small muted")
        if scene == "current" and index == 1:
            c.add(f'<text class="ui body" x="675" y="{top+30}"><tspan class="green">Target succeeded</tspan><tspan class="amber"> · timing unknown</tspan></text>')
        else:
            c.txt(675, top + 30, result, "body red" if selected and scene == "failed" else "body green" if selected and scene == "current" else "body amber")
        c.txt(675, top + 55, age, "small muted")
        c.txt(1138, top + 30, "Current" if selected else "Not selected" if scene in ("current", "failed", "direct") else "Unknown", "body blue" if selected else "body muted")
        caption = "Confirmed by device · " + context["selection_age"] if selected else "No comparable timing reported" if scene == "current" and index == 1 else "Reported by the device" if scene in ("current", "failed", "direct") else "Waiting for a fresh selection report"
        if scene == "current" and index == 3:
            flow_link(c, 1138, top + 55, "Inspect link-hy2 →", "/topology?link=demo-link-hy2&device=demo-phone-f&service=demo-video&policy=demo-policy")
        else:
            c.txt(1138, top + 55, caption, "small muted")
        c.line(24, top + 80, 1562, top + 80, kind="table-rule")
        c.add('</g>')
        top += 80
        if scene == "current" and index == 2:
            c.add('<g data-ui="path-observation-detail" data-candidate="demo-media-one-hop">')
            c.rect(25, top, 1536, 88, "#FFFCF5", "none", 0)
            c.circle(50, top + 23, 4, "#D2A45B")
            c.txt(65, top + 28, "Expired entry report", "body amber")
            c.txt(65, top + 52, "Last successful entry check: 12m ago · android-phone → internet-exit.", "small")
            c.txt(65, top + 73, "No fresh check for this device and entry. Current reachability remains unknown.", "small muted")
            flow_link(c, 1540, top + 50, "View internet-exit resources →", "/devices/demo-egress-e?section=forwarding&fromDevice=demo-phone-f&service=demo-video&policy=demo-policy", anchor="end")
            c.line(24, top + 88, 1562, top + 88, kind="table-rule")
            c.add('</g>')
            top += 88
    c.txt(47, top + 29, "Viewing candidates does not change device traffic. Only a fresh device report confirms its selection.", "small muted")


def live_path_history(c: Canvas, scene: str, context: dict) -> None:
    if scene not in ("current", "expired"):
        c.txt(47, 755, "No matching target history in this view", "section")
        reason = {
            "failed": "No hourly history for workstation on this target yet. The latest request returned HTTP 503.",
            "direct": "The device reported its Direct selection, but no target samples have arrived.",
            "pending": "The new policy has no matching device selection or target samples yet.",
            "denied": "Access is denied. Earlier results cannot establish current permission or reachability.",
            "unassigned": "This device is not authorized for this service; no target samples are shown.",
            "lan": "No observations for 198.51.100.42. Shared link measurements do not measure this LAN target.",
        }[scene]
        c.txt(47, 790, reason, "body muted")
        c.txt(47, 820, "History follows the device, service, target and route being inspected.", "small muted")
        return
    c.txt(47, 749, "Previous WG route · 24h before last report" if scene == "expired" else "Last 24 hours · WG relay", "section")
    c.txt(1540, 749, context["device"] + " · " + context["probe"], "small mono muted", "end")
    succeeded = sum(state == "available" for state, _ in PATH_BUSINESS_SAMPLES)
    failed = sum(state == "unavailable" for state, _ in PATH_BUSINESS_SAMPLES)
    missing = sum(state == "unknown" for state, _ in PATH_BUSINESS_SAMPLES)
    c.txt(47, 797, "HOURS WITH A RESULT", "eyebrow muted")
    c.txt(47, 832, f"{succeeded+failed} / 24", "metric")
    c.txt(47, 864, f"{succeeded} succeeded · {failed} failed", "body")
    c.txt(47, 889, f"{missing} hours unknown", "small muted")
    c.txt(47, 922, "This route · one sample per hour", "small muted")
    for x, label, fill in ((47, "Success", "#64B88E"), (161, "Failed", "#C87171"), (259, "Unknown", "#FAFBFA")):
        c.rect(x, 951, 7, 12, fill, "#BFC9C2" if label == "Unknown" else fill, 1)
        c.txt(x + 15, 962, label, "tiny muted")
    business_history_chart(c, 457, 820, 1083, 100, as_of="12m ago" if scene == "expired" else "now")
    c.txt(47, 1020, "Historical window ends at the last report, 12m ago. These samples do not establish current reachability." if scene == "expired" else "Last matching sample each hour · full HTTPS request time · not request totals or continuous uptime.", "small muted")


def path_workspace_filters(service: str) -> tuple[str, ...]:
    return ("all", "failed", "unknown", *(group for group in PATH_GROUPS if path_members(service, group))) if path_members(service) else ("all",)


def path_navigation_origins(scene: str) -> tuple[tuple[str, str], ...]:
    """Presentation-only return locations for rows that open this detail."""
    return tuple((key, group) for key, service, _ in PATH_SUMMARY_SERVICES
                 for group in path_workspace_filters(service)
                 if any(record["scene"] == scene for record in path_members(service, group)))


def path_detail_fragment(scene: str, tab: str, origin: tuple[str, str] | None = None) -> str:
    suffix = "-from-" + "-".join(origin) if origin else ""
    return f"paths-{scene}-{tab}{suffix}"


def live_path_view(scene: str) -> Canvas:
    c = Canvas("live-paths", "Path detail", "Inspect this device's route, policy and observations for a specific target.", "network / paths", "live-paths", height=1224, show_status=False)
    c.role = "group"
    context = dict(PATH_CONTEXT)
    context.update(name=context["device"], roles="access")
    record = next((r for r in PATH_ASSIGNMENTS if r["scene"] == scene), None)
    if record:
        context.update({key: record[key] for key in ("device", "name", "service", "policy")})
    if scene in ("failed", "pending", "lan"):
        context["roles"] = "access + forward"
    if scene == "failed":
        context.update(selection_age="10s ago", business_age="10s ago")
    elif scene == "direct":
        context.update(candidate="demo-media-direct", selection_age="15s ago")
    if scene == "lan":
        context.update(device="demo-laptop", service="demo-office", policy="demo-lan-policy", target="198.51.100.42")
    elif scene == "pending":
        context["policy"] = "demo-direct-policy"
    elif scene == "unassigned":
        context.update(service="demo-private", policy="", target="private.example")
    device, service, policy = (context[key] for key in ("device", "service", "policy"))
    scope = f"device={device}&service={service}&policy={policy}"
    service_key = "office" if scene == "lan" else "private" if scene == "unassigned" else "media"
    origins = (None, *path_navigation_origins(scene))
    for origin in origins:
        key, group = origin or (service_key, "all")
        navigation = "-".join(origin) if origin else "default"
        c.add(f'<g class="path-origin-navigation path-origin-{navigation}" data-ui="path-return" data-service="{service}" data-filter="{group}">')
        target = "#paths-service-" + key + ("-" + group if group != "all" else "")
        flow_link(c, 1562, 97, "← " + context["service"] + " devices", f"/routing?service={service}&filter={group}", anchor="end", href=target)
        c.add('</g>')
    c.add(f'<g data-ui="path-context" data-scene="{scene}" data-device="{device}" data-service="{service}" data-policy="{policy}">')
    for x, label, value in ((24, "DEVICE", context["name"]), (358, "SERVICE", service)):
        c.txt(x, 205, label, "eyebrow muted")
        c.add(f'<g data-ui="path-{label.lower()}-context">')
        c.txt(x, 244, value, "section")
        c.add('</g>')
    c.txt(712, 205, "POLICY FOR THIS DEVICE", "eyebrow muted")
    if policy:
        policy_href = "06-policies-lan.svg" if scene == "lan" else "06-policies.svg" if scene in ("current", "expired") else ""
        flow_link(c, 712, 244, policy + "  ↗", f"/policies/{policy}?{scope}", href=policy_href)
    else:
        c.txt(712, 244, "None assigned", "body amber")
    c.txt(1100, 205, "LAN ROUTING" if scene == "lan" else "DEVICE MODE", "eyebrow muted")
    reported = scene in ("current", "failed", "direct")
    c.txt(1100, 244, "To fixed gateway" if scene == "lan" else "Auto" if reported else "Unknown", "section")
    c.txt(1280 if scene == "lan" else 1175 if reported else 1210, 244, "Within allowed routes" if scene == "lan" else "Reported by device" if reported else "No current report", "small muted")
    c.add(f'<g data-ui="path-policy-summary" data-policy="{policy}">')
    c.txt(24, 294, "Access denied" if scene == "denied" else "Not authorized" if scene == "unassigned" else "Access allowed", "body red" if scene in ("denied", "unassigned") else "body green")
    summary = "All paths and target probes are denied" if scene == "denied" else "Assign an access policy on this device to use private-app" if scene == "unassigned" else "Direct allowed · entry: unrestricted · transit: unrestricted · internet exit: only internet-exit" if scene in ("current", "expired", "failed") else "Direct only · no entry, transit or internet exit nodes" if scene in ("pending", "direct") else "Fixed gateway: relay-west · entry: unrestricted · transit: unrestricted"
    c.txt(171, 294, summary, "small muted")
    flow_link(c, 1562, 294, "Service details →", f"/services/{service}?{scope}", anchor="end", href="05-services-lan.svg" if scene == "lan" else "05-services.svg" if service == "demo-video" else "")
    c.add('</g>')
    c.line(24, 320, 1562, 320)

    title, status, tone, note = {
        "current": ("Current route", "Target succeeded · HTTPS 200 · media.example/health", "green", "Selected by android-phone · 8s ago"),
        "failed": ("Current route · target failed", "Target failed · HTTPS 503 · media.example/health", "red", "Selected by workstation · 10s ago"),
        "direct": ("Current route · target result unknown", "Direct selection confirmed · no business result for media.example/health", "amber", "Selected by new-phone · 15s ago"),
        "pending": ("Waiting for device confirmation", "Policy updated to direct-access · current route and target result unknown", "amber", "Policy assignment saved on control-a"),
        "expired": ("Current route unknown", "Device selection report expired · no fresh target result", "amber", "Last selection report · 12m ago"),
        "denied": ("Access denied by policy", "media-access now denies this service · no authorized routes or target probes", "red", "Device application remains unknown"),
        "unassigned": ("No access policy for this service", "private-app is not assigned to android-phone", "amber", "Requested service is not authorized"),
        "lan": ("Current route unknown", "No device selection report · dashed path is an allowed candidate preview", "amber", "Specific target · 198.51.100.42"),
    }[scene]
    c.txt(24, 355, title, "section")
    c.txt(1562, 355, note, "small muted", "end")
    c.circle(29, 388, 4, {"green": "#2AA875", "amber": "#D2A45B", "red": "#C87171"}[tone])
    c.txt(43, 393, status, "body " + tone)
    if scene in ("current", "failed", "lan"):
        flow_link(c, 1562, 393, "Open topology →", "/topology?link=" + ("demo-link-a-c" if scene == "lan" else "demo-link-wg") + "&" + scope, anchor="end", href="03-topology.svg" if scene == "current" else "")
    elif scene in ("pending", "expired"):
        c.txt(1562, 393, "Previous route · media-access · not current", "small muted", "end")
    if scene in ("denied", "unassigned"):
        c.icon("icon-lock", 47, 456, 30)
        c.txt(102, 473, "Access is blocked by the current policy." if scene == "denied" else "Choose a policy on the device to grant access.", "section")
        c.txt(102, 504, "Earlier successful checks do not establish current permission. Direct is not a fallback.", "small muted")
        flow_link(c, 102, 536, "Review media-access →" if scene == "denied" else "Edit this device's policies →", f"/policies/{policy}?{scope}" if scene == "denied" else f"/devices/{device}?section=access&{scope}")
    else:
        live_path_diagram(c, scene, context)
    c.line(24, 567, 1562, 567)
    c.txt(24, 594, "TARGET RESULT" if scene in ("lan", "denied", "unassigned") else "END-TO-END HTTPS", "eyebrow muted")
    c.txt(24, 625, f"{PATH_BUSINESS_SAMPLES[-1][1]} ms" if scene == "current" else "HTTPS 503" if scene == "failed" else "Not authorized" if scene in ("denied", "unassigned") else "Unknown", "metric" if scene == "current" else "body red" if scene == "failed" else "body amber")
    c.txt(218, 594, context["probe"] if scene != "lan" and service == "demo-video" else context["target"], "body mono")
    c.txt(218, 622, f'Measured on {device} · {context["business_age"]}' if scene in ("current", "failed") else "No target observation received" if scene == "direct" else "No applicable HTTPS target or actual business sample" if scene == "lan" else "Earlier samples cannot confirm the current result", "small muted")
    c.txt(960, 594, "DEVICE RUNTIME", "eyebrow muted")
    c.txt(960, 625, "Unknown", "body amber")
    c.txt(1057, 625, "No fresh runtime report", "small muted")
    device_href = "02-nodes-detail.svg#detail-ssh-joined-overview" if scene in ("lan", "failed") else "02-nodes-detail.svg#detail-qr-joined-overview" if scene == "direct" else "02-nodes-detail.svg" if scene == "pending" else ""
    flow_link(c, 1562, 625, "View device →", f"/devices/{device}?section=overview&service={service}&policy={policy}", anchor="end", href=device_href)
    c.line(24, 650, 1562, 650)

    c.add(f'<g data-ui="path-tabs" data-scene="{scene}">')
    for origin in origins:
        navigation = "-".join(origin) if origin else "default"
        c.add(f'<g class="path-origin-navigation path-origin-{navigation}">')
        for x, key, label, width in ((24, "candidates", "Candidate routes", 142), (201, "history", "History", 69)):
            c.add(f'<a id="paths-{scene}-tab-{key}-{navigation}" class="path-tab path-tab-{key}" href="#{path_detail_fragment(scene, key, origin)}" data-ui="path-tab" data-tab="{key}">')
            c.rect(x, 667, width, 38, "transparent", "none", 0)
            c.txt(x + 4, 691, label, "body path-tab-label")
            c.add(f'<line class="path-tab-mark" x1="{x}" y1="706" x2="{x+width}" y2="706" stroke-width="2"/>')
            c.add('</a>')
        c.add('</g>')
    counts = {"current": 4, "failed": 4, "direct": 1, "expired": 4, "pending": 1, "lan": 2, "denied": 0, "unassigned": 0}
    count = counts[scene]
    c.txt(1562, 691, f'{count} authorized candidate{"s" if count != 1 else ""} · read only', "small muted", "end")
    c.add('</g>')
    c.line(24, 708, 1562, 708)
    for key, draw in (("candidates", live_path_candidates), ("history", live_path_history)):
        c.add(f'<g id="paths-{scene}-panel-{key}" class="path-panel path-panel-{key}" data-ui="path-panel" data-tab="{key}">')
        draw(c, scene, context)
        c.add('</g>')
    c.add('</g>')
    return c


def path_device_rows(c: Canvas, members: tuple[dict, ...], y: int, *, origin: tuple[str, str]) -> int:
    for x, heading in ((386, "DEVICE"), (590, "POLICY"), (805, "CURRENT ROUTE"), (1140, "TARGET / UPDATED")):
        c.txt(x, y, heading, "eyebrow muted")
    top = y + 18
    c.line(362, top, 1562, top)
    for record in members:
        device, service, policy = (record[key] for key in ("device", "service", "policy"))
        c.add(f'<a data-ui="path-device-row" data-device="{device}" data-service="{service}" data-policy="{policy}" data-scene="{record["scene"]}" href="#{path_detail_fragment(record["scene"], "candidates", origin)}">')
        c.rect(363, top + 1, 1198, 82, "transparent", "none", 0)
        c.txt(386, top + 31, record["name"], "body mono")
        c.txt(386, top + 55, "Open path details →", "small green")
        c.txt(590, top + 31, policy, "body mono")
        group = record["group"] if record["selection"] == "fresh" else "unconfirmed"
        c.txt(805, top + 31, PATH_GROUPS[group]["label"], "body")
        c.txt(805, top + 55, "Waiting for new policy confirmation" if record["selection"] == "pending" else "No device selection report" if record["selection"] != "fresh" else PATH_GROUPS[group]["caption"], "small muted")
        tone = {"available": "green", "unavailable": "red", "unknown": "amber"}[record["target"]]
        result = {"available": "Target succeeded", "unavailable": "Target failed", "unknown": "Target unknown"}[record["target"]]
        c.txt(1140, top + 31, result, "body " + tone)
        c.txt(1140, top + 55, record["reason"], "small muted")
        c.txt(1540, top + 31, record["age"], "small muted", "end")
        c.add('</a>')
        c.line(362, top + 84, 1562, top + 84, kind="table-rule")
        top += 84
    return top


def path_service_navigation(c: Canvas, selected: str) -> None:
    c.add('<g data-ui="path-services-list" role="navigation" aria-label="Services">')
    c.txt(24, 211, "Services", "section")
    c.txt(310, 211, "Devices", "small muted", "end")
    search_control(c, 24, 237, 286, "Find a service")
    for index, (key, service, subtitle) in enumerate(PATH_SUMMARY_SERVICES):
        top = 294 + index * 126
        members = path_members(service)
        c.add(f'<a data-ui="path-service-select" data-service="{service}" data-devices="{"unknown" if key == "work" else len(members)}" aria-current="{str(key == selected).lower()}" href="#paths-service-{key}">')
        c.rect(24, top + 1, 286, 124, "#EDF5F0" if key == selected else "transparent", "none", 0)
        if key == selected:
            c.rect(24, top + 1, 3, 124, "#248F64", "none", 0)
        c.txt(44, top + 30, service, "body")
        c.txt(294, top + 30, "Unknown" if key == "work" else str(len(members)), "small amber" if key == "work" else "body", "end")
        c.txt(44, top + 54, "LAN · relay-west" if key == "office" else "Service suspended" if key == "work" else "Internet", "small muted")
        if members:
            failed = sum(r["target"] == "unavailable" for r in members)
            unknown = sum(r["target"] == "unknown" for r in members)
            result = " · ".join(f"{count} {label}" for count, label in ((failed, "failed"), (unknown, "unknown")) if count) or "Targets succeeded"
            c.txt(44, top + 78, result, "small red" if failed else "small amber" if unknown else "small green")
            routes = " · ".join(f"{label} {len(path_members(service, group))}" for group, label in (("wg", "WG"), ("direct", "Direct"), ("unconfirmed", "Unconfirmed")) if path_members(service, group))
            c.txt(44, top + 102, routes, "tiny muted")
        else:
            c.txt(44, top + 78, "Conflicting changes" if key == "work" else "No devices assigned", "small amber" if key == "work" else "small muted")
            c.txt(44, top + 102, "Projection suspended" if key == "work" else "No authorized observations", "tiny muted")
        c.add('</a>')
        c.line(24, top + 126, 310, top + 126)
    c.add('</g>')


def live_paths_workspace(key: str, group: str = "all") -> Canvas:
    _, service, subtitle = next(row for row in PATH_SUMMARY_SERVICES if row[0] == key)
    all_members = path_members(service)
    members = path_members(service, group)
    c = Canvas("live-paths", "Live paths", "Choose a service to see its devices. Open a device for path details.", "network / paths", "live-paths", height=944, show_status=False)
    c.role = "group"
    devices = {r["device"] for r in PATH_ASSIGNMENTS}
    c.txt(1562, 97, f'{len(PATH_SUMMARY_SERVICES)} services · {len(devices)} devices in active services · {len(PATH_ASSIGNMENTS)} access records', "small muted", "end")
    path_service_navigation(c, key)
    c.line(334, 198, 334, 888)
    c.add(f'<g data-ui="path-devices-list" data-service="{service}" data-filter="{group}">')
    c.txt(362, 211, service, "metric")
    policies = {r["policy"] for r in all_members}
    c.txt(1562, 211, "Assignment count unknown" if key == "work" else f'{len(all_members)} device{"s" if len(all_members) != 1 else ""} · {len(policies)} polic{"ies" if len(policies) != 1 else "y"}', "body", "end")
    c.txt(362, 244, subtitle, "body muted")
    c.line(362, 258, 1562, 258)
    if not all_members:
        c.txt(386, 318, "Service suspended" if key == "work" else "No devices assigned", "section")
        c.txt(386, 356, "Two conflicting service changes prevent a current route projection." if key == "work" else "This service has no device policy assignments, so there are no access paths to inspect.", "body muted")
        flow_link(c, 386, 399, "Review configuration conflict →" if key == "work" else "Manage service →", "/administration/configuration?target=demo-work" if key == "work" else "/services/demo-private", href="09-administration-configuration.svg#compare" if key == "work" else "")
        c.add('</g>')
        return c
    search_control(c, 362, 276, 300, "Find a device")
    label = "Target failures" if group == "failed" else "Unknown target results" if group == "unknown" else "All devices" if group == "all" else PATH_GROUPS[group]["label"]
    c.txt(1562, 302, f"{label} · {len(members)} of {len(all_members)} devices", "small muted", "end")
    filters = ((75, "all", "All"), (90, "failed", "Failed"), (124, "unknown", "Unknown"),
               (330, "wg", "WG · control-a → internet-exit"), (106, "direct", "Direct"),
               (230, "unconfirmed", "No confirmed route"))
    x = 370
    for width, value, title in filters:
        filtered = path_members(service, value)
        if value in PATH_GROUPS and not filtered:
            continue
        fragment = f"paths-service-{key}" + ("-" + value if value != "all" else "")
        active = group == value
        c.add(f'<a data-ui="path-device-filter" data-filter="{value}" data-count="{len(filtered)}" aria-current="{str(active).lower()}" href="#{fragment}">')
        c.rect(x - 8, 332, width, 36, "transparent", "none", 0)
        c.txt(x, 356, f"{title} · {len(filtered)}", "small green" if active else "small muted")
        if active:
            c.add(f'<line x1="{x - 8}" y1="376" x2="{x + width - 8}" y2="376" stroke="#248F64" stroke-width="2"/>')
        c.add('</a>')
        x += width + (36 if value == "unknown" else 18)
    bottom = path_device_rows(c, members, 407, origin=(key, group))
    if not members:
        c.txt(386, bottom + 36, "No devices match this filter.", "body muted")
    else:
        c.txt(362, bottom + 37, "Target results apply to the observed target only. Missing device reports remain unknown.", "small muted")
    c.add('</g>')
    return c


# Two page levels: service navigation with its device list -> device path detail.
# Tabs and observation states stay inside their page, not separate output files.
LIVE_PATH_PROTOTYPES = {
    "04-live-paths": "paths-service-media",
    "04-live-paths-detail": "paths-current-candidates",
}


def live_path_targets() -> dict[str, tuple[str, str, str]]:
    # Fragment -> output file, drawing scene, detail tab. This is a drawing index.
    targets = {}
    for key, service, _ in PATH_SUMMARY_SERVICES:
        for group in path_workspace_filters(service):
            fragment = "paths-service-" + key + ("-" + group if group != "all" else "")
            targets[fragment] = ("04-live-paths", f"{key}-{group}", "")
    for scene in ("current", "failed", "direct", "pending", "expired", "denied", "unassigned", "lan"):
        for origin in (None, *path_navigation_origins(scene)):
            for tab in ("candidates", "history"):
                targets[path_detail_fragment(scene, tab, origin)] = ("04-live-paths-detail", scene, tab)
    return targets


def live_paths(page: str = "04-live-paths") -> Canvas:
    targets = live_path_targets()
    local = {fragment: (scene, tab) for fragment, (owner, scene, tab) in targets.items() if owner == page}
    default_scene, default_tab = local[LIVE_PATH_PROTOTYPES[page]]

    def draw(scene: str) -> Canvas:
        if "-" in scene:
            return live_paths_workspace(*scene.split("-", 1))
        return live_path_view(scene)

    def tab_style(scope: str, selected: str) -> list[str]:
        rules = []
        for tab in ("candidates", "history"):
            active = tab == selected
            rules.extend((
                f"{scope} .path-panel-{tab} {{ display:{'inline' if active else 'none'}; }}",
                f"{scope} .path-tab-{tab} .path-tab-label {{ fill:{'#248F64' if active else '#79837D'}; font-weight:{600 if active else 400}; }}",
                f"{scope} .path-tab-{tab} .path-tab-mark {{ stroke:{'#248F64' if active else 'transparent'}; }}",
            ))
        return rules

    c = draw(default_scene)
    c.name = page
    default_parts = c.parts
    c.parts = []
    css = [
        ".path-scene { display:none; }",
        f"#paths-scene-{default_scene} {{ display:inline; }}",
        f"svg:has(.path-scene-target:target) #paths-scene-{default_scene} {{ display:none; }}",
        *tab_style("svg", default_tab or "candidates"),
        ".path-origin-navigation { display:none; } .path-origin-default { display:inline; }",
        "a:focus-visible { outline:2px solid #4D78D1; outline-offset:3px; }",
    ]
    for fragment, (scene, tab) in local.items():
        c.add(f'<g id="{fragment}" class="path-scene-target"/>')
        scope = f"svg:has(#{fragment}:target) #paths-scene-{scene}"
        css.append(f"{scope} {{ display:inline; }}")
        if tab:
            css.extend(tab_style(scope, tab))
        if "-from-" in fragment:
            origin = fragment.split("-from-", 1)[1]
            css.extend((f"{scope} .path-origin-default {{ display:none; }}",
                        f"{scope} .path-origin-{origin} {{ display:inline; }}"))
    for scene in dict.fromkeys(scene for scene, _ in local.values()):
        c.add(f'<g id="paths-scene-{scene}" class="path-scene">')
        c.parts.extend(default_parts if scene == default_scene else draw(scene).parts)
        c.add('</g>')
    c.add('<style><![CDATA[' + "\n".join(css) + ']]></style>')

    def destination(match: re.Match) -> str:
        fragment = match[1]
        owner = targets[fragment][0]
        if owner == page:
            return f'href="#{fragment}"'
        suffix = "" if LIVE_PATH_PROTOTYPES[owner] == fragment else "#" + fragment
        return f'href="{owner}.svg{suffix}"'

    c.parts = [re.sub(r'href="#(paths-[^"]+)"', destination, part) for part in c.parts]
    return c


def flow_canvas(name: str, title: str, subtitle: str, section: str, *, height: int = 992) -> Canvas:
    return Canvas(name, title, subtitle, section, "nodes", height=height, content_x=353, show_status=False)


def flow_input(c: Canvas, x: int, y: int, w: int, value: str, *, dropdown: bool = False) -> None:
    c.add('<g data-ui="input">')
    c.rect(x, y, w, 42, "#FFFFFF", "#D8E0DA", 5)
    c.txt(x + 14, y + 27, value, "body")
    if dropdown:
        c.icon("icon-chevron", x + w - 29, y + 13)
    c.add('</g>')


def flow_link(c: Canvas, x: int, y: int, label: str, route: str, *, anchor: str = "start", href: str = "") -> None:
    tag = 'a' if href else 'g'
    destination = f' href="{escape(href)}"' if href else ''
    c.add(f'<{tag} data-ui="navigation" data-route="{escape(route)}"{destination}>')
    c.txt(x, y, label, "small green", anchor)
    c.add(f'</{tag}>')


def join_scope(c: Canvas, method: str, state: str) -> None:
    scene = JOIN_SCENES[method]
    delivery = "script" if method == "control" else method
    c.add(f'<g data-ui="join-context" data-device="{scene["device"]}" data-invite="{scene["invite"]}" data-method="{delivery}" data-state="{state}">')


def invited_policies(c: Canvas, y: int, method: str) -> int:
    policy_ids = JOIN_SCENES[method]["policies"]
    c.txt(353, y, "Selected access policies", "section")
    c.txt(1233, y, "Selection fixed when issued", "small muted", "end")
    if not policy_ids:
        c.txt(353, y + 38, "No access policies · this device has no access role", "body")
        c.txt(353, y + 68, "Forwarding and exit permissions follow the authorized traffic of other devices.", "small muted")
        return y + 98
    for x, label in ((353, "POLICY"), (820, "SERVICE · FROM POLICY")):
        c.txt(x, y + 39, label, "eyebrow muted")
    c.line(353, y + 54, 1233, y + 54)
    top = y + 54
    for policy in policy_ids:
        service = POLICY_FIXTURES[policy]["service"]
        c.add(f'<g data-ui="invited-policy" data-policy="{policy}" data-service="{service}" aria-readonly="true">')
        c.txt(353, top + 28, policy, "body mono")
        c.txt(353, top + 51, "Direct only" if policy == "demo-direct-policy" else "Allow · shared policy", "small muted")
        c.txt(820, top + 28, service, "body mono")
        target = "198.51.100.0/24 · relay-west" if service == "demo-office" else "media.example + .cdn.media.example"
        c.txt(820, top + 51, target, "small muted")
        c.line(353, top + 70, 1233, top + 70)
        c.add('</g>')
        top += 70
    c.txt(353, top + 27, "Shared rule updates apply to these policies, including before the device joins.", "small muted")
    return top + 50


def flow_actions(c: Canvas, y: int, primary: str, *, x: int = 353, w: int = 880,
                 secondary: str = "Cancel", meta: str = "", primary_w: int = 218,
                 destructive: bool = False) -> None:
    c.add('<g data-ui="form-actions">')
    c.line(x, y, x + w, y)
    if meta:
        c.txt(x, y + 49, meta, "small muted")
    if secondary:
        c.txt(x + w - primary_w - 28, y + 49, secondary, "body muted", "end")
    fill = "#B44B45" if destructive else "#248F64"
    c.rect(x + w - primary_w, y + 22, primary_w, 42, fill, fill, 6)
    c.txt(x + w - primary_w // 2, y + 49, primary, "body white", "middle")
    c.add('</g>')


def tag_selector(c: Canvas, x: int, y: int, w: int, items: tuple[tuple[str, str], ...], *, field: str, placeholder: str) -> int:
    """Searchable multi-selection; chip identity is separate from its label."""
    positions = []
    tx, ty = x + 10, y + 9
    for identity, label in items:
        tw = math.ceil(len(display_text(label)) * 6.7) + 36
        if tx + tw > x + w - 29:
            tx, ty = x + 10, ty + 35
        positions.append((identity, label, tx, ty, tw))
        tx += tw + 7
    search_w = math.ceil(len(placeholder) * 6.3) + 12
    if tx + search_w > x + w - 29:
        tx, ty = x + 10, ty + 35
    height = ty - y + 35
    c.add(f'<g data-ui="tag-selector" data-field="{field}" aria-multiselectable="true">')
    c.rect(x, y, w, height, "#FFFFFF", "#D8E0DA", 5)
    for identity, label, px, py, pw in positions:
        c.add(f'<g data-ui="selected-tag" data-value="{identity}">')
        c.rect(px, py, pw, 26, "#EEF3F0", "none", 4)
        c.txt(px + 9, py + 17, label, "small")
        c.add(f'<g data-ui="remove-tag" data-value="{identity}">')
        c.txt(px + pw - 12, py + 17, "×", "body muted", "middle")
        c.add('</g></g>')
    c.txt(tx + 3, ty + 18, placeholder, "small muted")
    c.icon("icon-chevron", x + w - 24, y + 15)
    c.add('</g>')
    return height


def policy_picker(c: Canvas, y: int, policy_ids: tuple[str, ...], *, device: str) -> int:
    """Node drafts edit PolicyIDs only; service and rule summaries are derived."""
    c.add(f'<g data-ui="policy-picker" data-device="{device}" data-submit-scope="policy-ids">')
    c.txt(353, y, "Access policies", "section")
    flow_link(c, 1233, y, "+ New policy", f"/policies?new=1&return_device={device}", anchor="end")
    tags = tuple((policy, policy + " · " + POLICY_FIXTURES[policy]["service"]) for policy in policy_ids)
    height = tag_selector(c, 353, y + 19, 880, tags, field="policy-ids", placeholder="Find a policy…")
    c.txt(353, y + height + 45, "Each policy includes its service and rules. Choose at most one policy per service.", "small muted")
    top = y + height + 72
    for policy in policy_ids:
        value = POLICY_FIXTURES[policy]
        service = value["service"]
        c.add(f'<g data-ui="selected-policy-summary" data-policy="{policy}" data-service="{service}" aria-readonly="true">')
        c.line(353, top, 1233, top)
        c.txt(353, top + 31, policy, "body mono")
        c.txt(629, top + 31, service + " · " + ("Shared LAN" if service == "demo-office" else "Internet"), "body")
        flow_link(c, 1233, top + 31, "View rules →", f"/policies/{policy}", anchor="end")
        c.txt(353, top + 59, value["summary"], "small muted")
        c.txt(353, top + 85, SERVICE_FIXTURES[service]["target"], "small mono muted")
        c.add('</g>')
        top += 111
    if not policy_ids:
        c.txt(353, top + 24, "Join only · no service access", "body muted")
        top += 60
    c.add('</g>')
    return top


def catalog_rail(c: Canvas, y: int, title: str, search: str, entries: tuple[tuple[str, str, str], ...], *, selected: str = "") -> None:
    """A flat object list; only the selected row gets a background."""
    c.add('<g data-ui="catalog-list">')
    c.txt(24, y, title, "section")
    c.txt(360, y, str(len(entries)), "small muted", "end")
    search_control(c, 24, y + 20, 336, search)
    for i, (name, detail, state) in enumerate(entries):
        top = y + 76 + i * 92
        active = name == selected if selected else i == 0
        c.add(f'<g data-ui="catalog-item" data-object="{name}" aria-selected="{str(active).lower()}">')
        if active:
            c.rect(24, top, 336, 92, "#EDF4FB", "none", 4)
            c.rect(24, top + 10, 3, 72, "#4D78D1", "none", 0)
        c.txt(42, top + 28, name, "body mono")
        c.txt(42, top + 52, detail, "small muted")
        if name == "demo-work":
            c.add('<a href="09-administration-configuration.svg#compare" data-ui="configuration-conflict-link">')
        c.txt(42, top + 74, state, "small amber" if "Suspended" in state else "tiny muted")
        if name == "demo-work":
            c.add('</a>')
        c.txt(344, top + 30, "›", "body muted", "end")
        c.line(24, top + 92, 360, top + 92)
        c.add('</g>')
    c.add('</g>')


def services(*, lan: bool = False) -> Canvas:
    c = Canvas("services-lan" if lan else "services", "Services", "Define internet destinations or a shared LAN. Policies decide how devices may access each service.", "network intent", "services", height=1140, show_status=False)
    tabs(c, ("Services", "Exact .loom DNS", "Probe targets"), "Services", 219)
    c.button(1382, 106, 180, "+ Add service ▾", True)
    catalog_rail(c, 278, "All services", "Search name or destination", (
        ("demo-video", "media.example + 1 suffix", "Internet · used by 1 device"),
        ("demo-work", "2 conflicting changes", "Suspended · review conflict →"),
        ("demo-private", "private.example", "Internet · no device assignments"),
        ("demo-office", "198.51.100.0/24 · demo-forward-c", "Shared LAN · no device assignments"),
    ), selected="demo-office" if lan else "demo-video")
    c.txt(24, 767, "Create policies for a service.", "small muted")
    c.txt(24, 790, "Then assign policies to devices.", "small muted")
    flow_link(c, 24, 832, "Manage access policies →", "/policies")
    c.line(396, 258, 396, 1112)

    left, right, width = 446, 1514, 1068
    c.txt(left, 278, "Service details", "section")
    c.txt(right, 278, "Service ID · " + ("demo-office" if lan else "demo-video"), "small mono muted", "end")
    c.circle(left + 4, 304, 4, "#2AA875")
    c.txt(left + 18, 309, "Effective · LAN service" if lan else "Effective · internet destinations", "small green")
    c.txt(right, 309, "Editing draft", "small muted", "end")
    c.txt(left, 354, "Display name", "body")
    flow_input(c, left, 369, width, "Office network" if lan else "Media traffic")
    if lan:
        c.add('<g data-ui="lan-service-detail" data-service="demo-office" data-gateway="demo-forward-c">')
        c.txt(left, 457, "Network provided by this service", "section")
        c.txt(left, 500, "GATEWAY NODE", "eyebrow muted")
        c.txt(left, 531, "demo-forward-c", "body mono")
        c.txt(740, 531, "forward · fixed gateway for this service", "small muted")
        c.txt(right, 531, "Open gateway →", "small green", "end")
        c.txt(left, 581, "ADDRESS USED BY ACCESS DEVICES", "eyebrow muted")
        c.txt(1080, 581, "NETWORK BEHIND THE GATEWAY", "eyebrow muted")
        c.txt(left, 615, "198.51.100.0/24", "section mono")
        c.txt(1008, 615, "→", "body muted")
        c.txt(1080, 615, "192.0.2.0/24", "section mono")
        c.txt(left, 646, "Virtual prefix · assigned when the service was created", "small muted")
        c.txt(1080, 646, "Reported LAN prefix", "small muted")
        c.txt(left, 688, "Example · 198.51.100.42 → demo-forward-c → 192.0.2.42", "body mono")
        c.txt(left, 716, "Access rules choose how to reach this gateway. The destination stays this local network.", "small muted")
        c.line(left, 744, right, 744)
        c.txt(left, 778, "Policies for this service", "section")
        flow_link(c, right, 778, "+ New policy", "/policies?new=1&service=demo-office", anchor="end")
        c.add('<g data-ui="service-policy" data-service="demo-office" data-policy="demo-lan-policy">')
        flow_link(c, left, 813, "office-lan →", "/policies/demo-lan-policy")
        c.txt(right, 813, "No devices assigned", "small muted", "end")
        c.add('</g>')
        c.line(left, 841, right, 841)
        c.txt(left, 875, "Related private name", "body")
        c.txt(left, 909, "demo-printer.loom → 198.51.100.42", "body mono")
        c.txt(right, 909, "View DNS record →", "small green", "end")
        c.txt(left, 944, "Business observation · unknown · no matching HTTPS target", "small muted")
        flow_actions(c, 976, "Save service name", x=left, w=width, secondary="Discard", meta="LAN service · fixed gateway")
        c.line(left, 1065, right, 1065)
        c.txt(left, 1099, "Delete LAN service", "body red")
        c.txt(left + 179, 1099, "Withdraws its mapping, access routes and related DNS projection.", "small muted")
        c.add('</g>')
        return c
    c.txt(left, 457, "Destinations", "section")
    c.txt(right, 457, "2 matchers", "small muted", "end")
    c.txt(left, 490, "HOSTNAME OR SUFFIX", "eyebrow muted")
    c.txt(1118, 490, "MATCH", "eyebrow muted")
    for y, destination, match_type in ((508, "media.example", "Exact"), (564, ".cdn.media.example", "Suffix")):
        flow_input(c, left, y, 650, destination)
        flow_input(c, 1118, y, 252, match_type, dropdown=True)
        c.txt(right, y + 27, "Remove", "small muted", "end")
    c.txt(left, 638, "+ Add matcher", "body green")
    c.txt(right, 638, "A suffix starts with a dot, such as .cdn.media.example", "small muted", "end")
    c.line(left, 665, right, 665)
    c.txt(left, 699, "Matching probe target", "body")
    c.txt(left, 730, "https://media.example/health", "body mono")
    c.txt(right, 730, "View probe pool →", "small green", "end")
    c.txt(left, 755, "From the shared pool, filtered by destinations and each device's access.", "small muted")
    c.line(left, 782, right, 782)
    c.txt(left, 816, "Policies for this service", "section")
    flow_link(c, right, 816, "+ New policy", "/policies?new=1&service=demo-video", anchor="end")
    c.txt(left, 852, "POLICY", "eyebrow muted")
    c.txt(1000, 852, "USED BY", "eyebrow muted")
    c.line(left, 868, right, 868)
    for yy, policy, usage in ((900, "demo-policy", "demo-phone-f · 1 device"), (961, "demo-direct-policy", "No devices assigned")):
        c.add(f'<g data-ui="service-policy" data-service="demo-video" data-policy="{policy}">')
        flow_link(c, left, yy, policy + " →", f"/policies/{policy}")
        c.txt(1000, yy, usage, "body muted")
        c.line(left, yy + 24, right, yy + 24)
        c.add('</g>')
    c.txt(left, 1017, "Destination changes affect every policy and device using this service.", "small muted")
    flow_actions(c, 1044, "Save destinations", x=left, w=width, secondary="Discard", meta="Service definition only")
    c.line(left, 1133, right, 1133)
    c.txt(left, 1167, "Delete service", "body red")
    c.txt(left + 152, 1167, "Removes access through its policies. Devices do not switch to another service.", "small muted")
    c.fit_height(1208)
    return c


def services_dns() -> Canvas:
    c = Canvas("services-dns", "Private DNS", "Choose a private name to inspect its answers or edit an explicit record.", "services / dns", "services", height=1110, show_status=False)
    tabs(c, ("Services", "Exact .loom DNS", "Probe targets"), "Exact .loom DNS", 219)
    c.button(1382, 106, 180, "+ Add record", True)
    search_control(c, 24, 253, 448, "Search a private name or address")
    c.txt(1562, 278, "demo-network · 2 names · 3 answers", "small muted", "end")
    c.card(24, 308, 1538, 778, "Private records", "current signed values · one editor open")
    for x, label in ((47, "EXACT NAME"), (580, "ANSWER / SOURCE"), (1260, "RECORD ACTION")):
        c.txt(x, 388, label, "eyebrow muted")
    c.line(24, 402, 1562, 402, kind="table-rule")
    c.add('<g data-ui="reserved-dns-record" data-name="control.loom" aria-readonly="true">')
    c.icon("icon-lock", 47, 426)
    c.txt(73, 440, "control.loom", "body mono")
    c.txt(47, 474, "Derived from serving private Web entries", "small muted")
    for y, answer, source in ((439, "192.0.2.10", "demo-control-a"), (477, "192.0.2.11", "demo-control-b")):
        c.txt(580, y, "A", "small muted")
        c.txt(615, y, answer, "body mono")
        c.txt(865, y, source, "small mono muted")
    c.txt(1260, 440, "Reserved · read only", "body muted")
    c.txt(1260, 474, "View Web entries →", "small green")
    c.add('</g>')
    c.line(24, 506, 1562, 506, kind="table-rule")
    c.rect(25, 507, 1536, 79, "#EDF4FB", "none", 0)
    c.rect(25, 507, 3, 79, "#4D78D1", "none", 0)
    c.txt(47, 538, "demo-printer.loom", "body mono")
    c.txt(47, 563, "Explicit record · effective", "small green")
    c.txt(580, 538, "A", "small muted")
    c.txt(615, 538, "198.51.100.42", "body mono")
    c.txt(865, 538, "Mapped LAN · demo-forward-c", "small muted")
    c.txt(580, 563, "Current answer", "small muted")
    c.txt(1260, 538, "Editing record", "body")
    c.txt(1260, 563, "Hide editor ⌃", "small green")
    c.line(24, 586, 1562, 586, kind="table-rule")

    c.add('<g data-ui="dns-record-editor" data-name="demo-printer.loom">')
    c.txt(66, 625, "Edit explicit record", "section")
    c.txt(1518, 625, "Draft · current answer remains active until saved", "small muted", "end")
    for x, label in ((66, "Exact private name"), (582, "Record type"), (804, "IPv4 answer")):
        c.txt(x, 670, label, "body")
    flow_input(c, 66, 685, 492, "demo-printer.loom")
    flow_input(c, 582, 685, 198, "A · IPv4", dropdown=True)
    flow_input(c, 804, 685, 714, "198.51.100.42")
    c.txt(66, 758, "Exact .loom names only · A / AAAA · control.loom is reserved", "small muted")
    c.line(66, 786, 1518, 786)
    c.txt(66, 820, "CURRENT ANSWER LEADS TO", "eyebrow muted")
    c.txt(1020, 820, "DNS OBSERVATION", "eyebrow muted")
    c.txt(66, 852, "demo-office", "body mono")
    c.txt(322, 852, "198.51.100.0/24 · gateway demo-forward-c", "body muted")
    c.txt(1020, 852, "unknown", "body amber")
    c.txt(1122, 852, "No current resolution measurement", "small muted")
    c.txt(66, 884, "Grant this service and a policy in each device's access settings.", "small muted")
    c.txt(1518, 884, "View LAN service →", "small green", "end")
    flow_actions(c, 925, "Save record", x=66, w=1452, primary_w=180, meta="Changes name resolution only")
    c.add('</g>')
    c.line(24, 1016, 1562, 1016, kind="panel-section")
    c.txt(47, 1044, "After saving: check local acceptance and peer propagation. DNS and service reachability need their own observations.", "small muted")
    c.txt(47, 1068, "Wildcard names and public-domain overrides are not supported.", "tiny muted")
    return c


def node_lan_mapping() -> Canvas:
    c = flow_canvas("node-lan-mapping", "Create shared LAN service", "Choose which network to share through demo-forward-c.", "devices / demo-forward-c / shared lan", height=1000)
    c.txt(353, 218, "Gateway", "small muted")
    c.txt(529, 218, "demo-forward-c", "body mono")
    c.txt(1233, 218, "Draft · no access granted", "small muted", "end")
    c.txt(353, 273, "Service name", "body")
    flow_input(c, 353, 285, 880, "Office network")
    c.txt(353, 371, "Reported local IPv4 prefix", "body")
    flow_input(c, 353, 383, 880, "192.0.2.0/24", dropdown=True)
    c.txt(353, 450, "Choose a network from this gateway's authenticated report.", "small muted")
    c.line(353, 481, 1233, 481)
    c.txt(353, 515, "Address mapping", "section")
    c.txt(1233, 515, "Assigned automatically", "small muted", "end")
    c.txt(353, 552, "Virtual prefix", "small muted")
    c.txt(761, 552, "Gateway node", "small muted")
    c.txt(353, 581, "198.51.100.0/24", "body mono")
    c.txt(761, 581, "demo-forward-c", "body mono")
    c.txt(353, 629, "Example access address", "small muted")
    c.txt(916, 629, "LAN destination", "small muted")
    c.txt(353, 660, "198.51.100.42", "section mono")
    c.add('<path d="M645 654H873" class="selected"/>')
    c.txt(916, 660, "192.0.2.42", "section mono")
    c.txt(353, 693, "Host bits stay the same. LAN hosts may reply to admitted connections only.", "small muted")
    c.line(353, 723, 1233, 723)
    c.txt(353, 758, "Assign access after creating the service", "body")
    c.txt(353, 786, "Create a policy for this LAN service, then select it on each device that needs access.", "small muted")
    c.txt(353, 811, "The policy always uses demo-forward-c as its destination gateway.", "small muted")
    c.txt(353, 845, "A prefix conflict disables the mapping; operator action follows at most three signed reallocation attempts.", "small muted")
    flow_actions(c, 891, "Create LAN service", meta="Shared LAN · fixed gateway")
    return c


def release_tabs(c: Canvas, selected: str) -> None:
    tabs(c, ("Linux", "Android", "Windows", "Device versions"), selected, 219)


# Exact-file fixtures shared by the platform and per-device readback drawings.
RELEASE_FILES = {
    "linux": (("demo-linux-agent", "demo-1.2.0", "sha256:6b…", "Node package"), ("demo-linux-cli", "demo-1.2.0", "sha256:2d…", "Generic public"), ("demo-linux-ui", "demo-1.2.0", "sha256:4a…", "Generic public")),
    "android": (("demo-android-app", "demo-1.2.0", "sha256:a3…", "Enrolled device"), ("demo-android-apk", "demo-1.2.0", "sha256:9c…", "Generic public"), ("demo-android-symbols", "demo-1.2.0", "sha256:0f…", "Restricted")),
    "windows": (("demo-windows-app", "demo-1.2.0", "sha256:88…", "Enrolled device"), ("demo-windows-installer", "demo-1.2.0", "sha256:53…", "Generic public"), ("demo-windows-portable", "demo-1.2.0", "sha256:71…", "Generic public")),
}


def release_catalog_context(c: Canvas, files: int) -> None:
    c.txt(24, 275, "Catalog demo-42", "section")
    c.circle(208, 270, 4, "#2AA875")
    c.txt(222, 275, "Publisher signature verified", "body green")
    c.txt(1562, 275, f"{files} exact files verified", "body green", "end")
    c.txt(24, 304, "sha256:7e… · verified with the publisher key from protected installation", "small muted")
    c.txt(1562, 304, "Current pointer selects this catalog only", "small muted", "end")


def deployments() -> Canvas:
    c = Canvas("deployments", "Device versions", "Check whether each device is running its assigned software.", "releases / device versions", "deployments", height=1240, show_status=False)
    release_tabs(c, "Device versions")
    release_catalog_context(c, 9)
    c.line(24, 326, 1562, 326)
    for x, value, label, tone in ((24, "1", "matching target", "green"), (260, "1", "different file", "amber"), (496, "3", "unknown", "amber")):
        c.txt(x, 366, value, "metric " + tone)
        c.txt(x + 37, 366, label, "body muted")
    c.txt(1562, 366, "5 devices · target and reported software", "small muted", "end")
    search_control(c, 24, 397, 440, "Search device or component")
    flow_input(c, 482, 395, 240, "All results", dropdown=True)
    flow_input(c, 738, 395, 224, "All platforms", dropdown=True)
    c.txt(1562, 421, "Linux packages →", "body green", "end")
    c.card(24, 455, 1538, 761, "Software by device", "Compare the exact files for the same component and platform")
    for x, label in ((47, "DEVICE / COMPONENT"), (562, "TARGET → REPORTED FILE"), (1160, "STATUS / DETAILS")):
        c.txt(x, 535, label, "eyebrow muted")
    c.line(24, 550, 1562, 550, kind="table-rule")
    rows = (
        ("demo-forward-c", "linux", "sha256:6b…", "Matching", "Recent report · exact file matches", "green"),
        ("demo-phone-f", "android", "unknown", "Unknown", "No recent device report", "amber"),
        ("demo-egress-e", "linux", "sha256:51…", "Different", "Recent report · file does not match", "amber"),
        ("demo-control-a", "linux", "unknown", "Unknown", "Report does not identify the file", "amber"),
        ("demo-forward-b", "linux", "unknown", "Unknown", "Last report is too old", "amber"),
    )
    top = 550
    for device, platform, reported, state, evidence, tone in rows:
        component, _, desired, _ = RELEASE_FILES[platform][0]
        selected = device == "demo-egress-e"
        c.add(f'<g data-ui="deployment-row" data-device="{device}" data-result="{state.lower()}">')
        if selected:
            c.rect(25, top, 1536, 88, "#FFF8EC", "none", 0)
            c.rect(25, top, 3, 88, "#D2A45B", "none", 0)
        c.txt(47, top + 34, device, "body mono")
        c.txt(47, top + 60, f"{platform.title()} · {component}", "small muted")
        c.txt(562, top + 34, desired, "body mono")
        c.txt(803, top + 34, "→", "body muted")
        c.txt(855, top + 34, reported, "body amber" if reported == "unknown" else "body mono")
        c.txt(562, top + 60, "Assigned target", "small muted")
        c.txt(855, top + 60, "Reported by device", "small muted")
        c.txt(1160, top + 34, {"Matching": "Matches target", "Different": "Differs from target", "Unknown": "Unknown"}[state], "body " + tone)
        c.txt(1160, top + 60, evidence, "small muted")
        c.txt(1538, top + 34, "⌃" if selected else "›", "body muted", "end")
        top += 88
        c.line(24, top, 1562, top, kind="table-rule")
        if selected:
            c.add('<g data-ui="deployment-detail">')
            c.rect(25, top, 1536, 142, "#FFFCF6", "none", 0)
            c.txt(66, top + 32, "Reported software does not match the target", "body amber")
            c.txt(66, top + 60, "demo-egress-e reports a Linux agent file that differs from its assigned target.", "body")
            c.txt(66, top + 87, "The cause and delivery status are unknown. Open the device report to investigate.", "small muted")
            c.txt(66, top + 118, "View device report →", "small green")
            c.txt(294, top + 118, "View target package →", "small green")
            c.txt(1518, top + 118, "Hide details ⌃", "small green", "end")
            c.add('</g>')
            top += 142
            c.line(24, top, 1562, top, kind="table-rule")
        c.add('</g>')
    c.txt(47, 1165, "A match requires a recent device report identifying the exact target file for the same component and platform.", "small muted")
    c.txt(47, 1191, "Unknown means there is not enough recent information. Minimum compatibility applies only when specified by a signed release.", "small muted")
    return c


EVENT_TYPES = (
    ("change", "Changes", "#5D89C5"),
    ("membership", "Membership", "#9176BC"),
    ("report", "Device reports", "#59AA88"),
    ("conflict", "Conflicts", "#CE7272"),
    ("expiry", "Observation expiry", "#D0A353"),
)
EVENT_AS_OF = datetime(2030, 1, 1, 10, 50, tzinfo=timezone.utc)


def event_drawing_records(as_of: datetime) -> tuple[dict, ...]:
    """Fixed synthetic history; timestamps and types feed both the chart and list."""
    start = as_of - timedelta(hours=72)
    records = []
    # Earlier illustration records stop before the original six latest events.
    for index in range(426):
        busy = 48 <= index % 144 < 90
        counts = (
            int(index % 11 == 1) + int(busy and index % 5 == 0),
            int(index % 83 == 12),
            (2, 1, 0, 3, 1, 2, 0, 1, 2, 1, 3, 0)[index % 12] + (2 if busy else 0),
            int(index in (24, 25, 26, 162, 163, 164, 320, 321)),
            int(index % 29 == 9),
        )
        ordinal = 0
        for (kind, _, _), count in zip(EVENT_TYPES, counts):
            for _ in range(count):
                ordinal += 1
                records.append({"id": f"demo-event-{index:03d}-{ordinal}", "kind": kind,
                                "received": start + timedelta(minutes=index * 10, seconds=ordinal * 47)})
    entries = (
        ("10:42:17", "change", "demo-phone-f · service access updated", "Material accepted · demo-control-a · demo-video → demo-policy", "Local only", "Peer receipt not confirmed", "amber"),
        ("10:40:05", "membership", "demo-control-b · member certificate verified", "Member change · old-member majority", "Effective", "Member chain updated", "green"),
        ("10:35:11", "report", "demo-phone-f · demo-video HTTPS probe", "Signed device report · demo-phone-f · media.example/health", "Available", "Reported HTTPS success", "green"),
        ("10:24:46", "conflict", "demo-work · incompatible service updates", "Conflict detected · demo-control-a · 2 verified facts", "Suspended", "Service projection paused", "amber"),
        ("10:10:20", "expiry", "demo-work · previous observation expired", "Observation expired · demo-phone-f · previous scope", "Unknown", "No current observation at that time", "amber"),
        ("09:55:02", "report", "demo-forward-c · runtime report", "Signed device report · demo-forward-c · then-current View", "Running", "Process and ACL reported", "green"),
    )
    for index, (stamp, kind, *display) in enumerate(entries):
        hour, minute, second = map(int, stamp.split(":"))
        records.append({"id": f"demo-event-latest-{index}", "kind": kind, "display": display,
                        "received": as_of.replace(hour=hour, minute=minute, second=second)})
    return tuple(sorted(records, key=lambda record: (record["received"], record["id"])))


def event_volume_chart(c: Canvas, records: tuple[dict, ...], as_of: datetime) -> None:
    start = as_of - timedelta(hours=72)
    bins = [[0] * len(EVENT_TYPES) for _ in range(432)]
    type_index = {kind: index for index, (kind, _, _) in enumerate(EVENT_TYPES)}
    for record in records:
        if start <= record["received"] < as_of:
            index = int((record["received"] - start).total_seconds()) // 600
            bins[index][type_index[record["kind"]]] += 1
    totals = [sum(bucket[index] for bucket in bins) for index in range(len(EVENT_TYPES))]
    limit = max(4, math.ceil(max(map(sum, bins)) / 4) * 4)
    c.add(f'<g data-ui="event-histogram" data-window-hours="72" data-bucket-minutes="10" data-bucket-count="432" data-total="{sum(totals)}" data-window-start="{start.isoformat()}" data-window-end="{as_of.isoformat()}" data-coverage="complete">')
    c.txt(24, 328, "Events over time", "section")
    c.txt(1562, 328, f"{sum(totals):,} events · last 72 hours", "small muted", "end")
    for x, (kind, label, color), total in zip((24, 220, 436, 686, 880), EVENT_TYPES, totals):
        c.add(f'<g data-ui="event-legend" data-kind="{kind}" data-count="{total}">')
        c.rect(x, 346, 10, 10, color, "none", 2)
        c.txt(x + 19, 356, f"{label} · {total:,}", "small")
        c.add('</g>')
    x, y, width, height = 72, 406, 1490, 160
    c.txt(x, 386, "Events / 10 min", "tiny muted")
    for step in range(5):
        value = limit * step // 4
        yy = y + height - height * value / limit
        c.line(x, yy, x + width, yy)
        c.txt(x - 13, yy + 4, str(value), "tiny muted", "end")
    pitch = width / len(bins)
    c.add('<style>.event-bin-hit:hover { fill:#427994; fill-opacity:.12; } .event-bin-hit { cursor:crosshair; }</style>')
    for index, counts in enumerate(bins):
        bucket_start = start + timedelta(minutes=index * 10)
        bucket_end = bucket_start + timedelta(minutes=10)
        xx = x + index * pitch + .35
        c.add(f'<g data-ui="event-bucket" data-index="{index}" data-start="{bucket_start.isoformat()}" data-end="{bucket_end.isoformat()}" data-total="{sum(counts)}">')
        bottom = y + height
        for (kind, _, color), count in zip(EVENT_TYPES, counts):
            if not count:
                continue
            bar_height = height * count / limit
            bottom -= bar_height
            c.add(f'<rect data-ui="event-stack" data-kind="{kind}" data-count="{count}" x="{xx:.2f}" y="{bottom:.2f}" width="{pitch-.7:.2f}" height="{bar_height:.2f}" fill="{color}"/>')
        tooltip = (bucket_start.strftime("%Y-%m-%d %H:%M") + "–" + bucket_end.strftime("%Y-%m-%d %H:%M UTC") +
                   f" · {sum(counts)} events\n" + "\n".join(f"{label}: {count}" for (_, label, _), count in zip(EVENT_TYPES, counts)))
        c.add(f'<rect class="event-bin-hit" x="{x + index * pitch:.2f}" y="{y}" width="{pitch:.2f}" height="{height}" fill="transparent"><title>{escape(tooltip)}</title></rect>')
        c.add('</g>')
    for index in range(7):
        tick = start + timedelta(hours=index * 12)
        xx = x + width * index / 6
        anchor = "start" if index == 0 else "end" if index == 6 else "middle"
        c.txt(xx, 589, tick.strftime("%Y-%m-%d"), "tiny muted", anchor)
        c.txt(xx, 607, tick.strftime("%H:%M"), "tiny muted", anchor)
    c.txt(24, 631, "UTC · events received by demo-control-a · all 72 hours available · hover a bar for counts", "small muted")
    c.add('</g>')


def events() -> Canvas:
    records = event_drawing_records(EVENT_AS_OF)
    latest = tuple(reversed(records[-6:]))
    colors = {kind: color for kind, _, color in EVENT_TYPES}
    c = Canvas("events", "Events", "Explore event activity and open a record to inspect its impact and current state.", "operations / history", "events", height=1552, show_status=False)
    c.button(1384, 106, 178, "Export filtered")
    c.txt(24, 214, "History received by demo-control-a", "body")
    c.txt(1562, 214, EVENT_AS_OF.strftime("As of %Y-%m-%d %H:%M UTC"), "small muted", "end")
    c.add('<g data-ui="event-filters" data-window-hours="72" data-bucket-minutes="10">')
    search_control(c, 24, 246, 336, "Search events, devices or objects", height=42)
    for x, width, label in ((376, 190, "All event types"), (582, 190, "All sources"), (788, 170, "All objects"),
                            (974, 180, "Last 72 hours"), (1170, 166, "10 min buckets")):
        flow_input(c, x, 246, width, label, dropdown=True)
    c.button(1352, 246, 116, "Apply filters", True, height=42)
    c.button(1484, 246, 78, "Clear", height=42)
    c.add('</g>')
    event_volume_chart(c, records, EVENT_AS_OF)
    c.add(f'<g data-ui="event-feed" data-scroll="page" data-loaded="{len(latest)}" data-total="{len(records)}">')
    c.card(24, 650, 1538, 880, "Local history", "newest receipt first · no global order")
    for x, label in ((47, "RECEIVED UTC"), (268, "EVENT / SOURCE"), (1130, "RESULT AT RECEIPT")):
        c.txt(x, 730, label, "eyebrow muted")
    c.line(24, 745, 1562, 745, kind="table-rule")
    top = 745
    for i, record in enumerate(latest):
        subject, source, effect, detail, tone = record["display"]
        stamp = record["received"].strftime("%H:%M:%S")
        c.add(f'<g data-ui="event-row" data-event="{record["id"]}" data-kind="{record["kind"]}" data-received="{record["received"].isoformat()}">')
        if i == 3:
            c.rect(25, top, 1536, 88, "#FFF8EC", "none", 0)
            c.rect(25, top, 3, 88, "#D2A45B", "none", 0)
        c.txt(47, top + 35, stamp, "body mono")
        c.txt(47, top + 60, record["received"].strftime("%Y-%m-%d"), "small muted")
        c.circle(249, top + 29, 4, colors[record["kind"]])
        c.txt(268, top + 34, subject, "body")
        c.txt(268, top + 60, source, "small muted")
        c.txt(1130, top + 34, effect, "body " + tone)
        c.txt(1130, top + 60, detail, "small muted")
        c.txt(1538, top + 34, "⌃" if i == 3 else "›", "body muted", "end")
        top += 88
        c.line(24, top, 1562, top, kind="table-rule")
        if i == 3:
            c.add('<g data-ui="event-detail">')
            c.rect(25, top, 1536, 148, "#FFFCF6", "none", 0)
            c.txt(66, top + 32, "What happened at 10:24:46", "body amber")
            c.txt(66, top + 62, "Two incompatible changes paused demo-work. The service had no active destinations or eligible routes.", "body")
            c.txt(66, top + 90, "This is the result recorded at receipt. Open current state to inspect the conflicting facts and resolve the target.", "small muted")
            c.add('<a href="09-administration-configuration.svg#compare" data-ui="configuration-conflict-link">')
            c.txt(66, top + 124, "Inspect current conflict →", "body green")
            c.add('</a>')
            c.txt(1518, top + 124, "Hide details ⌃", "small green", "end")
            c.add('</g>')
            top += 148
            c.line(24, top, 1562, top, kind="table-rule")
        c.add('</g>')
    c.txt(47, top + 32, "History records verified changes and authenticated reports. An earlier result does not establish current device or service state.", "small muted")
    c.line(24, top + 53, 1562, top + 53, kind="table-rule")
    c.txt(47, top + 84, f"{len(latest)} of {len(records):,} events loaded", "small muted")
    c.add('<g data-ui="event-load-more" data-trigger="scroll" data-state="loading" role="status" aria-live="polite">')
    c.circle(1320, top + 79, 7, "none", "#D8E0DA")
    c.add(f'<path d="M1320 {top+72}a7 7 0 0 1 7 7" fill="none" stroke="#248F64" stroke-width="2" stroke-linecap="round"/>')
    c.txt(1337, top + 84, "Loading earlier events…", "small muted")
    c.add('</g></g>')
    return c


def add_device(method: str = "ssh") -> Canvas:
    scene = JOIN_SCENES[method]
    name = "add-device" if method == "ssh" else "add-device-" + method
    roles, policy_ids = scene["roles"], scene["policies"]
    action = {"ssh": "Install via SSH", "script": "Generate install script", "qr": "Generate QR code"}[method]
    pure_access = set(roles) == {"access"}
    allowed_methods = ("qr",) if pure_access else ("ssh", "script")
    if method not in allowed_methods:
        raise ValueError("delivery must follow the selected roles")

    left, right, width = 353, 1233, 880
    service_y = {"ssh": 638, "script": 514, "qr": 492}[method]
    c = Canvas(name, "Add device", "Choose roles, then set up how the device joins.", "devices / add", "nodes", content_x=left)
    c.role = "group"
    c.add(f'<g data-ui="join-draft" data-name="{scene["name"]}" data-method="{method}">')

    def input_box(x: int, y: int, w: int, value: str, *, dropdown: bool = False) -> None:
        c.add('<g data-ui="input">')
        c.rect(x, y, w, 42, "#FFFFFF", "#D8E0DA", 5)
        c.txt(x + 14, y + 27, value, "body")
        if dropdown:
            c.icon("icon-chevron", x + w - 29, y + 13)
        c.add('</g>')

    c.txt(left, 218, "Device name", "body")
    c.txt(right, 218, "Unsaved · no invitation issued", "small muted", "end")
    input_box(left, 230, width, scene["name"])
    c.txt(left, 310, "Roles", "body")
    c.txt(right, 310, "Select one or more", "small muted", "end")
    for index, role in enumerate(("access", "forward", "internet_egress", "control")):
        x = left + index * 220
        selected = role in roles
        c.add(f'<g data-ui="role-choice" data-role="{role}" aria-checked="{str(selected).lower()}" aria-disabled="false">')
        c.rect(x, 328, 18, 18, "#248F64" if selected else "#FFFFFF", "#248F64" if selected else "#BCC8C0", 3)
        if selected:
            c.txt(x + 9, 342, "✓", "small white", "middle")
        c.txt(x + 29, 342, role, "body")
        c.add('</g>')

    c.txt(left, 388, "Add using", "body")
    if pure_access:
        c.add('<g data-ui="delivery-choice" data-method="qr" aria-checked="true">')
        c.icon("icon-qr", left, 407, 20)
        c.txt(left + 31, 423, "QR invitation", "body")
        c.txt(left, 451, "Generate an invitation to scan or import in Loom.", "small muted")
        c.add('</g>')
    else:
        c.rect(left, 404, 320, 40, "#EFF3F0", "none", 6)
        for index, key in enumerate(allowed_methods):
            x = left + index * 160
            selected = key == method
            c.add(f'<g data-ui="delivery-choice" data-method="{key}" aria-checked="{str(selected).lower()}">')
            if selected:
                c.rect(x + 3, 407, 154, 34, "#FFFFFF", "#CFDBD3", 4)
            c.icon("icon-terminal" if key == "ssh" else "icon-code", x + 30, 416, 16, "nav-active" if selected else "nav-icon")
            c.txt(x + 58, 429, "SSH" if key == "ssh" else "sh script", "body" if selected else "body muted")
            c.add('</g>')
        c.txt(left, 470, "Connect to the target and install Loom." if method == "ssh" else "Generate a script to run on the target device.", "small muted")
    if method == "ssh":
        c.txt(left, 514, "SSH target", "body")
        input_box(left, 526, 702, "demo-new-host", dropdown=True)
        c.add('<g data-ui="check-target">')
        c.rect(right - 162, 526, 162, 42, "#FFFFFF", "#D8E0DA", 5)
        c.txt(right - 81, 553, "Check target", "body", "middle")
        c.add('</g>')
        c.circle(left + 7, 591, 6, "#248F64")
        c.txt(left + 7, 595, "✓", "micro white", "middle")
        c.txt(left + 24, 596, "Linux / amd64 · Roles supported · No existing Loom identity found", "small green")

    settings_y = service_y
    if "access" in roles:
        end = policy_picker(c, service_y, policy_ids, device=scene["device"])
        settings_y = end + 32

    c.line(left, settings_y, right, settings_y)
    c.add('<g data-ui="invitation-settings" aria-expanded="false">')
    c.txt(left, settings_y + 32, "›", "section muted")
    c.txt(left + 25, settings_y + 31, "Invitation settings", "body")
    c.txt(right, settings_y + 31, "24 hours · demo-control-a", "small muted", "end")
    c.add('</g>')
    c.line(left, settings_y + 71, right, settings_y + 71)
    c.add('<g data-ui="form-actions">')
    count = len(policy_ids)
    scope = (f"{count} {'policy' if count == 1 else 'policies'} · {count} {'service' if count == 1 else 'services'}"
             if count else "No access policies")
    c.txt(left, settings_y + 119, f"{len(roles)} role" + ("s" if len(roles) != 1 else "") + " · " + scope, "small muted")
    c.txt(right - 245, settings_y + 119, "Cancel", "body muted", "end")
    c.add(f'<a href="{JOIN_FILES[method]}" data-ui="submit-add" data-submit-scope="policy-ids" data-next-route="/devices/invites/{scene["invite"]}" aria-label="{action}">')
    c.rect(right - 218, settings_y + 93, 218, 42, "#248F64", "#248F64", 6)
    c.txt(right - 109, settings_y + 120, action, "body white", "middle")
    c.add('</a></g></g>')
    c.fit_height(settings_y + 175)
    return c


def release_platform(platform: str) -> Canvas:
    title = platform.title()
    examples = RELEASE_FILES[platform]
    c = Canvas(f"releases-{platform}", f"{title} releases", "Download installation files and check the software reported by your devices.", "releases", f"releases-{platform}", height=1150 if platform != "windows" else 1060, show_status=False)
    release_tabs(c, title)
    release_catalog_context(c, len(examples))
    c.card(24, 334, 1538, 498, f"{title} files", "Download a file or open its details")
    for x, label in ((47, "FILE / VERSION / DIGEST"), (770, "AUDIENCE / DISTRIBUTION"), (1180, "VERIFICATION"), (1374, "DOWNLOAD")):
        c.txt(x, 418, label, "eyebrow muted")
    c.line(24, 432, 1562, 432, kind="table-rule")
    top = 432
    for i, (component, version, digest, audience) in enumerate(examples):
        c.add(f'<g data-ui="release-file" data-component="{component}" aria-selected="{str(i == 0).lower()}">')
        if i == 0:
            c.rect(25, top, 1536, 80, "#EDF4FB", "none", 0)
            c.rect(25, top, 3, 80, "#4D78D1", "none", 0)
        c.txt(47, top + 31, component, "body mono")
        c.txt(47, top + 57, f"{version} · {title} · {digest}", "small mono muted")
        c.txt(690, top + 31, "Hide details ⌃" if i == 0 else "Details ⌄", "small green", "end")
        c.txt(770, top + 31, audience, "body")
        c.txt(770, top + 57, "Public distribution permitted" if audience == "Generic public" else "Authenticated distribution only", "small muted")
        c.circle(1184, top + 26, 4, "#2AA875")
        c.txt(1198, top + 31, "Verified file", "body green")
        c.txt(1180, top + 57, "Catalog signature + exact bytes", "small muted")
        download_label = {"demo-linux-agent": "Download package", "demo-android-apk": "Download APK",
                          "demo-windows-installer": "Download installer", "demo-windows-portable": "Download portable"}.get(component, "Download")
        c.add(f'<g data-ui="release-download" data-component="{component}" data-source="verified-release-file" data-auth-required="{str(audience != "Generic public").lower()}">')
        c.button(1374, top + 10, 164, download_label, True)
        c.add('</g>')
        c.add(f'<g data-ui="release-copy-link" data-component="{component}" data-source="verified-release-file" data-auth-required="{str(audience != "Generic public").lower()}">')
        c.txt(1456, top + 65, "Copy link", "small green", "middle")
        c.add('</g>')
        top += 80
        c.line(24, top, 1562, top, kind="table-rule")
        if i == 0:
            c.add('<g data-ui="release-file-detail">')
            c.rect(25, top, 1536, 118, "#F8FAFC", "none", 0)
            c.txt(66, top + 30, "FILE TRUST", "eyebrow muted")
            c.txt(770, top + 30, "MINIMUM COMPATIBLE VERSION", "eyebrow muted")
            c.txt(66, top + 60, "Publisher key pinned by protected installation", "body")
            c.txt(770, top + 60, "Not declared for this component", "body muted")
            c.txt(66, top + 91, "Immutable file · bytes match the signed digest above", "small muted")
            c.txt(770, top + 91, "No minimum-version conclusion is inferred from the file name.", "small muted")
            c.add('</g>')
            top += 118
            c.line(24, top, 1562, top, kind="table-rule")
        c.add('</g>')
    c.txt(47, 815, "Only files signed for public distribution have public links. Other downloads require authentication.", "small muted")

    c.card(24, 848, 1538, 278 if platform != "windows" else 188, "Device application", f"Selected file · {examples[0][0]} / {title}")
    if platform == "windows":
        c.add('<g data-ui="no-deployment-target">')
        c.icon("icon-node", 47, 929, 28)
        c.txt(95, 945, "No enrolled Windows target", "section")
        c.txt(95, 976, "Desired file: none · applied readback: unknown", "body muted")
        c.txt(95, 1006, "Enroll a device before there is a target to compare with this release.", "small muted")
        c.txt(1538, 945, "View devices →", "body green", "end")
        c.add('</g>')
        return c

    target = {"linux": "demo-forward-c", "android": "demo-phone-f"}[platform]
    matching = platform == "linux"
    c.txt(47, 939, "Device", "small muted")
    flow_input(c, 135, 912, 366, target, dropdown=True)
    c.txt(1538, 939, "View device versions →", "body green", "end")
    for x, label in ((47, "DESIRED FILE"), (564, "REPORTED APPLIED"), (1120, "COMPARISON")):
        c.txt(x, 989, label, "eyebrow muted")
    c.txt(47, 1022, examples[0][2], "section mono")
    c.txt(47, 1048, "Signed intent · selected component and platform", "small muted")
    c.txt(564, 1022, examples[0][2] if matching else "unknown", "section mono" if matching else "section amber")
    c.txt(564, 1048, "Fresh device report · scope matches" if matching else "No fresh report for this component and platform", "small muted")
    c.txt(1120, 1022, "Matching" if matching else "Unknown", "section green" if matching else "section amber")
    c.txt(1120, 1048, "Exact desired file is reported applied" if matching else "Application is not confirmed", "small muted")
    c.line(24, 1071, 1562, 1071, kind="panel-section")
    c.txt(47, 1103, "This result belongs to the selected device. Catalog verification alone does not confirm application.", "small muted")
    c.txt(1538, 1103, "View device →", "small green", "end")
    return c


def guest_entry() -> Canvas:
    c = Canvas("guest-entry", "Loom private control center", "This private site is reachable from an enrolled access device.", "private entry", "overview", height=760)
    c.parts.clear()
    compound, transform = logo_geometry()
    c.add('<rect width="1586" height="760" fill="#FCFDFC"/>')
    c.add('<rect width="1586" height="58" fill="#FFFFFF"/>')
    c.line(0, 57, 1586, 57)
    c.add(f'<svg x="18" y="8" width="39" height="39" viewBox="127 112 1000 1000"><g transform="{transform}"><path d="{compound}" fill="#252927" fill-rule="evenodd" clip-rule="evenodd"/></g></svg>')
    c.txt(65, 36, "LOOM", "section")
    c.txt(1546, 35, "PRIVATE SITE", "eyebrow muted", "end")
    c.icon("icon-lock", 353, 143, 32)
    c.txt(353, 224, "Private site reached", "title")
    c.txt(353, 257, "https://control.loom/", "body mono muted")
    c.txt(353, 302, "Install your admin certificate to open the control center.", "body")
    c.line(353, 337, 1233, 337)
    c.txt(353, 384, "1", "section muted")
    c.txt(392, 383, "Receive the admin package", "section")
    c.txt(392, 414, "Control creates admin.p12 and a separate password file.", "body muted")
    c.txt(392, 441, "Retrieve them through the protected operator channel.", "body muted")
    c.txt(353, 497, "2", "section muted")
    c.txt(392, 496, "Import the certificate into your browser", "section")
    c.txt(392, 528, "Select the admin certificate when prompted, then reload this private address.", "body muted")
    flow_actions(c, 580, "Reload with certificate", secondary="", primary_w=238)
    c.txt(353, 686, "Device lists and management data are available only after admin authentication.", "small muted")
    return c


def operations() -> Canvas:
    device = ACCESS_EDIT_DEVICE
    c = flow_canvas("operations", "Device access saved", "demo-forward-c · saved on control-a; device application is still unknown.", "devices / demo-forward-c / save result", height=1040)
    c.add(f'<g data-ui="access-result" data-device="{device}" data-policy="demo-direct-policy" data-state="accepted">')
    c.circle(360, 215, 6, "#248F64")
    c.txt(360, 219, "✓", "micro white", "middle")
    c.txt(378, 220, "Saved on control-a", "body green")
    c.txt(1233, 220, "Applied on device · unknown", "body amber", "end")
    c.line(353, 251, 1233, 251)
    c.txt(353, 287, "media · selected policy changed", "section")
    c.txt(353, 325, "Previous shared policy", "small muted")
    c.txt(845, 325, "Selected existing policy", "small muted")
    c.txt(353, 358, "demo-policy", "section mono")
    c.txt(845, 358, "demo-direct-policy", "section mono")
    c.add('<path d="M670 351H797" class="selected"/>')
    c.txt(353, 388, "Direct or routes through Loom", "small muted")
    c.txt(845, 388, "Direct only", "small muted")
    c.txt(353, 427, "Both policies keep their rules. Only relay-west's selection for media changed.", "small muted")
    c.line(353, 459, 1233, 459)
    c.txt(353, 494, "Save and application results", "section")
    for index, (key, label, detail, result, tone) in enumerate((
        ("policy", "Selected policy", "direct-access · already saved and reusable", "Existing", "muted"),
        ("authorization", "Device access", "relay-west selects direct-access · service media", "Saved", "green"),
        ("replication", "Other controls", "No confirmation of these changes yet", "Unknown", "amber"),
        ("configuration", "Device configuration", "No matching report of the saved configuration", "Unknown", "amber"),
        ("runtime", "Runtime", "No fresh runtime report for this configuration", "Unknown", "amber"),
        ("business", "media availability", "No business result for this policy selection", "Unknown", "amber"),
    )):
        y = 539 + index * 61
        c.add(f'<g data-ui="save-readback" data-field="{key}" data-result="{result.lower()}">')
        c.txt(353, y, label, "body")
        c.txt(619, y, detail, "small muted")
        c.txt(1233, y, result, "small " + tone, "end")
        c.line(353, y + 23, 1233, y + 23)
        c.add('</g>')
    c.txt(353, 910, "The policy selection is saved. Device and business reports must confirm their own results.", "small muted")
    c.add(f'<g data-ui="navigation" data-route="/devices/{device}">')
    flow_actions(c, 945, "Back to device", secondary="")
    c.add('</g></g>')
    return c


def policy_range(c: Canvas, y: int, label: str, field: str, *, mode: str = "any",
                 nodes: tuple[str, ...] = (), picker_options: tuple[tuple[str, str], ...] = ()) -> int:
    c.add(f'<g data-ui="policy-range" data-field="{field}" data-mode="{mode}" data-options="any only none">')
    c.txt(446, y + 25, label, "body")
    c.add(f'<g data-ui="policy-range-mode" role="radiogroup" aria-label="{escape(label)}">')
    for x, value, title in ((754, "any", "Unrestricted"), (934, "only", "Selected nodes"), (1138, "none", "None")):
        selected = mode == value
        c.add(f'<g role="radio" data-value="{value}" aria-checked="{str(selected).lower()}">')
        c.circle(x, y + 20, 8, "#FFFFFF", "#248F64" if selected else "#BCC8C0")
        if selected:
            c.circle(x, y + 20, 4, "#248F64")
        c.txt(x + 21, y + 25, title, "body green" if selected else "body")
        c.add('</g>')
    c.add('</g>')
    if mode == "only":
        top = y + 41
        c.add(f'<g data-ui="policy-node-picker" aria-expanded="{str(bool(picker_options)).lower()}">')
        top += tag_selector(c, 746, top, 768, tuple((node, node) for node in nodes), field=field, placeholder="Search nodes…")
        if picker_options:
            top += 6
            c.add(f'<g data-ui="policy-node-options" role="listbox" aria-label="{escape(label)}" aria-multiselectable="true" data-close-on-select="false">')
            c.rect(746, top, 768, 34 + len(picker_options) * 42, "#FFFFFF", "#D8E0DA", 5)
            c.txt(763, top + 22, "ELIGIBLE NODES", "eyebrow muted")
            c.txt(1496, top + 22, f"{len(nodes)} selected · select one or more", "small muted", "end")
            for index, (node, description) in enumerate(picker_options):
                row_y = top + 34 + index * 42
                selected = node in nodes
                c.add(f'<g data-ui="policy-node-option" role="option" data-value="{node}" aria-selected="{str(selected).lower()}">')
                if selected:
                    c.rect(750, row_y, 760, 40, "#F0F7F3", "none", 3)
                c.rect(764, row_y + 11, 17, 17, "#248F64" if selected else "#FFFFFF", "#248F64" if selected else "#BCC8C0", 3)
                if selected:
                    c.txt(773, row_y + 24, "✓", "small white", "middle")
                c.txt(793, row_y + 25, node, "body")
                c.txt(1496, row_y + 25, description, "small muted", "end")
                c.add('</g>')
            top += 34 + len(picker_options) * 42
            c.add('</g>')
        c.add('</g>')
        c.txt(746, top + 25, "Select at least one node. Selection order does not define a route.", "small muted")
        bottom = top + 25
    else:
        hint = "All current and future eligible nodes." if mode == "any" else (
            "No intermediate nodes; a one-hop path may still be allowed." if field == "forwarding-nodes"
            else "No managed paths." if field == "data-entries" else "No managed internet exits.")
        c.txt(746, y + 53, hint, "small muted")
        bottom = y + 53
    c.add('</g>')
    return bottom + 26


def policies(*, lan: bool = False, new: bool = False) -> Canvas:
    policy = "demo-private-access" if new else "demo-lan-policy" if lan else "demo-policy"
    service = "demo-private" if new else POLICY_FIXTURES[policy]["service"]
    c = Canvas("policies-new" if new else "policies-lan" if lan else "policies", "Access policies",
               "A policy defines access to one service. Assign the same policy to any devices that need these rules.",
               "network intent", "policies", height=1400, show_status=False)
    c.add('<g data-ui="navigation" data-route="/policies?new=1">')
    c.button(1382, 106, 180, "+ New policy", True)
    c.add('</g>')
    catalog_rail(c, 228, "Saved policies", "Search policy or service", (
        ("demo-policy", "demo-video · internet", "1 device · Direct or internet-exit"),
        ("demo-direct-policy", "demo-video · internet", "0 devices · Direct only"),
        ("demo-lan-policy", "demo-office · shared LAN", "0 devices · fixed gateway"),
    ), selected="new-draft" if new else policy)
    c.txt(24, 628, "One service can have several policies.", "small muted")
    c.txt(24, 655, "Each device chooses one per service.", "small muted")
    c.txt(24, 697, "Assign policies from device details →", "small green")
    left, right, width = 446, 1514, 1068
    c.add(f'<g data-ui="policy-editor" data-policy="{policy}" data-service="{service}" data-state="{"new-draft" if new else "shared-edit"}">')
    c.txt(left, 228, "New policy" if new else policy, "section" if new else "section mono")
    if new:
        c.txt(right, 228, "Unsaved · no device access granted", "small muted", "end")
    else:
        if lan:
            c.txt(820, 228, "Unsaved changes · entry nodes", "small amber")
        flow_link(c, right, 228, "Copy as new policy →", f"/policies?copy={policy}", anchor="end")
    c.txt(left, 273, "Service", "body")
    c.add(f'<g data-ui="policy-service" data-service="{service}" aria-readonly="{str(not new).lower()}">')
    if new:
        flow_input(c, 746, 249, 768, service, dropdown=True)
    else:
        c.txt(746, 273, service, "body mono")
        flow_link(c, right, 273, "View service →", f"/services/{service}", anchor="end")
    c.txt(left, 312, SERVICE_FIXTURES[service]["target"], "small mono muted")
    c.txt(right, 340, "Fixed after creation" if new else "Service cannot be changed", "small muted", "end")
    c.add('</g>')
    c.txt(left, 375, "Policy name", "body")
    flow_input(c, left, 390, width, "Private access" if new else "Office LAN access" if lan else "Media access")
    c.line(left, 459, right, 459)
    c.txt(left, 496, "Access to this service", "section")
    c.add('<g data-ui="policy-effect" data-value="allow" role="radiogroup">')
    for x, label, value in ((830, "Allow", "allow"), (965, "Deny", "deny")):
        c.add(f'<g role="radio" data-value="{value}" aria-checked="{str(value == "allow").lower()}">')
        c.circle(x, 490, 8, "#FFFFFF", "#248F64" if value == "allow" else "#BCC8C0")
        if value == "allow":
            c.circle(x, 490, 4, "#248F64")
        c.txt(x + 22, 496, label, "body")
        c.add('</g>')
    c.add('</g>')
    c.txt(left, 528, "Deny keeps the policy assigned but blocks access to this service.", "small muted")
    if lan:
        c.add('<g data-ui="fixed-lan-gateway" data-node="demo-forward-c" aria-readonly="true">')
        c.txt(left, 579, "Destination gateway", "body")
        c.txt(746, 579, "demo-forward-c · fixed by office-network", "body mono")
        c.add('</g>')
        y = 614
    else:
        c.add('<g data-ui="allow-direct" aria-checked="true">')
        c.rect(left, 561, 18, 18, "#248F64", "#248F64", 3)
        c.txt(left + 9, 575, "✓", "small white", "middle")
        c.txt(left + 29, 575, "Allow Direct · device connects to the destination itself", "body")
        c.add('</g>')
        c.txt(left, 606, "To require a managed internet exit, turn off Direct.", "small muted")
        y = 635
    y = policy_range(c, y, "Entry nodes · first hop", "data-entries", mode="only" if lan else "any",
                     nodes=("demo-control-a",) if lan else (),
                     picker_options=(("demo-control-a", "control + forward"),
                                     ("demo-egress-e", "internet_egress")) if lan else ())
    if not lan:
        y = policy_range(c, y, "Internet exits · final hop", "internet-exits", mode="any" if new else "only",
                         nodes=() if new else ("demo-egress-e",))
    y = policy_range(c, y, "Intermediate forwarding nodes", "forwarding-nodes")
    c.txt(left, y + 2, "No entry nodes = no LAN path. No transit nodes may still allow one hop to the gateway." if lan else
          "No entry nodes = no managed path. No transit nodes may still allow one hop. Direct is separate.", "small muted")
    if not lan:
        c.add('<g data-ui="advanced-policy-rules" aria-expanded="false">')
        c.txt(left, y + 45, "› Device-limited local egress", "body")
        c.txt(right, y + 45, "None · no eligible hybrid exit", "small muted", "end")
        c.add('</g>')
        y += 75
    else:
        y += 33
    c.line(left, y, right, y)
    c.txt(left, y + 36, "Allowed access · draft" if lan else "Allowed access", "section")
    if lan:
        c.txt(left, y + 71, "Entry: control-a · Transit: unrestricted · LAN gateway: relay-west", "body mono")
        c.txt(left, y + 101, "The device chooses a permitted path to 198.51.100.0/24. The LAN gateway stays fixed.", "small muted")
    elif new:
        c.txt(left, y + 71, "Direct, or any eligible entry → transit → internet exit → private.example", "body mono")
        c.txt(left, y + 101, "No path restrictions set. This policy grants access only after a device selects it.", "small muted")
    else:
        c.txt(left, y + 71, "Direct, or eligible entry / transit nodes → internet-exit → media.example", "body mono")
        c.txt(left, y + 101, "Direct and one hop through internet-exit are allowed. Actual availability is shown in Live paths.", "small muted")
    y += 130
    c.line(left, y, right, y)
    if new:
        c.txt(left, y + 35, "After saving", "body")
        c.txt(left, y + 66, "Select this policy when adding a device or editing its access. Creating it assigns no devices.", "small muted")
        flow_actions(c, y + 98, "Create policy", x=left, w=width, meta="New policy · private-app")
        bottom = y + 190
    else:
        c.add(f'<g data-ui="policy-assignments" data-policy="{policy}">')
        c.txt(left, y + 35, "Used by", "section")
        c.txt(right, y + 35, "0 devices · 0 active invitations" if lan else "1 device · 0 active invitations", "small muted", "end")
        if lan:
            c.txt(left, y + 71, "No devices assigned. Select office-lan from a device's access policies.", "body muted")
        else:
            c.add('<g data-ui="policy-assignment" data-device="demo-phone-f" data-policy="demo-policy" data-service="demo-video">')
            flow_link(c, left, y + 71, "android-phone →", "/devices/demo-phone-f")
            c.txt(746, y + 71, "Android · access · media", "body")
            c.add('</g>')
        c.txt(left, y + 106, "Saving updates every reference. To change one device, assign another policy or save a copy.", "small muted")
        c.add('</g>')
        flow_actions(c, y + 133, "Save shared policy", x=left, w=width, secondary="Discard", meta="Changes this policy's rules")
        c.txt(left, y + 241, "Delete policy", "body red")
        c.txt(left + 152, y + 241, "Removes its access. Devices do not switch to another policy automatically.", "small muted")
        bottom = y + 279
    c.add('</g>')
    c.line(396, 208, 396, bottom - 20)
    c.fit_height(bottom)
    return c


def device_access_edit() -> Canvas:
    device = ACCESS_EDIT_DEVICE
    c = flow_canvas("device-access-edit", "Edit access policies", "demo-forward-c · choose the policies this device uses.", "devices / demo-forward-c / access", height=936)
    c.add(f'<g data-ui="access-edit" data-device="{device}" data-state="draft" data-source-policy="demo-policy" data-policy="demo-direct-policy">')
    c.txt(353, 218, "Linux / amd64 · access + forward", "small muted")
    c.txt(1233, 218, "Unsaved changes", "small amber", "end")
    end = policy_picker(c, 270, ("demo-direct-policy",), device=device)
    c.line(353, end + 20, 1233, end + 20)
    c.txt(353, end + 56, "Change for media", "section")
    c.txt(353, end + 93, "media-access → direct-access", "body mono")
    c.txt(353, end + 124, "Replaces the selected policy for this service. Both shared policies keep their existing rules.", "small muted")
    c.add(f'<g data-ui="submit-access" data-device="{device}" data-submit-scope="policy-ids" data-next-route="/devices/{device}/access/result">')
    flow_actions(c, end + 163, "Save device access", meta="1 policy · 1 service")
    c.add('</g></g>')
    c.fit_height(end + 257)
    return c


def device_detail_frame(device: str, name: str, subtitle: str, sections: tuple, *, context: str = "", joined: bool = True) -> Canvas:
    prefix = "detail-" + (context + "-" if context else "")
    target_class = "join-detail-target" if context else "detail-target"
    target_selector = "." + target_class + ("-" + context if context else "")
    scope = f"#detail-context-{context} " if context else ""
    c = Canvas("device-detail", name, subtitle, "devices / detail", "nodes",
               height=1040, show_status=False)
    c.role = "group"
    # Same-file fragment links switch presentation only; no script or new state.
    css = [
        f"{scope}.detail-panel {{ display:none; }} #{prefix}panel-overview {{ display:inline; }}",
        ".detail-nav { cursor:pointer; text-decoration:none; }",
        ".detail-nav-bg, .detail-nav-mark { fill:transparent; }",
        ".detail-nav-label { font-weight:400; }",
        f"#{prefix}nav-overview .detail-nav-bg {{ fill:#EDF4FB; }}",
        f"#{prefix}nav-overview .detail-nav-mark {{ fill:#4D78D1; }}",
        f"#{prefix}nav-overview .detail-nav-label {{ font-weight:600; }}",
        f"svg:has({target_selector}:target) #{prefix}panel-overview {{ display:none; }}",
        f"svg:has({target_selector}:target) #{prefix}nav-overview .detail-nav-bg, svg:has({target_selector}:target) #{prefix}nav-overview .detail-nav-mark {{ fill:transparent; }}",
        f"svg:has({target_selector}:target) #{prefix}nav-overview .detail-nav-label {{ font-weight:400; }}",
        ".detail-nav:hover .detail-nav-bg { stroke:#B7CABC; }",
        ".detail-nav:focus-visible { outline:none; }",
        ".detail-nav:focus-visible .detail-nav-bg { stroke:#248F64; stroke-width:2; }",
    ]
    for key, _, _ in sections:
        css.extend((
            f"svg:has(#{prefix}{key}:target) #{prefix}panel-{key} {{ display:inline; }}",
            f"svg:has(#{prefix}{key}:target) #{prefix}nav-{key} .detail-nav-bg {{ fill:#EDF4FB; }}",
            f"svg:has(#{prefix}{key}:target) #{prefix}nav-{key} .detail-nav-mark {{ fill:#4D78D1; }}",
            f"svg:has(#{prefix}{key}:target) #{prefix}nav-{key} .detail-nav-label {{ font-weight:600; }}",
        ))
    c.add('<style><![CDATA[' + "\n".join(css) + ']]></style>')
    for key, _, _ in sections:
        classes = target_class + (" " + target_class + "-" + context if context else "")
        c.add(f'<g id="{prefix}{key}" class="{classes}"/>')
    c.add(f'<g data-ui="device-detail" data-device="{device}" data-route="/devices/{device}">')
    c.txt(24, 228, "Device sections", "section")
    c.add('<g data-ui="device-section-navigation" role="navigation" aria-label="Device sections">')
    for index, (key, label, description) in enumerate(sections):
        y = 254 + index * 94
        c.add(f'<a id="{prefix}nav-{key}" class="detail-nav" href="#{prefix}{key}" data-ui="device-section-link" data-section="{key}" aria-label="{escape(label)}" aria-controls="{prefix}panel-{key}">')
        c.add(f'<rect class="detail-nav-bg" x="24" y="{y}" width="336" height="80" rx="4" stroke="none"/>')
        c.add(f'<rect class="detail-nav-mark" x="24" y="{y + 10}" width="3" height="60"/>')
        c.txt(42, y + 31, label, "body detail-nav-label")
        c.txt(42, y + 58, description, "small muted")
        c.txt(343, y + 31, "›", "body muted", "end")
        c.add('</a>')
    c.add('</g>')
    bottom = 254 + len(sections) * 94 + 28
    c.line(24, bottom, 360, bottom)
    if joined:
        flow_link(c, 24, bottom + 36, "View in topology →", f"/topology?device={device}")
    else:
        c.txt(24, bottom + 36, "Pending join · not authorized", "small muted")
    flow_link(c, 24, bottom + 71, "← All devices", "/devices", href="02-nodes.svg")
    c.line(396, 208, 396, 1008)
    return c


def current_device_detail() -> Canvas:
    device = ACCESS_EDIT_DEVICE
    sections = (
        ("overview", "Overview", "Status, configuration and RX / TX"),
        ("access", "Access policies", "1 policy · 1 service"),
        ("forwarding", "Forwarding & LAN", "1 resource · 1 link · 1 LAN service"),
        ("identity", "Identity & actions", "Joining, execution and permissions"),
    )
    c = device_detail_frame(device, device, "Linux · amd64 · access + forward", sections)
    left, right = 446, 1514

    def panel(key: str, label: str) -> None:
        c.add(f'<g id="detail-panel-{key}" class="detail-panel" data-ui="device-section" data-section="{key}" role="region" aria-label="{escape(label)}">')
        c.txt(left, 228, label, "section")

    panel("overview", "Overview")
    c.txt(right, 228, "Authorization saved on control-a", "small green", "end")
    for x, label, value, tone in ((left, "Authorization", "Effective", "green"),
                                  (806, "Configuration", "Unknown", "amber"),
                                  (1166, "Runtime", "Unknown", "amber")):
        c.txt(x, 278, label, "small muted")
        c.txt(x, 312, value, "metric " + tone)
    c.txt(left, 355, "Waiting for the device to report the saved configuration and its current runtime.", "small muted")
    flow_link(c, right, 355, "View runtime report →", f"/devices/{device}/runtime", anchor="end")
    c.line(left, 385, right, 385)
    c.txt(left, 429, "Interface traffic", "section")
    c.txt(right, 429, "Last 24 hours · observed counters", "small muted", "end")
    rx = traffic_series(device=device, direction="rx")
    tx = traffic_series(device=device)
    for x, label, value in ((left, "Observed RX", byte_size(traffic_total(rx))),
                            (806, "Observed TX", byte_size(traffic_total(tx))),
                            (1166, "Hours with deltas", "22 / 24")):
        c.txt(x, 474, label, "small muted")
        c.txt(x, 511, value, "metric")
    c.rect(left, 550, 8, 8, "#8CCCB0", "none", 2)
    c.txt(left + 16, 558, "RX", "tiny muted")
    c.rect(left + 60, 550, 8, 8, "#5D89C5", "none", 2)
    c.txt(left + 76, 558, "TX", "tiny muted")
    c.txt(right, 558, "Dashed columns · unknown", "tiny muted", "end")
    traffic_chart(c, left + 24, 604, 1044, 168, ((rx, "#8CCCB0"), (tx, "#5D89C5")))
    c.txt(left, 831, "Invalid counter intervals are excluded. Historical traffic does not confirm the current runtime.", "small muted")
    c.line(left, 865, right, 865)
    c.txt(left, 900, "Latest access change", "body")
    c.add('<a href="#detail-access" data-ui="detail-shortcut" aria-label="View access policies">')
    c.txt(right, 900, "View access policies →", "small green", "end")
    c.add('</a>')
    c.txt(left, 937, "media-access → direct-access · service media", "body mono")
    c.txt(left, 971, "Policy selection saved. Configuration and business results are still unknown.", "small muted")
    c.add('</g>')

    panel("access", "Access policies")
    c.add(f'<g data-ui="navigation" data-route="/devices/{device}/access">')
    c.button(1312, 204, 202, "Edit access policies", True)
    c.add('</g>')
    c.txt(left, 275, "These policies control this device's own access to their services.", "small muted")
    c.add('<g data-ui="service-access" data-role="access" data-policy="demo-direct-policy" data-service="demo-video">')
    for x, label in ((left, "POLICY"), (786, "SERVICE"), (1206, "BUSINESS")):
        c.txt(x, 326, label, "eyebrow muted")
    c.line(left, 345, right, 345, kind="table-rule")
    c.txt(left, 382, "demo-direct-policy", "body mono")
    c.txt(786, 382, "demo-video", "body mono")
    c.txt(1206, 382, "unknown", "body amber")
    c.txt(left, 414, "Direct only · existing shared policy", "small muted")
    c.txt(786, 414, "media.example + .cdn.media.example", "small mono muted")
    c.line(left, 442, right, 442, kind="table-rule")
    flow_link(c, left, 479, "Change policy →", f"/devices/{device}/access")
    flow_link(c, right, 479, "View shared policy →", "/policies/demo-direct-policy", anchor="end")
    c.txt(left, 517, "The device selection is saved on control-a. Shared policy rules have not changed.", "small muted")
    c.line(left, 552, right, 552)
    c.txt(left, 595, "Current media path", "section")
    c.txt(right, 595, "Preference · Auto", "small muted", "end")
    c.txt(left, 641, "Unknown · no current selected path", "body amber")
    c.txt(left, 675, "Awaiting path and business results for the current configuration.", "small muted")
    flow_link(c, left, 717, "View live paths →", f"/routing?device={device}&service=demo-video")
    c.line(left, 752, right, 752)
    flow_link(c, left, 794, "+ Assign another policy", f"/devices/{device}/access")
    c.txt(left, 829, "Choose at most one policy per service. Replacing a selection changes only this device.", "small muted")
    c.add('</g></g>')

    panel("forwarding", "Forwarding & LAN")
    c.txt(right, 228, "Role · forward", "small muted", "end")
    c.add('<g data-ui="forwarding" data-role="forward">')
    c.txt(left, 275, "Resources and relay links", "body")
    c.rows(left, 319, (205, 310, 400, 153), ("Type", "Resource / LinkID", "Evidence", "Result"), [
        ("WG resource", "demo-wg-forward-c", "Current transport action", "available"),
        ("Relay link", "demo-link-c-cb", "No report for new spec", "unknown"),
    ], 62, True)
    c.txt(left, 497, "Each resource and link has its own observation; service access is checked separately.", "small muted")
    c.line(left, 530, right, 530)
    c.txt(left, 575, "LAN services provided", "section")
    flow_link(c, right, 575, "+ Create LAN service", f"/devices/{device}/lan/new", anchor="end")
    c.txt(left, 624, "demo-office", "body mono")
    c.txt(right, 624, "Fixed gateway · this device", "small muted", "end")
    for x, label, value in ((left, "Reported local prefix", "192.0.2.0/24"),
                            (806, "Virtual prefix", "198.51.100.0/24"),
                            (1166, "Gateway node", device)):
        c.txt(x, 673, label, "small muted")
        c.txt(x, 708, value, "body mono")
    c.txt(left, 753, "Other devices select a policy for this LAN service to access the network behind this gateway.", "small muted")
    flow_link(c, left, 795, "Open office-network in Services →", "/services/demo-office")
    c.add('</g></g>')

    panel("identity", "Identity & actions")
    for y, label, value in ((282, "Device ID", device), (324, "Platform", "Linux · amd64")):
        c.txt(left, y, label, "small muted")
        c.txt(746, y, value, "body mono" if y == 282 else "body")
    c.txt(left, 367, "Roles", "small muted")
    c.add('<g data-ui="device-roles">')
    c.pill(746, 346, 99, "access", h=28)
    c.pill(857, 346, 105, "forward", h=28)
    c.add('</g>')
    flow_link(c, right, 367, "Edit roles →", f"/devices/{device}/roles", anchor="end")
    c.line(left, 402, right, 402)
    c.txt(left, 443, "Joining & execution", "section")
    flow_link(c, right, 443, "View history →", f"/devices/{device}/history", anchor="end")
    c.txt(left, 484, "Installation", "body")
    c.txt(746, 484, "Unknown · no retained execution result", "small muted")
    c.txt(left, 524, "Device identity", "body")
    c.txt(746, 524, "Bound · device key registered", "small green")
    c.txt(left, 564, "Joining", "body")
    c.txt(746, 564, "Completed · invitation consumed", "small green")
    c.txt(left, 601, "Current configuration and runtime are shown in Overview. Joining stays completed.", "small muted")
    c.line(left, 630, right, 630)
    c.txt(left, 671, "Revoke authorization", "section")
    c.txt(left, 707, "Remove this device's permissions while retaining its identity.", "small muted")
    c.add(f'<g data-ui="device-action" data-action="review-revocation" data-device="{device}">')
    c.txt(right, 671, "Review revocation →", "small red", "end")
    c.add('</g>')
    c.line(left, 738, right, 738)
    c.txt(left, 779, "Delete device identity", "section")
    c.txt(left, 815, "Remove the device and its authorization. This identity cannot join again.", "small muted")
    c.add(f'<g data-ui="device-action" data-action="review-deletion" data-device="{device}">')
    c.txt(right, 779, "Review deletion →", "small red", "end")
    c.add('</g>')
    c.txt(left, 849, "If the identity is lost, delete this node and use Add Device.", "small muted")
    c.add('</g></g>')
    return c


# Fixed snapshots, not a client-side join state machine. Links select a drawing.
JOIN_DETAIL_VIEWS = (
    ("qr-waiting", "qr", "open"),
    ("qr-joined", "qr", "completed"),
    ("script-waiting", "script", "open"),
    ("script-joined", "script", "completed"),
    ("ssh-joined", "ssh", "completed"),
    ("ssh-failed", "ssh", "open"),
    ("ssh-unconfirmed", "ssh", "open"),
    ("control-waiting", "control", "bound"),
    ("control-joined", "control", "completed"),
)


def join_device_detail(context: str, method: str, state: str) -> Canvas:
    scene = JOIN_SCENES[method]
    device, roles = scene["device"], scene["roles"]
    joined = state == "completed"
    bound = state != "open"
    platform = ("Android · arm64" if method == "qr" else "Linux · amd64") if bound or method == "ssh" else "Platform not identified"
    sections = [("overview", "Overview", "Joining, authorization and runtime")]
    if "access" in roles:
        count = len(scene["policies"])
        sections.append(("access", "Access policies", f"{count} selected · {'authorized' if joined else 'not active yet'}"))
    if "forward" in roles or "internet_egress" in roles:
        sections.append(("forwarding", "Forwarding & LAN", "Resources not reported" if joined else "Available after joining"))
    sections.append(("identity", "Identity & actions", "Joining, execution and recovery"))
    c = device_detail_frame(device, scene["name"], platform + " · " + " + ".join(roles), tuple(sections), context=context, joined=joined)
    join_scope(c, method, state)
    prefix = "detail-" + context + "-"
    left, right = 446, 1514
    runtime_failed = context == "script-joined"
    install_failed = context == "ssh-failed"
    join_label = "Joined" if joined else "Waiting for signatures" if method == "control" else "Waiting for device"
    install = ("Completed" if joined else "Failed" if install_failed else "Unknown") if method == "ssh" else "Not reported"
    runtime = "Failed" if runtime_failed else "Unknown"

    def panel(key: str, label: str) -> None:
        c.add(f'<g id="{prefix}panel-{key}" class="detail-panel" data-ui="device-section" data-section="{key}" role="region" aria-label="{escape(label)}">')
        c.txt(left, 228, label, "section")

    def local_link(y: int, label: str, section: str, *, x: int = left, anchor: str = "start") -> None:
        flow_link(c, x, y, label, f"/devices/{device}#{section}", href=f"#{prefix}{section}", anchor=anchor)

    def recovery(y: int) -> None:
        if method == "control" and not joined:
            c.add('<g data-ui="cancel-bound-control" data-effect="request-only">')
            c.button(left, y - 23, 212, "Request cancellation")
            c.add('</g>')
            c.txt(left, y + 37, "Cancellation also needs the current members' majority. The device ID stays reserved until confirmed.", "small muted")
            c.txt(left, y + 66, "If joining completes first, use Delete node to remove the node and all its roles.", "small muted")
        elif not joined:
            if method == "ssh":
                label, fragment = "Check target and continue →", "#ssh-failed" if install_failed else "#ssh-unconfirmed"
            else:
                label, fragment = ("Open QR code →" if method == "qr" else "Open install script →"), ""
            flow_link(c, left, y, label, f'/devices/invites/{scene["invite"]}', href=JOIN_FILES[method] + fragment)
            c.add('<g data-ui="cancel-open-invite" data-effect="cancel-invitation">')
            c.txt(right, y, "Cancel invitation", "small red", "end")
            c.add('</g>')
            c.txt(left, y + 36, "Same invitation and device ID · expires 2030-01-02 00:00 UTC · issued by control-a", "small muted")
            c.txt(left, y + 66, "You can close this page. The client completes joining independently." if method == "qr" else "Closing this page does not cancel the invitation or stop an installation already in progress.", "small muted")
        else:
            if method == "qr":
                flow_link(c, left, y, "Review re-adding →", f"/devices/{device}/rejoin")
            actions = ((1110, "member-removal", "Review member removal →"), (right, "deletion", "Review node deletion →")) if method == "control" else ((1110, "revocation", "Review revocation →"), (right, "deletion", "Review deletion →"))
            for x, action, label in actions:
                c.add(f'<g data-ui="device-action" data-action="review-{action}" data-device="{device}">')
                c.txt(x, y, label, "small red", "end")
                c.add('</g>')
            c.txt(left, y + 36, "Invitation consumed · it is no longer offered for another identity.", "small muted")
            c.txt(left, y + 66, "Member removal keeps other roles; node deletion removes them all. Both need a majority certificate." if method == "control" else "Reconnect with the existing identity. Re-adding is only for replacing a lost identity." if method == "qr" else "If the identity is lost, delete this node and use Add Device. Otherwise reconnect with the existing identity.", "small muted")

    panel("overview", "Overview")
    c.txt(right, 228, "Joined · authorization verified" if joined else "Pending join · no active authorization", "small green" if joined else "small muted", "end")
    for x, label, value, tone in ((left, "Joining", join_label, "green" if joined else "amber"),
                                  (806, "Authorization", "Effective" if joined else "Not granted", "green" if joined else "muted"),
                                  (1166, "Runtime", runtime, "red" if runtime_failed else "amber")):
        c.txt(x, 278, label, "small muted")
        c.txt(x, 312, value, "metric " + tone)
    captions = {
        "qr-waiting": "Scan the invitation in Loom on new-phone. No join request has reached control-a yet.",
        "script-waiting": "Run the generated script on new-relay. No join request has reached control-a yet.",
        "ssh-unconfirmed": "SSH disconnected before the execution result arrived. The installation may have continued.",
        "ssh-failed": "The SSH executor reported a full target disk. No installation or device claim completed.",
        "control-waiting": "The device key is bound. Both forward and control wait for the member certificate.",
        "qr-joined": "The client has joined. Configuration, runtime and service results have not been reported yet.",
        "script-joined": "Joining is complete. The latest device report says the configured runtime could not start.",
        "ssh-joined": "SSH installation and joining completed. The device has not reported its current runtime yet.",
        "control-joined": "The majority certificate is verified. The requested roles are active; runtime is still unknown.",
    }
    c.txt(left, 355, captions[context], "small muted")
    c.line(left, 385, right, 385)
    if method == "control" and not joined:
        c.txt(left, 429, "Member signatures", "section")
        c.txt(right, 429, "1 of 2 required", "body amber", "end")
        c.txt(left, 469, "Current members sign the same change automatically. No second administrator approval is needed.", "small muted")
        for y, member, result, tone in ((526, "demo-control-a", "Received", "green"), (590, "demo-control-b", "Pending", "amber")):
            c.txt(left, y, member, "body mono")
            c.txt(right, y, result, "body " + tone, "end")
            c.line(left, y + 24, right, y + 24)
        c.txt(left, 657, "No device configuration or temporary membership is granted while signatures are pending.", "small muted")
        local_link(704, "View joining & execution →", "identity")
        c.line(left, 743, right, 743)
        recovery(792)
    else:
        c.txt(left, 429, "Latest results" if joined else "This addition", "section")
        local_link(429, "View joining & execution →", "identity", x=right, anchor="end")
        if joined:
            facts = (("Joining", "Completed", "Member certificate verified" if method == "control" else "Device authorization verified", "green"),
                     ("Configuration", "Received" if runtime_failed else "Unknown", "Reported by this device" if runtime_failed else "No configuration receipt", "green" if runtime_failed else "amber"),
                     ("Runtime", runtime, "Device report · runtime process exited" if runtime_failed else "No current runtime report", "red" if runtime_failed else "amber"))
        else:
            facts = (("Installation" if method != "qr" else "Invitation", install if method != "qr" else "Ready to scan", "SSH executor · target disk is full" if install_failed else "No execution result received" if method != "qr" else "Issued for this device only", "red" if install_failed else "muted"),
                     ("Join request", "Not received", "Read back from control-a", "muted"),
                     ("Device key", "Not bound", "Device ID reserved by this invitation", "muted"))
        for index, (label, value, evidence, tone) in enumerate(facts):
            y = 482 + index * 68
            c.txt(left, y, label, "body")
            c.txt(730, y, value, "body " + tone)
            c.txt(right, y, evidence, "small muted", "end")
            c.line(left, y + 26, right, y + 26)
        if not joined:
            recovery(699)
        else:
            local_link(699, "Inspect the reported runtime failure →" if runtime_failed else "View this addition's record →", "identity")
            c.txt(left, 737, "Joining stays completed even when runtime fails or a report is missing.", "small muted")
        c.line(left, 810, right, 810)
        c.txt(left, 854, "Interface traffic", "section")
        c.txt(right, 854, "No samples", "body muted", "end")
        c.txt(left, 894, "No valid counter history has been received for this device. Missing samples are not zero traffic.", "small muted")
        c.txt(left, 929, "Service availability is measured separately after joining.", "small muted")
    c.add('</g>')

    if "access" in roles:
        panel("access", "Access policies")
        c.txt(right, 228, "Authorized selections" if joined else "Selected for joining · not active", "small green" if joined else "small muted", "end")
        c.txt(left, 276, "Services come from the selected policies. Shared rules are managed in Policies.", "small muted")
        for x, label in ((left, "POLICY"), (790, "SERVICE"), (1210, "ACCESS / BUSINESS")):
            c.txt(x, 323, label, "eyebrow muted")
        c.line(left, 343, right, 343)
        for index, policy in enumerate(scene["policies"]):
            fixture = POLICY_FIXTURES[policy]
            y = 383 + index * 96
            c.add(f'<g data-ui="service-access" data-policy="{policy}" data-service="{fixture["service"]}" aria-readonly="true">')
            c.txt(left, y, policy, "body mono")
            c.txt(790, y, fixture["service"], "body mono")
            c.txt(1210, y, "Allowed · business unknown" if joined else "Not authorized yet", "small amber" if joined else "small muted")
            c.txt(left, y + 29, fixture["summary"], "small muted")
            c.line(left, y + 54, right, y + 54)
            c.add('</g>')
        footer = 415 + len(scene["policies"]) * 96
        if joined:
            flow_link(c, left, footer, "Edit selected policies →", f"/devices/{device}/access")
            c.txt(left, footer + 39, "Replacing a selection changes only this device; editing a shared policy affects its other users.", "small muted")
        else:
            c.txt(left, footer, "The invitation fixes these selections. It does not grant active service access.", "small muted")
            c.txt(left, footer + 39, "Shared rule changes still apply. To change the selection, end this invitation before issuing another.", "small muted")
        c.add('</g>')

    if "forward" in roles or "internet_egress" in roles:
        panel("forwarding", "Forwarding & LAN")
        c.txt(right, 228, "Authorized · observations pending" if joined else "Requested roles · not active", "small green" if joined else "small muted", "end")
        c.txt(left, 291, "Resources and relay links", "section")
        c.txt(left, 338, "Unknown · no current resource or link report" if joined else "Available after this device joins", "body amber" if joined else "body muted")
        c.txt(left, 378, "Authorization does not prove that a listener, transport or relay path is available.", "small muted")
        c.line(left, 416, right, 416)
        c.txt(left, 463, "LAN services provided", "section")
        c.txt(left, 508, "No LAN service assigned to this gateway", "body muted")
        c.txt(left, 548, "Forwarding or internet egress does not automatically share a local network.", "small muted")
        if joined:
            c.txt(left, 599, "Create a LAN service after the device has reported an eligible local prefix.", "small muted")
        c.add('</g>')

    panel("identity", "Identity & actions")
    for y, label, value in ((279, "Device ID" if bound else "Reserved device ID", device),
                            (317, "Roles" if joined else "Requested roles", " + ".join(roles)),
                            (355, "Platform", platform), (393, "Invitation", scene["invite"]),
                            (431, "Added using", ("sh script" if method == "control" else "QR code" if method == "qr" else "sh script" if method == "script" else "SSH · target new-host") + " · issued by control-a")):
        c.txt(left, y, label, "small muted")
        c.txt(748, y, value, "body mono" if y in (279, 393) else "body")
    c.line(left, 464, right, 464)
    c.txt(left, 507, "Joining & execution", "section")
    c.txt(right, 507, "This device · this invitation", "small muted", "end")
    install_evidence = ("SSH executor confirmed installation" if joined else "SSH executor: target disk is full" if install_failed else "SSH disconnected before the result arrived") if method == "ssh" else "No installer output was reported to control-a"
    first_entry = ("QR invitation", "Consumed" if joined else "Ready to scan", "Claimed by this device" if joined else "Open the invitation in Loom on the intended device", "green" if joined else "muted") if method == "qr" else ("Installation", install, install_evidence, "green" if method == "ssh" and joined else "red" if install_failed else "muted")
    entries = (first_entry,
               ("Device key", "Bound" if bound else "Not bound", "Key accepted by control-a" if bound else "No claim received; no device key registered", "green" if bound else "muted"),
               ("Joining", "Completed" if joined else "1 / 2 signatures" if method == "control" else "Pending", "Majority certificate verified" if joined and method == "control" else "Device authorization verified" if joined else "Both roles wait for the member certificate" if method == "control" else "Invitation issued; no active device authorization", "green" if joined else "amber"),
               ("Runtime", runtime, "Device report: configured runtime process exited" if runtime_failed else "No current runtime report", "red" if runtime_failed else "amber"))
    for index, (label, value, evidence, tone) in enumerate(entries):
        y = 550 + index * 65
        c.add(f'<g data-ui="join-result-row" data-fact="{label.lower().replace(" ", "-")}" data-state="{escape(value.lower())}">')
        c.txt(left, y, label, "body")
        c.txt(748, y, value, "body " + tone)
        c.txt(748, y + 24, evidence, "small muted")
        c.line(left, y + 42, right, y + 42)
        c.add('</g>')
    recovery(844)
    c.add('</g></g></g>')
    return c


def device_detail() -> Canvas:
    c = current_device_detail()
    parts = c.parts
    c.parts = ['<g id="detail-context-current" class="detail-context">', *parts, '</g>']
    css = [".detail-context { display:none; } #detail-context-current { display:inline; }",
           "svg:has(.join-detail-target:target) #detail-context-current { display:none; }"]
    for context, method, state in JOIN_DETAIL_VIEWS:
        view = join_device_detail(context, method, state)
        css.append(f"svg:has(.join-detail-target-{context}:target) #detail-context-{context} {{ display:inline; }}")
        c.add(f'<g id="detail-context-{context}" class="detail-context" data-scene="{context}">')
        c.parts.extend(view.parts)
        c.add('</g>')
    c.add('<style><![CDATA[' + "\n".join(css) + ']]></style>')
    return c


def device_rejoin() -> Canvas:
    c = flow_canvas("device-rejoin", "Re-add access device", "Replace the lost identity of demo-phone-f with a new access invitation.", "devices / demo-phone-f / re-add", height=1072)
    c.txt(353, 218, "Old identity · demo-phone-f", "body")
    c.txt(1233, 218, "Review · nothing changed yet", "small amber", "end")
    c.txt(353, 248, "If the device still has its identity, reconnect or resume its existing join.", "small muted")
    c.txt(353, 298, "New device name", "body")
    flow_input(c, 353, 310, 880, "Android phone")
    c.txt(353, 385, "Role", "small muted")
    c.txt(561, 385, "access only · QR invitation", "body")
    c.txt(353, 420, "New identity", "small muted")
    c.txt(561, 420, "New device ID on issue; new key on the device", "body")
    c.txt(353, 453, "The client identifies its platform when it claims the invitation.", "small muted")
    end = policy_picker(c, 508, ("demo-policy",), device="demo-phone-replacement")
    settings_y = end + 32
    c.line(353, settings_y, 1233, settings_y)
    c.add('<g data-ui="invitation-settings" aria-expanded="false">')
    c.txt(353, settings_y + 32, "›", "section muted")
    c.txt(378, settings_y + 31, "Invitation settings", "body")
    c.txt(1233, settings_y + 31, "24 hours · demo-control-a", "small muted", "end")
    c.add('</g>')
    c.line(353, settings_y + 68, 1233, settings_y + 68)
    c.icon("icon-lock", 353, settings_y + 97, 20)
    c.txt(385, settings_y + 114, "The old identity will be permanently deleted", "body red")
    c.txt(353, settings_y + 147, "Delete the old identity locally, then issue the reviewed invitation for a new device ID.", "small")
    c.txt(353, settings_y + 174, "If issue fails, the old identity stays deleted. Retry the same request to issue the replacement.", "small muted")
    c.txt(353, settings_y + 201, "Peer revocation is checked separately. The new device's authorization and runtime need readback.", "small muted")
    c.txt(353, settings_y + 228, "The new QR appears after deletion and issue succeed locally. Reusing a name cannot restore the old ID.", "small muted")
    c.add('<g data-ui="submit-rejoin" data-submit-scope="policy-ids">')
    flow_actions(c, settings_y + 270, "Delete old identity and issue QR", primary_w=310, destructive=True,
                 meta="1 policy · 1 service")
    c.add('</g>')
    c.fit_height(settings_y + 365)
    return c


def open_join_details(c: Canvas, method: str, context: str, y: int, *, secondary: str = "", primary: bool = True) -> None:
    scene = JOIN_SCENES[method]
    c.line(353, y, 1233, y)
    if secondary:
        c.add(f'<g data-ui="delivery-action" data-action="resume-existing" data-invite="{scene["invite"]}" data-device="{scene["device"]}">')
        c.button(353, y + 24, 254, secondary)
        c.add('</g>')
    else:
        c.txt(353, y + 47, "You can close this page and return from Devices.", "small muted")
    c.add(f'<a href="02-nodes-detail.svg#detail-{context}-overview" data-ui="open-device" data-route="/devices/{scene["device"]}" data-device="{scene["device"]}">')
    c.button(1015, y + 24, 218, "Open device details", primary)
    c.add('</a>')
    c.txt(353, y + 97, "Later joining and runtime results appear in this device's details.", "small muted")


def join_delivery(method: str = "qr") -> Canvas:
    scene = JOIN_SCENES[method]
    title = "Scan to add " + scene["name"] if method == "qr" else "Install " + scene["name"]
    subtitle = "Open Loom on the intended device, then scan or import this invitation." if method == "qr" else "Copy the install command and paste it into the target device's terminal."
    c = flow_canvas("add-" + method + "-delivery", title, subtitle,
                    "devices / add / " + ("QR code" if method == "qr" else "install command"), height=1040)
    c.role = "group"
    join_scope(c, method, "open")
    c.txt(353, 218, "QR code ready" if method == "qr" else "Install command ready", "body green")
    c.txt(1233, 218, "Expires 2030-01-02 00:00 UTC", "small muted", "end")
    if method == "qr":
        c.add('<g data-ui="invitation-qr" data-payload="illustration-only">')
        c.rect(353, 258, 256, 256, "#FFFFFF", "#D8E0DA", 8)
        c.icon("icon-qr", 425, 290, 112)
        c.txt(481, 453, "Scan in Loom", "section", "middle")
        c.txt(481, 483, "One device · one invitation", "small muted", "middle")
        c.add('</g>')
        for y, label, value in ((283, "Device ID", scene["device"]), (325, "Role", "access only"),
                                (367, "Platform", "Not identified yet"), (409, "Issued by", "demo-control-a")):
            c.txt(649, y, label, "small muted")
            c.txt(827, y, value, "body")
        c.add(f'<g data-ui="delivery-action" data-invite="{scene["invite"]}" data-action="download-existing">')
        c.button(649, 455, 219, "Download invitation file")
        c.add('</g>')
        c.txt(353, 555, "Reopening this unused invitation shows the same code. A claimed code cannot add another device.", "small muted")
        c.line(353, 588, 1233, 588)
        end = invited_policies(c, 626, method)
        c.txt(353, end + 13, "Waiting for the device", "body amber")
        c.txt(1233, end + 13, "No join request · not authorized", "small muted", "end")
        c.txt(353, end + 48, "The client completes joining asynchronously. You do not need to keep this page open.", "small muted")
        action_y = end + 84
    else:
        # Synthetic manifest digest and nonfunctional Invite, never release material.
        # The protected page fixes the verified digest before public download.
        installer_digest = "0123456789abcdef" * 4
        installer_url = f"https://download.example/{installer_digest}/demo-install.sh"
        command_lines = [
            "(",
            "  set -eu",
            "  umask 077",
            "  loom_install_dir=$(mktemp -d)",
            "  trap 'rm -rf -- \"$loom_install_dir\"' 0",
            "  trap 'exit 1' 1 2 15",
            "  curl --fail --silent --show-error --proto '=https' \\",
            f"    '{installer_url}' \\",
            '    -o "$loom_install_dir/installer.sh"',
            "  printf '%s  %s\\n' \\",
            f"    '{installer_digest}' \\",
            '    "$loom_install_dir/installer.sh" | sha256sum --check --status -',
            '  sh "$loom_install_dir/installer.sh" --invite-stdin <<\'LOOM_DEMO_INVITE\'',
            "demo-invite-payload",
            "LOOM_DEMO_INVITE",
            ")",
        ]
        command = "\n".join(command_lines) + "\n"
        # Character references preserve shell newlines through XML attribute parsing.
        command_attr = escape(command, {'"': '&quot;'}).replace("\n", "&#10;")
        c.txt(353, 258, "Roles · " + " + ".join(scene["roles"]), "body")
        c.txt(1233, 258, "Issued by control-a", "small muted", "end")
        c.line(353, 283, 1233, 283)
        c.txt(353, 326, "Install command", "section")
        c.add(f'<g data-ui="script-action" data-action="copy-command" data-invite="{scene["invite"]}" data-copy-value="{command_attr}">')
        c.button(1041, 302, 192, "Copy command", True)
        c.add('</g>')
        c.add(f'<g data-ui="script-command" data-invite="{scene["invite"]}" data-device="{scene["device"]}" data-installer-url="{installer_url}" data-installer-digest="{installer_digest}" data-digest-source="verified-release-manifest" data-payload="illustration-only" data-command="{command_attr}">')
        c.rect(353, 352, 880, 366, "#F3F6F4", "none", 6)
        for index, line in enumerate(command_lines):
            c.add(f'<text x="375" y="{378 + index * 21}" class="ui small mono" xml:space="preserve" data-ui="script-command-line">{escape(line)}</text>')
        c.add('</g>')
        c.txt(353, 750, "This command contains the invitation and may be saved in your terminal history.", "small amber")
        c.txt(353, 786, "Paste this block once in a root shell on " + scene["name"] + ". The installer digest is verified first.", "small muted")
        c.txt(353, 817, "The invitation is read from stdin; the installer checks the platform and existing identity before joining.", "small muted")
        c.line(353, 854, 1233, 854)
        c.txt(353, 896, "Waiting for the device", "body amber")
        c.txt(1233, 896, "No join request · not authorized", "small muted", "end")
        c.txt(353, 934, "Copying the command does not run it. Joining and runtime results appear in device details.", "small muted")
        action_y = 975
    open_join_details(c, method, method + "-waiting", action_y, primary=method != "script")
    c.add('</g>')
    c.fit_height(action_y + 136)
    return c


def ssh_result_view(result: str) -> Canvas:
    scene = JOIN_SCENES["ssh"]
    succeeded = result == "completed"
    failed = result == "failed"
    tone = "green" if succeeded else "red" if failed else "amber"
    status = "Installation completed" if succeeded else "Installation failed" if failed else "Installation not confirmed"
    c = flow_canvas("add-ssh-result", "SSH result · " + scene["name"],
                    "Review this execution, then follow the device's joining and runtime results in its details.",
                    "devices / add / SSH result", height=1016)
    c.role = "group"
    join_scope(c, "ssh", "completed" if succeeded else "open")
    c.add(f'<g data-ui="ssh-execution" data-result="{result}" data-retry="same-invitation">')
    c.txt(353, 218, status, "section " + tone)
    c.txt(1233, 218, "SSH executor · target new-host", "small muted", "end")
    c.txt(353, 253, "The executor confirmed installation. control-a separately confirmed the device's joining." if succeeded else "The executor reported a full target disk before installation. Free space, then check and continue." if failed else "The SSH connection closed before the result arrived. Completion is unknown; inspect the target first.", "small muted")
    c.txt(353, 294, "Device", "small muted")
    c.txt(353, 326, scene["name"] + " · " + " + ".join(scene["roles"]), "body")
    c.txt(821, 294, "Platform", "small muted")
    c.txt(821, 326, "Linux / amd64 · identified on target", "body")
    c.txt(353, 366, "Invitation · " + scene["invite"], "small mono muted")
    c.txt(1233, 366, "Consumed" if succeeded else "Expires 2030-01-02 00:00 UTC", "small muted", "end")
    c.line(353, 396, 1233, 396)
    c.txt(353, 436, "Execution and joining", "section")
    facts = (("Installation", "Completed" if succeeded else "Failed" if failed else "Unknown", "SSH executor confirmed completion" if succeeded else "SSH executor: target disk is full" if failed else "No execution result received", tone),
             ("Device key", "Bound" if succeeded else "Not bound", "Claim accepted by control-a" if succeeded else "No claim received by control-a", "green" if succeeded else "muted"),
             ("Joining", "Completed" if succeeded else "Pending", "Device authorization verified" if succeeded else "Invitation issued; no active device authorization", "green" if succeeded else "muted"),
             ("Runtime", "Unknown", "No current runtime report", "amber"))
    for index, (label, value, evidence, color) in enumerate(facts):
        y = 480 + index * 58
        c.txt(353, y, label, "body")
        c.txt(599, y, evidence, "small muted")
        c.txt(1233, y, value, "body " + color, "end")
        c.line(353, y + 24, 1233, y + 24)
    c.txt(353, 724, "Selected access policies", "section")
    c.txt(1233, 724, "Authorized" if succeeded else "Not active yet", "small green" if succeeded else "small muted", "end")
    for index, policy in enumerate(scene["policies"]):
        service = POLICY_FIXTURES[policy]["service"]
        c.add(f'<g data-ui="invited-policy" data-policy="{policy}" data-service="{service}" aria-readonly="true">')
        c.txt(353, 764 + index * 34, policy, "body mono")
        c.txt(821, 764 + index * 34, "Service · " + service, "small muted")
        c.add('</g>')
    c.txt(353, 837, "Installation, joining and runtime are separate results." if succeeded else "Continue this same invitation and device ID after checking the target; do not create another identity.", "small muted")
    context = "ssh-joined" if succeeded else "ssh-" + result
    open_join_details(c, "ssh", context, 871, secondary="" if succeeded else "Check target and continue")
    c.add('</g></g>')
    return c


def ssh_result() -> Canvas:
    c = ssh_result_view("completed")
    parts = c.parts
    c.parts = ['<g id="ssh-result-completed" class="ssh-result-scene">', *parts, '</g>']
    css = [".ssh-result-scene { display:none; } #ssh-result-completed { display:inline; }",
           "svg:has(.ssh-result-target:target) #ssh-result-completed { display:none; }"]
    for result in ("failed", "unconfirmed"):
        css.append(f"svg:has(#ssh-{result}:target) #ssh-result-{result} {{ display:inline; }}")
        c.add(f'<g id="ssh-{result}" class="ssh-result-target"/>')
        c.add(f'<g id="ssh-result-{result}" class="ssh-result-scene">')
        c.parts.extend(ssh_result_view(result).parts)
        c.add('</g>')
    c.add('<style><![CDATA[' + "\n".join(css) + ']]></style>')
    return c


ADMINISTRATION_SECTIONS = (
    ("controls", "Control nodes", "Membership and sync", "09-administration.svg", 984),
    ("administrators", "Administrators", "Browser access", "09-administration-administrators.svg", 1160),
    ("certificates", "Web certificates", "HTTPS identity", "09-administration-certificates.svg", 1192),
    ("configuration", "Configuration state", "Effective values and conflicts", "09-administration-configuration.svg", 1224),
)


def administration_action(c: Canvas, x: int, y: int, width: int, label: str, href: str, *, primary: bool = False, action: str = "") -> None:
    c.add(f'<a href="{escape(href)}" data-ui="administration-action" data-action="{escape(action or label)}">')
    if action == "revoke-exact-admin-leaf":
        c.add('<g data-ui="button">')
        c.rect(x, y, width, 42, "#B74E4E", "#B74E4E", 6)
        c.txt(x + width // 2, y + 25, label, "small white", "middle")
        c.add('</g>')
    else:
        c.button(x, y, width, label, primary, height=42)
    c.add('</a>')


def administration_link(c: Canvas, x: int, y: int, label: str, href: str, *, anchor: str = "start") -> None:
    c.add(f'<a href="{escape(href)}" data-ui="administration-link">')
    c.txt(x, y, label, "small green", anchor)
    c.add('</a>')


def administration_heading(c: Canvas, title: str, subtitle: str) -> None:
    c.txt(328, 231, title, "metric")
    c.txt(328, 260, subtitle, "small muted")


def administration_notice(c: Canvas, y: int, title: str, detail: str, *, tone: str = "amber") -> None:
    fill, accent = {"amber": ("#FFF8EC", "#D2A45B"), "green": ("#EFF8F2", "#31936B"), "red": ("#FCF2F1", "#B74E4E")}[tone]
    c.rect(328, y, 1210, 72, fill, "none", 0)
    c.rect(328, y, 3, 72, accent, "none", 0)
    c.txt(348, y + 27, title, "body " + tone)
    c.txt(348, y + 53, detail, "small")


def administration_page(section: str, states: tuple[str, ...], draw) -> Canvas:
    """Fixed review scenes, not an executable management workflow or store."""
    selected = next(item for item in ADMINISTRATION_SECTIONS if item[0] == section)
    c = Canvas("administration-" + section, "Administration",
               "Manage control nodes, administrator access, certificates and configuration.",
               "control / management", "administration", height=selected[4], show_status=False)
    c.role = "group"
    for index, (key, title, caption, filename, _) in enumerate(ADMINISTRATION_SECTIONS):
        y = 214 + index * 76
        c.add(f'<a href="{filename}" data-ui="administration-navigation" data-section="{key}" aria-current="{"page" if key == section else "false"}">')
        if key == section:
            c.rect(24, y, 252, 65, "#EDF5EF", "none", 4)
            c.rect(24, y + 10, 3, 45, "#248F64", "none", 0)
        else:
            c.rect(24, y, 252, 65, "transparent", "none", 4)
        c.txt(42, y + 27, title, "body" if key == section else "body muted")
        c.txt(42, y + 49, caption, "small muted")
        c.add('</a>')
    c.line(296, 214, 296, c.height - 24)
    c.line(42, 550, 258, 550)
    c.txt(42, 582, "CURRENT CONNECTION", "eyebrow muted")
    c.txt(42, 613, "demo-control-a", "body mono")
    c.txt(42, 638, "Local authenticated view", "small muted")
    c.txt(42, 683, "Other controls may have", "small muted")
    c.txt(42, 705, "received different changes.", "small muted")
    css = [".administration-scene { display:none; } #administration-overview { display:inline; }",
           "svg:has(.administration-target:target) #administration-overview { display:none; }", "a { cursor:pointer; }"]
    for state in states:
        c.add(f'<g id="{state}" class="administration-target"/>')
        c.add(f'<g id="administration-{state}" class="administration-scene" data-ui="administration-scene" data-scene="{state}">')
        draw(c, state)
        c.add('</g>')
        css.append(f"svg:has(#{state}:target) #administration-{state} {{ display:inline; }}")
    c.add('<style><![CDATA[' + "\n".join(css) + ']]></style>')
    return c


def administration_controls_draw(c: Canvas, state: str) -> None:
    administration_heading(c, "Control nodes", "Membership gives a node authority to accept configuration changes.")
    administration_action(c, 1378, 210, 160, "+ Add node", "02-nodes-add-ssh.svg")
    c.txt(328, 311, "2 current members", "section")
    c.txt(628, 311, "1 node joining", "body amber")
    c.txt(1538, 311, "Membership chain verified here", "small green", "end")
    c.line(328, 338, 1538, 338)
    for x, label in ((344, "CONTROL NODE"), (688, "MEMBERSHIP"), (1052, "CONFIGURATION RECEIVED")):
        c.txt(x, 372, label, "eyebrow muted")
    rows = (
        ("demo-control-a", "This connection", "Member", "Can sign ordinary changes", "Current local view", "Read directly from this control", "green"),
        ("demo-control-b", "Authenticated peer", "Member", "Qualification unchanged", "Unknown", "No fresh receipt evidence", "amber"),
    )
    c.line(328, 389, 1538, 389)
    for index, (node, note, membership, qualification, received, evidence, tone) in enumerate(rows):
        top = 389 + index * 90
        c.add(f'<g data-ui="control-member" data-control="{node}" data-membership="member">')
        if index == 1 and state == "sync":
            c.rect(328, top, 1210, 90, "#EEF4FA", "none", 0)
        for x, first, second, cls in ((344, node, note, "body mono"), (688, membership, qualification, "body"), (1052, received, evidence, "body " + tone)):
            c.txt(x, top + 33, first, cls)
            c.txt(x, top + 60, second, "small muted")
        administration_link(c, 1518, top + 36, "Details" if index == 1 else "Sources", "#sync", anchor="end")
        c.line(328, top + 90, 1538, top + 90)
        c.add('</g>')
    if state == "sync":
        c.txt(344, 608, "What this control has verified", "section")
        c.txt(344, 640, "Issuer", "small muted")
        c.txt(720, 640, "Known at control-a", "small muted")
        c.txt(1120, 640, "Received at control-b", "small muted")
        for y, issuer, sequence in ((678, "demo-control-a", "24"), (711, "demo-control-b", "18")):
            c.txt(344, y, issuer, "body mono")
            c.txt(720, y, sequence, "body mono")
            c.txt(1120, y, "Unknown · no fresh readback", "small amber")
        c.txt(344, 748, "Each issuer has its own sequence. 24 and 18 are not comparable versions.", "small muted")
        administration_link(c, 1518, 748, "Hide details", "#overview", anchor="end")
        top = 785
    else:
        c.txt(344, 613, "No fresh peer evidence does not mean that control-b has lost membership.", "small muted")
        top = 668
    c.line(328, top, 1538, top)
    c.txt(344, top + 37, "demo-control-c", "body mono")
    c.txt(688, top + 37, "Joining · not a member yet", "body amber")
    c.txt(1052, top + 37, "1 of 2 required signatures", "body")
    c.txt(344, top + 65, "Requested roles · forward + control", "small muted")
    c.txt(688, top + 65, "No requested roles are active yet", "small muted")
    c.txt(1052, top + 65, "Same membership proposal and round", "small muted")
    administration_link(c, 344, top + 102, "View joining details →", "02-nodes-detail.svg#detail-control-waiting-overview")
    c.line(328, top + 131, 1538, top + 131)
    c.txt(344, top + 164, "Membership changes need 2 signatures from the 2 current members. Ordinary changes do not.", "small muted")


def configuration_impact(c: Canvas, y: int) -> None:
    """Known local references in this conflict scene, not a global inventory."""
    c.add('<g data-ui="conflict-impact" data-service="demo-work" data-control="demo-control-a" data-scope="known-local-references">')
    c.txt(348, y, "Affected references known here", "body")
    c.txt(1518, y, "1 device · 1 unexpired invitation", "small muted", "end")
    c.txt(348, y + 31, "Policy · demo-work-access → demo-work", "small mono")
    c.txt(1518, y + 31, "As of 2030-01-01 00:00 UTC", "small muted", "end")
    c.add('<g data-ui="affected-device" data-device="demo-laptop" data-policy="demo-work-access">')
    c.txt(348, y + 65, "Device", "small muted")
    c.txt(552, y + 65, "demo-laptop · demo-work-access", "small mono")
    c.txt(1060, y + 65, "Service access paused by this conflict", "small amber")
    c.add('</g>')
    c.add('<g data-ui="affected-invite" data-invite="demo-work-phone-invite" data-device="demo-work-phone" data-policy="demo-work-access">')
    c.txt(348, y + 97, "Invitation", "small muted")
    c.txt(552, y + 97, "demo-work-phone-invite → demo-work-phone", "small mono")
    c.txt(1060, y + 97, "Open · claim paused by this conflict", "small amber")
    c.txt(552, y + 122, "access · not bound · expires 2030-01-02 00:00 UTC", "small muted")
    c.add('</g>')
    c.txt(348, y + 151, "Verified on control-a only. Other controls may hold additional references; their scope is unknown.", "small muted")
    c.add('</g>')


def administration_configuration_draw(c: Canvas, state: str) -> None:
    resolved = state in ("resolved-a", "resolved-b")
    choice_b = state in ("review-b", "resolved-b")
    administration_heading(c, "Configuration state", "See which configuration is effective here and resolve affected objects.")
    administration_link(c, 1538, 229, "View event history →", "08-events.svg", anchor="end")
    search_control(c, 328, 286, 492, "Find a service, policy or device", height=42)
    administration_action(c, 838, 286, 170, "All objects · 5", "#" + state if resolved else "#overview")
    if resolved:
        c.txt(1040, 312, "No conflicts here", "small green")
        c.txt(1538, 312, "Resolution · control-a · sequence 25", "small muted", "end")
    else:
        administration_action(c, 1024, 286, 170, "Conflicts · 1", "#compare")
        administration_link(c, 1538, 312, "Configuration sources", "#sources", anchor="end")
    if state == "sources":
        c.txt(328, 381, "Verified configuration sources", "section")
        c.txt(328, 412, "These are the independent issuer chains known by control-a.", "small muted")
        for x, label in ((328, "ISSUER"), (800, "VERIFIED THROUGH"), (1162, "LATEST LOCAL CHANGE AT PEER")):
            c.txt(x, 461, label, "eyebrow muted")
        for y, issuer, seq in ((508, "demo-control-a", "24"), (567, "demo-control-b", "18")):
            c.txt(328, y, issuer, "body mono")
            c.txt(800, y, "Sequence " + seq, "body mono")
            c.txt(1162, y, "Unknown · no current evidence", "small amber")
            c.line(328, y + 24, 1538, y + 24)
        c.txt(328, 636, "Sequence numbers from different issuers do not indicate which control is ahead.", "body")
        c.txt(328, 668, "Only redacted values and references are shown. Private keys and device credentials stay on controls.", "small muted")
        administration_action(c, 328, 710, 180, "Back to objects", "#overview")
        return
    for x, label in ((344, "OBJECT"), (692, "CURRENT RESULT"), (1024, "EFFECT / ACTION")):
        c.txt(x, 370, label, "eyebrow muted")
    c.line(328, 388, 1538, 388)
    c.add(f'<g data-ui="configuration-object" data-target="demo-work" data-result="{"effective" if resolved else "suspended"}">')
    c.rect(328, 388, 1210, 90, "#EFF8F2" if resolved else "#FFF8EC", "none", 0)
    c.txt(344, 423, "demo-work", "body mono")
    c.txt(344, 452, "Service · destination rules", "small muted")
    c.txt(692, 423, "Effective here" if resolved else "Suspended · conflicting changes", "body " + ("green" if resolved else "amber"))
    c.txt(692, 452, "Resolution accepted by control-a" if resolved else "Two changes need your review", "small muted")
    c.txt(1024, 423, "Authorized routes can be derived" if resolved else "No active destinations or routes", "body")
    c.txt(1024, 452, "Device application is checked separately" if resolved else "Other services are unaffected", "small muted")
    administration_link(c, 1518, 453, "View result" if resolved else "Resolve →", "#resolved-b" if choice_b else "#resolved-a" if resolved else "#compare", anchor="end")
    c.line(328, 478, 1538, 478)
    if resolved:
        administration_notice(c, 502, "Conflict resolved on control-a", "A new change references both conflicting changes. The original signed records remain intact.", tone="green")
        c.txt(348, 613, "Final destinations", "small muted")
        c.txt(648, 613, "work.example + .cdn.work.example" if choice_b else "work.example", "body mono")
        c.txt(348, 651, "Other controls", "small muted")
        c.txt(648, 651, "Unknown · no receipt evidence for this resolution", "body amber")
        c.txt(348, 689, "Device application", "small muted")
        c.txt(648, 689, "Unknown · waiting for a report using the updated view", "body amber")
        c.txt(348, 732, "Effective configuration does not establish that the service is reachable.", "small muted")
        end = 768
    elif state in ("compare", "review-a", "review-b", "changed"):
        c.txt(348, 519, "Choose the destinations this service should use", "section")
        c.txt(348, 548, "Review both changes. Neither the latest timestamp nor the higher sequence wins automatically.", "small muted")
        for x, title, source, targets, fact in (
            (348, "Change A", "demo-control-a · sequence 21", "work.example", "demo-work-update-a"),
            (958, "Change B", "demo-control-b · sequence 18", "work.example + .cdn.work.example", "demo-work-update-b"),
        ):
            c.txt(x, 590, title, "body")
            c.txt(x, 619, source, "small muted")
            c.txt(x, 660, targets, "body mono")
            c.txt(x, 692, "Service type · Internet", "small muted")
            c.txt(x, 721, "Reference · " + fact, "small mono muted")
        c.line(930, 570, 930, 738)
        administration_action(c, 348, 756, 250, "Use destinations from A", "#review-a", primary=state == "review-a")
        administration_action(c, 958, 756, 250, "Use destinations from B", "#review-b", primary=choice_b)
        if state == "changed":
            administration_notice(c, 824, "Configuration changed while you were reviewing", "Nothing was saved. Refresh all conflicting changes and review the final value again.", tone="red")
            administration_action(c, 348, 917, 220, "Refresh and review", "#compare", primary=True)
            end = 989
        elif state in ("review-a", "review-b"):
            configuration_impact(c, 831)
            c.txt(348, 1014, "Final destinations · editable draft", "small muted")
            c.add('<g data-ui="conflict-final-value" data-target="demo-work" data-references="demo-work-update-a demo-work-update-b">')
            flow_input(c, 348, 1027, 1170, "work.example, .cdn.work.example" if choice_b else "work.example")
            c.add('</g>')
            c.txt(348, 1094, "Both conflicting facts are included. A newer conflict requires another review.", "small muted")
            administration_action(c, 1288, 1113, 230, "Save resolution", "#resolved-b" if choice_b else "#resolved-a", primary=True, action="submit-conflict-resolution")
            administration_link(c, 348, 1140, "Cancel", "#compare")
            end = 1174
        else:
            configuration_impact(c, 831)
            c.txt(348, 1024, "Select a final value before submitting. The service stays suspended until a resolution is accepted.", "small muted")
            administration_link(c, 348, 1065, "Cancel review", "#overview")
            end = 1100
    else:
        c.txt(348, 519, "Two controls changed the same service independently.", "body")
        c.txt(348, 550, "Review the destination differences, choose a final value, then save a resolution.", "small muted")
        administration_action(c, 1288, 584, 230, "Compare changes", "#compare", primary=True)
        administration_link(c, 348, 611, "View signed sources", "#sources")
        end = 650
    c.add('</g>')
    if state in ("overview", "resolved-a", "resolved-b"):
        rows = (("demo-video", "Service · media.example", "Destination rules available"),
                ("demo-phone-f", "Device · selected policy media-access", "Policy assignment is effective here"),
                ("demo-link-wg", "NetworkLink · WG", "Explicit relay is configured"),
                ("demo-office", "LAN Service · gateway relay-west", "LAN mapping is configured"))
        for index, (target, detail, impact) in enumerate(rows):
            top = end + index * 82
            c.line(328, top, 1538, top)
            c.txt(344, top + 31, target, "body mono")
            c.txt(344, top + 57, detail, "small muted")
            c.txt(692, top + 31, "Effective here", "body green")
            c.txt(1024, top + 31, impact, "small")
        end += len(rows) * 82
    c.line(328, end, 1538, end)
    c.txt(348, end + 33, "Current state on control-a · historical changes remain in Events.", "small muted")


def administration_administrators_draw(c: Canvas, state: str) -> None:
    administration_heading(c, "Administrators", "Manage the browser certificates allowed to administer this network.")
    administration_action(c, 1338, 210, 200, "+ Add certificate", "#add", primary=True)
    adding = state in ("add", "invalid", "added")
    if adding:
        administration_link(c, 328, 311, "‹ All administrators", "#overview")
        c.txt(328, 362, "Add an issued administrator certificate", "section")
        c.txt(328, 394, "Import the public certificate and its chain. The private key and P12 stay with the administrator.", "small muted")
        if state == "added":
            administration_notice(c, 426, "demo-admin-new is trusted on control-a", "The exact certificate was added after chain validation. This does not confirm a successful browser login.", tone="green")
            for y, label, value, tone in (
                (540, "Certificate", "demo-admin-new · clientAuth", ""),
                (583, "Expires (UTC)", "2030-12-31 00:00", ""),
                (626, "control-a", "Trusted here · new leaf accepted", "green"),
                (669, "control-b", "Unknown · no receipt evidence", "amber"),
                (712, "Browser login and write", "Not verified with this certificate", "amber"),
            ):
                c.txt(348, y, label, "small muted")
                c.txt(710, y, value, "body " + tone)
            c.txt(348, 768, "Import the matching P12 on the admin device, then verify login, a management change and its readback.", "small muted")
            c.txt(348, 798, "For a planned replacement, keep the old identity until those checks succeed.", "small muted")
            administration_action(c, 348, 842, 230, "View replacement steps", "#replace")
            return
        c.txt(328, 443, "Public certificate and chain", "body")
        flow_input(c, 328, 460, 880, "demo-admin-new-chain.pem" if state == "add" else "demo-untrusted-admin-chain.pem")
        administration_action(c, 1224, 460, 314, "Choose another certificate", "#add")
        c.add('<g data-ui="admin-public-certificate" data-private-key="excluded" data-leaf="demo-admin-new">')
        for y, label, value in ((548, "Identity", "demo-admin-new"), (585, "Purpose", "clientAuth · administrator browser identity"),
                                (622, "Expires (UTC)", "2030-12-31 00:00"), (659, "Fingerprint", "demo-admin-new-fingerprint · SHA-256")):
            c.txt(328, y, label, "small muted")
            c.txt(710, y, value, "body mono" if label == "Identity" else "body")
        c.add('</g>')
        if state == "invalid":
            administration_notice(c, 699, "Certificate chain could not be verified", "No administrator access was granted. Supply a certificate issued by the configured administrator authority.", tone="red")
            administration_action(c, 328, 802, 258, "Choose a valid certificate", "#add", primary=True)
        else:
            administration_notice(c, 699, "Certificate checks passed · access has not been granted", "Chain, intended use and validity were checked against the configured administrator trust material.", tone="green")
            c.txt(328, 808, "Trust this exact certificate for full administration. Other controls apply the change after receiving it.", "body")
            administration_action(c, 1318, 846, 220, "Trust certificate", "#added", primary=True, action="trust-validated-admin-leaf")
            administration_link(c, 328, 873, "Cancel", "#overview")
        administration_link(c, 328, 945, "Need a new certificate package? View local issuance steps →", "#replace")
        return
    revoked = state == "revoked"
    c.txt(328, 312, "Browser identity is separate from website HTTPS identity.", "body")
    c.txt(1538, 312, "3 known certificate identities", "small muted", "end")
    for x, label in ((344, "ADMINISTRATOR"), (734, "EXPIRES (UTC)"), (1040, "ACCESS ON THIS CONTROL")):
        c.txt(x, 365, label, "eyebrow muted")
    c.line(328, 384, 1538, 384)
    rows = (
        ("demo-admin-primary", "Current browser identity", "2030-12-31 00:00", "Trusted", "green"),
        ("demo-admin-backup", "Additional administrator", "2030-06-30 00:00", "Revoked" if revoked else "Trusted", "red" if revoked else "green"),
        ("demo-admin-retired", "Previous certificate", "2029-12-31 00:00", "Revoked · expired", "muted"),
    )
    for index, (identity, note, expiry, status, tone) in enumerate(rows):
        top = 384 + index * 86
        c.add(f'<g data-ui="administrator" data-leaf="{identity}" data-access="{status.lower()}">')
        if index == 1:
            c.rect(328, top, 1210, 86, "#EEF4FA", "none", 0)
        c.txt(344, top + 32, identity, "body mono")
        c.txt(344, top + 59, note, "small muted")
        c.txt(734, top + 32, expiry, "body")
        c.txt(1040, top + 32, status, "body " + tone)
        if index == 1:
            administration_link(c, 1518, top + 34, "Details", "#revoked" if revoked else "#overview", anchor="end")
        c.line(328, top + 86, 1538, top + 86)
        c.add('</g>')
    if state == "replace":
        c.txt(348, 684, "Replace an administrator certificate", "section")
        c.txt(348, 716, "Generate a new identity on a control. This page never downloads a P12 or its password.", "small muted")
        steps = (
            (765, "1", "Generate on the control", "Use the protected local issuance command to create a new key, certificate and admin.p12."),
            (839, "2", "Retrieve and import", "Manually retrieve admin.p12 and its separate password file. Import them on the admin device."),
            (913, "3", "Trust and verify the new identity", "Add the issued public certificate; verify a real login, management write and readback."),
        )
        for y, number, title, detail in steps:
            c.txt(348, y, number, "body muted")
            c.txt(382, y, title, "body")
            c.txt(382, y + 27, detail, "small muted")
        c.txt(348, 990, "Then revoke the old certificate separately. If it is lost or compromised, revoke it without waiting for replacement.", "small muted")
        administration_action(c, 348, 1021, 240, "Add issued certificate", "#add", primary=True)
        administration_action(c, 610, 1021, 240, "Revoke old certificate", "#revoke")
        c.txt(348, 1102, "Package generation does not grant access. Deleting a package does not revoke a trusted certificate.", "small muted")
    elif state == "revoke":
        c.txt(348, 685, "Revoke demo-admin-backup?", "section")
        c.txt(348, 727, "Exact certificate · demo-admin-backup-fingerprint", "body mono")
        c.txt(348, 765, "After this control accepts the change, it rejects this certificate and closes its management connections.", "body")
        c.txt(348, 798, "Other controls enforce revocation after receiving the change. Their result must be checked separately.", "small muted")
        c.txt(348, 840, "You are signed in as demo-admin-primary. This action does not revoke your current certificate.", "small")
        administration_action(c, 1308, 883, 210, "Revoke certificate", "#revoked", primary=True, action="revoke-exact-admin-leaf")
        administration_link(c, 348, 910, "Cancel", "#overview")
    elif revoked:
        administration_notice(c, 666, "demo-admin-backup was revoked on control-a", "New requests are rejected here and existing management connections for this certificate are closed.", tone="green")
        for y, name, result, tone in ((786, "demo-control-a", "Revocation applied · connections closed", "green"),
                                     (835, "demo-control-b", "Unknown · no receipt evidence", "amber")):
            c.txt(348, y, name, "body mono")
            c.txt(822, y, result, "body " + tone)
            c.line(348, y + 22, 1518, y + 22)
        c.txt(348, 905, "The certificate may still be accepted by a control that has not received revocation.", "small muted")
        administration_action(c, 348, 943, 240, "Replacement instructions", "#replace")
    else:
        c.txt(348, 685, "demo-admin-backup", "section mono")
        c.txt(348, 724, "Trusted for full administration", "body")
        c.txt(348, 759, "Fingerprint · demo-admin-backup-fingerprint · SHA-256", "small mono muted")
        c.txt(348, 800, "control-a · trusted here", "small green")
        c.txt(862, 800, "control-b · unknown, no fresh readback", "small amber")
        administration_action(c, 348, 837, 248, "Replacement instructions", "#replace")
        administration_action(c, 618, 837, 208, "Revoke certificate", "#revoke")
        c.line(328, 925, 1538, 925)
        c.txt(348, 961, "Need to install an administrator identity on another computer?", "body")
        c.txt(348, 993, "Retrieve the protected P12 and password from the control, then import them on the admin device.", "small muted")
        c.txt(348, 1021, "Public website certificates are available separately under Web certificates.", "small muted")
        administration_link(c, 348, 1062, "View website certificates →", "09-administration-certificates.svg")


def administration_certificates_draw(c: Canvas, state: str) -> None:
    administration_heading(c, "Web certificates", "Website identity for https://control.loom/ · administrator login is managed separately.")
    done, failed = state in ("complete", "downloads-renewed"), state == "activation-failed"
    administration_action(c, 1328, 210, 210, "Download trust root", "#downloads-renewed" if done else "#downloads", action="download-public-website-root")
    c.txt(328, 310, "2 control nodes", "section")
    c.txt(638, 310, "1 unknown" if done else "1 renewal reminder · 1 unknown", "body muted")
    c.txt(1538, 310, "As of 2030-01-01 00:00 UTC", "small muted", "end")
    for x, label in ((344, "CONTROL / ENTRY"), (744, "EXPIRES (UTC)"), (1084, "CURRENT RESULT")):
        c.txt(x, 365, label, "eyebrow muted")
    c.line(328, 385, 1538, 385)
    for index, node in enumerate(("demo-control-a", "demo-control-b")):
        top = 385 + index * 88
        c.add(f'<g data-ui="web-certificate" data-control="{node}" data-readback="{"current" if index == 0 else "stale"}">')
        if index == 0:
            c.rect(328, top, 1210, 88, "#EEF4FA", "none", 0)
        c.txt(344, top + 32, node, "body mono")
        c.txt(344, top + 59, "Local serving entry · control.loom" if index == 0 else "Authenticated peer readback is stale", "small muted")
        c.txt(744, top + 32, ("2031-01-01 00:00" if done else "2030-01-25 00:00") if index == 0 else "Unknown", "body" if index == 0 else "body amber")
        c.txt(744, top + 59, ("365 days remaining" if done else "24 days remaining") if index == 0 else "No current expiry value", "small muted")
        c.txt(1084, top + 32, ("Valid · renewed" if done else "Renew soon") if index == 0 else "Needs fresh readback", "body " + ("green" if done and index == 0 else "amber"))
        c.txt(1084, top + 59, "Serving readback verified" if done and index == 0 else "Current certificate remains in use" if index == 0 else "Expiry cannot be inferred", "small muted")
        c.line(328, top + 88, 1538, top + 88)
        c.add('</g>')
    if state in ("downloads", "downloads-renewed"):
        c.txt(348, 604, "Download public certificate files", "section")
        c.txt(348, 636, "Files are delivered through the authenticated management connection. No private keys are included.", "small muted")
        downloads = (
            ("Website certificate", "demo-control-a.crt", "Leaf for the current control-a entry", "leaf"),
            ("Certificate chain", "demo-control-a-chain.pem", "Current website leaf and public chain", "chain"),
            ("Website trust root", "demo-website-root.crt", "Public trust certificate for .loom", "root"),
        )
        for index, (label, filename, detail, kind) in enumerate(downloads):
            top = 662 + index * 100
            c.add(f'<g data-ui="certificate-download" data-kind="{kind}" data-generation="{"renewed" if done else "current"}" data-audience="authenticated-admin" data-private-key="excluded">')
            c.line(328, top, 1538, top)
            c.txt(348, top + 34, label, "body")
            c.txt(744, top + 34, filename, "body mono")
            c.txt(744, top + 65, detail, "small muted")
            c.add(f'<g data-ui="download-public-certificate" data-source="verified-{kind}">')
            c.button(1370, top + 22, 148, "Download", height=42)
            c.add('</g></g>')
        c.line(328, 962, 1538, 962)
        c.txt(348, 1003, "Initial browser trust must come from an independently trusted delivery channel.", "body")
        c.txt(348, 1035, "Downloading this root does not install it, grant admin access or replace the localhost development certificate.", "small muted")
        administration_link(c, 348, 1081, "‹ Certificate details", "#complete" if done else "#overview")
        return
    if state == "overview":
        c.txt(348, 604, "demo-control-a · serving certificate", "section")
        values = ((646, "Website name", "control.loom"), (683, "Issuer", "demo-website-root"),
                  (720, "Fingerprint", "demo-web-current-fingerprint · SHA-256"),
                  (757, "Purpose", "HTTPS server · serverAuth · not a CA"))
        for y, label, value in values:
            c.txt(348, y, label, "small muted")
            c.txt(744, y, value, "body mono" if label == "Website name" else "body")
        administration_action(c, 348, 794, 198, "Download certificate", "#downloads", action="download-public-website-leaf")
        administration_action(c, 562, 794, 198, "Download chain", "#downloads", action="download-public-website-chain")
        administration_action(c, 1298, 794, 220, "Prepare renewal", "#renewal", primary=True)
        c.line(328, 877, 1538, 877)
        c.txt(348, 917, "Renew before 25 January", "body amber")
        c.txt(348, 950, "Generate a bound request here, have it signed offline, then import the signed certificate chain.", "small muted")
        c.txt(348, 980, "Keep the current entry until the new certificate and browser access have been verified.", "small muted")
        c.txt(348, 1025, "Using the same trust root does not require browsers to import it again.", "small muted")
        c.txt(348, 1090, "If this entry expires, use another valid control entry or the protected local CLI for recovery.", "small muted")
        return
    c.txt(348, 604, "Renew website certificate · demo-control-a", "section")
    administration_link(c, 1518, 604, "Certificate details", "#complete" if done else "#overview", anchor="end")
    if state == "renewal":
        c.txt(348, 646, "1. Prepare a signing request", "body")
        c.txt(348, 683, "Control", "small muted")
        c.txt(744, 683, "demo-control-a · web entry demo-web-a-next", "body mono")
        c.txt(348, 720, "Website name", "small muted")
        c.txt(744, 720, "control.loom · fixed for this entry", "body")
        c.txt(348, 760, "A new private key is generated on control-a and stays there. Only the bound request is exported.", "small muted")
        c.txt(348, 789, "The website root signs offline. The current certificate remains in service during preparation.", "small muted")
        administration_action(c, 1238, 831, 280, "Generate signing request", "#request", primary=True, action="generate-bound-csr-on-owner")
        administration_link(c, 348, 858, "Cancel preparation", "#overview")
    elif state == "request":
        administration_notice(c, 634, "Signing request is ready", "Bound to control-a, its Web entry and current membership proof. The private key remains on control-a.", tone="green")
        c.txt(348, 746, "demo-control-a-web-request.zip", "body mono")
        c.txt(348, 775, "Includes CSR, authenticated node / entry binding and membership proof", "small muted")
        c.add('<g data-ui="download-bound-csr" data-control="demo-control-a" data-entry="demo-web-a-next" data-private-key="excluded">')
        c.button(1218, 725, 300, "Download signing request", height=42)
        c.add('</g>')
        c.line(328, 810, 1538, 810)
        c.txt(348, 851, "2. Have the request signed offline", "body")
        c.txt(348, 884, "Verify the request signature, member, key and entry before signing for control.loom.", "small muted")
        c.txt(348, 912, "Return the signed certificate chain. Never transfer the website root private key to a control.", "small muted")
        administration_action(c, 1218, 952, 300, "Import signed certificate", "#import", primary=True)
        c.txt(348, 1024, "You can leave this page. The pending key and entry are recovered from protected local state.", "small muted")
    elif state in ("import", "import-failed", "ready"):
        c.txt(348, 645, "3. Import the signed certificate chain", "body")
        flow_input(c, 348, 667, 866, "demo-control-a-signed-chain.pem")
        administration_action(c, 1230, 667, 288, "Choose certificate file", "#import")
        c.txt(348, 750, "New certificate", "small muted")
        c.txt(744, 750, "control.loom · expires 2031-01-01 00:00 UTC", "body")
        c.txt(348, 787, "Local signing request", "small muted")
        c.txt(744, 787, "demo-web-a-next · demo-control-a", "body mono")
        if state == "import-failed":
            administration_notice(c, 820, "Certificate does not match the pending private key", "Nothing was activated. Import the chain signed for this request; the current entry is unchanged.", tone="red")
            administration_action(c, 1258, 929, 260, "Choose another file", "#import", primary=True)
        elif state == "ready":
            administration_notice(c, 820, "Certificate and prepared entry checks passed", "Chain, name, use, validity and key match verified. TLS and Web preflight passed with SNI control.loom.", tone="green")
            c.txt(348, 928, "Ready to serve · formal browser verification is still required before retiring the old entry.", "body")
            administration_action(c, 1258, 963, 260, "Activate new certificate", "#verify", primary=True, action="activate-preflighted-web-entry")
        else:
            c.txt(348, 847, "The file has been selected; validation and preflight have not run yet.", "body amber")
            c.txt(348, 883, "Check the certificate against this request, then preflight TLS and Web on the prepared entry.", "small muted")
            administration_action(c, 1258, 928, 260, "Validate and preflight", "#ready", primary=True, action="validate-chain-and-preflight")
    elif state in ("verify", "complete", "activation-failed"):
        if done:
            administration_notice(c, 634, "Renewal verified · new certificate is serving", "Formal browser access passed. The old entry was drained and retired after verification.", tone="green")
        elif failed:
            administration_notice(c, 634, "New entry failed browser verification", "New connections to the failed entry are closed. The previous valid entry continues serving.", tone="red")
        else:
            administration_notice(c, 634, "New entry is serving · browser verification is pending", "The previous entry is still serving. Activation alone does not prove the new entry works for a browser.")
        rows = (("New entry", "Serving · browser verified" if done else "Draining · new connections closed" if failed else "Serving · browser check pending"),
                ("Previous entry", "Retired after browser verification" if done else "Serving · valid until 2030-01-25"),
                ("Trust root", "Unchanged · browsers do not need to import it again"))
        for index, (label, value) in enumerate(rows):
            y = 753 + index * 45
            c.txt(348, y, label, "small muted")
            c.txt(744, y, value, "body")
        if done:
            c.txt(348, 929, "The verified leaf fingerprint matches the new control-a entry. control-b still has no fresh readback.", "small muted")
            administration_action(c, 348, 973, 230, "Download current chain", "#downloads-renewed")
        elif failed:
            c.txt(348, 920, "Failure · the target browser could not complete authenticated Web access to the new entry.", "small red")
            c.txt(348, 951, "Check this entry from the protected local CLI before preparing a new attempt.", "small muted")
            administration_action(c, 348, 988, 230, "Review certificate", "#overview")
        else:
            c.txt(348, 925, "Verify the new entry with control.loom TLS identity and an authenticated browser readback.", "body")
            c.txt(348, 957, "A successful check must identify the new entry and certificate, not another control answering the same name.", "small muted")
            administration_action(c, 1208, 993, 310, "Verify new entry in browser", "#complete", primary=True, action="browser-readback-new-web-entry")
    c.line(328, 1110, 1538, 1110)
    c.txt(348, 1145, "Renewal is local to this control. Other entries keep their own certificate and readback status.", "small muted")


# Numeric filename prefixes follow NAV order; Canvas names identify scenes.
PAGES = {
    "01-overview": overview,
    "02-nodes": nodes,
    "02-nodes-add-ssh": add_device,
    "02-nodes-add-script": lambda: add_device("script"),
    "02-nodes-add-qr": lambda: add_device("qr"),
    "02-nodes-detail": device_detail,
    "02-nodes-access-edit": device_access_edit,
    "02-nodes-access-result": operations,
    "02-nodes-rejoin": device_rejoin,
    "02-nodes-add-qr-delivery": join_delivery,
    "02-nodes-add-ssh-result": ssh_result,
    "02-nodes-add-script-delivery": lambda: join_delivery("script"),
    "02-nodes-lan-mapping": node_lan_mapping,
    "03-topology": topology,
    **{page: (lambda page=page: live_paths(page)) for page in LIVE_PATH_PROTOTYPES},
    "05-services": services,
    "05-services-lan": lambda: services(lan=True),
    "05-services-dns": services_dns,
    "06-policies": policies,
    "06-policies-new": lambda: policies(new=True),
    "06-policies-lan": lambda: policies(lan=True),
    "07-releases-linux": lambda: release_platform("linux"),
    "07-releases-android": lambda: release_platform("android"),
    "07-releases-windows": lambda: release_platform("windows"),
    "07-releases-deployments": deployments,
    "08-events": events,
    "09-administration": lambda: administration_page("controls", ("overview", "sync"), administration_controls_draw),
    "09-administration-administrators": lambda: administration_page("administrators", ("overview", "add", "invalid", "added", "replace", "revoke", "revoked"), administration_administrators_draw),
    "09-administration-certificates": lambda: administration_page("certificates", ("overview", "downloads", "downloads-renewed", "renewal", "request", "import", "import-failed", "ready", "verify", "activation-failed", "complete"), administration_certificates_draw),
    "09-administration-configuration": lambda: administration_page("configuration", ("overview", "compare", "review-a", "review-b", "changed", "resolved-a", "resolved-b", "sources"), administration_configuration_draw),
    "10-entry-guest": guest_entry,
}


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, build in PAGES.items():
        target = OUTPUT / f"{name}.svg"
        target.write_text(build().render(), encoding="utf-8")
        ET.parse(target)
        print(target.relative_to(ROOT))


if __name__ == "__main__":
    main()
