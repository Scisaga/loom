#!/usr/bin/env python3
"""Generate editable target-state Web prototypes from the current UI projection.

All examples are synthetic. The SVGs are design references, not a deployment
readback or a source of control authority. The generator never reads an output
SVG, a screenshot, a clock, a network service, or production configuration.
"""

from __future__ import annotations

import math
from pathlib import Path
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
    "demo-laptop": "workstation", "demo-network": "Loom network",
    "demo-video": "media", "demo-work": "work-apps", "demo-private": "private-app",
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
    ("Releases", "releases", 789, "icon-release"),
    ("Events", "events", 902, "icon-events"),
    ("Signed state", "signed-state", 996, "icon-signed"),
)

PAGE_STATUS = {
    "overview": "Two verified members · latest local fact still propagating",
    "nodes": "Six stable device identities · three current runtime reports",
    "node-detail": "demo-forward-c · effective forward authorization · fresh runtime report",
    "topology": "Nine explicit relay LinkIDs · five fresh results · four unknown",
    "live-paths": "demo-video · Auto selected a reported relay path",
    "services": "Three known Services · demo-work is suspended by conflicting facts",
    "deployments": "Signed catalog verified · one of five targets has a matching readback",
    "events": "Verified local history · current state is read independently",
    "signed-state": "Member chain verified · one target suspended by conflict",
    "add-device": "Issue a bounded Invite through one authenticated control",
    "releases-linux": "Linux catalog entries verified · demo-forward-c has a matching applied readback",
    "releases-android": "Android catalog entries verified · application depends on device report",
    "releases-windows": "Windows catalog entries verified · no enrolled Windows target",
    "observations": "The demo-work business observation has expired",
    "operations": "Normal operation accepted locally · peer delivery remains unknown",
    "enrollment": "Invite issued before first claim; control joining waits for majority",
    "certificates": "Serving leaf expires within the 30-day reminder window",
}


class Canvas:
    def __init__(self, name: str, title: str, subtitle: str, section: str, active: str, *, height: int = 992):
        self.name = name
        self.height = height
        self.parts: list[str] = []
        self.add(f'<rect width="1586" height="{height}" fill="#FCFDFC"/>')
        self.header(active)
        self.txt(24, 97, section.upper(), "eyebrow green")
        self.txt(24, 134, title, "title")
        self.txt(24, 162, subtitle, "body muted")
        if name in PAGE_STATUS:
            attention = name in ("services", "signed-state", "observations", "enrollment", "certificates")
            self.circle(30, 180, 6, "#FFFFFF", "#C4994D" if attention else "#2AA875")
            self.txt(30, 184, "!" if attention else "✓", "tiny amber" if attention else "tiny green", "middle")
            self.txt(47, 184, PAGE_STATUS[name], "small")

    def add(self, svg: str) -> None:
        self.parts.append(svg)

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

    def button(self, x: int, y: int, w: int, label: str, primary: bool = False) -> None:
        self.add('<g data-ui="button">')
        self.rect(x, y, w, 34, "#248F64" if primary else "#FFFFFF", "#248F64" if primary else "#DDE4DE", 6)
        self.txt(x + w // 2, y + 21, label, "small white" if primary else "small", "middle")
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
            selected = active == key or (active == "node-detail" and key == "nodes") or (active.startswith("releases-") and key == "releases") or (active == "deployments" and key == "releases")
            self.add(f'<use href="#{icon}" x="{x}" y="20" width="15" height="15" class="{"nav-active" if selected else "nav-icon"}"/>')
            self.txt(x + 21, 34, label, "nav" + ("" if selected else " muted"))
            if selected:
                self.add(f'<line x1="{x}" y1="57" x2="{x + 18 + len(label) * 7}" y2="57" stroke="#2AA875" stroke-width="2"/>')
        self.icon("icon-node", 1285, 22, 14)
        self.txt(1307, 34, "demo-control-a", "small muted")
        self.add('<use href="#icon-lock" x="1450" y="20" width="14" height="14" class="nav-icon"/>')
        self.txt(1470, 34, "Admin view", "small muted")

    def render(self) -> str:
        description = f"Loom control center: {self.name}."
        body = "\n  ".join(self.parts)
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="{SVG_NS}" xmlns:xlink="http://www.w3.org/1999/xlink" width="1586" height="{self.height}" viewBox="0 0 1586 {self.height}" role="img" aria-labelledby="svg-title svg-desc">
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


def network_graph(c: Canvas, x: int, y: int, w: int, h: int, *, large: bool = False) -> None:
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


def search_control(c: Canvas, x: int, y: int, w: int, placeholder: str) -> None:
    c.rect(x, y, w, 38, "#F8FAF8", "#E1E7E2", 5)
    c.add(f'<use href="#icon-search" x="{x+11}" y="{y+11}" width="15" height="15" class="nav-icon"/>')
    c.txt(x + 35, y + 24, placeholder, "small muted")


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
    for xx, text, tone in ((47, "Policy accepted locally · demo-policy", "green"),
                           (555, "Member certificate verified · demo-control-b", "green"),
                           (1063, "Service suspended · demo-work conflict", "amber")):
        c.circle(xx + 4, 1088, 3, "#28A472" if tone == "green" else "#C99A46")
        c.txt(xx + 17, 1092, text, "small" if tone == "green" else "small amber")
    return c


def nodes() -> Canvas:
    c = Canvas("nodes", "Devices", "One stable identity per device, with roles, policy grants and runtime evidence.", "inventory", "nodes")
    status_strip(c, [("Device identities", "6", "same ID across roles"), ("Control members", "2", "majority certificate"), ("Observed running", "3", "fresh runtime reports"), ("Runtime unknown", "3", "no inferred process state")])
    tabs(c, ("All devices", "Control members", "Needs attention"), "All devices")
    c.card(24, 335, 1538, 636, "Device inventory", "one row per stable DeviceID")
    search_control(c, 46, 399, 356, "Search ID, policy or platform")
    c.pill(422, 404, 101, "All · 6", "green")
    c.pill(536, 404, 135, "Control · 2", "neutral")
    c.pill(684, 404, 145, "Runtime unknown · 3", "amber")
    c.button(1362, 401, 178, "+ Add device", True)
    c.line(24, 453, 1562, 453, kind="panel-section")
    c.rows(47, 479, (230, 303, 229, 200, 238, 209, 80), ("Device / platform", "Roles", "Policy grants", "Authorization", "Runtime / probe", "Report evidence", "Open"), [], 1, edges=(24, 1562))
    inventory = (
        ("demo-control-a", "Linux · member", "control + forward", "none", "effective", "running", "runtime fresh", "resource + LinkID current"),
        ("demo-control-b", "Linux · member", "control + forward", "none", "effective", "unknown", "runtime missing", "no fresh runtime View"),
        ("demo-forward-b", "Linux · relay", "forward", "none", "effective", "unknown", "runtime stale", "link digest changed"),
        ("demo-forward-c", "Linux · gateway", "forward", "none", "effective", "running", "runtime fresh", "LAN ACL current"),
        ("demo-egress-e", "Linux · exit", "forward + internet_egress", "none", "effective", "running", "runtime fresh", "path result is scoped"),
        ("demo-phone-f", "Android · access", "access", "demo-policy", "effective", "runtime unknown", "probe fresh", "demo-video available"),
    )
    for i, (name, platform, roles, grant, auth, runtime, age, detail) in enumerate(inventory):
        top = 493 + i * 70
        yy = top + 28
        if i == 3:
            c.rect(25, top, 1536, 70, "#F2F8F4", "none", 0)
        c.circle(53, yy - 5, 4, "#2AA875" if runtime == "running" else "#D79B3B")
        c.txt(66, yy, name, "body mono")
        c.txt(66, yy + 20, platform, "tiny muted")
        c.txt(277, yy + 11, roles, "body")
        c.txt(580, yy + 11, grant, "body mono")
        c.txt(809, yy + 11, auth, "body green")
        c.txt(1009, yy, runtime, "body green" if runtime == "running" else "body amber")
        c.txt(1009, yy + 20, detail, "tiny muted")
        c.txt(1247, yy + 11, age, "body amber" if age not in ("runtime fresh", "probe fresh") else "body")
        c.txt(1522, yy + 11, "›", "metric muted", "middle")
        c.line(24, top + 70, 1562, top + 70, kind="table-rule")
    c.txt(47, 946, "Ordinary grants can be accepted locally; control retirement and whole-node deletion require old-member majority.", "tiny muted")
    return c


def node_detail() -> Canvas:
    c = Canvas("node-detail", "demo-forward-c", "Stable Linux gateway · signed authorization and current runtime evidence.", "devices / detail", "node-detail")
    c.rect(24, 196, 1538, 81, panel=True)
    c.txt(46, 222, "DEVICE ID", "eyebrow muted")
    c.txt(46, 254, "demo-forward-c", "metric mono")
    c.txt(325, 252, "Linux · forward gateway", "body muted")
    c.line(576, 196, 576, 277, kind="panel-column")
    c.txt(599, 222, "CURRENT ROLES", "eyebrow muted")
    c.pill(599, 232, 115, "forward", "green")
    c.txt(735, 252, "Signed role; LAN report does not grant access.", "small muted")
    c.pill(1363, 215, 176, "running · fresh", "green")
    c.txt(1363, 262, "Business: unknown", "small amber")

    c.card(24, 294, 738, 263, "Device authorization", "signed projection")
    c.txt(46, 374, "Device ID", "small muted"); c.txt(187, 374, "demo-forward-c", "body mono")
    c.txt(46, 416, "Roles", "small muted")
    for i, (label, tone) in enumerate((("forward", "green"), ("access", "neutral"), ("internet_egress", "neutral"), ("control", "neutral"))):
        c.pill(187 + i * 130, 394, 120, label, tone)
    c.txt(46, 466, "Policy grants", "small muted")
    c.txt(187, 466, "none · this device is a forward gateway", "body muted")
    c.button(46, 502, 175, "Edit authorization", True)
    c.button(234, 502, 147, "Revoke device")
    c.txt(401, 524, "Ordinary role edits are accepted locally, then spread.", "small muted")

    c.card(778, 294, 784, 263, "Actual runtime", "signed report · current View digest")
    c.rows(800, 368, (240, 175, 325), ("Evidence", "Current", "What it proves"), [
        ("Process / listener", "running", "current matching report"),
        ("ACL / return path", "running", "device execution report"),
        ("Service business", "unknown", "no fresh scoped result"),
    ], 43, True, edges=(778, 1562))
    c.txt(800, 538, "A fresh process report cannot turn an unmeasured Service green.", "small muted")

    c.card(24, 573, 1538, 178, "WireGuard interface traffic", "valid adjacent counter increments · 24h")
    rx = traffic_series(device="demo-forward-c", direction="rx")
    tx = traffic_series(device="demo-forward-c")
    for xx, label, value in ((46, "OBSERVED RX", byte_size(traffic_total(rx))),
                             (245, "OBSERVED TX", byte_size(traffic_total(tx))),
                             (444, "HOURS WITH DELTAS", "22 / 24")):
        c.txt(xx, 650, label, "eyebrow muted")
        c.txt(xx, 680, value, "metric")
    c.rect(47, 700, 8, 8, "#8CCCB0", "none", 2); c.txt(64, 708, "RX", "tiny muted")
    c.rect(105, 700, 8, 8, "#5D89C5", "none", 2); c.txt(122, 708, "TX", "tiny muted")
    c.txt(47, 732, "Gaps and counter resets are excluded; current availability is separate.", "tiny muted")
    traffic_chart(c, 799, 656, 739, 58, ((rx, "#8CCCB0"), (tx, "#5D89C5")))

    c.card(24, 767, 951, 204, "Reusable resource and observations", "resource ID · LinkID · Service scope are separate")
    c.rows(46, 841, (214, 271, 231, 190), ("Layer", "Stable identity", "Evidence", "Result"), [
        ("WG resource", "demo-wg-forward-c", "real transport action", "available"),
        ("Relay LinkID", "demo-link-c-cb", "new spec digest", "unknown"),
        ("Service result", "demo-video", "no scoped report", "unknown"),
    ], 34, True, edges=(24, 975))

    c.card(991, 767, 571, 204, "Shared LAN mapping", "forward gateway only")
    for y, label, value in ((840, "Reported local", "192.0.2.0/24"), (870, "Virtual prefix", "198.51.100.0/24"),
                            (900, "Fixed gateway", "198.51.100.1"), (930, "Bound Policy", "demo-lan-policy")):
        c.txt(1013, y, label, "small muted")
        c.txt(1195, y, value, "body mono")
    c.button(1380, 925, 157, "Edit mapping")
    c.txt(1013, 954, "Only granted access devices receive this prefix.", "tiny muted")
    return c


def topology() -> Canvas:
    c = Canvas("topology", "Network topology", "Inspect declared connections and the path reported for a selected Service.", "network / topology", "topology", height=1080)
    c.rect(24, 201, 1080, 479, panel=True)
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
    network_graph(c, 45, 316, 1039, 313, large=True)
    c.line(24, 640, 1104, 640, kind="panel-section")
    c.add('<path d="M48 659h24" class="selected"/>')
    c.txt(83, 663, "Observed selection", "tiny muted")
    c.add('<path d="M233 659h25" stroke="#BECBC2" stroke-width="1.5"/>')
    c.txt(266, 663, "Declared relay", "tiny muted")
    c.circle(393, 659, 3, "#2AA875"); c.txt(404, 663, "Runtime current", "tiny muted")
    c.circle(515, 659, 3, "#B3BEB6"); c.txt(526, 663, "Runtime unknown", "tiny muted")
    c.txt(1082, 663, "3 / 6 current runtime reports", "tiny muted", "end")

    c.card(1120, 201, 442, 228, "Link observations", "current spec only")
    # One segment per current result; the ring encodes 5 of 9, not volume.
    c.add('<circle cx="1181" cy="302" r="33" fill="none" stroke="#F2E8D6" stroke-width="8"/>')
    c.add('<circle cx="1181" cy="302" r="33" fill="none" stroke="#3BAA79" stroke-width="8" stroke-dasharray="115.19 207.35" transform="rotate(-90 1181 302)"/>')
    c.txt(1181, 303, "5 / 9", "section", "middle")
    c.txt(1181, 319, "current", "tiny muted", "middle")
    c.circle(1245, 280, 4, "#3BAA79"); c.txt(1258, 285, "5 available", "body green")
    c.circle(1245, 308, 4, "#D2A45B"); c.txt(1258, 313, "4 unknown", "body amber")
    c.line(1120, 348, 1562, 348, kind="panel-section")
    c.txt(1141, 382, "demo-link-wg", "body mono")
    c.pill(1431, 364, 109, "available", "green", 25)
    c.txt(1141, 409, "Current spec · report from demo-control-a", "small muted")

    c.card(1120, 445, 442, 235, "Link traffic", "link-wg · endpoint TX")
    left = traffic_series(link_id="demo-link-wg", device="demo-control-a")
    right = traffic_series(link_id="demo-link-wg", device="demo-egress-e")
    c.txt(1141, 525, "OBSERVED TX", "eyebrow muted")
    c.txt(1141, 556, byte_size(traffic_total(traffic_series(link_id="demo-link-wg"))), "metric")
    c.txt(1141, 582, "2 reporting endpoints", "tiny muted")
    c.txt(1141, 604, "22 / 24 h with deltas", "tiny muted")
    traffic_chart(c, 1320, 527, 219, 79, ((left, "#5D89C5"), (right, "#8CCCB0")))
    c.rect(1141, 644, 8, 8, "#5D89C5", "none", 2); c.txt(1157, 652, "demo-control-a", "tiny mono muted")
    c.rect(1291, 644, 8, 8, "#8CCCB0", "none", 2); c.txt(1307, 652, "demo-egress-e", "tiny mono muted")
    c.txt(1539, 652, "24h", "tiny muted", "end")

    c.card(24, 696, 1538, 360, "Relay link inventory", "9 explicit links · access first hop is a separate resource")
    columns = (47, 229, 534, 639, 781, 1004, 1177)
    headings = ("LINKID", "ENDPOINTS", "TRANSPORT", "OBSERVATION", "24H OBSERVED TX", "HOURS WITH DELTAS", "EVIDENCE / SPEC")
    for xx, label in zip(columns, headings):
        c.txt(xx, 769, label, "eyebrow muted")
    c.line(24, 783, 1562, 783, kind="table-rule")
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
    max_tx = max(traffic_total(traffic_series(link_id=row[0])) or 0 for row in link_rows)
    for i, row in enumerate(link_rows):
        top = 783 + i * 28
        yy = top + 18
        if i == 0:
            c.rect(25, top, 1536, 28, "#EDF4FC", "none", 0)
            c.rect(25, top, 3, 28, "#537FCC", "none", 0)
        tx = traffic_total(traffic_series(link_id=row[0]))
        values = (*row[:4], byte_size(tx), "22 / 24" if tx is not None else "unknown", row[4])
        for j, (xx, value) in enumerate(zip(columns, values)):
            if j == 3:
                c.circle(xx + 3, yy - 4, 3, "#3BAA79" if value == "available" else "#D2A45B")
                c.txt(xx + 14, yy, value, "small green" if value == "available" else "small amber")
            else:
                c.txt(xx, yy, value, "small mono" if j in (0, 2) else "small muted" if j in (5, 6) else "small")
        if tx is not None:
            c.rect(892, yy - 8, 85, 6, "#EDF2EF", "none", 2)
            c.rect(892, yy - 8, round(85 * tx / max_tx), 6, "#8CC5A6", "none", 2)
        c.txt(1534, yy, "›", "small blue" if i == 0 else "small faint", "end")
        c.line(24, top + 28, 1562, top + 28, kind="table-rule")
    return c


def live_paths() -> Canvas:
    c = Canvas("live-paths", "Live paths", "Follow a device's selected path, then inspect the evidence for each eligible candidate.", "network / paths", "live-paths")
    c.rect(24, 201, 1538, 76, panel=True)
    for x, label, value, width in ((45, "DEVICE", "demo-phone-f", 265), (339, "SERVICE", "demo-video", 265)):
        c.txt(x, 223, label, "eyebrow muted")
        c.rect(x, 233, width, 31, "#FBFCFB", "#DFE7E1", 5)
        c.txt(x + 11, 254, value, "small mono")
        c.icon("icon-chevron", x + width - 26, 241)
    c.line(633, 201, 633, 277, kind="panel-column")
    c.txt(657, 223, "DEVICE PREFERENCE", "eyebrow muted")
    c.txt(657, 252, "Auto", "section")
    c.txt(708, 252, "read-only device report", "small muted")
    c.txt(1072, 223, "BUSINESS PROBE", "eyebrow muted")
    c.txt(1072, 252, "HTTPS · media.example/health", "small mono")
    c.pill(1398, 230, 139, "available", "green")

    c.card(24, 293, 332, 384, "Services", "this device")
    items = (
        ("demo-video", "available", "green", "Via demo-egress-e", "Current HTTPS business result"),
        ("demo-work", "suspended", "amber", "Conflicting Service facts", "No active matcher or candidate"),
        ("demo-private", "no grant", "neutral", "Not authorized for this device", "Business result · unknown"),
    )
    for i, (name, state, tone, detail, caption) in enumerate(items):
        yy = 357 + i * 103
        c.rect(43, yy, 294, 91, "#F0F5FD" if i == 0 else "#FFFFFF", "#CDDCF2" if i == 0 else "#E2E8E3", 6)
        if i == 0:
            c.rect(43, yy, 3, 91, "#4D78D1", "none", 1)
        c.txt(57, yy + 24, name, "small mono")
        c.pill(229, yy + 9, 96, state, tone, 23)
        c.txt(57, yy + 49, detail, "small")
        c.txt(57, yy + 72, caption, "tiny muted")

    c.card(372, 293, 1190, 384, "Selected path · demo-video", "reported by demo-phone-f")
    c.pill(393, 357, 133, "Auto · selected", "blue", 26)
    c.txt(1541, 374, "Final exit · demo-egress-e", "small muted", "end")
    for x, name, role, icon in ((410, "demo-phone-f", "access", "icon-phone"),
                                (880, "demo-control-a", "control · forward", "icon-signed"),
                                (1324, "demo-egress-e", "forward · internet_egress", "icon-globe")):
        c.rect(x, 418, 215, 66, "#FBFCFE", "#C8D8EE", 8)
        c.rect(x + 12, 434, 32, 32, "#ECF2FA", "none", 7)
        c.icon(icon, x + 20, 442, 16)
        c.txt(x + 55, 446, name, "small mono")
        c.txt(x + 55, 468, role, "tiny muted")
    c.add('<path d="M625 451H874M1095 451H1318" class="selected"/>')
    c.txt(752, 428, "Shared first-hop resource", "tiny blue", "middle")
    c.txt(1207, 428, "WG · demo-link-wg", "tiny blue mono", "middle")
    c.line(372, 509, 1562, 509, kind="panel-section")
    for x, title, result, detail, tone in (
        (394, "AUTHORIZATION", "demo-policy effective", "Signed grant for this Service", "green"),
        (793, "TRANSPORT", "available", "Real action · current scope", "green"),
        (1192, "SERVICE BUSINESS", "available", "HTTPS · current matching result", "green"),
    ):
        c.txt(x, 536, title, "eyebrow muted")
        c.txt(x, 564, result, f"body {tone}")
        c.txt(x, 588, detail, "tiny muted")
    c.note(394, 615, 1146, ("Device runtime is unknown. This scoped business result does not establish Ready or another Service's health.",), "blue")

    c.card(24, 693, 1538, 278, "Eligible candidates · demo-video", "Direct, Auto and specified exit share this candidate set")
    columns = (47, 237, 648, 864, 1067, 1280)
    for x, label in zip(columns, ("PREFERENCE", "CANDIDATE", "FINAL EXIT", "TRANSPORT", "BUSINESS", "DEVICE CHOICE")):
        c.txt(x, 768, label, "eyebrow muted")
    c.line(24, 781, 1562, 781, kind="table-rule")
    rows = (
        ("Direct · Auto", "Local underlay", "device", "available", "available", "eligible"),
        ("Auto · specified", "Shared first hop + demo-link-wg", "demo-egress-e", "available", "available", "selected"),
        ("Auto · specified", "One-hop shared resource", "demo-egress-e", "unknown", "unknown", "not selected"),
        ("Auto · specified", "Shared first hop + demo-link-hy2", "demo-egress-e", "unknown", "unknown", "not selected"),
    )
    for i, row in enumerate(rows):
        yy = 804 + i * 38
        if i == 1:
            c.rect(25, yy - 23, 1536, 38, "#F0F5FD", "none", 0)
            c.rect(25, yy - 23, 3, 38, "#4D78D1", "none", 0)
        for j, (x, value) in enumerate(zip(columns, row)):
            if j in (3, 4):
                c.circle(x + 4, yy - 4, 3, "#3BAA79" if value == "available" else "#D2A45B")
                c.txt(x + 16, yy, value, "small green" if value == "available" else "small amber")
            else:
                c.txt(x, yy, value, "small blue" if i == 1 and j == 5 else "small mono" if j == 2 else "small")
        c.line(24, yy + 15, 1562, yy + 15, kind="table-rule")
    c.txt(47, 956, "A one-hop candidate and a relayed candidate can reach the same final exit. Missing evidence remains unknown.", "tiny muted")
    return c


def services() -> Canvas:
    c = Canvas("services", "Services", "Exact matchers, policy grants, private DNS and LAN intent share one signed model.", "network intent", "services")
    tabs(c, ("Services", "Policies", "Exact .loom DNS", "Shared LAN mappings"), "Services", 219)
    c.button(1380, 250, 180, "+ Add service", True)
    c.txt(24, 276, "Editing demo-video · the Service links one Policy, scoped HTTPS targets and exact matchers.", "small muted")
    c.card(24, 297, 358, 674, "Service catalog", "3 configured")
    search_control(c, 45, 361, 316, "Search services or hosts")
    for i, (name, detail, matcher) in enumerate((("demo-video", "Media traffic · demo-policy", "media.example"),("demo-work", "Suspended · conflicting facts", "No matcher or candidate is active"),("demo-private", "Private app · no grant", "private.example"))):
        y = 415 + i * 91
        c.rect(45, y, 316, 78, "#EFF7F2" if i == 0 else "#FFFFFF", "#C9E3D1" if i == 0 else "#E7ECE8", 5)
        if i == 0:
            c.rect(45, y, 3, 78, "#2AA875", "none", 1)
        c.txt(60, y+25, name, "body mono")
        c.txt(60, y+47, detail, "small amber" if i == 1 else "small muted")
        c.txt(60, y+66, matcher, "tiny muted" if i == 1 else "tiny muted mono")
        if i == 1:
            c.icon("icon-lock", 331, y + 14, 14)
    c.line(24, 702, 382, 702, kind="panel-section")
    c.txt(45, 735, "MATCHING RULE", "eyebrow muted")
    c.txt(45, 759, "Exact matches one name; a leading dot", "small muted")
    c.txt(45, 780, "can match a domain and subdomains.", "small muted")
    c.note(45, 816, 316, ("No implicit fallback Service.", "Unmatched destinations fail closed."), "amber")
    c.txt(45, 936, "Select a Service to edit its signed intent.", "small muted")
    c.card(398, 297, 1164, 674, "Edit Service · demo-video")
    c.pill(1390, 313, 147, "Draft retained", "amber")
    c.txt(421, 368, "IDENTITY · OBJECT BASIS fact:demo-video", "eyebrow muted")
    c.field(421, 391, "Stable Service ID · read-only", "demo-video", 455)
    c.field(894, 391, "Display name", "Media traffic", 646)
    c.line(398, 463, 1562, 463, kind="panel-section")
    c.txt(421, 493, "Host matchers", "section")
    c.txt(589, 493, "A shared probe target must match this Service and the device's grant.", "small muted")
    c.rows(421, 523, (519, 215, 385), ("Hostname", "Match type", "Actions"), [("media.example", "Exact", ""),(".cdn.media.example", "Suffix", "")], 42, edges=(398, 1562))
    for yy in (564, 606):
        c.rect(1155, yy - 19, 62, 27, "#FFFFFF", "#DDE4DE", 5)
        c.txt(1186, yy - 1, "Edit", "small", "middle")
        c.rect(1228, yy - 19, 90, 27, "#FFFFFF", "#E5DAD9", 5)
        c.txt(1273, yy - 1, "Remove", "small red", "middle")
    c.button(421, 641, 168, "+ Add matcher")
    c.line(398, 694, 1562, 694, kind="panel-section")
    c.field(421, 719, "Policy for this Service", "demo-policy  ▾", 470)
    c.field(910, 719, "Matching shared HTTPS target", "https://media.example/health  ▾", 630)
    c.txt(910, 795, "From the shared target pool; filtered by matcher and grant.", "tiny muted")
    c.txt(421, 814, "NETWORK TOOLS", "eyebrow muted")
    c.pill(421, 830, 171, "Exact .loom DNS", "green")
    c.pill(604, 830, 163, "LAN mapping", "neutral")
    c.txt(787, 849, "demo-printer.loom → 198.51.100.42 · address does not grant access", "small muted")
    c.txt(787, 872, "demo-forward-c · 192.0.2.0/24 → 198.51.100.0/24 · demo-lan-policy", "tiny muted mono")
    c.line(398, 890, 1562, 890, kind="panel-section")
    c.txt(421, 922, "Local acceptance is shown before peer propagation; conflict keeps this draft.", "small muted")
    c.button(1256, 908, 112, "Discard")
    c.button(1380, 908, 160, "Submit change", True)
    return c


def services_dns() -> Canvas:
    c = Canvas("services-dns", "Private DNS", "Manage exact .loom records; names and answers never grant device access.", "services / dns", "services")
    tabs(c, ("Services", "Policies", "Exact .loom DNS", "Shared LAN mappings"), "Exact .loom DNS", 219)
    c.txt(24, 267, "Network · demo-network", "small mono")
    c.txt(1562, 267, "Editing demo-printer.loom · draft", "small amber", "end")
    c.card(24, 290, 994, 430, "DNS records", "signed network intent")
    search_control(c, 45, 354, 419, "Search a private name or address")
    c.button(830, 356, 166, "+ Add record", True)
    for x, label in ((47, "EXACT NAME"), (331, "TYPE"), (429, "ANSWER"), (693, "SOURCE"), (884, "EDIT")):
        c.txt(x, 424, label, "eyebrow muted")
    c.line(24, 438, 1018, 438, kind="table-rule")
    rows = (
        ("control.loom", "A", "192.0.2.10", "serving Web entry", "reserved"),
        ("control.loom", "A", "192.0.2.11", "serving Web entry", "reserved"),
        ("demo-printer.loom", "A", "198.51.100.42", "explicit record", "selected"),
    )
    for n, row in enumerate(rows):
        top = 438 + n * 68
        yy = top + 38
        if n == 2:
            c.rect(25, top, 992, 68, "#F0F7F3", "none", 0)
            c.rect(25, top, 3, 68, "#2AA875", "none", 0)
        for x, value in zip((47, 331, 429, 693, 884), row):
            c.txt(x, yy, value, "small mono" if x in (47, 429) else "small muted" if x >= 693 else "small")
        c.line(24, top + 68, 1018, top + 68, kind="table-rule")
    c.icon("icon-lock", 47, 678)
    c.txt(73, 691, "control.loom is derived from authenticated serving Web entries and cannot be edited here.", "small muted")
    c.card(24, 736, 994, 235, "Name resolution and access", "separate checks")
    c.icon("icon-service", 47, 804, 24)
    c.txt(86, 820, "demo-printer.loom", "body mono")
    c.add('<path d="M320 815H427" stroke="#A7B9AD" stroke-width="1.5"/>')
    c.txt(450, 820, "198.51.100.42", "body mono")
    c.pill(748, 800, 246, "DNS observation · unknown", "amber")
    c.txt(47, 877, "The answer is inside a mapped LAN. Actual access still requires demo-lan-policy.", "body")
    c.txt(47, 913, "Missing DNS measurements stay unknown even when the signed record is effective.", "small muted")
    c.txt(47, 946, "Only exact .loom A / AAAA records are supported. No wildcard or public-domain override.", "small muted")

    c.card(1034, 290, 528, 681, "Edit record", "unsent draft")
    c.field(1056, 365, "Exact private name", "demo-printer.loom", 484)
    c.txt(1056, 438, "Must end in .loom; control.loom is reserved.", "small muted")
    c.field(1056, 487, "Record type", "A  ▾", 484)
    c.field(1056, 584, "IPv4 answer", "198.51.100.42", 484)
    c.txt(1056, 665, "ADDRESS CONTEXT", "eyebrow muted")
    c.txt(1056, 692, "demo-forward-c · 198.51.100.0/24", "body mono")
    c.note(1056, 736, 484, ("This update changes name resolution only.", "It does not add a Policy grant or prove reachability."), "blue")
    c.line(1034, 829, 1562, 829, kind="panel-section")
    c.button(1056, 851, 114, "Cancel")
    c.button(1182, 851, 168, "Submit record", True)
    c.txt(1056, 919, "The receiving control returns local acceptance.", "small muted")
    c.txt(1056, 941, "Peer propagation is shown after the response.", "small muted")
    return c


def node_lan_mapping() -> Canvas:
    c = Canvas("node-lan-mapping", "Create shared LAN mapping", "Select a prefix reported by the forward gateway and review the access Policy before submitting.", "devices / demo-forward-c / shared lan", "node-detail")
    c.rect(24, 201, 1538, 75, "#F8FAF8", "#DFE7E1", 7)
    c.icon("icon-node", 45, 224, 24)
    c.txt(85, 230, "demo-forward-c", "section mono")
    c.txt(85, 254, "Authorized forward gateway · authenticated local-prefix report", "small muted")
    c.pill(1303, 224, 235, "Draft · not created", "amber")
    c.card(24, 294, 870, 677, "Mapping and access", "create a signed network fact")
    c.field(47, 366, "Reported local IPv4 prefix", "192.0.2.0/24  ▾", 824)
    c.txt(47, 443, "Choose from this gateway's authenticated report. Arbitrary CIDR input is disabled.", "small muted")
    c.field(47, 493, "Virtual prefix · automatic", "198.51.100.0/24", 399)
    c.field(470, 493, "Fixed gateway · assigned", "198.51.100.1", 401)
    c.txt(47, 571, "The virtual prefix has the same length as the reported LAN prefix.", "small muted")
    c.line(24, 593, 894, 593, kind="panel-section")
    c.txt(47, 625, "ACCESS POLICY", "eyebrow muted")
    c.rect(47, 644, 824, 72, "#F0F7F3", "#CDE4D5", 6)
    c.circle(68, 668, 7, "#FFFFFF", "#2AA875"); c.circle(68, 668, 3, "#2AA875")
    c.txt(88, 673, "Create dedicated Policy · demo-lan-policy", "body")
    c.txt(88, 698, "Authorizes only this LAN mapping; no existing device receives the grant automatically.", "small muted")
    c.rect(47, 729, 824, 75, "#FFFFFF", "#DEE6E0", 6)
    c.circle(68, 753, 7, "#FFFFFF", "#ACB9B0")
    c.txt(88, 758, "Use an existing Policy", "body")
    c.txt(88, 785, "demo-policy also authorizes demo-video. Review all targets before selecting it.", "small muted")
    c.line(24, 837, 894, 837, kind="panel-section")
    c.txt(47, 867, "Only signed mapping intent is submitted. Device application is read back separately.", "small muted")
    c.button(47, 895, 116, "Cancel")
    c.button(176, 895, 168, "Create mapping", True)
    c.txt(47, 951, "Creation does not modify the LAN router or authorize access devices.", "tiny muted")

    c.card(910, 294, 652, 316, "Address mapping preview", "same host bits · fixed gateway")
    c.txt(933, 371, "VIRTUAL ADDRESS", "eyebrow muted")
    c.txt(1310, 371, "LAN DESTINATION", "eyebrow muted")
    c.rect(933, 391, 229, 67, "#EFF5FC", "#CDDCEF", 7)
    c.txt(1047, 420, "198.51.100.42", "body mono", "middle")
    c.txt(1047, 444, "access-visible address", "tiny muted", "middle")
    c.add('<path d="M1173 424H1294" class="selected"/>')
    c.rect(1307, 391, 231, 67, "#F0F7F3", "#D1E6D8", 7)
    c.txt(1422, 420, "192.0.2.42", "body mono", "middle")
    c.txt(1422, 444, "gateway-local destination", "tiny muted", "middle")
    c.txt(933, 499, "Gateway", "small muted"); c.txt(1117, 499, "demo-forward-c", "body mono")
    c.txt(933, 532, "Bound Policy", "small muted"); c.txt(1117, 532, "demo-lan-policy", "body mono")
    c.txt(933, 576, "Replies follow the admitted connection through this gateway.", "small muted")
    c.card(910, 626, 652, 345, "After local acceptance", "separate device and runtime checks")
    c.step(933, 691, 1, "Grant the Policy", "Use a new Invite or edit an existing access device", "neutral")
    c.step(933, 768, 2, "Read the device View", "Only granted access devices receive the virtual prefix", "neutral")
    c.step(933, 845, 3, "Read actual results", "No scoped business result means unknown", "neutral")
    c.txt(933, 933, "Address conflict disables the mapping; automatic signed reallocation", "tiny muted")
    c.txt(933, 952, "is limited to three attempts before operator action is needed.", "tiny muted")
    return c


def release_tabs(c: Canvas, selected: str) -> None:
    tabs(c, ("Linux", "Android", "Windows", "Deployments"), selected)


def deployments() -> Canvas:
    c = Canvas("deployments", "Deployments", "Signed catalog, desired digest and actual device readback are separate.", "releases / deployments", "deployments")
    status_strip(c, [("Catalog", "verified", "pinned key"), ("Artifacts", "9 verified", "exact bytes"), ("Desired", "5 targets", "signed intent"), ("Applied", "1 / 5", "current readback")])
    release_tabs(c, "Deployments")
    c.card(24, 334, 410, 372, "Signed catalog")
    c.pill(296, 348, 115, "verified", "green", 25)
    for y, label, value in ((425,"Generation","demo-42"),(461,"Publisher key","protected install input"),(497,"Catalog digest","sha256:7e…"),(533,"Artifacts","9 exact files verified"),(569,"Current pointer","selected catalog only")):
        c.txt(46, y, label.upper(), "eyebrow muted")
        c.txt(201, y, value, "body mono" if y != 461 else "small")
        c.line(24, y+12, 434, y+12, kind="table-rule")
    c.note(46, 623, 366, ("A current pointer is not trust, intent", "or an applied version report."), "blue")
    c.card(450, 334, 1112, 372, "Application by device", "exact component + platform + digest + current report")
    c.rows(473, 408, (222, 145, 199, 197, 197, 107), ("Device", "Platform", "Desired", "Catalog", "Reported applied", "Result"), [
        ("demo-forward-c", "Linux", "sha256:6b…", "verified", "sha256:6b…", "matching"),
        ("demo-phone-f", "Android", "sha256:a3…", "verified", "no fresh report", "unknown"),
        ("demo-egress-e", "Linux", "sha256:6b…", "verified", "sha256:old…", "different"),
        ("demo-control-a", "Linux", "sha256:6b…", "verified", "no applied digest", "unknown"),
        ("demo-forward-b", "Linux", "sha256:6b…", "verified", "report expired", "unknown"),
    ], 49, True, edges=(450, 1562))
    c.txt(473, 690, "An artifact is shown as applied only after a fresh device report matches the signed desired digest.", "tiny muted")
    c.card(24, 722, 912, 249, "Release and application stages", "independent evidence at each boundary")
    c.txt(46, 800, "Verified catalog and bytes", "body")
    timeline(c, 79, 844, 804, ("Catalog", "Artifact", "Desired", "Delivered", "Readback"), 3)
    c.txt(47, 930, "For targets without a fresh matching readback, delivery and application remain unknown.", "small muted")
    c.card(952, 722, 610, 249, "Distribution and safety", "public generic artifacts only")
    c.txt(974, 800, "Signature and digest", "small muted"); c.txt(1302, 800, "verified", "body green")
    c.txt(974, 835, "Expected component", "small muted"); c.txt(1302, 835, "signed intent", "body")
    c.txt(974, 870, "Absent runtime report", "small muted"); c.txt(1302, 870, "unknown", "body amber")
    c.note(974, 895, 565, ("Minimum versions apply only when the signed catalog declares", "a comparable constraint for this component and platform."), "amber")
    return c


def events() -> Canvas:
    c = Canvas("events", "Events", "Verified fact changes and device reports explain transitions without becoming authority.", "operations / history", "events")
    c.txt(24, 221, "LOCAL VERIFIED HISTORY", "eyebrow muted")
    c.txt(24, 255, "6 entries", "metric")
    c.pill(174, 234, 143, "1 conflict", "amber")
    c.pill(329, 234, 164, "2 device reports", "blue")
    c.txt(908, 252, "2030-01-01 UTC · local receipt order, no global fact order", "body muted")
    c.line(24, 279, 1562, 279)

    c.card(24, 296, 1037, 675, "Verified history", "newest local receipt first")
    for x, w, label, tone in ((46, 104, "All · 6", "green"), (161, 112, "Facts · 3", "neutral"),
                              (284, 128, "Reports · 2", "neutral"), (423, 134, "Conflicts · 1", "amber")):
        c.pill(x, 364, w, label, tone)
    c.button(861, 361, 178, "Export filtered")
    c.line(24, 412, 1061, 412, kind="panel-section")
    for x, label in ((47, "LOCAL RECEIPT"), (169, "SOURCE"), (381, "KIND / SUBJECT"), (861, "DISPLAY")):
        c.txt(x, 440, label, "eyebrow muted")
    c.line(24, 456, 1061, 456, kind="table-rule")
    entries = (
        ("10:42:17", "demo-control-a", "Material accepted", "demo-policy grant → demo-phone-f", "local only", "amber"),
        ("10:40:05", "old member set", "Member certificate", "demo-control-b in current member chain", "effective", "green"),
        ("10:35:11", "demo-phone-f", "Signed device report", "demo-video · HTTPS business result", "available", "green"),
        ("10:24:46", "demo-control-a", "Conflicting facts", "demo-work · concurrent update", "suspended", "red"),
        ("10:10:20", "demo-phone-f", "Observation expired", "demo-work · previous scope is stale", "unknown", "amber"),
        ("09:55:02", "demo-forward-c", "Signed device report", "current View · process and ACL", "running", "green"),
    )
    for i, (stamp, source, kind, subject, effect, tone) in enumerate(entries):
        top = 456 + i * 76
        c.txt(47, top + 42, stamp, "body mono")
        c.txt(169, top + 42, source, "body mono")
        c.txt(381, top + 31, kind, "body")
        c.txt(381, top + 52, subject, "small muted")
        c.pill(861, top + 24, 153, effect, tone)
        c.line(24, top + 76, 1061, top + 76, kind="table-rule")
    c.txt(47, 946, "Receipt times only sort this view; verified facts and authenticated reports remain the sources.", "small muted")

    c.card(1077, 296, 485, 416, "Filter events", "view control · no state write")
    search_control(c, 1099, 364, 441, "Search object or DeviceID")
    c.txt(1099, 434, "KIND", "eyebrow muted")
    for x, w, label, tone in ((1099, 80, "All", "green"), (1191, 92, "Facts", "neutral"),
                              (1295, 104, "Reports", "neutral"), (1411, 128, "Conflicts", "neutral")):
        c.pill(x, 448, w, label, tone)
    c.field(1099, 506, "Issuer or device", "All verified sources  ▾", 441)
    c.field(1099, 588, "Object scope", "All objects  ▾", 211)
    c.field(1329, 588, "Local window", "Last 24 hours  ▾", 211)
    c.button(1099, 660, 134, "Apply filter", True)
    c.button(1245, 660, 116, "Clear")

    c.card(1077, 728, 485, 243, "State semantics", "projection + observations")
    for y, label, detail, tone in ((812, "Ordinary fact", "Accepted here; peer delivery separate", "green"),
                                   (852, "Member change", "Old-member majority certificate", "blue"),
                                   (892, "Conflict", "Only affected target is suspended", "red"),
                                   (932, "Observation", "Expired or mismatched → unknown", "amber")):
        c.pill(1099, y - 16, 136, label, tone, 25)
        c.txt(1247, y, detail, "small muted")
    return c


def signed_state() -> Canvas:
    c = Canvas("signed-state", "Signed state", "Inspect verified facts, local issuer frontiers and the targets affected by conflicts.", "control / facts", "signed-state")
    status_strip(c, [("Network anchor", "verified", "demo-network"), ("Control members", "2", "current member certificate"), ("Known issuers", "2", "independent local frontiers"), ("Conflicts", "1 target", "demo-work suspended")])
    tabs(c, ("Verified facts", "Members", "Conflicts", "Admin trust"), "Verified facts")
    c.card(24, 335, 966, 636, "Fact projection", "read-only · local to demo-control-a")
    search_control(c, 45, 399, 397, "Find a target, issuer or fact")
    c.rect(454, 399, 190, 38, "#FFFFFF", "#DAE3DC", 5)
    c.txt(467, 423, "All fact types", "small"); c.icon("icon-chevron", 616, 410)
    c.pill(780, 404, 188, "1 suspended target", "amber")
    for x, label in ((47, "TARGET"), (275, "TYPE / SCOPE"), (509, "ISSUER / SEQUENCE"), (805, "PROJECTION")):
        c.txt(x, 469, label, "eyebrow muted")
    c.line(24, 483, 990, 483, kind="table-rule")
    rows = (
        ("demo-video", "Service", "Matcher + probe scope", "demo-control-a", "23", "effective", "green"),
        ("demo-policy", "Policy grant", "demo-phone-f → demo-video", "demo-control-a", "24", "effective", "green"),
        ("demo-link-wg", "NetworkLink", "WG · explicit relay", "demo-control-a", "22", "effective", "green"),
        ("demo-work", "Service conflict", "2 incompatible updates", "demo-control-a / b", "21 / 18", "suspended", "amber"),
        ("demo-lan-policy", "LAN Policy", "demo-forward-c mapping", "demo-control-b", "17", "effective", "green"),
    )
    for i, (target, kind, detail, issuer, seq, state, tone) in enumerate(rows):
        top = 483 + i * 78
        yy = top + 30
        if target == "demo-work":
            c.rect(25, top, 964, 78, "#FFF9EF", "none", 0)
            c.rect(25, top, 3, 78, "#D2A45B", "none", 0)
        c.txt(47, yy + 11, target, "body mono")
        c.txt(275, yy, kind, "body")
        c.txt(275, yy + 23, detail, "tiny muted")
        c.txt(509, yy, issuer, "small mono")
        c.txt(509, yy + 23, "Local verified sequence · " + seq, "tiny muted")
        c.pill(805, yy - 7, 140, state, tone, 26)
        c.txt(966, yy + 11, "›", "body muted", "end")
        c.line(24, top + 78, 990, top + 78, kind="table-rule")
    c.icon("icon-lock", 47, 896)
    c.txt(73, 909, "Facts are inspected here. Changes submit a scoped management operation.", "small muted")
    c.txt(47, 944, "Each issuer has its own sequence. This control shows the facts it has verified.", "small muted")

    c.card(1006, 335, 556, 207, "Local verified frontiers", "independent issuer chains")
    for y, issuer, seq in ((410, "demo-control-a", "24"), (453, "demo-control-b", "18")):
        c.icon("icon-signed", 1028, y - 14)
        c.txt(1054, y, issuer, "body mono")
        c.txt(1375, y, "sequence", "small muted")
        c.txt(1539, y, seq, "body mono", "end")
        c.line(1006, y + 15, 1562, y + 15, kind="table-rule")
    c.txt(1028, 511, "Latest local fact at peers", "small muted")
    c.txt(1540, 511, "unknown", "small amber", "end")

    c.card(1006, 558, 556, 413, "demo-work", "selected conflict")
    c.pill(1028, 622, 136, "suspended", "amber", 26)
    c.txt(1180, 640, "Service projection is paused", "small")
    c.txt(1028, 688, "CONFLICTING VERIFIED FACTS", "eyebrow muted")
    for y, name, issuer in ((720, "demo-work-update-a", "demo-control-a · seq 21"), (754, "demo-work-update-b", "demo-control-b · seq 18")):
        c.txt(1028, y, name, "small mono")
        c.txt(1540, y, issuer, "tiny muted", "end")
    c.note(1028, 781, 512, ("This Service has no active matcher or eligible path.", "Unrelated Services remain available for projection."), "amber")
    c.button(1028, 867, 167, "Resolve conflict", True)
    c.button(1207, 867, 148, "Inspect facts")
    c.txt(1028, 939, "Resolution submits a new fact referencing both conflicting facts.", "tiny muted")
    return c


def add_device() -> Canvas:
    c = Canvas("add-device", "Add device", "Issue a bounded Invite, bind the device key, then read authorization and runtime separately.", "enrollment", "nodes")
    c.txt(24, 217, "INVITE WORKFLOW", "eyebrow muted")
    timeline(c, 226, 230, 973, ("Delivery", "Scope", "Issue", "Bind", "Readback"), 1)
    c.pill(1357, 205, 205, "Draft · not issued", "amber")
    c.line(24, 279, 1562, 279)
    c.card(24, 296, 499, 675, "Choose delivery", "private bootstrap tunnel")
    for y, title, detail, icon in ((360,"SSH direct add","Operator reaches a target host","icon-terminal"),(466,"Bootstrap script","Target fetches a bounded artifact","icon-code"),(572,"QR code","Mobile access role only","icon-qr")):
        c.rect(46, y, 454, 86, "#F5F9F6" if y == 360 else "#FFFFFF", "#CDE4D4" if y == 360 else "#E1E8E2", 6)
        if y == 360:
            c.rect(46, y, 3, 86, "#2AA875", "none", 1)
        c.add(f'<use href="#{icon}" x="66" y="{y+22}" width="21" height="21" class="nav-icon"/>')
        c.txt(100, y+35, title, "body")
        c.txt(100, y+61, detail, "small muted")
    c.note(46, 723, 454, ("QR Invite can grant access only.", "Every Invite fixes one issuer and target ID."), "amber")
    c.card(539, 296, 604, 675, "Invite details", "SSH direct add")
    c.field(561, 370, "Target device ID", "demo-laptop", 559)
    c.field(561, 445, "Platform", "Windows", 270)
    c.field(850, 445, "Issuer", "demo-control-a", 270)
    c.txt(561, 534, "Requested roles", "small muted")
    for i, (label, tone) in enumerate((("access", "green"),("forward", "neutral"),("internet_egress", "neutral"),("control", "neutral"))):
        xx = 561 + i * 139
        c.rect(xx, 548, 130, 31, "#ECF7F0" if i == 0 else "#F4F5F4", "#C8E5D1" if i == 0 else "#E4E8E5", 5)
        c.rect(xx + 8, 558, 11, 11, "#248F64" if i == 0 else "#E9EDE9", "#248F64" if i == 0 else "#C8CECA", 2)
        if i == 0:
            c.txt(xx + 14, 567, "✓", "micro white", "middle")
        c.txt(xx + 25, 568, label, "small green" if i == 0 else "small faint")
    c.txt(561, 602, "Windows supports access. Other roles are disabled for this platform.", "small muted")
    c.field(561, 626, "Policy grants", "demo-policy  ▾  (covers demo-video)", 559)
    c.field(561, 705, "Invite validity", "24 hours from issue  ▾", 559)
    c.button(561, 801, 164, "Issue Invite", True)
    c.line(539, 860, 1143, 860, kind="panel-section")
    c.txt(561, 890, "ISSUED INVITE PREVIEW", "eyebrow muted")
    c.txt(561, 916, "Issuer demo-control-a · demo-laptop · Windows · access", "small mono")
    c.txt(561, 941, "Exact grant demo-policy · first claim only at issuer", "small muted")
    c.card(1159, 296, 403, 675, "After issue", "normal device")
    c.add('<line x1="1194" y1="380" x2="1194" y2="665" stroke="#D4E6D9" stroke-width="2"/>')
    c.step(1181, 367, 1, "Issue Invite", "Admin approval occurs here", "neutral")
    c.step(1181, 462, 2, "Bind device key", "Issuer authenticates first claim", "neutral")
    c.step(1181, 557, 3, "Read authorization", "Signed fact accepted locally", "neutral")
    c.step(1181, 652, 4, "Read runtime", "Require fresh matching reports", "neutral")
    c.note(1181, 769, 359, ("If control is requested, the bound join", "waits for old-member majority.", "No role is effective before it forms."), "amber")
    c.txt(1181, 894, "Normal join: no second approval.", "small green")
    c.txt(1181, 920, "Ready requires a fresh matching report", "small muted")
    c.txt(1181, 940, "from device and selected path nodes.", "small muted")
    return c


def release_platform(platform: str) -> Canvas:
    title = platform.title()
    target = {"linux": "demo-forward-c", "android": "demo-phone-f", "windows": "No enrolled target"}[platform]
    examples = {
        "linux": (("demo-linux-agent", "demo-1.2.0", "sha256:6b…", "node package"), ("demo-linux-cli", "demo-1.2.0", "sha256:2d…", "generic public"), ("demo-linux-ui", "demo-1.2.0", "sha256:4a…", "generic public")),
        "android": (("demo-android-app", "demo-1.2.0", "sha256:a3…", "enrolled device"), ("demo-android-apk", "demo-1.2.0", "sha256:9c…", "generic public"), ("demo-android-symbols", "demo-1.2.0", "sha256:0f…", "restricted")),
        "windows": (("demo-windows-app", "demo-1.2.0", "sha256:88…", "enrolled device"), ("demo-windows-installer", "demo-1.2.0", "sha256:53…", "generic public"), ("demo-windows-portable", "demo-1.2.0", "sha256:71…", "generic public")),
    }[platform]
    c = Canvas(f"releases-{platform}", f"{title} releases", "Verified immutable artifacts are distinct from desired state and applied readback.", "releases", f"releases-{platform}")
    c.rect(24, 196, 1538, 83, "#F5FAF7", "#D6E8DB", 7)
    c.circle(56, 236, 18, "#E6F4EA", "#B7DDC4")
    c.txt(56, 241, "✓", "body green", "middle")
    c.txt(92, 230, f"{title} catalog · generation demo-42 · publisher signature verified", "section")
    c.txt(92, 256, "Three exact artifacts verified; desired digest and actual application are read separately.", "small muted")
    c.pill(1370, 221, 165, "matching readback" if platform == "linux" else "readback unknown", "green" if platform == "linux" else "amber")
    release_tabs(c, title)
    c.card(24, 335, 402, 393, "Catalog trust")
    c.pill(280, 348, 124, "verified", "green", 26)
    for y, label, value in ((423,"Generation","demo-42"),(469,"Publisher key","protected install input"),(515,"Platform",title),(561,"Catalog signature","valid"),(607,"File digests","3 / 3 verified")):
        c.txt(46, y, label.upper(), "eyebrow muted")
        c.txt(225, y, value, "body mono" if y != 469 else "small")
        c.line(24, y+16, 426, y+16, kind="table-rule")
    c.note(46, 646, 358, ("The mutable current pointer selects", "a catalog to verify; it grants no trust."), "blue")
    c.card(442, 335, 1120, 393, f"{title} artifacts", "exact files from a verified catalog")
    c.rows(465, 410, (270, 171, 215, 196, 222), ("Component", "Version", "Digest", "Audience", "Verification"), [(a,b,d,e,"signature + bytes") for a,b,d,e in examples], 76, edges=(442, 1562))
    c.txt(465, 694, "Only certified generic public files may be served from public distribution.", "small muted")
    c.button(1351, 673, 188, "View file details")
    c.card(24, 744, 842, 227, "Release verification", "each stage uses its own evidence")
    timeline(c, 72, 843, 748, ("Catalog", "Signature", "File digest", "Desired", "Readback"), {"linux": 5, "android": 4, "windows": 3}[platform], pending=platform != "windows")
    c.txt(47, 924, "A signed catalog does not state what a device currently runs.", "small muted")
    c.card(882, 744, 680, 227, "Target readback")
    readback = (
        ("Device ID", target),
        ("Desired digest", examples[0][2] if platform != "windows" else "none · no enrolled target"),
        ("Applied digest", examples[0][2] if platform == "linux" else "unknown"),
        ("Report evidence", "fresh · matching component + platform" if platform == "linux" else "no fresh matching report"),
    )
    for i, (label, value) in enumerate(readback):
        y = 824 + i * 32
        c.txt(905, y, label.upper(), "eyebrow muted")
        c.txt(1084, y, value, "small mono" if i in (0, 1, 2) else "small")
        if i < len(readback) - 1:
            c.line(882, y + 10, 1562, y + 10, kind="table-rule")
    c.pill(1398, 757, 140, "matching" if platform == "linux" else "unknown", "green" if platform == "linux" else "amber", 26)
    c.txt(905, 950, "Minimum compatibility applies only if signed and comparable.", "tiny muted")
    return c


def guest_entry() -> Canvas:
    c = Canvas("guest-entry", "Loom private control center", "This private site is reachable from an enrolled access device.", "private entry", "overview")
    c.parts.clear()
    compound, transform = logo_geometry()
    c.add('<rect width="1586" height="992" fill="#F8FAF8"/>')
    c.add('<rect width="1586" height="58" fill="#FFFFFF"/>')
    c.line(0, 57, 1586, 57)
    c.add(f'<svg x="18" y="8" width="39" height="39" viewBox="127 112 1000 1000"><g transform="{transform}"><path d="{compound}" fill="#252927" fill-rule="evenodd" clip-rule="evenodd"/></g></svg>')
    c.txt(65, 36, "LOOM", "section")
    c.txt(1546, 35, "PRIVATE SITE", "eyebrow muted", "end")
    c.rect(375, 214, 836, 604, "#FFFFFF", "#DFE8E1", 12, panel=True)
    c.circle(793, 334, 47, "#EAF6EE", "#C9E5D3")
    c.icon("icon-lock", 776, 317, 34)
    c.txt(793, 432, "Private site reached", "title", "middle")
    c.txt(793, 470, "https://control.loom/", "body mono muted", "middle")
    c.line(375, 500, 1211, 500, kind="panel-section")
    c.txt(793, 547, "Management requires an authorized admin client certificate.", "body", "middle")
    c.txt(793, 581, "Install the certificate package delivered through the protected operator channel.", "body muted", "middle")
    c.step(477, 616, 1, "Receive the admin package", "Control creates admin.p12 and a separate password file")
    c.step(477, 676, 2, "Import into your browser", "Reload through the trusted private HTTPS address")
    c.note(465, 716, 656, ("No device list, member state, topology, events or management snapshot", "is available here without an authorized admin certificate."), "blue")
    return c


def observations() -> Canvas:
    c = Canvas("observations", "Observation states", "Authorization, reachability, business probes and deployment evidence are separate.", "operations", "live-paths")
    status_strip(c, [("Device grant", "effective", "demo-policy"), ("Transport", "available", "fresh handshake"), ("demo-work probe", "unknown", "historical result expired"), ("Deployment", "unknown", "no readback")])
    c.card(24, 298, 1538, 448, "Evidence matrix", "current evidence")
    c.rows(47, 372, (315, 390, 371, 405), ("Layer", "Evidence source", "Current display", "Rule"), [
        ("Authorization", "signed DeviceAuthorization", "effective", "changes via new fact"),
        ("Resource", "real transport action", "available", "scoped to one resource"),
        ("demo-link-hy2", "matching LinkID digest absent", "unknown", "WG result cannot substitute"),
        ("demo-work HTTPS", "expired historical probe", "unknown", "demo-video cannot substitute"),
        ("Applied component", "report absent", "unknown", "catalog cannot substitute"),
    ], 62, True, edges=(24, 1562))
    c.txt(47, 723, "demo-work is also suspended by conflicting facts; its historical result cannot restore an eligible candidate.", "small amber")
    c.card(24, 763, 756, 208, "Known result", "available / unavailable")
    c.txt(47, 844, "Only a current matching action can fill these states.", "body")
    c.pill(47, 860, 141, "available", "green"); c.pill(201, 860, 155, "unavailable", "red")
    c.card(796, 763, 766, 208, "Missing or mismatched", "unknown")
    c.txt(819, 844, "No report, expired report or wrong digest resolves to unknown.", "body")
    c.pill(819, 860, 141, "unknown", "amber")
    return c


def operations() -> Canvas:
    c = Canvas("operations", "Operation feedback", "Typed management operations return local acceptance and separate propagation.", "operations", "signed-state")
    status_strip(c, [("Admin certificate", "valid", "exact trusted leaf"), ("Object baseline", "current", "demo-policy"), ("Local result", "accepted", "fact persisted"), ("Peer delivery", "unknown", "await frontier")])
    c.card(24, 297, 769, 674, "Edit a policy grant", "normal fact · one control signs")
    c.field(47, 367, "Target", "demo-policy", 350)
    c.field(416, 367, "Object causal basis", "fact:demo-policy-previous", 352)
    c.field(47, 451, "Operation", "Grant demo-phone-f demo-policy", 721)
    c.field(47, 535, "Stable request ID", "demo-request-001", 721)
    c.button(47, 630, 166, "Submit operation", True)
    c.note(47, 696, 721, ("A stale object baseline returns conflict and preserves this draft.", "The browser submits only the affected object's causal basis."), "amber")
    c.line(24, 791, 793, 791, kind="panel-section")
    c.txt(47, 823, "SIGNED FACT PREVIEW", "eyebrow muted")
    c.txt(47, 852, "target: demo-policy   operation: grant demo-phone-f", "body mono")
    c.txt(47, 879, "request_id: demo-request-001   issuer: demo-control-a", "body mono")
    c.txt(47, 924, "The request ID makes retries return the same accepted fact.", "small muted")
    c.card(809, 297, 753, 674, "Result timeline", "local ≠ fleet")
    c.add('<line x1="845" y1="383" x2="845" y2="707" stroke="#DCE9DF" stroke-width="2"/>')
    c.step(832, 370, 1, "Accepted locally", "Issuer verified and persisted one signed fact")
    c.pill(1381, 363, 155, "accepted", "green")
    c.step(832, 478, 2, "Propagating", "Other control frontiers are still unknown", "amber")
    c.pill(1381, 471, 155, "unknown", "amber")
    c.step(832, 586, 3, "Device View", "Available after each control projects the fact", "amber")
    c.pill(1381, 579, 155, "unknown", "amber")
    c.step(832, 694, 4, "Runtime result", "Requires fresh report and actual Service action", "amber")
    c.pill(1381, 687, 155, "unknown", "amber")
    c.note(832, 829, 707, ("Only control membership changes wait for an old-member majority certificate.",), "blue")
    c.txt(832, 925, "A local response does not claim immediate delivery to every control or device.", "small muted")
    return c


def enrollment() -> Canvas:
    c = Canvas("enrollment", "Enrollment states", "Ordinary joining and control joining share the Invite and binding path.", "operations", "nodes")
    status_strip(c, [("Access join", "authorized", "ordinary signed fact"), ("Control join", "pending", "member certificate required"), ("Member signatures", "1 / 2", "same successor proposal"), ("Ready", "unknown", "runtime checked separately")])
    c.card(24, 298, 748, 673, "Ordinary access join", "no second approval")
    c.step(47, 374, 1, "Invite issued", "Issuer, target, role, grants and expiry fixed")
    c.step(47, 476, 2, "Key bound", "First claim to the issuing control")
    c.step(47, 578, 3, "Authorized", "Issuer signs the ordinary authorization")
    c.step(47, 680, 4, "Ready · unknown", "Needs current device and path reports", "amber")
    c.note(47, 821, 702, ("There is no awaiting approval state after a signed Invite.",), "green")
    c.card(788, 298, 774, 673, "Control join", "old members sign one successor table")
    c.step(811, 374, 1, "Invite and key bound", "Same issuer-bound first claim")
    c.step(811, 476, 2, "Conditional ordinary roles", "Not effective before member certificate", "amber")
    c.step(811, 578, 3, "Waiting for majority · 1 / 2", "Existing members sign the same successor", "amber")
    c.step(811, 680, 4, "Member certificate · pending", "No control qualification before this certificate", "neutral")
    c.rect(811, 738, 728, 118, "#FBFCFB", "#E1E8E2", 6)
    c.txt(830, 763, "CURRENT MEMBERS", "eyebrow muted")
    c.txt(830, 795, "demo-control-a", "small mono")
    c.txt(1519, 795, "signature received", "small green", "end")
    c.line(811, 808, 1539, 808, kind="table-rule")
    c.txt(830, 835, "demo-control-b", "small mono")
    c.txt(1519, 835, "signature pending", "small amber", "end")
    c.note(811, 878, 728, ("Canceling a bound control join stays pending until a safe", "majority certificate voids it or the inherited join is resolved."), "amber")
    return c


def certificates() -> Canvas:
    c = Canvas("certificates", "Web certificates", "Admin-only expiry display for serving private Web entry points.", "operations", "signed-state")
    status_strip(c, [("Entry", "control.loom", "private DNS"), ("Local leaf", "24 days", "renewal reminder"), ("Peer leaf", "unknown", "stale readback"), ("Admin identity", "trusted leaf", "separate certificate")])
    c.card(24, 297, 972, 407, "Serving Web entries", "UTC · 2030-01-01")
    c.rows(47, 371, (292, 245, 209, 179), ("Control", "Leaf NotAfter UTC", "Remaining", "Status"), [("demo-control-a", "2030-01-25 00:00", "24 days", "renew soon"), ("demo-control-b", "unknown", "unknown", "unknown")], 91, True, edges=(24, 996))
    c.note(47, 616, 924, ("At 30 days remaining, admin sees a reminder. A missing or stale peer readback stays unknown.",), "amber")
    c.card(1012, 297, 550, 407, "Trust boundary", "two certificate uses")
    c.txt(1035, 371, "Website leaf", "body"); c.txt(1035, 400, "SAN exactly control.loom", "small muted")
    c.txt(1035, 457, "Admin client leaf", "body"); c.txt(1035, 486, "Exact trusted leaf authorizes management", "small muted")
    c.txt(1035, 543, "Offline website root", "body"); c.txt(1035, 572, "Root private key stays off control hosts", "small muted")
    c.card(24, 720, 1538, 251, "Renewal sequence", "manual operator action")
    c.step(47, 786, 1, "Generate bound CSR", "Control keeps its leaf private key")
    c.step(504, 786, 2, "Sign offline", "Operator verifies member, SNI and purpose")
    c.step(1007, 786, 3, "Preflight and read back", "Prepared TLS, serving browser, then retire old leaf")
    c.note(47, 877, 1492, ("Expired leaf: new TLS connections fail closed. Protected local CLI remains the diagnostic path.",), "amber")
    return c


PAGES = {
    "overview": overview,
    "nodes": nodes,
    "node-detail": node_detail,
    "topology": topology,
    "live-paths": live_paths,
    "services": services,
    "services-dns": services_dns,
    "node-lan-mapping": node_lan_mapping,
    "deployments": deployments,
    "events": events,
    "signed-state": signed_state,
    "add-device": add_device,
    "releases-linux": lambda: release_platform("linux"),
    "releases-android": lambda: release_platform("android"),
    "releases-windows": lambda: release_platform("windows"),
    "guest-entry": guest_entry,
    "observations": observations,
    "operations": operations,
    "enrollment": enrollment,
    "certificates": certificates,
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
