#!/usr/bin/env python3
"""Generate the editable Loom control-center interface prototypes.

The prototypes intentionally use only native SVG primitives and the Loom vector
mark.  They are a product/design target, not screenshots of the currently
deployed SSR interface.
"""

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
HEADER_LOGO = ASSETS / "loom-logo-transparent-titanium.svg"
SVG_NS = "http://www.w3.org/2000/svg"
LOGO_FILL = "#252927"


def approved_logo_geometry() -> tuple[str, str]:
    """Return the approved mark as one self-contained compound path."""
    source = ASSETS / "loom-logo-v4.svg"
    root = ET.parse(source).getroot()
    group = root.find(f".//{{{SVG_NS}}}g")
    if group is None:
        raise RuntimeError(f"{source} has no path group")
    paths = group.findall(f"{{{SVG_NS}}}path")
    if len(paths) < 2:
        raise RuntimeError(f"{source} does not contain the approved compound mark")
    compound = " ".join(path.attrib["d"].strip() for path in paths)
    transform = group.attrib.get(
        "transform", "translate(0.000000,1254.000000) scale(1.000000,-1.000000)"
    )
    return compound, transform


def inline_header_logo() -> str:
    """Embed plain vector geometry so a prototype has no external resources."""
    compound, transform = approved_logo_geometry()
    return f'''  <svg x="18" y="7" width="36" height="36"
       viewBox="127 112 1000 1000" preserveAspectRatio="xMidYMid meet"
       aria-label="Loom">
    <g transform="{transform}">
      <path d="{compound}" fill="{LOGO_FILL}" fill-rule="evenodd" clip-rule="evenodd"/>
    </g>
  </svg>'''


def generate_header_logo() -> None:
    """Build a mask-free dark graphite mark from the approved compound paths.

    The former transparent variant used a luminance mask. Some SVG viewers
    render that mask as white, making the mark disappear on the white header.
    A single even-odd compound path preserves the same negative spaces without
    a mask, CSS recoloring, or a background rectangle.
    """
    compound, transform = approved_logo_geometry()
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="{SVG_NS}" width="1000" height="1000" viewBox="127 112 1000 1000"
     preserveAspectRatio="xMidYMid meet" role="img" aria-labelledby="logo-title logo-desc">
  <title id="logo-title">Loom logo</title>
  <desc id="logo-desc">A smooth six-petal woven knot in dark graphite on a transparent background.</desc>
  <g transform="{transform}">
    <path d="{compound}" fill="{LOGO_FILL}" fill-rule="evenodd" clip-rule="evenodd"/>
  </g>
</svg>
'''
    HEADER_LOGO.write_text(svg, encoding="utf-8")


STYLE = r"""
      .ui { font-family: Inter, "Atkinson Hyperlegible Next", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; fill: #181B1A; }
      .mono { font-family: "Intel One Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
      .muted { fill: #717674; }
      .faint { fill: #9BA09E; }
      .green { fill: #239B68; }
      .amber { fill: #A66A14; }
      .red { fill: #B84C4C; }
      .blue { fill: #477D9C; }
      .heading { font-size: 28px; font-weight: 700; letter-spacing: -0.45px; }
      .eyebrow { font-size: 12px; font-weight: 600; letter-spacing: 1.35px; }
      .section { font-size: 16px; font-weight: 650; letter-spacing: -0.15px; }
      .subsection { font-size: 13px; font-weight: 650; }
      .label { font-size: 13px; font-weight: 500; }
      .body { font-size: 13px; font-weight: 400; }
      .small { font-size: 12px; font-weight: 400; }
      .tiny { font-size: 11px; font-weight: 400; }
      .metric { font-size: 17px; font-weight: 650; }
      .wordmark { font-size: 20px; font-weight: 700; letter-spacing: 0.8px; }
      .nav { font-size: 13px; font-weight: 450; }
      .nav-icon { fill: none; stroke: #7D8280; stroke-width: 1.35; stroke-linecap: round; stroke-linejoin: round; }
      .nav-icon-active { fill: none; stroke: #181B1A; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
      .status-icon { fill: none; stroke: #2AA875; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }
      .action-icon { fill: none; stroke: #5B6166; stroke-width: 1.45; stroke-linecap: round; stroke-linejoin: round; }
      .panel { fill: #FFFFFF; stroke: #E4E7E5; stroke-width: 1; }
      .panel-soft { fill: #F8F9F8; stroke: #E4E7E5; stroke-width: 1; }
      .rule { stroke: #E6E9E7; stroke-width: 1; }
      .rule-dark { stroke: #CBD0CD; stroke-width: 1; }
      .status-dot { fill: #2AA875; }
      .quiet-dot { fill: #72C69F; }
      .warn-dot { fill: #D79B3B; }
      .bad-dot { fill: #C65A5A; }
      .neutral-dot { fill: #A5AAA8; }
      .wg { fill: none; stroke: #A5AAA8; stroke-width: 1.25; stroke-linecap: round; }
      .candidate { fill: none; stroke: #B9BEBC; stroke-width: 1.35; stroke-dasharray: 5 6; stroke-linecap: round; }
      .selected { fill: none; stroke: #2AA875; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; marker-end: url(#arrow-selected); }
      .chip { fill: #F4F6F5; stroke: #DEE2DF; stroke-width: 1; }
      .chip-green { fill: #EEF8F3; stroke: #B9DEC9; stroke-width: 1; }
      .chip-amber { fill: #FFF8EB; stroke: #E7D3AB; stroke-width: 1; }
      .button { fill: #181B1A; }
      .button-green { fill: #239B68; }
      .button-disabled { fill: #EFF1F0; stroke: #DDE1DF; stroke-width: 1; }
      .code-bg { fill: #F7F8F7; stroke: #E4E7E5; stroke-width: 1; }
      .timeline { fill: none; stroke: #CBD0CD; stroke-width: 1.3; }
      .timeline-ok { fill: none; stroke: #2AA875; stroke-width: 1.7; }
      .stage-line { stroke: #2AA875; stroke-width: 1.5; }
      .route-dot { fill: #239B68; }
      .node-name { font-size: 14px; font-weight: 650; }
"""


NAV_ITEMS = {
    "Overview": (295, 293, 382, "icon-overview"),
    "Nodes": (397, 395, 466, "icon-nodes"),
    "Topology": (481, 479, 569, "icon-topology"),
    "Services": (584, 582, 669, "icon-services"),
    "Routing": (682, 680, 769, "icon-traffic"),
    "Deployments": (780, 778, 906, "icon-deployments"),
    "Events": (919, 917, 995, "icon-events"),
    "Settings": (1008, 1006, 1094, "icon-settings"),
}


def shell(*, active: str, eyebrow: str, title: str, subtitle: str,
          status: str, description: str, body: str,
          environment_status: str = "Operational",
          session_status: str = "Read-only view") -> str:
    _, active_left, active_right, _ = NAV_ITEMS[active]
    nav = []
    for label, (x, _, _, icon_id) in NAV_ITEMS.items():
        display_label = {"Routing": "Live paths", "Settings": "SSOT"}.get(label, label)
        weight = ' font-weight="600"' if label == active else ""
        icon_class = "nav-icon-active" if label == active else "nav-icon"
        nav.append(f'    <use href="#{icon_id}" x="{x}" y="18" width="14" height="14" class="{icon_class}"/>')
        nav.append(f'    <text x="{x + 21}" y="31"{weight}>{display_label}</text>')
    nav_text = "\n".join(nav)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="1586" height="992" viewBox="0 0 1586 992"
     role="img" aria-labelledby="title description">
  <title id="title">{title} — Loom control center prototype</title>
  <desc id="description">{description}</desc>
  <defs>
    <marker id="arrow-selected" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto" markerUnits="strokeWidth">
      <path d="M0 0L7 3.5L0 7Z" fill="#2AA875"/>
    </marker>
    <symbol id="icon-overview" viewBox="0 0 16 16">
      <rect x="1.5" y="1.5" width="5" height="5" rx="1"/><rect x="9.5" y="1.5" width="5" height="5" rx="1"/>
      <rect x="1.5" y="9.5" width="5" height="5" rx="1"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/>
    </symbol>
    <symbol id="icon-nodes" viewBox="0 0 16 16">
      <rect x="2" y="2" width="12" height="5" rx="1.4"/><rect x="2" y="9" width="12" height="5" rx="1.4"/>
      <circle cx="4.5" cy="4.5" r=".7"/><circle cx="4.5" cy="11.5" r=".7"/>
      <path d="M7 4.5h4.5M7 11.5h4.5"/>
    </symbol>
    <symbol id="icon-topology" viewBox="0 0 16 16">
      <path d="M4.2 4.2L8 8m3.8-3.8L8 8m0 0v4.4"/><circle cx="3" cy="3" r="1.8"/><circle cx="13" cy="3" r="1.8"/><circle cx="8" cy="13.5" r="1.8"/>
    </symbol>
    <symbol id="icon-services" viewBox="0 0 16 16">
      <rect x="2" y="2" width="12" height="12" rx="2"/><path d="M5 5h6M5 8h6M5 11h4"/>
    </symbol>
    <symbol id="icon-traffic" viewBox="0 0 16 16">
      <path d="M2 4h4.2C9 4 8.2 12 11 12h2.5M2 12h3.5C8.4 12 7.7 4 10.7 4h2.8"/><path d="M11.5 2l2 2-2 2m0 4l2 2-2 2"/>
    </symbol>
    <symbol id="icon-deployments" viewBox="0 0 16 16">
      <rect x="2" y="3" width="12" height="10.5" rx="2"/><path d="M5 3V1.5h6V3M8 6v4m-2-2 2 2 2-2"/>
    </symbol>
    <symbol id="icon-events" viewBox="0 0 16 16">
      <circle cx="8" cy="8" r="6.2"/><path d="M8 4.5V8l2.5 1.5"/>
    </symbol>
    <symbol id="icon-settings" viewBox="0 0 16 16">
      <path d="M2 4h5m3 0h4M2 8h2m3 0h7M2 12h7m3 0h2"/><circle cx="8.5" cy="4" r="1.5"/><circle cx="5.5" cy="8" r="1.5"/><circle cx="10.5" cy="12" r="1.5"/>
    </symbol>
    <symbol id="icon-status-ok" viewBox="0 0 16 16">
      <circle cx="8" cy="8" r="6.2"/><path d="M5 8.1l2 2 4-4.2"/>
    </symbol>
    <symbol id="icon-lock" viewBox="0 0 16 16">
      <rect x="3" y="7" width="10" height="7" rx="1.8"/><path d="M5.2 7V5a2.8 2.8 0 0 1 5.6 0v2"/>
    </symbol>
    <symbol id="icon-refresh" viewBox="0 0 16 16">
      <path d="M13.6 5.8A6 6 0 1 0 14 9"/><path d="M10.8 2.7h3v3"/>
    </symbol>
    <symbol id="icon-filter" viewBox="0 0 16 16">
      <path d="M2 3h12L9.5 8v4.2L6.5 14V8Z"/>
    </symbol>
    <symbol id="icon-download" viewBox="0 0 16 16">
      <path d="M8 2v8m-3-3 3 3 3-3M2.5 13.5h11"/>
    </symbol>
    <symbol id="icon-check" viewBox="0 0 16 16">
      <circle cx="8" cy="8" r="6"/><path d="M5 8l2 2 4-4"/>
    </symbol>
    <symbol id="icon-save" viewBox="0 0 16 16">
      <path d="M2.5 2.5h9l2 2v9h-11Z"/><path d="M5 2.5v4h6v-4M5 13v-4h6v4"/>
    </symbol>
    <symbol id="icon-plus" viewBox="0 0 16 16">
      <path d="M8 3v10M3 8h10"/>
    </symbol>
    <symbol id="icon-search" viewBox="0 0 16 16">
      <circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/>
    </symbol>
    <symbol id="icon-arrow-right" viewBox="0 0 16 16">
      <path d="M2.5 8h10M9 4.5 12.5 8 9 11.5"/>
    </symbol>
    <symbol id="icon-edit" viewBox="0 0 16 16">
      <path d="M3 11.8 2.5 14l2.2-.5 8.2-8.2-1.7-1.7Z"/><path d="m10.3 4.5 1.7 1.7"/>
    </symbol>
    <symbol id="icon-trash" viewBox="0 0 16 16">
      <path d="M3.5 4.5h9M6 4.5V2.7h4v1.8m1.5 0-.6 9h-5.8l-.6-9M6.8 7v4m2.4-4v4"/>
    </symbol>
    <symbol id="icon-key" viewBox="0 0 16 16">
      <circle cx="5" cy="8" r="3"/><path d="M8 8h6m-2 0v2m-2-2v2"/>
    </symbol>
    <symbol id="icon-copy" viewBox="0 0 16 16">
      <rect x="5" y="5" width="8" height="8" rx="1.5"/><path d="M3 10.5H2.5V3.5a1 1 0 0 1 1-1h7V3"/>
    </symbol>
    <style><![CDATA[
{STYLE}
    ]]></style>
  </defs>

  <rect width="1586" height="992" fill="#FCFCFB"/>

  <!-- Shared horizontal header. -->
  <rect x="0" y="0" width="1586" height="50" fill="#FFFFFF"/>
  <line class="rule" x1="0" y1="49.5" x2="1586" y2="49.5"/>
{inline_header_logo()}
  <text class="ui wordmark" x="65" y="33">LOOM</text>
  <g class="ui nav">
{nav_text}
  </g>
  <line x1="{active_left}" y1="49.5" x2="{active_right}" y2="49.5" stroke="#2AA875" stroke-width="2"/>
  <g class="ui nav">
    <text class="amber" x="1160" y="31">Prototype · sample data</text>
    <circle class="status-dot" cx="1322" cy="26" r="4"/>
    <text x="1335" y="31">{environment_status}</text>
    <use href="#icon-lock" x="1428" y="18" width="14" height="14" class="nav-icon"/>
    <text x="1538" y="31" text-anchor="end">{session_status}</text>
  </g>

  <g class="ui">
    <text class="eyebrow" x="21" y="91">{eyebrow}</text>
    <text class="heading" x="21" y="124">{title}</text>
    <text class="body muted" x="21" y="151">{subtitle}</text>
    <use href="#icon-status-ok" x="20" y="168" width="15" height="15" class="status-icon"/>
    <text class="small" x="43" y="181">{status}</text>
  </g>

{body}
</svg>
'''


def overview_page() -> str:
    """Keep the approved overview body while rebuilding its shared shell.

    The overview predates this generator.  Its dashboard body remains the
    visual source; the shared shell is regenerated so navigation and embedded
    assets cannot drift from the other prototypes.
    """
    source = ASSETS / "loom-control-center-overview-misaka-v1.svg"
    text = source.read_text(encoding="utf-8")
    marker = "  <!-- Compact status strip -->"
    if marker not in text:
        raise RuntimeError(f"{source} is missing the overview body marker")
    body = (marker + text.split(marker, 1)[1].rsplit("</svg>", 1)[0]).rstrip()
    # The asset is the overview body's visual source. Fail fast if its contract
    # labels drift instead of silently rewriting copy by string substitution.
    required_copy = (
        '5 / 5 <tspan class="body" font-weight="400">healthy</tspan>',
        '6 / 6 <tspan class="body" font-weight="400">observed</tspan>',
        ">Healthy<",
        "Read-only · signed Agent decisions",
        "Latest fleet rollout",
        "Automatic routing",
        "24h trusted adjacent-sample deltas",
        "Retained centrally · 30 days · fixed 60s samples / 3m gap",
        "10 / 12 buckets · 1 reset · 1 gap",
        "Carrier edge gz02 ↔ sg02 recovered",
    )
    missing = [expected for expected in required_copy if expected not in body]
    if missing:
        raise RuntimeError(f"{source} overview contract labels drifted: {missing}")
    return shell(
        active="Overview",
        eyebrow="LIVE NETWORK",
        title="Network overview",
        subtitle="jm24 control plane · observed 8s ago",
        status="All declared nodes are healthy",
        description="A restrained infrastructure overview showing five nodes, six WireGuard links, read-only automatic routing decisions, deployment state, and retained WireGuard counter-delta bars with explicit reset and gap boundaries.",
        body=body,
    )


def nodes_page() -> str:
    body = r'''
  <!-- Fleet state and the only primary action. -->
  <rect class="panel" x="21" y="202" width="1538" height="82" rx="7"/>
  <g class="ui">
    <text class="small muted" x="46" y="232">DECLARED</text><text class="metric" x="46" y="258">5 nodes</text>
    <text class="small muted" x="300" y="232">HEALTH</text><text class="metric green" x="300" y="258">5 healthy</text>
    <text class="small muted" x="554" y="232">ENROLLMENT</text><text class="metric green" x="554" y="258">Available</text>
    <text class="small muted" x="808" y="232">SNAPSHOT</text><text class="metric" x="808" y="258">5 verified</text>
    <text class="small muted" x="1062" y="232">ISSUES</text><text class="metric green" x="1062" y="258">None</text>
    <rect class="button" x="1390" y="221" width="143" height="40" rx="6"/>
    <use href="#icon-plus" x="1411" y="233" width="15" height="15" stroke="#FFFFFF" fill="none" stroke-width="1.5" stroke-linecap="round"/>
    <text class="small" x="1437" y="246" fill="#FFFFFF">Add node</text><text class="tiny green" x="1457" y="278" text-anchor="middle">SSH guarded</text>
  </g>
  <line class="rule" x1="272" y1="222" x2="272" y2="265"/><line class="rule" x1="526" y1="222" x2="526" y2="265"/>
  <line class="rule" x1="780" y1="222" x2="780" y2="265"/><line class="rule" x1="1034" y1="222" x2="1034" y2="265"/>
  <line class="rule" x1="1350" y1="222" x2="1350" y2="265"/>

  <!-- Nodes are an inventory, not an onboarding form. -->
  <rect class="panel" x="21" y="300" width="1538" height="473" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="332">Node inventory</text>
    <text class="tiny muted" x="196" y="332">Declared hosts and their newest trusted observation</text>
    <rect class="chip-green" x="1270" y="313" width="55" height="28" rx="14"/><text class="tiny green" x="1297" y="332" text-anchor="middle">All · 5</text>
    <text class="tiny muted" x="1348" y="332">Attention · 0</text><text class="tiny green" x="1539" y="332" text-anchor="end">Enroll · Available</text>

    <text class="small muted" x="47" y="379">NODE / LIFECYCLE</text><text class="small muted" x="180" y="379">DECLARED ENDPOINT / SSH PORT</text><text class="small muted" x="465" y="379">LOCATION</text>
    <text class="small muted" x="560" y="379">ROLE</text><text class="small muted" x="770" y="379">OBSERVATION</text><text class="small muted" x="970" y="379">SNAPSHOT</text>
    <text class="small muted" x="1140" y="379">CARRIER</text><text class="small muted" x="1300" y="379">LAST SEEN</text>
    <line class="rule" x1="41" y1="389" x2="1539" y2="389"/>

    <text class="subsection mono" x="47" y="421">jm24</text><text class="tiny muted" x="47" y="442">control · Active</text>
    <text class="body mono" x="180" y="421">sfab.cc</text><text class="tiny muted" x="180" y="442">SSH port 61222 · host/user not retained</text><text class="body" x="465" y="421">Beijing</text>
    <text class="body" x="560" y="421">control + access</text><text class="tiny muted" x="560" y="442">tunnel endpoint</text>
    <circle class="quiet-dot" cx="775" cy="416" r="4"/><text class="body" x="788" y="421">Healthy</text><text class="tiny muted" x="788" y="442">local /status</text>
    <text class="body mono" x="970" y="421">4f09f6f5716d</text><text class="tiny green" x="970" y="442">Verified</text><text class="body" x="1140" y="421">2 / 2 observed</text><text class="body mono" x="1300" y="421">10s</text>
    <use href="#icon-arrow-right" x="1518" y="411" width="14" height="14" class="action-icon"/><line class="rule" x1="41" y1="459" x2="1539" y2="459"/>

    <text class="subsection mono" x="47" y="488">gz02</text><text class="tiny muted" x="47" y="509">remote · Active</text>
    <text class="body mono" x="180" y="488">8.163.70.120</text><text class="tiny muted" x="180" y="509">SSH port 22 · host/user not retained</text><text class="body" x="465" y="488">Guangzhou</text>
    <text class="body" x="560" y="488">domestic + egress</text><text class="tiny muted" x="560" y="509">tunnel endpoint</text>
    <circle class="quiet-dot" cx="775" cy="483" r="4"/><text class="body" x="788" y="488">Healthy</text><text class="tiny muted" x="788" y="509">trusted learned state</text>
    <text class="body mono" x="970" y="488">4f09f6f5716d</text><text class="tiny green" x="970" y="509">Verified</text><text class="body" x="1140" y="488">2 / 2 observed</text><text class="body mono" x="1300" y="488">11s</text>
    <use href="#icon-arrow-right" x="1518" y="478" width="14" height="14" class="action-icon"/><line class="rule" x1="41" y1="526" x2="1539" y2="526"/>

    <text class="subsection mono" x="47" y="555">hz01</text><text class="tiny muted" x="47" y="576">remote · Active</text>
    <text class="body mono" x="180" y="555">47.97.127.101</text><text class="tiny muted" x="180" y="576">SSH port 22 · host/user not retained</text><text class="body" x="465" y="555">Hangzhou</text>
    <text class="body" x="560" y="555">domestic + egress</text><text class="tiny muted" x="560" y="576">tunnel endpoint</text>
    <circle class="quiet-dot" cx="775" cy="550" r="4"/><text class="body" x="788" y="555">Healthy</text><text class="tiny muted" x="788" y="576">trusted learned state</text>
    <text class="body mono" x="970" y="555">4f09f6f5716d</text><text class="tiny green" x="970" y="576">Verified</text><text class="body" x="1140" y="555">2 / 2 observed</text><text class="body mono" x="1300" y="555">13s</text>
    <use href="#icon-arrow-right" x="1518" y="545" width="14" height="14" class="action-icon"/><line class="rule" x1="41" y1="593" x2="1539" y2="593"/>

    <text class="subsection mono" x="47" y="622">sg02</text><text class="tiny muted" x="47" y="643">remote · Active</text>
    <text class="body mono" x="180" y="622">194.156.163.227</text><text class="tiny muted" x="180" y="643">SSH port 22 · host/user not retained</text><text class="body" x="465" y="622">Singapore</text>
    <text class="body" x="560" y="622">reverse-only + egress</text><text class="tiny muted" x="560" y="643">tunnel endpoint</text>
    <circle class="quiet-dot" cx="775" cy="617" r="4"/><text class="body" x="788" y="622">Healthy</text><text class="tiny muted" x="788" y="643">trusted learned state</text>
    <text class="body mono" x="970" y="622">4f09f6f5716d</text><text class="tiny green" x="970" y="643">Verified</text><text class="body" x="1140" y="622">3 / 3 observed</text><text class="body mono" x="1300" y="622">8s</text>
    <use href="#icon-arrow-right" x="1518" y="612" width="14" height="14" class="action-icon"/><line class="rule" x1="41" y1="660" x2="1539" y2="660"/>

    <text class="subsection mono" x="47" y="689">ber01</text><text class="tiny muted" x="47" y="710">remote · Active</text>
    <text class="body mono" x="180" y="689">194.156.154.254</text><text class="tiny muted" x="180" y="710">SSH port 22 · host/user not retained</text><text class="body" x="465" y="689">Berlin</text>
    <text class="body" x="560" y="689">reverse-only + egress</text><text class="tiny muted" x="560" y="710">tunnel endpoint</text>
    <circle class="quiet-dot" cx="775" cy="684" r="4"/><text class="body" x="788" y="689">Healthy</text><text class="tiny muted" x="788" y="710">trusted learned state</text>
    <text class="body mono" x="970" y="689">4f09f6f5716d</text><text class="tiny green" x="970" y="710">Verified</text><text class="body" x="1140" y="689">3 / 3 observed</text><text class="body mono" x="1300" y="689">8s</text>
    <use href="#icon-arrow-right" x="1518" y="679" width="14" height="14" class="action-icon"/><line class="rule" x1="41" y1="727" x2="1539" y2="727"/>

    <text class="tiny muted" x="41" y="753">Declared endpoint is SSOT intent; UDP ingress remains unverified. Durable management host/user remain a control-inventory gap.</text>
    <text class="small green" x="1430" y="753">View topology</text><use href="#icon-arrow-right" x="1518" y="741" width="14" height="14" class="action-icon"/>
  </g>

  <!-- Enrollment reuses one implemented control-wide key pair. -->
  <rect class="panel" x="21" y="789" width="1538" height="184" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="821">Control bootstrap identity</text><circle class="quiet-dot" cx="365" cy="816" r="4"/><text class="tiny green" x="378" y="821">Implemented · one control-wide key</text>
    <text class="tiny muted" x="41" y="844">Fingerprint SHA256:yAaQ7u7vY2qJ…r9cW · generated once and reused by every enrollment.</text>
    <rect class="code-bg" x="41" y="860" width="602" height="45" rx="5"/><use href="#icon-key" x="56" y="875" width="14" height="14" class="action-icon"/>
    <text class="tiny mono" x="81" y="888">ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… loom-control-bootstrap</text>
    <rect class="panel" x="659" y="860" width="170" height="45" rx="5"/><use href="#icon-copy" x="674" y="875" width="14" height="14" class="action-icon"/><text class="tiny" x="699" y="888">Copy public key</text>
    <rect class="panel" x="843" y="860" width="145" height="45" rx="5"/><use href="#icon-download" x="858" y="875" width="14" height="14" class="action-icon"/><text class="tiny" x="883" y="888">Download .pub</text>
    <text class="small green" x="1090" y="888" text-anchor="end">Key settings →</text>
    <line class="rule" x1="41" y1="922" x2="1090" y2="922"/>
    <text class="tiny muted" x="41" y="949">Private key stays on the control node · separate from platform signing trust and node WG identity.</text>

    <line class="rule" x1="1115" y1="811" x2="1115" y2="951"/>
    <text class="subsection" x="1140" y="821">Enrollment key policy</text>
    <text class="body" x="1140" y="853">One control-wide ED25519 identity</text>
    <text class="body" x="1140" y="881">The same public key authorizes every bootstrap</text>
    <text class="body" x="1140" y="909">Private material is never exported</text>
    <text class="body" x="1140" y="937">Revoke separately after Agent/TLS bootstrap, if desired</text>
  </g>
'''
    return shell(
        active="Nodes",
        eyebrow="NETWORK / NODES",
        title="Nodes",
        subtitle="Monitor trusted node state · host-key-guarded enrollment on the control node",
        status="5 declared · 5 healthy · enrollment available",
        description="A full-width node inventory with one control-wide bootstrap SSH identity and a clear entry point to a separate onboarding page, distinct from platform signing trust and node-local WireGuard identity.",
        body=body,
        session_status="Control workflow",
    )


def node_add_page() -> str:
    body = r'''
  <!-- Implemented task-oriented SSH trust and guarded SSOT workflow. -->
  <rect class="panel" x="21" y="202" width="1538" height="82" rx="7"/>
  <g class="ui">
    <use href="#icon-status-ok" x="46" y="228" width="20" height="20" class="status-icon"/>
    <text class="tiny green" x="80" y="231">COMPLETE</text><text class="section" x="80" y="256">1 · Connect remote host</text>
    <circle cx="558" cy="238" r="10" fill="#EEF8F3" stroke="#2AA875"/><text class="tiny green" x="558" y="242" text-anchor="middle" font-weight="650">2</text>
    <text class="tiny green" x="586" y="231">CURRENT</text><text class="section" x="586" y="256">Review identity &amp; policy</text>
    <circle cx="1086" cy="238" r="10" fill="#F4F6F5" stroke="#CBD0CD"/><text class="tiny muted" x="1086" y="242" text-anchor="middle" font-weight="650">3</text>
    <text class="tiny muted" x="1114" y="231">NEXT</text><text class="section" x="1114" y="256">Save reviewed declaration</text>
  </g>
  <line class="rule" x1="509" y1="222" x2="509" y2="265"/><line class="rule" x1="1037" y1="222" x2="1037" y2="265"/>

  <!-- Only bootstrap connection coordinates are entered manually. -->
  <rect class="panel" x="21" y="300" width="520" height="673" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="332">Connect to the remote host</text>
    <text class="tiny muted" x="41" y="354">The shared control key must already be authorized on this host.</text>

    <text class="small muted" x="41" y="389">SHARED CONTROL PUBLIC KEY</text>
    <rect class="code-bg" x="41" y="401" width="480" height="47" rx="6"/><use href="#icon-key" x="57" y="417" width="14" height="14" class="action-icon"/>
    <text class="tiny mono" x="82" y="430">ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…</text><use href="#icon-copy" x="489" y="417" width="14" height="14" class="action-icon" aria-label="Copy shared control public key"/>

    <text class="small muted" x="41" y="480">HOST OR IP ADDRESS</text><text class="small muted" x="263" y="480">SSH USER</text><text class="small muted" x="441" y="480">PORT</text>
    <rect class="panel-soft" x="41" y="492" width="210" height="50" rx="6"/><text class="body mono" x="57" y="523">hk01.edge.example.net</text>
    <rect class="panel-soft" x="263" y="492" width="166" height="50" rx="6"/><text class="small mono" x="279" y="523">loom-bootstrap</text>
    <rect class="panel-soft" x="441" y="492" width="80" height="50" rx="6"/><text class="body mono" x="457" y="523">22</text>
    <text class="tiny muted" x="41" y="562">Input once · eligible only as a control-resolved candidate</text><text class="tiny green" x="521" y="562" text-anchor="end">Advanced →</text>

    <rect class="panel" x="41" y="584" width="202" height="41" rx="6"/><use href="#icon-refresh" x="58" y="597" width="14" height="14" class="action-icon"/><text class="small" x="83" y="610">Run preflight again</text>

    <line class="rule" x1="41" y1="650" x2="521" y2="650"/>
    <text class="subsection" x="41" y="680">Remote host identity</text>
    <text class="small muted" x="41" y="711">SSH HOST KEY</text><text class="tiny mono" x="180" y="711">SHA256:W1f2Qe…8k9m</text><text class="tiny green" x="472" y="711" text-anchor="end">Confirmed by operator</text>
    <text class="small muted" x="41" y="743">HOSTNAME</text><text class="body mono" x="180" y="743">hk01</text><text class="tiny muted" x="472" y="743" text-anchor="end">hostname -s</text>
    <text class="small muted" x="41" y="775">SYSTEM</text><text class="body" x="180" y="775">Ubuntu 24.04 · x86_64</text>
    <text class="small muted" x="41" y="807">PRIVILEGE</text><text class="body green" x="180" y="807">Bootstrap permitted</text>
    <text class="small muted" x="41" y="839">WIREGUARD</text><text class="body green" x="180" y="839">Kernel support available</text>

    <line class="rule" x1="41" y1="865" x2="521" y2="865"/>
    <text class="tiny muted" x="41" y="892">Node ID comes from the verified remote hostname.</text>
    <text class="tiny muted" x="41" y="916">Control resolves and dials a global endpoint candidate.</text>
    <text class="tiny muted" x="41" y="940">Connection policy is reviewed separately after preflight.</text>
    <text class="tiny amber" x="41" y="960">Separate semantics · this version promotes only a trusted global SSH target as candidate.</text>
  </g>

  <!-- Discovery and the concrete SSOT diff have enough room to be reviewed. -->
  <rect class="panel" x="557" y="300" width="1002" height="673" rx="7"/>
  <g class="ui">
    <text class="section" x="577" y="332">Review discovered node</text>
    <text class="tiny muted" x="577" y="354">Identity is SSH-observed; endpoint is a control-dialed candidate. UDP exposure is not inferred.</text>

    <text class="small muted" x="577" y="390">NODE ID</text><text class="metric mono" x="577" y="418">hk01</text><text class="tiny muted" x="577" y="438">From remote hostname · locked</text>
    <text class="small muted" x="802" y="390">ENDPOINT CANDIDATE</text><text class="metric mono" x="802" y="418">hk01.edge.example.net</text><text class="tiny amber" x="802" y="438">Global SSH dial succeeded · UDP unverified</text>
    <text class="small muted" x="1097" y="390">CONNECTION DIRECTION</text><text class="tiny green" x="1322" y="390" text-anchor="end">Review →</text>
    <rect class="panel-soft" x="1097" y="398" width="225" height="36" rx="5" aria-label="Change connection policy"/>
    <text class="body" x="1112" y="421">Automatic</text><text class="tiny green mono" x="1201" y="421">→ reverse_only</text>
    <path d="M1302 411l5 5 5-5" fill="none" stroke="#717674" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
    <text class="tiny muted" x="1097" y="450">Recompute, review, then commit a locked direction</text>
    <text class="small muted" x="1378" y="390">EGRESS</text><text class="metric green" x="1378" y="418">Enabled</text><text class="tiny muted" x="1378" y="438">New-node default</text>
    <line class="rule" x1="772" y1="378" x2="772" y2="454"/><line class="rule" x1="1067" y1="378" x2="1067" y2="454"/><line class="rule" x1="1348" y1="378" x2="1348" y2="454"/>

    <line class="rule" x1="577" y1="463" x2="1539" y2="463"/>
    <text class="section" x="577" y="493">Proposed network changes</text><text class="tiny green" x="1539" y="493" text-anchor="end">Recomputed with policy · no conflicts</text>
    <text class="small muted" x="583" y="523">EDGE</text><text class="small muted" x="765" y="523">TUNNEL ADDRESSES</text><text class="small muted" x="1048" y="523">ACCEPTOR / LISTEN</text><text class="small muted" x="1240" y="523">INITIATOR</text><text class="small muted" x="1360" y="523">FIREWALL</text>
    <line class="rule" x1="577" y1="531" x2="1539" y2="531"/>
    <text class="body mono" x="583" y="552">hk01 ↔ jm24</text><text class="body mono" x="765" y="552">10.99.2.1/32 ↔ 10.99.2.2/32</text><text class="body mono" x="1048" y="552">jm24 · 61775/udp</text><text class="body mono" x="1240" y="552">hk01</text><text class="body" x="1360" y="552">Allow UDP on jm24</text>
    <text class="body mono" x="583" y="579">hk01 ↔ gz02</text><text class="body mono" x="765" y="579">10.99.2.3/32 ↔ 10.99.2.4/32</text><text class="body mono" x="1048" y="579">gz02 · 61683/udp</text><text class="body mono" x="1240" y="579">hk01</text><text class="body" x="1360" y="579">Allow UDP on gz02</text>
    <text class="body mono" x="583" y="606">hk01 ↔ hz01</text><text class="body mono" x="765" y="606">10.99.2.5/32 ↔ 10.99.2.6/32</text><text class="body mono" x="1048" y="606">hz01 · 61719/udp</text><text class="body mono" x="1240" y="606">hk01</text><text class="body" x="1360" y="606">Allow UDP on hz01</text>
    <line class="rule" x1="577" y1="560" x2="1539" y2="560"/><line class="rule" x1="577" y1="587" x2="1539" y2="587"/><line class="rule" x1="577" y1="614" x2="1539" y2="614"/>

    <text class="small muted" x="577" y="637">WIREGUARD IDENTITY</text><text class="body amber" x="755" y="637">Prepared on hk01 at commit</text>
    <text class="tiny muted" x="1098" y="637">Reuse existing key or generate locally · private key never leaves hk01</text>
    <line class="rule" x1="577" y1="657" x2="1539" y2="657"/>

    <text class="section" x="577" y="687">SSOT change summary</text>
    <circle class="quiet-dot" cx="583" cy="713" r="3.5"/><text class="body" x="596" y="718">Add node <tspan class="mono">hk01</tspan> using its verified hostname</text>
    <circle class="quiet-dot" cx="583" cy="743" r="3.5"/><text class="body" x="596" y="748">Record the global endpoint candidate successfully dialed by control</text>
    <circle class="quiet-dot" cx="583" cy="773" r="3.5"/><text class="body" x="596" y="778">Save direction <tspan class="mono">reverse_only</tspan> · enable egress · add derived persistent tunnels</text>
    <circle class="neutral-dot" cx="583" cy="803" r="3.5"/><text class="body" x="596" y="808">No service or access policy changes</text>
    <text class="tiny amber" x="577" y="838">Declaration only · Agent, platform trust, node secrets and TLS identity are not installed by this action.</text>

    <line class="rule" x1="577" y1="858" x2="1539" y2="858"/>
    <circle class="quiet-dot" cx="583" cy="887" r="4"/><text class="small green" x="596" y="892">Discovery and allocation plan are valid</text>
    <rect class="panel" x="1193" y="875" width="118" height="42" rx="6"/><text class="small" x="1252" y="901" text-anchor="middle">Cancel</text>
    <rect class="button-green" x="1325" y="875" width="214" height="42" rx="6"/><use href="#icon-check" x="1338" y="889" width="14" height="14" stroke="#FFFFFF" fill="none" stroke-width="1.5"/><text class="tiny" x="1359" y="900" fill="#FFFFFF">Prepare WG + save declaration</text>
    <text class="tiny muted" x="577" y="947"><tspan font-weight="600" fill="#181B1A">On confirm:</tspan> prepare hk01 WG identity → revision-guarded SSOT save → remain joining until separate Agent/TLS bootstrap and trusted report.</text>
  </g>
'''
    return shell(
        active="Nodes",
        eyebrow="NODES / ADD",
        title="Add node",
        subtitle="Connect once; the control plane discovers identity, endpoint and the resulting network changes",
        status="Authenticated workflow · host key and SSOT revision guarded",
        description="A dedicated declaration-bootstrap page where the operator enters SSH coordinates, confirms an Ed25519 host fingerprint, reviews a direction-bound tunnel plan, and prepares the remote WireGuard identity before an SSOT revision-guarded save. It explicitly does not claim to install or start the Loom Agent.",
        body=body,
        session_status="Write session",
    )


def topology_page() -> str:
    body = r'''
  <defs>
    <marker id="arrow-automatic" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto" markerUnits="strokeWidth">
      <path d="M0 0L7 3.5L0 7Z" fill="#466FC2"/>
    </marker>
  </defs>
  <!-- Layered topology -->
  <rect class="panel" x="21" y="202" width="1075" height="478" rx="7"/>
  <g class="ui">
    <text class="section" x="40" y="232">Topology layers</text>
    <text class="small muted" x="40" y="254">Declared structure remains visible when trusted observation is missing.</text>

    <line class="wg" x1="654" y1="226" x2="684" y2="226"/>
    <text class="tiny muted" x="691" y="230">Persistent WG</text>
    <line x1="798" y1="226" x2="828" y2="226" stroke="#4F9B74" stroke-width="1.6"/>
    <text class="tiny muted" x="835" y="230">Hy2 direct</text>
    <line x1="922" y1="226" x2="952" y2="226" stroke="#466FC2" stroke-width="2.4"/>
    <path d="M948 222L954 226L948 230" fill="none" stroke="#466FC2" stroke-width="1.6"/>
    <text class="tiny muted" x="961" y="230">Auto · read-only</text>
    <rect class="panel-soft" x="1054" y="213" width="28" height="26" rx="5"/>
    <use href="#icon-refresh" x="1061" y="219" width="14" height="14" class="action-icon" aria-label="Refresh observations"/>
  </g>

  <!-- Current double-ring layout: three dialable anchors and three reverse-only servers. -->
  <ellipse cx="560" cy="430" rx="300" ry="160" fill="none" stroke="#EDF0EE"/>
  <ellipse cx="560" cy="420" rx="175" ry="95" fill="none" stroke="#EDF0EE" stroke-dasharray="3 5"/>

  <!-- Nine SSOT-declared persistent WireGuard links (3 × 3). -->
  <g aria-label="Nine persistent WireGuard links">
    <line class="wg" x1="560" y1="320" x2="300" y2="350"/>
    <line class="wg" x1="560" y1="320" x2="820" y2="350"/>
    <line class="wg" x1="560" y1="320" x2="560" y2="590"/>
    <line class="wg" x1="410" y1="475" x2="300" y2="350"/>
    <line class="wg" x1="410" y1="475" x2="820" y2="350"/>
    <line class="wg" x1="410" y1="475" x2="560" y2="590"/>
    <line class="wg" x1="710" y1="475" x2="300" y2="350"/>
    <line class="wg" x1="710" y1="475" x2="820" y2="350"/>
    <line class="wg" x1="710" y1="475" x2="560" y2="590"/>
  </g>

  <!-- Three observed public Hysteria2 single-hop probes between inner anchors. -->
  <g aria-label="Three observed Hysteria2 direct links" fill="none" stroke="#4F9B74" stroke-width="1.6">
    <line x1="554" y1="331" x2="418" y2="466"/>
    <line x1="566" y1="331" x2="702" y2="466"/>
    <path d="M422 482Q560 525 698 482"/>
  </g>

  <!-- Current Agent decisions are projected automatically; this is not a path picker. -->
  <path class="selected" style="stroke:#466FC2;stroke-width:2.4;marker-end:url(#arrow-automatic)" d="M571 320L807 349"/>
  <path class="selected" style="stroke:#466FC2;stroke-width:2.4;marker-end:url(#arrow-automatic)" d="M560 310L592 284"/>
  <text class="ui tiny blue mono" x="603" y="285">cn-web · local exit</text>
  <text class="ui tiny blue mono" x="660" y="325">intl-api · jm24 → ber01</text>

  <g class="ui">
    <circle cx="560" cy="320" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="560" cy="320" r="5"/>
    <text class="mono" x="560" y="301" text-anchor="middle" font-size="14" font-weight="650">jm24</text>
    <text class="tiny muted" x="560" y="343" text-anchor="middle">control + access + server + egress</text>

    <circle cx="410" cy="475" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="410" cy="475" r="5"/>
    <text class="mono" x="390" y="474" text-anchor="end" font-size="14" font-weight="650">hz01</text>
    <text class="tiny muted" x="390" y="494" text-anchor="end">server + egress</text>

    <circle cx="710" cy="475" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="710" cy="475" r="5"/>
    <text class="mono" x="730" y="474" font-size="14" font-weight="650">gz02</text>
    <text class="tiny muted" x="730" y="494">server + egress</text>

    <circle cx="300" cy="350" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="300" cy="350" r="5"/>
    <text class="mono" x="280" y="349" text-anchor="end" font-size="14" font-weight="650">sv01</text>
    <text class="tiny muted" x="280" y="369" text-anchor="end">reverse-only + server + egress</text>

    <circle cx="820" cy="350" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="820" cy="350" r="5"/>
    <text class="mono" x="840" y="349" font-size="14" font-weight="650">ber01</text>
    <text class="tiny muted" x="840" y="369">reverse-only + server + egress</text>

    <circle cx="560" cy="590" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="560" cy="590" r="5"/>
    <text class="mono" x="560" y="615" text-anchor="middle" font-size="14" font-weight="650">sg02</text>
    <text class="tiny muted" x="560" y="634" text-anchor="middle">reverse-only + server + egress</text>

    <text class="tiny muted" x="40" y="649">Candidate edges describe allowable business paths. Missing a direct WG edge does not mean there is no path.</text>
  </g>

  <!-- Layer inspection -->
  <rect class="panel" x="1112" y="202" width="447" height="270" rx="7"/>
  <g class="ui">
    <text class="section" x="1132" y="232">Layer status</text>

    <text class="small muted" x="1132" y="266">CONFIG INTENT</text>
    <text class="metric" x="1132" y="290">9 persistent links</text>
    <text class="tiny muted" x="1132" y="309">Source · current validated SSOT · desired state</text>

    <line class="rule" x1="1132" y1="327" x2="1539" y2="327"/>
    <text class="small muted" x="1132" y="352">TRUSTED OBSERVATION</text>
    <circle class="status-dot" cx="1137" cy="376" r="4"/>
    <text class="metric" x="1150" y="381">9 / 9 reachable</text>
    <text class="tiny muted" x="1132" y="401">report.neighbors · newest 8s · oldest 16s</text>

    <line class="rule" x1="1132" y1="419" x2="1539" y2="419"/>
    <text class="small muted" x="1132" y="444">HY2 DIRECT</text><text class="small muted" x="1330" y="444">AUTOMATIC ROUTING</text>
    <text class="body green" x="1132" y="463">3 / 3 sampled</text><text class="body blue" x="1330" y="463">2 / 2 fresh · read-only</text>
  </g>

  <!-- Focused-link history: each endpoint contributes TX only. -->
  <rect class="panel" x="1112" y="488" width="447" height="192" rx="7"/>
  <g class="ui">
    <text class="section" x="1132" y="518">Link traffic</text>
    <text class="tiny green" x="1539" y="518" text-anchor="end">Retained · endpoint TX only</text>
    <text class="body mono" x="1132" y="545">Inspecting · gz02 ↔ sg02</text>

    <text class="tiny green" x="1132" y="568">Endpoint TX total</text>
    <text class="metric" x="1132" y="590">403 GB</text>
    <text class="tiny blue" x="1132" y="615">Reporting endpoints</text>
    <text class="metric" x="1132" y="637">2</text>
    <text class="small muted" x="1132" y="662">Undirected link · no RX double-count</text>

    <line class="rule" x1="1288" y1="546" x2="1539" y2="546"/>
    <line class="rule" x1="1288" y1="579" x2="1539" y2="579"/>
    <line class="rule" x1="1288" y1="612" x2="1539" y2="612"/>
    <line class="rule" x1="1288" y1="645" x2="1539" y2="645"/>
    <g aria-label="Accepted undirected link TX buckets plus one reset and one long gap">
      <g fill="#2AA875">
        <rect x="1293" y="627" width="8" height="18" rx="1"/><rect x="1323" y="613" width="8" height="32" rx="1"/>
        <rect x="1353" y="620" width="8" height="25" rx="1"/>
        <rect x="1413" y="603" width="8" height="42" rx="1"/><rect x="1443" y="589" width="8" height="56" rx="1"/>
        <rect x="1503" y="595" width="8" height="50" rx="1"/>
      </g>
      <g fill="#477D9C" fill-opacity="0.82">
        <rect x="1303" y="633" width="8" height="12" rx="1"/><rect x="1333" y="625" width="8" height="20" rx="1"/>
        <rect x="1363" y="627" width="8" height="18" rx="1"/>
        <rect x="1423" y="617" width="8" height="28" rx="1"/><rect x="1453" y="610" width="8" height="35" rx="1"/>
        <rect x="1513" y="616" width="8" height="29" rx="1"/>
      </g>
      <rect x="1381" y="584" width="20" height="61" rx="1" fill="none" stroke="#D79B3B" stroke-dasharray="3 3"/>
      <rect x="1471" y="584" width="20" height="61" rx="1" fill="none" stroke="#A5AAA8" stroke-dasharray="3 3"/>
      <text class="tiny amber" x="1391" y="599" text-anchor="middle">R</text>
      <text class="tiny muted" x="1481" y="599" text-anchor="middle">G</text>
    </g>
    <text class="tiny muted" x="1288" y="663">1h ago</text>
    <text class="tiny muted" x="1539" y="663" text-anchor="end">now</text>
  </g>

  <!-- Edge inventory -->
  <rect class="panel" x="21" y="696" width="1538" height="277" rx="7"/>
  <rect x="31" y="934" width="1518" height="28" rx="4" fill="#F1F8F4"/>
  <g class="ui">
    <text class="section" x="40" y="726">Persistent WireGuard edges</text>
    <text class="tiny muted" x="318" y="726">24h link bytes = TX deltas from each endpoint; receiver RX is not added again</text>
    <text class="tiny green" x="1539" y="726" text-anchor="end">Control retention · 30 days</text>
    <text class="small muted" x="46" y="758">EDGE</text>
    <text class="small muted" x="300" y="758">24H TX TOTAL / BAR</text>
    <text class="small muted" x="735" y="758">BUCKETS WITH SAMPLES</text>
    <text class="small muted" x="965" y="758">RTT</text>
    <text class="small muted" x="1080" y="758">STATE</text>
    <text class="small muted" x="1270" y="758">LATEST TRUSTED SAMPLE</text>
  </g>
  <line class="rule" x1="40" y1="766" x2="1540" y2="766"/>
  <g class="ui body">
    <text class="mono" x="46" y="788">jm24 ↔ sv01</text><text class="mono" x="300" y="788">312 GB</text><rect x="415" y="780" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="780" width="190" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="788">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="788">32 ms</text><circle class="quiet-dot" cx="1084" cy="783" r="4"/><text x="1097" y="788">Active</text><text class="muted" x="1270" y="788">8s ago</text>
    <text class="mono" x="46" y="808">jm24 ↔ ber01</text><text class="mono" x="300" y="808">238 GB</text><rect x="415" y="800" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="800" width="145" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="808">23 / 24 · G1</text><text class="mono" x="965" y="808">150 ms</text><circle class="quiet-dot" cx="1084" cy="803" r="4"/><text x="1097" y="808">Active</text><text class="muted" x="1270" y="808">8s ago</text>
    <text class="mono" x="46" y="828">jm24 ↔ sg02</text><text class="mono" x="300" y="828">400 GB</text><rect x="415" y="820" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="820" width="243" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="828">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="828">277 ms</text><circle class="quiet-dot" cx="1084" cy="823" r="4"/><text x="1097" y="828">Active</text><text class="muted" x="1270" y="828">8s ago</text>
    <text class="mono" x="46" y="848">hz01 ↔ sv01</text><text class="mono" x="300" y="848">285 GB</text><rect x="415" y="840" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="840" width="173" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="848">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="848">28 ms</text><circle class="quiet-dot" cx="1084" cy="843" r="4"/><text x="1097" y="848">Active</text><text class="muted" x="1270" y="848">13s ago</text>
    <text class="mono" x="46" y="868">hz01 ↔ ber01</text><text class="mono" x="300" y="868">278 GB</text><rect x="415" y="860" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="860" width="169" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="868">23 / 24 · G1</text><text class="mono" x="965" y="868">240 ms</text><circle class="quiet-dot" cx="1084" cy="863" r="4"/><text x="1097" y="868">Active</text><text class="muted" x="1270" y="868">13s ago</text>
    <text class="mono" x="46" y="888">hz01 ↔ sg02</text><text class="mono" x="300" y="888">179 GB</text><rect x="415" y="880" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="880" width="109" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="888">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="888">350 ms</text><circle class="quiet-dot" cx="1084" cy="883" r="4"/><text x="1097" y="888">Active</text><text class="muted" x="1270" y="888">13s ago</text>
    <text class="mono" x="46" y="908">gz02 ↔ sv01</text><text class="mono" x="300" y="908">365 GB</text><rect x="415" y="900" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="900" width="222" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="908">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="908">35 ms</text><circle class="quiet-dot" cx="1084" cy="903" r="4"/><text x="1097" y="908">Active</text><text class="muted" x="1270" y="908">11s ago</text>
    <text class="mono" x="46" y="928">gz02 ↔ ber01</text><text class="mono" x="300" y="928">342 GB</text><rect x="415" y="920" width="245" height="8" rx="2" fill="#EEF1EF"/><rect x="415" y="920" width="208" height="8" rx="2" fill="#72C69F"/><text class="mono" x="735" y="928">24 / 24 · 2 endpoints</text><text class="mono" x="965" y="928">226 ms</text><circle class="quiet-dot" cx="1084" cy="923" r="4"/><text x="1097" y="928">Active</text><text class="muted" x="1270" y="928">11s ago</text>
    <text class="mono" x="46" y="952">gz02 ↔ sg02</text><text class="mono green" x="300" y="952">403 GB</text><rect x="415" y="944" width="245" height="8" rx="2" fill="#DDEFE6"/><rect x="415" y="944" width="245" height="8" rx="2" fill="#239B68"/><text class="mono green" x="735" y="952">22 / 24 · R1 G1</text><text class="mono" x="965" y="952">190 ms</text><circle class="quiet-dot" cx="1084" cy="947" r="4"/><text x="1097" y="952">Active</text><text class="muted" x="1270" y="952">11s ago</text>
  </g>
  <line class="rule" x1="40" y1="796" x2="1540" y2="796"/><line class="rule" x1="40" y1="816" x2="1540" y2="816"/><line class="rule" x1="40" y1="836" x2="1540" y2="836"/><line class="rule" x1="40" y1="856" x2="1540" y2="856"/><line class="rule" x1="40" y1="876" x2="1540" y2="876"/><line class="rule" x1="40" y1="896" x2="1540" y2="896"/><line class="rule" x1="40" y1="916" x2="1540" y2="916"/><line class="rule" x1="40" y1="936" x2="1540" y2="936"/>
'''
    return shell(
        active="Topology",
        eyebrow="NETWORK / TOPOLOGY",
        title="Network topology",
        subtitle="Intent, trusted observations and read-only automatic Agent decisions · observed 2026-08-27 17:54 UTC",
        status="6 nodes · 9 persistent WireGuard links · 2 fresh automatic decisions",
        description="A layered network topology view distinguishing SSOT intent, persistent WireGuard observations, configured candidate paths, automatically projected read-only Agent decisions, and centrally retained TX-only link-delta bars with explicit missing-sample gaps.",
        body=body,
    )


def node_detail_page() -> str:
    body = r'''
  <!-- The node belongs to inventory; topology remains a relationship view. -->
  <text class="ui tiny green" x="1538" y="181" text-anchor="end">Nodes / jm24 · View in topology →</text>

  <!-- Identity and deployment facts remain compact and full width. -->
  <rect class="panel" x="21" y="202" width="1538" height="78" rx="7"/>
  <g class="ui">
    <text class="label" x="51" y="228">Snapshot</text><text class="metric mono" x="51" y="255">4f09f6f5716d</text>
    <text class="label" x="415" y="228">Loom code</text><text class="metric mono" x="415" y="255">28224ed</text>
    <text class="label" x="745" y="228">Binary</text><text class="metric mono" x="745" y="255">449597b5…</text>
    <text class="label" x="1064" y="228">WireGuard tools</text><text class="metric mono" x="1064" y="255">1.0.20250521</text>
    <text class="label" x="1390" y="228">Rollout</text><text class="metric green" x="1390" y="255">Verified</text>
  </g>
  <line class="rule" x1="376" y1="216" x2="376" y2="266"/><line class="rule" x1="706" y1="216" x2="706" y2="266"/><line class="rule" x1="1025" y1="216" x2="1025" y2="266"/><line class="rule" x1="1351" y1="216" x2="1351" y2="266"/>

  <!-- Equal columns keep process state and network observation at the same level. -->
  <rect class="panel" x="21" y="296" width="758" height="320" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="325">Runtime</text><text class="tiny muted" x="41" y="346">Expected components and observed process state</text>
    <text class="small muted" x="47" y="371">UNIT</text><text class="small muted" x="270" y="371">ROLE</text><text class="small muted" x="500" y="371">STATE</text><text class="small muted" x="650" y="371">RESTARTS</text>
    <line class="rule" x1="41" y1="379" x2="759" y2="379"/>
    <text class="body mono" x="47" y="404">loom-report</text><text class="body" x="270" y="404">status + signed relay</text><circle class="quiet-dot" cx="504" cy="399" r="4"/><text class="body" x="517" y="404">Active</text><text class="body mono" x="680" y="404">0</text>
    <text class="body mono" x="47" y="431">loom-agent</text><text class="body" x="270" y="431">selector control loop</text><circle class="quiet-dot" cx="504" cy="426" r="4"/><text class="body" x="517" y="431">Active</text><text class="body mono" x="680" y="431">0</text>
    <text class="body mono" x="47" y="458">loom-publisher</text><text class="body" x="270" y="458">automatic release</text><circle class="quiet-dot" cx="504" cy="453" r="4"/><text class="body" x="517" y="458">Active</text><text class="body mono" x="680" y="458">0</text>
    <text class="body mono" x="47" y="485">loom-pull.timer</text><text class="body" x="270" y="485">snapshot convergence</text><circle class="quiet-dot" cx="504" cy="480" r="4"/><text class="body" x="517" y="485">Waiting</text><text class="body mono" x="680" y="485">—</text>
    <line class="rule" x1="41" y1="412" x2="759" y2="412"/><line class="rule" x1="41" y1="439" x2="759" y2="439"/><line class="rule" x1="41" y1="466" x2="759" y2="466"/><line class="rule" x1="41" y1="493" x2="759" y2="493"/>
    <text class="subsection" x="41" y="521">Component parity <tspan class="tiny muted" font-weight="400">· signed expected / actual report</tspan></text>
    <text class="small muted" x="47" y="546">COMPONENT</text><text class="small muted" x="260" y="546">EXPECTED</text><text class="small muted" x="475" y="546">ACTUAL</text><text class="small muted" x="670" y="546">RESULT</text>
    <line class="rule" x1="41" y1="554" x2="759" y2="554"/>
    <text class="body" x="47" y="576">sing-box</text><text class="body mono" x="260" y="576">managed</text><text class="body mono" x="475" y="576">managed</text><text class="body green" x="670" y="576">Match</text>
    <text class="body" x="47" y="602">wireguard-tools</text><text class="body mono" x="260" y="602">1.0.20250521</text><text class="body mono" x="475" y="602">1.0.20250521</text><text class="body green" x="670" y="602">Match</text>
  </g>

  <rect class="panel" x="795" y="296" width="764" height="320" rx="7"/>
  <g class="ui">
    <text class="section" x="815" y="325">Observation</text><circle class="status-dot" cx="1444" cy="321" r="4"/><text class="tiny green" x="1539" y="325" text-anchor="end">Verified healthy</text>
    <text class="small muted" x="815" y="358">SOURCE</text><text class="body" x="1015" y="358">Direct /status · local evidence</text>
    <text class="small muted" x="815" y="388">ROLE</text><text class="body" x="1015" y="388">Access + tunnel endpoint · runtime control</text>
    <text class="small muted" x="815" y="418">EGRESS CAPABLE</text><text class="body" x="1015" y="418">No · local direct remains a zero-hop candidate</text>
    <line class="rule" x1="815" y1="443" x2="1539" y2="443"/>

    <text class="section" x="815" y="473">WireGuard interface I/O</text><text class="tiny green" x="1539" y="473" text-anchor="end">Current cumulative · direct-self evidence</text>
    <text class="small muted" x="833" y="501">INTERFACE</text><text class="small muted" x="992" y="501">PEER</text><text class="small muted" x="1115" y="501">RX TOTAL</text><text class="small muted" x="1248" y="501">TX TOTAL</text><text class="small muted" x="1400" y="501">HANDSHAKE</text>
    <line class="rule" x1="815" y1="509" x2="1539" y2="509"/>
    <circle class="quiet-dot" cx="821" cy="532" r="4"/><text class="body mono" x="833" y="537">wg-sg02</text><text class="body mono" x="992" y="537">sg02</text><text class="body mono" x="1115" y="537">3.84 TB</text><text class="body mono" x="1248" y="537">2.91 TB</text><text class="body" x="1400" y="537">37s</text>
    <circle class="quiet-dot" cx="821" cy="562" r="4"/><text class="body mono" x="833" y="567">wg-ber01</text><text class="body mono" x="992" y="567">ber01</text><text class="body mono" x="1115" y="567">2.10 TB</text><text class="body mono" x="1248" y="567">1.11 TB</text><text class="body" x="1400" y="567">57s</text>
    <line class="rule" x1="815" y1="547" x2="1539" y2="547"/>
    <text class="tiny muted" x="815" y="598">/status: diagnostic + learned attachments · /traffic.json: latest report-round cache, schema v1 · fixed 60s samples / 3m gap.</text>
  </g>

  <!-- Traffic receives a full-width row instead of being squeezed into the right column. -->
  <rect class="panel" x="21" y="632" width="1538" height="128" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="660">Forwarding traffic · last 24h</text>
    <text class="tiny green" x="1539" y="660" text-anchor="end">Control retention · 30 days</text>
    <text class="small muted" x="41" y="686">HISTORICAL RX</text><text class="metric" x="41" y="713">356 GB</text>
    <text class="small muted" x="212" y="686">HISTORICAL TX</text><text class="metric" x="212" y="713">282 GB</text>
    <text class="small muted" x="383" y="686">BUCKETS WITH SAMPLES</text><text class="metric" x="383" y="713">16 / 18</text>
    <text class="tiny muted" x="41" y="746">WG only · direct, service/sing-box and Hysteria2 excluded.</text>
    <text class="tiny muted" x="383" y="746">R/G = missing, not zero.</text>

    <rect x="620" y="674" width="10" height="8" rx="1" fill="#2AA875"/><text class="tiny green" x="637" y="682">RX</text>
    <rect x="671" y="674" width="10" height="8" rx="1" fill="#477D9C" fill-opacity=".82"/><text class="tiny blue" x="688" y="682">TX</text>
    <line class="rule" x1="620" y1="691" x2="1539" y2="691"/><line class="rule" x1="620" y1="711" x2="1539" y2="711"/><line class="rule" x1="620" y1="731" x2="1539" y2="731"/>
    <g aria-label="Sixteen accepted RX and TX buckets plus one counter reset and one long gap">
      <g fill="#2AA875">
        <rect x="632" y="715" width="13" height="16" rx="1"/><rect x="681" y="705" width="13" height="26" rx="1"/><rect x="730" y="699" width="13" height="32" rx="1"/><rect x="779" y="709" width="13" height="22" rx="1"/><rect x="877" y="695" width="13" height="36" rx="1"/><rect x="926" y="688" width="13" height="43" rx="1"/><rect x="975" y="697" width="13" height="34" rx="1"/><rect x="1024" y="708" width="13" height="23" rx="1"/><rect x="1122" y="702" width="13" height="29" rx="1"/><rect x="1171" y="691" width="13" height="40" rx="1"/><rect x="1220" y="686" width="13" height="45" rx="1"/><rect x="1269" y="700" width="13" height="31" rx="1"/><rect x="1318" y="706" width="13" height="25" rx="1"/><rect x="1367" y="694" width="13" height="37" rx="1"/><rect x="1416" y="703" width="13" height="28" rx="1"/><rect x="1465" y="689" width="13" height="42" rx="1"/>
      </g>
      <g fill="#477D9C" fill-opacity=".82">
        <rect x="647" y="723" width="13" height="8" rx="1"/><rect x="696" y="716" width="13" height="15" rx="1"/><rect x="745" y="712" width="13" height="19" rx="1"/><rect x="794" y="719" width="13" height="12" rx="1"/><rect x="892" y="711" width="13" height="20" rx="1"/><rect x="941" y="705" width="13" height="26" rx="1"/><rect x="990" y="711" width="13" height="20" rx="1"/><rect x="1039" y="718" width="13" height="13" rx="1"/><rect x="1137" y="714" width="13" height="17" rx="1"/><rect x="1186" y="707" width="13" height="24" rx="1"/><rect x="1235" y="704" width="13" height="27" rx="1"/><rect x="1284" y="713" width="13" height="18" rx="1"/><rect x="1333" y="717" width="13" height="14" rx="1"/><rect x="1382" y="709" width="13" height="22" rx="1"/><rect x="1431" y="715" width="13" height="16" rx="1"/><rect x="1480" y="706" width="13" height="25" rx="1"/>
      </g>
      <rect x="826" y="686" width="32" height="45" rx="1" fill="none" stroke="#D79B3B" stroke-dasharray="3 3"/>
      <rect x="1071" y="686" width="32" height="45" rx="1" fill="none" stroke="#A5AAA8" stroke-dasharray="3 3"/>
      <text class="tiny amber" x="842" y="700" text-anchor="middle">R</text>
      <text class="tiny muted" x="1087" y="700" text-anchor="middle">G</text>
    </g>
    <text class="tiny muted" x="620" y="748">24h ago</text><text class="tiny muted" x="1539" y="748" text-anchor="end">now</text>
  </g>

  <!-- Existing detail is preserved in equal bottom columns. -->
  <rect class="panel" x="21" y="776" width="758" height="197" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="806">Automatic Agent decisions</text><text class="tiny muted" x="302" y="806">Read-only · generated by managed Service rules</text>
    <text class="small muted" x="47" y="834">SERVICE RULE</text><text class="small muted" x="260" y="834">AGENT-SELECTED PATH</text><text class="small muted" x="610" y="834">EVIDENCE</text>
    <line class="rule" x1="41" y1="842" x2="759" y2="842"/>
    <text class="body" x="47" y="870">Domestic web <tspan class="mono muted">· cn-web</tspan></text><text class="body mono blue" x="260" y="870">jm24 → local exit</text><text class="tiny muted" x="610" y="870">signed selector</text>
    <text class="body" x="47" y="908">International API <tspan class="mono muted">· intl-api</tspan></text><text class="body mono blue" x="260" y="908">jm24 → ber01</text><text class="tiny muted" x="610" y="908">signed selector</text>
    <line class="rule" x1="41" y1="884" x2="759" y2="884"/>
    <rect class="panel-soft" x="41" y="927" width="718" height="31" rx="5"/><text class="tiny muted" x="57" y="947">Host → Service → Policy → Agent · clients use the single automatic ingress and do not choose these paths.</text>
  </g>

  <rect class="panel" x="795" y="776" width="764" height="197" rx="7"/>
  <g class="ui">
    <text class="section" x="815" y="806">Measurements</text><text class="tiny muted" x="815" y="827">Uplink failures are actionable. Target failures are route-pruning data.</text>
    <text class="small muted" x="821" y="852">TYPE</text><text class="small muted" x="955" y="852">TARGET</text><text class="small muted" x="1218" y="852">OBSERVATION</text><text class="small muted" x="1442" y="852">MEANING</text>
    <line class="rule" x1="815" y1="860" x2="1539" y2="860"/>
    <text class="body" x="821" y="884">uplink</text><text class="body" x="955" y="884">uplink.example.net</text><text class="body green" x="1218" y="884">63 ms · reachable</text><text class="body" x="1442" y="884">Healthy</text>
    <text class="body" x="821" y="919">target</text><text class="body" x="955" y="919">api.ipify.org</text><text class="body blue" x="1218" y="919">5 / 5 timeout</text><text class="body blue" x="1442" y="919">Mainland classification</text>
    <text class="body" x="821" y="954">edge</text><text class="body mono" x="955" y="954">jm24 ↔ sg02</text><text class="body green" x="1218" y="954">277 ms · 4/4</text><text class="body" x="1442" y="954">Carrier</text>
    <line class="rule" x1="815" y1="895" x2="1539" y2="895"/><line class="rule" x1="815" y1="930" x2="1539" y2="930"/>
  </g>
'''
    return shell(
        active="Nodes",
        eyebrow="NODES / DETAIL",
        title="jm24",
        subtitle="Beijing · control + access + tunnel endpoint · direct /status observed 10s ago",
        status="No confirmed issues · egress capable: no",
        description="A re-laid-out node detail view that preserves deployment identity, runtime, observation, WireGuard counters, traffic history, route decisions, and measurements without overloading the right column.",
        body=body,
    )


def services_page() -> str:
    body = r'''
  <!-- Compact mode switch and primary action; this is a configuration page, not a KPI dashboard. -->
  <g class="ui">
    <rect class="chip-green" x="21" y="202" width="122" height="34" rx="17"/>
    <text class="small green" x="82" y="224" text-anchor="middle">Services · 2</text>
    <text class="small muted" x="169" y="224">Access policies · 3</text>
    <circle class="quiet-dot" cx="326" cy="219" r="4"/><text class="small green" x="339" y="224">All definitions valid</text>
    <rect class="chip-green" x="486" y="202" width="225" height="34" rx="17"/><text class="tiny green" x="599" y="223" text-anchor="middle">Structured save · implemented</text>
    <rect class="button" x="1390" y="198" width="169" height="40" rx="6"/>
    <use href="#icon-plus" x="1413" y="210" width="15" height="15" stroke="#FFFFFF" fill="none" stroke-width="1.5" stroke-linecap="round"/>
    <text class="small" x="1439" y="223" fill="#FFFFFF">Add service</text>
  </g>
  <line class="rule" x1="21" y1="250" x2="1559" y2="250"/>

  <!-- One catalog panel; permanent help is kept quiet and out of the editor. -->
  <rect class="panel" x="21" y="269" width="410" height="596" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="301">Service catalog</text><text class="tiny muted" x="405" y="301" text-anchor="end">2 configured</text>
    <rect class="panel-soft" x="41" y="319" width="370" height="38" rx="6"/>
    <use href="#icon-search" x="54" y="331" width="14" height="14" class="action-icon"/>
    <text class="small muted" x="78" y="344">Search services or hostnames</text>

    <rect x="31" y="373" width="390" height="101" rx="6" fill="#F1F8F4"/>
    <rect x="31" y="373" width="3" height="101" rx="1.5" fill="#2AA875"/>
    <text class="subsection mono" x="49" y="402">intl-api</text><text class="tiny muted" x="49" y="423">International APIs</text>
    <text class="small" x="49" y="451">2 host rules</text><text class="small muted" x="164" y="451">Best egress</text>

    <text class="subsection mono" x="49" y="513">cn-web</text><text class="tiny muted" x="49" y="534">Domestic websites</text>
    <text class="small" x="49" y="562">4 host rules</text><text class="small muted" x="164" y="562">Best egress</text>
    <line class="rule" x1="41" y1="489" x2="411" y2="489"/><line class="rule" x1="41" y1="582" x2="411" y2="582"/>

    <text class="subsection" x="41" y="622">How matching works</text>
    <text class="small muted" x="41" y="649">A service groups destination hostnames.</text>
    <text class="small muted" x="41" y="674">Exact matches one hostname.</text>
    <text class="small muted" x="41" y="699">Suffix matches a domain and its subdomains.</text>
    <line class="rule" x1="41" y1="730" x2="411" y2="730"/>
    <text class="subsection" x="41" y="766">Safe by default</text>
    <text class="small" x="41" y="794">Unmatched hostnames are rejected.</text>
    <text class="small muted" x="41" y="819">There is no implicit fallback service.</text>
  </g>

  <!-- Flat editor: only actual controls get containers. Derived/runtime facts stay lightweight. -->
  <g class="ui">
    <text class="small muted" x="467" y="290">EDIT SERVICE</text>
    <text class="section" x="467" y="318">International APIs</text><text class="subsection muted" x="625" y="318">·</text><text class="subsection mono" x="644" y="318">intl-api</text>
    <circle class="warn-dot" cx="1431" cy="313" r="4"/><text class="tiny amber" x="1444" y="317">Unsaved changes</text>
    <line class="rule" x1="467" y1="338" x2="1559" y2="338"/>

    <text class="subsection" x="467" y="373">Identity</text>
    <text class="small muted" x="467" y="401">SERVICE ID</text><text class="small muted" x="821" y="401">DISPLAY NAME</text>
    <rect class="button-disabled" x="467" y="412" width="330" height="54" rx="6"/>
    <text class="body mono" x="483" y="436">intl-api</text><text class="tiny muted" x="483" y="455">Stable ID · read-only while editing</text>
    <use href="#icon-lock" x="765" y="424" width="14" height="14" class="nav-icon"/>
    <rect class="panel-soft" x="821" y="412" width="738" height="54" rx="6"/>
    <text class="body" x="837" y="445">International APIs</text>
    <line class="rule" x1="467" y1="489" x2="1559" y2="489"/>

    <text class="subsection" x="467" y="522">Host rules</text>
    <text class="tiny muted" x="561" y="522">Requests matching either rule are treated as this service.</text>
    <text class="small muted" x="467" y="558">HOSTNAME</text><text class="small muted" x="1280" y="558">MATCH TYPE</text><text class="small muted" x="1458" y="558">ACTIONS</text>
    <line class="rule" x1="467" y1="570" x2="1559" y2="570"/>
    <text class="body mono" x="483" y="601">api.vendor.example</text><rect class="chip" x="1280" y="579" width="78" height="28" rx="14"/><text class="tiny muted" x="1319" y="598" text-anchor="middle">Exact</text>
    <use href="#icon-edit" x="1467" y="587" width="14" height="14" class="action-icon" aria-label="Edit api.vendor.example"/><use href="#icon-trash" x="1510" y="587" width="14" height="14" class="action-icon" aria-label="Remove api.vendor.example"/>
    <line class="rule" x1="467" y1="614" x2="1559" y2="614"/>
    <text class="body mono" x="483" y="645">.cdn.vendor.example</text><rect class="chip" x="1280" y="623" width="78" height="28" rx="14"/><text class="tiny muted" x="1319" y="642" text-anchor="middle">Suffix</text>
    <use href="#icon-edit" x="1467" y="631" width="14" height="14" class="action-icon" aria-label="Edit .cdn.vendor.example"/><use href="#icon-trash" x="1510" y="631" width="14" height="14" class="action-icon" aria-label="Remove .cdn.vendor.example"/>
    <line class="rule" x1="467" y1="659" x2="1559" y2="659"/>
    <rect class="panel" x="467" y="677" width="151" height="36" rx="5"/>
    <use href="#icon-plus" x="484" y="688" width="14" height="14" class="action-icon"/><text class="small" x="509" y="701">Add hostname</text>
    <text class="tiny muted" x="644" y="694">Leading dot = domain suffix. At least one exact hostname is required for probing.</text>
    <text class="tiny muted" x="644" y="713">URLs, paths, host:port, IP addresses and wildcard * are rejected.</text>
    <line class="rule" x1="467" y1="735" x2="1559" y2="735"/>

    <text class="subsection" x="467" y="768">Access policy</text>
    <text class="tiny muted" x="467" y="791">Determines permitted paths; services sharing it still choose independently.</text>
    <rect class="panel-soft" x="467" y="805" width="520" height="54" rx="6"/>
    <text class="body" x="483" y="829">Best egress</text><text class="tiny muted mono" x="483" y="848">best-egress</text>
    <path d="M959 825l5 5 5-5" fill="none" stroke="#717674" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>

    <text class="subsection" x="1037" y="768">Routing ownership</text>
    <text class="tiny muted" x="1037" y="791">This service is applied by the centrally managed rule set.</text>
    <circle class="quiet-dot" cx="1042" cy="824" r="4"/><text class="body green" x="1055" y="829">Centrally managed</text>
    <text class="tiny muted" x="1037" y="848">Clients do not select a port, policy or exit for this service.</text>
    <line class="rule" x1="467" y1="879" x2="1559" y2="879"/>

    <text class="small muted" x="467" y="906">RUNTIME</text><text class="body" x="555" y="906">Current path and health are observed in Live paths.</text>
    <text class="tiny amber" x="1080" y="906">Unmatched telemetry · Planned</text>
    <text class="small green" x="1431" y="906">View live path</text><use href="#icon-arrow-right" x="1526" y="894" width="14" height="14" class="action-icon"/>
    <line class="rule" x1="467" y1="921" x2="1559" y2="921"/>

    <circle class="quiet-dot" cx="472" cy="951" r="4"/><text class="small green" x="485" y="956">All fields valid</text>
    <text class="tiny muted" x="616" y="956">Save validates, writes SSOT atomically and publishes automatically.</text>
    <rect class="panel" x="1290" y="932" width="112" height="39" rx="6"/><text class="small" x="1346" y="956" text-anchor="middle">Discard</text>
    <rect class="button-green" x="1417" y="932" width="142" height="39" rx="6"/>
    <use href="#icon-save" x="1437" y="944" width="14" height="14" stroke="#FFFFFF" fill="none" stroke-width="1.4" stroke-linejoin="round"/>
    <text class="small" x="1462" y="956" fill="#FFFFFF">Save service</text>
  </g>
'''
    return shell(
        active="Services",
        eyebrow="TRAFFIC / SERVICES",
        title="Services",
        subtitle="Group destination hostnames and choose how each group reaches the internet",
        status="2 services configured · unmatched hosts fail closed",
        description="A flat service catalog and editor separating desired host and policy configuration from runtime routing observations.",
        body=body,
        session_status="Design target",
    )


def routes_page() -> str:
    body = r'''
  <!-- Runtime routing summary. Service definitions are managed on the Services page. -->
  <rect class="panel" x="21" y="202" width="1538" height="82" rx="7"/>
  <g class="ui">
    <text class="small muted" x="46" y="232">SERVICES</text><text class="metric" x="46" y="258">2 configured</text>
    <text class="small muted" x="329" y="232">ACCESS POLICIES</text><text class="metric" x="329" y="258">3 configured</text>
    <text class="small muted" x="646" y="232">AUTOMATIC DECISIONS</text><text class="metric" x="646" y="258">2 / 2 fresh</text>
    <text class="small muted" x="972" y="232">ELIGIBLE CANDIDATES</text><text class="metric" x="972" y="258">30 evaluated</text>
    <rect class="panel-soft" x="1304" y="221" width="228" height="39" rx="6"/>
    <use href="#icon-services" x="1343" y="233" width="15" height="15" class="action-icon"/>
    <text class="small" x="1370" y="246">Manage services</text>
    <use href="#icon-arrow-right" x="1486" y="233" width="15" height="15" class="action-icon"/>
  </g>
  <line class="rule" x1="300" y1="222" x2="300" y2="265"/><line class="rule" x1="617" y1="222" x2="617" y2="265"/><line class="rule" x1="943" y1="222" x2="943" y2="265"/><line class="rule" x1="1275" y1="222" x2="1275" y2="265"/>

  <!-- Observed paths, not a configuration surface. -->
  <rect class="panel" x="21" y="300" width="537" height="500" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="330">Automatic routing scopes</text><text class="tiny muted" x="538" y="330" text-anchor="end">read-only</text>

    <text class="subsection" x="49" y="375">Domestic web <tspan class="mono muted">· cn-web</tspan></text><text class="tiny muted" x="49" y="394">Service rule · latency policy</text>
    <text class="body mono blue" x="49" y="417">jm24 → local exit</text><circle class="quiet-dot" cx="480" cy="390" r="4"/><text class="tiny green" x="493" y="394">Fresh</text><text class="tiny muted" x="528" y="414" text-anchor="end">15 candidates</text>
    <line class="rule" x1="41" y1="438" x2="538" y2="438"/>

    <rect x="31" y="448" width="517" height="78" rx="6" fill="#EEF3FB"/>
    <rect x="31" y="448" width="3" height="78" rx="1.5" fill="#466FC2"/>
    <text class="subsection" x="49" y="472">International API <tspan class="mono muted">· intl-api</tspan></text><text class="tiny muted" x="49" y="491">Service rule · best-egress policy</text>
    <text class="body mono blue" x="49" y="514">jm24 → ber01</text><circle class="quiet-dot" cx="480" cy="487" r="4"/><text class="tiny green" x="493" y="491">Fresh</text><text class="tiny muted" x="528" y="511" text-anchor="end">15 candidates</text>

    <rect class="panel-soft" x="41" y="552" width="497" height="190" rx="6"/>
    <text class="subsection" x="59" y="582">How a decision is produced</text>
    <circle cx="65" cy="612" r="9" fill="#FFFFFF" stroke="#CBD0CD"/><text class="tiny muted" x="65" y="616" text-anchor="middle">1</text><text class="body" x="85" y="617">Host matches a managed Service rule.</text>
    <circle cx="65" cy="650" r="9" fill="#FFFFFF" stroke="#CBD0CD"/><text class="tiny muted" x="65" y="654" text-anchor="middle">2</text><text class="body" x="85" y="655">The Service references an Access policy.</text>
    <circle cx="65" cy="688" r="9" fill="#FFFFFF" stroke="#CBD0CD"/><text class="tiny muted" x="65" y="692" text-anchor="middle">3</text><text class="body" x="85" y="693">The Agent evaluates candidates and applies one.</text>
    <text class="tiny muted" x="59" y="723">Clients use the single automatic ingress; this page does not set a path.</text>
  </g>

  <!-- Focused routing-entry detail. -->
  <g class="ui">
    <text class="section" x="594" y="330">International API <tspan class="mono muted">· intl-api</tspan></text><text class="tiny muted" x="940" y="330">Service rule · automatic decision</text>
    <rect class="chip-green" x="1401" y="313" width="136" height="27" rx="13.5"/><circle class="quiet-dot" cx="1418" cy="326" r="3.5"/><text class="tiny green" x="1429" y="330">Fresh on jm24</text>

    <line x1="770" y1="405" x2="1260" y2="405" stroke="#466FC2" stroke-width="2.4"/>
    <path d="M1252 400L1261 405L1252 410" fill="none" stroke="#466FC2" stroke-width="2"/>
    <circle cx="759" cy="405" r="10" fill="#FFFFFF" stroke="#466FC2" stroke-width="2"/><circle cx="1272" cy="405" r="10" fill="#FFFFFF" stroke="#466FC2" stroke-width="2"/>
    <text class="body mono" x="759" y="438" text-anchor="middle">jm24</text><text class="body mono" x="1272" y="438" text-anchor="middle">ber01</text>
    <text class="tiny muted" x="759" y="458" text-anchor="middle">access node</text><text class="tiny muted" x="1272" y="458" text-anchor="middle">Agent-selected egress</text>

    <text class="small muted" x="594" y="498">SOURCE</text><text class="body" x="756" y="498">jm24 /status · signed selector read-back</text>
    <text class="small muted" x="594" y="526">UPDATED</text><text class="body mono" x="756" y="526">2026-08-27 17:50:52 UTC</text><text class="tiny muted" x="1012" y="526">each Service decision is reported independently</text>
    <text class="small muted" x="594" y="554">MEANING</text><text class="body" x="756" y="554">Applied routing state · not proof that traffic is active</text>
    <line class="rule" x1="594" y1="576" x2="1539" y2="576"/>

    <text class="subsection" x="594" y="606">Access policy</text>
    <text class="small muted" x="594" y="635">Objective</text><text class="body" x="704" y="635">latency</text>
    <text class="small muted" x="886" y="635">Egress</text><text class="body mono" x="962" y="635">best eligible</text>
    <text class="small muted" x="1162" y="635">Cadence</text><text class="body" x="1247" y="635">10 minutes</text>
    <text class="small muted" x="594" y="665">Window</text><text class="body" x="704" y="665">2 hours</text>
    <text class="small muted" x="886" y="665">Min samples</text><text class="body" x="1002" y="665">6</text>
    <text class="small muted" x="1162" y="665">Switch threshold</text><text class="body" x="1305" y="665">20%</text>
    <line class="rule" x1="594" y1="686" x2="1539" y2="686"/>

    <text class="subsection" x="594" y="716">Agent evaluation summary</text>
    <text class="body green" x="594" y="747">5 healthy</text><text class="body" x="713" y="747">· 0 degraded · 0 failed · 5 stale · 5 unknown</text>
    <text class="tiny muted" x="594" y="772">Source · signed jm24 Agent report · per-candidate detail is not reported centrally.</text>
  </g>

  <!-- Candidate paths for the focused routing entry. -->
  <rect class="panel" x="21" y="816" width="1538" height="157" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="846">Eligible paths for <tspan class="mono">intl-api</tspan></text>
    <text class="tiny muted" x="390" y="846">Generated from SSOT. The blue row is Agent-selected; eligibility alone does not imply health.</text>
    <text class="small muted" x="47" y="877">PATH</text><text class="small muted" x="633" y="877">STATUS</text><text class="small muted" x="972" y="877">SOURCE</text><text class="small muted" x="1347" y="877">EGRESS</text>
    <line class="rule" x1="41" y1="885" x2="1539" y2="885"/>
    <text class="body mono" x="47" y="910">jm24 → local exit</text><text class="body muted" x="633" y="910">Eligible · not selected</text><text class="body muted" x="972" y="910">generated from SSOT</text><text class="body mono" x="1347" y="910">jm24</text>
    <text class="body mono blue" x="47" y="938">jm24 → ber01</text><circle cx="637" cy="933" r="4" fill="#466FC2"/><text class="body blue" x="650" y="938">Agent-selected path</text><text class="body" x="972" y="938">jm24 /status · signed selector</text><text class="body mono" x="1347" y="938">ber01</text>
    <text class="body mono" x="47" y="966">jm24 → sg02</text><text class="body muted" x="633" y="966">Eligible · not selected</text><text class="body muted" x="972" y="966">generated from SSOT</text><text class="body mono" x="1347" y="966">sg02</text>
  </g>
  <line class="rule" x1="41" y1="918" x2="1539" y2="918"/><line class="rule" x1="41" y1="946" x2="1539" y2="946"/>
'''
    return shell(
        active="Routing",
        eyebrow="AGENT / TRAFFIC",
        title="Live paths",
        subtitle="Read-only automatic decisions generated from Service rules and Access policies",
        status="Agent applies paths automatically; control center observes signed state",
        description="A read-only runtime view showing the two Service-scoped Agent decisions, one diagnostic focus, and its automatically generated alternatives.",
        body=body,
    )


def deployments_page() -> str:
    body = r'''
  <!-- Release summary -->
  <rect class="panel" x="21" y="202" width="1538" height="86" rx="7"/>
  <g class="ui">
    <text class="small muted" x="47" y="234">PUBLISHER</text><circle class="status-dot" cx="51" cy="257" r="4"/><text class="metric" x="64" y="262">Heartbeat healthy</text>
    <text class="small muted" x="421" y="234">FLEET SNAPSHOT</text><text class="metric mono" x="421" y="262">4f09f6f5716d</text>
    <text class="small muted" x="786" y="234">ROLLOUT</text><text class="metric" x="786" y="262">5 / 5 verified</text>
    <text class="small muted" x="1106" y="234">DISTRIBUTION POINTER</text><circle class="warn-dot" cx="1110" cy="257" r="4"/><text class="metric amber" x="1123" y="262">Legacy current</text><text class="tiny muted" x="1293" y="261">floor not reported · signed current planned</text>
  </g>
  <line class="rule" x1="386" y1="222" x2="386" y2="269"/><line class="rule" x1="751" y1="222" x2="751" y2="269"/><line class="rule" x1="1071" y1="222" x2="1071" y2="269"/>

  <!-- Publisher -->
  <rect class="panel" x="21" y="304" width="511" height="392" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="334">Publisher</text>
    <rect class="chip-green" x="401" y="316" width="108" height="27" rx="13.5"/><circle class="quiet-dot" cx="418" cy="329" r="3.5"/><text class="tiny green" x="429" y="333">Healthy</text>
    <text class="tiny muted" x="41" y="357">Automatic release worker on jm24</text>
    <text class="small muted" x="41" y="395">HEARTBEAT</text><text class="body" x="218" y="395">8s ago</text>
    <text class="small muted" x="41" y="427">INTERVAL</text><text class="body" x="218" y="427">30 seconds</text>
    <text class="small muted" x="41" y="459">LOOM CODE</text><text class="body mono" x="218" y="459">28224ed</text>
    <text class="small muted" x="41" y="491">BINARY</text><text class="body mono" x="218" y="491">449597b5…</text>
    <text class="small muted" x="41" y="523">LAST SUCCESS</text><text class="body" x="218" y="523">19h ago</text>
    <text class="small muted" x="41" y="555">LAST SNAPSHOT</text><text class="body mono" x="218" y="555">4f09f6f5716d</text>
    <line class="rule" x1="41" y1="579" x2="512" y2="579"/>
    <text class="tiny muted" x="41" y="607">No new publish is expected while SSOT and renderer output are unchanged.</text>
    <text class="tiny muted" x="41" y="629">Heartbeat freshness, not release age, determines publisher health.</text>
    <rect class="chip" x="41" y="650" width="168" height="27" rx="6"/><text class="tiny" x="125" y="668" text-anchor="middle">No manual Publish action</text>
    <text class="tiny muted" x="225" y="668">Fleet rollout · not code deployment history</text>
  </g>

  <!-- Node convergence -->
  <rect class="panel" x="548" y="304" width="1011" height="392" rx="7"/>
  <g class="ui">
    <text class="section" x="568" y="334">Fleet convergence</text><text class="tiny muted" x="742" y="334">target snapshot <tspan class="mono">4f09f6f5716d</tspan></text>
    <text class="small muted" x="574" y="369">NODE</text><text class="small muted" x="743" y="369">TARGET</text><text class="small muted" x="928" y="369">STAGE</text><text class="small muted" x="1098" y="369">ENTERED</text><text class="small muted" x="1281" y="369">LAST GOOD</text><text class="small muted" x="1438" y="369">DRIFT</text>
    <line class="rule" x1="568" y1="377" x2="1539" y2="377"/>
    <text class="body mono" x="574" y="412">jm24</text><text class="body mono" x="743" y="412">4f09f6f</text><circle class="quiet-dot" cx="932" cy="407" r="4"/><text class="body" x="945" y="412">Verified</text><text class="body" x="1098" y="412">19h ago</text><text class="body mono" x="1281" y="412">3e8d7c2a</text><text class="tiny muted" x="1438" y="412">Not reported</text>
    <text class="body mono" x="574" y="463">gz02</text><text class="body mono" x="743" y="463">4f09f6f</text><circle class="quiet-dot" cx="932" cy="458" r="4"/><text class="body" x="945" y="463">Verified</text><text class="body" x="1098" y="463">19h ago</text><text class="body mono" x="1281" y="463">3e8d7c2a</text><text class="tiny muted" x="1438" y="463">Not reported</text>
    <text class="body mono" x="574" y="514">hz01</text><text class="body mono" x="743" y="514">4f09f6f</text><circle class="quiet-dot" cx="932" cy="509" r="4"/><text class="body" x="945" y="514">Verified</text><text class="body" x="1098" y="514">19h ago</text><text class="body mono" x="1281" y="514">3e8d7c2a</text><text class="tiny muted" x="1438" y="514">Not reported</text>
    <text class="body mono" x="574" y="565">sg02</text><text class="body mono" x="743" y="565">4f09f6f</text><circle class="quiet-dot" cx="932" cy="560" r="4"/><text class="body" x="945" y="565">Verified</text><text class="body" x="1098" y="565">19h ago</text><text class="body mono" x="1281" y="565">3e8d7c2a</text><text class="tiny muted" x="1438" y="565">Not reported</text>
    <text class="body mono" x="574" y="616">ber01</text><text class="body mono" x="743" y="616">4f09f6f</text><circle class="quiet-dot" cx="932" cy="611" r="4"/><text class="body" x="945" y="616">Verified</text><text class="body" x="1098" y="616">19h ago</text><text class="body mono" x="1281" y="616">3e8d7c2a</text><text class="tiny muted" x="1438" y="616">Not reported</text>
    <line class="rule" x1="568" y1="431" x2="1539" y2="431"/><line class="rule" x1="568" y1="482" x2="1539" y2="482"/><line class="rule" x1="568" y1="533" x2="1539" y2="533"/><line class="rule" x1="568" y1="584" x2="1539" y2="584"/><line class="rule" x1="568" y1="635" x2="1539" y2="635"/>
    <text class="tiny muted" x="568" y="668">A node is converged only after its local verifier records the target snapshot as verified.</text>
  </g>

  <!-- Release pipeline -->
  <rect class="panel" x="21" y="712" width="1004" height="261" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="742">Automatic release workflow</text><text class="tiny amber" x="315" y="742">Stage history is not reported</text>
    <text class="tiny muted" x="41" y="764">Saving a valid SSOT change is the only write; the publisher owns every downstream stage.</text>
    <line class="timeline" x1="87" y1="830" x2="955" y2="830"/>
    <circle class="neutral-dot" cx="87" cy="830" r="5"/><circle class="neutral-dot" cx="232" cy="830" r="5"/><circle class="neutral-dot" cx="377" cy="830" r="5"/><circle class="neutral-dot" cx="522" cy="830" r="5"/><circle class="neutral-dot" cx="667" cy="830" r="5"/><circle class="neutral-dot" cx="812" cy="830" r="5"/><circle class="neutral-dot" cx="955" cy="830" r="5"/>
    <text class="small" x="87" y="860" text-anchor="middle">Validate</text><text class="small" x="232" y="860" text-anchor="middle">Render</text><text class="small" x="377" y="860" text-anchor="middle">Sign</text><text class="small" x="522" y="860" text-anchor="middle">Distribute</text><text class="small" x="667" y="860" text-anchor="middle">Pull</text><text class="small" x="812" y="860" text-anchor="middle">Apply</text><text class="small" x="955" y="860" text-anchor="middle">Verify</text>
    <text class="tiny muted" x="87" y="882" text-anchor="middle">SSOT</text><text class="tiny muted" x="232" y="882" text-anchor="middle">per node</text><text class="tiny muted" x="377" y="882" text-anchor="middle">manifest</text><text class="tiny muted" x="522" y="882" text-anchor="middle">snapshot</text><text class="tiny muted" x="667" y="882" text-anchor="middle">timer</text><text class="tiny muted" x="812" y="882" text-anchor="middle">atomic</text><text class="tiny muted" x="955" y="882" text-anchor="middle">local</text>
    <line class="rule" x1="41" y1="909" x2="1005" y2="909"/>
    <text class="small muted" x="41" y="938">LATEST FLEET</text><text class="body" x="153" y="938">Snapshot manifest signed · distributed · verified by 5 nodes</text><text class="tiny muted mono" x="870" y="938">publisher code 28224ed</text>
  </g>

  <!-- Distribution contract -->
  <rect class="panel" x="1041" y="712" width="518" height="261" rx="7"/>
  <g class="ui">
    <text class="section" x="1061" y="742">Distribution &amp; safety boundary</text>
    <text class="small muted" x="1061" y="778">SNAPSHOT MANIFEST</text><text class="body green" x="1267" y="778">Signed</text>
    <text class="small muted" x="1061" y="810">CURRENT POINTER</text><text class="body amber" x="1267" y="810">Legacy / unsigned</text>
    <text class="small muted" x="1061" y="842">NODE ROLLBACK</text><text class="body" x="1267" y="842">Last verified snapshot</text>
    <line class="rule" x1="1061" y1="866" x2="1539" y2="866"/>
    <text class="tiny muted" x="1061" y="889">A manifest signature proves content authenticity, not pointer freshness.</text>
    <rect class="chip-amber" x="1061" y="903" width="478" height="43" rx="6"/>
    <text class="tiny amber" x="1077" y="922">Canary controller + representative business-path gate</text>
    <text class="tiny muted" x="1077" y="939">Not implemented · no Promote or Rollback action in the web UI</text>
    <text class="tiny muted" x="1061" y="964">Signed-current reader rollout remains pending.</text>
  </g>
'''
    return shell(
        active="Deployments",
        eyebrow="CONTROL PLANE / RELEASE",
        title="Fleet deployments",
        subtitle="jm24 publisher · heartbeat 8s ago · reconciliation interval 30s",
        status="Latest fleet snapshot verified across 5 nodes · business-path canary planned",
        description="A fleet-configuration deployment view showing publisher heartbeat, node rollout state, the declared automatic release workflow, and the pending signed-current pointer migration; it is not source-code deployment history.",
        body=body,
    )


def events_page() -> str:
    body = r'''
  <!-- Current unresolved state summary -->
  <rect class="panel" x="21" y="202" width="1538" height="86" rx="7"/>
  <g class="ui">
    <text class="small muted" x="47" y="234">CURRENT ISSUES</text><text class="metric green" x="47" y="262">0 unresolved</text>
    <text class="small muted" x="393" y="234">PENDING WINDOWS</text><text class="metric" x="393" y="262">0 current</text>
    <text class="small muted" x="706" y="234">HISTORY TOTAL</text><text class="metric muted" x="706" y="262">Not reported</text>
    <text class="small muted" x="1112" y="234">RETENTION</text><text class="metric" x="1112" y="262">30 days</text>
    <text class="tiny muted" x="1272" y="261">change events only</text>
  </g>
  <line class="rule" x1="358" y1="222" x2="358" y2="269"/><line class="rule" x1="671" y1="222" x2="671" y2="269"/><line class="rule" x1="1077" y1="222" x2="1077" y2="269"/>

  <!-- Event stream -->
  <rect class="panel" x="21" y="304" width="1069" height="669" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="334">State transitions</text>
    <text class="tiny muted" x="41" y="356">A quiet system produces no events. Current truth is read separately from the tracker.</text>
    <text class="small muted" x="47" y="392">TIME</text><text class="small muted" x="173" y="392">NODE</text><text class="small muted" x="303" y="392">KIND / SUBJECT</text><text class="small muted" x="574" y="392">TRANSITION</text><text class="small muted" x="866" y="392">DURATION</text>
    <line class="rule" x1="41" y1="400" x2="1070" y2="400"/>

    <text class="body mono muted" x="47" y="438">12:08:36</text><text class="body mono" x="173" y="438">jm24</text><text class="body" x="303" y="438">route · intl-api</text><circle class="neutral-dot" cx="578" cy="433" r="4"/><text class="body" x="591" y="438">sg02 → ber01</text><text class="body muted" x="866" y="438">5.8h · ongoing</text>
    <text class="tiny muted" x="303" y="457">Candidate p95 1249 ms · 34% better · threshold 20%.</text>

    <text class="body mono muted" x="47" y="501">07:06:46</text><text class="body mono" x="173" y="501">jm24</text><text class="body" x="303" y="501">route · intl-api</text><circle class="neutral-dot" cx="578" cy="496" r="4"/><text class="body" x="591" y="501">ber01 → sg02</text><text class="body muted" x="866" y="501">5.0h</text>
    <text class="tiny muted" x="303" y="520">Candidate p95 1523 ms · 57% better · threshold 20%.</text>

    <text class="body mono muted" x="47" y="564">00:14:31</text><text class="body mono" x="173" y="564">jm24</text><text class="body" x="303" y="564">route · intl-api</text><circle class="neutral-dot" cx="578" cy="559" r="4"/><text class="body" x="591" y="564">sg02 → ber01</text><text class="body muted" x="866" y="564">6.9h</text>
    <text class="tiny muted" x="303" y="583">Candidate p95 780 ms · 43% better · threshold 20%.</text>

    <text class="body mono muted" x="47" y="627">08-26 22:11</text><text class="body mono" x="173" y="627">jm24</text><text class="body" x="303" y="627">snapshot</text><circle class="neutral-dot" cx="578" cy="622" r="4"/><text class="body" x="591" y="627">ad7d33b8 → 4f09f6f</text><text class="body muted" x="866" y="627">—</text>
    <text class="tiny muted" x="303" y="646">Informational release change; not a health incident.</text>

    <text class="body mono muted" x="47" y="690">08-26 22:11</text><text class="body mono" x="173" y="690">gz02</text><text class="body" x="303" y="690">snapshot</text><circle class="neutral-dot" cx="578" cy="685" r="4"/><text class="body" x="591" y="690">ad7d33b8 → 4f09f6f</text><text class="body muted" x="866" y="690">—</text>
    <text class="tiny muted" x="303" y="709">Recorded independently for each node observation.</text>

    <text class="body mono muted" x="47" y="753">08-26 22:11</text><text class="body mono" x="173" y="753">hz01</text><text class="body" x="303" y="753">snapshot</text><circle class="neutral-dot" cx="578" cy="748" r="4"/><text class="body" x="591" y="753">ad7d33b8 → 4f09f6f</text><text class="body muted" x="866" y="753">—</text>
    <text class="tiny muted" x="303" y="772">Recorded independently for each node observation.</text>

    <text class="body mono muted" x="47" y="816">08-26 22:11</text><text class="body mono" x="173" y="816">sg02</text><text class="body" x="303" y="816">snapshot</text><circle class="neutral-dot" cx="578" cy="811" r="4"/><text class="body" x="591" y="816">ad7d33b8 → 4f09f6f</text><text class="body muted" x="866" y="816">—</text>
    <text class="tiny muted" x="303" y="835">Recorded independently for each node observation.</text>

    <text class="body mono muted" x="47" y="879">08-26 22:11</text><text class="body mono" x="173" y="879">ber01</text><text class="body" x="303" y="879">snapshot</text><circle class="neutral-dot" cx="578" cy="874" r="4"/><text class="body" x="591" y="879">ad7d33b8 → 4f09f6f</text><text class="body muted" x="866" y="879">—</text>
    <text class="tiny muted" x="303" y="898">Recorded independently for each node observation.</text>

    <line class="rule" x1="41" y1="474" x2="1070" y2="474"/><line class="rule" x1="41" y1="537" x2="1070" y2="537"/><line class="rule" x1="41" y1="600" x2="1070" y2="600"/><line class="rule" x1="41" y1="663" x2="1070" y2="663"/><line class="rule" x1="41" y1="726" x2="1070" y2="726"/><line class="rule" x1="41" y1="789" x2="1070" y2="789"/><line class="rule" x1="41" y1="852" x2="1070" y2="852"/><line class="rule" x1="41" y1="915" x2="1070" y2="915"/>
    <text class="tiny muted" x="41" y="950">8 example transitions · total count and pagination are not reported</text><use href="#icon-download" x="965" y="939" width="14" height="14" class="action-icon"/><text class="tiny green" x="986" y="950">Filtered CSV export</text>
  </g>

  <!-- Filters -->
  <rect class="panel" x="1106" y="304" width="453" height="242" rx="7"/>
  <g class="ui">
    <use href="#icon-filter" x="1126" y="321" width="16" height="16" class="action-icon"/><text class="section" x="1150" y="334">Filter</text><text class="tiny green" x="1202" y="334">SSR query · implemented</text>
    <rect class="chip-green" x="1126" y="357" width="75" height="30" rx="5"/><text class="small green" x="1163" y="377" text-anchor="middle">All</text>
    <rect class="chip" x="1209" y="357" width="97" height="30" rx="5"/><text class="small" x="1257" y="377" text-anchor="middle">Problems</text>
    <rect class="chip" x="1314" y="357" width="105" height="30" rx="5"/><text class="small" x="1366" y="377" text-anchor="middle">Recoveries</text>
    <rect class="chip" x="1427" y="357" width="105" height="30" rx="5"/><text class="small" x="1479" y="377" text-anchor="middle">Changes</text>
    <text class="small muted" x="1126" y="424">NODE</text><text class="body" x="1262" y="424">All nodes</text><text class="tiny green" x="1503" y="424">Change</text>
    <text class="small muted" x="1126" y="456">KIND</text><text class="body" x="1262" y="456">All event kinds</text><text class="tiny green" x="1503" y="456">Change</text>
    <text class="small muted" x="1126" y="488">RANGE</text><text class="body" x="1262" y="488">Last 24 hours</text><text class="tiny green" x="1503" y="488">Change</text>
    <line class="rule" x1="1126" y1="504" x2="1539" y2="504"/>
    <text class="tiny muted" x="1126" y="520">Node, kind, level and text filters use SSR query parameters.</text>
    <text class="tiny muted" x="1126" y="536">Filters affect history only, never the current issue count.</text>
  </g>

  <!-- Semantics -->
  <rect class="panel" x="1106" y="562" width="453" height="411" rx="7"/>
  <g class="ui">
    <text class="section" x="1126" y="592">Event semantics</text>

    <circle class="bad-dot" cx="1131" cy="628" r="4"/><text class="subsection" x="1144" y="633">Problem</text>
    <text class="tiny muted" x="1126" y="654">Tunnel, reach, edge, identity, rollout,</text><text class="tiny muted" x="1126" y="671">uplink or publisher enters a bad state.</text>

    <circle class="quiet-dot" cx="1131" cy="707" r="4"/><text class="subsection" x="1144" y="712">Recovery</text>
    <text class="tiny muted" x="1126" y="733">A previously bad state returns to normal.</text>

    <circle class="neutral-dot" cx="1131" cy="769" r="4"/><text class="subsection" x="1144" y="774">Information</text>
    <text class="tiny muted" x="1126" y="795">Snapshot, route and target changes describe</text><text class="tiny muted" x="1126" y="812">normal system behavior or pruning data.</text>

    <circle class="warn-dot" cx="1131" cy="848" r="4"/><text class="subsection" x="1144" y="853">Pending</text>
    <text class="tiny muted" x="1126" y="874">A safe transition that should not remain open,</text><text class="tiny muted" x="1126" y="891">such as a credential rotation window.</text>

    <line class="rule" x1="1126" y1="915" x2="1539" y2="915"/>
    <text class="tiny muted" x="1126" y="940">History explains when and for how long.</text>
    <text class="tiny muted" x="1126" y="957">It never substitutes for present-state observation.</text>
  </g>
'''
    return shell(
        active="Events",
        eyebrow="OPERATIONS / HISTORY",
        title="Events",
        subtitle="State transitions only · current truth comes from the separate state tracker",
        status="No current unresolved issues · history total is not reported",
        description="An operations event history that separates current state from transition history and classifies problems, recoveries, informational changes, and pending windows.",
        body=body,
    )


def settings_page() -> str:
    body = r'''
  <!-- Settings context -->
  <rect class="panel" x="21" y="202" width="1538" height="72" rx="7"/>
  <g class="ui">
    <text class="small muted" x="45" y="232">CONTROL NODE</text><text class="body mono" x="45" y="256">jm24</text>
    <text class="small muted" x="384" y="232">WRITE AUTHORITY</text><text class="body" x="384" y="256">Single control node</text>
    <text class="small muted" x="800" y="232">DISTRIBUTED SNAPSHOT</text><text class="body mono" x="800" y="256">4f09f6f5716d</text>
    <text class="small muted" x="1125" y="232">PUBLISH CADENCE</text><text class="body" x="1125" y="256">≤ 30s</text>
    <text class="tiny muted" x="1231" y="256">fleet target ≤ 90s · no publish button</text>
  </g>
  <line class="rule" x1="349" y1="219" x2="349" y2="259"/><line class="rule" x1="765" y1="219" x2="765" y2="259"/><line class="rule" x1="1090" y1="219" x2="1090" y2="259"/>

  <!-- Tabs -->
  <g class="ui nav">
    <text x="21" y="311" font-weight="600">Raw SSOT</text><text class="muted" x="110" y="311">Secret references · Planned</text><text class="muted" x="320" y="311">Release policy · Planned</text>
  </g>
  <line x1="21" y1="325" x2="78" y2="325" stroke="#2AA875" stroke-width="2"/>
  <line class="rule" x1="21" y1="325" x2="1559" y2="325"/>

  <!-- The implemented surface is the authenticated raw /ssot YAML editor. -->
  <rect class="panel" x="21" y="341" width="1005" height="632" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="373">Raw SSOT editor</text>
    <text class="tiny muted" x="218" y="373">Full YAML buffer · viewport shown below</text>
    <rect class="chip" x="735" y="354" width="116" height="30" rx="5"/><use href="#icon-check" x="750" y="362" width="14" height="14" class="action-icon"/><text class="small" x="812" y="374" text-anchor="middle">Validate</text>
    <rect class="button-green" x="860" y="354" width="144" height="30" rx="5"/><use href="#icon-save" x="875" y="362" width="14" height="14" class="action-icon" style="stroke:#FFFFFF"/><text class="small" x="945" y="374" text-anchor="middle" fill="#FFFFFF">Validate &amp; save</text>
    <text class="tiny muted" x="41" y="404">GET /ssot · POST /ssot · viewport lines 11–33</text><text class="tiny green" x="1004" y="404" text-anchor="end">Write session · node-local operator_ref</text>
  </g>

  <rect class="code-bg" x="41" y="419" width="965" height="532" rx="5"/>
  <rect x="41" y="419" width="46" height="532" rx="5" fill="#F1F3F2"/>
  <line class="rule" x1="87" y1="419" x2="87" y2="951"/>
  <g class="ui tiny mono muted" text-anchor="end">
    <text x="76" y="447">11</text><text x="76" y="469">12</text><text x="76" y="491">13</text><text x="76" y="513">14</text><text x="76" y="535">15</text><text x="76" y="557">16</text><text x="76" y="579">17</text><text x="76" y="601">18</text><text x="76" y="623">19</text><text x="76" y="645">20</text><text x="76" y="667">21</text><text x="76" y="689">22</text><text x="76" y="711">23</text><text x="76" y="733">24</text><text x="76" y="755">25</text><text x="76" y="777">26</text><text x="76" y="799">27</text><text x="76" y="821">28</text><text x="76" y="843">29</text><text x="76" y="865">30</text><text x="76" y="887">31</text><text x="76" y="909">32</text><text x="76" y="931">33</text>
  </g>
  <g class="ui body mono">
    <text x="101" y="447"><tspan class="blue">defaults</tspan>:</text>
    <text x="101" y="469">  <tspan class="faint"># Control, signing and publishing live on jm24.</tspan></text>
    <text x="101" y="491">  <tspan class="faint"># Forwarding continues if that writer is unavailable.</tspan></text>
    <text x="101" y="513">  <tspan class="faint"># Writer state can be moved with SSOT and signing material.</tspan></text>
    <text x="101" y="535"> </text>
    <text x="101" y="557">  <tspan class="faint"># Nodes fetch signed immutable snapshots from this origin.</tspan></text>
    <text x="101" y="579">  <tspan class="faint"># Distribution transport itself is not trusted.</tspan></text>
    <text x="101" y="601">  <tspan class="faint"># Node-local pinned trust verifies the manifest.</tspan></text>
    <text x="101" y="623">  <tspan class="blue">distribution_url</tspan>: <tspan class="green">https://psi-ai.cn/loom/</tspan></text>
    <text x="101" y="645">  <tspan class="faint"># Resolver defaults are selected for the deployed region.</tspan></text>
    <text x="101" y="667">  <tspan class="faint"># Request-derived destinations still resolve at the selected egress.</tspan></text>
    <text x="101" y="689">  <tspan class="faint"># The raw buffer continues; this is only the visible viewport.</tspan></text>
    <text x="101" y="711">  <tspan class="blue">dns</tspan>: [<tspan class="green">223.5.5.5</tspan>, <tspan class="green">119.29.29.29</tspan>]</text>
    <text x="101" y="733"> </text>
    <text x="101" y="755">  <tspan class="blue">components</tspan>:</text>
    <text x="101" y="777">    <tspan class="blue">sing_box</tspan>: <tspan class="green">1.11.4</tspan></text>
    <text x="101" y="799">    <tspan class="blue">wireguard</tspan>: <tspan class="green">1.0.20250521</tspan></text>
    <text x="101" y="821">    <tspan class="blue">agent</tspan>: <tspan class="green">0.1.0</tspan></text>
    <text x="101" y="843"> </text>
    <text x="101" y="865"><tspan class="blue">nodes</tspan>:</text>
    <text x="101" y="887">  <tspan class="faint"># Domestic nodes have public endpoints; no mesh is deployed.</tspan></text>
    <text x="101" y="909">  <tspan class="faint"># Candidate paths are distinct from persistent WireGuard edges.</tspan></text>
    <text x="101" y="931">  <tspan class="faint"># Scroll for complete node, tunnel, declaration and service entries.</tspan></text>
  </g>

  <!-- Validation and automatic publication contract -->
  <rect class="panel" x="1042" y="341" width="517" height="632" rx="7"/>
  <g class="ui">
    <text class="section" x="1062" y="373">Validation</text>
    <circle class="status-dot" cx="1067" cy="406" r="4"/><text class="body green" x="1080" y="411">Current file passes all checks</text>
    <text class="small muted" x="1062" y="443">Schema</text><text class="body" x="1207" y="443">Valid</text>
    <text class="small muted" x="1062" y="471">Topology</text><text class="body" x="1207" y="471">5 nodes · 6 tunnels</text>
    <text class="small muted" x="1062" y="499">Routing entries</text><text class="body" x="1207" y="499">5 renderable</text>
    <text class="tiny muted" x="1062" y="522">Save performs validation again; the UI check is not the guard.</text>
  </g>

  <line class="rule" x1="1062" y1="545" x2="1539" y2="545"/>
  <g class="ui">
    <text class="section" x="1062" y="585">What happens after save</text>
    <text class="body" x="1062" y="619">1</text><text class="body" x="1093" y="619">Atomic SSOT write after validation</text>
    <text class="body" x="1062" y="650">2</text><text class="body" x="1093" y="650">Publisher detects the change within ~30s</text>
    <text class="body" x="1062" y="681">3</text><text class="body" x="1093" y="681">Render, sign and distribute immutable snapshot</text>
    <text class="body" x="1062" y="712">4</text><text class="body" x="1093" y="712">Nodes pull, apply, verify or stay on last good</text>
    <line class="rule" x1="1062" y1="731" x2="1539" y2="731"/>
    <text class="tiny muted" x="1062" y="751">There is deliberately no second, manual Publish decision.</text>
  </g>

  <line class="rule" x1="1062" y1="772" x2="1539" y2="772"/>
  <g class="ui">
    <text class="section" x="1062" y="812">Security boundary &amp; gaps</text>
    <text class="small muted" x="1062" y="841">AUTH SOURCE</text><text class="body" x="1238" y="841">Node-local secrets · operator_ref</text>
    <text class="small muted" x="1062" y="869">CONTROL BOOTSTRAP</text><text class="body" x="1238" y="869">/etc/loom/control.json · not editable here</text>
    <text class="small muted" x="1062" y="897">PRIVATE KEYS</text><text class="body" x="1238" y="897">Never shown or stored in SSOT</text>
    <line class="rule" x1="1062" y1="912" x2="1539" y2="912"/>
    <text class="tiny amber" x="1062" y="932">Known web-editing gaps</text>
    <text class="tiny muted" x="1062" y="950">Web writers share a process lock + revision guard.</text>
    <text class="tiny muted" x="1062" y="967">External Git/editor is not locked; stop or reload before saving.</text>
  </g>
'''
    return shell(
        active="Settings",
        eyebrow="CONTROL / SSOT",
        title="Settings / SSOT",
        subtitle="Declarative source of truth · saves are validated and published automatically",
        status="Raw SSOT write session · authenticated by node-local operator_ref",
        description="The authenticated raw SSOT YAML editor with whole-buffer validation, a lock shared by cooperating web writers, revision-guarded atomic saves, automatic publication, and an explicit single-writer boundary for external editors.",
        body=body,
        environment_status="Control node",
        session_status="Write session",
    )


PAGES = {
    "loom-control-center-overview-misaka-v1.svg": overview_page,
    "loom-control-center-nodes-misaka-v1.svg": nodes_page,
    "loom-control-center-node-add-misaka-v1.svg": node_add_page,
    "loom-control-center-topology-misaka-v1.svg": topology_page,
    "loom-control-center-node-detail-misaka-v1.svg": node_detail_page,
    "loom-control-center-services-misaka-v1.svg": services_page,
    "loom-control-center-routes-misaka-v1.svg": routes_page,
    "loom-control-center-deployments-misaka-v1.svg": deployments_page,
    "loom-control-center-events-misaka-v1.svg": events_page,
    "loom-control-center-settings-misaka-v1.svg": settings_page,
}


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    generate_header_logo()
    print(HEADER_LOGO.relative_to(ROOT))
    for filename, render in PAGES.items():
        target = ASSETS / filename
        target.write_text(render(), encoding="utf-8")
        print(target.relative_to(ROOT))


if __name__ == "__main__":
    main()
