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
    "Overview": (360, 358, 447, "icon-overview"),
    "Topology": (462, 460, 550, "icon-topology"),
    "Services": (565, 563, 650, "icon-services"),
    "Routing": (665, 663, 752, "icon-traffic"),
    "Deployments": (765, 763, 891, "icon-deployments"),
    "Events": (908, 906, 984, "icon-events"),
    "Settings": (1002, 1000, 1088, "icon-settings"),
}


def shell(*, active: str, eyebrow: str, title: str, subtitle: str,
          status: str, description: str, body: str,
          environment_status: str = "Operational",
          session_status: str = "Read only") -> str:
    _, active_left, active_right, _ = NAV_ITEMS[active]
    nav = []
    for label, (x, _, _, icon_id) in NAV_ITEMS.items():
        weight = ' font-weight="600"' if label == active else ""
        icon_class = "nav-icon-active" if label == active else "nav-icon"
        nav.append(f'    <use href="#{icon_id}" x="{x}" y="18" width="14" height="14" class="{icon_class}"/>')
        nav.append(f'    <text x="{x + 21}" y="31"{weight}>{label}</text>')
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
    <text x="1210" y="31">Production</text>
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
    body = marker + text.split(marker, 1)[1].rsplit("</svg>", 1)[0]
    return shell(
        active="Overview",
        eyebrow="LIVE NETWORK",
        title="Network overview",
        subtitle="jm24 control plane · observed 8s ago",
        status="All systems operational",
        description="A restrained infrastructure overview showing five nodes, six WireGuard links, current traffic paths, deployment state, and recent events.",
        body=body,
    )


def topology_page() -> str:
    body = r'''
  <!-- Layered topology -->
  <rect class="panel" x="21" y="202" width="1075" height="478" rx="7"/>
  <g class="ui">
    <text class="section" x="40" y="232">Topology layers</text>
    <text class="small muted" x="40" y="254">Declared structure remains visible when trusted observation is missing.</text>

    <line class="wg" x1="654" y1="226" x2="684" y2="226"/>
    <text class="tiny muted" x="691" y="230">Persistent WG</text>
    <line class="candidate" x1="798" y1="226" x2="828" y2="226"/>
    <text class="tiny muted" x="835" y="230">Candidate</text>
    <line x1="922" y1="226" x2="952" y2="226" stroke="#2AA875" stroke-width="1.8"/>
    <path d="M948 222L954 226L948 230" fill="none" stroke="#2AA875" stroke-width="1.4"/>
    <text class="tiny muted" x="961" y="230">Agent decision</text>
    <rect class="panel-soft" x="1054" y="213" width="28" height="26" rx="5"/>
    <use href="#icon-refresh" x="1061" y="219" width="14" height="14" class="action-icon" aria-label="Refresh observations"/>
  </g>

  <!-- Six SSOT-declared persistent WireGuard links. -->
  <g aria-label="Six persistent WireGuard links">
    <line class="wg" x1="342" y1="309" x2="806" y2="361"/>
    <line class="wg" x1="342" y1="309" x2="806" y2="525"/>
    <line class="wg" x1="342" y1="417" x2="806" y2="361"/>
    <line class="wg" x1="342" y1="417" x2="806" y2="525"/>
    <line class="wg" x1="342" y1="548" x2="806" y2="361"/>
    <line class="wg" x1="342" y1="548" x2="806" y2="525"/>
  </g>

  <!-- Candidate hops are intent only, not health claims. -->
  <g aria-label="Configured candidate hops">
    <line class="candidate" x1="342" y1="321" x2="342" y2="405"/>
    <line class="candidate" x1="342" y1="429" x2="342" y2="536"/>
    <path class="candidate" d="M332 320C283 378 286 493 332 540"/>
  </g>

  <!-- One routing-entry Agent overlay. -->
  <path class="selected" d="M342 321L342 404"/>
  <path class="selected" d="M354 416L793 363"/>
  <text class="ui tiny green mono" x="579" y="388">sg-fixed</text>

  <g class="ui">
    <circle cx="342" cy="309" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="342" cy="309" r="5"/>
    <text class="mono" x="297" y="310" text-anchor="end" font-size="14" font-weight="650">jm24</text>
    <text class="tiny muted" x="325" y="330" text-anchor="end">control + access</text>

    <circle cx="342" cy="417" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="342" cy="417" r="5"/>
    <text class="mono" x="297" y="418" text-anchor="end" font-size="14" font-weight="650">gz02</text>
    <text class="tiny muted" x="325" y="438" text-anchor="end">domestic + egress</text>

    <circle cx="342" cy="548" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="342" cy="548" r="5"/>
    <text class="mono" x="297" y="549" text-anchor="end" font-size="14" font-weight="650">hz01</text>
    <text class="tiny muted" x="325" y="569" text-anchor="end">domestic + egress</text>

    <circle cx="806" cy="361" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="806" cy="361" r="5"/>
    <text class="mono" x="825" y="365" font-size="14" font-weight="650">sg02</text>
    <text class="tiny muted" x="825" y="385">reverse-only + egress</text>

    <circle cx="806" cy="525" r="8" fill="#FFFFFF"/><circle class="status-dot" cx="806" cy="525" r="5"/>
    <text class="mono" x="825" y="529" font-size="14" font-weight="650">ber01</text>
    <text class="tiny muted" x="825" y="549">reverse-only + egress</text>

    <text class="tiny muted" x="40" y="649">Candidate edges describe allowable business paths. Missing a direct WG edge does not mean there is no path.</text>
  </g>

  <!-- Layer inspection -->
  <rect class="panel" x="1112" y="202" width="447" height="270" rx="7"/>
  <g class="ui">
    <text class="section" x="1132" y="232">Layer status</text>

    <text class="small muted" x="1132" y="266">CONFIG INTENT</text>
    <text class="metric" x="1132" y="290">6 persistent links</text>
    <text class="tiny muted" x="1132" y="309">Source · signed snapshot / SSOT</text>

    <line class="rule" x1="1132" y1="327" x2="1539" y2="327"/>
    <text class="small muted" x="1132" y="352">TRUSTED OBSERVATION</text>
    <circle class="status-dot" cx="1137" cy="376" r="4"/>
    <text class="metric" x="1150" y="381">6 / 6 active</text>
    <text class="tiny muted" x="1132" y="401">report.neighbors · newest 8s · oldest 16s</text>

    <line class="rule" x1="1132" y1="419" x2="1539" y2="419"/>
    <text class="small muted" x="1132" y="444">AGENT DECISION</text>
    <text class="body" x="1260" y="444">Routing-entry overlay</text>
    <text class="tiny amber" x="1132" y="462">Design target · requires upgraded Agent reporting</text>
  </g>

  <rect class="panel" x="1112" y="488" width="447" height="192" rx="7"/>
  <g class="ui">
    <text class="section" x="1132" y="518">Observation contract</text>
    <text class="small muted" x="1132" y="546">Sampling cadence</text><text class="body" x="1519" y="546" text-anchor="end">about 1 minute</text>
    <text class="small muted" x="1132" y="576">Page refresh</text><text class="body" x="1519" y="576" text-anchor="end">30 seconds</text>
    <text class="small muted" x="1132" y="606">Freshness</text><text class="body" x="1519" y="606" text-anchor="end">shown per datum</text>
    <line class="rule" x1="1132" y1="624" x2="1539" y2="624"/>
    <text class="tiny muted" x="1132" y="650">Unknown remains unknown; it is never promoted to healthy.</text>
  </g>

  <!-- Edge inventory -->
  <rect class="panel" x="21" y="696" width="1538" height="277" rx="7"/>
  <g class="ui">
    <text class="section" x="40" y="726">Persistent WireGuard edges</text>
    <text class="tiny muted" x="318" y="726">SSOT declaration + trusted carrier observation</text>
    <text class="small muted" x="46" y="758">EDGE</text>
    <text class="small muted" x="328" y="758">DECLARATION</text>
    <text class="small muted" x="574" y="758">OBSERVED</text>
    <text class="small muted" x="775" y="758">RTT</text>
    <text class="small muted" x="915" y="758">STATE</text>
    <text class="small muted" x="1083" y="758">SOURCE</text>
  </g>
  <line class="rule" x1="40" y1="766" x2="1540" y2="766"/>
  <g class="ui body">
    <text class="mono" x="46" y="794">jm24 ↔ sg02</text><text x="328" y="794">Persistent WG</text><text x="574" y="794">8s ago</text><text class="mono" x="775" y="794">277 ms</text><circle class="quiet-dot" cx="919" cy="789" r="4"/><text x="932" y="794">Active</text><text class="muted" x="1083" y="794">trusted report.neighbors</text>
    <text class="mono" x="46" y="826">jm24 ↔ ber01</text><text x="328" y="826">Persistent WG</text><text x="574" y="826">8s ago</text><text class="mono" x="775" y="826">150 ms</text><circle class="quiet-dot" cx="919" cy="821" r="4"/><text x="932" y="826">Active</text><text class="muted" x="1083" y="826">trusted report.neighbors</text>
    <text class="mono" x="46" y="858">gz02 ↔ sg02</text><text x="328" y="858">Persistent WG</text><text x="574" y="858">11s ago</text><text class="mono" x="775" y="858">190 ms</text><circle class="quiet-dot" cx="919" cy="853" r="4"/><text x="932" y="858">Active</text><text class="muted" x="1083" y="858">trusted report.neighbors</text>
    <text class="mono" x="46" y="890">gz02 ↔ ber01</text><text x="328" y="890">Persistent WG</text><text x="574" y="890">11s ago</text><text class="mono" x="775" y="890">226 ms</text><circle class="quiet-dot" cx="919" cy="885" r="4"/><text x="932" y="890">Active</text><text class="muted" x="1083" y="890">trusted report.neighbors</text>
    <text class="mono" x="46" y="922">hz01 ↔ sg02</text><text x="328" y="922">Persistent WG</text><text x="574" y="922">13s ago</text><text class="mono" x="775" y="922">350 ms</text><circle class="quiet-dot" cx="919" cy="917" r="4"/><text x="932" y="922">Active</text><text class="muted" x="1083" y="922">trusted report.neighbors</text>
    <text class="mono" x="46" y="954">hz01 ↔ ber01</text><text x="328" y="954">Persistent WG</text><text x="574" y="954">13s ago</text><text class="mono" x="775" y="954">240 ms</text><circle class="quiet-dot" cx="919" cy="949" r="4"/><text x="932" y="954">Active</text><text class="muted" x="1083" y="954">trusted report.neighbors</text>
  </g>
  <line class="rule" x1="40" y1="802" x2="1540" y2="802"/><line class="rule" x1="40" y1="834" x2="1540" y2="834"/><line class="rule" x1="40" y1="866" x2="1540" y2="866"/><line class="rule" x1="40" y1="898" x2="1540" y2="898"/><line class="rule" x1="40" y1="930" x2="1540" y2="930"/>
'''
    return shell(
        active="Topology",
        eyebrow="NETWORK / TOPOLOGY",
        title="Network topology",
        subtitle="Intent, trusted observations and routing-entry Agent decisions · observed 2026-08-27 17:54 UTC",
        status="5 nodes · 6 persistent WireGuard links · 51 configured candidate paths",
        description="A layered network topology view distinguishing SSOT intent, persistent WireGuard observations, configured candidate paths, and Agent route decisions.",
        body=body,
    )


def node_detail_page() -> str:
    body = r'''
  <!-- Identity and compact status strip -->
  <text class="ui tiny green" x="1538" y="181" text-anchor="end">Topology / Nodes / jm24</text>
  <rect class="panel" x="21" y="202" width="1538" height="86" rx="7"/>
  <g class="ui">
    <text class="label" x="51" y="234">Snapshot</text><text class="metric mono" x="51" y="261">4f09f6f5716d</text>
    <text class="label" x="415" y="234">Commit</text><text class="metric mono" x="415" y="261">28224ed</text>
    <text class="label" x="745" y="234">Binary</text><text class="metric mono" x="745" y="261">449597b5…</text>
    <text class="label" x="1064" y="234">WireGuard tools</text><text class="metric mono" x="1064" y="261">1.0.20250521</text>
    <text class="label" x="1390" y="234">Rollout</text><text class="metric green" x="1390" y="261">Verified</text>
  </g>
  <line class="rule" x1="376" y1="222" x2="376" y2="269"/><line class="rule" x1="706" y1="222" x2="706" y2="269"/><line class="rule" x1="1025" y1="222" x2="1025" y2="269"/><line class="rule" x1="1351" y1="222" x2="1351" y2="269"/>

  <!-- Services and components -->
  <rect class="panel" x="21" y="304" width="807" height="397" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="334">Runtime</text>
    <text class="tiny muted" x="41" y="356">Expected components and observed process state</text>

    <text class="small muted" x="47" y="390">UNIT</text><text class="small muted" x="276" y="390">ROLE</text><text class="small muted" x="512" y="390">STATE</text><text class="small muted" x="651" y="390">RESTARTS</text>
    <line class="rule" x1="41" y1="398" x2="808" y2="398"/>
    <text class="body mono" x="47" y="428">loom-report</text><text class="body" x="276" y="428">status + signed relay</text><circle class="quiet-dot" cx="516" cy="423" r="4"/><text class="body" x="529" y="428">Active</text><text class="body mono" x="681" y="428">0</text>
    <text class="body mono" x="47" y="463">loom-agent</text><text class="body" x="276" y="463">selector control loop</text><circle class="quiet-dot" cx="516" cy="458" r="4"/><text class="body" x="529" y="463">Active</text><text class="body mono" x="681" y="463">0</text>
    <text class="body mono" x="47" y="498">loom-publisher</text><text class="body" x="276" y="498">automatic release</text><circle class="quiet-dot" cx="516" cy="493" r="4"/><text class="body" x="529" y="498">Active</text><text class="body mono" x="681" y="498">0</text>
    <text class="body mono" x="47" y="533">loom-pull.timer</text><text class="body" x="276" y="533">snapshot convergence</text><circle class="quiet-dot" cx="516" cy="528" r="4"/><text class="body" x="529" y="533">Waiting</text><text class="body mono" x="681" y="533">—</text>
    <line class="rule" x1="41" y1="446" x2="808" y2="446"/><line class="rule" x1="41" y1="481" x2="808" y2="481"/><line class="rule" x1="41" y1="516" x2="808" y2="516"/><line class="rule" x1="41" y1="551" x2="808" y2="551"/>

    <text class="subsection" x="41" y="584">Component parity <tspan class="tiny muted" font-weight="400">· host audit, not yet reported centrally</tspan></text>
    <text class="small muted" x="47" y="613">COMPONENT</text><text class="small muted" x="276" y="613">EXPECTED</text><text class="small muted" x="512" y="613">ACTUAL</text><text class="small muted" x="691" y="613">RESULT</text>
    <line class="rule" x1="41" y1="621" x2="808" y2="621"/>
    <text class="body" x="47" y="649">sing-box</text><text class="body mono" x="276" y="649">managed</text><text class="body mono" x="512" y="649">managed</text><text class="body green" x="691" y="649">Match</text>
    <text class="body" x="47" y="680">wireguard-tools</text><text class="body mono" x="276" y="680">1.0.20250521</text><text class="body mono" x="512" y="680">1.0.20250521</text><text class="body green" x="691" y="680">Match</text>
  </g>

  <!-- Observation trust -->
  <rect class="panel" x="844" y="304" width="715" height="171" rx="7"/>
  <g class="ui">
    <text class="section" x="864" y="334">Observation</text>
    <circle class="status-dot" cx="869" cy="361" r="4"/><text class="body" x="882" y="366">Verified healthy</text>
    <text class="small muted" x="864" y="394">SOURCE</text><text class="body" x="1054" y="394">Direct /status · signed local statement</text>
    <text class="small muted" x="864" y="422">ROLE</text><text class="body" x="1054" y="422">Access + tunnel endpoint · runtime control</text>
    <text class="small muted" x="864" y="450">EGRESS CAPABLE</text><text class="body" x="1054" y="450">No · local direct remains a zero-hop candidate</text>
  </g>

  <!-- WireGuard interfaces -->
  <rect class="panel" x="844" y="491" width="715" height="210" rx="7"/>
  <g class="ui">
    <text class="section" x="864" y="521">WireGuard interfaces</text>
    <text class="small muted" x="870" y="554">INTERFACE</text><text class="small muted" x="1060" y="554">PEER</text><text class="small muted" x="1240" y="554">HANDSHAKE</text><text class="small muted" x="1422" y="554">STATE</text>
    <line class="rule" x1="864" y1="562" x2="1539" y2="562"/>
    <text class="body mono" x="870" y="593">wg-sg02</text><text class="body mono" x="1060" y="593">sg02</text><text class="body" x="1240" y="593">37s · 277 ms RTT</text><circle class="quiet-dot" cx="1426" cy="588" r="4"/><text class="body" x="1439" y="593">Active</text>
    <text class="body mono" x="870" y="631">wg-ber01</text><text class="body mono" x="1060" y="631">ber01</text><text class="body" x="1240" y="631">57s · 150 ms RTT</text><circle class="quiet-dot" cx="1426" cy="626" r="4"/><text class="body" x="1439" y="631">Active</text>
    <line class="rule" x1="864" y1="609" x2="1539" y2="609"/><line class="rule" x1="864" y1="647" x2="1539" y2="647"/>
    <text class="tiny muted" x="864" y="678">Handshake age is local tunnel state; RTT is a separate edge observation.</text>
  </g>

  <!-- Current path read-back is local audit evidence until the AgentState upgrade lands. -->
  <rect class="panel" x="21" y="717" width="758" height="256" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="747">Agent route decisions</text>
    <text class="tiny amber" x="274" y="747">Locally verified · health evidence not published by legacy Agent</text>
    <text class="small muted" x="47" y="778">ROUTING ENTRY</text><text class="small muted" x="223" y="778">CURRENT PATH</text><text class="small muted" x="588" y="778">EVIDENCE</text>
    <line class="rule" x1="41" y1="786" x2="759" y2="786"/>
    <text class="body mono" x="47" y="812">cn-web</text><text class="body mono" x="223" y="812">jm24 → direct</text><text class="tiny muted" x="588" y="812">runtime selector</text>
    <text class="body mono" x="47" y="844">intl-api</text><text class="body mono" x="223" y="844">jm24 → ber01</text><text class="tiny muted" x="588" y="844">runtime selector</text>
    <text class="body mono" x="47" y="876">sg-fixed</text><text class="body mono green" x="223" y="876">jm24 → gz02 → sg02</text><text class="tiny muted" x="588" y="876">runtime selector</text>
    <text class="body mono" x="47" y="908">de-fixed</text><text class="body mono" x="223" y="908">jm24 → ber01</text><text class="tiny muted" x="588" y="908">runtime selector</text>
    <text class="body mono" x="47" y="940">best-egress</text><text class="body mono" x="223" y="940">jm24 → ber01</text><text class="tiny muted" x="588" y="940">runtime selector</text>
    <line class="rule" x1="41" y1="820" x2="759" y2="820"/><line class="rule" x1="41" y1="852" x2="759" y2="852"/><line class="rule" x1="41" y1="884" x2="759" y2="884"/><line class="rule" x1="41" y1="916" x2="759" y2="916"/><line class="rule" x1="41" y1="948" x2="759" y2="948"/>
  </g>

  <!-- Measurements: explicit distinction between alarm-bearing uplinks and pruning data. -->
  <rect class="panel" x="795" y="717" width="764" height="256" rx="7"/>
  <g class="ui">
    <text class="section" x="815" y="747">Measurements</text>
    <text class="tiny muted" x="815" y="769">Uplink failures are actionable. Target failures are route-pruning data.</text>
    <text class="small muted" x="821" y="803">TYPE</text><text class="small muted" x="955" y="803">TARGET</text><text class="small muted" x="1218" y="803">OBSERVATION</text><text class="small muted" x="1442" y="803">MEANING</text>
    <line class="rule" x1="815" y1="811" x2="1539" y2="811"/>
    <text class="body" x="821" y="843">uplink</text><text class="body" x="955" y="843">www.baidu.com</text><text class="body green" x="1218" y="843">63 ms · reachable</text><text class="body" x="1442" y="843">Healthy</text>
    <text class="body" x="821" y="883">target</text><text class="body" x="955" y="883">api.ipify.org</text><text class="body blue" x="1218" y="883">5 / 5 timeout</text><text class="body blue" x="1442" y="883">Pruning data</text>
    <text class="body" x="821" y="923">edge</text><text class="body mono" x="955" y="923">jm24 ↔ sg02</text><text class="body green" x="1218" y="923">277 ms · 4/4</text><text class="body" x="1442" y="923">Carrier</text>
    <line class="rule" x1="815" y1="859" x2="1539" y2="859"/><line class="rule" x1="815" y1="899" x2="1539" y2="899"/><line class="rule" x1="815" y1="939" x2="1539" y2="939"/>
  </g>
'''
    return shell(
        active="Topology",
        eyebrow="TOPOLOGY / NODE",
        title="jm24",
        subtitle="Beijing · control + access + tunnel endpoint · direct /status observed 10s ago",
        status="No confirmed issues · egress capable: no",
        description="A node detail view for jm24 showing trusted identity, runtime services, component versions, WireGuard interfaces, rollout state, drift, and measurements.",
        body=body,
    )


def services_page() -> str:
    body = r'''
  <!-- Compact mode switch and primary action; this is a configuration page, not a KPI dashboard. -->
  <g class="ui">
    <rect class="chip-green" x="21" y="202" width="122" height="34" rx="17"/>
    <text class="small green" x="82" y="224" text-anchor="middle">Services · 2</text>
    <text class="small muted" x="169" y="224">Routing policies · 3</text>
    <circle class="quiet-dot" cx="326" cy="219" r="4"/><text class="small green" x="339" y="224">All definitions valid</text>
    <rect class="chip-amber" x="486" y="202" width="225" height="34" rx="17"/><text class="tiny amber" x="599" y="223" text-anchor="middle">Target state · write API pending</text>
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
    <text class="body mono" x="483" y="436">intl-api</text><text class="tiny muted" x="483" y="455">Stable after first publish</text>
    <use href="#icon-lock" x="765" y="424" width="14" height="14" class="nav-icon"/>
    <rect class="panel-soft" x="821" y="412" width="738" height="54" rx="6"/>
    <text class="body" x="837" y="445">International APIs</text>
    <line class="rule" x1="467" y1="489" x2="1559" y2="489"/>

    <text class="subsection" x="467" y="522">Host rules</text>
    <text class="tiny muted" x="561" y="522">Requests matching either rule are treated as this service.</text>
    <text class="small muted" x="467" y="558">HOSTNAME</text><text class="small muted" x="1280" y="558">MATCH TYPE</text><text class="small muted" x="1458" y="558">ACTIONS</text>
    <line class="rule" x1="467" y1="570" x2="1559" y2="570"/>
    <text class="body mono" x="483" y="601">api.ipify.org</text><rect class="chip" x="1280" y="579" width="78" height="28" rx="14"/><text class="tiny muted" x="1319" y="598" text-anchor="middle">Exact</text>
    <use href="#icon-edit" x="1467" y="587" width="14" height="14" class="action-icon" aria-label="Edit api.ipify.org"/><use href="#icon-trash" x="1510" y="587" width="14" height="14" class="action-icon" aria-label="Remove api.ipify.org"/>
    <line class="rule" x1="467" y1="614" x2="1559" y2="614"/>
    <text class="body mono" x="483" y="645">.githubusercontent.com</text><rect class="chip" x="1280" y="623" width="78" height="28" rx="14"/><text class="tiny muted" x="1319" y="642" text-anchor="middle">Suffix</text>
    <use href="#icon-edit" x="1467" y="631" width="14" height="14" class="action-icon" aria-label="Edit .githubusercontent.com"/><use href="#icon-trash" x="1510" y="631" width="14" height="14" class="action-icon" aria-label="Remove .githubusercontent.com"/>
    <line class="rule" x1="467" y1="659" x2="1559" y2="659"/>
    <rect class="panel" x="467" y="677" width="151" height="36" rx="5"/>
    <use href="#icon-plus" x="484" y="688" width="14" height="14" class="action-icon"/><text class="small" x="509" y="701">Add hostname</text>
    <text class="tiny muted" x="644" y="694">Leading dot = domain suffix. At least one exact hostname is required for probing.</text>
    <text class="tiny muted" x="644" y="713">URLs, paths, host:port values and wildcards are rejected.</text>
    <line class="rule" x1="467" y1="735" x2="1559" y2="735"/>

    <text class="subsection" x="467" y="768">Routing policy</text>
    <text class="tiny muted" x="467" y="791">Determines permitted paths; services sharing it still choose independently.</text>
    <rect class="panel-soft" x="467" y="805" width="520" height="54" rx="6"/>
    <text class="body" x="483" y="829">Best egress</text><text class="tiny muted mono" x="483" y="848">best-egress</text>
    <path d="M959 825l5 5 5-5" fill="none" stroke="#717674" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>

    <text class="subsection" x="1037" y="768">Configured ingress</text>
    <text class="tiny muted" x="1037" y="791">Where applications send hostnames to Loom.</text>
    <text class="body mono" x="1037" y="824">jm24 · 127.0.0.1:1083</text>
    <text class="tiny muted" x="1037" y="848">Use remote DNS / socks5h · configuration only, not listener health</text>
    <line class="rule" x1="467" y1="879" x2="1559" y2="879"/>

    <text class="small muted" x="467" y="906">RUNTIME</text><text class="body" x="555" y="906">Current path and health are observed in Routing.</text>
    <text class="tiny muted" x="1168" y="906">Unmatched-host telemetry unavailable</text>
    <text class="small green" x="1431" y="906">View routing</text><use href="#icon-arrow-right" x="1526" y="894" width="14" height="14" class="action-icon"/>
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
        session_status="Authenticated",
    )


def routes_page() -> str:
    body = r'''
  <!-- Runtime routing summary. Service definitions are managed on the Services page. -->
  <rect class="panel" x="21" y="202" width="1538" height="82" rx="7"/>
  <g class="ui">
    <text class="small muted" x="46" y="232">SERVICES</text><text class="metric" x="46" y="258">2 configured</text>
    <text class="small muted" x="329" y="232">ACCESS POLICIES</text><text class="metric" x="329" y="258">3 configured</text>
    <text class="small muted" x="646" y="232">CURRENT PATHS</text><text class="metric" x="646" y="258">5 / 5 reported</text>
    <text class="small muted" x="972" y="232">CANDIDATE PATHS</text><text class="metric" x="972" y="258">51 available</text>
    <rect class="panel-soft" x="1304" y="221" width="228" height="39" rx="6"/>
    <use href="#icon-services" x="1343" y="233" width="15" height="15" class="action-icon"/>
    <text class="small" x="1370" y="246">Manage services</text>
    <use href="#icon-arrow-right" x="1486" y="233" width="15" height="15" class="action-icon"/>
  </g>
  <line class="rule" x1="300" y1="222" x2="300" y2="265"/><line class="rule" x1="617" y1="222" x2="617" y2="265"/><line class="rule" x1="943" y1="222" x2="943" y2="265"/><line class="rule" x1="1275" y1="222" x2="1275" y2="265"/>

  <!-- Observed paths, not a configuration surface. -->
  <rect class="panel" x="21" y="300" width="537" height="500" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="330">Current paths</text><text class="tiny muted" x="538" y="330" text-anchor="end">one per routing scope</text>

    <rect x="31" y="351" width="517" height="78" rx="6" fill="#F1F8F4"/>
    <rect x="31" y="351" width="3" height="78" rx="1.5" fill="#2AA875"/>
    <text class="subsection mono" x="49" y="375">sg-fixed</text><text class="tiny muted" x="49" y="394">access policy · stability · egress sg02</text>
    <text class="body mono" x="49" y="417">jm24 → gz02 → sg02</text><circle class="quiet-dot" cx="480" cy="390" r="4"/><text class="tiny green" x="493" y="394">Fresh</text><text class="tiny muted" x="528" y="414" text-anchor="end">3 candidate paths</text>

    <text class="subsection mono" x="49" y="461">cn-web</text><text class="tiny muted" x="49" y="480">service · latency policy</text><text class="body mono" x="49" y="503">jm24 → direct</text><circle class="quiet-dot" cx="480" cy="476" r="4"/><text class="tiny" x="493" y="480">Fresh</text><text class="tiny muted" x="528" y="500" text-anchor="end">15 candidate paths</text>
    <line class="rule" x1="41" y1="438" x2="538" y2="438"/>

    <text class="subsection mono" x="49" y="546">intl-api</text><text class="tiny muted" x="49" y="565">service · latency policy</text><text class="body mono" x="49" y="588">jm24 → ber01</text><circle class="quiet-dot" cx="480" cy="561" r="4"/><text class="tiny" x="493" y="565">Fresh</text><text class="tiny muted" x="528" y="585" text-anchor="end">15 candidate paths</text>
    <line class="rule" x1="41" y1="523" x2="538" y2="523"/>

    <text class="subsection mono" x="49" y="631">best-egress</text><text class="tiny muted" x="49" y="650">access policy · latency · any egress</text><text class="body mono" x="49" y="673">jm24 → ber01</text><circle class="quiet-dot" cx="480" cy="646" r="4"/><text class="tiny" x="493" y="650">Fresh</text><text class="tiny muted" x="528" y="670" text-anchor="end">15 candidate paths</text>
    <line class="rule" x1="41" y1="608" x2="538" y2="608"/>

    <text class="subsection mono" x="49" y="716">de-fixed</text><text class="tiny muted" x="49" y="735">access policy · stability · egress ber01</text><text class="body mono" x="49" y="758">jm24 → ber01</text><circle class="quiet-dot" cx="480" cy="731" r="4"/><text class="tiny" x="493" y="735">Fresh</text><text class="tiny muted" x="528" y="755" text-anchor="end">3 candidate paths</text>
    <line class="rule" x1="41" y1="693" x2="538" y2="693"/>
  </g>

  <!-- Focused routing-entry detail. -->
  <rect class="panel" x="574" y="300" width="985" height="500" rx="7"/>
  <g class="ui">
    <text class="section" x="594" y="330">sg-fixed</text><text class="tiny muted" x="684" y="330">access policy · current traffic path</text>
    <rect class="chip-green" x="1401" y="313" width="136" height="27" rx="13.5"/><circle class="quiet-dot" cx="1418" cy="326" r="3.5"/><text class="tiny green" x="1429" y="330">Current on jm24</text>

    <line x1="694" y1="405" x2="991" y2="405" stroke="#2AA875" stroke-width="2"/>
    <line x1="1013" y1="405" x2="1310" y2="405" stroke="#2AA875" stroke-width="2"/>
    <circle cx="683" cy="405" r="10" fill="#FFFFFF" stroke="#2AA875" stroke-width="2"/><circle cx="1002" cy="405" r="10" fill="#FFFFFF" stroke="#2AA875" stroke-width="2"/><circle cx="1321" cy="405" r="10" fill="#FFFFFF" stroke="#2AA875" stroke-width="2"/>
    <text class="body mono" x="683" y="438" text-anchor="middle">jm24</text><text class="body mono" x="1002" y="438" text-anchor="middle">gz02</text><text class="body mono" x="1321" y="438" text-anchor="middle">sg02</text>
    <text class="tiny muted" x="683" y="458" text-anchor="middle">access</text><text class="tiny muted" x="1002" y="458" text-anchor="middle">domestic hop</text><text class="tiny muted" x="1321" y="458" text-anchor="middle">pinned egress</text>

    <text class="small muted" x="594" y="498">SOURCE</text><text class="body" x="756" y="498">jm24 /status · sing-box read-back</text>
    <text class="small muted" x="594" y="526">UPDATED</text><text class="body mono" x="756" y="526">2026-08-27 17:50:52 UTC</text><text class="tiny muted" x="1012" y="526">each routing entry is reported independently</text>
    <text class="small muted" x="594" y="554">EVIDENCE</text><text class="body" x="756" y="554">Current value read back from sing-box</text>
    <line class="rule" x1="594" y1="576" x2="1539" y2="576"/>

    <text class="subsection" x="594" y="606">Access policy</text>
    <text class="small muted" x="594" y="635">Objective</text><text class="body" x="704" y="635">stability</text>
    <text class="small muted" x="886" y="635">Egress</text><text class="body mono" x="962" y="635">pinned:sg02</text>
    <text class="small muted" x="1162" y="635">Cadence</text><text class="body" x="1247" y="635">10 minutes</text>
    <text class="small muted" x="594" y="665">Window</text><text class="body" x="704" y="665">2 hours</text>
    <text class="small muted" x="886" y="665">Min samples</text><text class="body" x="1002" y="665">6</text>
    <text class="small muted" x="1162" y="665">Switch threshold</text><text class="body" x="1305" y="665">20%</text>
    <line class="rule" x1="594" y1="686" x2="1539" y2="686"/>

    <text class="subsection" x="594" y="716">Candidate path health</text>
    <text class="body green" x="594" y="747">1 success</text><text class="body" x="713" y="747">· 0 degraded · 0 failed · 1 stale · 1 unknown</text>
    <text class="tiny muted" x="594" y="772">Summary covers this routing entry; the current View has no per-path realtime metrics.</text>
  </g>

  <!-- Candidate paths for the focused routing entry. -->
  <rect class="panel" x="21" y="816" width="1538" height="157" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="846">Candidate paths for <tspan class="mono">sg-fixed</tspan></text>
    <text class="tiny muted" x="430" y="846">SSOT allows these paths. Only the green row is current; other rows imply no health.</text>
    <text class="small muted" x="47" y="877">PATH</text><text class="small muted" x="633" y="877">STATUS</text><text class="small muted" x="972" y="877">SOURCE</text><text class="small muted" x="1347" y="877">EGRESS</text>
    <line class="rule" x1="41" y1="885" x2="1539" y2="885"/>
    <text class="body mono" x="47" y="910">jm24 → sg02</text><text class="body muted" x="633" y="910">Allowed by SSOT · health not reported</text><text class="body muted" x="972" y="910">SSOT RouteCandidate.ServerChain</text><text class="body mono" x="1347" y="910">sg02</text>
    <text class="body mono green" x="47" y="938">jm24 → gz02 → sg02</text><circle class="quiet-dot" cx="637" cy="933" r="4"/><text class="body green" x="650" y="938">Current path</text><text class="body" x="972" y="938">jm24 /status · sing-box read-back</text><text class="body mono" x="1347" y="938">sg02</text>
    <text class="body mono" x="47" y="966">jm24 → hz01 → sg02</text><text class="body muted" x="633" y="966">Allowed by SSOT · health not reported</text><text class="body muted" x="972" y="966">SSOT RouteCandidate.ServerChain</text><text class="body mono" x="1347" y="966">sg02</text>
  </g>
  <line class="rule" x1="41" y1="918" x2="1539" y2="918"/><line class="rule" x1="41" y1="946" x2="1539" y2="946"/>
'''
    return shell(
        active="Routing",
        eyebrow="AGENT / TRAFFIC",
        title="Traffic routing",
        subtitle="Current traffic path for each service or access policy · reported by the access Agent",
        status="Agent applies paths; control center observes",
        description="A runtime traffic-routing view showing five service or access-policy scopes, one focused Agent decision, and a direct link to service configuration.",
        body=body,
    )


def deployments_page() -> str:
    body = r'''
  <!-- Release summary -->
  <rect class="panel" x="21" y="202" width="1538" height="86" rx="7"/>
  <g class="ui">
    <text class="small muted" x="47" y="234">PUBLISHER</text><circle class="status-dot" cx="51" cy="257" r="4"/><text class="metric" x="64" y="262">Heartbeat healthy</text>
    <text class="small muted" x="421" y="234">CURRENT SNAPSHOT</text><text class="metric mono" x="421" y="262">4f09f6f5716d</text>
    <text class="small muted" x="786" y="234">ROLLOUT</text><text class="metric" x="786" y="262">5 / 5 verified</text>
    <text class="small muted" x="1106" y="234">DISTRIBUTION POINTER</text><circle class="warn-dot" cx="1110" cy="257" r="4"/><text class="metric amber" x="1123" y="262">Legacy current</text><text class="tiny muted" x="1293" y="261">floor 0 / 5 · signed current not deployed</text>
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
    <text class="small muted" x="41" y="459">COMMIT</text><text class="body mono" x="218" y="459">28224ed</text>
    <text class="small muted" x="41" y="491">BINARY</text><text class="body mono" x="218" y="491">449597b5…</text>
    <text class="small muted" x="41" y="523">LAST SUCCESS</text><text class="body" x="218" y="523">19h ago</text>
    <text class="small muted" x="41" y="555">LAST SNAPSHOT</text><text class="body mono" x="218" y="555">4f09f6f5716d</text>
    <line class="rule" x1="41" y1="579" x2="512" y2="579"/>
    <text class="tiny muted" x="41" y="607">No new publish is expected while SSOT and renderer output are unchanged.</text>
    <text class="tiny muted" x="41" y="629">Heartbeat freshness, not release age, determines publisher health.</text>
    <rect class="chip" x="41" y="650" width="168" height="27" rx="6"/><text class="tiny" x="125" y="668" text-anchor="middle">No manual Publish action</text>
  </g>

  <!-- Node convergence -->
  <rect class="panel" x="548" y="304" width="1011" height="392" rx="7"/>
  <g class="ui">
    <text class="section" x="568" y="334">Node convergence</text><text class="tiny muted" x="742" y="334">target snapshot <tspan class="mono">4f09f6f5716d</tspan></text>
    <text class="small muted" x="574" y="369">NODE</text><text class="small muted" x="743" y="369">TARGET</text><text class="small muted" x="928" y="369">STAGE</text><text class="small muted" x="1098" y="369">ENTERED</text><text class="small muted" x="1281" y="369">LAST GOOD</text><text class="small muted" x="1452" y="369">DRIFT</text>
    <line class="rule" x1="568" y1="377" x2="1539" y2="377"/>
    <text class="body mono" x="574" y="412">jm24</text><text class="body mono" x="743" y="412">4f09f6f</text><circle class="quiet-dot" cx="932" cy="407" r="4"/><text class="body" x="945" y="412">Verified</text><text class="body" x="1098" y="412">19h ago</text><text class="body mono" x="1281" y="412">3e8d7c2a</text><text class="body green" x="1452" y="412">Clean</text>
    <text class="body mono" x="574" y="463">gz02</text><text class="body mono" x="743" y="463">4f09f6f</text><circle class="quiet-dot" cx="932" cy="458" r="4"/><text class="body" x="945" y="463">Verified</text><text class="body" x="1098" y="463">19h ago</text><text class="body mono" x="1281" y="463">3e8d7c2a</text><text class="body green" x="1452" y="463">Clean</text>
    <text class="body mono" x="574" y="514">hz01</text><text class="body mono" x="743" y="514">4f09f6f</text><circle class="quiet-dot" cx="932" cy="509" r="4"/><text class="body" x="945" y="514">Verified</text><text class="body" x="1098" y="514">19h ago</text><text class="body mono" x="1281" y="514">3e8d7c2a</text><text class="body green" x="1452" y="514">Clean</text>
    <text class="body mono" x="574" y="565">sg02</text><text class="body mono" x="743" y="565">4f09f6f</text><circle class="quiet-dot" cx="932" cy="560" r="4"/><text class="body" x="945" y="565">Verified</text><text class="body" x="1098" y="565">19h ago</text><text class="body mono" x="1281" y="565">3e8d7c2a</text><text class="body green" x="1452" y="565">Clean</text>
    <text class="body mono" x="574" y="616">ber01</text><text class="body mono" x="743" y="616">4f09f6f</text><circle class="quiet-dot" cx="932" cy="611" r="4"/><text class="body" x="945" y="616">Verified</text><text class="body" x="1098" y="616">19h ago</text><text class="body mono" x="1281" y="616">3e8d7c2a</text><text class="body green" x="1452" y="616">Clean</text>
    <line class="rule" x1="568" y1="431" x2="1539" y2="431"/><line class="rule" x1="568" y1="482" x2="1539" y2="482"/><line class="rule" x1="568" y1="533" x2="1539" y2="533"/><line class="rule" x1="568" y1="584" x2="1539" y2="584"/><line class="rule" x1="568" y1="635" x2="1539" y2="635"/>
    <text class="tiny muted" x="568" y="668">A node is converged only after its local verifier records the target snapshot as verified.</text>
  </g>

  <!-- Release pipeline -->
  <rect class="panel" x="21" y="712" width="1004" height="261" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="742">Automatic release pipeline</text>
    <text class="tiny muted" x="41" y="764">Saving a valid SSOT change is the only write; the publisher owns every downstream stage.</text>
    <line class="timeline-ok" x1="87" y1="830" x2="955" y2="830"/>
    <circle class="status-dot" cx="87" cy="830" r="5"/><circle class="status-dot" cx="232" cy="830" r="5"/><circle class="status-dot" cx="377" cy="830" r="5"/><circle class="status-dot" cx="522" cy="830" r="5"/><circle class="status-dot" cx="667" cy="830" r="5"/><circle class="status-dot" cx="812" cy="830" r="5"/><circle class="status-dot" cx="955" cy="830" r="5"/>
    <text class="small" x="87" y="860" text-anchor="middle">Validate</text><text class="small" x="232" y="860" text-anchor="middle">Render</text><text class="small" x="377" y="860" text-anchor="middle">Sign</text><text class="small" x="522" y="860" text-anchor="middle">Distribute</text><text class="small" x="667" y="860" text-anchor="middle">Pull</text><text class="small" x="812" y="860" text-anchor="middle">Apply</text><text class="small" x="955" y="860" text-anchor="middle">Verify</text>
    <text class="tiny muted" x="87" y="882" text-anchor="middle">SSOT</text><text class="tiny muted" x="232" y="882" text-anchor="middle">per node</text><text class="tiny muted" x="377" y="882" text-anchor="middle">manifest</text><text class="tiny muted" x="522" y="882" text-anchor="middle">snapshot</text><text class="tiny muted" x="667" y="882" text-anchor="middle">timer</text><text class="tiny muted" x="812" y="882" text-anchor="middle">atomic</text><text class="tiny muted" x="955" y="882" text-anchor="middle">local</text>
    <line class="rule" x1="41" y1="909" x2="1005" y2="909"/>
    <text class="small muted" x="41" y="938">Latest</text><text class="body" x="126" y="938">Snapshot manifest signed · distributed · verified by 5 nodes</text><text class="body mono" x="870" y="938">28224ed</text>
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
        title="Deployments",
        subtitle="jm24 publisher · heartbeat 8s ago · reconciliation interval 30s",
        status="Latest snapshot locally verified across 5 nodes · business-path canary not implemented",
        description="A deployment view showing publisher heartbeat, node rollout state, the automatic release pipeline, and the pending signed-current pointer migration.",
        body=body,
    )


def events_page() -> str:
    body = r'''
  <!-- Current unresolved state summary -->
  <rect class="panel" x="21" y="202" width="1538" height="86" rx="7"/>
  <g class="ui">
    <text class="small muted" x="47" y="234">CONFIRMED ISSUES</text><text class="metric green" x="47" y="262">0 unresolved</text>
    <text class="small muted" x="393" y="234">PENDING</text><text class="metric" x="393" y="262">0 transitions</text>
    <text class="small muted" x="706" y="234">CURRENT STATE BASIS</text><text class="metric" x="706" y="262">state.json tracker</text>
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

    <text class="body mono muted" x="47" y="438">12:08:36</text><text class="body mono" x="173" y="438">jm24</text><text class="body" x="303" y="438">route · sg-fixed</text><circle class="neutral-dot" cx="578" cy="433" r="4"/><text class="body" x="591" y="438">sg02 → gz02&gt;sg02</text><text class="body muted" x="866" y="438">5.8h · ongoing</text>
    <text class="tiny muted" x="303" y="457">Candidate p95 1249 ms · 34% better · threshold 20%.</text>

    <text class="body mono muted" x="47" y="501">07:06:46</text><text class="body mono" x="173" y="501">jm24</text><text class="body" x="303" y="501">route · sg-fixed</text><circle class="neutral-dot" cx="578" cy="496" r="4"/><text class="body" x="591" y="501">gz02&gt;sg02 → sg02</text><text class="body muted" x="866" y="501">5.0h</text>
    <text class="tiny muted" x="303" y="520">Candidate p95 1523 ms · 57% better · threshold 20%.</text>

    <text class="body mono muted" x="47" y="564">00:14:31</text><text class="body mono" x="173" y="564">jm24</text><text class="body" x="303" y="564">route · sg-fixed</text><circle class="neutral-dot" cx="578" cy="559" r="4"/><text class="body" x="591" y="564">sg02 → gz02&gt;sg02</text><text class="body muted" x="866" y="564">6.9h</text>
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
    <text class="tiny muted" x="41" y="950">Showing 8 of 200 recent transitions</text><use href="#icon-download" x="985" y="939" width="14" height="14" class="action-icon"/><text class="tiny green" x="1006" y="950">Export JSONL</text>
  </g>

  <!-- Filters -->
  <rect class="panel" x="1106" y="304" width="453" height="242" rx="7"/>
  <g class="ui">
    <use href="#icon-filter" x="1126" y="321" width="16" height="16" class="action-icon"/><text class="section" x="1150" y="334">Filter</text>
    <rect class="chip-green" x="1126" y="357" width="75" height="30" rx="5"/><text class="small green" x="1163" y="377" text-anchor="middle">All</text>
    <rect class="chip" x="1209" y="357" width="97" height="30" rx="5"/><text class="small" x="1257" y="377" text-anchor="middle">Problems</text>
    <rect class="chip" x="1314" y="357" width="105" height="30" rx="5"/><text class="small" x="1366" y="377" text-anchor="middle">Recoveries</text>
    <rect class="chip" x="1427" y="357" width="105" height="30" rx="5"/><text class="small" x="1479" y="377" text-anchor="middle">Changes</text>
    <text class="small muted" x="1126" y="424">NODE</text><text class="body" x="1262" y="424">All nodes</text><text class="tiny green" x="1503" y="424">Change</text>
    <text class="small muted" x="1126" y="456">KIND</text><text class="body" x="1262" y="456">All event kinds</text><text class="tiny green" x="1503" y="456">Change</text>
    <text class="small muted" x="1126" y="488">RANGE</text><text class="body" x="1262" y="488">Last 24 hours</text><text class="tiny green" x="1503" y="488">Change</text>
    <line class="rule" x1="1126" y1="504" x2="1539" y2="504"/>
    <text class="tiny muted" x="1126" y="520">Target interaction · current SSR has no event filters.</text>
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
        status="No confirmed unresolved issues",
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
    <text class="small muted" x="800" y="232">DISTRIBUTION REPORTS</text><text class="body mono" x="800" y="256">4f09f6f5716d</text>
    <text class="small muted" x="1125" y="232">PUBLISH CADENCE</text><text class="body" x="1125" y="256">≤ 30s</text>
    <text class="tiny muted" x="1231" y="256">fleet target ≤ 90s · no publish button</text>
  </g>
  <line class="rule" x1="349" y1="219" x2="349" y2="259"/><line class="rule" x1="765" y1="219" x2="765" y2="259"/><line class="rule" x1="1090" y1="219" x2="1090" y2="259"/>

  <!-- Tabs -->
  <g class="ui nav">
    <text x="21" y="311" font-weight="600">SSOT</text><text class="muted" x="88" y="311">Secret references</text><text class="muted" x="226" y="311">Release policy</text>
  </g>
  <line x1="21" y1="325" x2="56" y2="325" stroke="#2AA875" stroke-width="2"/>
  <line class="rule" x1="21" y1="325" x2="1559" y2="325"/>

  <!-- Sanitized editor -->
  <rect class="panel" x="21" y="341" width="1005" height="632" rx="7"/>
  <g class="ui">
    <text class="section" x="41" y="373">Single source of truth</text>
    <text class="tiny muted" x="276" y="373">Redacted prototype · sensitive values hidden</text>
    <rect class="chip" x="735" y="354" width="116" height="30" rx="5"/><use href="#icon-check" x="750" y="362" width="14" height="14" class="action-icon"/><text class="small" x="812" y="374" text-anchor="middle">Validate</text>
    <rect class="button-green" x="860" y="354" width="144" height="30" rx="5"/><use href="#icon-save" x="875" y="362" width="14" height="14" class="action-icon" style="stroke:#FFFFFF"/><text class="small" x="945" y="374" text-anchor="middle" fill="#FFFFFF">Validate &amp; save</text>
    <text class="tiny muted" x="41" y="404">/opt/loom/deploy/ssot.yaml</text><text class="tiny green" x="1004" y="404" text-anchor="end">Authenticated operator</text>
  </g>

  <rect class="code-bg" x="41" y="419" width="965" height="532" rx="5"/>
  <rect x="41" y="419" width="46" height="532" rx="5" fill="#F1F3F2"/>
  <line class="rule" x1="87" y1="419" x2="87" y2="951"/>
  <g class="ui tiny mono muted" text-anchor="end">
    <text x="76" y="447">1</text><text x="76" y="469">2</text><text x="76" y="491">3</text><text x="76" y="513">4</text><text x="76" y="535">5</text><text x="76" y="557">6</text><text x="76" y="579">7</text><text x="76" y="601">8</text><text x="76" y="623">9</text><text x="76" y="645">10</text><text x="76" y="667">11</text><text x="76" y="689">12</text><text x="76" y="711">13</text><text x="76" y="733">14</text><text x="76" y="755">15</text><text x="76" y="777">16</text><text x="76" y="799">17</text><text x="76" y="821">18</text><text x="76" y="843">19</text><text x="76" y="865">20</text><text x="76" y="887">21</text><text x="76" y="909">22</text><text x="76" y="931">23</text>
  </g>
  <g class="ui body mono">
    <text x="101" y="447"><tspan class="blue">defaults</tspan>:</text>
    <text x="101" y="469">  <tspan class="blue">components</tspan>:</text>
    <text x="101" y="491">    <tspan class="blue">wireguard</tspan>: <tspan class="green">1.0.20250521</tspan></text>
    <text x="101" y="513">    <tspan class="blue">agent</tspan>: <tspan class="green">0.1.0</tspan></text>
    <text x="101" y="535"> </text>
    <text x="101" y="557"><tspan class="blue">nodes</tspan>:</text>
    <text x="101" y="579">  - <tspan class="blue">id</tspan>: <tspan class="green">jm24</tspan></text>
    <text x="101" y="601">    <tspan class="blue">city</tspan>: Beijing</text>
    <text x="101" y="623">    <tspan class="blue">server</tspan>: { <tspan class="blue">direction</tspan>: bidirectional, <tspan class="blue">egress_capable</tspan>: false }</text>
    <text x="101" y="645">  - <tspan class="blue">id</tspan>: <tspan class="green">gz02</tspan></text>
    <text x="101" y="667">    <tspan class="blue">server</tspan>: { <tspan class="blue">direction</tspan>: bidirectional, <tspan class="blue">egress_capable</tspan>: true }</text>
    <text x="101" y="689">  <tspan class="faint"># … 3 more nodes</tspan></text>
    <text x="101" y="711"> </text>
    <text x="101" y="733"><tspan class="blue">tunnels</tspan>:</text>
    <text x="101" y="755">  - { <tspan class="blue">from</tspan>: jm24, <tspan class="blue">to</tspan>: sg02, <tspan class="faint"># addresses hidden</tspan> }</text>
    <text x="101" y="777">  - { <tspan class="blue">from</tspan>: gz02, <tspan class="blue">to</tspan>: sg02, <tspan class="faint"># addresses hidden</tspan> }</text>
    <text x="101" y="799">  <tspan class="faint"># … 4 more persistent links</tspan></text>
    <text x="101" y="821"> </text>
    <text x="101" y="843"><tspan class="blue">declarations</tspan>:</text>
    <text x="101" y="865">  - { <tspan class="blue">id</tspan>: <tspan class="green">best-egress</tspan>, <tspan class="blue">egress_axis</tspan>: any, <tspan class="blue">objective</tspan>: latency, <tspan class="blue">max_hops</tspan>: 2 }</text>
    <text x="101" y="887"> </text>
    <text x="101" y="909"><tspan class="blue">services</tspan>:</text>
    <text x="101" y="931">  - { <tspan class="blue">id</tspan>: <tspan class="green">intl-api</tspan>, <tspan class="blue">declaration</tspan>: best-egress, <tspan class="blue">addresses</tspan>: [api.ipify.org, .githubusercontent.com] }</text>
  </g>

  <!-- Validation and automatic publication contract -->
  <rect class="panel" x="1042" y="341" width="517" height="196" rx="7"/>
  <g class="ui">
    <text class="section" x="1062" y="373">Validation</text>
    <circle class="status-dot" cx="1067" cy="406" r="4"/><text class="body green" x="1080" y="411">Current file passes all checks</text>
    <text class="small muted" x="1062" y="443">Schema</text><text class="body" x="1207" y="443">Valid</text>
    <text class="small muted" x="1062" y="471">Topology</text><text class="body" x="1207" y="471">5 nodes · 6 tunnels</text>
    <text class="small muted" x="1062" y="499">Routing entries</text><text class="body" x="1207" y="499">5 renderable</text>
    <text class="tiny muted" x="1062" y="522">Save performs validation again; the UI check is not the guard.</text>
  </g>

  <rect class="panel" x="1042" y="553" width="517" height="211" rx="7"/>
  <g class="ui">
    <text class="section" x="1062" y="585">What happens after save</text>
    <text class="body" x="1062" y="619">1</text><text class="body" x="1093" y="619">Atomic SSOT write after validation</text>
    <text class="body" x="1062" y="650">2</text><text class="body" x="1093" y="650">Publisher detects the change within ~30s</text>
    <text class="body" x="1062" y="681">3</text><text class="body" x="1093" y="681">Render, sign and distribute immutable snapshot</text>
    <text class="body" x="1062" y="712">4</text><text class="body" x="1093" y="712">Nodes pull, apply, verify or stay on last good</text>
    <line class="rule" x1="1062" y1="731" x2="1539" y2="731"/>
    <text class="tiny muted" x="1062" y="751">There is deliberately no second, manual Publish decision.</text>
  </g>

  <rect class="panel" x="1042" y="780" width="517" height="193" rx="7"/>
  <g class="ui">
    <text class="section" x="1062" y="812">Security boundary &amp; gaps</text>
    <text class="small muted" x="1062" y="845">PRIVATE KEYS</text><text class="body" x="1238" y="845">Never shown or stored here</text>
    <text class="small muted" x="1062" y="876">CREDENTIALS</text><text class="body" x="1238" y="876">References only</text>
    <line class="rule" x1="1062" y1="895" x2="1539" y2="895"/>
    <text class="tiny amber" x="1062" y="918">Known web-editing gaps</text>
    <text class="tiny muted" x="1062" y="938">No dry-run diff, source revision guard, or approval audit.</text>
    <text class="tiny muted" x="1062" y="957">Concurrent saves are last-writer-wins; live snapshot stays old on failure.</text>
  </g>
'''
    return shell(
        active="Settings",
        eyebrow="SINGLE WRITER",
        title="Settings / SSOT",
        subtitle="Declarative source of truth · saves are validated and published automatically",
        status="Authenticated operator session · secrets remain node-local",
        description="An authenticated SSOT configuration editor showing validation, automatic publication behavior, known concurrency gaps, and the security boundary around secrets.",
        body=body,
        environment_status="Control node",
        session_status="Authenticated",
    )


PAGES = {
    "loom-control-center-overview-misaka-v1.svg": overview_page,
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
