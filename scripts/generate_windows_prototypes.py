#!/usr/bin/env python3
"""Render Windows design SVGs; never used by the native UI review.

See docs/clients/prototype-review.md. Fixtures are illustrative, not live status.
Rendering is deterministic: the canonical logo and the scene name are the only
inputs. This does not render or update the Win32/Direct2D screenshot goldens.
"""

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets/client/windows"
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)

WIDTH, HEIGHT = 876, 614
LEFT, RIGHT = 200, 852
CONTENT_WIDTH = RIGHT - LEFT
VIEWPORT_TOP = 52
VIEWPORT_BOTTOM = HEIGHT - 0.5
VIEWPORT_HEIGHT = VIEWPORT_BOTTOM - VIEWPORT_TOP
CONTENT_BOTTOM_PADDING = 24
CONTROL_HEIGHT = 32
PANEL_RADIUS = 12
CONTROL_RADIUS = 8
PANEL_HEADER_HEIGHT = 48
PANEL_INSET = 16
INNER_LEFT, INNER_RIGHT = LEFT + PANEL_INSET, RIGHT - PANEL_INSET
PROFILE_ROW_HEIGHT = 64
PROFILE_ROW_GAP = 8
ROUTES_TOP = 296
ROUTE_HEIGHT = 112
DETAIL_HEIGHT = 232
RULE = 0.75
# Share Android's surface/active palette, with desktop control dimensions.
CANVAS = "#F0F4F1"
SURFACE = "#FFFFFF"
SOFT_SURFACE = "#F7FBF8"
INK = "#17211B"
MUTED = "#647269"
LINE = "#E1E8E3"
GREEN = "#239B68"
GREEN_TEXT = "#22764F"
GREEN_BG = "#EAF6F0"
RED = "#B75C57"
SCENES = (
    "connected", "fixed-tun", "path-expanded", "profile-rename",
    "profiles-empty", "join-draft", "join-empty", "join-error", "viewport-bottom",
)


def element(parent, tag, **attrs):
    return ET.SubElement(parent, f"{{{NS}}}{tag}", {
        key.replace("_", "-"): str(value)
        for key, value in attrs.items() if value is not None
    })


def rect(parent, x, y, w, h, fill="none", stroke=None, radius=0, **attrs):
    return element(parent, "rect", x=x, y=y, width=w, height=h,
                   rx=radius or None, fill=fill, stroke=stroke,
                   stroke_width=RULE if stroke else None, **attrs)


def line(parent, x1, y1, x2, y2, color=LINE, width=RULE, **attrs):
    return element(parent, "line", x1=x1, y1=y1, x2=x2, y2=y2,
                   stroke=color, stroke_width=width, **attrs)


def text(parent, x, y, value, size=12, color=INK, weight=400, anchor="start", **attrs):
    node = element(parent, "text", x=x, y=y, font_size=size, fill=color,
                   font_weight=weight, text_anchor=anchor,
                   dominant_baseline="central", **attrs)
    node.text = value
    return node


def path(parent, d, color=MUTED, width=1, **attrs):
    return element(parent, "path", d=d, fill="none", stroke=color,
                   stroke_width=width, stroke_linecap="round",
                   stroke_linejoin="round", **attrs)


def circle(parent, x, y, r, fill, **attrs):
    return element(parent, "circle", cx=x, cy=y, r=r, fill=fill, **attrs)


def button(parent, x, y, w, label, kind="secondary", expanded=None):
    group = element(parent, "g", data_ui="button", data_state=kind)
    fill = {"primary": GREEN, "tonal": GREEN_BG, "disabled": "#E8EEEA"}.get(kind, SURFACE)
    border = None if kind in ("primary", "tonal", "disabled") else "#D7DFD9"
    foreground = {"primary": SURFACE, "tonal": GREEN_TEXT, "disabled": "#A0ABA4"}.get(kind, INK)
    rect(group, x, y, w, CONTROL_HEIGHT, fill, border, CONTROL_RADIUS)
    text(group, x + w / 2 - (8 if expanded is not None else 0), y + CONTROL_HEIGHT / 2, label,
         color=foreground, weight=500, anchor="middle")
    if expanded is not None:
        cy = y + CONTROL_HEIGHT / 2
        tip = -2 if expanded else 2
        path(group, f"M{x+w-24} {cy-tip}l4 {tip*2} 4 {-tip*2}", foreground)


def panel(parent, top, height, kind, fill=SURFACE):
    group = element(parent, "g", data_ui="panel", data_kind=kind)
    rect(group, LEFT, top, CONTENT_WIDTH, height, fill, radius=PANEL_RADIUS)
    return group


def panel_divider(parent, y):
    # Separators span the surface; only text and controls have a 16px inset.
    return line(parent, LEFT, y, RIGHT, y, data_ui="panel-divider")


def logo_definitions(defs, canonical):
    source_paths = list(canonical.iter(f"{{{NS}}}path"))
    element(defs, "path", id="loom-outline", d=source_paths[0].get("d"))
    element(defs, "path", id="petal-opening",
            d="M628 1040C520 945 535 790 628 660C721 790 736 945 628 1040Z")
    titlemark = element(defs, "symbol", id="loom-title-mark", viewBox="125 110 1005 1005")
    titlegroup = element(titlemark, "g", transform="translate(0 1254) scale(1 -1)")
    element(titlegroup, "use", href="#loom-outline", fill="#6D63BD")
    for angle in range(0, 360, 60):
        element(titlegroup, "use", href="#petal-opening", fill="#FFFFFF",
                transform=f"rotate({angle} 628 644)")
    gradient = element(defs, "linearGradient", id="brand-bg", x1=0, y1=0, x2=1, y2=1)
    element(gradient, "stop", offset="0", stop_color="#667EEA")
    element(gradient, "stop", offset="1", stop_color="#764BA2")
    tile = element(defs, "symbol", id="loom-tile-mark", viewBox="0 0 1254 1254")
    tilegroup = element(tile, "g", transform="translate(0 1254) scale(1 -1)")
    for source in source_paths:
        # Preserve the existing small Windows tile's flat cutout treatment.
        fill = "#7062C2" if source.get("fill") == "#5b6166" else "#FAFAF7"
        element(tilegroup, "path", d=source.get("d"), fill=fill)


def frame(root, defs, scene):
    clip = element(defs, "clipPath", id="window-clip")
    rect(clip, 0.5, 0.5, WIDTH - 1, HEIGHT - 1, radius=10)
    group = element(root, "g", clip_path="url(#window-clip)")
    rect(group, 0, 0, WIDTH, HEIGHT, CANVAS)
    rect(group, 0, 36, 176, HEIGHT - 36, "#F7F9F7")
    rect(group, 0, 0, WIDTH, 36, "#FAFBFA")
    line(group, 0, 36, WIDTH, 36)
    line(group, 176, 36, 176, HEIGHT)
    element(group, "use", href="#loom-title-mark", x=14, y=9, width=18, height=18)
    title = "Loom" if scene in ("profiles-empty", "join-empty", "join-error") else "Loom (Portable TUN) 已连接 · 演示网络甲"
    text(group, 40, 18, title, 11, "#626E66")
    line(group, 790, 18, 802, 18, MUTED, 1)
    path(group, "M839 13l10 10m0-10l-10 10", MUTED)
    sidebar(group, scene)
    return group


def sidebar(parent, scene):
    rect(parent, 16, 56, 36, 36, "url(#brand-bg)", radius=8)
    element(parent, "use", href="#loom-tile-mark", x=16, y=56, width=36, height=36)
    text(parent, 64, 66, "Loom", 20, weight=600)
    text(parent, 64, 88, "你的连接配置", 11, MUTED)
    text(parent, 16, 120, "连接配置", 11, MUTED, 500)
    # The plus has a full 32px interaction area, even though its glyph is small.
    plus = element(parent, "g", data_ui="icon-button")
    rect(plus, 132, 104, 32, 32, "#F7F9F7", radius=4)
    path(plus, "M142 120h12m-6-6v12", GREEN)
    if scene == "profiles-empty":
        return
    selected = 1 if scene in ("join-empty", "join-error") else 0
    for index in range(2):
        top = 144 + index * (PROFILE_ROW_HEIGHT + PROFILE_ROW_GAP)
        group = element(parent, "g", data_ui="profile-row", data_selected=str(index == selected).lower())
        if index == selected:
            rect(group, 12, top, 152, PROFILE_ROW_HEIGHT, GREEN_BG, radius=CONTROL_RADIUS)
            rect(group, 12, top + 20, 2, 24, GREEN, radius=1)
        title = "演示网络甲" if index == 0 else "演示空配置" if selected == 1 else "演示网络乙"
        status = "已连接" if index == 0 else "导入失败" if scene == "join-error" else "未加入" if selected == 1 else "未连接"
        color = GREEN_TEXT if index == 0 else RED if scene == "join-error" else MUTED
        circle(group, 28, top + 20, 3, color)
        if scene == "profile-rename" and index == 0:
            rect(group, 40, top + 4, 116, 32, SURFACE, GREEN, CONTROL_RADIUS, data_ui="input")
            text(group, 52, top + 20, "demo-renamed", 12)
            line(group, 142, top + 12, 142, top + 28, GREEN, 1)
        else:
            text(group, 40, top + 20, title, 12, weight=500 if index == selected else 400)
        text(group, 40, top + 48, status, 11, color)
    line(parent, 16, 542, 160, 542)
    text(parent, 16, 566, "双击名称可重命名", 11, MUTED)
    text(parent, 16, 590, "同时只运行一个连接", 11, MUTED)


def heading(parent, label, delete=False, connected=False):
    text(parent, LEFT, 72, label, 20, weight=600)
    if delete:
        button(parent, 756, 56, 96, "删除配置", "disabled" if connected else "secondary")


def status_icon(parent, x, y, state):
    color = GREEN if state == "connected" else RED if state == "error" else MUTED
    fill = GREEN_BG if state == "connected" else "#FBF0EE" if state == "error" else "#EFF2F0"
    circle(parent, x, y, 16, fill)
    if state == "connected":
        path(parent, f"M{x-6} {y}l4 4 8-8", color, 1.25)
    elif state == "error":
        path(parent, f"M{x} {y-6}v7", color, 1.25)
        circle(parent, x, y + 5, 0.85, color)
    else:
        path(parent, f"M{x-5} {y-6}h7l3 3v9h-10zM{x+2} {y-6}v3h3", color, 1.25)


def connection_summary(parent, fixed=False):
    extra = 24 if fixed else 0
    group = panel(parent, 104, 112 + extra, "connection-summary", SOFT_SURFACE)
    status_icon(group, 232, 136, "connected")
    text(group, 264, 136, "已连接", 20, weight=500)
    button(group, 740, 120, 96, "断开", "primary")
    if fixed:
        text(group, 264, 168, "系统 TUN 已启用；本地 HTTP/SOCKS 代理：127.0.0.1:1080。", 11, MUTED)
    panel_divider(group, 168 + extra)
    text(group, INNER_LEFT, 192 + extra, "Device  demo-device-a", 11, MUTED)
    return 112 + extra


def route_mode(parent, top, fixed=False):
    text(parent, LEFT, top + 16, "路由模式", 14, weight=500)
    group = element(parent, "g", data_ui="segmented-control")
    rect(group, 280, top, 240, 32, "#E4ECE7", radius=CONTROL_RADIUS)
    selected = 2 if fixed else 1
    rect(group, 284 + selected * 80, top + 4, 72, 24, GREEN, radius=4,
         data_ui="selected-segment")
    for index, label in enumerate(("直连", "自动", "固定出口")):
        text(group, 320 + index * 80, top + 16, label, 12,
             SURFACE if selected == index else MUTED,
             500 if selected == index else 400, "middle")
    if fixed:
        selector = element(parent, "g", data_ui="select")
        rect(selector, 536, top, 160, 32, SURFACE, "#D7DFD9", CONTROL_RADIUS)
        text(selector, 548, top + 16, "demo-exit")
        path(selector, f"M676 {top+14}l4 4 4-4")
        text(parent, 708, top + 16, "前置路径自动选择", 11, MUTED)


def route_node(parent, x, y, label, kind):
    circle(parent, x, y, 16, "#F3F6F4", stroke="#DAE3DD", stroke_width=RULE)
    group = element(parent, "g", transform=f"translate({x} {y})")
    if kind == "device":
        path(group, "M-6-5H6v8H-6zM-8 6H8", "#6B8174")
    elif kind == "relay":
        path(group, "M-5-7H5V7H-5zM-2-3H2M-2 1H2M-2 5H2", "#6B8174")
    elif kind == "exit":
        path(group, "M-5-7H5V7H-5zM-2-3H2M-2 1H2M2 5H8m-2-2 2 2-2 2", "#6B8174")
    else:
        circle(group, 0, 0, 6, "none", stroke="#6B8174", stroke_width=1)
        path(group, "M-6 0H6M0-6C-4-3-4 3 0 6C4 3 4-3 0-6", "#6B8174")
    text(parent, x, y + 32, label, 11, "#627169", anchor="middle")


def route_row(parent, top, service, healthy=True, expanded=False):
    group = element(parent, "g", data_ui="route-row", data_service=service)
    text(group, INNER_LEFT, top + 20, service, 12, weight=500)
    evidence = "TCP/TLS 与 UDP/DNS 已验证" if healthy else "尚无真实业务结果"
    # Reserve one 80px status column so both observation summaries align.
    text(group, INNER_RIGHT - 80 - 16, top + 20, evidence, 11, MUTED, anchor="end")
    status = "可用" if healthy else "测量未知"
    # 12px + 4px dot + 8px gap + CJK label + 12px. Both pills have equal insets.
    status_width = 36 + len(status) * 11
    status_left = INNER_RIGHT - status_width
    badge = element(group, "g", data_ui="status-badge", data_state="available" if healthy else "unknown")
    rect(badge, status_left, top + 8, status_width, 24,
         GREEN_BG if healthy else "#F0F3F1", radius=12)
    circle(badge, status_left + 14, top + 20, 2, GREEN if healthy else "#99A69E")
    text(badge, status_left + 24, top + 20, status, 11, GREEN_TEXT if healthy else MUTED)
    # Reserve an 80px label column at either end before distributing four nodes.
    first, last = INNER_LEFT + 40, INNER_RIGHT - 40
    centers = tuple(first + index * (last - first) / 3 for index in range(4))
    for start, end in zip(centers, centers[1:]):
        line(group, start + 24, top + 64, end - 24, top + 64, "#C6D4CB", 1)
        path(group, f"M{end-28} {top+61}l4 3-4 3", "#AABCB0")
    prefix = "demo-prefix-a" if healthy else "demo-prefix-b"
    labels = ("本机", prefix, "demo-exit", "目标地址")
    for x, label, kind in zip(centers, labels, ("device", "relay", "exit", "target")):
        route_node(group, x, top + 64, label, kind)
    if expanded:
        # All evidence is a fixed demo fixture, never inferred from route preference.
        # Evidence stays in its Service, separated without another card.
        panel_divider(group, top + 112)
        text(group, INNER_LEFT, top + 136, "业务目标：https://web.example/ · HTTPS 成功", 11, MUTED)
        text(group, INNER_LEFT, top + 160, "观测范围：demo-web · 当前候选 · 当前网络", 11, MUTED)
        text(group, INNER_LEFT, top + 184, "业务采样：2030-01-01 10:00:00 UTC · 有效至 10:05:00 UTC", 11, MUTED)
        text(group, INNER_LEFT, top + 208, "selector 回读：当前候选 · 回读时间：2030-01-01 10:00:20 UTC", 11, MUTED)
    return DETAIL_HEIGHT if expanded else ROUTE_HEIGHT


def route_panel(parent, top, services, expanded=False):
    heights = [DETAIL_HEIGHT if expanded and index == 0 else ROUTE_HEIGHT
               for index in range(len(services))]
    height = PANEL_HEADER_HEIGHT + sum(heights) + 16
    group = panel(parent, top, height, "routes")
    text(group, 216, top + 24, "当前选路", 14, weight=500)
    button(group, 740, top + 8, 96, "收起详情" if expanded else "详细信息",
           "tonal", expanded=expanded)
    panel_divider(group, top + PANEL_HEADER_HEIGHT)
    row_top = top + PANEL_HEADER_HEIGHT
    for index, (service, healthy) in enumerate(services):
        if index:
            panel_divider(group, row_top)
        row_top += route_row(group, row_top, service, healthy, expanded and index == 0)
    return height


def scroll_view(parent, defs):
    clip = element(defs, "clipPath", id="content-clip")
    rect(clip, LEFT, VIEWPORT_TOP, CONTENT_WIDTH, VIEWPORT_HEIGHT)
    return element(parent, "g", clip_path="url(#content-clip)", data_ui="scroll-content")


def scrollbar(parent, content_bottom, at_bottom=False):
    if content_bottom <= VIEWPORT_BOTTOM:
        return
    content_height = content_bottom - VIEWPORT_TOP
    group = element(parent, "g", data_ui="scrollbar")
    width = 3
    x = WIDTH - 0.5 - width  # Flush with the inner edge of the window frame.
    rect(group, x, VIEWPORT_TOP, width, VIEWPORT_HEIGHT, "#F0F3F1", radius=1.5)
    thumb_height = round(VIEWPORT_HEIGHT * VIEWPORT_HEIGHT / content_height, 2)
    thumb_top = VIEWPORT_BOTTOM - thumb_height if at_bottom else VIEWPORT_TOP
    rect(group, x, thumb_top, width, thumb_height, "#C7D1CA", radius=1.5)


def connected(parent, defs, scene):
    fixed = scene == "fixed-tun"
    expanded = scene == "path-expanded"
    # The entire right pane scrolls, as it does in viewport-bottom. The sidebar
    # and titlebar remain outside this clip in every scene.
    content = scroll_view(parent, defs)
    heading(content, "演示网络甲", delete=True, connected=True)
    summary_height = connection_summary(content, fixed)
    mode_top = 104 + summary_height + 24
    route_mode(content, mode_top, fixed)
    services = [("统一上网路径", True)] if fixed else [("demo-web", True), ("demo-api", False)]
    routes_top = mode_top + CONTROL_HEIGHT + 24
    height = route_panel(content, routes_top, services, expanded)
    scrollbar(parent, routes_top + height + CONTENT_BOTTOM_PADDING)


def viewport_bottom(parent, defs):
    content = scroll_view(parent, defs)
    # Use the same panel and row geometry as the top view. At the bottom,
    # Services 4–7 are fully visible, with the tail of Service 3 above them.
    height = PANEL_HEADER_HEIGHT + 7 * ROUTE_HEIGHT + 16
    # Bottom padding belongs to the scrollable content, not to a fixed strip
    # outside its viewport. It becomes visible only at the end of the panel.
    content_bottom = ROUTES_TOP + height + CONTENT_BOTTOM_PADDING
    scroll_offset = max(0, content_bottom - VIEWPORT_BOTTOM)
    route_panel(content, ROUTES_TOP - scroll_offset,
                [(f"demo-service-{index}", True) for index in range(1, 8)])
    scrollbar(parent, content_bottom, at_bottom=True)


def profiles_empty(parent):
    heading(parent, "连接配置")
    group = panel(parent, 104, 160, "profiles-empty")
    status_icon(group, 232, 136, "empty")
    text(group, 264, 136, "尚无连接配置", 20, weight=500)
    text(group, 264, 176, "完成加入并保存后，配置才会出现在列表中。", 12)
    button(group, 264, 208, 152, "添加连接配置", "primary")


def join_draft(parent):
    heading(parent, "添加连接配置")
    group = panel(parent, 104, 336, "join-draft")
    text(group, 216, 128, "保存后保持断开，现有连接继续运行。", 11, MUTED)
    panel_divider(group, 152)
    text(group, 216, 176, "配置名称", 12, weight=500)
    rect(group, 216, 192, CONTENT_WIDTH - 32, 32, SURFACE, "#D7DFD9", CONTROL_RADIUS, data_ui="input")
    text(group, 228, 208, "demo-unsaved-input")
    text(group, 216, 256, "加入邀请", 12, weight=500)
    text(group, 216, 280, "二维码 PNG 或 .loom-invite 文件，也可从剪贴板粘贴。", 11, MUTED)
    button(group, 216, 300, 152, "选择邀请文件")
    button(group, 380, 300, 152, "粘贴二维码")
    text(group, 216, 352, "导入中控提供的加入二维码后，才会保存连接配置。", 11, MUTED)
    panel_divider(group, 376)
    button(group, 604, 392, 96, "取消")
    button(group, 712, 392, 124, "加入并保存", "disabled")


def join_unavailable(parent, error=False):
    heading(parent, "演示空配置", delete=True)
    # State, recovery actions and the still-running connection share one surface.
    group = panel(parent, 104, 256, "join-error" if error else "join-empty")
    status_icon(group, 232, 136, "error" if error else "empty")
    text(group, 264, 136, "导入失败" if error else "此配置尚未加入", 20, weight=500)
    if error:
        text(group, 264, 176, "演示邀请已过期，请使用新的邀请重试。", 12, RED)
    else:
        text(group, 264, 176, "导入此配置的加入邀请，加入后保持断开。", 12)
    text(group, 264, 200, "支持二维码 PNG 或 .loom-invite 文件。", 11, MUTED)
    button(group, 264, 224, 152, "重新选择…" if error else "选择邀请文件")
    button(group, 428, 224, 152, "粘贴二维码")
    text(group, 264, 280, "也可拖入邀请文件，或按 Ctrl+V 粘贴。", 11, MUTED)
    panel_divider(group, 312)
    circle(group, 220, 336, 3, GREEN)
    text(group, 232, 336, "当前连接：“演示网络甲”", 11, MUTED)


def render(scene, canonical):
    root = ET.Element(f"{{{NS}}}svg", {
        "width": str(WIDTH), "height": str(HEIGHT),
        "viewBox": f"0 0 {WIDTH} {HEIGHT}", "role": "img",
        "aria-labelledby": "scene-title scene-description",
        "font-family": "'Segoe UI', 'Microsoft YaHei UI', 'Noto Sans CJK SC', sans-serif",
    })
    element(root, "title", id="scene-title").text = f"Loom Windows — {scene}"
    description = (
        "Editable Windows design prototype with demo fixtures. "
        "Android-aligned panel surfaces, status chips and active colors; "
        "24px content insets, 16px panel insets and 32px desktop controls. "
        "Not a native Win32 screenshot or evidence of runtime health."
    )
    if scene == "profiles-empty":
        description += (
            " First-use state: the profile list is empty; the plus and Add connection profile "
            "actions open the existing join-draft form. No identity or active connection exists."
        )
    elif scene == "join-empty":
        description += (
            " Exceptional comparison state: an existing profile entry lacks joined identity "
            "or a complete certified LKG. This is neither first use nor the next step of "
            "normal profile creation. The other profile's active connection continues."
        )
    elif scene == "path-expanded":
        description += (
            " Business outcome and selector readback are separate fixed demo observations. "
            "Illustrative current time is 2030-01-01T10:00:30Z, within the business "
            "observation's validity ending at 2030-01-01T10:05:00Z."
        )
    element(root, "desc", id="scene-description").text = description
    defs = element(root, "defs")
    logo_definitions(defs, canonical)
    window = frame(root, defs, scene)
    if scene == "profiles-empty":
        profiles_empty(window)
    elif scene == "join-draft":
        join_draft(window)
    elif scene in ("join-empty", "join-error"):
        join_unavailable(window, scene == "join-error")
    elif scene == "viewport-bottom":
        viewport_bottom(window, defs)
    else:
        connected(window, defs, scene)
    rect(root, 0.5, 0.5, WIDTH - 1, HEIGHT - 1, stroke="#CDD5CF", radius=10)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def main():
    canonical = ET.parse(ROOT / "assets/loom-logo-v4.svg").getroot()
    OUT.mkdir(parents=True, exist_ok=True)
    for scene in SCENES:
        (OUT / f"{scene}.svg").write_text(render(scene, canonical), encoding="utf-8")
    print(f"Generated {len(SCENES)} Windows design SVGs.")


if __name__ == "__main__":
    main()
