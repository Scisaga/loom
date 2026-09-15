#!/usr/bin/env python3
"""按客户端界面规范，还原已安装 Android 三个 Tab 并补充多配置和路径详情。"""

from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets/client/android"
WIDTH, HEIGHT = 412, 940
INK, MUTED, GREEN = "#17211B", "#647269", "#239B68"
PAPER, CARD_TINT, LINE = "#F0F4F1", "#F7FBF8", "#E3E8E5"
OUTLINE, OUTLINE_TEXT = "#857E8C", "#725AA8"
FONT = "'Noto Sans CJK SC','Roboto',sans-serif"
TABS = (("connection", "连接", "power"), ("configuration", "配置", "sliders"), ("diagnostics", "诊断", "pulse"))


def text(x, y, value, size=13, color=INK, weight=400, anchor="start", spacing=0):
    return (f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}" letter-spacing="{spacing}">'
            f'{escape(value)}</text>')


def rect(x, y, w, h, fill="white", radius=16, stroke="none"):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
            f'rx="{radius}" fill="{fill}" stroke="{stroke}"/>')


def line(y):
    return f'<path d="M38 {y}h336" stroke="{LINE}"/>'


def dot(x, y, r=4, fill=GREEN):
    return f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}"/>'


def paragraph(x, y, values, size=13, color=MUTED, leading=22):
    return "".join(text(x, y + i * leading, value, size, color) for i, value in enumerate(values))


def icon(name, x, y, color=MUTED, size=22):
    shapes = {
        "power": '<circle cx="12" cy="13" r="8"/><path d="M12 2v9"/>',
        "sliders": '<path d="M3 6h18M3 12h18M3 18h18"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
        "pulse": '<path d="M2 12h5l3-7 4 14 3-7h5"/>',
        "more": '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
        "plus": '<path d="M12 5v14M5 12h14"/>',
        "down": '<path d="m6 9 6 6 6-6"/>',
        "phone": '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 18h4"/>',
        "server": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.1M7 17.5h.1M12 6.5h5M12 17.5h5"/>',
        "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18M12 3c-5 5-5 13 0 18"/>',
    }
    return (f'<g transform="translate({x},{y}) scale({size / 24})" fill="none" '
            f'stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
            f'stroke-linejoin="round">{shapes[name]}</g>')


def control(body, kind, hint):
    return f'<g data-component="{kind}"><title>{escape(hint)}</title>{body}</g>'


def button(x, y, w, label, *, filled=False, small_radius=False, hint="", height=48):
    color = "white" if filled else OUTLINE_TEXT
    radius = 14 if filled else 12 if small_radius else height / 2
    body = rect(x, y, w, height, GREEN if filled else "white", radius, "none" if filled else OUTLINE)
    body += text(x + w / 2, y + height / 2 + 5, label, 14, color, 500, "middle")
    return control(body, "Button" if filled else "OutlinedButton", hint or label)


def text_button(x, y, w, label, hint=""):
    body = rect(x, y, w, 48, "transparent", 24)
    body += text(x + w / 2, y + 30, label, 13, OUTLINE_TEXT, 500, "middle")
    return control(body, "TextButton", hint or label)


def brand():
    # 复用已安装版 ic_loom 的透明图形；仅将这一原型中的图案设为纯黑。
    source = ET.parse(ROOT / "assets/loom-logo-transparent-titanium.svg").getroot()
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    groups = []
    for child in source:
        if child.tag.rsplit("}", 1)[-1] != "g":
            continue
        for element in child.iter():
            if element.get("fill"):
                element.set("fill", "#000000")
        groups.append(ET.tostring(child, encoding="unicode"))
    return f'<symbol id="brand" viewBox="{source.get("viewBox")}">{"".join(groups)}</symbol>'


def header(title, subtitle):
    out = text(22, 19, "12:00", 12, weight=500)
    out += '<path d="M344 18v-4m5 4v-7m5 7V8" stroke="#17211B" stroke-width="2.4"/>'
    out += rect(369, 8, 18, 10, "none", 2, INK) + rect(371, 10, 12, 6, INK, 1)
    out += '<path d="M389 11v4" stroke="#17211B" stroke-width="2"/>'
    out += '<use href="#brand" x="22" y="38" width="32" height="32"/>'
    out += text(63, 54, "LOOM", 18, weight=500, spacing=2)
    out += text(63, 71, "ANDROID", 9, MUTED, spacing=1)
    out += text(22, 120, title, 26, weight=700)
    out += text(22, 156, subtitle, 13, MUTED)
    return out


def navigation(selected):
    out = rect(0, 840, WIDTH, 100, "white", 0)
    for i, (key, label, glyph) in enumerate(TABS):
        center = WIDTH * (i + 0.5) / 3
        color = GREEN if key == selected else MUTED
        item = rect(center - WIDTH / 6, 840, WIDTH / 3, 80, "transparent", 0)
        if key == selected:
            item += rect(center - 32, 852, 64, 32, "#EAF6F0", 16)
        item += icon(glyph, center - 11, 857, color)
        item += text(center, 907, label, 12, color, 500, "middle")
        out += control(item, "NavigationBarItem", f"切换到{label} Tab，保留各页滚动位置")
    out += rect(152, 930, 108, 4, "#17211B", 2)
    return out


def route_diagram():
    # 连线表达实际读回的路径；观测未知只影响数值，不抹掉已确认的链路。
    nodes = (
        (468, "phone", "本机", "设备"),
        (546, "server", "demo-a", "入口"),
        (624, "server", "demo-exit", "出口"),
        (702, "globe", "demo.example", "目标地址"),
    )
    links = (
        (468, "Hysteria2 · 入口 ping", "12 ms", "本机测量 · 12:00:00"),
        (546, "WireGuard", "38 ms", "服务器观测 · 12:00:01"),
        (624, "HTTPS · 首次响应", "—", "暂无观测"),
    )
    out = ""
    for y, protocol, metric, source in links:
        out += f'<path d="M56 {y + 17}v44m-4-6 4 6 4-6" fill="none" stroke="#ACC5B6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
        out += text(86, y + 41, protocol, 12, MUTED)
        out += text(374, y + 41, metric, 13, MUTED, anchor="end")
        out += text(86, y + 59, source, 11, MUTED)
    for y, glyph, name, role in nodes:
        out += f'<circle cx="56" cy="{y}" r="16" fill="#F1F5F2" stroke="#DEE7E0"/>'
        out += icon(glyph, 46, y - 10, size=20)
        out += text(86, y + 5, name, 14, weight=500)
        out += text(374, y + 5, role, 11, MUTED, anchor="end")
    return f'<g data-component="CurrentPathDiagram">{out}</g>'


def connection():
    out = header("连接", "连接状态与当前生效路径")
    out += rect(22, 178, 368, 156, CARD_TINT, 20)
    out += dot(45.5, 210, 5.5) + text(60, 217, "已连接", 20, weight=700)
    out += text_button(264, 187, 120, "个人网络", "打开原生底部选择面板；切换连接需明确点击操作")
    out += icon("down", 367, 203, GREEN, 16)
    out += text(40, 247, "VPN 已开启 · Auto", 13, MUTED)
    out += button(40, 266, 332, "断开", filled=True, height=50, hint="通过现有 VpnService 停止连接")

    out += rect(22, 350, 368, 470)
    out += text(38, 382, "当前路径", 17, weight=700)
    out += rect(294, 366, 80, 27, "#EAF6F0", 20)
    out += text(334, 384, "当前连接", 11, GREEN, 700, "middle")
    out += text(38, 415, "demo-web · 选路详情", 14, weight=700)
    out += text(38, 438, "实际候选：demo-route-a", 12, MUTED)
    out += route_diagram()
    out += text(38, 738, "按入口与服务器观测选路 · 12:00:02", 11, MUTED)
    out += button(38, 754, 336, "收起详情", hint="在现有路径卡片内展开或收起；内容随连接页整体滚动")
    return out + navigation("connection")


def profile_row(y, name, detail, selected):
    body = rect(38, y, 336, 72, "transparent", 0)
    body += f'<circle cx="50" cy="{y + 32}" r="9" fill="none" stroke="{GREEN if selected else MUTED}" stroke-width="1.8"/>'
    if selected:
        body += dot(50, y + 32, 5)
    body += text(76, y + 27, name, 15, weight=600 if selected else 400)
    body += text(76, y + 51, detail, 12, GREEN if selected else MUTED)
    out = control(body, "RadioButton ListItem", "选择此配置以查看和设置；不会自动切换正在运行的 VPN")
    menu = rect(334, y + 8, 48, 48, "transparent", 24) + icon("more", 348, y + 20, size=24)
    return out + control(menu, "IconButton", "原生菜单：连接 / 重命名 / 删除；改名和删除用 AlertDialog，运行中的配置先断开")


def configuration():
    out = header("配置", "设备已加入 · 配置签名已验证")
    out += rect(22, 178, 368, 252)
    out += text(38, 209, "连接配置", 17, weight=700)
    add = rect(292, 176, 96, 48, "transparent", 24)
    add += icon("plus", 308, 191, OUTLINE_TEXT, 18) + text(350, 206, "添加", 13, OUTLINE_TEXT, 500, "middle")
    out += control(add, "TextButton", "原生底部面板选择扫码或导入文件；保存新配置后保持未连接")
    out += profile_row(228, "个人网络", "demo-home · 已连接", True)
    out += profile_row(300, "办公网络", "demo-work · 未连接", False)
    out += line(373)
    out += text(38, 403, "Device demo-device-a", 12, MUTED)
    out += text_button(276, 375, 98, "检查更新", "只检查所选配置的签名更新")
    out += text(22, 456, "已选择：个人网络 · 切换查看不会改变连接", 12, MUTED)

    out += rect(22, 478, 368, 164)
    out += text(38, 508, "流量模式", 17, weight=700)
    for i, label in enumerate(("Direct", "Auto", "指定出口")):
        width = (336 - 16) / 3
        out += button(38 + i * (width + 8), 529, width, label, filled=i == 1, small_radius=True,
                      hint="选择已授权出口后才提交模式" if i == 2 else f"为所选配置设置 {label} 模式")
    out += text(38, 606, "Auto · 使用已授权规则自动选择路径", 12, MUTED)
    out += text(22, 674, "每份配置分别保存身份、配置与连接模式。", 12, MUTED)
    out += text(22, 697, "同一时间只运行一个连接。", 12, MUTED)
    return out + navigation("configuration")


def diagnostics():
    out = header("诊断", "网络证据、可信上报与本机组件")
    out += rect(22, 178, 368, 380)
    out += text(38, 209, "网络诊断", 17, weight=700)
    out += text(38, 239, "个人网络 · demo-home", 12, MUTED)
    out += paragraph(38, 275, ["业务 DNS/HTTPS（不作为激活门禁）", "未测量 / 未测量", "可信上报：已提交", "服务器观测：部分可用"], 13, INK, 27)
    out += line(378)
    out += text(38, 407, "信任边界", 12, MUTED, 700)
    out += paragraph(38, 438, ["libbox · core 已加载", "Keystore 不可导出 P-256"], 13, INK, 27)
    out += paragraph(38, 499, ["每个底层网络代只测量授权入口一次；", "入口之后复用可信服务器观测，", "不探测完整业务路径。"], 11, MUTED, 19)
    return out + navigation("diagnostics")


def document(key, label, content):
    source = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
              f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-labelledby="title desc">'
              f'<title id="title">Loom Android · {label} Tab 原型</title>'
              '<desc id="desc">基于当前已安装 Android 客户端的连接、配置、诊断界面，'
              '保留原生 Material 3 卡片、按钮与底部导航。补充当前选路详情和多配置。'
              '每个文件只有一个 Tab 界面；全部身份、时间、路径和指标均为演示数据。'
              '本图是目标原型，不能作为原生功能已实现的证据。</desc>'
              f'<defs>{brand()}</defs>{rect(0, 0, WIDTH, HEIGHT, PAPER, 0)}'
              f'<g id="screen-{key}" font-family="{FONT}">{content}</g></svg>')
    root = ET.fromstring(source)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for (key, label, _), draw in zip(TABS, (connection, configuration, diagnostics)):
        path = OUTPUT / f"{key}.svg"
        path.write_text(document(key, label, draw()), encoding="utf-8")
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
