#!/usr/bin/env python3
"""按 design.md §7.2 / §7.3 将 Windows 实际界面绘为 Android 单张流程稿。"""

from html import escape
from pathlib import Path
import argparse
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
INK, MUTED, GREEN = "#1B211D", "#68736C", "#239B68"
PAPER, LINE, TINT = "#FCFCFB", "#E1E6E2", "#EAF5EE"
RED, AMBER = "#B0443D", "#906322"
WIDTH, HEIGHT = 390, 900
FONT = "'Noto Sans CJK SC','Microsoft YaHei UI',sans-serif"


def text(x, y, value, size=14, color=INK, weight=400, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{escape(value)}</text>')


def rect(x, y, w, h, fill="white", radius=12, stroke=LINE):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
            f'fill="{fill}" stroke="{stroke}"/>')


def line(x, y, w, color=LINE):
    return f'<path d="M{x} {y}h{w}" stroke="{color}"/>'


def dot(x, y, r=4, color=GREEN):
    return f'<circle cx="{x}" cy="{y}" r="{r}" fill="{color}"/>'


def para(x, y, lines, size=13, color=MUTED, leading=22):
    return "".join(text(x, y + leading * i, item, size, color) for i, item in enumerate(lines))


def icon(name, x, y, size=22, color=MUTED):
    paths = {
        "check": '<path d="m5 12 4 4L19 6"/>',
        "phone": '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 18h4"/>',
        "server": '<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.1M8 17.5h.1M12 6.5h4M12 17.5h4"/>',
        "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18M12 3c-5 5-5 13 0 18"/>',
        "plus": '<path d="M12 5v14M5 12h14"/>',
        "back": '<path d="m14 5-7 7 7 7"/>',
        "down": '<path d="m6 9 6 6 6-6"/>',
        "up": '<path d="m6 15 6-6 6 6"/>',
        "edit": '<path d="m5 15 10-10 4 4L9 19l-5 1Z"/>',
        "scan": '<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5M7 12h10"/>',
        "file": '<path d="M14 3H5v18h14V8Zm0 0v5h5M8 12h8M8 16h5"/>',
        "error": '<circle cx="12" cy="12" r="9"/><path d="M12 6v7M12 17h.01"/>',
        "power": '<path d="M12 3v9M7 5.5a8 8 0 1 0 10 0"/>',
        "progress": '<path d="M12 3a9 9 0 1 1-9 9"/><path d="M12 3H7M12 3v5"/>',
    }
    return (f'<g transform="translate({x},{y}) scale({size / 24})" fill="none" '
            f'stroke="{color}" stroke-width="1.6" stroke-linecap="round" '
            f'stroke-linejoin="round">{paths[name]}</g>')


def button(x, y, w, label, primary=False, danger=False, disabled=False, size=14):
    fill = "#F0F2F0" if disabled else RED if danger and primary else GREEN if primary else "white"
    color = "#929B95" if disabled else "white" if primary else RED if danger else INK
    return (rect(x, y, w, 48, fill, 8, fill if primary else LINE)
            + text(x + w / 2, y + 30, label, size, color, 500, "middle"))


def badge(x, y, label, color=GREEN, fill=TINT, w=68):
    return rect(x, y, w, 24, fill, 6, "none") + text(x + w / 2, y + 17, label, 11, color, 500, "middle")


def phone(content, back=None):
    out = rect(0.5, 0.5, WIDTH - 1, HEIGHT - 1, PAPER, 24, "#CCD5CE")
    out += text(22, 24, "9:41", 12, weight=600)
    out += '<path d="M322 23v-4m5 4v-7m5 7V13" stroke="#1B211D" stroke-width="2.5"/>'
    out += rect(345, 13, 21, 11, "none", 3, INK) + rect(347, 15, 15, 7, INK, 1, "none")
    out += '<path d="M368 16v5" stroke="#1B211D" stroke-width="2"/>'
    if back:
        out += icon("back", 19, 52, 24, INK) + text(55, 72, back, 20, weight=600)
    else:
        out += '<use href="#brand" x="20" y="45" width="38" height="38"/>'
        out += text(70, 70, "Loom", 24, weight=650) + text(71, 91, "你的连接配置", 11, MUTED)
    out += line(20, 103, 350)
    out += f'<g data-content="true">{content}</g>'
    out += rect(144, 885, 102, 4, "#C4CBC6", 2, "none")
    return out


def profiles(selected="demo-work", rename=False):
    out = text(20, 133, "连接配置", 13, MUTED, 600)
    out += rect(322, 104, 48, 48, "#F0F3F0", 8, "none") + icon("plus", 335, 117, 22, INK)
    for i, name in enumerate(("demo-work", "demo-personal")):
        y = 154 + i * 52
        chosen = name == selected
        if chosen:
            out += rect(20, y, 350, 52, TINT, 0, "none")
            out += rect(20, y, 3, 52, GREEN, 0, "none")
        if rename and i == 1:
            out += rect(48, y + 6, 265, 40, "white", 5, GREEN)
            out += text(60, y + 32, "demo-home", 15)
            out += '<path d="M147 213v24" stroke="#239B68"/>'
        else:
            out += text(48, y + 23, name, 15, weight=600 if chosen else 400)
            out += text(48, y + 43, "已连接" if i == 0 else "未连接", 11, GREEN if i == 0 else MUTED)
        out += dot(35, y + 19, 3.5, GREEN if i == 0 else "#A4ADA6")
        if chosen and not rename:
            out += icon("edit", 334, y + 15, 20)
    return out


def heading(y, name="demo-work", deletable=False):
    return text(20, y + 29, name, 22, weight=650) + button(298, y, 72, "删除", disabled=not deletable, danger=deletable, size=12)


def status(y, state="已连接", device="demo-device-a", action="断开", note="VPN 已启用", color=GREEN):
    kind = "check" if state == "已连接" else "error" if state == "连接失败" else "progress" if state == "连接中" else "power"
    out = rect(20, y, 350, 118)
    out += dot(52, y + 34, 19, TINT if state == "已连接" else "#F2F4F2")
    out += icon(kind, 40, y + 22, 24, color)
    out += text(83, y + 43, state, 22, color if state == "连接失败" else INK, 500)
    out += text(84, y + 67, note, 12, color)
    out += button(264, y + 20, 90, action, primary=state != "已连接", size=13)
    out += line(36, y + 84, 318)
    out += text(36, y + 105, f"Device  {device}", 11, MUTED)
    return out


def modes(y, selected="自动", note="按服务自动选择路径", pending=False):
    out = text(20, y, "路由模式", 13, weight=600)
    out += rect(20, y + 14, 350, 48, "#F0F3F0", 8)
    labels = ("直连", "自动", "固定出口")
    for i, name in enumerate(labels):
        x = 23 + i * 115
        if name == selected:
            out += rect(x, y + 17, 114, 42, "white", 6, "#DCE5DE")
        out += text(x + 57, y + 45, name, 14, GREEN if name == selected else MUTED, 600 if name == selected else 400, "middle")
    out += text(20, y + 84, note, 12, AMBER if pending else MUTED)
    return out


def route(y, service="demo-web", second=False, direct=False, fixed=False):
    out = rect(20, y, 350, 120)
    out += text(36, y + 27, "统一上网路径" if fixed else "本机直连" if direct else service, 14, weight=600)
    names = ("本机", "目标地址") if direct else ("本机", "demo-b" if second else "demo-a", "demo-exit", "目标地址")
    xs = (61, 327) if direct else (51, 147, 243, 339)
    kinds = ("phone", "globe") if direct else ("phone", "server", "server", "globe")
    metrics = ("直连 · 未测量",) if direct else ("ping 12 ms", "170 ms" if second else "38 ms", "—" if second else "57 ms")
    for i, value in enumerate(metrics):
        color = "#C5CDC7" if value == "—" or direct else "#B1D3BF"
        out += line(xs[i] + 15, y + 66, xs[i + 1] - xs[i] - 30, color)
        out += text((xs[i] + xs[i + 1]) / 2, y + 49, value, 10.5, MUTED, anchor="middle")
    for x, name, kind in zip(xs, names, kinds):
        out += dot(x, y + 66, 15, "#F4F7F4")
        out += icon(kind, x - 9, y + 57, 18)
        out += text(x, y + 99, name, 11, anchor="middle")
    return out


def paths_title(y, expanded=False, disabled=False):
    return text(20, y, "当前选路", 16, weight=600) + button(274, y - 30, 96, "收起详情" if expanded else "详细信息", disabled=disabled, size=12)


def home():
    out = profiles() + heading(266) + status(318)
    out += modes(463)
    out += paths_title(579) + route(603) + route(735, "demo-api", second=True)
    return phone(out)


def other_profile():
    out = profiles("demo-personal")
    out += rect(20, 272, 350, 38, TINT, 8, "none")
    out += dot(35, 291, 3) + text(48, 297, "当前连接：demo-work", 12, GREEN)
    out += heading(322, "demo-personal", True)
    out += status(374, "未连接", "demo-device-b", "切换连接", "已保存配置", MUTED)
    out += modes(520, note="此配置的偏好 · 下次连接使用")
    out += paths_title(637, disabled=True)
    out += rect(20, 661, 350, 146)
    out += icon("phone", 41, 686, 28) + text(84, 707, "此配置尚未连接", 16, weight=500)
    out += para(36, 747, ["连接后显示这份配置的实际路径。", "切换连接会先断开 demo-work。"])
    return phone(out)


def field(y, title, value, placeholder=False):
    return (text(36, y, title, 13, MUTED)
            + rect(36, y + 14, 318, 50, "white", 7, "#CAD5CD")
            + text(50, y + 46, value, 15, MUTED if placeholder else INK))


def add_profile(pending=False):
    out = rect(20, 121, 350, 42, TINT, 8, "none")
    out += dot(35, 142, 3) + text(48, 148, "demo-work 继续保持连接", 12, GREEN)
    out += text(20, 202, "继续加入" if pending else "添加配置", 25, weight=650)
    out += text(20, 228, "使用管理员提供的加入邀请", 13, MUTED)
    out += rect(20, 253, 350, 534 if pending else 566)
    out += field(284, "配置名称", "demo-new")
    out += text(36, 380, "加入邀请", 13, MUTED)
    if pending:
        out += badge(36, 401, "等待继续", AMBER, "#FBF2E5", 80)
        out += para(36, 457, ["暂时无法完成加入。", "已保留这次加入的信息。"], 15, INK, 27)
        out += para(36, 530, ["继续时会使用同一份邀请和身份。", "关闭页面后，也可以稍后再试。"])
        out += button(36, 620, 318, "继续加入", primary=True)
        out += button(36, 684, 318, "稍后继续")
        out += text(36, 763, "需要恢复邀请时，请联系管理员。", 12, MUTED)
    else:
        out += button(36, 399, 151, "扫码") + icon("scan", 51, 413, 19)
        out += button(203, 399, 151, "导入文件")
        out += button(36, 457, 318, "从剪贴板粘贴")
        out += text(36, 531, "支持二维码图片与 .loom-invite 文件", 12, MUTED)
        out += line(36, 554, 318) + badge(36, 572, "已验证")
        out += text(36, 624, "demo-invite.loom-invite", 15, weight=500)
        out += text(36, 650, "Device  demo-device-new", 12, MUTED)
        out += para(36, 690, ["保存后保持未连接。", "点击连接按钮，才会接管流量。"], 12)
        out += button(36, 740, 204, "加入并保存", primary=True)
        out += button(252, 740, 102, "取消")
    return phone(out, "返回连接")


def fixed_exit():
    out = text(20, 140, "demo-work", 22, weight=650) + badge(286, 120, "已连接", w=84)
    out += modes(182, note="当前生效：自动 · 正在选择固定出口", pending=True)
    out += rect(20, 286, 350, 275)
    out += text(36, 318, "选择出口", 16, weight=600)
    out += text(36, 343, "仅显示这份配置允许使用的出口", 12, MUTED)
    for i, name in enumerate(("demo-exit", "demo-backup")):
        y = 361 + i * 58
        out += rect(36, y, 318, 50, TINT if i == 0 else "white", 7, "none")
        out += f'<circle cx="54" cy="{y + 25}" r="8" fill="white" stroke="{GREEN if i == 0 else LINE}" stroke-width="1.5"/>'
        if i == 0:
            out += dot(54, y + 25, 4)
        out += text(75, y + 31, name, 15)
    out += button(36, 492, 204, "使用此出口", primary=True) + button(252, 492, 102, "取消")
    out += paths_title(606) + route(630)
    out += para(20, 791, ["确认前，继续使用当前自动路径。", "固定出口只指定最后一跳。"], 13)
    return phone(out)


def details():
    out = text(20, 140, "demo-work", 22, weight=650) + badge(286, 120, "已连接", w=84)
    out += paths_title(190, True)
    out += rect(20, 218, 350, 639)
    out += text(36, 248, "demo-web", 16, weight=600)
    out += text(36, 272, "当前实际路径", 12, MUTED)
    out += para(36, 301, ["本机 → demo-a → demo-exit", "→ demo.example"], 13, INK, 23)
    out += line(36, 344, 318)
    sections = (
        (373, "本机 → demo-a", "12 ms", "入口 · 当前网络的一次 ping", "03:04:05 UTC"),
        (479, "demo-a → demo-exit", "38 ms", "Hysteria2 · 服务器签名观测", "03:04:06 UTC · Δ 3 ms · 6.4 Mb/s"),
        (585, "demo-exit → demo.example", "57 ms", "目标首次响应 · 出口服务器观测", "03:04:07 UTC"),
    )
    for y, title, metric, source, timestamp in sections:
        out += text(36, y, title, 13, weight=500) + text(354, y, metric, 14, anchor="end")
        out += text(36, y + 27, source, 12, MUTED)
        out += text(36, y + 50, timestamp, 11, MUTED)
        out += line(36, y + 73, 318)
    out += text(36, 694, "选路说明", 14, weight=600)
    out += para(36, 721, ["根据入口与服务器观测选择当前路径。", "各段指标不代表整条路径的实测质量。"], 12)
    out += para(36, 779, ["读取时间  03:04:08 UTC", "决策范围  demo-scope", "观测日期  2026-01-02"], 11, MUTED, 23)
    return phone(out)


def fixed_active():
    out = profiles() + heading(266) + status(318)
    out += modes(463, "固定出口", "当前出口：demo-exit")
    out += paths_title(579) + route(603, fixed=True)
    out += para(20, 767, ["受管上网流量共用这条实际路径。", "前面的服务器仍由客户端自动选择。", "已有连接可能继续沿用原路径。"], 13)
    return phone(out)


def rename():
    out = profiles("demo-personal", rename=True)
    out += button(48, 266, 146, "保存名称", primary=True) + button(206, 266, 148, "取消")
    out += text(48, 343, "名称只在本机显示，最长 64 个字符。", 12, MUTED)
    out += text(48, 366, "不改变身份，也不会重启连接。", 12, MUTED)
    out += line(20, 392, 350)
    out += heading(410, "demo-personal", True)
    out += status(462, "未连接", "demo-device-b", "切换连接", "已保存配置", MUTED)
    out += modes(608, note="此配置的偏好 · 下次连接使用")
    out += rect(20, 735, 350, 75, TINT, 8, "none")
    out += dot(36, 758, 3) + text(48, 763, "当前连接：demo-work", 13, GREEN)
    out += text(48, 789, "改名不影响当前流量。", 12, MUTED)
    return phone(out)


def delete():
    out = profiles("demo-personal") + heading(266, "demo-personal", True)
    out += rect(20, 328, 350, 322)
    out += text(36, 366, "删除 demo-personal？", 19, weight=600)
    out += text(36, 396, "Device  demo-device-b · 未连接", 12, MUTED)
    out += para(36, 445, ["将移除此配置在本机的身份和数据。", "再次加入需要新的邀请。"], 14, INK, 27)
    out += para(36, 520, ["不会撤销中控里的 Device。", "demo-work 的连接不受影响。"], 12)
    out += button(36, 580, 151, "取消") + button(203, 580, 151, "删除配置", primary=True, danger=True)
    return phone(out)


SCREENS = (
    ("main", "主界面", "Windows 配置列表移到上方；下方保留状态、模式与路径。", home),
    ("select", "点选另一份配置", "只切换查看；“切换连接”才会启动所选配置。", other_profile),
    ("add", "点击 ＋ 添加配置", "扫码、导入或粘贴邀请；加入后保持未连接。", add_profile),
    ("fixed", "点击固定出口", "先选授权出口，再确认；取消仍保留自动模式。", fixed_exit),
    ("details", "展开详细信息", "主界面向下滚动；在原位置展开逐段来源与时间。", details),
    ("fixed-active", "固定出口已生效", "当前选路变为一条统一上网路径，不保留旧服务路径。", fixed_active),
    ("rename", "点名称旁的编辑图标", "列表原位改名，保存或取消，不影响活动连接。", rename),
    ("delete", "点击删除", "具名确认，只删除未运行配置的本机身份与数据。", delete),
    ("resume", "加入尚未完成", "稍后继续保留原事务；再次打开恢复同一份身份。", lambda: add_profile(True)),
)


def definitions():
    # §7.2：直接复用 Windows 的大尺寸品牌源，不另画一套 Android 品牌。
    logo = ET.parse(ROOT / "assets/loom-logo-v4.svg").getroot()
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    body = "".join(ET.tostring(child, encoding="unicode") for child in logo)
    body = re.sub(r'\bid="([^"]+)"', lambda m: f'id="brand-{m[1]}"', body)
    body = re.sub(r'url\(#([^)]*)\)', lambda m: f'url(#brand-{m[1]})', body)
    return f'<defs><symbol id="brand" viewBox="{logo.get("viewBox")}">{body}</symbol></defs>'


def document(content, width, height, title):
    source = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">\n'
            f'<title id="title">{escape(title)}</title>\n'
            '<desc id="desc">以仓库 Windows 当前界面与功能实现为依据的 Android 目标原型。'
            '所有身份、路径、时间和指标均为合成示例，不代表原生实现或部署状态。</desc>\n'
              f'{definitions()}\n<g font-family="{FONT}">{content}</g>\n</svg>\n')
    root = ET.fromstring(source)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def state_tile(x, y, label, note, action, state="", color=MUTED):
    out = rect(x, y, 390, 186)
    kind = "error" if state == "error" else "progress" if state == "busy" else "power"
    out += icon(kind, x + 20, y + 22, 24, color)
    out += text(x + 58, y + 43, label, 20, weight=600)
    out += text(x + 20, y + 82, note, 13, MUTED)
    out += button(x + 20, y + 114, 350, action, disabled=state == "disabled", primary=state == "error")
    return out


def storyboard():
    width, height = 1338, 3930
    out = rect(0, 0, width, height, "#F0F3F0", 0, "none")
    out += text(48, 58, "LOOM  /  ANDROID", 14, GREEN, 600)
    out += text(48, 109, "从 Windows 的功能界面，重新排到手机上。", 32, weight=650)
    out += text(48, 147, "配置列表 → 所选配置 → 连接状态 → 路由模式 → 当前选路", 16, MUTED)
    out += text(48, 179, "单页主界面 · 操作状态连续展示 · 全部为演示数据 · 原生界面尚待实现", 13, MUTED)
    for index, (key, title, caption, draw) in enumerate(SCREENS):
        x = 48 + (index % 3) * 426
        y = 250 + (index // 3) * 1024
        out += text(x, y - 24, f"{index + 1:02d}  {title}", 18, weight=600)
        out += f'<g id="screen-{key}" transform="translate({x},{y})">{draw()}</g>'
        # 长说明分成两行，保持手机绘图区与评审标注各自独立。
        split = caption.find("；") + 1 if "；" in caption else caption.find("，") + 1
        lines = [caption[:split], caption[split:]] if split > 0 else [caption]
        out += para(x, y + 933, lines, 13, MUTED, 22)
    y = 3320
    out += text(48, y, "同一张连接卡片随实际状态变化", 22, weight=600)
    out += text(48, y + 31, "连接中可以取消；停止完成前不能启动另一份配置；失败后清除旧路径。", 14, MUTED)
    out += state_tile(48, y + 57, "连接中", "demo-personal · 正在建立 VPN", "取消连接", "busy", GREEN)
    out += state_tile(474, y + 57, "断开中", "demo-work · 等待连接完全停止", "正在断开…", "disabled")
    out += state_tile(900, y + 57, "连接失败", "demo-personal · 未获系统 VPN 授权", "重试连接", "error", RED)
    out += rect(48, 3597, 390, 214)
    out += text(68, 3634, "直连已生效", 20, weight=600)
    out += '<g transform="translate(48,3030)">' + route(620, direct=True) + '</g>'
    out += state_tile(474, 3597, "还没有连接配置", "使用管理员提供的邀请加入网络。", "添加配置")
    out += state_tile(900, 3597, "设备已停用", "此身份已被管理员停用，无法连接。", "无法连接", "disabled", RED)
    out += text(48, 3859, "观测未知时显示 —，不追加探测。所有示例时间、身份、连线数值均为合成数据。", 14, MUTED)
    out += text(48, 3896, "依据：Windows 当前截图及配置、路由与详情代码。模式与路径语义遵循 design.md §7.2 / §7.3。", 12, MUTED)
    return document(out, width, height, "Loom Android · 参照 Windows 功能界面重做")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview-dir", type=Path, help="额外导出单屏 SVG 到指定临时目录供人工检查")
    args = parser.parse_args()
    output = ROOT / "assets/client/android/loom-android.svg"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(storyboard(), encoding="utf-8")
    if args.preview_dir:
        args.preview_dir.mkdir(parents=True, exist_ok=True)
        for key, title, _, draw in SCREENS:
            (args.preview_dir / f"{key}.svg").write_text(document(draw(), WIDTH, HEIGHT, title), encoding="utf-8")
    print(output.relative_to(ROOT))


if __name__ == "__main__":
    main()
