#!/usr/bin/env python3
"""按 design.md §7.3 生成 Android 三页及页内交互原型；所有身份均为示例。"""

from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets/client/android"
INK = "#17211B"
MUTED = "#647269"
GREEN = "#239B68"
LINE = "#E3E8E5"


def text(x, y, value, size=13, color=INK, weight=400, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{escape(value)}</text>')


def rect(x, y, width, height, fill="white", radius=16, stroke=LINE):
    return (f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}" stroke="{stroke}"/>')


def button(x, y, width, label, primary=False, disabled=False):
    fill = "#E8EDE9" if disabled else GREEN if primary else "white"
    color = "#829086" if disabled else "white" if primary else INK
    stroke = "#E8EDE9" if disabled else GREEN if primary else "#AEBBB2"
    return rect(x, y, width, 48, fill, 12, stroke) + text(x + width / 2, y + 29, label, 14, color, 600, "middle")


def rule(x, y, width):
    return f'<path d="M{x} {y}h{width}" stroke="{LINE}"/>'


def icon(kind, x, y, color=MUTED):
    paths = {
        "连接": '<path d="M12 2v9M6.2 5.8a8.5 8.5 0 1 0 11.6 0"/>',
        "路由": '<path d="m6 17 6-11 6 11"/><g fill="white"><circle cx="6" cy="17" r="2.5"/><circle cx="12" cy="6" r="2.5"/><circle cx="18" cy="17" r="2.5"/></g>',
        "设置": '<path d="M4 6h16M4 12h16M4 18h16"/><g fill="white"><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/></g>',
    }
    return (f'<g transform="translate({x},{y})" fill="none" stroke="{color}" '
            f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{paths[kind]}</g>')


def phone(x, selected, subtitle, content, profile="demo-home"):
    result = f'<g transform="translate({x},166)">'
    result += rect(0, 0, 360, 780, "#FCFCFB", 28, "#CBD3CD")
    result += '<use href="#loom-mark" x="22" y="26" width="32" height="32"/>'
    result += text(63, 44, "LOOM", 18, weight=900) + text(63, 59, "ANDROID", 9, MUTED)
    result += rect(184, 18, 154, 48, "white", 12)
    result += text(200, 47, profile, 13, weight=600) + text(318, 46, "›", 16, MUTED, anchor="middle")
    result += text(22, 104, selected, 26, weight=700) + text(22, 130, subtitle, 13, MUTED)
    result += content
    result += '<path d="M1 704h358v48q0 27-27 27H28Q1 779 1 752Z" fill="white"/>' + rule(1, 704, 358)
    for index, label in enumerate(("连接", "路由", "设置")):
        center = 60 + index * 120
        color = GREEN if label == selected else MUTED
        if label == selected:
            result += rect(center - 31, 714, 62, 30, "#EAF6F0", 15, "none")
        result += icon(label, center - 12, 717, color)
        result += text(center, 763, label, 12, color, 600 if label == selected else 400, "middle")
    return result + '</g>'


def connection_card(joined=True):
    result = rect(22, 154, 316, 162, "#F1F5F2", 20, "none")
    result += f'<circle cx="45" cy="187" r="5.5" fill="{GREEN if joined else "#98A29B"}"/>'
    result += text(59, 195, "已连接" if joined else "未连接", 20, weight=700)
    result += text(40, 224, "Loom VPN 正在运行" if joined else "加入网络后，即可连接 Loom VPN。", 13, MUTED)
    result += button(40, 250, 280, "断开" if joined else "请先加入网络", True, not joined)
    return result


def mode_card(y=332, choosing=False, joined=True):
    result = rect(22, y, 316, 326 if choosing else 164)
    result += text(38, y + 30, "连接模式", 17, weight=700)
    for index, label in enumerate(("Direct", "Auto", "指定出口")):
        result += button(38 + index * (292 / 3), y + 48, 268 / 3, label, index == 1, not joined)
    result += text(38, y + 121, "按已下发规则自动选择各服务的路径。" if joined else "加入网络后可选择连接模式", 12, MUTED)
    if joined:
        result += text(38, y + 144, "Auto · 已生效", 12, GREEN)
    if choosing:
        result += rect(38, y + 157, 284, 151, "#F1F5F2", 12, "none")
        result += text(50, y + 180, "选择已授权出口", 13, weight=700)
        result += text(50, y + 201, "选择后应用于新连接", 11, MUTED)
        result += button(50, y + 213, 260, "demo-exit")
        result += text(180, y + 290, "取消选择", 13, GREEN, 600, "middle")
    return result


def paths_card():
    result = rect(22, 154, 316, 226)
    result += text(38, 184, "当前路径", 17, weight=700)
    result += rect(249, 166, 73, 25, "#EAF6F0", 13, "none") + text(285.5, 183, "当前连接", 11, GREEN, 600, "middle")
    result += rule(38, 204, 284)
    result += text(38, 232, "网页浏览、即时通讯等 3 项", 14, weight=700)
    result += text(38, 258, "本机 → demo-entry → demo-exit", 13)
    result += text(38, 280, "→ 目标地址", 13)
    result += text(38, 304, "分段观测见逐项详情", 12, MUTED)
    result += button(38, 316, 284, "查看 3 项详情")
    return result


def network_card():
    result = rect(22, 396, 316, 264)
    result += text(38, 426, "网络状态", 17, weight=700)
    for index, (label, value) in enumerate((("DNS", "—"), ("HTTPS", "—"), ("可信上报", "已接收 · 示例状态"), ("服务器观测", "尚未读取"))):
        y = 461 + 40 * index
        result += text(38, y, label, 12, MUTED) + text(322, y, value, 12, INK, anchor="end")
        if index < 3:
            result += rule(38, y + 15, 284)
    result += text(38, 622, "分段数据用于说明选路，", 12, MUTED)
    result += text(38, 642, "缺失时显示未知。", 12, MUTED)
    return result


def profile_list(viewed="demo-home"):
    result = rect(22, 154, 316, 230)
    result += text(38, 184, "连接配置", 17, weight=700)
    result += text(322, 184, "+ 添加", 13, GREEN, 600, "end")
    for index, name in enumerate(("demo-home", "demo-work")):
        y = 204 + index * 70
        if name == viewed:
            result += rect(34, y, 292, 62, "#F1F5F2", 10, "none")
        result += text(46, y + 24, name, 14, weight=600)
        result += text(46, y + 47, "已连接" if index == 0 else "未连接", 12, GREEN if index == 0 else MUTED)
        result += text(310, y + 35, "当前查看" if name == viewed else "查看", 12, MUTED, anchor="end")
    result += text(38, 368, "选择配置仅切换查看", 11, MUTED)
    return result


def settings_cards():
    result = profile_list()
    result += rect(22, 400, 316, 138)
    result += text(38, 430, "demo-home", 17, weight=700)
    result += text(38, 454, "已加入 · 当前配置已验证", 12, GREEN)
    result += button(38, 473, 284, "检查更新")
    result += rect(22, 554, 316, 60)
    result += text(38, 590, "连接通知", 15, weight=600)
    result += text(322, 590, "已允许 ›", 12, MUTED, anchor="end")
    result += rect(22, 630, 316, 60)
    result += text(38, 666, "关于此设备", 15, weight=600)
    result += text(322, 666, "版本与密钥 ›", 12, MUTED, anchor="end")
    return result


def add_profile():
    result = rect(22, 154, 316, 418)
    result += text(38, 184, "添加连接", 17, weight=700)
    result += text(38, 219, "连接名称", 12, MUTED)
    result += rect(38, 232, 284, 48, "white", 10, "#AEBBB2")
    result += text(50, 261, "demo-new", 14)
    result += text(38, 311, "邀请", 12, MUTED)
    result += text(38, 337, "尚未选择邀请", 13, MUTED)
    result += button(38, 355, 138, "扫描二维码")
    result += button(184, 355, 138, "导入文件")
    result += button(38, 419, 284, "加入并保存", True, True)
    result += text(180, 501, "取消", 14, GREEN, 600, "middle")
    result += text(38, 541, "加入成功后可在列表中选择此连接。", 12, MUTED)
    result += text(22, 606, "demo-home 正在连接", 13, GREEN)
    result += text(22, 630, "添加配置不会中断当前连接。", 12, MUTED)
    return result


def rename_profile():
    result = profile_list("demo-work")
    result += rect(22, 400, 316, 280)
    result += text(38, 430, "管理 demo-work", 17, weight=700)
    result += text(38, 460, "连接名称", 12, MUTED)
    result += rect(38, 475, 284, 48, "white", 10, "#AEBBB2")
    result += text(50, 504, "demo-office", 14)
    result += button(38, 539, 138, "保存名称", True)
    result += button(184, 539, 138, "取消")
    result += rule(38, 603, 284)
    result += text(38, 635, "删除此配置", 14, "#A33636", 600)
    result += text(38, 661, "仅管理此份本机连接配置", 12, MUTED)
    return result


def switch_profile():
    result = rect(22, 154, 316, 68, "#F1F5F2")
    result += text(38, 182, "demo-home 正在连接", 14, GREEN, 600)
    result += text(38, 205, "当前查看 demo-work", 12, MUTED)
    result += rect(22, 238, 316, 154, "#F1F5F2", 20, "none")
    result += text(40, 272, "未连接", 20, weight=700)
    result += text(40, 300, "先断开 demo-home，再连接此配置。", 12, MUTED)
    result += button(40, 326, 280, "切换并连接", True)
    result += mode_card(y=408).replace("Auto · 已生效", "Auto · 下次连接使用")
    result += button(22, 590, 316, "查看当前配置的路径")
    return result


def delete_profile():
    result = profile_list("demo-work")
    result += rect(22, 400, 316, 268, "#FFF7E8", 16, "#E7D8BB")
    result += text(38, 432, "删除 demo-work？", 17, weight=700)
    result += text(38, 469, "将移除此配置的本机身份与配置数据。", 12)
    result += text(38, 494, "不会撤销中控中的设备。", 12)
    result += text(38, 519, "demo-home 的连接不受影响。", 12)
    result += button(38, 544, 284, "继续保留")
    result += text(180, 632, "确认删除", 14, "#A33636", 600, "middle")
    return result


def route_detail():
    result = rect(22, 154, 316, 528)
    result += text(38, 184, "当前路径", 17, weight=700)
    result += text(38, 213, "逐项详情 · 1 / 3", 12, MUTED)
    result += text(38, 243, "网页浏览", 15, weight=700)
    labels = (("本机", "入口测量 · —"), ("demo-entry", "服务器分段观测 · —"), ("demo-exit", "出口目标观测 · —"), ("目标地址", ""))
    for index, (label, detail) in enumerate(labels):
        y = 274 + index * 54
        if index < 3:
            result += f'<path d="M48 {y}v54" stroke="#B9CEBF"/>'
        result += f'<circle cx="48" cy="{y}" r="4" fill="white" stroke="#77AB8B" stroke-width="2"/>'
        result += text(66, y + 5, label, 13)
        if detail:
            result += text(66, y + 26, detail, 11, MUTED)
    result += rule(38, 460, 284)
    result += text(38, 484, "实际候选", 11, MUTED) + text(38, 507, "demo-candidate", 13)
    result += text(38, 534, "选路说明", 11, MUTED)
    result += text(38, 556, "当前使用已授权路径；", 12)
    result += text(38, 576, "分段数据尚未读取。", 12)
    result += text(38, 603, "决策时间 · —", 11, MUTED)
    for index, label in enumerate(("上一项", "收起", "下一项")):
        result += button(38 + index * (292 / 3), 618, 268 / 3, label, disabled=index == 0)
    return result


def board(filename, title, subtitle, screens):
    # §7.3：共享现有完整版标志，不复制另一套近似图形。
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    logo = ET.parse(ROOT / "assets/loom-logo-transparent-titanium.svg").getroot()
    group = ET.tostring(logo.find("{http://www.w3.org/2000/svg}g"), encoding="unicode")
    result = '<?xml version="1.0" encoding="UTF-8"?>\n'
    result += '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="1040" viewBox="0 0 1280 1040" role="img" aria-labelledby="title description">\n'
    result += f'<title id="title">{escape(title)}</title><desc id="description">{escape(subtitle)} 全部身份及状态均为示例，不对应实际部署。</desc>\n'
    result += '<defs><symbol id="loom-mark" viewBox="127 112 1000 1000">' + group + '</symbol></defs>\n'
    result += '<style>text { font-family: "Noto Sans CJK SC", "Microsoft YaHei", system-ui, sans-serif; }</style>\n'
    result += rect(0, 0, 1280, 1040, "#EEF1EE", 0, "none")
    result += text(48, 42, "LOOM / ANDROID", 11, GREEN, 700)
    result += text(48, 81, title, 28, weight=700)
    result += text(48, 110, subtitle, 14, MUTED)
    result += text(1232, 42, "MISAKA · 多配置目标设计 · 演示数据", 11, MUTED, anchor="end")
    for index, (tab, page_subtitle, content, caption, notes, profile) in enumerate(screens):
        x = 48 + index * 412
        result += text(x, 148, caption, 12, GREEN, 600)
        result += phone(x, tab, page_subtitle, content, profile)
        for line, note in enumerate(notes):
            result += text(x, 978 + line * 22, note, 12, MUTED)
    result += '</svg>\n'
    ET.fromstring(result)
    (OUTPUT / filename).write_text(result.replace("><", ">\n<"), encoding="utf-8")


def layout_board():
    result = '<?xml version="1.0" encoding="UTF-8"?>\n'
    result += '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="730" viewBox="0 0 1280 730" role="img" aria-labelledby="title description">'
    result += '<title id="title">Android 三态按钮窄屏与大字体排版</title>'
    result += '<desc id="description">常规字号横排，宽度不足或字号放大时整组纵排。指定出口保持完整单行，不缩字、不截断。所有尺寸均为设计示意。</desc>'
    result += '<style>text { font-family: "Noto Sans CJK SC", "Microsoft YaHei", system-ui, sans-serif; }</style>'
    result += rect(0, 0, 1280, 730, "#EEF1EE", 0, "none")
    result += text(48, 42, "LOOM / ANDROID", 11, GREEN, 700)
    result += text(48, 81, "“指定出口”完整显示，布局跟随字号。", 28, weight=700)
    result += text(48, 111, "按实际字体测量三列所需宽度；空间不足时整组纵排，标签始终保持单行。", 14, MUTED)
    for x, width, scale, stacked, caption in ((48, 360, 1, False, "360 dp · 常规字号"), (456, 320, 1, True, "320 dp · 三列空间不足时"), (824, 360, 1.5, True, "360 dp · 按钮字号 150%")):
        result += text(x, 162, caption, 14, GREEN, 600)
        result += rect(x, 180, width, 412, "#FCFCFB", 24, "#CBD3CD")
        result += text(x + 22, 221, "连接模式", 17 * scale, weight=700)
        result += rect(x + 22, 245, width - 44, 267)
        inner_width = width - 76
        label_size = 14 * scale
        button_height = max(48, 20 * scale + 24)
        for index, label in enumerate(("Direct", "Auto", "指定出口")):
            bx = x + 38 if stacked else x + 38 + index * ((inner_width + 8) / 3)
            by = 263 + index * (button_height + 8) if stacked else 263
            bw = inner_width if stacked else (inner_width - 16) / 3
            selected = index == 1
            result += rect(bx, by, bw, button_height, GREEN if selected else "white", 12, GREEN if selected else "#AEBBB2")
            result += text(bx + bw / 2, by + button_height / 2 + label_size * 0.36, label, label_size, "white" if selected else INK, 600, "middle")
        result += text(x + 38, 487, "按已下发规则自动选择路径。", 12, MUTED)
        result += text(x + 22, 548, "单行标签 · 保留完整文字", 12, MUTED)
        result += text(x + 22, 572, "整组纵排" if stacked else "等宽横排 · 按钮间距 8 dp", 12, MUTED)
    result += text(48, 638, "页面边距 22 dp  /  卡片边距 16 dp  /  按钮水平内边距 10 dp  /  触摸高度至少 48 dp", 14, weight=600)
    result += text(48, 674, "三列阈值 = 3 ×（当前字体下最宽标签 + 两侧内边距）+ 两个间距。更宽屏幕继续横排；大字体允许纵向滚动。", 13, MUTED)
    result += '</svg>\n'
    ET.fromstring(result)
    (OUTPUT / "loom-client-layout-misaka-v1.svg").write_text(result.replace("><", ">\n<"), encoding="utf-8")


def main():
    board("loom-client-home-misaka-v1.svg", "三个页面，三件清楚的事。", "连接页做日常操作，路由页解释实际路径，设置页管理设备。", [
        ("连接", "管理 VPN 连接与上网方式", connection_card() + mode_card() + button(22, 514, 316, "查看当前路径与网络状态"), "01 / 连接与模式", ["顶部选择要查看的配置，开关与三态集中在首页。", "一次只运行一份连接；出口选择在卡片内展开。"], "demo-home"),
        ("路由", "demo-home · 当前连接", paths_card() + network_card(), "02 / 路径与证据", ["路径与证据归属于正在查看的配置。", "另一配置的连接不能冒充当前配置已连接。"], "demo-home"),
        ("设置", "连接配置与本机设置", settings_cards(), "03 / 多配置管理", ["新增、重命名与删除围绕具体配置进行。", "通知和本机信息在同页展开；底部导航固定。"], "demo-home"),
    ])
    board("loom-client-interactions-misaka-v1.svg", "关键操作，都在当前页面完成。", "首次加入、选择出口、浏览路径；保留清楚的返回位置与状态反馈。", [
        ("设置", "为新连接导入邀请", add_profile(), "A / 添加并加入", ["先填写名称并导入邀请，再加入并保存。", "新配置保持未连接，既有连接继续运行。"], "新连接"),
        ("连接", "管理 VPN 连接与上网方式", connection_card() + mode_card(choosing=True), "B / 选择出口", ["选择前仍显示已确认的 Auto；取消不改变模式。", "按钮至少高 48；窄屏、大字体时整组纵排。"], "demo-home"),
        ("路由", "demo-home · 当前连接", route_detail(), "C / 逐项详情", ["一次展示一项，上一项 / 收起 / 下一项页内操作。", "真实实现保留来源、时间、原因及未知值。"], "demo-home"),
    ])
    board("loom-client-profiles-misaka-v1.svg", "保存多份配置，一次运行一个连接。", "与 Windows 保持相同的配置语义：切换查看不启动连接，每份配置独立保存身份与偏好。", [
        ("设置", "连接配置与本机设置", rename_profile(), "A / 选择与重命名", ["当前查看 demo-work，实际仍由 demo-home 承载。", "重命名只改变显示名称，不改变身份与连接。"], "demo-work"),
        ("连接", "demo-work · 未连接", switch_profile(), "B / 切换并连接", ["主操作绑定 demo-work；先停止旧宿主，再启动新宿主。", "失败保持当前配置未连接，显示实际失败原因。"], "demo-work"),
        ("设置", "连接配置与本机设置", delete_profile(), "C / 删除本机配置", ["只删除被选中的未连接配置；在原卡片内确认。", "正在使用的配置需先断开，其他配置保持原状。"], "demo-work"),
    ])
    layout_board()


if __name__ == "__main__":
    main()
