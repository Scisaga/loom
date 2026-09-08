//go:build windows

package main

import (
	"strings"
	"time"
	"unsafe"

	"loom/internal/clientcore"
)

func (app *portableGUI) paintMisaka(dc uintptr) {
	if dc == 0 || app.skin == nil || app.skin.canvas == nil {
		return
	}
	var bounds portableRect
	procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&bounds)))
	c, s := app.skin.canvas, app.scale
	if !app.beginMisakaPaint(dc, bounds) {
		return
	}
	c.Fill(bounds, misakaBackground, 0)
	c.Fill(misakaRect(0, s(40), s(176), bounds.bottom-s(40)), misakaSidebar, 0)
	c.Fill(misakaRect(s(176), s(40), s(1), bounds.bottom-s(40)), misakaBorder, 0)
	c.Fill(misakaRect(0, 0, bounds.right, s(40)), misakaWhite, 0)
	c.Fill(misakaRect(0, s(39), bounds.right, s(1)), misakaBorder, 0)
	c.Text("Loom", misakaRect(s(42), s(9), s(80), s(23)), s(16), 600, misakaText, 0)
	c.Text(windowsEditionLabel(app.edition), misakaRect(s(110), s(10), s(210), s(22)), s(11), 400, misakaMuted, 0)
	for i, label := range []string{"−", "□", "×"} {
		r := misakaRect(bounds.right-s(int32(3-i)*42), 0, s(42), s(40))
		color := uint32(misakaText)
		if app.skin.hoverCaption == i+1 {
			fill := uint32(0xEEF0EE)
			if i == 2 {
				fill = misakaRed
				color = misakaWhite
			}
			c.Fill(r, fill, 0)
		}
		c.Text(label, r, s(18), 400, color, 1)
	}
	snapshot := app.snapshot()
	c.Text("Loom", misakaRect(s(62), s(63), s(95), s(28)), s(20), 600, misakaText, 0)
	c.Text("连接配置", misakaRect(s(16), s(115), s(112), s(24)), s(12), 600, misakaMuted, 0)
	if snapshot.profileDraft != nil {
		app.paintMisakaDraft(c, snapshot)
		app.finishMisakaPaint(dc)
		app.drawMisakaBrand(dc, true)
		return
	}
	c.Text("双击名称可重命名", misakaRect(s(16), bounds.bottom-s(47), s(148), s(20)), s(10), 400, misakaMuted, 0)
	main, end := s(196), bounds.right-s(20)
	name := snapshot.profileName
	if name == "" {
		name = "连接"
	}
	c.Text(name, misakaRect(main, s(57), end-main, s(31)), s(23), 600, misakaText, 0)
	caption := "中控签名配置 · 本地名称可修改"
	if snapshot.activeProfile != "" && snapshot.activeProfile != snapshot.selectedProfile {
		caption = "当前连接：" + snapshot.activeProfileName
	}
	if !snapshot.joined {
		caption = "添加连接配置，安全加入 Loom 网络。"
	}
	c.Text(caption, misakaRect(main, s(88), end-main, s(20)), s(11), 400, misakaMuted, 0)
	card := misakaRect(main, s(118), end-main, s(112))
	c.Fill(card, misakaBorder, s(9))
	inset := card
	inset.left++
	inset.top++
	inset.right--
	inset.bottom--
	c.Fill(inset, misakaWhite, s(8))
	message := "连接后按中控规则接管系统流量"
	if app.edition == editionPortableMixed {
		message = "应用代理 · 仅接管使用本地代理的应用"
	}
	if snapshot.state == guiConnected && app.edition != editionPortableMixed {
		message = "系统 TUN 已启用 · 流量按中控规则分流"
	}
	if !snapshot.joined {
		message = "每份配置独立保存身份，同一时间连接一份。"
	}
	c.Text(message, misakaRect(main+s(18), s(164), end-main-s(36), s(20)), s(11), 400, misakaMuted, 0)
	if snapshot.joined {
		c.Text("当前选路", misakaRect(main, s(240), s(150), s(25)), s(16), 600, misakaText, 0)
		c.Text("按服务 · 用于新连接", misakaRect(main+s(90), s(244), end-main-s(180), s(18)), s(10), 400, misakaMuted, 0)
		if len(snapshot.paths) == 0 || snapshot.state != guiConnected {
			empty := misakaRect(main, s(272), end-main, bounds.bottom-s(320))
			c.Fill(empty, misakaWhite, s(8))
		}
	} else {
		text := "通过 + 添加配置，然后粘贴二维码或选择邀请文件。"
		if !snapshot.profilesReady {
			_, text, _, _ = app.presentation(snapshot)
		}
		c.Text(text, misakaRect(main+s(18), s(268), end-main-s(36), s(70)), s(13), 400, misakaMuted, 0)
	}
	if app.skin.menu {
		popup := misakaRect(s(12), bounds.bottom-s(166), s(152), s(82))
		c.Fill(popup, misakaBorder, s(8))
		popup.left++
		popup.top++
		popup.right--
		popup.bottom--
		c.Fill(popup, misakaWhite, s(7))
	}
	app.finishMisakaPaint(dc)
	app.drawMisakaBrand(dc, true)
}

func (app *portableGUI) drawMisakaBrand(dc uintptr, large bool) {
	instance, _, _ := procGetModuleHandle.Call(0)
	s := app.scale
	icon := loadPortableAppIcon(instance, portableSMCXSmallIcon, portableSMCYSmallIcon, app.dpi())
	iconWidth := portableSystemMetricForDPI(portableSMCXSmallIcon, app.dpi())
	iconHeight := portableSystemMetricForDPI(portableSMCYSmallIcon, app.dpi())
	procDrawIconEx.Call(dc, uintptr(s(15)), uintptr((s(40)-iconHeight)/2), icon, uintptr(iconWidth), uintptr(iconHeight), 0, 0, portableDrawIconNormal)
	if large {
		brand, _, _ := procLoadImage.Call(instance, portableIconApp, portableImageIcon, uintptr(s(36)), uintptr(s(36)), portableLRShared)
		procDrawIconEx.Call(dc, uintptr(s(16)), uintptr(s(60)), brand, uintptr(s(36)), uintptr(s(36)), 0, 0, portableDrawIconNormal)
	}
}

func (app *portableGUI) paintMisakaDraft(c *misakaCanvas, snapshot portableGUISnapshot) {
	s := app.scale
	x, y, w := app.misakaDraftBounds()
	c.Text("添加连接配置", misakaRect(x+s(24), y+s(22), w-s(48), s(32)), s(23), 600, misakaText, 0)
	c.Text("保存后保持断开，现有连接继续运行。", misakaRect(x+s(24), y+s(59), w-s(48), s(24)), s(12), 400, misakaMuted, 0)
	c.Text("配置名称", misakaRect(x+s(24), y+s(88), w-s(48), s(21)), s(11), 600, misakaMuted, 0)
	field := misakaRect(x+s(20), y+s(111), w-s(40), s(36))
	c.Fill(field, misakaBorder, s(6))
	field.left++
	field.top++
	field.right--
	field.bottom--
	c.Fill(field, misakaWhite, s(5))
	c.Text("加入邀请", misakaRect(x+s(24), y+s(165), w-s(48), s(23)), s(11), 600, misakaMuted, 0)
	text := app.skin.inviteLabel
	if text == "" {
		text = "支持二维码 PNG / .loom-invite，也可粘贴二维码图片。"
	}
	color := uint32(misakaMuted)
	if d := snapshot.profileDraft; d != nil {
		if d.Recoverable {
			text = "已有受保护的加入进度，继续时沿用原身份。"
		}
		if d.Detail != "" {
			text = d.Detail
		}
		if d.State == guiError {
			color = misakaRed
		}
	}
	if app.skin.draftError != "" {
		text = app.skin.draftError
		color = misakaRed
	}
	c.Paragraph(text, misakaRect(x+s(24), y+s(247), w-s(48), s(78)), s(12), 400, color)
}

func (app *portableGUI) drawMisakaItem(item *portableDrawItem) bool {
	if item == nil || app.skin == nil || app.skin.canvas == nil {
		return false
	}
	if item.hwndItem == app.controls.networkList {
		app.drawMisakaProfile(item)
		return true
	}
	if item.hwndItem == app.controls.pathsValue {
		app.drawMisakaPath(item)
		return true
	}
	if item.hwndItem == app.controls.routeCombo {
		app.drawMisakaRoute(item)
		return true
	}
	if item.hwndItem == app.controls.stateValue || item.hwndItem == app.controls.message {
		if !app.beginMisakaPaint(item.dc, item.rect) {
			return true
		}
		bg, fg, size := uint32(misakaWhite), uint32(misakaText), app.scale(19)
		if item.hwndItem == app.controls.message {
			bg, fg, size = misakaBackground, misakaMuted, app.scale(11)
		}
		app.skin.canvas.Fill(item.rect, bg, 0)
		app.skin.canvas.Text(misakaControlText(item.hwndItem), item.rect, size, 500, fg, 0)
		app.finishMisakaPaint(item.dc)
		return true
	}
	if item.controlType != 4 {
		return false
	} // ODT_BUTTON
	c, s := app.skin.canvas, app.scale
	if !app.beginMisakaPaint(item.dc, item.rect) {
		return true
	}
	r := item.rect
	bg, fg := uint32(misakaWhite), uint32(misakaText)
	parent := uint32(misakaWhite)
	if item.hwndItem == app.controls.addProfileButton || item.hwndItem == app.controls.profileMenu {
		parent = misakaSidebar
		bg = misakaSidebar
	}
	c.Fill(r, parent, 0)
	selected := false
	mode := misakaSelectedMode(app.snapshot())
	if item.hwndItem == app.controls.modeAuto {
		selected = mode == clientcore.Auto
	}
	if item.hwndItem == app.controls.modeFixed {
		selected = mode == clientcore.FixedExit
	}
	if item.hwndItem == app.controls.modeDirect {
		selected = mode == clientcore.Direct
	}
	primary := item.hwndItem == app.controls.primaryButton || item.hwndItem == app.controls.draftSubmit
	if primary {
		bg = misakaGreen
		fg = misakaWhite
	}
	if selected {
		bg = misakaGreenLight
		fg = misakaGreen
	}
	if item.itemState&portableODSSelected != 0 {
		if primary {
			bg = 0x187C51
		} else {
			bg = 0xE4EBE7
		}
	}
	if item.itemState&(portableODSDisabled|portableODSGrayed) != 0 {
		bg = 0xF0F2F0
		fg = 0x9BA09E
	}
	border := uint32(misakaBorder)
	if primary || selected {
		border = bg
	}
	if item.itemState&portableODSFocus != 0 {
		border = misakaGreen
	}
	c.Fill(r, border, s(6))
	r.left += s(1)
	r.top += s(1)
	r.right -= s(1)
	r.bottom -= s(1)
	c.Fill(r, bg, s(5))
	label := misakaControlText(item.hwndItem)
	size := s(12)
	if item.hwndItem == app.controls.addProfileButton {
		label = "+"
		size = s(21)
	}
	if item.hwndItem == app.controls.profileMenu {
		label = "配置操作   ···"
	}
	c.Text(label, r, size, 500, fg, 1)
	app.finishMisakaPaint(item.dc)
	return true
}

func (app *portableGUI) drawMisakaProfile(item *portableDrawItem) {
	c, s := app.skin.canvas, app.scale
	if !app.beginMisakaPaint(item.dc, item.rect) {
		return
	}
	c.Fill(item.rect, misakaSidebar, 0)
	if item.itemID == ^uint32(0) {
		app.finishMisakaPaint(item.dc)
		return
	}
	snapshot := app.snapshot()
	if int(item.itemID) >= len(snapshot.profiles) {
		app.finishMisakaPaint(item.dc)
		return
	}
	profile := snapshot.profiles[item.itemID]
	r := item.rect
	r.top += s(2)
	r.bottom -= s(2)
	if item.itemState&portableODSSelected != 0 {
		c.Fill(r, 0xEAEFEC, s(6))
		c.Fill(misakaRect(r.left, r.top+s(10), s(3), r.bottom-r.top-s(20)), misakaGreen, s(1))
	}
	color := uint32(0xA4AAA6)
	label := "未连接"
	if profile.State == guiConnected {
		color = misakaGreen
		label = "已连接"
	}
	if portableStatusAnimated(profile.State) {
		color = misakaAmber
		label = "正在连接"
	}
	if profile.State == guiJoining {
		label = "正在加入"
	}
	if profile.State == guiLoading {
		label = "正在检查"
	}
	if profile.State == guiNeedsJoin {
		label = "未加入"
	}
	if profile.State == guiStopping {
		label = "正在断开"
	}
	if profile.State == guiError {
		color = misakaRed
		label = "连接错误"
	}
	if !portableStatusAnimated(profile.State) {
		c.Fill(misakaRect(r.left+s(12), r.top+s(15), s(7), s(7)), color, s(4))
	}
	c.Text(profile.Name, misakaRect(r.left+s(29), r.top+s(4), r.right-r.left-s(35), s(23)), s(13), 500, misakaText, 0)
	c.Text(label, misakaRect(r.left+s(29), r.top+s(25), r.right-r.left-s(35), s(16)), s(10), 400, misakaMuted, 0)
	if item.itemState&portableODSFocus != 0 {
		c.Fill(misakaRect(r.left+s(8), r.bottom-s(2), r.right-r.left-s(16), s(1)), misakaGreen, 0)
	}
	app.finishMisakaPaint(item.dc)
	if portableStatusAnimated(profile.State) {
		icon := app.statusIcons.icon(profile.State, app.statusFrame, app.statusIcon)
		procDrawIconEx.Call(item.dc, uintptr(r.left+s(8)), uintptr(r.top+s(10)), icon, uintptr(s(16)), uintptr(s(16)), 0, 0, portableDrawIconNormal)
	}
}

func (app *portableGUI) drawMisakaRoute(item *portableDrawItem) {
	c, s := app.skin.canvas, app.scale
	if !app.beginMisakaPaint(item.dc, item.rect) {
		return
	}
	bg, fg := uint32(misakaWhite), uint32(misakaText)
	if item.itemState&portableODSSelected != 0 && item.itemState&portableODSComboBoxEdit == 0 {
		bg = misakaGreenLight
		fg = misakaGreen
	}
	if item.itemState&portableODSDisabled != 0 {
		bg = 0xF0F2F0
		fg = misakaMuted
	}
	c.Fill(item.rect, bg, 0)
	label := "选择出口…"
	if int(item.itemID) < len(app.routeVisible) {
		snapshot := app.snapshot()
		index := app.routeVisible[item.itemID]
		if index < len(snapshot.routeOptions) {
			label = strings.TrimPrefix(snapshot.routeOptions[index].Label, "固定出口 · ")
		}
	}
	if app.routeFiltering && item.itemState&portableODSComboBoxEdit != 0 {
		label = app.routeFilter
	}
	r := item.rect
	r.left += s(8)
	r.right -= s(4)
	c.Text(label, r, s(12), 400, fg, 0)
	app.finishMisakaPaint(item.dc)
}

func (app *portableGUI) drawMisakaPath(item *portableDrawItem) {
	c, s := app.skin.canvas, app.scale
	if !app.beginMisakaPaint(item.dc, item.rect) {
		return
	}
	c.Fill(item.rect, misakaBackground, 0)
	if int(item.itemID) >= len(app.skin.lastPaths) {
		r := item.rect
		r.bottom -= s(8)
		c.Fill(r, misakaWhite, s(8))
		text := "未连接；连接成功后显示各服务的实际路径。"
		if app.snapshot().state == guiConnected {
			text = "当前选路未知，正在读取本机实际状态。"
		}
		c.Text(text, misakaRect(r.left+s(18), r.top+s(24), r.right-r.left-s(36), s(50)), s(12), 400, misakaMuted, 0)
		app.finishMisakaPaint(item.dc)
		return
	}
	row := app.skin.lastPaths[item.itemID]
	r := item.rect
	r.bottom -= s(8)
	r.right -= s(3)
	c.Fill(r, misakaBorder, s(8))
	r.left++
	r.top++
	r.right--
	r.bottom--
	c.Fill(r, misakaWhite, s(7))
	color := uint32(misakaMuted)
	if row.Health == "正常" {
		color = misakaGreen
	}
	if row.Health == "不稳定" || row.Health == "测量已过期" {
		color = misakaAmber
	}
	if row.Health == "故障" {
		color = misakaRed
	}
	c.Text(row.Service, misakaRect(r.left+s(14), r.top+s(8), r.right-r.left-s(110), s(22)), s(13), 600, misakaText, 0)
	c.Text(row.Health, misakaRect(r.right-s(100), r.top+s(8), s(84), s(22)), s(11), 500, color, 2)
	// §7.3.3：只拆分只读显示字符串用于布局，不由名称推导路径或操作 selector。
	nodes := strings.Split(row.Chain, " → ")
	if len(nodes) < 2 || row.Candidate == "" {
		c.Text("实际路径未知", misakaRect(r.left+s(14), r.top+s(40), r.right-r.left-s(28), s(30)), s(12), 400, misakaMuted, 0)
		app.finishMisakaPaint(item.dc)
		return
	}
	for start := 0; start < len(nodes); start += 4 {
		count := min(4, len(nodes)-start)
		usable := r.right - r.left - s(124)
		step := usable / int32(max(1, count-1))
		y := r.top + s(51+int32(start/4)*64)
		if start > 0 {
			c.Text("↳", misakaRect(r.left+s(12), y-s(12), s(22), s(24)), s(16), 400, misakaMuted, 1)
		}
		for index := 0; index < count; index++ {
			x := r.left + s(62) + int32(index)*step
			if count == 1 {
				x = r.left + s(62)
			}
			if index < count-1 {
				c.Fill(misakaRect(x+s(11), y-s(1), step-s(22), s(2)), 0xCDD9D1, 0)
			}
			c.Fill(misakaRect(x-s(10), y-s(10), s(20), s(20)), 0xDCE8E0, s(10))
			c.Fill(misakaRect(x-s(8), y-s(8), s(16), s(16)), misakaWhite, s(8))
			glyph := "▤"
			if start+index == 0 {
				glyph = "□"
			}
			if start+index == len(nodes)-1 {
				glyph = "◎"
			}
			c.Text(glyph, misakaRect(x-s(8), y-s(9), s(16), s(18)), s(12), 400, misakaGreen, 1)
			labelWidth := min(s(120), step-s(6))
			left := max(r.left+s(10), min(x-labelWidth/2, r.right-s(10)-labelWidth))
			label := nodes[start+index]
			if start+index == len(nodes)-1 {
				label = strings.Replace(label, "目标", "目标地址", 1)
			}
			c.Text(label, misakaRect(left, y+s(13), labelWidth, s(20)), s(11), 400, misakaText, 1)
			if start+index == len(nodes)-2 && misakaSelectedMode(app.snapshot()) == clientcore.FixedExit {
				c.Text("固定出口", misakaRect(x-s(32), y-s(28), s(64), s(16)), s(9), 500, misakaGreen, 1)
			}
		}
	}
	qualityY := r.top + s(93+int32((len(nodes)-1)/4)*64)
	quality := row.SelectedQuality
	if quality == "" || quality == "未知" {
		quality = "—"
	}
	c.Text("完整路径  "+quality, misakaRect(r.left+s(14), qualityY, r.right-r.left-s(134), s(23)), s(11), 400, misakaMuted, 0)
	stamp := "观测未知"
	if parsed, err := time.Parse(time.RFC3339Nano, row.UpdatedAt); err == nil {
		stamp = "观测 " + parsed.Local().Format("15:04:05")
	}
	c.Text(stamp, misakaRect(r.right-s(112), qualityY, s(98), s(23)), s(10), 400, misakaMuted, 2)
	if app.pathsExpanded {
		lines := []string{"当前：" + row.SelectedQuality + "  ·  最佳：" + row.BestQuality, "原因：" + row.Reason, "读取时间：" + row.UpdatedAt}
		if row.UpdatedAt == "" {
			lines[2] = "读取时间：未知"
		}
		if row.DecisionScope != "" {
			lines = append(lines, "决策范围："+row.DecisionScope)
		}
		y := qualityY + s(30)
		for _, line := range lines {
			c.Paragraph(line, misakaRect(r.left+s(14), y, r.right-r.left-s(28), s(32)), s(10), 400, misakaMuted)
			y += s(32)
		}
	}
	app.finishMisakaPaint(item.dc)
}
