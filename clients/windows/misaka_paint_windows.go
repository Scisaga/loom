//go:build windows

package main

import (
	"math"
	"strings"
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
	c.Fill(misakaRect(s(97), s(8), s(96), s(24)), 0xF4F6F5, s(12))
	c.Text(windowsEditionLabel(app.edition), misakaRect(s(97), s(8), s(96), s(24)), s(10), 400, misakaMuted, 1)
	for i, label := range []string{"−", "×"} {
		r := misakaRect(bounds.right-s(int32(2-i)*42), 0, s(42), s(40))
		color := uint32(misakaText)
		if app.skin.hoverCaption == i+1 {
			fill := uint32(0xEEF0EE)
			if i == 1 {
				fill = misakaRed
				color = misakaWhite
			}
			c.Fill(r, fill, 0)
		}
		c.Text(label, r, s(18), 400, color, 1)
	}
	c.Text("Loom", misakaRect(s(67), s(58), s(95), s(28)), s(23), 600, misakaText, 0)
	c.Text("你的连接配置", misakaRect(s(68), s(85), s(98), s(18)), s(10), 400, misakaMuted, 0)
	c.Text("连接配置", misakaRect(s(16), s(115), s(112), s(24)), s(12), 600, misakaMuted, 0)
	c.Fill(misakaRect(s(16), bounds.bottom-s(64), s(144), s(1)), misakaBorder, 0)
	c.Text("双击名称可重命名", misakaRect(s(16), bounds.bottom-s(56), s(148), s(20)), s(10), 400, misakaMuted, 0)
	c.Text("同时只运行一个连接", misakaRect(s(16), bounds.bottom-s(34), s(148), s(20)), s(10), 400, misakaMuted, 0)
	app.finishMisakaPaint(dc)
	app.drawMisakaBrand(dc, true)
}

func (app *portableGUI) paintMisakaPane(dc uintptr) {
	if dc == 0 || app.skin == nil || app.skin.canvas == nil {
		return
	}
	var bounds portableRect
	procGetClientRect.Call(app.skin.pane, uintptr(unsafe.Pointer(&bounds)))
	if !app.beginMisakaPaint(dc, bounds) {
		return
	}
	c, s := app.skin.canvas, app.scale
	c.Fill(bounds, misakaBackground, 0)
	c.offsetX, c.offsetY = -s(176), -s(40)-app.skin.scrollY
	snapshot := app.snapshot()
	if snapshot.profileDraft != nil {
		app.paintMisakaDraft(c, snapshot)
	} else {
		app.paintMisakaContent(c, snapshot)
	}
	app.finishMisakaPaint(dc)
}

func (app *portableGUI) paintMisakaContent(c *misakaCanvas, snapshot portableGUISnapshot) {
	s := app.scale
	main, end := s(196), app.misakaContentEnd()
	name := snapshot.profileName
	if name == "" {
		name = "连接"
	}
	c.Text(name, misakaRect(main, s(57), end-main-s(110), s(31)), s(23), 600, misakaText, 0)
	card := misakaRect(main, s(98), end-main, s(112))
	c.Fill(card, misakaBorder, s(9))
	inset := card
	inset.left++
	inset.top++
	inset.right--
	inset.bottom--
	c.Fill(inset, misakaWhite, s(8))
	c.Fill(misakaRect(main+s(18), s(185), end-main-s(36), s(1)), misakaBorder, 0)
	device := "Device  " + snapshot.deviceID
	if snapshot.deviceID == "" {
		device = "尚未保存加入身份"
	}
	c.Text(device, misakaRect(main+s(18), s(189), end-main-s(36), s(18)), s(10), 400, misakaMuted, 0)
	if snapshot.joined {
		c.Text("路由模式", misakaRect(main, s(220), s(65), s(34)), s(11), 600, misakaText, 0)
		modeGroup := misakaRect(main+s(73), s(220), s(231), s(34))
		c.Fill(modeGroup, 0xE1E6E2, s(6))
		modeGroup.left++
		modeGroup.top++
		modeGroup.right--
		modeGroup.bottom--
		c.Fill(modeGroup, 0xF1F3F1, s(5))
		if misakaSelectedMode(snapshot) == clientcore.FixedExit && end-s(689) >= s(120) {
			c.Text("前置路径自动选择", misakaRect(s(689), s(220), end-s(689), s(34)), s(10), 400, misakaMuted, 2)
		}
		c.Text("当前选路", misakaRect(main, s(269), s(140), s(25)), s(15), 600, misakaText, 0)
		routeCaption := "按服务 · 用于新连接"
		if misakaSelectedMode(snapshot) == clientcore.FixedExit {
			routeCaption = "全部上网流量 · 用于新连接"
		}
		c.Text(routeCaption, misakaRect(main+s(90), s(273), end-main-s(188), s(18)), s(10), 400, misakaMuted, 2)
	} else {
		text := "通过 + 添加配置，然后粘贴二维码或选择邀请文件。"
		if !snapshot.profilesReady {
			_, text, _, _ = app.presentation(snapshot)
		}
		c.Text(text, misakaRect(main+s(18), s(268), end-main-s(36), s(70)), s(13), 400, misakaMuted, 0)
	}
}

func (app *portableGUI) drawMisakaBrand(dc uintptr, large bool) {
	instance, _, _ := procGetModuleHandle.Call(0)
	s := app.scale
	icon := loadPortableAppIcon(instance, portableSMCXSmallIcon, portableSMCYSmallIcon, app.dpi())
	iconWidth := portableSystemMetricForDPI(portableSMCXSmallIcon, app.dpi())
	iconHeight := portableSystemMetricForDPI(portableSMCYSmallIcon, app.dpi())
	procDrawIconEx.Call(dc, uintptr(s(15)), uintptr((s(40)-iconHeight)/2), icon, uintptr(iconWidth), uintptr(iconHeight), 0, 0, portableDrawIconNormal)
	if large {
		// §7.2：窗口内品牌区沿用完整版标志，系统小图标继续使用 favicon 原图。
		brand, _, _ := procLoadImage.Call(instance, portableIconBrand, portableImageIcon, uintptr(s(40)), uintptr(s(40)), portableLRShared)
		procDrawIconEx.Call(dc, uintptr(s(16)), uintptr(s(58)), brand, uintptr(s(40)), uintptr(s(40)), 0, 0, portableDrawIconNormal)
	}
}

func (app *portableGUI) paintMisakaDraft(c *misakaCanvas, snapshot portableGUISnapshot) {
	s := app.scale
	x, y, w := app.misakaDraftBounds()
	c.Text("添加连接配置", misakaRect(x, s(57), w, s(31)), s(23), 600, misakaText, 0)
	c.Text("保存后保持断开，现有连接继续运行。", misakaRect(x, s(88), w, s(20)), s(11), 400, misakaMuted, 0)
	// §7.2：沿用首页的一层内容卡片，名称和邀请控件直接排列，不再嵌套上传面板。
	card := misakaRect(x, y, w, s(330))
	c.Fill(card, misakaBorder, s(9))
	card.left++
	card.top++
	card.right--
	card.bottom--
	c.Fill(card, misakaWhite, s(8))
	c.Text("配置名称", misakaRect(x+s(24), y+s(20), w-s(48), s(21)), s(11), 600, misakaMuted, 0)
	field := misakaRect(x+s(24), y+s(46), w-s(48), s(36))
	c.Fill(field, misakaBorder, s(6))
	field.left++
	field.top++
	field.right--
	field.bottom--
	c.Fill(field, misakaWhite, s(5))
	c.Text("加入邀请", misakaRect(x+s(24), y+s(102), w-s(48), s(23)), s(11), 600, misakaMuted, 0)
	c.Text("二维码 PNG 或 .loom-invite 文件，也可从剪贴板粘贴。", misakaRect(x+s(24), y+s(126), w-s(48), s(20)), s(11), 400, misakaMuted, 0)
	text := app.skin.inviteLabel
	if text == "" {
		text = "尚未选择加入邀请。"
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
	c.Paragraph(text, misakaRect(x+s(24), y+s(204), w-s(48), s(52)), s(12), 400, color)
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
	if item.hwndItem == app.controls.stateIcon {
		app.drawMisakaStatus(item)
		return true
	}
	if item.hwndItem == app.controls.stateValue || item.hwndItem == app.controls.message {
		if !app.beginMisakaPaint(item.dc, item.rect) {
			return true
		}
		bg, fg, size := uint32(misakaWhite), uint32(misakaText), app.scale(23)
		if item.hwndItem == app.controls.message {
			bg, fg, size = misakaWhite, misakaMuted, app.scale(11)
			if app.snapshot().state == guiConnected {
				fg = misakaGreen
			}
			if app.snapshot().state == guiError {
				fg = misakaRed
			}
		}
		app.skin.canvas.Fill(item.rect, bg, 0)
		if item.hwndItem == app.controls.message {
			app.skin.canvas.Paragraph(misakaControlText(item.hwndItem), item.rect, size, 500, fg)
		} else {
			app.skin.canvas.Text(misakaControlText(item.hwndItem), item.rect, size, 500, fg, 0)
		}
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
	if item.hwndItem == app.controls.deleteButton {
		parent = misakaBackground
	}
	if item.hwndItem == app.controls.addProfileButton {
		parent = misakaSidebar
		bg = 0xEEF1EE
	}
	selected := false
	snapshot := app.snapshot()
	mode := misakaSelectedMode(snapshot)
	isMode := item.hwndItem == app.controls.modeAuto || item.hwndItem == app.controls.modeFixed || item.hwndItem == app.controls.modeDirect
	if isMode {
		parent, bg, fg = 0xF1F3F1, 0xF1F3F1, misakaMuted
		paintMisakaModeBackground(c, r, s, item.hwndItem == app.controls.modeDirect, item.hwndItem == app.controls.modeFixed)
	} else {
		c.Fill(r, parent, 0)
	}
	if item.hwndItem == app.controls.modeAuto {
		selected = mode == clientcore.Auto
	}
	if item.hwndItem == app.controls.modeFixed {
		selected = mode == clientcore.FixedExit
	}
	if item.hwndItem == app.controls.modeDirect {
		selected = mode == clientcore.Direct
	}
	primary := item.hwndItem == app.controls.draftSubmit || item.hwndItem == app.controls.primaryButton && snapshot.state != guiConnected && !portableStatusAnimated(snapshot.state)
	if primary {
		bg = misakaGreen
		fg = misakaWhite
	}
	if selected {
		bg = misakaWhite
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
		if !isMode {
			bg = 0xF0F2F0
		}
		fg = 0x9BA09E
	}
	border := uint32(misakaBorder)
	if primary || isMode && !selected || item.hwndItem == app.controls.addProfileButton {
		border = bg
	}
	if item.itemState&portableODSFocus != 0 {
		border = misakaGreen
	}
	if isMode {
		r.left += s(3)
		r.top += s(3)
		r.right -= s(3)
		r.bottom -= s(3)
	}
	c.Fill(r, border, s(6))
	r.left += s(1)
	r.top += s(1)
	r.right -= s(1)
	r.bottom -= s(1)
	c.Fill(r, bg, s(5))
	label := misakaControlText(item.hwndItem)
	switch item.hwndItem {
	case app.controls.addProfileButton:
		paintMisakaAdd(c, r, s, fg)
	default:
		c.Text(label, r, s(12), 500, fg, 1)
	}
	app.finishMisakaPaint(item.dc)
	return true
}

func paintMisakaModeBackground(c *misakaCanvas, rect portableRect, scale func(int32) int32, first, last bool) {
	// §7.2：首尾按钮各自绘制整段的外圆角，不能用矩形背景盖掉父画布的边角。
	c.Fill(rect, misakaBackground, 0)
	radius := int32(0)
	if first || last {
		radius = scale(6)
	}
	c.Fill(rect, 0xE1E6E2, radius)
	middle := (rect.left + rect.right) / 2
	if first {
		c.Fill(misakaRect(middle, rect.top, rect.right-middle, rect.bottom-rect.top), 0xE1E6E2, 0)
	} else if last {
		c.Fill(misakaRect(rect.left, rect.top, middle-rect.left, rect.bottom-rect.top), 0xE1E6E2, 0)
	}
	rect.top++
	rect.bottom--
	if first {
		rect.left++
	} else if last {
		rect.right--
	}
	c.Fill(rect, 0xF1F3F1, max(int32(0), radius-1))
	if first {
		c.Fill(misakaRect(middle, rect.top, rect.right-middle, rect.bottom-rect.top), 0xF1F3F1, 0)
	} else if last {
		c.Fill(misakaRect(rect.left, rect.top, middle-rect.left, rect.bottom-rect.top), 0xF1F3F1, 0)
	}
}

func (app *portableGUI) drawMisakaStatus(item *portableDrawItem) {
	if !app.beginMisakaPaint(item.dc, item.rect) {
		return
	}
	c, s := app.skin.canvas, app.scale
	c.Fill(item.rect, misakaWhite, 0)
	state := app.snapshot().state
	ink, fill := uint32(misakaMuted), uint32(0xF4F6F5)
	if state == guiConnected || portableStatusAnimated(state) {
		ink, fill = misakaGreen, misakaGreenLight
	}
	if state == guiStopping {
		ink, fill = misakaAmber, 0xFFF6E7
	}
	if state == guiError {
		ink, fill = misakaRed, 0xFFF0ED
	}
	x, y := (item.rect.left+item.rect.right)/2, (item.rect.top+item.rect.bottom)/2
	paintMisakaEllipse(c, misakaCenteredRect(x, y, s(38), s(38)), fill)
	switch {
	case portableStatusAnimated(state):
		for index := 0; index < portableStatusFrameCount; index++ {
			angle := float64(index)*2*math.Pi/portableStatusFrameCount - math.Pi/2
			phase := (index - app.statusFrame%portableStatusFrameCount + portableStatusFrameCount) % portableStatusFrameCount
			opacity := uint32(64 + (portableStatusFrameCount-1-phase)*191/(portableStatusFrameCount-1))
			color := uint32(0)
			for _, shift := range []uint{0, 8, 16} {
				color |= (((ink>>shift&255)*opacity + (fill>>shift&255)*(255-opacity)) / 255) << shift
			}
			dx, dy := int32(math.Round(math.Cos(angle)*float64(s(10)))), int32(math.Round(math.Sin(angle)*float64(s(10))))
			paintMisakaEllipse(c, misakaCenteredRect(x+dx, y+dy, s(3), s(3)), color)
		}
	case state == guiConnected:
		paintMisakaLine(c, x-s(8), y, x-s(2), y+s(6), s(2), ink)
		paintMisakaLine(c, x-s(2), y+s(6), x+s(9), y-s(6), s(2), ink)
	case state == guiError:
		paintMisakaLine(c, x-s(6), y-s(6), x+s(6), y+s(6), s(2), ink)
		paintMisakaLine(c, x-s(6), y+s(6), x+s(6), y-s(6), s(2), ink)
	default:
		c.Fill(misakaCenteredRect(x, y, s(14), s(2)), ink, 0)
	}
	app.finishMisakaPaint(item.dc)
}

func paintMisakaLine(c *misakaCanvas, x1, y1, x2, y2, width int32, color uint32) {
	dx, dy := float64(x2-x1), float64(y2-y1)
	length := math.Hypot(dx, dy)
	if length == 0 {
		return
	}
	cosine, sine := float32(dx/length), float32(dy/length)
	transform := [6]float32{cosine, sine, -sine, cosine, float32(x1 - c.bounds.left), float32(y1 - c.bounds.top)}
	identity := [6]float32{1, 0, 0, 1, 0, 0}
	misakaCOMCall(c.target, 30, uintptr(unsafe.Pointer(&transform)))
	defer misakaCOMCall(c.target, 30, uintptr(unsafe.Pointer(&identity)))
	c.Fill(misakaRect(c.bounds.left, c.bounds.top-width/2, int32(math.Round(length)), width), color, width/2)
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
	if item.itemState&portableODSSelected != 0 {
		c.Fill(r, 0xE9F3ED, 0)
		c.Fill(misakaRect(r.left, r.top, s(3), r.bottom-r.top), misakaGreen, 0)
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
	c.Text(label, misakaRect(r.left+s(29), r.top+s(33), r.right-r.left-s(35), s(16)), s(10), 400, misakaMuted, 0)
	app.finishMisakaPaint(item.dc)
	app.drawMisakaProfileName(item.dc, r, profile.Name, item.itemState&portableODSSelected != 0)
	if portableStatusAnimated(profile.State) {
		icon := app.statusIcons.icon(profile.State, app.statusFrame, app.statusIcon)
		procDrawIconEx.Call(item.dc, uintptr(r.left+s(8)), uintptr(r.top+s(10)), icon, uintptr(s(16)), uintptr(s(16)), 0, 0, portableDrawIconNormal)
	}
}

// §7.2：操作符号使用几何中心，避免系统字体的基线与字符留白改变可见位置。
func paintMisakaAdd(c *misakaCanvas, bounds portableRect, scale func(int32) int32, color uint32) {
	x, y := (bounds.left+bounds.right)/2, (bounds.top+bounds.bottom)/2
	c.Fill(misakaCenteredRect(x, y, scale(12), scale(2)), color, 0)
	c.Fill(misakaCenteredRect(x, y, scale(2), scale(12)), color, 0)
}

func misakaCenteredRect(x, y, width, height int32) portableRect {
	return misakaRect(x-width/2, y-height/2, width, height)
}

func paintMisakaPathNode(c *misakaCanvas, x, y int32, index, count int, scale func(int32) int32, fixed bool) {
	outline, ink, fill := uint32(0xD8DFDA), uint32(misakaMuted), uint32(0xF7F9F8)
	if fixed {
		outline, ink, fill = misakaGreen, misakaGreen, misakaGreenLight
	}
	c.Fill(misakaCenteredRect(x, y, scale(34), scale(34)), outline, scale(17))
	c.Fill(misakaCenteredRect(x, y, scale(32), scale(32)), fill, scale(16))
	stroke := max(int32(1), scale(1))
	if index == count-1 {
		// §1：目标地址使用地址球面符号，不把它绘成服务器。
		paintMisakaEllipse(c, misakaCenteredRect(x, y, scale(16), scale(16)), ink)
		paintMisakaEllipse(c, misakaCenteredRect(x, y, scale(16)-2*stroke, scale(16)-2*stroke), fill)
		paintMisakaEllipse(c, misakaCenteredRect(x, y, scale(8), scale(16)), ink)
		paintMisakaEllipse(c, misakaCenteredRect(x, y, scale(8)-2*stroke, scale(16)-2*stroke), fill)
		c.Fill(misakaCenteredRect(x, y, scale(14), stroke), ink, 0)
		return
	}
	if index == 0 {
		monitor := misakaCenteredRect(x, y-scale(2), scale(16), scale(11))
		c.Fill(monitor, ink, stroke)
		monitor.left += stroke
		monitor.top += stroke
		monitor.right -= stroke
		monitor.bottom -= stroke
		c.Fill(monitor, fill, 0)
		c.Fill(misakaCenteredRect(x, y+scale(5), stroke, scale(5)), ink, 0)
		c.Fill(misakaCenteredRect(x, y+scale(7), scale(9), stroke), ink, 0)
		return
	}
	for _, offset := range []int32{-5, 5} {
		server := misakaCenteredRect(x, y+scale(offset), scale(14), scale(7))
		c.Fill(server, ink, stroke)
		server.left += stroke
		server.top += stroke
		server.right -= stroke
		server.bottom -= stroke
		c.Fill(server, fill, 0)
		c.Fill(misakaCenteredRect(x-scale(3), y+scale(offset), stroke, stroke), ink, 0)
		c.Fill(misakaCenteredRect(x+scale(2), y+scale(offset), scale(4), stroke), ink, 0)
	}
}

func paintMisakaEllipse(c *misakaCanvas, rect portableRect, color uint32) {
	if !c.canDraw(rect) {
		return
	}
	brush := c.brush(color)
	if brush == nil {
		return
	}
	area := c.relativeRect(rect)
	ellipse := [4]float32{(area.left + area.right) / 2, (area.top + area.bottom) / 2, (area.right - area.left) / 2, (area.bottom - area.top) / 2}
	misakaCOMCall(c.target, 21, uintptr(unsafe.Pointer(&ellipse)), uintptr(unsafe.Pointer(brush)))
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
		r.bottom -= s(12)
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
	r.bottom -= s(12)
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
	serviceWidth := min(s(200), (r.right-r.left-s(110))/3)
	serviceLabel := row.Service
	if misakaSelectedMode(app.snapshot()) == clientcore.FixedExit {
		serviceLabel = "统一上网路径"
	}
	c.Text(serviceLabel, misakaRect(r.left+s(18), r.top+s(8), serviceWidth, s(24)), s(13), 600, misakaText, 0)
	quality := row.SelectedQuality
	if quality == "" || quality == "未知" {
		quality = "—"
	}
	qualityLeft := r.left + s(30) + serviceWidth
	c.Text("完整路径质量  "+quality, misakaRect(qualityLeft, r.top+s(8), r.right-s(104)-qualityLeft, s(24)), s(11), 400, misakaMuted, 2)
	health := misakaRect(r.right-s(92), r.top+s(9), s(76), s(22))
	healthFill := uint32(0xF4F6F5)
	if row.Health == "正常" {
		healthFill = misakaGreenLight
	} else if color == misakaRed {
		healthFill = 0xFFF0ED
	} else if color == misakaAmber {
		healthFill = 0xFFF6E7
	}
	c.Fill(health, healthFill, s(11))
	healthLabel := row.Health
	if healthLabel == "" || healthLabel == "未知" {
		healthLabel = "健康未知"
	}
	c.Text(healthLabel, health, s(10), 500, color, 1)
	// §7.3.3：只拆分只读显示字符串用于布局，不由名称推导路径或操作 selector。
	nodes := strings.Split(row.Chain, " → ")
	if len(nodes) < 2 || row.Candidate == "" {
		c.Text("实际路径未知", misakaRect(r.left+s(14), r.top+s(40), r.right-r.left-s(28), s(30)), s(12), 400, misakaMuted, 0)
		app.finishMisakaPaint(item.dc)
		return
	}
	for start := 0; start < len(nodes); start += 4 {
		count := min(4, len(nodes)-start)
		usable := r.right - r.left - s(84)
		step := usable / int32(max(1, count-1))
		y := r.top + s(59+int32(start/4)*64)
		if start > 0 {
			c.Text("↳", misakaRect(r.left+s(12), y-s(12), s(22), s(24)), s(16), 400, misakaMuted, 1)
		}
		for index := 0; index < count; index++ {
			x := r.left + s(42) + int32(index)*step
			if count == 1 {
				x = r.left + s(42)
			}
			if index < count-1 {
				c.Fill(misakaRect(x+s(17), y-s(1), step-s(34), s(2)), 0xC7D8CD, 0)
			}
			fixed := start+index == len(nodes)-2 && misakaSelectedMode(app.snapshot()) == clientcore.FixedExit
			paintMisakaPathNode(c, x, y, start+index, len(nodes), s, fixed)
			// §7.2：两端标签按可用对称宽度收窄，不将文字挤离节点的中心轴。
			labelWidth := min(s(120), step-s(6), (x-r.left-s(10))*2, (r.right-s(10)-x)*2)
			left := x - labelWidth/2
			label := nodes[start+index]
			if start+index == len(nodes)-1 {
				label = strings.Replace(label, "目标", "目标地址", 1)
			}
			c.Text(label, misakaRect(left, y+s(23), labelWidth, s(20)), s(11), 400, misakaText, 1)
		}
	}
	if app.pathsExpanded {
		y := r.top + s(106+int32((len(nodes)-1)/4)*64)
		width := r.right - r.left - s(28)
		best := row.BestQuality
		if best == "" || best == "未知" {
			best = "未知"
		}
		c.Text("最佳："+best, misakaRect(r.left+s(14), y, width, s(20)), s(10), 400, misakaMuted, 0)
		reason := row.Reason
		if reason == "" {
			reason = "未知"
		}
		c.Paragraph("原因："+reason, misakaRect(r.left+s(14), y+s(20), width, s(32)), s(10), 400, misakaMuted)
		at := row.UpdatedAt
		if at == "" {
			at = "未知"
		}
		c.Text("读取："+at, misakaRect(r.left+s(14), y+s(54), width, s(18)), s(9), 400, misakaMuted, 0)
		if row.DecisionScope != "" {
			c.Text("决策范围："+row.DecisionScope, misakaRect(r.left+s(14), y+s(72), width, s(16)), s(9), 400, misakaMuted, 0)
		}
	}
	app.finishMisakaPaint(item.dc)
}
