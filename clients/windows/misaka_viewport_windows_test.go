//go:build windows

package main

import (
	"fmt"
	"image"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
)

// §7.2：只使用合成窗口和演示路径，验证原生视口、键盘和组合框的实际行为。
func newMisakaViewportTestWindow(t *testing.T) *portableGUI {
	t.Helper()
	app := newProfileGUITestWindow(t)
	path := app.paths[0]
	app.paths = nil
	for index := 0; index < 8; index++ {
		path.Service = fmt.Sprintf("demo-service-%d", index)
		app.paths = append(app.paths, path)
	}
	app.renderControls()
	return app
}

func misakaViewportControlRect(t *testing.T, hwnd, parent uintptr) portableRect {
	t.Helper()
	r := guiWindowRect(t, hwnd)
	procMisakaMapPoints.Call(0, parent, uintptr(unsafe.Pointer(&r)), 2)
	return r
}

func misakaViewportClientRect(hwnd uintptr) portableRect {
	var r portableRect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}

func misakaViewportMatchingPixels(before, after *image.NRGBA, area portableRect, delta int32) (int, int) {
	matching, total := 0, 0
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			if before.NRGBAAt(int(x), int(y)) == after.NRGBAAt(int(x), int(y-delta)) {
				matching++
			}
			total++
		}
	}
	return matching, total
}

func TestGUIMisakaViewportScrollsWholeRightPaneAndReachesLastService(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	if app.skin.pane == 0 || profileGUIStyle(app.skin.pane)&portableWSVScroll == 0 {
		t.Fatal("[§7.2] 右侧没有统一的原生滚动视口")
	}
	if profileGUIStyle(app.controls.pathsValue)&portableWSVScroll != 0 {
		t.Fatal("[§7.2] 路径列表仍有第二条滚动条")
	}
	left := guiWindowRect(t, app.controls.networkList)
	add := guiWindowRect(t, app.controls.addProfileButton)
	right := []uintptr{app.controls.stateIcon, app.controls.stateValue, app.controls.primaryButton, app.controls.modeDirect, app.controls.modeAuto, app.controls.modeFixed, app.controls.pathsValue}
	beforeRects := make([]portableRect, len(right))
	for index, control := range right {
		parent, _, _ := portableUser32.NewProc("GetParent").Call(control)
		if parent != app.skin.pane {
			t.Fatalf("[§7.2] 右侧控件 %x 未归属统一滚动视口", control)
		}
		beforeRects[index] = guiWindowRect(t, control)
	}
	before := readProfileGUITestWindow(t, app)
	delta := app.scale(12)
	app.scrollMisakaPane(delta)
	if app.skin.scrollY != delta {
		t.Fatalf("[§7.2] 右侧滚动位置=%d，预期 %d", app.skin.scrollY, delta)
	}
	for index, control := range right {
		want := beforeRects[index]
		want.top, want.bottom = want.top-delta, want.bottom-delta
		if got := guiWindowRect(t, control); got != want {
			t.Errorf("[§7.2] 右侧控件 %x 未共同移动：实际=%+v 预期=%+v", control, got, want)
		}
	}
	if guiWindowRect(t, app.controls.networkList) != left || guiWindowRect(t, app.controls.addProfileButton) != add {
		t.Fatal("[§7.2] 右侧滚动移动了左侧配置列表或添加按钮")
	}
	after := readProfileGUITestWindow(t, app)
	header := misakaRect(app.scale(196), app.scale(57), app.scale(180), app.scale(31))
	if matching, total := misakaViewportMatchingPixels(before, after, header, delta); matching != total {
		t.Errorf("[§7.2] 标题实际绘制没有与内容共同滚动：相同像素=%d/%d", matching, total)
	}
	app.scrollMisakaPane(app.skin.scrollMaximum)
	last := portableRect{}
	if result, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x0198, uintptr(len(app.paths)-1), uintptr(unsafe.Pointer(&last))); result == ^uintptr(0) {
		t.Fatal("[§7.2] 最后一个服务没有原生列表项")
	}
	procMisakaMapPoints.Call(app.controls.pathsValue, app.skin.pane, uintptr(unsafe.Pointer(&last)), 2)
	view := misakaViewportClientRect(app.skin.pane)
	if last.top < 0 || last.bottom > view.bottom || last.bottom < view.bottom-app.scale(40) {
		t.Fatalf("[§7.2] 滚动底部后最后一个服务不能完整到达：最后项=%+v 视口=%+v", last, view)
	}
	captureConfiguredProfileGUIState(t, app, "-viewport-bottom")
}

func TestGUIMisakaViewportTabRevealsFocusedControl(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	app.routeSelected = 1
	app.renderControls()
	// §7.2：只有合成窗口可见；不激活其他客户端或读取真实窗口内容。
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	procMisakaSetFocus.Call(app.controls.routeCombo)
	app.scrollMisakaPane(app.skin.scrollMaximum)
	if r := misakaViewportControlRect(t, app.controls.primaryButton, app.skin.pane); r.bottom >= 0 {
		t.Fatal("[§7.2] 键盘回归前置无效：目标按钮没有滚出视口")
	}
	if !misakaDialogMessage(portableMSG{hwnd: app.controls.routeCombo, msg: portableWMKeyDown, wParam: 0x09}) {
		t.Fatal("[§7.2] 原生 Tab 消息没有进入对话框导航")
	}
	focused, _, _ := portableUser32.NewProc("GetFocus").Call()
	if focused != app.controls.primaryButton {
		t.Fatalf("[§7.2] Tab 未到达连接按钮：焦点=%x 预期=%x", focused, app.controls.primaryButton)
	}
	r, view := misakaViewportControlRect(t, focused, app.skin.pane), misakaViewportClientRect(app.skin.pane)
	if r.top < 0 || r.bottom > view.bottom {
		t.Fatalf("[§7.2] Tab 焦点仍在视口外：控件=%+v 视口=%+v", r, view)
	}
}

func TestGUIMisakaViewportComboCentersAndOpensMultipleRows(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for index := 0; index < 7; index++ {
		name := fmt.Sprintf("demo-exit-%d", index)
		app.routeOptions = append(app.routeOptions, portableRouteOption{Label: "固定出口 · " + name, Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: name}})
	}
	app.routeSelected = 1
	app.renderControls()
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		app.scrollMisakaPane(0)
		mode, combo := guiWindowRect(t, app.controls.modeFixed), guiWindowRect(t, app.controls.routeCombo)
		if delta := absMisakaAlignment((mode.top + mode.bottom) - (combo.top + combo.bottom)); delta > 2 {
			t.Errorf("[§7.2] DPI %d 出口下拉框实际折叠中心偏移 %.1f 像素", dpi, float64(delta)/2)
		}
		var info struct {
			size              uint32
			item, button      portableRect
			state             uint32
			combo, edit, list uintptr
		}
		info.size = uint32(unsafe.Sizeof(info))
		if ok, _, err := portableUser32.NewProc("GetComboBoxInfo").Call(app.controls.routeCombo, uintptr(unsafe.Pointer(&info))); ok == 0 || info.list == 0 {
			t.Fatalf("[§7.2] 获取出口下拉框原生列表: %v", err)
		}
		procSendMessage.Call(app.controls.routeCombo, 0x014F, 1, 0)
		visible, _, _ := portableUser32.NewProc("IsWindowVisible").Call(info.list)
		drop := guiWindowRect(t, info.list)
		itemHeight, _, _ := procSendMessage.Call(app.controls.routeCombo, 0x0154, 0, 0)
		procSendMessage.Call(app.controls.routeCombo, 0x014F, 0, 0)
		if visible == 0 || itemHeight == 0 || drop.bottom-drop.top < int32(itemHeight)*3 {
			t.Errorf("[§7.2] DPI %d 出口列表未显示多行：可见=%d 高=%d 行高=%d", dpi, visible, drop.bottom-drop.top, itemHeight)
		}
	}
}

func TestGUIMisakaViewportUnchangedLayoutDoesNotMoveOrRebuild(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	app.routeSelected = 1
	app.renderControls()
	app.scrollMisakaPane(app.scale(12))
	writes := recordProfileGUIWrites(t, app)
	var original uintptr
	var panePositions int
	set := portableUser32.NewProc("SetWindowLongPtrW")
	call := portableUser32.NewProc("CallWindowProcW")
	callback := windows.NewCallback(func(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
		if message == 0x0046 {
			panePositions++
		}
		result, _, _ := call.Call(original, hwnd, uintptr(message), wParam, lParam)
		return result
	})
	original, _, _ = set.Call(app.skin.pane, ^uintptr(3), callback)
	if original == 0 {
		t.Fatal("[§7.2] 无法观察视口原生位置消息")
	}
	defer set.Call(app.skin.pane, ^uintptr(3), original)
	for index := 0; index < 5; index++ {
		app.layoutControls()
		app.renderControls()
	}
	if len(*writes) != 0 || panePositions != 0 {
		t.Fatalf("[§7.2] 无变化布局仍移动控件或重建列表：写入=%+v 视口位置消息=%d", *writes, panePositions)
	}
}

func TestGUIMisakaViewportDraftResetMatchesActualChildPositions(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, uintptr(app.scale(860)), uintptr(app.scale(340)), 0x0016)
	app.scrollMisakaPane(app.skin.scrollMaximum)
	app.brokerProfileDraft = &windowsProfileDraftDisplay{State: guiNeedsJoin, Name: "demo-draft"}
	app.renderControls()
	if app.skin.scrollY != 0 {
		t.Fatalf("[§7.2] 打开添加表单没有回到顶部：%d", app.skin.scrollY)
	}
	x, y, _ := app.misakaDraftBounds()
	r := misakaViewportControlRect(t, app.controls.draftName, app.skin.pane)
	if r.left != x+app.scale(29)-app.scale(176) || r.top != y+app.scale(51)-app.scale(40) {
		t.Fatalf("[§7.2] 添加表单重置滚动后实际输入框位置过期：%+v", r)
	}
}

func TestGUIMisakaViewportDisconnectDropsOldScrollablePathArea(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	app.scrollMisakaPane(app.skin.scrollMaximum)
	app.state = guiStopped
	app.renderControls()
	var item portableRect
	procSendMessage.Call(app.controls.pathsValue, 0x0198, 0, uintptr(unsafe.Pointer(&item)))
	list := misakaViewportClientRect(app.controls.pathsValue)
	if list.bottom > item.bottom-item.top+1 {
		t.Fatalf("[§7.2] 断开后仍保留旧多服务高度：列表=%+v 空状态行=%+v", list, item)
	}
	if app.skin.scrollY != 0 || app.skin.scrollMaximum != 0 {
		t.Fatalf("[§7.2] 断开后仍保留旧路径滚动范围：位置=%d 最大值=%d", app.skin.scrollY, app.skin.scrollMaximum)
	}
}

func TestGUIMisakaViewportPassesCoveredResizeEdgesToRoot(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		app.scrollMisakaPane(0)
		client := misakaViewportClientRect(app.hwnd)
		for _, edge := range []struct {
			name  string
			point portablePoint
			cover uintptr
			want  uintptr
		}{
			{"right", portablePoint{x: client.right - 1, y: app.scale(110)}, app.skin.pane, 11},
			{"bottom", portablePoint{x: app.scale(240), y: client.bottom - 1}, app.skin.pane, 15},
			{"bottom path list", portablePoint{x: app.scale(240), y: client.bottom - 1}, app.controls.pathsValue, 15},
			{"bottom-right", portablePoint{x: client.right - 1, y: client.bottom - 1}, app.skin.pane, 17},
		} {
			covered := misakaViewportControlRect(t, edge.cover, app.hwnd)
			if edge.point.x < covered.left || edge.point.x >= covered.right || edge.point.y < covered.top || edge.point.y >= covered.bottom {
				t.Fatalf("[§7.2] DPI %d %s 前置无效：控件没有覆盖缩放边缘", dpi, edge.name)
			}
			point := edge.point
			procMisakaMapPoints.Call(app.hwnd, 0, uintptr(unsafe.Pointer(&point)), 1)
			packed := uintptr(uint32(uint16(point.x)) | uint32(uint16(point.y))<<16)
			rootHit, _, _ := procSendMessage.Call(app.hwnd, 0x0084, 0, packed)
			coverHit, _, _ := procSendMessage.Call(edge.cover, 0x0084, 0, packed)
			if rootHit != edge.want || coverHit != ^uintptr(0) {
				t.Errorf("[§7.2] DPI %d %s 被子控件拦截：根窗口命中=%d 覆盖控件命中=%d", dpi, edge.name, rootHit, int64(coverHit))
			}
		}
		// §7.2：只有缩放边缘穿透；滚动条的可操作区域继续保留原生命中。
		point := portablePoint{x: client.right - app.scale(10), y: app.scale(110)}
		procMisakaMapPoints.Call(app.hwnd, 0, uintptr(unsafe.Pointer(&point)), 1)
		packed := uintptr(uint32(uint16(point.x)) | uint32(uint16(point.y))<<16)
		if hit, _, _ := procSendMessage.Call(app.skin.pane, 0x0084, 0, packed); hit != 7 {
			t.Errorf("[§7.2] DPI %d 边缘穿透破坏了原生滚动条命中：%d", dpi, int64(hit))
		}
	}
}

func TestGUIMisakaViewportFixedTUNActualHintCapture(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.routeOptions = append(app.routeOptions, portableRouteOption{Label: "直连", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.Direct}})
	app.routeSelected = 1
	app.paths = app.paths[:1]
	app.detail = "系统 TUN 已启用；本地 HTTP/SOCKS 代理：127.0.0.1:1080。"
	app.renderControls()
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	procRedrawWindow.Call(app.hwnd, 0, 0, 0x0181)
	misakaAssertVisibleFrame(t, app, "固定出口合成截图")
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if selection != 0 || profileGUIText(app.controls.routeCombo) != "固定出口 · demo-exit" {
		t.Fatal("[§7.2] 固定出口组合框没有选择实际快照中的出口")
	}
	// §7.2：先验证真实可见 HWND 的字形。隐藏且从未绘制的原生组合框
	// 在 WM_PRINT 中可能遗漏折叠标签，不能据此将验收截图当作真实显示。
	dc, _, _ := portableUser32.NewProc("GetDC").Call(app.controls.routeCombo)
	if dc == 0 {
		t.Fatal("[§7.2] 无法读取合成窗口的原生出口显示区")
	}
	comboBounds := misakaViewportClientRect(app.controls.routeCombo)
	visibleInk := 0
	for y := app.scale(3); y < comboBounds.bottom-app.scale(3); y++ {
		for x := app.scale(8); x < comboBounds.right-app.scale(28); x++ {
			pixel, _, _ := portableGDI32.NewProc("GetPixel").Call(dc, uintptr(x), uintptr(y))
			if pixel&255 < 150 && pixel>>8&255 < 150 && pixel>>16&255 < 150 {
				visibleInk++
			}
		}
	}
	portableUser32.NewProc("ReleaseDC").Call(app.controls.routeCombo, dc)
	if visibleInk < 20 {
		t.Fatalf("[§7.2] 原生出口组合框真实显示为空：字形像素数=%d", visibleInk)
	}
	if profileGUIText(app.controls.message) != app.detail || profileGUIStyle(app.controls.routeCombo)&portableWSVisible == 0 {
		t.Fatal("[§7.2] 固定出口或真实快照提示未呈现")
	}
	picture := readProfileGUITestWindow(t, app)
	area := misakaViewportControlRect(t, app.controls.message, app.hwnd)
	green := 0
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			pixel := picture.NRGBAAt(int(x), int(y))
			if int(pixel.G) > int(pixel.R)+30 && int(pixel.G) > int(pixel.B)+15 {
				green++
			}
		}
	}
	if green < 20 {
		t.Fatalf("[§7.2] 已连接状态的实际提示没有绿色高亮：像素数=%d", green)
	}
	captureConfiguredProfileGUIState(t, app, "-fixed-tun")
}
