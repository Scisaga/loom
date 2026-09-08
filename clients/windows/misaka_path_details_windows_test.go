//go:build windows

package main

import (
	"strings"
	"testing"
	"unsafe"

	"loom/internal/clientreport"
)

func misakaDetailInkBounds(pixels []byte, width int32, area portableRect) (portableRect, int) {
	ink := portableRect{left: area.right, top: area.bottom, right: area.left, bottom: area.top}
	count := 0
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			pixel := misakaCanvasTestPixel(pixels, width, x, y)
			if pixel>>16 >= 210 || pixel>>8&255 >= 210 || pixel&255 >= 210 {
				continue
			}
			count++
			ink.left, ink.top = min(ink.left, x), min(ink.top, y)
			ink.right, ink.bottom = max(ink.right, x+1), max(ink.bottom, y+1)
		}
	}
	return ink, count
}

func TestGUIMisakaPathDetailsFollowActualReasonLinesWithoutBlankRow(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.paths = app.paths[:1]
	app.pathsExpanded = true
	long := strings.Repeat("演示路径根据入口与服务器观测选择，保留各段测量的来源与时间。", 5) + "\nDEMO_REASON_END"
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		for _, reason := range []string{"根据入口与服务器观测选择当前路径", long} {
			var withoutScope int32
			for _, scoped := range []bool{false, true} {
				app.paths[0].Reason = reason
				app.paths[0].UpdatedAt = "demo-read-time"
				app.paths[0].DecisionScope = ""
				if scoped {
					app.paths[0].DecisionScope = strings.Repeat("d", 64)
				}
				app.renderControls()
				app.layoutControls()
				var item portableRect
				procSendMessage.Call(app.controls.pathsValue, 0x0198, 0, uintptr(unsafe.Pointer(&item)))
				if item.bottom-item.top != app.scale(app.misakaPathHeight()) {
					t.Fatalf("[§7.2] DPI %d 原生行高没有同步原因换行：%+v", dpi, item)
				}
				item = misakaRect(0, 0, item.right-item.left, item.bottom-item.top)
				dc, pixels := misakaCanvasTestDC(t, item.right, item.bottom)
				draw := portableDrawItem{hwndItem: app.controls.pathsValue, dc: dc, rect: item, itemID: 0}
				procSendMessage.Call(app.skin.pane, portableWMDrawItem, 0, uintptr(unsafe.Pointer(&draw)))
				portableGDI32.NewProc("GdiFlush").Call()
				details := app.misakaPathDetails(app.paths[0], item.right-app.scale(3)-2-app.scale(36))
				place := func(r portableRect) portableRect {
					x, y := 1+app.scale(18), 1+app.scale(142)
					return portableRect{left: r.left + x, top: r.top + y, right: r.right + x, bottom: r.bottom + y}
				}
				reasonInk, reasonCount := misakaDetailInkBounds(pixels, item.right, place(details.reasonBounds))
				readInk, readCount := misakaDetailInkBounds(pixels, item.right, place(details.readBounds))
				if reasonCount < 10 || readCount < 10 {
					t.Fatalf("[§7.2] DPI %d 原因或读取时间未绘出：原因=%d 读取=%d", dpi, reasonCount, readCount)
				}
				if gap := readInk.top - reasonInk.bottom; gap < 0 || gap > app.scale(18) {
					t.Errorf("[§7.2] DPI %d 读取与原因的实际字形之间仍有空行或重叠：间距=%d", dpi, gap)
				}
				last := readInk
				if scoped {
					scopeInk, scopeCount := misakaDetailInkBounds(pixels, item.right, place(details.scopeBounds))
					if scopeCount < 10 || scopeInk.top-readInk.bottom > app.scale(12) {
						t.Fatalf("[§7.2] DPI %d 决策范围未紧接读取时间完整绘出", dpi)
					}
					last = scopeInk
					if item.bottom <= withoutScope {
						t.Fatalf("[§7.2] DPI %d 无scope时仍虚占同样行高", dpi)
					}
				} else {
					withoutScope = item.bottom
				}
				cardBottom := item.bottom
				if gap := cardBottom - last.bottom; gap < app.scale(6) || gap > app.scale(28) {
					t.Errorf("[§7.2] DPI %d 卡片末尾没有按详情内容收紧：尾部空白=%d", dpi, gap)
				}
				if reason == long {
					endLine := place(details.reasonBounds)
					endLine.top = endLine.bottom - app.scale(16)
					if _, count := misakaDetailInkBounds(pixels, item.right, endLine); count < 10 {
						t.Fatalf("[§7.2] DPI %d 长原因的最后一行被裁切", dpi)
					}
				}
			}
		}
	}
}

func TestGUIMisakaPathDetailsResizeUpdatesNativeRowsAndScrollReach(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.paths = app.paths[:1]
	app.pathsExpanded = true
	app.paths[0].Reason = strings.Repeat("演示原因按当前窗口宽度换行，入口与服务器观测用于当前选择。", 8)
	app.paths[0].DecisionScope = strings.Repeat("d", 64)
	app.renderControls()
	var wide int32
	for _, width := range []int32{1000, 720, 1000} {
		procSetWindowPos.Call(app.hwnd, 0, 0, 0, uintptr(app.scale(width)), uintptr(app.scale(420)), 0x0016)
		var item portableRect
		procSendMessage.Call(app.controls.pathsValue, 0x0198, 0, uintptr(unsafe.Pointer(&item)))
		height := item.bottom - item.top
		if width == 1000 && wide == 0 {
			wide = height
		} else if width == 1000 && height != wide || width == 720 && height <= wide {
			t.Fatalf("[§7.2] 宽度 %d 没有同步详情原生行高：实际=%d 宽窗=%d", width, height, wide)
		}
		app.scrollMisakaPane(app.skin.scrollMaximum)
		procSendMessage.Call(app.controls.pathsValue, 0x0198, 0, uintptr(unsafe.Pointer(&item)))
		procMisakaMapPoints.Call(app.controls.pathsValue, app.skin.pane, uintptr(unsafe.Pointer(&item)), 2)
		view := misakaViewportClientRect(app.skin.pane)
		if gap := view.bottom - item.bottom; gap < app.scale(19) || gap > app.scale(21) {
			t.Fatalf("[§7.2] 宽度 %d 详情末尾不能按正确滚动范围到达：间距=%d", width, gap)
		}
	}
}

func TestGUIMisakaPathDetailsCompactSyntheticCapture(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.paths = app.paths[:1]
	app.pathsExpanded = true
	app.routeSelected = 1
	app.detail = "系统 TUN 已启用；本地 HTTP/SOCKS 代理：127.0.0.1:1080。"
	app.paths[0].UpdatedAt = "demo-read-time"
	app.renderControls()
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	procRedrawWindow.Call(app.hwnd, 0, 0, 0x0181)
	misakaAssertVisibleFrame(t, app, "紧凑路径详情")
	captureConfiguredProfileGUIState(t, app, "-detail-short")
	app.paths[0].Reason = strings.Repeat("演示路径根据入口与服务器观测选择，保留各段测量的来源与时间。", 4)
	app.paths[0].DecisionScope = strings.Repeat("d", 64)
	app.renderControls()
	app.scrollMisakaPane(app.skin.scrollMaximum)
	captureConfiguredProfileGUIState(t, app, "-detail-long-scope")
}

// §7.2 / §16.1：使用真实摘要投影验证单样本为中性色，统计和比较边界完整换行。
func TestGUIMisakaPathDetailsRenderLimitedMeasurementEvidence(t *testing.T) {
	app := newProfileGUITestWindow(t)
	latency := 37
	app.paths = windowsPathsFromReport(&clientreport.AgentState{Selections: []clientreport.AgentSelection{{
		Declaration: "demo-service", Candidate: "demo-path", Chain: []string{"demo-entry", "demo-exit"},
		UpdatedAt: "demo-read-time", Reason: "当前候选仅有一次近期探测，继续比较其余授权候选",
		Health: &clientreport.AgentCandidateHealth{Candidates: 12, RecentSuccess: 1, RecentFailed: 1, Unknown: 9, Stale: 1,
			SelectedState: "success", SelectedSamples: 1, SelectedP50MS: &latency, SelectedP95MS: &latency, BestP50MS: &latency},
	}}})
	app.pathsExpanded = true
	for _, dpi := range []int32{96, 144, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		app.renderControls()
		app.layoutControls()
		var item portableRect
		procSendMessage.Call(app.controls.pathsValue, 0x0198, 0, uintptr(unsafe.Pointer(&item)))
		item = misakaRect(0, 0, item.right-item.left, item.bottom-item.top)
		dc, pixels := misakaCanvasTestDC(t, item.right, item.bottom)
		draw := portableDrawItem{hwndItem: app.controls.pathsValue, dc: dc, rect: item, itemID: 0}
		procSendMessage.Call(app.skin.pane, portableWMDrawItem, 0, uintptr(unsafe.Pointer(&draw)))
		portableGDI32.NewProc("GdiFlush").Call()
		badgeX, badgeY := item.right-app.scale(3)-1-app.scale(92)+app.scale(7), 1+app.scale(20)
		if got := misakaCanvasTestPixel(pixels, item.right, badgeX, badgeY); got != 0xF4F6F5 {
			t.Fatalf("[§16.1] DPI %d 单样本徽标没有使用中性色：%06x", dpi, got)
		}
		details := app.misakaPathDetails(app.paths[0], item.right-app.scale(3)-2-app.scale(36))
		last := details.bestBounds
		last.left, last.right = last.left+1+app.scale(18), last.right+1+app.scale(18)
		last.top, last.bottom = last.top+1+app.scale(142), last.bottom+1+app.scale(142)
		last.top = last.bottom - app.scale(16)
		if _, count := misakaDetailInkBounds(pixels, item.right, last); count < 10 {
			t.Fatalf("[§16.1] DPI %d 比较边界最后一行被裁切", dpi)
		}
		if dpi == 144 {
			captureConfiguredProfileGUIState(t, app, "-measurement-evidence")
		}
	}
}
