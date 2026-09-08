//go:build windows

package main

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
)

func misakaWheelPoint(r portableRect) uintptr {
	return uintptr(uint32(uint16((r.left+r.right)/2)) | uint32(uint16((r.top+r.bottom)/2))<<16)
}

func TestGUIMisakaRouteWheelOutsidePopupScrollsPageWithoutSelecting(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	for index := 0; index < 12; index++ {
		name := fmt.Sprintf("demo-wheel-%d", index)
		app.routeOptions = append(app.routeOptions, portableRouteOption{Label: name, Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: name}})
	}
	app.renderControls()
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
	dropped, _, _ := procSendMessage.Call(app.controls.routeCombo, 0x0157, 0, 0)
	if dropped == 0 {
		t.Fatal("[§7.2] 回归前置：出口菜单未打开")
	}
	pane := guiWindowRect(t, app.skin.pane)
	point := misakaWheelPoint(misakaRect(pane.left+app.scale(20), pane.top+app.scale(350), app.scale(40), app.scale(20)))
	procSendMessage.Call(app.controls.routeCombo, 0x020A, uintptr(uint32(0xff88)<<16), point)
	if app.skin.scrollY == 0 {
		t.Error("[§7.2] 鼠标已在页面，焦点仍让出口框吞掉滚轮")
	}
	dropped, _, _ = procSendMessage.Call(app.controls.routeCombo, 0x0157, 0, 0)
	if dropped != 0 || app.skin.route.picker || app.skin.route.pending != nil || app.routeSelected != 0 {
		t.Error("[§7.2] 页面滚动未撤销出口编辑，或误提交出口")
	}
}

func TestGUIMisakaScrollDoesNotMeasureRowsAgain(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	app.pathsExpanded = true
	app.renderControls()
	var reads int
	set := portableUser32.NewProc("SetWindowLongPtrW")
	call := portableUser32.NewProc("CallWindowProcW")
	var original uintptr
	callback := windows.NewCallback(func(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
		if message == 0x01A1 || message == portableLBSetItemHeight {
			reads++
		}
		result, _, _ := call.Call(original, hwnd, uintptr(message), wParam, lParam)
		return result
	})
	original, _, _ = set.Call(app.controls.pathsValue, ^uintptr(3), callback)
	if original == 0 {
		t.Fatal("[§7.2] 无法记录路径列表高度消息")
	}
	defer set.Call(app.controls.pathsValue, ^uintptr(3), original)
	start := time.Now()
	for index := 0; index < 20; index++ {
		app.scrollMisakaPane(app.scale(int32(index%2+1) * 24))
	}
	t.Logf("20 次详情滚动耗时 %s；行高读写 %d", time.Since(start), reads)
	if reads != 0 {
		t.Errorf("[§7.2] 纯滚动仍重复访问行高 %d 次", reads)
	}
}

func TestGUIMisakaRouteWheelInsidePopupKeepsNativeListNavigation(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	for index := 0; index < 80; index++ {
		name := fmt.Sprintf("demo-menu-%d", index)
		app.routeOptions = append(app.routeOptions, portableRouteOption{Label: name, Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: name}})
	}
	app.renderControls()
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0057)
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
	list := app.skin.route.list
	if list == 0 {
		t.Fatal("[§7.2] 出口原生列表不存在")
	}
	point := misakaWheelPoint(guiWindowRect(t, list))
	for _, receiver := range []uintptr{list, app.controls.routeCombo} {
		procSendMessage.Call(list, 0x0197, 0, 0) // LB_SETTOPINDEX
		before, _, _ := procSendMessage.Call(list, 0x018E, 0, 0)
		for step := 0; step < 12; step++ {
			procSendMessage.Call(receiver, 0x020A, uintptr(uint32(0xff88)<<16), point)
		}
		after, _, _ := procSendMessage.Call(list, 0x018E, 0, 0)
		dropped, _, _ := procSendMessage.Call(app.controls.routeCombo, 0x0157, 0, 0)
		if dropped == 0 || after <= before || app.skin.scrollY != 0 || app.skin.route.pending != nil || app.routeSelected != 0 {
			t.Fatalf("[§7.2] 菜单内滚轮丢失原生滚动或改变实际选路：菜单=%d 首项=%d→%d 页面=%d", dropped, before, after, app.skin.scrollY)
		}
	}
	pane := guiWindowRect(t, app.skin.pane)
	point = misakaWheelPoint(misakaRect(pane.left+app.scale(20), pane.top+app.scale(350), app.scale(40), app.scale(20)))
	procSendMessage.Call(list, 0x020A, uintptr(uint32(0xff88)<<16), point)
	dropped, _, _ := procSendMessage.Call(app.controls.routeCombo, 0x0157, 0, 0)
	if dropped != 0 || app.skin.scrollY == 0 || app.skin.route.picker || app.skin.route.pending != nil {
		t.Fatal("[§7.2] 弹出列表捕获滚轮后，没有按鼠标位置交还页面")
	}
}

func TestGUIMisakaScrolledPixelsMatchCompleteRepaint(t *testing.T) {
	app := newMisakaViewportTestWindow(t)
	// §7.2：只读取本测试窗口的 DC；先验收正常 WM_PAINT，再与完整重绘比较。
	procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0053)
	capture := func() []byte {
		view := misakaViewportClientRect(app.skin.pane)
		memory, pixels := misakaCanvasTestDC(t, view.right, view.bottom)
		dc, _, _ := portableUser32.NewProc("GetDC").Call(app.skin.pane)
		if dc == 0 {
			t.Fatal("[§7.2] 无法读取测试视口")
		}
		ok, _, _ := portableGDI32.NewProc("BitBlt").Call(memory, 0, 0, uintptr(view.right), uintptr(view.bottom), dc, 0, 0, 0x00CC0020)
		portableUser32.NewProc("ReleaseDC").Call(app.skin.pane, dc)
		portableGDI32.NewProc("GdiFlush").Call()
		if ok == 0 {
			t.Fatal("[§7.2] 无法复制测试视口")
		}
		return append([]byte(nil), pixels...)
	}
	for _, expanded := range []bool{false, true} {
		app.pathsExpanded = expanded
		app.updateMisakaPaths(app.snapshot(), true)
		app.layoutControls()
		for _, position := range []int32{24, 280, 12} {
			app.scrollMisakaPane(0)
			procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
			app.scrollMisakaPane(app.scale(position))
			misakaAssertVisibleFrame(t, app, "菜单关闭后滚动")
			normal := capture()
			procRedrawWindow.Call(app.skin.pane, 0, 0, 0x0185)
			misakaAssertVisibleFrame(t, app, "完整参考重绘")
			fresh := capture()
			changed := 0
			for i := 0; i < len(normal); i += 4 {
				if normal[i] != fresh[i] || normal[i+1] != fresh[i+1] || normal[i+2] != fresh[i+2] {
					changed++
				}
			}
			if changed != 0 {
				t.Errorf("[§7.2] 详情=%v 位置=%d：正常滚动仍有 %d 个像素需要额外刷新", expanded, position, changed)
			}
		}
	}
}
