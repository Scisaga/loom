//go:build windows

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type misakaScrollInfo struct {
	size, mask       uint32
	minimum, maximum int32
	page             uint32
	position, track  int32
}

var misakaPaneBaseCallback = windows.NewCallback(func(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	result, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return result
})

func (app *portableGUI) createMisakaPane(instance uintptr) error {
	class, _ := windows.UTF16PtrFromString("LoomMisakaViewport")
	cursor, _, _ := procLoadCursor.Call(0, portableIDCArrow)
	wc := portableWNDClassEx{size: uint32(unsafe.Sizeof(portableWNDClassEx{})), wndProc: misakaPaneBaseCallback, instance: instance, cursor: cursor, className: class}
	if atom, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 && err != windows.ERROR_CLASS_ALREADY_EXISTS {
		return fmt.Errorf("[§7.2] 注册右侧滚动视口: %w", err)
	}
	defer runtime.KeepAlive(wc)
	// §7.2：右侧只有一个滚动视口；原生子控件共同合成，避免状态切换露出分步绘制。
	pane, _, err := procCreateWindowEx.Call(0x02010000, uintptr(unsafe.Pointer(class)), 0,
		portableWSChild|portableWSVisible|portableWSVScroll|0x02000000|0x04000000, 0, 0, 10, 10, app.hwnd, 0, instance, 0)
	if pane == 0 {
		return fmt.Errorf("[§7.2] 创建右侧滚动视口: %w", err)
	}
	app.skin.pane = pane
	if ok, _, err := procMisakaSetSubclass.Call(pane, misakaSubclassCallback, 1, app.hwnd); ok == 0 {
		return fmt.Errorf("[§7.2] 初始化右侧滚动视口: %w", err)
	}
	return nil
}

func (app *portableGUI) misakaContentEnd() int32 {
	var r portableRect
	procGetClientRect.Call(app.skin.pane, uintptr(unsafe.Pointer(&r)))
	return app.scale(176) + r.right - app.scale(20)
}

// §7.2：几何没有变化时不发送位置消息；更新仅使旧、新控件位置失效。
func moveMisakaControl(hwnd uintptr, parent uintptr, r portableRect) bool {
	var old portableRect
	procMisakaGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&old)))
	procMisakaMapPoints.Call(0, parent, uintptr(unsafe.Pointer(&old)), 2)
	if old == r {
		return false
	}
	procMoveWindow.Call(hwnd, uintptr(r.left), uintptr(r.top), uintptr(max(1, r.right-r.left)), uintptr(max(1, r.bottom-r.top)), 0)
	procInvalidateRect.Call(parent, uintptr(unsafe.Pointer(&old)), 0)
	procInvalidateRect.Call(parent, uintptr(unsafe.Pointer(&r)), 0)
	procInvalidateRect.Call(hwnd, 0, 0)
	return true
}

func (app *portableGUI) updateMisakaScroll(content int32) {
	var r portableRect
	procGetClientRect.Call(app.skin.pane, uintptr(unsafe.Pointer(&r)))
	app.skin.scrollMaximum = max(0, content-r.bottom)
	app.skin.scrollY = min(max(0, app.skin.scrollY), app.skin.scrollMaximum)
	if app.skin.scrollContent == content && app.skin.scrollPage == r.bottom && app.skin.scrollPosition == app.skin.scrollY {
		return
	}
	app.skin.scrollContent, app.skin.scrollPage, app.skin.scrollPosition = content, r.bottom, app.skin.scrollY
	info := misakaScrollInfo{mask: 7, maximum: max(0, content-1), page: uint32(max(1, r.bottom)), position: app.skin.scrollY}
	info.size = uint32(unsafe.Sizeof(info))
	portableUser32.NewProc("SetScrollInfo").Call(app.skin.pane, 1, uintptr(unsafe.Pointer(&info)), 1)
}

func (app *portableGUI) scrollMisakaPane(position int32) {
	next := min(max(0, position), app.skin.scrollMaximum)
	if next == app.skin.scrollY {
		return
	}
	dropped, _, _ := procSendMessage.Call(app.controls.routeCombo, 0x0157, 0, 0) // CB_GETDROPPEDSTATE
	if dropped != 0 || app.skin.route.picker || app.routeFiltering {
		app.cancelMisakaRoutePicker()
	}
	delta := app.skin.scrollY - next
	app.skin.scrollY = next
	// §7.2：滚动只平移已有控件，不重新测量所有服务和详情段落。
	if !app.moveMisakaPaneChildren(delta) {
		app.layoutControls()
	} else {
		app.updateMisakaScroll(app.skin.scrollContent)
	}
	// §7.2：批量移动结束后同时刷新背景与子控件，清除弹出层和旧位置残影。
	procRedrawWindow.Call(app.skin.pane, 0, 0, portableRDWInvalidate|portableRDWAllChildren|0x0004)
}

func (app *portableGUI) moveMisakaPaneChildren(delta int32) bool {
	deferPos := portableUser32.NewProc("DeferWindowPos")
	batch, _, _ := portableUser32.NewProc("BeginDeferWindowPos").Call(uintptr(len(app.controls.all())))
	if batch == 0 {
		return false
	}
	app.skin.layingOut = true
	defer func() { app.skin.layingOut = false }()
	for _, hwnd := range app.controls.all() {
		parent, _, _ := portableUser32.NewProc("GetParent").Call(hwnd)
		style, _, _ := procMisakaGetWindowLong.Call(hwnd, ^uintptr(15))
		if parent != app.skin.pane || style&portableWSVisible == 0 {
			continue
		}
		var r portableRect
		procMisakaGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		procMisakaMapPoints.Call(0, parent, uintptr(unsafe.Pointer(&r)), 2)
		batch, _, _ = deferPos.Call(batch, hwnd, 0, uintptr(r.left), uintptr(r.top+delta), 0, 0,
			0x001D) // NOSIZE | NOZORDER | NOREDRAW | NOACTIVATE
		if batch == 0 {
			return false
		}
	}
	ok, _, _ := portableUser32.NewProc("EndDeferWindowPos").Call(batch)
	return ok != 0
}

func (app *portableGUI) revealMisakaControl(hwnd uintptr) {
	if app.skin.layingOut {
		return
	}
	parent, _, _ := portableUser32.NewProc("GetParent").Call(hwnd)
	if parent != app.skin.pane {
		return
	}
	var r, view portableRect
	procMisakaGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	procMisakaMapPoints.Call(0, parent, uintptr(unsafe.Pointer(&r)), 2)
	procGetClientRect.Call(parent, uintptr(unsafe.Pointer(&view)))
	if r.top < 0 {
		app.scrollMisakaPane(app.skin.scrollY + r.top - app.scale(12))
	} else if r.bottom > view.bottom {
		app.scrollMisakaPane(app.skin.scrollY + r.bottom - view.bottom + app.scale(12))
	}
}

func (app *portableGUI) misakaPaneMessage(hwnd uintptr, message uint32, wParam, lParam uintptr) (uintptr, bool) {
	if message == 0x0084 { // §7.2：视口及超出视口的长列表不能截获根窗口的缩放边缘。
		parent, _, _ := portableUser32.NewProc("GetParent").Call(hwnd)
		if hwnd == app.skin.pane || parent == app.skin.pane {
			hit, _, _ := procSendMessage.Call(app.hwnd, uintptr(message), wParam, lParam)
			if hit >= 10 && hit <= 17 {
				return ^uintptr(0), true // HTTRANSPARENT：继续查找同线程的根窗口。
			}
		}
	}
	if hwnd != app.skin.pane {
		return 0, false
	}
	switch message {
	case 0x0014:
		return 1, true
	case 0x000F:
		var paint struct {
			dc              uintptr
			erase           int32
			rect            portableRect
			restore, update int32
			reserved        [32]byte
		}
		dc, _, _ := procMisakaBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		app.paintMisakaPane(dc)
		procMisakaEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		return 0, true
	case 0x0318:
		app.paintMisakaPane(wParam)
		return 0, true
	case portableWMCommand, portableWMDrawItem, portableWMMeasureItem, portableWMCtlColorStatic, 0x0133, 0x0134:
		result, _, _ := procSendMessage.Call(app.hwnd, uintptr(message), wParam, lParam)
		return result, true
	case 0x0115: // WM_VSCROLL：只滚动完整右面板。
		var view portableRect
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&view)))
		next := app.skin.scrollY
		switch wParam & 0xffff {
		case 0:
			next -= app.scale(28)
		case 1:
			next += app.scale(28)
		case 2:
			next -= view.bottom - app.scale(28)
		case 3:
			next += view.bottom - app.scale(28)
		case 4, 5:
			info := misakaScrollInfo{mask: 0x10}
			info.size = uint32(unsafe.Sizeof(info))
			portableUser32.NewProc("GetScrollInfo").Call(hwnd, 1, uintptr(unsafe.Pointer(&info)))
			next = info.track
		case 6:
			next = 0
		case 7:
			next = app.skin.scrollMaximum
		}
		app.scrollMisakaPane(next)
		return 0, true
	case 0x020A: // WM_MOUSEWHEEL：高分辨率滚轮的余数跨消息保留。
		app.skin.wheelDelta += int32(int16(wParam >> 16))
		steps := app.skin.wheelDelta / 120
		app.skin.wheelDelta %= 120
		app.scrollMisakaPane(app.skin.scrollY - steps*app.scale(72))
		return 0, true
	}
	return 0, false
}
