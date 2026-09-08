//go:build windows

package main

import (
	"fmt"
	"unsafe"
)

var (
	procMisakaSetCapture  = portableUser32.NewProc("SetCapture")
	procMisakaGetCapture  = portableUser32.NewProc("GetCapture")
	procMisakaRelease     = portableUser32.NewProc("ReleaseCapture")
	procMisakaTrackMouse  = portableUser32.NewProc("TrackMouseEvent")
	procMisakaMonitorFrom = portableUser32.NewProc("MonitorFromWindow")
	procMisakaMonitorInfo = portableUser32.NewProc("GetMonitorInfoW")
)

type misakaMouseTracking struct {
	size, flags uint32
	hwnd        uintptr
	hoverTime   uint32
}

type misakaMonitorInfo struct {
	size          uint32
	monitor, work portableRect
	flags         uint32
}

func misakaCaptionPoint(hwnd uintptr, packed uintptr, nonclient bool) portablePoint {
	point := portablePoint{x: int32(int16(packed)), y: int32(int16(packed >> 16))}
	if nonclient {
		procMisakaMapPoints.Call(0, hwnd, uintptr(unsafe.Pointer(&point)), 1)
	}
	return point
}

func misakaCaptionHit(app *portableGUI, hwnd uintptr, point portablePoint) int {
	var bounds portableRect
	if ok, _, _ := procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
		return 0
	}
	s := app.scale
	left := bounds.right - s(126)
	if point.y < 0 || point.y >= s(40) || point.x < left || point.x >= bounds.right {
		return 0
	}
	// §7.2：分别缩放各条边界，与非整数 DPI 下的绘制位置一致，
	// 避免三个取整后的按钮宽度累加产生偏差。
	if point.x < bounds.right-s(84) {
		return 1
	}
	if point.x < bounds.right-s(42) {
		return 2
	}
	return 3
}

func misakaInvalidateCaption(app *portableGUI, hwnd uintptr) {
	var bounds portableRect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	bounds.left, bounds.bottom = bounds.right-app.scale(126), app.scale(40)
	procInvalidateRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)), 0)
}

func misakaCaptionHover(app *portableGUI, hwnd uintptr, button int) {
	if app.skin.hoverCaption != button {
		app.skin.hoverCaption = button
		misakaInvalidateCaption(app, hwnd)
	}
}

func misakaCancelCaption(app *portableGUI, hwnd uintptr, release bool) {
	changed := app.skin.pressedCaption != 0 || app.skin.hoverCaption != 0
	app.skin.pressedCaption, app.skin.hoverCaption = 0, 0
	if release {
		if capture, _, _ := procMisakaGetCapture.Call(); capture == hwnd {
			procMisakaRelease.Call()
		}
	}
	if changed {
		misakaInvalidateCaption(app, hwnd)
	}
}

// §7.2：仅接管三个自绘标题按钮；标题拖动、边缘缩放与标题双击交给系统。
func misakaCaptionMessage(app *portableGUI, hwnd uintptr, message uint32, wParam, lParam uintptr) (uintptr, bool) {
	if app == nil || app.skin == nil || app.skin.closed {
		return 0, false
	}
	switch message {
	case 0x0201, 0x0203, 0x00A1, 0x00A3: // §7.2：客户区／非客户区左键按下或双击。
		nonclient := message == 0x00A1 || message == 0x00A3
		if nonclient && wParam != 9 { // §7.2：仅处理最大化按钮，保留系统拖动和缩放。
			return 0, false
		}
		button := misakaCaptionHit(app, hwnd, misakaCaptionPoint(hwnd, lParam, nonclient))
		if button == 0 || nonclient && button != 2 {
			return 0, nonclient
		}
		app.skin.pressedCaption = button
		misakaCaptionHover(app, hwnd, button)
		procMisakaSetCapture.Call(hwnd)
		if capture, _, _ := procMisakaGetCapture.Call(); capture != hwnd {
			misakaCancelCaption(app, hwnd, false)
		}
		misakaInvalidateCaption(app, hwnd)
		// §7.2：接管非客户区按下事件，避免默认过程再次执行最大化按钮跟踪。
		return 0, true
	case 0x0202, 0x00A2: // §7.2：鼠标捕获可能把非客户区按下转换为客户区抬起。
		nonclient := message == 0x00A2
		button := misakaCaptionHit(app, hwnd, misakaCaptionPoint(hwnd, lParam, nonclient))
		pressed := app.skin.pressedCaption
		if pressed == 0 {
			return 0, button != 0 || nonclient && wParam == 9
		}
		capture, _, _ := procMisakaGetCapture.Call()
		activate := capture == hwnd && button == pressed
		misakaCancelCaption(app, hwnd, true)
		if activate {
			switch pressed {
			case 1:
				procShowWindow.Call(hwnd, 6) // §7.2：最小化。
			case 2:
				toggleMisakaMaximize(hwnd)
			case 3:
				procShowWindow.Call(hwnd, portableSWHide) // §7.2：隐藏到托盘，保留连接。
			}
		}
		return 0, true
	case 0x0200, 0x00A0: // §7.2：客户区／非客户区鼠标移动。
		nonclient := message == 0x00A0
		button := misakaCaptionHit(app, hwnd, misakaCaptionPoint(hwnd, lParam, nonclient))
		if nonclient && wParam != 9 {
			button = 0 // §7.2：按钮旁的缩放边缘仍由系统处理。
		}
		misakaCaptionHover(app, hwnd, button)
		if button != 0 {
			tracking := misakaMouseTracking{flags: 2, hwnd: hwnd} // §7.2：跟踪鼠标离开。
			tracking.size = uint32(unsafe.Sizeof(tracking))
			if nonclient {
				tracking.flags |= 0x10 // §7.2：跟踪非客户区。
			}
			procMisakaTrackMouse.Call(uintptr(unsafe.Pointer(&tracking)))
		}
		// §7.2：保留默认过程的最大化悬停处理，以支持 Windows 贴靠布局。
		return 0, false
	case 0x02A3, 0x02A2: // §7.2：鼠标离开客户区或非客户区。
		misakaCaptionHover(app, hwnd, 0)
		return 0, false
	case 0x0215: // §7.2：失去捕获后，迟到的抬起事件不得激活按钮。
		if app.skin.pressedCaption != 0 && lParam != hwnd {
			misakaCancelCaption(app, hwnd, false)
		}
		return 0, false
	case 0x001F: // §7.2：取消当前鼠标操作。
		if app.skin.pressedCaption != 0 {
			misakaCancelCaption(app, hwnd, true)
		}
		return 0, false
	case 0x0006: // §7.2：窗口失去激活状态。
		if wParam&0xffff == 0 {
			misakaCancelCaption(app, hwnd, app.skin.pressedCaption != 0)
		}
	case 0x0018: // §7.2：窗口显示状态变化。
		if wParam == 0 {
			misakaCancelCaption(app, hwnd, app.skin.pressedCaption != 0)
		}
	case portableWMDestroy:
		misakaCancelCaption(app, hwnd, app.skin.pressedCaption != 0)
	}
	return 0, false
}

func misakaInitialBounds(work portableRect, dpi int32) portableRect {
	if dpi <= 0 {
		dpi = 96
	}
	width := min(860*dpi/96, max(1, work.right-work.left))
	height := min(600*dpi/96, max(1, work.bottom-work.top))
	x := work.left + (work.right-work.left-width)/2
	y := work.top + (work.bottom-work.top-height)/2
	return misakaRect(x, y, width, height)
}

// §7.2：在隐藏 HWND 创建后、首次显示前执行一次。初始边界遵循当前
// 显示器工作区、任务栏与 DPI；不修改显示设置或其他窗口。
func fitMisakaInitialWindow(hwnd uintptr, dpi int32) error {
	monitor, _, err := procMisakaMonitorFrom.Call(hwnd, 2)
	if monitor == 0 {
		return fmt.Errorf("[§7.2] 定位初始窗口的显示器: %w", err)
	}
	info := misakaMonitorInfo{}
	info.size = uint32(unsafe.Sizeof(info))
	if ok, _, err := procMisakaMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return fmt.Errorf("[§7.2] 读取初始窗口工作区: %w", err)
	}
	if info.work.right <= info.work.left || info.work.bottom <= info.work.top {
		return fmt.Errorf("[§7.2] 初始显示器工作区无效")
	}
	bounds := misakaInitialBounds(info.work, dpi)
	if ok, _, err := procSetWindowPos.Call(hwnd, 0, uintptr(bounds.left), uintptr(bounds.top),
		uintptr(bounds.right-bounds.left), uintptr(bounds.bottom-bounds.top), portableSWPNoZOrder|portableSWPNoActivate); ok == 0 {
		return fmt.Errorf("[§7.2] 将初始窗口定位到工作区: %w", err)
	}
	return nil
}
