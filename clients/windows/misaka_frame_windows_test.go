//go:build windows

package main

import (
	"testing"
	"unsafe"
)

func misakaCaptionTestPoint(t *testing.T, app *portableGUI, button int, nonclient bool) uintptr {
	t.Helper()
	var bounds portableRect
	procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&bounds)))
	point := portablePoint{x: bounds.right - app.scale(147-int32(button)*42), y: app.scale(20)}
	if nonclient {
		procMisakaMapPoints.Call(app.hwnd, 0, uintptr(unsafe.Pointer(&point)), 1)
	}
	return uintptr(uint32(uint16(point.x)) | uint32(uint16(point.y))<<16)
}

func TestMisakaCaptionPairsButtonsAndCancelsCapture(t *testing.T) {
	app := newProfileGUITestWindow(t)
	defer procMisakaRelease.Call()
	// §7.2：其他手势的抬起事件不得触发本窗口最大化或最小化。
	for _, event := range []struct {
		message uint32
		button  int
		nc      bool
	}{{0x0202, 1, false}, {0x00A2, 2, true}} {
		misakaCaptionMessage(app, app.hwnd, event.message, 9, misakaCaptionTestPoint(t, app, event.button, event.nc))
	}
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 {
		t.Fatal("[§7.2] 未配对的抬起事件触发了最大化")
	}
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic != 0 {
		t.Fatal("[§7.2] 未配对的抬起事件触发了最小化")
	}
	maxPoint := misakaCaptionTestPoint(t, app, 2, true)
	if _, handled := misakaCaptionMessage(app, app.hwnd, 0x00A1, 9, maxPoint); !handled || app.skin.pressedCaption != 2 {
		t.Fatal("[§7.2] 自绘标题未接管非客户区最大化按下事件")
	}
	if captured, _, _ := procMisakaGetCapture.Call(); captured != app.hwnd {
		t.Fatal("[§7.2] 标题按钮按下后未获取原生鼠标捕获")
	}
	// §7.2：移出标题栏后抬起，只取消按下状态。
	outside := uintptr(uint32(20) | uint32(uint16(app.scale(90)))<<16)
	misakaCaptionMessage(app, app.hwnd, 0x0200, 0, outside)
	misakaCaptionMessage(app, app.hwnd, 0x0202, 0, outside)
	if app.skin.pressedCaption != 0 || app.skin.hoverCaption != 0 {
		t.Fatal("[§7.2] 移出后抬起仍保留按钮按下状态")
	}
	if captured, _, _ := procMisakaGetCapture.Call(); captured == app.hwnd {
		t.Fatal("[§7.2] 移出后抬起仍保留鼠标捕获")
	}
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 {
		t.Fatal("[§7.2] 移出最大化按钮后仍激活了最大化")
	}
	misakaCaptionMessage(app, app.hwnd, 0x00A1, 9, maxPoint)
	procMisakaSetCapture.Call(app.controls.networkList)
	misakaCaptionMessage(app, app.hwnd, 0x0215, 0, app.controls.networkList)
	if app.skin.pressedCaption != 0 {
		t.Fatal("[§7.2] 失去捕获后最大化按钮仍处于按下状态")
	}
	misakaCaptionMessage(app, app.hwnd, 0x00A2, 9, maxPoint)
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 {
		t.Fatal("[§7.2] 失去捕获后的迟到抬起事件触发了最大化")
	}
	procMisakaRelease.Call()
	closePoint := misakaCaptionTestPoint(t, app, 3, false)
	misakaCaptionMessage(app, app.hwnd, 0x0201, 0, closePoint)
	misakaCaptionMessage(app, app.hwnd, 0x001F, 0, 0)
	if app.skin.pressedCaption != 0 {
		t.Fatal("[§7.2] WM_CANCELMODE 未取消标题按钮按下状态")
	}
	// §7.2：合成按钮的成对关闭手势只隐藏窗口，保留 HWND 和连接状态，
	// 不执行应用的退出操作。
	misakaCaptionMessage(app, app.hwnd, 0x0201, 0, closePoint)
	misakaCaptionMessage(app, app.hwnd, 0x0202, 0, closePoint)
	if valid, _, _ := portableUser32.NewProc("IsWindow").Call(app.hwnd); valid == 0 || app.snapshot().state != guiConnected {
		t.Fatal("[§7.2] 标题关闭按钮销毁了窗口或断开了连接")
	}
	t.Log("[§7.2] 原生捕获、按下抬起配对、移出取消、捕获丢失和关闭到托盘通过")
}

func TestMisakaCaptionHoverAndSystemGestures(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, event := range []struct {
		button int
		move   uint32
		leave  uint32
		nc     bool
	}{{1, 0x0200, 0x02A3, false}, {2, 0x00A0, 0x02A2, true}, {3, 0x0200, 0x02A3, false}} {
		misakaCaptionMessage(app, app.hwnd, event.move, 9, misakaCaptionTestPoint(t, app, event.button, event.nc))
		if app.skin.hoverCaption != event.button {
			t.Fatalf("[§7.2] 按钮 %d 未进入悬停状态", event.button)
		}
		misakaCaptionMessage(app, app.hwnd, event.leave, 0, 0)
		if app.skin.hoverCaption != 0 {
			t.Fatal("[§7.2] 鼠标离开后仍保留标题悬停高亮")
		}
	}
	for _, event := range []struct {
		message uint32
		hit     uintptr
	}{{0x00A1, 2}, {0x00A3, 2}, {0x00A1, 10}, {0x00A1, 17}} {
		if _, handled := misakaCaptionMessage(app, app.hwnd, event.message, event.hit, 0); handled {
			t.Errorf("[§7.2] 系统标题或缩放手势被拦截：%+v", event)
		}
	}
	t.Log("[§7.2] 客户区／非客户区离开后清除悬停；系统拖动、缩放和标题双击保持有效")
}

func TestMisakaInitialBoundsFitMonitorWorkArea(t *testing.T) {
	for _, work := range []portableRect{{0, 0, 1920, 1040}, {-1600, 32, 0, 880}, {50, -1080, 1416, -360}, {0, 0, 800, 560}} {
		for _, dpi := range []int32{96, 120, 144, 168, 192} {
			bounds := misakaInitialBounds(work, dpi)
			if bounds.left < work.left || bounds.top < work.top || bounds.right > work.right || bounds.bottom > work.bottom {
				t.Errorf("[§7.2] %d DPI 初始窗口超出工作区：%+v／%+v", dpi, bounds, work)
			}
			if bounds.right <= bounds.left || bounds.bottom <= bounds.top {
				t.Fatal("[§7.2] 初始窗口面积无效")
			}
		}
	}
	app := newProfileGUITestWindow(t)
	if err := fitMisakaInitialWindow(app.hwnd, app.dpi()); err != nil {
		t.Fatal(err)
	}
	monitor, _, _ := procMisakaMonitorFrom.Call(app.hwnd, 2)
	info := misakaMonitorInfo{size: uint32(unsafe.Sizeof(misakaMonitorInfo{}))}
	procMisakaMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info)))
	bounds := guiWindowRect(t, app.hwnd)
	if bounds.left < info.work.left || bounds.top < info.work.top || bounds.right > info.work.right || bounds.bottom > info.work.bottom {
		t.Fatalf("[§7.2] 原生初始窗口超出工作区：%+v／%+v", bounds, info.work)
	}
	t.Log("[§7.2] 初始窗口适配实际工作区；负坐标显示器与 100–200% DPI 边界通过")
}
