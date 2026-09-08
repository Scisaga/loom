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
	point := portablePoint{x: bounds.right - app.scale(105-int32(button)*42), y: app.scale(20)}
	if nonclient {
		procMisakaMapPoints.Call(app.hwnd, 0, uintptr(unsafe.Pointer(&point)), 1)
	}
	return uintptr(uint32(uint16(point.x)) | uint32(uint16(point.y))<<16)
}

func TestMisakaCaptionPairsButtonsAndCancelsCapture(t *testing.T) {
	app := newProfileGUITestWindow(t)
	defer procMisakaRelease.Call()
	// §7.2：其他手势的抬起事件不得触发本窗口最小化或关闭。
	for _, event := range []struct {
		message uint32
		button  int
		nc      bool
	}{{0x0202, 1, false}, {0x00A2, 2, true}} {
		misakaCaptionMessage(app, app.hwnd, event.message, 20, misakaCaptionTestPoint(t, app, event.button, event.nc))
	}
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 {
		t.Fatal("[§7.2] 未配对的抬起事件触发了最大化")
	}
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic != 0 {
		t.Fatal("[§7.2] 未配对的抬起事件触发了最小化")
	}
	minPoint := misakaCaptionTestPoint(t, app, 1, true)
	if _, handled := misakaCaptionMessage(app, app.hwnd, 0x00A1, 8, minPoint); !handled || app.skin.pressedCaption != 1 {
		t.Fatal("[§7.2] 自绘标题未接管非客户区最小化按下事件")
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
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic != 0 {
		t.Fatal("[§7.2] 移出最小化按钮后仍改变了窗口状态")
	}
	misakaCaptionMessage(app, app.hwnd, 0x00A1, 8, minPoint)
	procMisakaSetCapture.Call(app.controls.networkList)
	misakaCaptionMessage(app, app.hwnd, 0x0215, 0, app.controls.networkList)
	if app.skin.pressedCaption != 0 {
		t.Fatal("[§7.2] 失去捕获后最小化按钮仍处于按下状态")
	}
	misakaCaptionMessage(app, app.hwnd, 0x00A2, 8, minPoint)
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic != 0 {
		t.Fatal("[§7.2] 失去捕获后的迟到抬起事件触发了最小化")
	}
	procMisakaRelease.Call()
	closePoint := misakaCaptionTestPoint(t, app, 2, false)
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
	}{{1, 0x0200, 0x02A3, false}, {2, 0x00A0, 0x02A2, true}} {
		misakaCaptionMessage(app, app.hwnd, event.move, 20, misakaCaptionTestPoint(t, app, event.button, event.nc))
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
	}{{0x00A1, 2}, {0x00A1, 10}, {0x00A1, 17}} {
		if _, handled := misakaCaptionMessage(app, app.hwnd, event.message, event.hit, 0); handled {
			t.Errorf("[§7.2] 系统标题或缩放手势被拦截：%+v", event)
		}
	}
	t.Log("[§7.2] 客户区／非客户区离开后清除悬停；系统拖动、缩放保持有效")
}

func TestMisakaCaptionHasNoMaximizeAndRestoresOnlyMinimizedWindow(t *testing.T) {
	app := newProfileGUITestWindow(t)
	if profileGUIStyle(app.hwnd)&portableWSMaximizeBox != 0 {
		t.Fatal("[§7.2] 窗口仍向系统声明最大化按钮")
	}
	// §7.2：测试只操作屏幕外的合成 HWND，不启动真实客户端或数据面。
	procSetWindowPos.Call(app.hwnd, 0, ^uintptr(29999), ^uintptr(29999), 0, 0, 0x0015)
	want := guiWindowRect(t, app.hwnd)
	procSendMessage.Call(app.hwnd, 0x00A3, 2, 0)
	procSendMessage.Call(app.hwnd, 0x00A1, 9, misakaCaptionTestPoint(t, app, 1, true))
	procSendMessage.Call(app.hwnd, 0x00A2, 9, misakaCaptionTestPoint(t, app, 1, true))
	procSendMessage.Call(app.hwnd, 0x0112, 0xF030, 0)
	procSendMessage.Call(app.hwnd, 0x0112, 0xF032, 0)
	procSendMessage.Call(app.hwnd, 0x0112, 0xF120, 0)
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 || guiWindowRect(t, app.hwnd) != want {
		t.Fatal("[§7.2] 标题双击或系统最大化／还原命令改变了普通窗口")
	}
	point := misakaCaptionTestPoint(t, app, 1, false)
	procSendMessage.Call(app.hwnd, 0x0201, 0, point)
	procSendMessage.Call(app.hwnd, 0x0202, 0, point)
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic == 0 {
		t.Fatal("[§7.2] 两按钮标题栏的最小化操作失效")
	}
	procSendMessage.Call(app.hwnd, 0x0112, 0xF120, 0)
	if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic != 0 {
		t.Fatal("[§7.2] 系统还原命令无法恢复最小化窗口")
	}
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed != 0 {
		t.Fatal("[§7.2] 最小化还原意外恢复成最大化")
	}
	if visible, _, _ := portableUser32.NewProc("IsWindowVisible").Call(app.hwnd); visible == 0 {
		t.Fatal("[§7.2] 系统还原命令没有显示窗口")
	}
	point = misakaCaptionTestPoint(t, app, 2, false)
	procSendMessage.Call(app.hwnd, 0x0201, 0, point)
	procSendMessage.Call(app.hwnd, 0x0202, 0, point)
	if visible, _, _ := portableUser32.NewProc("IsWindowVisible").Call(app.hwnd); visible != 0 {
		t.Fatal("[§7.2] 两按钮标题栏的关闭操作没有隐藏到托盘")
	}
	if valid, _, _ := portableUser32.NewProc("IsWindow").Call(app.hwnd); valid == 0 {
		t.Fatal("[§7.2] 关闭到托盘销毁了窗口")
	}
	if app.snapshot().state != guiConnected {
		t.Fatal("[§7.2] 窗口操作改变了现有连接")
	}
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
