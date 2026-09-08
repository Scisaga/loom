//go:build windows

package main

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMisakaFrameCalculatesBothClientRectForms(t *testing.T) {
	app := newProfileGUITestWindow(t)
	want := guiWindowRect(t, app.hwnd)
	for _, full := range []uintptr{0, 1} {
		params := struct {
			rects    [3]portableRect
			position uintptr
		}{rects: [3]portableRect{want}}
		procSendMessage.Call(app.hwnd, 0x0083, full, uintptr(unsafe.Pointer(&params)))
		if params.rects[0] != want {
			t.Errorf("[§7.2] WM_NCCALCSIZE(%d) 恢复了系统非客户区：got=%+v want=%+v", full, params.rects[0], want)
		}
	}
}

func misakaAssertVisibleFrame(t *testing.T, app *portableGUI, stage string) {
	t.Helper()
	for count := 0; ; count++ {
		var message portableMSG
		if pending, _, _ := portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0, 1); pending == 0 {
			break
		}
		if count > 1000 {
			t.Fatal("[§7.2] 原生窗口消息持续自激，无法完成一次空闲刷新")
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
	var client portableRect
	procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&client)))
	window := guiWindowRect(t, app.hwnd)
	if zoomed, _, _ := procMisakaIsZoomed.Call(app.hwnd); zoomed == 0 {
		if client.right != window.right-window.left || client.bottom != window.bottom-window.top {
			t.Errorf("[§7.2] %s 后原生标题侵占客户区：window=%+v client=%+v", stage, window, client)
		}
	} else {
		procMisakaMapPoints.Call(app.hwnd, 0, uintptr(unsafe.Pointer(&client)), 2)
		monitor, _, _ := procMisakaMonitorFrom.Call(app.hwnd, 2)
		info := misakaMonitorInfo{size: uint32(unsafe.Sizeof(misakaMonitorInfo{}))}
		procMisakaMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info)))
		if client != info.work {
			t.Errorf("[§7.2] %s 后最大化客户区不等于显示器工作区：client=%+v work=%+v", stage, client, info.work)
		}
		procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&client)))
	}
	// §7.2：读取实际可见 HWND 的 DC，不能用 WM_PRINT 的自绘结果遮住
	// DefWindowProc 已直接写入窗口表面的默认标题。
	dc, _, _ := portableUser32.NewProc("GetDC").Call(app.hwnd)
	if dc == 0 {
		t.Fatal("[§7.2] 无法读取可见测试窗口")
	}
	defer portableUser32.NewProc("ReleaseDC").Call(app.hwnd, dc)
	for _, y := range []int32{10, 20, 30} {
		pixel, _, _ := portableGDI32.NewProc("GetPixel").Call(dc, uintptr(client.right/2), uintptr(app.scale(y)))
		if uint32(pixel) != misakaColorRef(misakaWhite) {
			t.Errorf("[§7.2] %s 后自绘标题被默认框覆盖：y=%d pixel=%#x", stage, y, pixel)
		}
	}
}

func TestMisakaFrameVisibleLifecycle(t *testing.T) {
	app := newProfileGUITestWindow(t)
	class, _ := windows.UTF16PtrFromString("STATIC")
	other, _, err := procCreateWindowEx.Call(0x80, uintptr(unsafe.Pointer(class)), 0,
		portableWSCaption|portableWSSysMenu, 0, 0, 160, 100, 0, 0, 0, 0)
	if other == 0 {
		t.Fatal(err)
	}
	t.Cleanup(func() { procDestroyWindow.Call(other) })
	procShowWindow.Call(other, 4)
	procShowWindow.Call(app.hwnd, 4)
	portableUser32.NewProc("UpdateWindow").Call(app.hwnd)
	misakaAssertVisibleFrame(t, app, "首次显示")
	activate := func(hwnd uintptr) {
		portableUser32.NewProc("SetActiveWindow").Call(hwnd)
		if got, _, _ := portableUser32.NewProc("GetActiveWindow").Call(); got != hwnd {
			t.Fatalf("[§7.2] 可见窗口没有实际完成激活：got=%#x want=%#x", got, hwnd)
		}
	}
	wantStyle := profileGUIStyle(app.hwnd)
	for index := 0; index < 4; index++ {
		activate(other)
		activate(app.hwnd)
		misakaAssertVisibleFrame(t, app, fmt.Sprintf("第 %d 次激活", index+1))
		setPortableControlText(app.hwnd, fmt.Sprintf("Loom — demo-window-%d", index))
		if got := profileGUIText(app.hwnd); got != fmt.Sprintf("Loom — demo-window-%d", index) {
			t.Fatal("[§7.2] 自绘窗口丢弃了供任务栏与无障碍读取的真实标题")
		}
		misakaAssertVisibleFrame(t, app, "更新窗口标题")
		for _, iconKind := range []uintptr{0, 1} {
			icon, _, _ := portableUser32.NewProc("LoadIconW").Call(0, 32515)
			if icon == 0 {
				t.Fatal("[§7.2] 无法加载原生测试图标")
			}
			procSendMessage.Call(app.hwnd, 0x0080, iconKind, icon)
			got, _, _ := procSendMessage.Call(app.hwnd, 0x007F, iconKind, 0)
			if got != icon {
				t.Fatal("[§7.2] 自绘窗口丢弃了供任务栏读取的真实图标")
			}
			misakaAssertVisibleFrame(t, app, "更新窗口图标")
		}
		for _, message := range []uintptr{0x031A, 0x031E, 0x0085} {
			procSendMessage.Call(app.hwnd, message, 0, 0)
			misakaAssertVisibleFrame(t, app, fmt.Sprintf("消息 %#x", message))
		}
		if got := profileGUIStyle(app.hwnd); got != wantStyle {
			t.Fatalf("[§7.2] 消息处理永久改变了窗口样式：got=%#x want=%#x", got, wantStyle)
		}
		procMisakaSetStyle.Call(app.hwnd, ^uintptr(15), wantStyle|0x04000000)
		procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0037)
		misakaAssertVisibleFrame(t, app, "样式变化")
		procMisakaSetStyle.Call(app.hwnd, ^uintptr(15), wantStyle)
		procSetWindowPos.Call(app.hwnd, 0, 0, 0, 0, 0, 0x0037)
		procShowWindow.Call(app.hwnd, 3)
		portableUser32.NewProc("UpdateWindow").Call(app.hwnd)
		misakaAssertVisibleFrame(t, app, "最大化")
		activate(other)
		activate(app.hwnd)
		misakaAssertVisibleFrame(t, app, "最大化后再次激活")
		procShowWindow.Call(app.hwnd, 6)
		if iconic, _, _ := portableUser32.NewProc("IsIconic").Call(app.hwnd); iconic == 0 {
			t.Fatal("[§7.2] 系统最小化失效")
		}
		procShowWindow.Call(app.hwnd, 9)
		procShowWindow.Call(app.hwnd, 9)
		portableUser32.NewProc("UpdateWindow").Call(app.hwnd)
		misakaAssertVisibleFrame(t, app, "最小化后还原")
	}
	t.Log("[§7.2] 可见窗口重复激活、标题、图标、主题、合成与样式变更、最大化、最小化和还原通过")
}

func TestMisakaFrameWithoutDWMNonclientRendering(t *testing.T) {
	app := newProfileGUITestWindow(t)
	procShowWindow.Call(app.hwnd, 4)
	// §7.2：只切换这个合成测试窗口的 DWM 策略，模拟非客户区合成
	// 被禁用后的系统绘制路径；不更改桌面主题或其他窗口。
	policy := uint32(1)
	result, _, _ := misakaDWM.NewProc("DwmSetWindowAttribute").Call(app.hwnd, 2,
		uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy))
	if int32(result) < 0 {
		t.Fatalf("[§7.2] 无法设置测试窗口的 DWM 非客户区策略：%#x", result)
	}
	portableUser32.NewProc("UpdateWindow").Call(app.hwnd)
	for index := 0; index < 3; index++ {
		procSendMessage.Call(app.hwnd, 0x0086, 0, 0)
		procSendMessage.Call(app.hwnd, 0x0086, 1, 0)
		setPortableControlText(app.hwnd, fmt.Sprintf("Loom — demo-basic-%d", index))
		misakaAssertVisibleFrame(t, app, "禁用非客户区合成后更新标题")
	}
	policy = 0
	misakaDWM.NewProc("DwmSetWindowAttribute").Call(app.hwnd, 2,
		uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy))
	portableUser32.NewProc("UpdateWindow").Call(app.hwnd)
	misakaAssertVisibleFrame(t, app, "恢复非客户区合成")
}

func TestMisakaFrameMetadataDoesNotShowHiddenWindow(t *testing.T) {
	app := newProfileGUITestWindow(t)
	if profileGUIStyle(app.hwnd)&portableWSVisible != 0 {
		t.Fatal("[§7.2] 测试窗口应从隐藏状态开始")
	}
	setPortableControlText(app.hwnd, "Loom — demo-hidden")
	icon, _, _ := portableUser32.NewProc("LoadIconW").Call(0, 32515)
	procSendMessage.Call(app.hwnd, 0x0080, 0, icon)
	for _, message := range []uintptr{0x031A, 0x031E, 0x0086} {
		procSendMessage.Call(app.hwnd, message, 0, 0)
	}
	if profileGUIStyle(app.hwnd)&portableWSVisible != 0 {
		t.Fatal("[§7.2] 更新标题、图标或主题意外显示了隐藏到托盘的窗口")
	}
	if profileGUIText(app.hwnd) != "Loom — demo-hidden" {
		t.Fatal("[§7.2] 隐藏窗口的真实标题未保存")
	}
}
