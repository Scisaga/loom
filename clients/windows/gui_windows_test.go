//go:build windows

package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientcore"
)

func TestGUIJoinProgressPreservesTransactionState(t *testing.T) {
	for _, edition := range []clientEdition{editionPortableMixed, editionPortableTUN, editionInstalled} {
		t.Run(string(edition), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				app := &portableGUI{edition: edition, ctx: ctx, state: guiLoading}
				app.joinProgress("正在联系中控，等待加入配置…")
				time.Sleep(65 * time.Second)
				app.joinProgress("中控已确认设备，正在等待配置发布…")
				s := app.snapshot()
				if s.state != guiJoining || s.joined || s.deviceID != "" || app.runCancel != nil {
					t.Fatal("progress advanced the join or started a workload")
				}
				if !strings.Contains(s.detail, "1 分 05 秒") {
					t.Fatalf("stage change reset elapsed time: %q", s.detail)
				}
				_, message, _, enabled := app.presentation(s)
				if enabled || message != s.detail {
					t.Fatal("pending join lost progress or allowed a second import")
				}
				if remote := app.brokerSnapshot(); remote.Detail != s.detail || remote.Joined {
					t.Fatal("Installed broker lost join progress or prematurely reported joined")
				}
				app.update(guiError, false, "", "加入已结束")
				app.joinProgress("迟到的阶段回调")
				if s := app.snapshot(); s.state != guiError || s.detail != "加入已结束" {
					t.Fatal("late progress overwrote completed state")
				}
				app.mu.Lock()
				app.state, app.joined = guiStopped, true
				app.mu.Unlock()
				app.joinProgress("迟到的阶段回调")
				if s := app.snapshot(); s.state != guiStopped || !s.joined || strings.Contains(s.detail, "已用时") {
					t.Fatal("joined state regressed or retained the join clock")
				}
				app.mu.Lock()
				app.state, app.joined = guiJoining, false
				app.mu.Unlock()
				cancel()
				app.joinProgress("取消后的阶段回调")
				if strings.Contains(app.snapshot().detail, "取消后") {
					t.Fatal("progress continued after cancellation")
				}
			})
		})
	}
}

func TestGUIDPIChanges(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{
		edition: editionPortableTUN, ctx: ctx, cancel: cancel,
		state: guiNeedsJoin, root: `C:\demo-loom`, routeSelected: -1,
	}
	hwnd, err := createPortableWindow(app)
	if err != nil {
		t.Fatal(err)
	}
	app.hwnd = hwnd
	portableGUIWindows.Store(hwnd, app)
	defer func() {
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		app.deleteIcons()
		// DestroyWindow 会投递 WM_QUIT，避免它影响同线程的后续窗口测试。
		var message portableMSG
		portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	}()
	if err := app.createControls(); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	checkGUIFonts(t, app, app.dpi())

	// 直接送达系统消息，不改测试机器的显示设置，也不启动加入或数据面流程。
	for _, joined := range []bool{false, true} {
		app.mu.Lock()
		app.joined = joined
		if joined {
			app.state, app.deviceID = guiConnected, "demo-device"
		}
		app.mu.Unlock()
		app.renderControls()
		for _, dpi := range []int32{96, 120, 144, 168, 192, 144, 96} {
			oldFonts := append([]uintptr(nil), app.fonts...)
			width, height := portableMinimumWindowSize(dpi)
			suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
			result, _, _ := procSendMessage.Call(hwnd, 0x02E0,
				uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
			if result != 0 {
				t.Fatalf("WM_DPICHANGED returned %d", result)
			}
			if got := app.dpi(); got != dpi {
				t.Fatalf("joined=%t: DPI = %d, want %d", joined, got, dpi)
			}
			checkGUIFonts(t, app, dpi)
			for _, font := range oldFonts {
				var buffer [92]byte // LOGFONTW
				if size, _, _ := portableGDI32.NewProc("GetObjectW").Call(font, uintptr(len(buffer)), uintptr(unsafe.Pointer(&buffer[0]))); size != 0 {
					t.Errorf("DPI %d: old font still allocated", dpi)
				}
			}
			if rect := guiWindowRect(t, hwnd); rect != suggested {
				t.Errorf("DPI %d: window rectangle = %+v, want %+v", dpi, rect, suggested)
			}
			button := guiWindowRect(t, app.controls.primaryButton)
			buttonWidth := int32(100)
			if !joined {
				buttonWidth = 132 // §7.2：空配置的导入按钮与说明左对齐，容纳完整操作名。
			}
			if button.right-button.left != buttonWidth*dpi/96 || button.bottom-button.top != 32*dpi/96 {
				t.Errorf("DPI %d: button did not scale with its font: %+v", dpi, button)
			}
			for _, row := range []struct {
				control, message, index uintptr
				height                  int32
			}{
				{app.controls.networkList, 0x01A1, 0, 55}, // LB_GETITEMHEIGHT
				{app.controls.routeCombo, 0x0154, 0, 23},  // CB_GETITEMHEIGHT
				{app.controls.routeCombo, 0x0154, ^uintptr(0), 23},
			} {
				got, _, _ := procSendMessage.Call(row.control, row.message, row.index, 0)
				if int32(got) != row.height*dpi/96 {
					t.Errorf("DPI %d: row height = %d, want %d", dpi, got, row.height*dpi/96)
				}
			}
			t.Logf("joined=%t: %d%% fonts, control sizes, row heights and window bounds verified", joined, dpi*100/96)
		}
	}
}

func checkGUIFonts(t *testing.T, app *portableGUI, dpi int32) {
	t.Helper()
	for _, control := range app.controls.all() {
		if control == app.controls.brandIcon || control == app.controls.stateIcon {
			continue
		}
		font, _, _ := procSendMessage.Call(control, portableWMGetFont, 0, 0)
		var logicalFont struct {
			height, width, escapement, orientation, weight int32
			styles                                         [8]byte
			face                                           [32]uint16
		}
		size, _, _ := portableGDI32.NewProc("GetObjectW").Call(font, unsafe.Sizeof(logicalFont), uintptr(unsafe.Pointer(&logicalFont)))
		if size != unsafe.Sizeof(logicalFont) {
			t.Fatalf("control %x: could not read native font", control)
		}
		points, weight := int32(9), int32(portableFWNormal)
		if control == app.controls.brandName || control == app.controls.stateValue {
			points, weight = 11, portableFWSemibold
		}
		height := -points * dpi / 72
		if control == app.controls.profileNameEdit {
			height, weight = -misakaProfileNameSize*dpi/96, portableFWSemibold
		}
		if logicalFont.height != height || logicalFont.weight != weight {
			t.Errorf("DPI %d control %x: font height/weight = %d/%d, want %d/%d", dpi, control,
				logicalFont.height, logicalFont.weight, height, weight)
		}
	}
}

func guiWindowRect(t *testing.T, hwnd uintptr) portableRect {
	t.Helper()
	var rect portableRect
	if ok, _, err := portableUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&rect))); ok == 0 {
		t.Fatalf("GetWindowRect: %v", err)
	}
	return rect
}

func TestGUIStatusRefreshDoesNotRewriteUnchangedControls(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{edition: editionInstalled, ctx: ctx, cancel: cancel,
		state: guiConnected, joined: true, deviceID: "demo-device", root: `C:\demo-client`,
		detail: "已连接", routeSelected: 0, routeOptions: []portableRouteOption{
			{Label: "自动选择", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.Auto}},
			{Label: "固定出口 · demo-exit", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}},
		}}
	hwnd, err := createPortableWindow(app)
	if err != nil {
		t.Fatal(err)
	}
	app.hwnd = hwnd
	portableGUIWindows.Store(hwnd, app)
	defer func() {
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		app.deleteIcons()
		var message portableMSG
		portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	}()
	if err := app.createControls(); err != nil {
		t.Fatal(err)
	}
	app.renderControls()

	// §7.2：在真实 HWND 上记录引起闪烁的写消息，不能仅断言缓存变量相等。
	type write struct {
		control uintptr
		message uint32
	}
	var writes []write
	setProcedure := portableUser32.NewProc("SetWindowLongPtrW")
	callProcedure := portableUser32.NewProc("CallWindowProcW")
	for _, control := range append(app.controls.all(), hwnd) {
		var original uintptr
		callback := windows.NewCallback(func(window uintptr, message uint32, wParam, lParam uintptr) uintptr {
			if message == 0x000C || message == 0x0046 || // WM_SETTEXT / WM_WINDOWPOSCHANGING
				message == portableWMSetIcon || message == portableSTMSetIcon ||
				(window == app.controls.networkList && message == portableLBResetContent) ||
				(window == app.controls.routeCombo && message == portableCBResetContent) {
				writes = append(writes, write{window, message})
			}
			result, _, _ := callProcedure.Call(original, window, uintptr(message), wParam, lParam)
			return result
		})
		original, _, err = setProcedure.Call(control, ^uintptr(3), callback) // GWLP_WNDPROC
		if original == 0 {
			t.Fatal(err)
		}
		defer setProcedure.Call(control, ^uintptr(3), original)
	}
	for refresh := 0; refresh < 20; refresh++ {
		// 每次 broker JSON 解码会产生新切片，但显示内容并没有改变。
		app.routeOptions = append([]portableRouteOption(nil), app.routeOptions...)
		app.renderControls()
	}
	if len(writes) != 0 {
		t.Fatalf("unchanged status issued %d native control writes", len(writes))
	}
	app.detail = "连接详情已更新"
	app.renderControls()
	if len(writes) != 1 || writes[0] != (write{app.controls.message, 0x000C}) {
		t.Fatalf("detail update rewrote unrelated controls: %+v", writes)
	}
	writes = nil
	app.routeSelected = 1
	app.renderControls()
	resets := 0
	for _, event := range writes {
		if event.message == 0x0046 { // §7.2：固定出口会展开出口输入，允许这次真实模式变化重排布局。
			continue
		}
		if event.control != app.controls.routeCombo && event.control != app.controls.modeAuto &&
			event.control != app.controls.modeFixed && event.control != app.controls.modeDirect {
			t.Fatalf("route update rewrote another control: %+v", event)
		}
		if event.message == portableCBResetContent {
			resets++
		}
	}
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	// §7.2：只改变实际选择时复用已有授权列表，不能为刷新读回值重建整个弹出层。
	if resets != 0 || selection == ^uintptr(0) || int(selection) >= len(app.routeVisible) || app.routeVisible[selection] != app.routeSelected {
		t.Fatal("real route change was lost")
	}
	t.Log("20 identical polls: zero native writes; detail and route changes update only their controls")
}
