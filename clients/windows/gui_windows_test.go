//go:build windows

package main

import (
	"context"
	"runtime"
	"testing"
	"unsafe"
)

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
			buttonWidth := int32(120)
			if joined {
				buttonWidth = 105
			}
			if button.right-button.left != buttonWidth*dpi/96 || button.bottom-button.top != 26*dpi/96 {
				t.Errorf("DPI %d: button did not scale with its font: %+v", dpi, button)
			}
			for _, row := range []struct {
				control, message, index uintptr
			}{
				{app.controls.networkList, 0x01A1, 0}, // LB_GETITEMHEIGHT
				{app.controls.routeCombo, 0x0154, 0},  // CB_GETITEMHEIGHT
				{app.controls.routeCombo, 0x0154, ^uintptr(0)},
			} {
				got, _, _ := procSendMessage.Call(row.control, row.message, row.index, 0)
				if int32(got) != 23*dpi/96 {
					t.Errorf("DPI %d: row height = %d, want %d", dpi, got, 23*dpi/96)
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
		if logicalFont.height != -points*dpi/72 || logicalFont.weight != weight {
			t.Errorf("DPI %d control %x: font height/weight = %d/%d, want %d/%d", dpi, control,
				logicalFont.height, logicalFont.weight, -points*dpi/72, weight)
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
