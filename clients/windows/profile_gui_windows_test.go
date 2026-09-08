//go:build windows

package main

import (
	"context"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
)

const (
	profileGUIFixtureA = "00112233445566778899aabbccddeeff"
	profileGUIFixtureB = "ffeeddccbbaa99887766554433221100"
)

// §7.2：仅创建合成身份的原生窗口，不访问服务、真实身份或加入入口。
func newProfileGUITestWindow(t *testing.T) *portableGUI {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	ctx, cancel := context.WithCancel(context.Background())
	app := &portableGUI{
		brokerClient: true, brokerProfilesReady: true, edition: editionPortableTUN,
		root: `C:\demo-client`, ctx: ctx, cancel: cancel, state: guiConnected,
		joined: true, deviceID: "demo-device-a", hostname: "demo-workstation",
		selectedProfile: profileGUIFixtureA, profileName: "演示网络甲",
		activeProfile: profileGUIFixtureA, activeProfileName: "演示网络甲",
		brokerProfiles: []windowsProfileDisplay{
			{ID: profileGUIFixtureA, Name: "演示网络甲", DeviceID: "demo-device-a", State: guiConnected},
			{ID: profileGUIFixtureB, Name: "演示网络乙", DeviceID: "demo-device-b", State: guiStopped},
		},
		routeSelected: 0, routeOptions: []portableRouteOption{
			{Label: "自动选择", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.Auto}},
			{Label: "固定出口 · demo-exit", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}},
		},
		paths: []windowsPathDisplay{
			{Service: "demo-web", Candidate: "demo-candidate-a", Chain: "本机 → demo-prefix-a → demo-exit → 目标", Health: "正常",
				SelectedQuality: "P50 17 ms · P95 23 ms", BestQuality: "P50 17 ms", Reason: "完整路径测量满足切换门槛"},
			{Service: "demo-api", Candidate: "demo-candidate-b", Chain: "本机 → demo-prefix-b → demo-exit → 目标", Health: "未知",
				SelectedQuality: "未知", BestQuality: "未知", Reason: "本次 Agent 尚无当前候选的有效测量"},
		},
	}
	hwnd, err := createPortableWindow(app)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	app.hwnd = hwnd
	portableGUIWindows.Store(hwnd, app)
	t.Cleanup(func() {
		cancel()
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		app.deleteIcons()
		portableGUIWindows.Delete(hwnd)
		var message portableMSG
		portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	})
	if err := app.createControls(); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	return app
}

func profileGUIText(control uintptr) string {
	length, _, _ := procGetWindowTextLength.Call(control)
	text := make([]uint16, int(length)+1)
	procGetWindowText.Call(control, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
	return windows.UTF16ToString(text)
}

func profileGUIStyle(control uintptr) uintptr {
	style, _, _ := portableUser32.NewProc("GetWindowLongPtrW").Call(control, ^uintptr(15)) // GWL_STYLE
	return style
}

func profileGUIListText(t *testing.T, control uintptr, index int) string {
	t.Helper()
	length, _, _ := procSendMessage.Call(control, 0x018A, uintptr(index), 0) // LB_GETTEXTLEN
	if length == ^uintptr(0) {
		t.Fatal("native profile list entry is missing")
	}
	text := make([]uint16, int(length)+1)
	procSendMessage.Call(control, 0x0189, uintptr(index), uintptr(unsafe.Pointer(&text[0]))) // LB_GETTEXT
	return windows.UTF16ToString(text)
}

func profileGUIPathText(t *testing.T, app *portableGUI) string {
	t.Helper()
	count, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x018B, 0, 0) // LB_GETCOUNT
	if count == ^uintptr(0) {
		t.Fatal("actual paths must expose native list entries")
	}
	if count == 0 {
		return profileGUIText(app.controls.pathsValue)
	}
	var rows []string
	for index := 0; index < int(count); index++ {
		rows = append(rows, profileGUIListText(t, app.controls.pathsValue, index))
	}
	return strings.Join(rows, "\n")
}

type profileGUIWrite struct {
	control uintptr
	message uint32
}

func recordProfileGUIWrites(t *testing.T, app *portableGUI) *[]profileGUIWrite {
	t.Helper()
	var writes []profileGUIWrite
	setProcedure := portableUser32.NewProc("SetWindowLongPtrW")
	callProcedure := portableUser32.NewProc("CallWindowProcW")
	for _, control := range append(app.controls.all(), app.hwnd) {
		var original uintptr
		callback := windows.NewCallback(func(window uintptr, message uint32, wParam, lParam uintptr) uintptr {
			if message == 0x000C || message == 0x0046 || message == portableWMSetIcon || message == portableSTMSetIcon ||
				(window == app.controls.networkList && message == portableLBResetContent) ||
				(window == app.controls.pathsValue && message == portableLBResetContent) ||
				(window == app.controls.routeCombo && message == portableCBResetContent) {
				writes = append(writes, profileGUIWrite{window, message})
			}
			result, _, _ := callProcedure.Call(original, window, uintptr(message), wParam, lParam)
			return result
		})
		var err error
		original, _, err = setProcedure.Call(control, ^uintptr(3), callback)
		if original == 0 {
			t.Fatal(err)
		}
		t.Cleanup(func() { setProcedure.Call(control, ^uintptr(3), original) })
	}
	return &writes
}

func TestGUIProfilesSelectionAndActualServicePaths(t *testing.T) {
	app := newProfileGUITestWindow(t)
	count, _, _ := procSendMessage.Call(app.controls.networkList, 0x018B, 0, 0) // LB_GETCOUNT
	selection, _, _ := procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
	if count != 2 || selection != 0 || profileGUIListText(t, app.controls.networkList, 0) != "演示网络甲" || profileGUIListText(t, app.controls.networkList, 1) != "演示网络乙" {
		t.Fatal("native profile list lost separate friendly names or selection")
	}
	text := profileGUIPathText(t, app)
	for _, row := range app.paths {
		if !strings.Contains(text, row.Service) || !strings.Contains(text, row.Chain) || !strings.Contains(text, row.Health) {
			t.Fatalf("native paths view lost a complete service path: %q", text)
		}
	}
	if profileGUIStyle(app.controls.pathsValue)&0x0010 == 0 { // LBS_OWNERDRAWFIXED
		t.Fatal("actual path control is not a native owner-drawn list")
	}
	procSendMessage.Call(app.controls.pathsValue, 0x0102, uintptr('X'), 0) // WM_CHAR
	if got := profileGUIPathText(t, app); got != text {
		t.Fatal("read-only paths changed in response to typed text")
	}
	captureConfiguredProfileGUIState(t, app, "")
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlPathDetails, app.controls.pathsDetailsButton)
	expanded := profileGUIPathText(t, app)
	if !strings.Contains(profileGUIText(app.controls.pathsValue), `C:\demo-client\profiles\`+profileGUIFixtureA) {
		t.Fatal("profile details displayed the shared root instead of this profile's root")
	}
	for _, row := range app.paths {
		for _, field := range []string{row.Service, row.Chain, row.SelectedQuality, row.BestQuality, row.Reason} {
			if !strings.Contains(expanded, field) {
				t.Fatalf("expanded native path view lost %q: %q", field, expanded)
			}
		}
	}
	captureConfiguredProfileGUIState(t, app, "-expanded")
	// §7.2：模拟 broker 返回正在查看的乙配置；实际连接仍是甲，不调用连接命令。
	app.mu.Lock()
	app.selectedProfile, app.profileName = profileGUIFixtureB, "演示网络乙"
	app.deviceID, app.state, app.paths = "demo-device-b", guiStopped, nil
	app.mu.Unlock()
	app.renderControls()
	selection, _, _ = procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
	snapshot := app.snapshot()
	if selection != 1 || snapshot.activeProfile != profileGUIFixtureA || snapshot.profiles[0].State != guiConnected || snapshot.profiles[1].State != guiStopped {
		t.Fatal("viewing another profile changed the connected profile")
	}
	text = profileGUIPathText(t, app)
	if !strings.Contains(text, "未连接") || strings.Contains(text, "demo-prefix-a") || strings.Contains(text, "demo-web") {
		t.Fatalf("disconnected profile inherited another profile's actual paths: %q", text)
	}
	message := profileGUIText(app.controls.message)
	if !strings.Contains(message, "当前连接：“演示网络甲”") || !strings.Contains(message, "正在查看：“演示网络乙”") {
		t.Fatalf("active and viewed profiles are ambiguous: %q", message)
	}
}

func TestGUIProfileNameDraftSurvivesUnchangedPolling(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.beginMisakaRename()
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible == 0 {
		t.Fatal("inline name editor is hidden after rename starts")
	}
	draft := "尚未保存的本地名称"
	setPortableControlText(app.controls.profileNameEdit, draft)
	writes := recordProfileGUIWrites(t, app)
	for iteration := 0; iteration < 20; iteration++ {
		app.brokerProfiles = slices.Clone(app.brokerProfiles)
		app.paths = slices.Clone(app.paths)
		app.routeOptions = slices.Clone(app.routeOptions)
		app.renderControls()
	}
	if len(*writes) != 0 || profileGUIText(app.controls.profileNameEdit) != draft {
		t.Fatalf("unchanged polling erased the name draft or rewrote controls: %+v", *writes)
	}
	app.detail = "新的连接详情"
	app.renderControls()
	if profileGUIText(app.controls.profileNameEdit) != draft {
		t.Fatal("unrelated detail update erased the name draft")
	}
	for _, write := range *writes {
		if write.control == app.controls.profileNameEdit {
			t.Fatal("unrelated detail update rewrote the name editor")
		}
	}
	t.Log("20 unchanged polls preserve editable name and issue zero native writes")
}

func TestGUIProfileConnectingTimerOnlyChangesStatusIcon(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.state = guiStarting
	app.brokerProfiles[0].State = guiStarting
	app.paths = nil
	app.renderControls()
	icon, _, _ := procSendMessage.Call(app.controls.stateIcon, 0x0171, 0, 0) // STM_GETICON
	if icon == 0 || !app.statusAnimating || profileGUIText(app.controls.stateValue) != "正在连接" {
		t.Fatal("connecting status has no visible animated icon")
	}
	writes := recordProfileGUIWrites(t, app)
	for frame := 0; frame < 16; frame++ {
		previous := icon
		procSendMessage.Call(app.hwnd, 0x0113, portableStatusTimerID, 0) // WM_TIMER
		icon, _, _ = procSendMessage.Call(app.controls.stateIcon, 0x0171, 0, 0)
		if icon == 0 || icon == previous {
			t.Fatalf("animation did not advance at frame %d", frame)
		}
	}
	if len(*writes) != 16 {
		t.Fatalf("animation issued %d writes for 16 frames", len(*writes))
	}
	for _, write := range *writes {
		if write != (profileGUIWrite{app.controls.stateIcon, portableSTMSetIcon}) {
			t.Fatalf("icon animation rewrote text, layout, or a list: %+v", write)
		}
	}
	app.state = guiStopped
	app.brokerProfiles[0].State = guiStopped
	app.renderControls()
	*writes = nil
	procSendMessage.Call(app.hwnd, 0x0113, portableStatusTimerID, 0)
	if app.statusAnimating || len(*writes) != 0 {
		t.Fatal("stopped state retained an active animation")
	}
	t.Log("16 connecting frames only replace the status icon; stopped state ignores timer")
}

func TestGUIProfileLayoutScalesWithoutOverlap(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, joined := range []bool{true, false} {
		app.joined = joined
		if !joined {
			app.state = guiNeedsJoin
		}
		app.renderControls()
		for _, dpi := range []int32{96, 120, 144, 168, 192} {
			width, height := portableMinimumWindowSize(dpi)
			suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
			procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
			checkGUIFonts(t, app, dpi)
			var client portableRect
			procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&client)))
			var occupied []struct {
				control uintptr
				rect    portableRect
			}
			for _, control := range app.controls.all() {
				if profileGUIStyle(control)&portableWSVisible == 0 {
					continue
				}
				rect := guiWindowRect(t, control)
				portableUser32.NewProc("MapWindowPoints").Call(0, app.hwnd, uintptr(unsafe.Pointer(&rect)), 2)
				if rect.left < 0 || rect.top < 0 || rect.right > client.right || rect.bottom > client.bottom || rect.right <= rect.left || rect.bottom <= rect.top {
					t.Errorf("joined=%t DPI=%d control=%x exceeds client bounds: %+v inside %+v", joined, dpi, control, rect, client)
				}
				if control == app.controls.interfaceGroup || control == app.controls.localGroup {
					continue // §7.2：分组边框有意包围其内容，不算相邻控件重叠。
				}
				for _, other := range occupied {
					if rect.left < other.rect.right && other.rect.left < rect.right && rect.top < other.rect.bottom && other.rect.top < rect.bottom {
						t.Errorf("joined=%t DPI=%d controls=%x/%x overlap: %+v / %+v", joined, dpi, control, other.control, rect, other.rect)
					}
				}
				occupied = append(occupied, struct {
					control uintptr
					rect    portableRect
				}{control, rect})
			}
			for _, button := range []uintptr{app.controls.addProfileButton, app.controls.primaryButton, app.controls.profileMenu} {
				if profileGUIStyle(button)&portableWSVisible == 0 {
					t.Errorf("joined=%t DPI=%d required button=%x is hidden", joined, dpi, button)
				}
			}
			for _, control := range []uintptr{app.controls.profileNameEdit, app.controls.renameProfileButton, app.controls.deleteButton} {
				if profileGUIStyle(control)&portableWSVisible != 0 {
					t.Errorf("joined=%t DPI=%d inactive editor or menu action=%x remains visible", joined, dpi, control)
				}
			}
			t.Logf("joined=%t: %d%% native profile controls fit without overlap", joined, dpi*100/96)
		}
	}
}

// §7.2：只捕获本测试的合成 HWND，不读取屏幕或其他客户端窗口。
func readProfileGUITestWindow(t *testing.T, app *portableGUI) *image.NRGBA {
	t.Helper()
	rect := guiWindowRect(t, app.hwnd)
	width, height := rect.right-rect.left, rect.bottom-rect.top
	header := portableBitmapInfoHeader{size: uint32(unsafe.Sizeof(portableBitmapInfoHeader{})), width: width, height: -height, planes: 1, bitCount: 32}
	dc, _, _ := portableGDI32.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		t.Fatal("cannot create native capture DC")
	}
	defer procDeleteDC.Call(dc)
	var pixels unsafe.Pointer
	bitmap, _, _ := procCreateDIBSection.Call(dc, uintptr(unsafe.Pointer(&header)), portableDIBRGBColors, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		t.Fatal("cannot allocate native capture bitmap")
	}
	defer procDeleteObject.Call(bitmap)
	previous, _, _ := procSelectObject.Call(dc, bitmap)
	defer procSelectObject.Call(dc, previous)
	// §7.2：隐藏测试窗口没有 DWM 表面；直接请求本窗口及子控件打印到内存 DC。
	procSendMessage.Call(app.hwnd, 0x0317, dc, 0x001e) // WM_PRINT: non-client, client, erase, children
	portableGDI32.NewProc("GdiFlush").Call()
	picture := image.NewNRGBA(image.Rect(0, 0, int(width), int(height)))
	data := unsafe.Slice((*byte)(pixels), len(picture.Pix))
	for index := 0; index < len(data); index += 4 {
		picture.Pix[index], picture.Pix[index+1], picture.Pix[index+2], picture.Pix[index+3] = data[index+2], data[index+1], data[index], 255
	}
	return picture
}

func captureProfileGUITestWindow(t *testing.T, app *portableGUI, path string) {
	t.Helper()
	picture := readProfileGUITestWindow(t, app)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(file, picture); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic native profile window captured to %s", path)
}

func captureConfiguredProfileGUIState(t *testing.T, app *portableGUI, suffix string) {
	t.Helper()
	output := os.Getenv("LOOM_PROFILE_GUI_CAPTURE")
	if output == "" {
		return
	}
	extension := filepath.Ext(output)
	if suffix != "" {
		output = strings.TrimSuffix(output, extension) + suffix + extension
	}
	captureProfileGUITestWindow(t, app, output)
}
