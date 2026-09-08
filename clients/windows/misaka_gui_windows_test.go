//go:build windows

package main

import (
	"image/color"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGUIMisakaFrameRetainsNativeWindowInteractions(t *testing.T) {
	app := newProfileGUITestWindow(t)
	window := guiWindowRect(t, app.hwnd)
	var client portableRect
	procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&client)))
	if client.right != window.right-window.left || client.bottom != window.bottom-window.top {
		t.Fatalf("custom frame still reserves a system caption or border: window=%+v client=%+v", window, client)
	}
	for _, hit := range []struct {
		name string
		x, y int32
		want uintptr
	}{
		{"caption", client.right / 2, app.scale(20), 2},
		{"left resize", 1, client.bottom / 2, 10},
		{"bottom-right resize", client.right - 1, client.bottom - 1, 17},
		{"maximize and snap", client.right - app.scale(63), app.scale(20), 9},
	} {
		point := uintptr(uint32(uint16(window.left+hit.x)) | uint32(uint16(window.top+hit.y))<<16)
		got, _, _ := procSendMessage.Call(app.hwnd, 0x0084, 0, point) // WM_NCHITTEST
		if got != hit.want {
			t.Errorf("%s hit=%d, want %d", hit.name, got, hit.want)
		}
	}
	t.Log("custom caption fills the window while native drag, resize, maximize and snap hit targets remain available")
}

func TestGUIMisakaInlineRenameUsesKeyboardAndPersistsOnlyOnSave(t *testing.T) {
	app := newProfileGUITestWindow(t)
	m := newProfileManagerFixture(t)
	app.brokerClient, app.profiles = false, m
	_, stopped := startProfileFixture(m.children[legacyConnectionProfile], nil)
	app.renderControls()
	original := m.store.Snapshot().Profiles[0].Name
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible != 0 {
		t.Fatal("name editor is permanently visible")
	}
	procSendMessage.Call(app.controls.networkList, portableWMKeyDown, 0x71, 0) // F2
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible == 0 {
		t.Fatal("F2 did not open the inline editor")
	}
	setPortableControlText(app.controls.profileNameEdit, "demo-canceled")
	procSendMessage.Call(app.controls.profileNameEdit, portableWMKeyDown, portableVKEscape, 0)
	m.workers.Wait()
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible != 0 || m.store.Snapshot().Profiles[0].Name != original {
		t.Fatal("Escape saved the draft or left the editor visible")
	}
	procSendMessage.Call(app.hwnd, portableWMCommand, uintptr(portableControlNetworkList)|2<<16, app.controls.networkList)
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible == 0 {
		t.Fatal("double-click did not open the inline editor")
	}
	setPortableControlText(app.controls.profileNameEdit, "   ")
	procSendMessage.Call(app.controls.profileNameEdit, portableWMKeyDown, portableVKReturn, 0)
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible == 0 || m.store.Snapshot().Profiles[0].Name != original {
		t.Fatal("invalid empty name replaced the persisted name or dismissed the editor")
	}
	setPortableControlText(app.controls.profileNameEdit, "demo-renamed")
	captureConfiguredProfileGUIState(t, app, "-rename")
	procSendMessage.Call(app.controls.profileNameEdit, portableWMKeyDown, portableVKReturn, 0)
	m.workers.Wait()
	app.renderControls()
	if profileGUIStyle(app.controls.profileNameEdit)&portableWSVisible != 0 || m.store.Snapshot().Profiles[0].Name != "demo-renamed" || profileGUIListText(t, app.controls.networkList, 0) != "demo-renamed" {
		t.Fatal("Enter did not persist and display the new name")
	}
	if s := app.snapshot(); s.activeProfile != legacyConnectionProfile || s.state != guiConnected {
		t.Fatal("renaming changed the active connection")
	}
	select {
	case <-stopped:
		t.Fatal("renaming stopped the existing workload")
	default:
	}
}

func TestGUIMisakaDoubleClickRenameUsesActualListSelection(t *testing.T) {
	app := newProfileGUITestWindow(t)
	// §7.2：第二项刚被点击，异步 broker 快照尚未更新；编辑对象仍必须是眼前的第二项。
	procSendMessage.Call(app.controls.networkList, portableLBSetCurSel, 1, 0)
	procSendMessage.Call(app.hwnd, portableWMCommand, uintptr(portableControlNetworkList)|2<<16, app.controls.networkList)
	if app.skin.renameID != profileGUIFixtureB || profileGUIText(app.controls.profileNameEdit) != "演示网络乙" {
		t.Fatal("double-click edited the previous broker selection")
	}
	procSendMessage.Call(app.controls.profileNameEdit, portableWMKeyDown, portableVKEscape, 0)
}

func TestGUIMisakaHeaderActionsAndContextMenuBindExplicitProfile(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, control := range []uintptr{app.controls.renameProfileButton, app.controls.deleteButton} {
		if profileGUIStyle(control)&portableWSVisible == 0 {
			t.Fatal("右侧缺少配置操作")
		}
	}
	procSendMessage.Call(app.controls.networkList, portableLBSetCurSel, 1, 0)
	id, _ := app.misakaProfileMenuTarget(^uintptr(0))
	if id != profileGUIFixtureB {
		t.Fatal("键盘菜单没有绑定实际列表选中项")
	}
	menu := app.createMisakaProfileMenu(id)
	if menu == 0 {
		t.Fatal("未创建原生配置菜单")
	}
	defer procDestroyMenu.Call(menu)
	count, _, _ := portableUser32.NewProc("GetMenuItemCount").Call(menu)
	if count != 4 {
		t.Fatalf("菜单项数量=%d，预期启动、重命名、分隔符和删除", count)
	}
	app.misakaProfileAction(id, misakaProfileRename)
	if app.skin.renameID != profileGUIFixtureB {
		t.Fatal("异步快照使菜单重命名了另一项")
	}
	app.finishMisakaRename(false)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRenameProfile, app.controls.renameProfileButton)
	if app.skin.renameID != profileGUIFixtureA {
		t.Fatal("右侧铅笔未绑定当前面板")
	}
	app.finishMisakaRename(false)
	app.misakaProfileAction("deleted-profile", misakaProfileRename)
	if app.skin.rename {
		t.Fatal("已删除菜单对象仍能触发操作")
	}
}

func TestGUIMisakaDraftPreservesActiveConnectionAndUnsavedInput(t *testing.T) {
	app := newProfileGUITestWindow(t)
	m := newProfileManagerFixture(t)
	app.brokerClient, app.profiles = false, m
	_, stopped := startProfileFixture(m.children[legacyConnectionProfile], nil)
	app.renderControls()
	before := m.store.Snapshot()
	app.openMisakaDraft()
	m.workers.Wait()
	app.renderControls()
	if snapshot := app.snapshot(); snapshot.profileDraft == nil || snapshot.activeProfile != legacyConnectionProfile || !slices.Equal(snapshot.profiles, app.rendered.profiles) {
		t.Fatal("opening the add panel lost the current connection or profile list")
	}
	for _, control := range []uintptr{app.controls.draftName, app.controls.draftImport, app.controls.draftPaste, app.controls.draftSubmit, app.controls.draftCancel} {
		if profileGUIStyle(control)&portableWSVisible == 0 {
			t.Fatal("add panel omitted a required input or action")
		}
	}
	if profileGUIStyle(app.controls.networkList)&portableWSVisible == 0 {
		t.Fatal("the add form hid the saved connection list")
	}
	if enabled, _, _ := procIsWindowEnabled.Call(app.controls.networkList); enabled != 0 {
		t.Fatal("the saved connection list accepts changes during the add form")
	}
	if enabled, _, _ := procIsWindowEnabled.Call(app.controls.draftSubmit); enabled != 0 {
		t.Fatal("join submission is enabled without an invitation")
	}
	setPortableControlText(app.controls.draftName, "demo-unsaved-input")
	captureConfiguredProfileGUIState(t, app, "-draft")
	writes := recordProfileGUIWrites(t, app)
	for iteration := 0; iteration < 20; iteration++ {
		app.renderControls()
	}
	if len(*writes) != 0 || profileGUIText(app.controls.draftName) != "demo-unsaved-input" {
		t.Fatal("stable add-panel polling rewrote controls or the local name draft")
	}
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlDraftCancel, app.controls.draftCancel)
	m.workers.Wait()
	app.renderControls()
	after := m.store.Snapshot()
	if app.snapshot().profileDraft != nil || !slices.Equal(before.Profiles, after.Profiles) || before.Selected != after.Selected || before.LastConnected != after.LastConnected {
		t.Fatal("canceling an unsubmitted add left an empty profile or changed the selection")
	}
	select {
	case <-stopped:
		t.Fatal("opening or canceling the add panel stopped the current workload")
	default:
	}
}

func TestGUIMisakaCustomCanvasPaintsLightFrameAndSeparateSidebar(t *testing.T) {
	app := newProfileGUITestWindow(t)
	picture := readProfileGUITestWindow(t, app)
	for _, sample := range []struct {
		name string
		x, y int32
		want color.NRGBA
	}{
		{"custom title background", 350, 10, color.NRGBA{255, 255, 255, 255}},
		{"sidebar background", 5, 105, color.NRGBA{247, 248, 247, 255}},
		{"main background", 184, 200, color.NRGBA{252, 252, 251, 255}},
	} {
		if got := picture.NRGBAAt(int(app.scale(sample.x)), int(app.scale(sample.y))); got != sample.want {
			t.Errorf("%s is not painted: got=%v want=%v", sample.name, got, sample.want)
		}
	}
	// §7.2：父背景绘制成功不代表子控件被打印；连接主按钮与每个服务的路径图都必须有真实像素。
	window := guiWindowRect(t, app.hwnd)
	button := guiWindowRect(t, app.controls.primaryButton)
	button.left, button.right = button.left-window.left, button.right-window.left
	button.top, button.bottom = button.top-window.top, button.bottom-window.top
	light, ink := 0, 0
	for y := button.top + app.scale(4); y < button.bottom-app.scale(4); y++ {
		for x := button.left + app.scale(4); x < button.right-app.scale(4); x++ {
			pixel := picture.NRGBAAt(int(x), int(y))
			if pixel.R > 235 && pixel.G > 235 && pixel.B > 235 {
				light++
			}
			if pixel.R < 190 && pixel.G < 190 && pixel.B < 190 {
				ink++
			}
		}
	}
	if area := int((button.right - button.left) * (button.bottom - button.top)); light < area/3 || ink < int(app.scale(5)*app.scale(5)) {
		t.Errorf("断开按钮缺少白底或可读文字: light=%d ink=%d area=%d", light, ink, area)
	}
	for index, row := range app.paths {
		var rect portableRect
		if result, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x0198, uintptr(index), uintptr(unsafe.Pointer(&rect))); result == ^uintptr(0) { // LB_GETITEMRECT
			t.Fatal("cannot locate the rendered service path")
		}
		portableUser32.NewProc("MapWindowPoints").Call(app.controls.pathsValue, app.hwnd, uintptr(unsafe.Pointer(&rect)), 2)
		ink, light, sampled := 0, 0, 0
		for y := rect.top + app.scale(38); y < rect.bottom-app.scale(4) && int(y) < picture.Bounds().Dy(); y++ {
			for x := rect.left + app.scale(4); x < rect.right-app.scale(4) && int(x) < picture.Bounds().Dx(); x++ {
				pixel := picture.NRGBAAt(int(x), int(y))
				sampled++
				if pixel.R < 190 && pixel.G < 190 && pixel.B < 190 && pixel.A == 255 {
					ink++
				}
				if pixel.R > 235 && pixel.G > 235 && pixel.B > 235 && pixel.A == 255 {
					light++
				}
			}
		}
		if minimum := int(app.scale(8) * app.scale(8)); ink < minimum {
			t.Errorf("service %s path graphic was not printed: ink=%d, need at least %d", row.Service, ink, minimum)
		}
		if light < sampled/3 {
			t.Errorf("service %s path graphic lost its light card background: light=%d of %d pixels", row.Service, light, sampled)
		}
	}
}

func TestGUIMisakaNameInputsKeepNativePasteShortcut(t *testing.T) {
	app := newProfileGUITestWindow(t)
	var original [256]byte
	get := portableUser32.NewProc("GetKeyboardState")
	set := portableUser32.NewProc("SetKeyboardState")
	if ok, _, err := get.Call(uintptr(unsafe.Pointer(&original[0]))); ok == 0 {
		t.Fatal(err)
	}
	defer set.Call(uintptr(unsafe.Pointer(&original[0])))
	pressed := original
	pressed[portableVKControl] = 0x80
	if ok, _, err := set.Call(uintptr(unsafe.Pointer(&pressed[0]))); ok == 0 {
		t.Fatal(err)
	}
	// §7.2：只模拟当前测试线程的键盘状态，不读取剪贴板。已加入快照阻止旧错误分支读取真实邀请。
	for _, edit := range []uintptr{app.controls.profileNameEdit, app.controls.draftName} {
		message := portableMSG{hwnd: edit, msg: portableWMKeyDown, wParam: portableVKV}
		if handlePortablePasteShortcut(message) {
			t.Fatal("name input Ctrl+V was swallowed by the invitation shortcut")
		}
	}
}

func TestGUIMisakaBackgroundPathRefreshDoesNotRevealHiddenList(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.brokerProfileDraft = &windowsProfileDraftDisplay{State: guiNeedsJoin, Name: "demo-new"}
	app.renderControls()
	if profileGUIStyle(app.controls.pathsValue)&portableWSVisible != 0 {
		t.Fatal("the add form did not hide the old path list")
	}
	app.paths = slices.Clone(app.paths)
	app.paths[0].Chain = "本机 → demo-next-prefix → demo-exit → 目标"
	app.paths[0].Reason = "演示路径更新"
	app.renderControls()
	if profileGUIStyle(app.controls.pathsValue)&portableWSVisible != 0 {
		t.Fatal("background selector readback revealed the old list over the add form")
	}
	if profileGUIStyle(app.controls.draftName)&portableWSVisible == 0 || app.snapshot().activeProfile != profileGUIFixtureA {
		t.Fatal("background path update replaced the add form or the active connection")
	}
}

func TestGUIMisakaResizeAndDPIKeepInlineRenameUncommitted(t *testing.T) {
	app := newProfileGUITestWindow(t)
	m := newProfileManagerFixture(t)
	app.brokerClient, app.profiles = false, m
	app.renderControls()
	originalName := m.store.Snapshot().Profiles[0].Name
	app.beginMisakaRename()
	setPortableControlText(app.controls.profileNameEdit, "demo-resize-draft")
	var hidden, procedure uintptr
	setProcedure := portableUser32.NewProc("SetWindowLongPtrW")
	callProcedure := portableUser32.NewProc("CallWindowProcW")
	callback := windows.NewCallback(func(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
		if message == 0x0046 && lParam != 0 { // WM_WINDOWPOSCHANGING
			position := (*struct {
				window, after uintptr
				x, y, w, h    int32
				flags         uint32
			})(unsafe.Pointer(lParam))
			if position.flags&0x0080 != 0 { // SWP_HIDEWINDOW：隐藏会引发失焦提交。
				hidden++
			}
		}
		result, _, _ := callProcedure.Call(procedure, hwnd, uintptr(message), wParam, lParam)
		return result
	})
	procedure, _, _ = setProcedure.Call(app.controls.profileNameEdit, ^uintptr(3), callback)
	if procedure == 0 {
		t.Fatal("cannot observe native editor visibility changes")
	}
	defer setProcedure.Call(app.controls.profileNameEdit, ^uintptr(3), procedure)
	procSendMessage.Call(app.hwnd, portableWMSize, 0, 0)
	for _, dpi := range []int32{96, 144, 192, 96} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		m.workers.Wait()
		if !app.skin.rename || profileGUIText(app.controls.profileNameEdit) != "demo-resize-draft" || m.store.Snapshot().Profiles[0].Name != originalName {
			t.Fatalf("resize or DPI %d submitted or erased the name draft", dpi)
		}
	}
	if hidden != 0 {
		t.Fatalf("layout hid the active editor %d times, risking an implicit focus-loss commit", hidden)
	}
	app.finishMisakaRename(false)
}
