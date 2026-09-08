//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

func TestGUIMisakaContextMenuMouseTargetsAndEmptySpace(t *testing.T) {
	app := newProfileGUITestWindow(t)
	pointFor := func(y int32) uintptr {
		point := portablePoint{app.scale(20), y}
		procMisakaMapPoints.Call(app.controls.networkList, 0, uintptr(unsafe.Pointer(&point)), 1)
		return uintptr(uint32(uint16(point.x)) | uint32(uint16(point.y))<<16)
	}
	var row portableRect
	procSendMessage.Call(app.controls.networkList, 0x0198, 1, uintptr(unsafe.Pointer(&row)))
	id, _ := app.misakaProfileMenuTarget(pointFor((row.top + row.bottom) / 2))
	if id != profileGUIFixtureB || app.snapshot().selectedProfile != profileGUIFixtureA {
		t.Fatal("右键未绑定点击行或提前改变了已确认快照")
	}
	id, _ = app.misakaProfileMenuTarget(pointFor(row.bottom + app.scale(10)))
	if id != "" {
		t.Fatal("列表空白处仍弹出了最后一项菜单")
	}
}

func TestGUIMisakaNativeContextMenuReflectsConnectionState(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, item := range []struct {
		state              portableGUIState
		label              string
		primary, deletable bool
	}{
		{guiConnected, "断开", true, false}, {guiStarting, "取消连接", true, false},
		{guiStopping, "正在处理…", false, false}, {guiJoining, "正在处理…", false, false},
		{guiStopped, "启动", true, true}, {guiNeedsElevation, "管理员启动", true, true},
	} {
		app.brokerProfiles[1].State = item.state
		menu := app.createMisakaProfileMenu(profileGUIFixtureB)
		if menu == 0 {
			t.Fatal("无法创建原生菜单")
		}
		text := make([]uint16, 64)
		portableUser32.NewProc("GetMenuStringW").Call(menu, misakaProfileStart, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)), 0)
		primary, _, _ := portableUser32.NewProc("GetMenuState").Call(menu, misakaProfileStart, 0)
		deletion, _, _ := portableUser32.NewProc("GetMenuState").Call(menu, misakaProfileDelete, 0)
		procDestroyMenu.Call(menu)
		// §7.2：通过原生 HMENU 状态验收键盘/鼠标共享的操作，不只检查绘制文案。
		if got := windows.UTF16ToString(text); got != item.label || (primary&3 == 0) != item.primary || (deletion&3 == 0) != item.deletable {
			t.Fatalf("状态 %v 的原生菜单错误: %q, primary=%x delete=%x", item.state, got, primary, deletion)
		}
	}
}

func TestGUIMisakaButtonFocusNotificationsHaveNoActions(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, id := range []uint16{portableControlAddProfile, portableControlRenameProfile, portableControlPathDetails, portableControlPrimary, portableControlPaste, portableControlDelete} {
		for _, notification := range []uintptr{6, 7} { // BN_SETFOCUS / BN_KILLFOCUS
			procSendMessage.Call(app.hwnd, portableWMCommand, uintptr(id)|notification<<16, 0)
		}
	}
	if app.skin.rename || app.pathsExpanded || app.snapshot().profileDraft != nil {
		t.Fatal("按钮焦点通知触发了点击操作")
	}
}

func TestGUIMisakaRenameDraftSurvivesDelayedSelectionAcknowledgement(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.beginMisakaRenameFor(profileGUIFixtureB)
	setPortableControlText(app.controls.profileNameEdit, "demo-unsaved-name")
	app.selectedProfile, app.profileName, app.state = profileGUIFixtureB, "演示网络乙", guiStopped
	app.renderControls()
	if !app.skin.rename || app.skin.renameID != profileGUIFixtureB || profileGUIText(app.controls.profileNameEdit) != "demo-unsaved-name" {
		t.Fatal("异步选中确认覆盖了正在输入的重命名草稿")
	}
	app.finishMisakaRename(false)
}
