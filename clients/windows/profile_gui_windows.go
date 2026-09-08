//go:build windows

package main

import (
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

const portableStatusTimerID = 4101

var (
	procSetTimer  = portableUser32.NewProc("SetTimer")
	procKillTimer = portableUser32.NewProc("KillTimer")
)

func (app *portableGUI) updateStatusIcon(state portableGUIState) {
	// §7.2：进度动画仅使独立状态图标失效，不修改文字、控件大小或整个窗口。
	procInvalidateRect.Call(app.controls.stateIcon, 0, 0)
	animated := portableStatusAnimated(state) || slices.ContainsFunc(app.snapshot().profiles, func(p windowsProfileDisplay) bool { return portableStatusAnimated(p.State) })
	if animated == app.statusAnimating {
		return
	}
	app.statusAnimating = animated
	if animated {
		procSetTimer.Call(app.hwnd, portableStatusTimerID, uintptr(portableStatusFrameInterval.Milliseconds()), 0)
	} else {
		procKillTimer.Call(app.hwnd, portableStatusTimerID)
	}
}

func (app *portableGUI) animateMisakaProfiles(snapshot portableGUISnapshot) {
	for index, profile := range snapshot.profiles {
		if !portableStatusAnimated(profile.State) {
			continue
		}
		var rect portableRect
		procSendMessage.Call(app.controls.networkList, 0x0198, uintptr(index), uintptr(unsafe.Pointer(&rect)))
		rect.left += app.scale(5)
		rect.right = rect.left + app.scale(22)
		procInvalidateRect.Call(app.controls.networkList, uintptr(unsafe.Pointer(&rect)), 0)
	}
}

func sameWindowsProfileEntries(a, b []windowsProfileDisplay) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name {
			return false
		}
	}
	return true
}

func (app *portableGUI) renderProfileList(snapshot portableGUISnapshot, previous *portableGUISnapshot) {
	app.profileListUpdating = true
	defer func() { app.profileListUpdating = false }()
	rebuild := previous == nil || !sameWindowsProfileEntries(snapshot.profiles, previous.profiles)
	if rebuild {
		procSendMessage.Call(app.controls.networkList, portableLBResetContent, 0, 0)
		for _, p := range snapshot.profiles {
			text, _ := windows.UTF16PtrFromString(p.Name)
			procSendMessage.Call(app.controls.networkList, portableLBAddString, 0, uintptr(unsafe.Pointer(text)))
			runtime.KeepAlive(text)
		}
	}
	if rebuild || previous.selectedProfile != snapshot.selectedProfile {
		index := slices.IndexFunc(snapshot.profiles, func(p windowsProfileDisplay) bool { return p.ID == snapshot.selectedProfile })
		procSendMessage.Call(app.controls.networkList, portableLBSetCurSel, uintptr(index), 0)
	}
	if !rebuild && !slices.Equal(snapshot.profiles, previous.profiles) {
		procInvalidateRect.Call(app.controls.networkList, 0, 0)
	}
	// §7.2：右键先打开原位编辑时，后到的选中确认不能覆盖用户已经输入的草稿。
	editing := app.skin != nil && app.skin.rename && app.skin.renameID == snapshot.selectedProfile
	if !editing && (previous == nil || previous.selectedProfile != snapshot.selectedProfile || previous.profileName != snapshot.profileName) {
		setPortableControlText(app.controls.profileNameEdit, snapshot.profileName)
	}
	enablePortableControl(app.controls.profileNameEdit, snapshot.selectedProfile != "")
}

func (app *portableGUI) renderProfileDetails(s portableGUISnapshot, previous *portableGUISnapshot) {
	group := "连接: " + s.profileName
	if s.selectedProfile == "" {
		group = "添加连接配置"
		setPortableControlText(app.controls.primaryButton, "添加配置")
	}
	setPortableControlText(app.controls.interfaceGroup, group)
	setPortableControlText(app.controls.localGroup, "当前选路（按服务）")
	setPortableControlText(app.controls.modeCaption, "方式:")
	button := "详细信息"
	if app.pathsExpanded {
		button = "收起详情"
	}
	// §7.2：路径文字由原生列表项提供，无需再重写 LISTBOX 窗口标题。
	setPortableControlText(app.controls.pathsDetailsButton, button)
}
