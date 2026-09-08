//go:build windows

package main

import (
	"fmt"
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
	procSendMessage.Call(app.controls.stateIcon, portableSTMSetIcon, app.statusIcons.icon(state, app.statusFrame, app.statusIcon), 0)
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
	if previous == nil || previous.selectedProfile != snapshot.selectedProfile || previous.profileName != snapshot.profileName {
		setPortableControlText(app.controls.profileNameEdit, snapshot.profileName)
	}
	enablePortableControl(app.controls.profileNameEdit, snapshot.selectedProfile != "")
	enablePortableControl(app.controls.renameProfileButton, snapshot.selectedProfile != "")
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
	text := formatWindowsPaths(s.paths, app.pathsExpanded)
	if s.state != guiConnected {
		text = "未连接；连接成功后显示各服务实际选路。"
	} else if len(s.paths) == 0 {
		text = "当前选路未知；正在读取本机实际连接状态。"
	}
	button := "详细信息"
	if app.pathsExpanded {
		button = "收起详情"
		root := app.root
		if s.selectedProfile != "" && s.selectedProfile != "legacy" {
			root += `\profiles\` + s.selectedProfile
		}
		text += fmt.Sprintf("\r\n\r\n配置：中控签名配置（只读）\r\n状态目录：%s\r\n运行方式：%s · Windows/%s", root, windowsEditionLabel(app.edition), runtime.GOARCH)
	}
	setPortableControlText(app.controls.pathsValue, text)
	setPortableControlText(app.controls.pathsDetailsButton, button)
}
