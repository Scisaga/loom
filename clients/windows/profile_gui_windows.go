//go:build windows

package main

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
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
	animated := portableStatusAnimated(state)
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

func (app *portableGUI) layoutProfileControls(snapshot portableGUISnapshot, width, height int32) {
	s := app.scale
	move := func(control uintptr, x, y, w, h int32) {
		procMoveWindow.Call(control, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0)
	}
	for _, c := range app.controls.all() {
		setPortableControlVisible(c, false)
	}
	for _, c := range []uintptr{app.controls.brandIcon, app.controls.brandName, app.controls.brandEdition, app.controls.networkList,
		app.controls.addProfileButton, app.controls.profileNameEdit, app.controls.renameProfileButton,
		app.controls.interfaceGroup, app.controls.stateCaption, app.controls.stateIcon, app.controls.stateValue,
		app.controls.primaryButton, app.controls.deleteButton, app.controls.message} {
		setPortableControlVisible(c, true)
	}
	margin, left, gap := s(8), s(165), s(12)
	right := margin + left + gap
	rightWidth := width - right - margin
	bottom := height - s(30)
	move(app.controls.brandIcon, margin, s(10), s(48), s(48))
	move(app.controls.brandName, margin+s(58), s(14), left-s(58), s(20))
	move(app.controls.brandEdition, margin+s(58), s(36), left-s(58), s(20))
	move(app.controls.networkList, margin, s(70), left, bottom-s(70)-s(64))
	move(app.controls.profileNameEdit, margin, bottom-s(56), left, s(23))
	move(app.controls.addProfileButton, margin, bottom-s(27), (left-s(6))/2, s(26))
	move(app.controls.renameProfileButton, margin+(left+s(6))/2, bottom-s(27), (left-s(6))/2, s(26))
	move(app.controls.interfaceGroup, right, s(8), rightWidth, s(154))
	captionX, captionWidth := right+s(12), s(56)
	valueX := captionX + captionWidth + s(8)
	valueWidth := right + rightWidth - valueX - s(12)
	move(app.controls.stateCaption, captionX, s(37), captionWidth, s(22))
	move(app.controls.stateIcon, valueX, s(38), s(20), s(20))
	move(app.controls.stateValue, valueX+s(25), s(37), valueWidth-s(25), s(22))
	if snapshot.joined {
		for _, c := range []uintptr{app.controls.modeCaption, app.controls.modeValue, app.controls.routeCaption, app.controls.routeCombo,
			app.controls.localGroup, app.controls.deviceCaption, app.controls.deviceValue, app.controls.pathsValue, app.controls.pathsHint, app.controls.pathsDetailsButton} {
			setPortableControlVisible(c, true)
		}
		move(app.controls.modeCaption, captionX, s(65), captionWidth, s(21))
		move(app.controls.modeValue, valueX, s(65), valueWidth, s(21))
		move(app.controls.routeCaption, captionX, s(95), captionWidth, s(21))
		move(app.controls.routeCombo, valueX, s(90), valueWidth, s(180))
		move(app.controls.primaryButton, valueX, s(124), s(112), s(26))
		move(app.controls.deleteButton, valueX+s(122), s(124), s(80), s(26))
		localTop := s(172)
		move(app.controls.localGroup, right, localTop, rightWidth, bottom-localTop)
		move(app.controls.deviceCaption, captionX, localTop+s(23), captionWidth, s(20))
		move(app.controls.deviceValue, valueX, localTop+s(23), valueWidth, s(20))
		move(app.controls.pathsValue, right+s(12), localTop+s(49), rightWidth-s(24), bottom-localTop-s(115))
		move(app.controls.pathsHint, right+s(12), bottom-s(60), rightWidth-s(24), s(23))
		move(app.controls.pathsDetailsButton, right+s(12), bottom-s(32), s(105), s(25))
		move(app.controls.message, margin, height-s(25), width-2*margin, s(23))
	} else {
		setPortableControlVisible(app.controls.pasteButton, snapshot.selectedProfile != "")
		move(app.controls.primaryButton, valueX, s(100), s(112), s(26))
		move(app.controls.pasteButton, valueX+s(122), s(100), s(112), s(26))
		move(app.controls.deleteButton, right+s(12), s(176), s(80), s(26))
		move(app.controls.message, right+s(12), s(218), rightWidth-s(24), s(100))
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
	if s.activeProfile != "" && s.activeProfile != s.selectedProfile {
		_, message, _, _ := app.presentation(s)
		message = "当前连接：“" + s.activeProfileName + "”；正在查看：“" + s.profileName + "”。  " + message
		setPortableControlText(app.controls.message, strings.TrimSpace(message))
	}
}
