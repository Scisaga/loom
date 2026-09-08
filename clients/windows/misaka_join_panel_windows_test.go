//go:build windows

package main

import (
	"strings"
	"testing"
	"unsafe"
)

func TestGUIMisakaEmptyProfileOffersInlineJoinWithoutChangingActiveProfile(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.selectedProfile, app.profileName = profileGUIFixtureB, "演示空配置"
	app.joined, app.deviceID, app.state, app.paths = false, "", guiNeedsJoin, nil
	app.brokerProfiles[1].Name, app.brokerProfiles[1].DeviceID, app.brokerProfiles[1].State = app.profileName, "", guiNeedsJoin
	app.renderControls()
	if got := profileGUIText(app.controls.stateValue); got != "此配置尚未加入" {
		t.Fatal("[§7.2] 空配置仍复用了连接状态的大段标题", got)
	}
	message := profileGUIText(app.controls.message)
	if strings.Contains(message, "当前连接") || strings.Contains(message, "通过 +") || !strings.Contains(message, "加入后保持断开") {
		t.Fatal("[§7.2] 空配置导入说明仍混入其他连接状态或重复的添加引导", message)
	}
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		r := misakaRect(30, 30, width, height)
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&r)))
		for _, control := range []uintptr{app.controls.primaryButton, app.controls.pasteButton, app.controls.deleteButton} {
			if profileGUIStyle(control)&portableWSVisible == 0 {
				t.Fatalf("[§7.2] DPI=%d 空配置缺少直接导入、粘贴或删除入口", dpi)
			}
		}
		for _, control := range []uintptr{app.controls.modeDirect, app.controls.modeAuto, app.controls.modeFixed, app.controls.routeCombo, app.controls.pathsValue, app.controls.pathsDetailsButton} {
			if profileGUIStyle(control)&portableWSVisible != 0 {
				t.Fatalf("[§7.2] DPI=%d 空配置泄露上个已连接配置的选路控件", dpi)
			}
		}
		primary := guiWindowRect(t, app.controls.primaryButton)
		paste := guiWindowRect(t, app.controls.pasteButton)
		message := guiWindowRect(t, app.controls.message)
		if primary.top != paste.top || primary.bottom != paste.bottom || primary.right >= paste.left || primary.top <= message.bottom || primary.left != message.left {
			t.Fatalf("[§7.2] DPI=%d 空配置说明与操作没有对齐或发生重叠", dpi)
		}
	}
	writes := recordProfileGUIWrites(t, app)
	app.renderControls()
	if len(*writes) != 0 || app.snapshot().activeProfile != profileGUIFixtureA || app.snapshot().profiles[0].State != guiConnected {
		t.Fatal("[§7.2] 查看空配置重写了稳定控件或改变正在运行的另一配置")
	}
	captureConfiguredProfileGUIState(t, app, "-empty-profile")
	app.state, app.detail = guiJoining, "正在验证加入邀请。"
	app.brokerProfiles[1].State = guiJoining
	app.renderControls()
	for _, control := range []uintptr{app.controls.primaryButton, app.controls.pasteButton, app.controls.deleteButton} {
		if enabled, _, _ := procIsWindowEnabled.Call(control); enabled != 0 {
			t.Fatal("[§7.2] 加入过程中仍能重复提交或删除配置")
		}
	}
	app.state, app.detail = guiError, "演示邀请已过期，请使用新的邀请重试。"
	app.brokerProfiles[1].State = guiError
	app.renderControls()
	if profileGUIText(app.controls.message) != app.detail {
		t.Fatal("[§7.2] 导入失败的原因没有直接保留在说明位置")
	}
	for _, control := range []uintptr{app.controls.primaryButton, app.controls.pasteButton} {
		if enabled, _, _ := procIsWindowEnabled.Call(control); enabled == 0 {
			t.Fatal("[§7.2] 导入失败后没有恢复文件/粘贴重试入口")
		}
	}
	captureConfiguredProfileGUIState(t, app, "-empty-profile-error")
}

func TestGUIMisakaNoProfilesShowsOneAddEntry(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.selectedProfile, app.profileName, app.activeProfile, app.activeProfileName = "", "", "", ""
	app.joined, app.deviceID, app.state, app.paths, app.brokerProfiles = false, "", guiNeedsJoin, nil, nil
	app.renderControls()
	if profileGUIText(app.controls.stateValue) != "添加第一个连接配置" || profileGUIText(app.controls.primaryButton) != "添加配置" || profileGUIStyle(app.controls.pasteButton)&portableWSVisible != 0 {
		t.Fatal("[§7.2] 无配置时必须先进入完整加入表单，不能向缺少目标的配置直接粘贴")
	}
}
