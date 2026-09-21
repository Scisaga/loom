//go:build windows

package main

import (
	"os"
	"testing"

	"loom/internal/clientmodel"
)

// TestGUIVisualScenarios renders only synthetic state through the production Win32 UI.
// The fixed VM runner supplies LOOM_UI_CAPTURE_DIR; ordinary unit runs skip the expensive captures.
func TestGUIVisualScenarios(t *testing.T) {
	if os.Getenv("LOOM_UI_CAPTURE_DIR") == "" {
		t.Skip("visual capture output is not configured")
	}
	t.Run("connected", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		captureProfileGUIVisualScenario(t, app, "connected")
	})
	t.Run("path-expanded", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		procSendMessage.Call(app.hwnd, portableWMCommand, portableControlPathDetails, app.controls.pathsDetailsButton)
		captureProfileGUIVisualScenario(t, app, "path-expanded")
	})
	t.Run("profile-rename", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		app.beginMisakaRename()
		setPortableControlText(app.controls.profileNameEdit, "demo-renamed")
		captureProfileGUIVisualScenario(t, app, "profile-rename")
	})
	t.Run("join-draft", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		app.brokerProfileDraft = &windowsProfileDraftDisplay{
			State:  guiNeedsJoin,
			Name:   "demo-new-profile",
			Detail: "导入中控提供的加入二维码后，才会保存连接配置。",
		}
		app.renderControls()
		setPortableControlText(app.controls.draftName, "demo-unsaved-input")
		captureProfileGUIVisualScenario(t, app, "join-draft")
	})
	t.Run("join-empty", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		configureVisualEmptyProfile(app, guiNeedsJoin, "")
		captureProfileGUIVisualScenario(t, app, "join-empty")
	})
	t.Run("join-error", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		configureVisualEmptyProfile(app, guiError, "演示邀请已过期，请使用新的邀请重试。")
		captureProfileGUIVisualScenario(t, app, "join-error")
	})
	t.Run("viewport-bottom", func(t *testing.T) {
		app := newMisakaViewportTestWindow(t)
		app.scrollMisakaPane(app.skin.scrollMaximum)
		captureProfileGUIVisualScenario(t, app, "viewport-bottom")
	})
	t.Run("fixed-tun", func(t *testing.T) {
		app := newProfileGUITestWindow(t)
		app.routeOptions = append(app.routeOptions, portableRouteOption{
			Label:      "直连",
			Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeDirect},
		})
		app.routeSelected = 1
		app.paths = app.paths[:1]
		app.detail = "系统 TUN 已启用；本地 HTTP/SOCKS 代理：127.0.0.1:1080。"
		app.renderControls()
		captureProfileGUIVisualScenario(t, app, "fixed-tun")
	})
}

func configureVisualEmptyProfile(app *portableGUI, state portableGUIState, detail string) {
	app.selectedProfile, app.profileName = profileGUIFixtureB, "演示空配置"
	app.joined, app.deviceID, app.state, app.paths = false, "", state, nil
	app.detail = detail
	app.brokerProfiles[1].Name = app.profileName
	app.brokerProfiles[1].DeviceID = ""
	app.brokerProfiles[1].State = state
	app.renderControls()
}
