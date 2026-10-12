//go:build windows

package main

// §7.2：空配置已有自己的入口，不再引导用户另建配置或重复展示缺失身份。
func (app *portableGUI) paintMisakaJoinPanel(c *misakaCanvas, snapshot portableGUISnapshot) {
	s := app.scale
	main, end := s(200), app.misakaContentEnd()
	height := int32(160)
	if snapshot.selectedProfile != "" {
		height = 256
	}
	card := misakaRect(main, s(104), end-main, s(height))
	c.Fill(card, misakaWhite, s(12))
	if !snapshot.profilesReady || snapshot.selectedProfile != "" {
		c.Text("也可拖入邀请文件，或按 Ctrl+V 粘贴。", misakaRect(main+s(64), s(276), end-main-s(80), s(24)), s(11), 400, misakaMuted, 0)
	}
	if snapshot.activeProfile != "" && snapshot.activeProfile != snapshot.selectedProfile {
		c.Fill(misakaRect(main, s(312), end-main, s(1)), misakaBorder, 0)
		c.Text("当前连接：“"+snapshot.activeProfileName+"”", misakaRect(main+s(16), s(312), end-main-s(32), s(48)), s(11), 400, misakaMuted, 0)
	}
}
