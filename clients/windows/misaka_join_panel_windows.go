//go:build windows

package main

// §7.2：空配置已有自己的入口，不再引导用户另建配置或重复展示缺失身份。
func (app *portableGUI) paintMisakaJoinPanel(c *misakaCanvas, snapshot portableGUISnapshot) {
	s := app.scale
	main, end := s(196), app.misakaContentEnd()
	card := misakaRect(main, s(98), end-main, s(176))
	c.Fill(card, misakaBorder, s(9))
	card.left++
	card.top++
	card.right--
	card.bottom--
	c.Fill(card, misakaWhite, s(8))
	if !snapshot.profilesReady || snapshot.selectedProfile != "" {
		c.Text("也可拖入邀请文件，或按 Ctrl+V 粘贴。", misakaRect(main+s(68), s(252), end-main-s(86), s(16)), s(10), 400, misakaMuted, 0)
	}
	if snapshot.activeProfile != "" && snapshot.activeProfile != snapshot.selectedProfile {
		c.Text("当前连接：“"+snapshot.activeProfileName+"”", misakaRect(main, s(284), end-main, s(22)), s(10), 400, misakaMuted, 0)
	}
}
