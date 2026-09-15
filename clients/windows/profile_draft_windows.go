//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/windowsv2"
)

// 草稿快照只给 UI 阶段与可恢复提示，不返回二维码、路径或秘密材料。
type windowsProfileDraftDisplay struct {
	State       portableGUIState `json:"state"`
	Name        string           `json:"name"`
	Detail      string           `json:"detail"`
	Recoverable bool             `json:"recoverable"`
	Busy        bool             `json:"busy"`
}

type windowsProfileDraft struct {
	profile *connectionProfile
	child   *portableGUI
	display windowsProfileDraftDisplay
	epoch   uint64
}

func profileDraftOperation(operation string) bool {
	return operation == "add_profile" || operation == "join_profile" || operation == "cancel_add_profile"
}

func (m *windowsProfileManager) nextProfileDraftName() string {
	for number := 1; ; number++ {
		name := fmt.Sprintf("连接配置 %d", number)
		found := false
		for _, profile := range m.store.Snapshot().Profiles {
			found = found || strings.EqualFold(profile.Name, name)
		}
		if !found {
			return name
		}
	}
}

func (m *windowsProfileManager) restoreProfileDraft(profile connectionProfile) error {
	root, err := m.store.ResolveDraftRoot(profile.ID)
	if err != nil {
		return err
	}
	recoverable, err := windowsProfileDraftHasIdentity(root)
	if err != nil {
		return err
	}
	detail := "导入中控提供的加入二维码后，才会保存连接配置。"
	if recoverable {
		detail = "已保留上次加入进度；继续加入将复用原身份。"
	}
	m.draft = &windowsProfileDraft{profile: &profile, display: windowsProfileDraftDisplay{
		State: guiNeedsJoin, Name: profile.Name, Detail: detail, Recoverable: recoverable,
	}}
	m.draftVisible = true
	return nil
}

func (m *windowsProfileManager) openProfileDraft(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.owner.ctx.Err() != nil {
		return context.Canceled
	}
	if m.draft == nil {
		if name == "" {
			name = m.nextProfileDraftName()
		}
		if err := validateConnectionProfileName(name); err != nil {
			return err
		}
		m.draft = &windowsProfileDraft{display: windowsProfileDraftDisplay{State: guiNeedsJoin, Name: name,
			Detail: "导入中控提供的加入二维码后，才会保存连接配置。"}}
	}
	m.draftVisible = true
	return nil
}

func (m *windowsProfileManager) cancelProfileDraft() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.draftVisible = false
	if m.draft != nil {
		m.draft.epoch++
	}
	if m.draft != nil && m.draft.child != nil {
		m.draft.child.cancel()
	}
	if m.draft != nil && m.draft.profile == nil {
		m.draft = nil
	}
}

func (m *windowsProfileManager) prepareProfileDraft(req brokerRequest, expected *windowsProfileDraft, epoch uint64) (child *portableGUI, v2Carrier string, retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.owner.ctx.Err() != nil {
		return nil, "", context.Canceled
	}
	if m.draft != expected || expected == nil || expected.epoch != epoch {
		return nil, "", context.Canceled
	}
	if m.draft == nil || !m.draftVisible {
		return nil, "", errors.New("请先打开添加连接配置面板")
	}
	if m.draft.display.Busy {
		return nil, "", errors.New("加入正在进行，请等待当前操作完成")
	}
	defer func() {
		if retErr != nil {
			m.draft.display.State, m.draft.display.Detail = guiError, retErr.Error()
		}
	}()
	name := req.Name
	if name == "" {
		name = m.draft.display.Name
	}
	if req.V2Carrier != "" {
		carrier, carrierErr := windowsv2.DecodeEnrollmentCarrierText(req.V2Carrier)
		if carrierErr != nil || carrier.ValidateShape() != nil {
			return nil, "", errors.New("Windows v2 加入或续传凭据无效")
		}
		if m.draft.display.Recoverable && carrier.Resume == nil {
			return nil, "", errors.New("已有 pending transaction；只能导入匹配的 .loom-resume")
		}
	} else if !m.draft.display.Recoverable {
		return nil, "", errWindowsJoinInputRequired
	}

	if expected := m.draft.profile; expected != nil {
		retained, err := m.store.Draft()
		if err != nil {
			return nil, "", err
		}
		if retained == nil || retained.ID != expected.ID {
			return nil, "", errors.New("加入恢复记录已变化，拒绝重新创建身份")
		}
	}
	profile, err := m.store.BeginDraft(name)
	if err != nil {
		return nil, "", err
	}
	m.draft.profile = &profile
	root, err := m.store.ResolveDraftRoot(profile.ID)
	if err != nil {
		return nil, "", err
	}
	child = m.makeProfileChild(root)
	child.mu.Lock()
	child.state, child.joinStarted, child.detail = guiJoining, time.Now(), "正在读取加入二维码…"
	child.mu.Unlock()
	m.draft.child = child
	m.draft.display.Name, m.draft.display.State, m.draft.display.Busy = name, guiJoining, true
	m.owner.repaint()
	return child, req.V2Carrier, nil
}

func (m *windowsProfileManager) joinProfileDraft(req brokerRequest) error {
	m.mu.Lock()
	draft := m.draft
	var epoch uint64
	if draft != nil {
		epoch = draft.epoch
	}
	m.mu.Unlock()
	return m.joinProfileDraftFor(req, draft, epoch)
}

func (m *windowsProfileManager) joinProfileDraftFor(req brokerRequest, draft *windowsProfileDraft, epoch uint64) error {
	child, v2Carrier, err := m.prepareProfileDraft(req, draft, epoch)
	if err != nil {
		return err
	}
	result, err := m.joinDraftV2(child, v2Carrier)
	if err == nil {
		var deviceID string
		deviceID, _, err = m.readJoined(child.root, child.protector())
		if err == nil && deviceID != result.NodeID {
			err = errors.New("已完成加入的身份与配置不一致")
		}
	}
	if err == nil {
		child.afterJoin(result.NodeID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if child.ctx.Err() != nil || m.closing {
		err = context.Canceled
	}
	if err == nil {
		profile, commitErr := m.store.CommitDraft(m.draft.profile.ID)
		if commitErr == nil {
			m.children[profile.ID] = child
			m.draft, m.draftVisible = nil, false
			// 加入只新增已断开的宿主，不触碰旧连接、Agent 或 LastConnected。
			return nil
		}
		err = commitErr
	}
	child.cancel()
	recoverable, recoveryErr := windowsProfileDraftHasIdentity(child.root)
	m.draft.display.Busy, m.draft.display.Recoverable = false, recoverable || recoveryErr != nil
	m.draft.display.State, m.draft.display.Detail = guiError, err.Error()
	if errors.Is(err, context.Canceled) {
		m.draft.display.Detail = "加入已停止；已保存的身份和加入进度将保留，稍后可以继续。"
	}
	return errors.Join(err, recoveryErr)
}

func windowsProfileDraftHasIdentity(root string) (bool, error) {
	for _, path := range []string{filepath.Join(root, "join", "identity.json.dpapi"), filepath.Join(root, "join", "ready.json.dpapi"),
		filepath.Join(root, "config", "client.json"), windowsV2IdentityPath(root),
		windowsV2JournalPath(root), windowsV2StatePath(root)} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("加入恢复材料必须是普通文件")
		}
		if err := checkWindowsProfilePath(path); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
