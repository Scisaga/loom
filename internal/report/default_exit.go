package report

import (
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/validate"
	"loom/internal/webui"
)

// defaultExitStateFromContent 只暴露设备已经获授权的声明，不把完整拓扑、候选链
// 或凭据交给管理 UI。未来设备身份 API 可以复用同一返回模型，但不能复用当前
// 运维会话认证边界。
func defaultExitStateFromContent(content []byte, nodeID, revision string) (webui.DefaultExitState, error) {
	s, err := model.Load(content)
	if err != nil {
		return webui.DefaultExitState{}, fmt.Errorf("解析 SSOT:%w", err)
	}
	if findings := validate.Validate(s); len(findings) > 0 {
		return webui.DefaultExitState{}, fmt.Errorf("SSOT 校验不通过:%s", validate.Format(findings))
	}
	return defaultExitState(s, nodeID, revision)
}

func defaultExitState(s *model.SSOT, nodeID, revision string) (webui.DefaultExitState, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return webui.DefaultExitState{}, fmt.Errorf("node 不能为空")
	}
	node := s.NodeByID()[nodeID]
	if node == nil {
		return webui.DefaultExitState{}, fmt.Errorf("节点 %q 不存在", nodeID)
	}
	if !node.IsAccess() {
		return webui.DefaultExitState{}, fmt.Errorf("节点 %q 不是接入节点", nodeID)
	}
	managed := node.Access.Platform.UsesTUN()
	for _, port := range node.Access.MixedPorts {
		managed = managed || port.ManagedAutomatic()
	}
	if !managed {
		return webui.DefaultExitState{}, fmt.Errorf(
			"节点 %q 没有 TUN 或 services:true mixed，不能承载设备默认出口", nodeID)
	}

	state := webui.DefaultExitState{
		Node: nodeID, Revision: revision, Current: node.Access.DefaultDeclaration,
		Options: []webui.DefaultExitOption{{
			Name: "No default (block unmatched)", Mode: "none", Available: true,
		}},
	}
	credentials := s.CredentialByID()
	declarations := s.DeclarationByID()
	authorized := map[string]bool{}
	for _, credentialID := range node.Access.Credentials {
		credential := credentials[credentialID]
		if credential == nil || credential.Revoked() || credential.Declaration == "" {
			continue
		}
		authorized[credential.Declaration] = true
	}
	ids := make([]string, 0, len(authorized))
	for id := range authorized {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		declaration := declarations[id]
		if declaration == nil {
			continue // 完整校验会报告；这里不把残缺对象伪装成选项。
		}
		name := declaration.Name
		if name == "" {
			name = declaration.ID
		}
		mode := "automatic"
		if declaration.PinnedEgress() != "" {
			mode = "fixed"
		}
		available := declaration.AddressFromRequest()
		if available {
			candidates, _ := s.EnumerateCandidates(node, declaration)
			available = len(candidates) > 0
		}
		state.Options = append(state.Options, webui.DefaultExitOption{
			ID: declaration.ID, Name: name, Mode: mode, Available: available,
		})
	}
	return state, nil
}

func selectableDefaultExit(state webui.DefaultExitState, declaration string) error {
	for _, option := range state.Options {
		if option.ID != declaration {
			continue
		}
		if !option.Available {
			return fmt.Errorf("设备默认出口 %q 当前没有可用候选", declaration)
		}
		return nil
	}
	return fmt.Errorf("设备未获授权使用默认出口 %q", declaration)
}
