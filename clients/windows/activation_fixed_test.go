package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/agent"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
)

func TestPreferencePrivateSelectorRejectionPreservesActiveAutoGeneration(t *testing.T) {
	a := managedActivationFixture(t)
	defer a.clear()
	var body map[string]any
	if err := json.Unmarshal(a.BaseConfig, &body); err != nil {
		t.Fatal(err)
	}
	planBody, _ := json.Marshal(a.AgentConfig)
	var cfg agent.Config
	_ = json.Unmarshal(planBody, &cfg)
	d := cfg.Declarations[0]
	d.ID, d.Selector = "demo-private", "opaque:private"
	d.Candidates = []agent.Cand{{Tag: "opaque:private-path", ProbeUser: "demo-private-probe"}}
	cfg.Declarations = append(cfg.Declarations, d)
	body["outbounds"] = append(body["outbounds"].([]any), map[string]any{"type": "direct", "tag": "opaque:private-path"}, map[string]any{"type": "selector", "tag": d.Selector, "outbounds": []string{"opaque:private-path"}, "default": "opaque:private-path"})
	for _, value := range body["inbounds"].([]any) {
		inbound := value.(map[string]any)
		if inbound["tag"] == "probe-in" {
			inbound["users"] = append(inbound["users"].([]any), map[string]any{"username": "demo-private-probe", "password": cfg.ProbeSecret})
		}
	}
	route := body["route"].(map[string]any)
	rules := route["rules"].([]any)
	last := rules[len(rules)-1]
	route["rules"] = append(rules[:len(rules)-1],
		map[string]any{"inbound": []string{"probe-in"}, "auth_user": []string{"demo-private-probe"}, "outbound": "opaque:private-path"},
		map[string]any{"inbound": []string{"tun-in", "in-1080"}, "ip_cidr": []string{"10.0.0.0/8"}, "outbound": d.Selector},
		last,
	)
	encoded, _ := json.Marshal(body)
	planBody, _ = json.Marshal(cfg)
	policy, err := clientruntime.BuildWindowsSelectorPlan(encoded, planBody, clientruntime.WindowsInstalledProfile, clientruntime.WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	a.BaseConfig, a.Policy = encoded, policy
	auto, err := a.withPreference(clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
	if err != nil {
		t.Fatal(err)
	}
	auto.WaitForStart = false
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	defer manager.Stop()
	if _, err := manager.Replace(context.Background(), auto); err != nil {
		t.Fatal(err)
	}
	old := manager.active
	config := bytes.Clone(old.spec.Config)
	agentConfig, _ := json.Marshal(old.spec.AgentConfig)
	persisted := false
	control := &routeControl{persist: func(clientcore.Preference) error { persisted = true; return nil }}
	err = applyRouteRequest(context.Background(), manager, control, routeRequest{preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}})
	if err == nil || !strings.Contains(err.Error(), "独立私网 selector 无法合并到统一上网模式") {
		t.Fatal("[§7.3] 不支持的固定偏好没有明确拒绝", err)
	}
	currentAgent, _ := json.Marshal(manager.active.spec.AgentConfig)
	if persisted || manager.active != old || manager.active.spec.Preference.Mode != clientcore.Auto || !bytes.Equal(manager.active.spec.Config, config) || !bytes.Equal(currentAgent, agentConfig) {
		t.Fatal("[§7.3] 拒绝偏好后改变了当前 Auto 配置、Agent generation 或持久偏好")
	}
	if starts, stops := harness.counts(); starts != 1 || stops != 0 {
		t.Fatal("[§7.3] 派生失败仍取消或重启了原有 Auto 数据面与 Agent")
	}
}
