package render

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/agent"
	"loom/internal/model"
	"loom/internal/wire"
)

func TestV2ScopeKeepsTransitAndBindsBothRuntimeConsumers(t *testing.T) {
	source := load(t)
	before, _ := json.Marshal(source)
	for _, node := range source.Nodes {
		if node.Access == nil || node.Server != nil || node.Access.Platform == model.LinuxServer {
			continue
		}
		t.Run(string(node.Access.Platform), func(t *testing.T) {
			plans := renderSelectorPlans(source, &node)
			egress := ""
			for _, plan := range plans {
				if !strings.HasPrefix(plan.Selector, "decl:") {
					continue
				}
				for _, candidate := range plan.Candidates {
					if len(candidate.Chain) == 2 {
						egress = candidate.Chain[1]
						break
					}
				}
				if egress != "" {
					break
				}
			}
			if egress == "" {
				t.Fatal("测试缺少经过转发节点的出口路径")
			}
			grants := &wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{{Kind: "egress", TargetID: egress}}}
			scope, err := newClientAccessScope(source, grants)
			if err != nil {
				t.Fatal(err)
			}
			file, skipped, err := renderSingBoxScoped(source, &node, scope)
			if err != nil || len(skipped) != 0 {
				t.Fatal(err, skipped)
			}
			files, skipped := renderAgentPlanScoped(source, &node, scope)
			if len(files) != 1 || len(skipped) != 0 {
				t.Fatal("授权收窄被错误当成未实现功能", skipped)
			}
			var config sbConfig
			var plan agent.Config
			if json.Unmarshal([]byte(file.Content), &config) != nil || json.Unmarshal([]byte(files[0].Content), &plan) != nil {
				t.Fatal("运行配置不能解析")
			}
			selectors := map[string][]string{}
			outbounds := map[string]bool{}
			for _, outbound := range config.Outbounds {
				outbounds[outbound.Tag] = true
				if outbound.Type == "selector" {
					selectors[outbound.Tag] = outbound.Outbounds
				}
			}
			twoHops := false
			for _, selector := range plan.Selectors {
				if !strings.HasPrefix(selector.Selector, "decl:") {
					t.Fatal("未授权服务仍有 selector")
				}
				if len(selectors[selector.Selector]) != len(selector.Candidates) {
					t.Fatal("数据面和 Agent 候选不一致")
				}
				for _, candidate := range selector.Candidates {
					if !outbounds[candidate.Tag] {
						t.Fatal("Agent 引用不存在的候选")
					}
					if len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] != egress {
						t.Fatal("仍可选未授权出口")
					}
					twoHops = twoHops || len(candidate.Chain) == 2 && candidate.Chain[0] != egress
				}
				delete(selectors, selector.Selector)
			}
			if len(selectors) != 0 || !twoHops {
				t.Fatal("遗漏 selector 或误删中继")
			}
			for _, declaration := range plan.Declarations {
				for _, candidate := range declaration.Candidates {
					if !outbounds[candidate.Tag] || len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] != egress {
						t.Fatal("自动选路扩大授权")
					}
				}
			}
		})
	}
	after, _ := json.Marshal(source)
	if string(before) != string(after) {
		t.Fatal("投影修改了原网络")
	}
}

func TestV2ScopeDeniesMissingAuthorityAndRevokedPinnedExit(t *testing.T) {
	source := load(t)
	if _, err := newClientAccessScope(source, nil); err == nil {
		t.Fatal("缺 v2 授权时回退到旧权限")
	}
	for _, kind := range []string{"service", "egress"} {
		if _, err := newClientAccessScope(source, &wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{{Kind: kind, TargetID: "demo-unknown"}}}); err == nil {
			t.Fatal("未知授权被静默忽略")
		}
	}
	scope, err := newClientAccessScope(source, &wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range source.Nodes {
		if node.Access == nil || node.Access.Platform != model.Android {
			continue
		}
		file, skipped, err := renderSingBoxScoped(source, &node, scope)
		if err != nil || len(skipped) != 0 {
			t.Fatal(err, skipped)
		}
		var config sbConfig
		if json.Unmarshal([]byte(file.Content), &config) != nil {
			t.Fatal("配置不能解析")
		}
		for _, outbound := range config.Outbounds {
			if outbound.Type == "hysteria2" || outbound.Type == "trojan" || outbound.Type == "selector" {
				t.Fatal("旧固定出口在撤销授权后仍可用")
			}
		}
		if config.Route.Final != "block" {
			t.Fatal("撤销后回退到未授权访问")
		}
	}
}
