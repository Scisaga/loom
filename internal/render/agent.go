package render

import (
	"encoding/json"

	"loom/internal/agent"
	"loom/internal/model"
)

// 本文件只保留 Windows/Android 现有签名 bundle 的平台无关调度计划。
// Linux 不再获得 Agent 配置或独立生命周期；其统一运行时消费 DeviceView。
//
// **节点上不放 SSOT。** Agent 要的只是"探测哪些候选、打哪个目标、多久一轮、
// 什么时候允许切",这些全都能从 SSOT 纯函数导出。把整份 SSOT 铺到每台机器
// 上,等于把全网拓扑和别人的凭据一起交出去。

const observationStale = "10m"

// renderAgentPlan 生成接入节点本地调参回路的已有 agent.Config 协议。
//
// 这个文件与 sing-box/config.json 进入同一节点 bundle，由 bundle hash
// 和 snapshot 签名一起绑定；不设第二个调度系统或旁路交付。候选、Service
// 目标和评分/探测参数仍全部由 renderAgentDeclarations 从 SSOT 推导。
func renderAgentPlan(s *model.SSOT, p *model.Node) ([]File, []Skip) {
	if !p.IsAccess() || p.Access.Platform.UsesLinuxLifecycle() {
		return nil, nil
	}
	declarations, skips := renderAgentDeclarations(s, p)
	cfg := agent.Config{
		Schema:                agent.ConfigSchema,
		Node:                  p.ID,
		API:                   APIListen,
		APISecret:             secretRef("api/" + p.ID),
		Probe:                 ProbeListen,
		ProbeSecret:           secretRef("probe/" + p.ID),
		Declarations:          declarations,
		Selectors:             renderSelectorPlans(s, p),
		ObservationStale:      observationStale,
		AttestationMinVersion: s.AttestationMinVersion(),
	}

	if len(cfg.Declarations) == 0 {
		reason := "没有任何可自动调参的声明；仍交付 selector 计划供客户端三态切换"
		if len(cfg.Selectors) == 0 {
			reason = "没有任何可调参的声明,不生成 Agent 配置"
		}
		skips = append(skips, Skip{
			Where:  "agent:" + p.ID,
			Reason: reason,
		})
		// Linux 没有循环可跑时不安装空 Agent。移动/桌面客户端仍需要完整
		// selector 计划承载三态偏好，即使某些 objective 暂不能自动排名。
		if len(cfg.Selectors) == 0 {
			return nil, skips
		}
	}

	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		// Config 全是具体类型,序列化不会失败;真失败了也不能悄悄少写文件。
		return nil, append(skips, Skip{Where: "agent:" + p.ID, Reason: err.Error()})
	}
	return []File{
		{Path: "agent/config.json", Content: string(b) + "\n"},
	}, skips
}

// renderSelectorPlans 覆盖 sing-box 中客户端可写的全部 selector，包括因 objective
// 或探测目标不足而不能进入 Agent 自动排序的声明。顶层模式仍必须能安全地切换这些
// selector；候选链在这里由 renderer 明示，客户端不得从 opaque tag 猜拓扑。
func renderSelectorPlans(s *model.SSOT, p *model.Node) []agent.SelectorPlan {
	declIDs, _ := accessDecls(s, p)
	declarations := s.DeclarationByID()
	pinned, _ := pinnedDecls(p)
	var plans []agent.SelectorPlan
	appendPlan := func(selector string, candidates []model.RouteCandidate) {
		if len(candidates) == 0 {
			return
		}
		plan := agent.SelectorPlan{Selector: selector}
		var tags []string
		for i := range candidates {
			tag := candidates[i].Tag()
			tags = append(tags, tag)
			plan.Candidates = append(plan.Candidates, agent.Cand{
				Tag: tag, Chain: append([]string(nil), candidates[i].ServerChain...), ProbeUser: ProbeUser(tag),
			})
		}
		plan.Default = selectorDefault(tags)
		plans = append(plans, plan)
	}
	for _, declarationID := range declIDs {
		declaration := declarations[declarationID]
		if declaration == nil {
			continue
		}
		if pinned[declarationID] {
			candidates, _ := s.EnumerateCandidates(p, declaration)
			appendPlan("decl:"+declarationID, candidates)
		}
		for _, service := range s.ServicesFor(declarationID) {
			candidates, _ := s.EnumerateServiceCandidates(p, declaration, service)
			appendPlan(service.Tag(), candidates)
		}
	}
	return plans
}

// renderAgentDeclarations 为仍在范围内的平台宿主导出候选与探测计划。
func renderAgentDeclarations(s *model.SSOT, p *model.Node) ([]agent.Decl, []Skip) {
	declIDs, _ := accessDecls(s, p)
	decls := s.DeclarationByID()
	pinned, _ := pinnedDecls(p)
	var out []agent.Decl
	var skips []Skip
	for _, did := range declIDs {
		d, ok := decls[did]
		if !ok {
			continue
		}
		// 跑不了的 objective 必须在渲染期就说出来,而不是让 Agent 在节点上
		// 启动失败 —— 那时候人已经不在终端前面了(§12 的"不静默降级")。
		if ok, why := agent.Supported(d.Objective); !ok {
			skips = append(skips, Skip{
				Where:  "agent:" + p.ID + "/" + did,
				Reason: "该声明不进 Agent 配置:" + why,
			})
			continue
		}
		// 被端口钉住的声明才有声明级 selector;只治理服务的声明,
		// 调参落在各个服务上(§4.5)。
		if pinned[did] {
			cands, _ := s.EnumerateCandidates(p, d)
			if len(cands) == 0 {
				continue // 没有候选就没有 selector,Agent 去读会直接报错
			}
			ad := newDecl(did, "decl:"+did, d, []string{d.ProbeURL})
			for i := range cands {
				tag := cands[i].Tag()
				ad.Candidates = append(ad.Candidates, agent.Cand{
					Tag: tag, Chain: append([]string(nil), cands[i].ServerChain...),
					ProbeUser: ProbeUser(tag),
				})
			}
			out = append(out, ad)
		}

		// 每个服务独立调参 —— 这正是 D43 修正的那点。
		for _, svc := range s.ServicesFor(did) {
			cands, _ := s.EnumerateServiceCandidates(p, d, svc)
			if len(cands) == 0 {
				continue
			}
			targets := probeURLsFor(svc)
			if len(targets) == 0 {
				skips = append(skips, Skip{
					Where: "agent:" + p.ID + "/svc:" + svc.ID,
					Reason: "服务只有后缀地址,没有可探测的具体地址 —— " +
						"它进不了 Agent 配置,selector 会停在默认候选上",
				})
				continue
			}
			ad := newDecl(svc.ID, svc.Tag(), d, targets)
			for i := range cands {
				tag := cands[i].Tag()
				ad.Candidates = append(ad.Candidates, agent.Cand{
					Tag: tag, Chain: append([]string(nil), cands[i].ServerChain...),
					ProbeUser: ProbeUser(tag),
				})
			}
			out = append(out, ad)
		}
	}
	return out, skips
}

// newDecl 造一个调参目标:一个 selector + 一组候选 + 一组探测目标 + 策略。
//
// 策略(objective、周期、阻尼)来自访问声明;服务只是把它套用在自己那组
// 地址上。多个服务共用一条声明是常见的 —— 同样的策略,各自选路。
func newDecl(id, selector string, d *model.AccessDeclaration, targets []string) agent.Decl {
	return agent.Decl{
		ID: id, Selector: selector,
		Objective: d.Objective, Targets: targets,
		TuningPeriod: d.TuningPeriod, SwitchThreshold: d.SwitchThreshold,
		Window: d.Window, MinSamples: d.MinSamples, StaleAfter: d.StaleAfter,
		ProbeBudget: d.ProbeBudget,
	}
}

// probeURLsFor 把服务的地址变成可探测的 URL。
//
// 后缀地址(`.baidu.com`)探不了 —— 它不是一个具体主机。所以服务至少要有
// 一个具体地址,否则它没法被度量,只能停在默认候选上。
func probeURLsFor(svc *model.Service) []string {
	var out []string
	for _, a := range svc.SortedAddresses() {
		if model.IsSuffix(a) {
			continue
		}
		out = append(out, "https://"+a+"/")
	}
	return out
}
