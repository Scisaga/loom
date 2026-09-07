package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"loom/internal/agent"
	"loom/internal/model"
)

// 本文件渲染接入节点上的 Agent 配置(§5.5 的调参回路)。
//
// **节点上不放 SSOT。** Agent 要的只是"探测哪些候选、打哪个目标、多久一轮、
// 什么时候允许切",这些全都能从 SSOT 纯函数导出。把整份 SSOT 铺到每台机器
// 上,等于把全网拓扑和别人的凭据一起交出去。

const agentUnit = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=Loom Agent (调参回路 %s)
# 控制端点和探测入口都在 sing-box 里,它没起来时 Agent 无事可做。
# 上报者要先起来:Agent 的第一轮就要问它拿全网观测来剪枝,晚一步就得
# 等一整个 tuning_period(实测两者同时重启会撞上这个race)。
After=sing-box.service loom-report.service
Wants=sing-box.service loom-report.service

[Service]
Type=simple
ExecStart=/usr/local/bin/loom agent -c /etc/loom/agent/config.json
Restart=on-failure
RestartSec=10s
# 配置里含控制端点口令,只允许 root 读
UMask=0077
NoNewPrivileges=true
StateDirectory=loom

[Install]
WantedBy=multi-user.target
`

// renderAgent 生成 Linux 接入节点的 Agent 配置与 unit。Windows 只复用
// renderAgentPlan 产出的平台无关调度计划，它的宿主生命周期不在此处表达。
func renderAgent(s *model.SSOT, p *model.Node) ([]File, []Skip) {
	files, skips := renderAgentPlan(s, p)
	if len(files) == 0 {
		return nil, skips
	}
	return append(files, File{
		Path: "systemd/loom-agent.service", Content: fmt.Sprintf(agentUnit, p.ID),
	}), skips
}

// renderAgentPlan 生成接入节点本地调参回路的已有 agent.Config 协议。
//
// 这个文件与 sing-box/config.json 进入同一节点 bundle，由 bundle hash
// 和 snapshot 签名一起绑定；不设第二个调度系统或旁路交付。候选、Service
// 目标和评分/探测参数仍全部由 renderAgentDeclarations 从 SSOT 推导。
//
// Linux 的对端观测剪枝依赖 report、节点 CA 路径和 systemd，因此只在 Linux
// 计划中增补；Windows 包里只放可由平台宿主消费的本地端到端调参输入。
func renderAgentPlan(s *model.SSOT, p *model.Node) ([]File, []Skip) {
	if !p.IsAccess() {
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
		ObservationStale:      observationStale,
		AttestationMinVersion: s.AttestationMinVersion(),
	}

	if usesLinuxLifecycle(p) {
		cfg.AttestationCA = tlsCAPath
		// 能顺着隧道直接够到的节点。AllowedIPs 是 /32,所以只有隧道对端 ——
		// 拉不到"对端的对端"。
		shortest := ""
		for i := range cfg.Declarations {
			if period := cfg.Declarations[i].TuningPeriod; shortest == "" || shorterPeriod(period, shortest) {
				shortest = period
			}
		}
		for i := range s.Tunnels {
			t := &s.Tunnels[i]
			peer := ""
			switch p.ID {
			case t.From:
				peer = t.To
			case t.To:
				peer = t.From
			default:
				continue
			}
			if a := s.TunnelAddrOn(peer, p.ID); a != "" {
				cfg.Peers = append(cfg.Peers, agent.Peer{
					Node: peer, Addr: fmt.Sprintf("%s:%d", a, ReportPort)})
			}
		}
		sort.Slice(cfg.Peers, func(i, j int) bool { return cfg.Peers[i].Node < cfg.Peers[j].Node })
		// 本机上报者必须明确走 loopback。Listen 排序后第一个常常是 10.99.*，
		// 从 report 配置反取会把“本机”错误地绑到 WG 是否在线。
		cfg.SelfReport = fmt.Sprintf("127.0.0.1:%d", ReportPort)
		// 拉取节奏跟最短的调参周期走,不另发明一个旋钮:上报阈值是 5 分钟,
		// 按同样的量级去拉就够了。
		cfg.PeerPeriod = shortest
	}

	if len(cfg.Declarations) == 0 {
		skips = append(skips, Skip{
			Where:  "agent:" + p.ID,
			Reason: "没有任何可调参的声明,不生成 Agent 配置",
		})
		return nil, skips
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

// renderAgentDeclarations 是 Agent 配置与 report.expected_routes 的唯一候选
// 推导。两份消费者各枚举一次迟早会让“可选路径”和“Agent 真能选的路径”漂移。
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

// shorterPeriod 比较两个时长字符串。解析不了的一律当成"不更短",
// 让校验器去报错,渲染这边不越权。
func shorterPeriod(a, b string) bool {
	da, err1 := time.ParseDuration(a)
	db, err2 := time.ParseDuration(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return da < db
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
