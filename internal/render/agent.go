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
After=sing-box.service
Wants=sing-box.service

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

// renderAgent 生成接入节点的 Agent 配置与 unit。
//
// 只有接入节点需要:调参是"这个接入点该走哪条路"的决定(§5.1),服务器
// 上没有 selector 可切。
func renderAgent(s *model.SSOT, p *model.Node) ([]File, []Skip) {
	if !p.IsAccess() {
		return nil, nil
	}
	declIDs, _ := accessDecls(s, p)
	decls := s.DeclarationByID()

	var skips []Skip
	cfg := agent.Config{
		Node:        p.ID,
		API:         APIListen,
		APISecret:   secretRef("api/" + p.ID),
		Probe:       ProbeListen,
		ProbeSecret: secretRef("probe/" + p.ID),
	}

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
		cands, _ := s.EnumerateCandidates(p, d)
		if len(cands) == 0 {
			// 没有候选就没有 selector,Agent 去读会直接报错。
			continue
		}
		ad := agent.Decl{
			ID: did, Selector: "decl:" + did,
			Objective: d.Objective, ProbeURL: d.ProbeURL,
			TuningPeriod: d.TuningPeriod, SwitchThreshold: d.SwitchThreshold,
			Window: d.Window, MinSamples: d.MinSamples, StaleAfter: d.StaleAfter,
		}
		for i := range cands {
			tag := cands[i].Tag()
			ad.Candidates = append(ad.Candidates, agent.Cand{Tag: tag, ProbeUser: ProbeUser(tag)})
		}
		sort.Slice(ad.Candidates, func(i, j int) bool {
			return ad.Candidates[i].Tag < ad.Candidates[j].Tag
		})
		cfg.Declarations = append(cfg.Declarations, ad)
	}

	// 能顺着隧道直接够到的节点。AllowedIPs 是 /32,所以只有隧道对端 ——
	// 拉不到"对端的对端"。
	shortest := ""
	for i := range cfg.Declarations {
		if p := cfg.Declarations[i].TuningPeriod; shortest == "" || shorterPeriod(p, shortest) {
			shortest = p
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
	// 拉取节奏跟最短的调参周期走,不另发明一个旋钮:上报阈值是 5 分钟,
	// 按同样的量级去拉就够了。
	cfg.PeerPeriod = shortest

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
		{Path: "systemd/loom-agent.service", Content: fmt.Sprintf(agentUnit, p.ID)},
	}, skips
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
