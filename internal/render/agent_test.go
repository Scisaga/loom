package render

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/agent"
	"loom/internal/model"
	"loom/internal/report"
)

func agentConfigs(t *testing.T, s *model.SSOT) map[string]*agent.Config {
	t.Helper()
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*agent.Config{}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "agent/config.json" {
				continue
			}
			var c agent.Config
			if err := json.Unmarshal([]byte(f.Content), &c); err != nil {
				t.Fatalf("%s 的 Agent 配置不是合法 JSON:%v", b.Owner, err)
			}
			out[b.Owner] = &c
		}
	}
	return out
}

// 这是这一层真正要买的保险:Agent 配置与 sing-box 配置必须枚举出**同一批**
// 声明和候选。两边各写一遍枚举逻辑,迟早分叉,而分叉的表现很隐蔽 ——
// Agent 去切一个不存在的 selector(每轮报错),或者漏掉某条候选从不探测
// (它永远达不到 min_samples,于是永远不会被选中,看起来只是"它比较慢")。
func TestAgentAndSingBoxAgreeOnCandidates(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	cfgs := agentConfigs(t, s)

	for _, b := range res.Bundles {
		ac := cfgs[b.Owner]
		if ac == nil {
			continue
		}
		var raw string
		for _, f := range b.Files {
			if f.Path == "sing-box/config.json" {
				raw = f.Content
			}
		}
		if raw == "" {
			t.Fatalf("%s 有 Agent 配置却没有 sing-box 配置", b.Owner)
		}
		var sb struct {
			Inbounds []struct {
				Tag   string `json:"tag"`
				Users []struct {
					Username string `json:"username"`
				} `json:"users"`
			} `json:"inbounds"`
			Outbounds []struct {
				Tag       string   `json:"tag"`
				Type      string   `json:"type"`
				Outbounds []string `json:"outbounds"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(raw), &sb); err != nil {
			t.Fatal(err)
		}

		selectors := map[string][]string{}
		for _, o := range sb.Outbounds {
			if o.Type == "selector" {
				selectors[o.Tag] = o.Outbounds
			}
		}
		probeUsers := map[string]bool{}
		for _, in := range sb.Inbounds {
			if in.Tag == "probe-in" {
				for _, u := range in.Users {
					probeUsers[u.Username] = true
				}
			}
		}

		for _, d := range ac.Declarations {
			members, ok := selectors[d.Selector]
			if !ok {
				t.Errorf("%s:Agent 要切 %s,但 sing-box 里没有这个 selector",
					b.Owner, d.Selector)
				continue
			}
			inSel := map[string]bool{}
			for _, m := range members {
				inSel[m] = true
			}
			if len(members) != len(d.Candidates) {
				t.Errorf("%s/%s:selector 有 %d 个成员,Agent 只知道 %d 条候选",
					b.Owner, d.ID, len(members), len(d.Candidates))
			}
			for _, c := range d.Candidates {
				if !inSel[c.Tag] {
					t.Errorf("%s/%s:Agent 会探测 %s,但它不是 selector 的成员",
						b.Owner, d.ID, c.Tag)
				}
				if !probeUsers[c.ProbeUser] {
					t.Errorf("%s/%s:候选 %s 的探测用户名 %s 不在 probe-in 里 —— 探测会认证失败",
						b.Owner, d.ID, c.Tag, c.ProbeUser)
				}
				if c.ProbeUser != ProbeUser(c.Tag) {
					t.Errorf("%s:探测用户名与 ProbeUser() 不一致", c.Tag)
				}
			}
		}
	}
}

func TestAgentSelfReportAlwaysUsesLoopback(t *testing.T) {
	s := load(t)
	for node, cfg := range agentConfigs(t, s) {
		if cfg.Schema != agent.ConfigSchema {
			t.Errorf("%s 的新渲染 Agent 配置缺少 schema=%d，得到 %d", node, agent.ConfigSchema, cfg.Schema)
		}
		if !usesLinuxLifecycle(s.NodeByID()[node]) {
			if cfg.SelfReport != "" || len(cfg.Peers) != 0 || cfg.PeerPeriod != "" || cfg.AttestationCA != "" {
				t.Errorf("%s 的平台无关调度计划泄漏 Linux report/CA 依赖:%+v", node, cfg)
			}
			continue
		}
		if cfg.SelfReport != "127.0.0.1:61802" {
			t.Errorf("%s 的本机上报者依赖隧道地址:%q", node, cfg.SelfReport)
		}
	}
}

// Windows 不运行 Linux lifecycle，但它必须在 sing-box 的同一节点 bundle 里
// 获得完整的 agent.Config 调度计划。直接比对唯一候选推导函数，避免
// 平台分支只复制 selector 名称，却丢掉 Service 目标或评分/探测参数。
func TestWindowsAgentPlanContainsSameCompleteDeclarations(t *testing.T) {
	s := load(t)
	s.Services = append(s.Services, model.Service{
		ID: "windows-web", Addresses: []string{"api.example.com", ".example.com"}, Declaration: "best-egress",
	})
	workstation := s.NodeByID()["workstation"]
	if workstation == nil || workstation.Access.Platform != model.WindowsDesktop {
		t.Fatal("fixture 缺少 Windows workstation")
	}
	// 不支持的 objective 和 L4 不可表达的声明仍由共享推导函数
	// 显式记入 Skipped；不在 Windows 分支中另造一份“完整”候选。
	want, _ := renderAgentDeclarations(s, workstation)
	got := agentConfigs(t, s)[workstation.ID]
	if got == nil {
		t.Fatal("Windows bundle 缺少 agent/config.json")
	}
	gotJSON, err := json.Marshal(got.Declarations)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("Windows 调度计划与共享推导结果不同:\n got %s\nwant %s", gotJSON, wantJSON)
	}
	if got.API != APIListen || got.Probe != ProbeListen ||
		got.APISecret != secretRef("api/"+workstation.ID) || got.ProbeSecret != secretRef("probe/"+workstation.ID) {
		t.Fatalf("Windows 调度计划没有复用 sing-box 的控制/探测入口:%+v", got)
	}
	services := 0
	for _, d := range got.Declarations {
		if strings.HasPrefix(d.Selector, "svc:") {
			services++
		}
		if len(d.Candidates) == 0 || len(d.Targets) == 0 || d.Objective == "" ||
			d.TuningPeriod == "" || d.SwitchThreshold <= 0 || d.Window == "" ||
			d.MinSamples == 0 || d.StaleAfter == "" {
			t.Errorf("Windows 调度计划 %s 缺候选、目标或评分/探测参数:%+v", d.ID, d)
		}
	}
	if services == 0 {
		t.Fatal("Windows 调度计划没有任何 Service 级目标")
	}
}

func TestAgentAndReportShareObservationStale(t *testing.T) {
	s := load(t)
	agents := agentConfigs(t, s)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "report/config.json" {
				continue
			}
			var rc report.Config
			if err := json.Unmarshal([]byte(f.Content), &rc); err != nil {
				t.Fatal(err)
			}
			if rc.ObservationStale != observationStale {
				t.Errorf("%s report observation_stale=%q, want %q", b.Owner, rc.ObservationStale, observationStale)
			}
		}
	}
	for node, ac := range agents {
		if ac.ObservationStale != observationStale {
			t.Errorf("%s Agent observation_stale=%q, want %q", node, ac.ObservationStale, observationStale)
		}
	}
}

func TestAttestationUpgradeGateReachesEveryReader(t *testing.T) {
	s := load(t)
	s.Defaults.AttestationMinVersion = 5
	agents := agentConfigs(t, s)
	for node, cfg := range agents {
		if cfg.AttestationMinVersion != 5 {
			t.Errorf("%s Agent 没收到 phase-B 门禁:%d", node, cfg.AttestationMinVersion)
		}
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for node, cfg := range reportConfigs(t, res) {
		if cfg.AttestationMinVersion != 5 {
			t.Errorf("%s report 没收到 phase-B 门禁:%d", node, cfg.AttestationMinVersion)
		}
	}
}

func TestEveryReportConfigCarriesWholeNetworkCandidatePaths(t *testing.T) {
	s := load(t)
	want := map[string]bool{}
	for _, access := range s.AccessNodes() {
		for _, r := range report.ExpectedRoutesForAccess(s, access) {
			want[r.Access+"\x00"+r.Declaration+"\x00"+strings.Join(r.Chain, "\x00")] = true
		}
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	reports, serverWithPaths := 0, false
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "report/config.json" {
				continue
			}
			reports++
			var cfg report.Config
			if err := json.Unmarshal([]byte(f.Content), &cfg); err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, r := range cfg.ExpectedRoutes {
				got[r.Access+"\x00"+r.Declaration+"\x00"+strings.Join(r.Chain, "\x00")] = true
			}
			if len(got) != len(want) {
				t.Errorf("%s 只拿到 %d/%d 条全网候选路径", b.Owner, len(got), len(want))
			}
			for key := range want {
				if !got[key] {
					t.Errorf("%s 的 report 配置缺候选 %q", b.Owner, key)
				}
			}
			if !s.NodeByID()[b.Owner].IsAccess() && len(got) > 0 {
				serverWithPaths = true
			}
		}
	}
	if reports == 0 || !serverWithPaths {
		t.Fatal("没有证明服务器 UI 也能拿到接入节点的候选路径")
	}
}

// 渲染出来的配置必须能被 Agent 自己解析。Load 用 DisallowUnknownFields,
// 所以这条也顺带钉住"渲染端加了字段而消费端不认识"。
func TestRenderedAgentConfigLoads(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "agent/config.json" {
				continue
			}
			n++
			// 渲染层只写占位符,Load 会拒绝未替换的秘密 —— 这里模拟 hydrate。
			hydrated := strings.NewReplacer(
				"${secret:api/"+b.Owner+"}", "fake-api",
				"${secret:probe/"+b.Owner+"}", "fake-probe").Replace(f.Content)
			if _, err := agent.Load([]byte(hydrated)); err != nil {
				t.Errorf("%s 的 Agent 配置无法被 Agent 解析:%v", b.Owner, err)
			}
			// 未 hydrate 的必须被挡住,否则表现是"认证一直失败"。
			if _, err := agent.Load([]byte(f.Content)); err == nil {
				t.Errorf("%s:未替换占位符的配置竟然通过了加载", b.Owner)
			}
		}
	}
	if n == 0 {
		t.Fatal("没有渲染出任何 Agent 配置")
	}
}

// selector 的默认值不该是直连:实测 best-egress 的直连候选对目标超时 10 秒,
// 而 sing-box 每次重启都回到 default。Agent 没起来的那段时间里,流量会一直
// 打在一条已知不通的路上。
func TestSelectorDefaultAvoidsDirect(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "sing-box/config.json" {
				continue
			}
			var sb struct {
				Outbounds []struct {
					Tag       string   `json:"tag"`
					Type      string   `json:"type"`
					Default   string   `json:"default"`
					Outbounds []string `json:"outbounds"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal([]byte(f.Content), &sb); err != nil {
				t.Fatal(err)
			}
			for _, o := range sb.Outbounds {
				if o.Type != "selector" || !strings.HasSuffix(o.Default, ":direct") {
					continue
				}
				// 只有"除了直连没别的候选"时才允许。
				for _, m := range o.Outbounds {
					if !strings.HasSuffix(m, ":direct") {
						t.Errorf("%s 的 %s 默认停在直连,而它还有别的候选 %v",
							b.Owner, o.Tag, o.Outbounds)
						break
					}
				}
			}
		}
	}
}
