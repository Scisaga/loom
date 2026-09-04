package render

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"loom/internal/agent"
	"loom/internal/model"
	"loom/internal/report"
)

func reportConfigs(t *testing.T, res *Result) map[string]*report.Config {
	t.Helper()
	out := map[string]*report.Config{}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "report/config.json" {
				continue
			}
			c, err := report.Load([]byte(f.Content))
			if err != nil {
				t.Fatalf("%s 的上报者配置无法被 report 解析:%v", b.Owner, err)
			}
			out[b.Owner] = c
		}
	}
	return out
}

func TestEveryInnerPairHasExactlyOneDialableLinkMetricDirection(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	cfgs := reportConfigs(t, res)
	var inner []*model.Node
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Decommission && n.MeshEligible() && runsSingBox(n) {
			inner = append(inner, n)
		}
	}
	wantPairs := map[string]bool{}
	for i := 0; i < len(inner); i++ {
		for j := i + 1; j < len(inner); j++ {
			a, b := inner[i].ID, inner[j].ID
			if b < a {
				a, b = b, a
			}
			wantPairs[a+"\x00"+b] = true
		}
	}
	if len(wantPairs) == 0 {
		t.Fatal("fixture 没有可检查的内圈无向对")
	}

	// ExpectedDirectLinks is the no-secret global inventory repeated in
	// every reporter config. Check one copy and then require all copies to
	// be identical, so a node cannot render a different topology contract.
	var baseline []report.ExpectedDirectLink
	for id, cfg := range cfgs {
		if baseline == nil {
			baseline = cfg.ExpectedDirectLinks
		} else if !sameExpectedDirectLinks(baseline, cfg.ExpectedDirectLinks) {
			t.Fatalf("%s 的 ExpectedDirectLinks 与其他节点不一致: %+v vs %+v",
				id, cfg.ExpectedDirectLinks, baseline)
		}
	}
	counts := map[string]int{}
	inbound := map[string]int{}
	tunnelPairs := map[string]bool{}
	for _, tunnel := range s.Tunnels {
		a, b := tunnel.From, tunnel.To
		if b < a {
			a, b = b, a
		}
		tunnelPairs[a+"\x00"+b] = true
	}
	nodes := s.NodeByID()
	for _, link := range baseline {
		a, b := link.From, link.To
		if b < a {
			a, b = b, a
		}
		pair := a + "\x00" + b
		counts[pair]++
		if tunnelPairs[pair] {
			t.Errorf("有效 SSOT 将同一节点对同时渲染为 WG 和 direct Hy2: %q", pair)
		}
		target := nodes[link.To]
		if target == nil || !target.PubliclyDialable() || target.Server == nil ||
			target.Server.InboundProtocol.Or() != model.Hysteria2 {
			t.Errorf("%s→%s 的目标不是可拨 Hysteria2 inbound", link.From, link.To)
		} else {
			inbound[link.To]++
		}
	}
	for pair := range wantPairs {
		if counts[pair] != 1 {
			t.Errorf("内圈无向对 %q 有 %d 个可拨方向，want exactly 1", pair, counts[pair])
		}
	}
	for pair, count := range counts {
		if !wantPairs[pair] {
			t.Errorf("渲染了不属于内圈的 direct link %q (%d)", pair, count)
		}
	}
	publicHy2 := 0
	for _, n := range inner {
		if n.PubliclyDialable() && n.Server.InboundProtocol.Or() == model.Hysteria2 {
			publicHy2++
		}
	}
	coveragePossible := publicHy2 >= 3 || (publicHy2 > 0 && publicHy2 < len(inner))
	if coveragePossible {
		for _, n := range inner {
			if n.PubliclyDialable() && n.Server.InboundProtocol.Or() == model.Hysteria2 && inbound[n.ID] == 0 {
				t.Errorf("可公网拨入节点 %s 没有任何定向探测", n.ID)
			}
		}
	}
}

func sameExpectedDirectLinks(a, b []report.ExpectedDirectLink) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Linux 上报者覆盖所有 Linux 节点；Windows/Android 的同类观测由各自平台宿主承担。
func TestEveryTunneledNodeGetsAReporter(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	cfgs := reportConfigs(t, res)

	// 平台边界必须是双向的：Linux 不能漏，非 Linux 也不能夹带 Linux 配置。
	for i := range s.Nodes {
		n := &s.Nodes[i]
		got := cfgs[n.ID] != nil
		if want := usesLinuxLifecycle(n); got != want {
			t.Errorf("%s:report 配置=%v,期望 Linux 生命周期=%v", n.ID, got, want)
		}
	}
	// 每份配置都要配一个 unit,否则没人启动它。
	for _, b := range res.Bundles {
		has, unit := false, false
		for _, f := range b.Files {
			switch f.Path {
			case "report/config.json":
				has = true
			case "systemd/loom-report.service":
				unit = true
			}
		}
		if has != unit {
			t.Errorf("%s:上报者配置=%v 但 unit=%v", b.Owner, has, unit)
		}
	}
}

func TestReporterCarriesRoleScopedComponentExpectations(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for owner, cfg := range reportConfigs(t, res) {
		n := s.NodeByID()[owner]
		want := s.VersionsFor(n)
		if runsSingBox(n) && cfg.ExpectedComponents.SingBox != want.SingBox {
			t.Errorf("%s sing-box expectation=%q, want %q", owner, cfg.ExpectedComponents.SingBox, want.SingBox)
		}
		if len(cfg.Interfaces) > 0 && cfg.ExpectedComponents.WireGuard != want.WireGuard {
			t.Errorf("%s wireguard expectation=%q, want %q", owner, cfg.ExpectedComponents.WireGuard, want.WireGuard)
		}
		if runsAgent(s, n) {
			if cfg.ExpectedComponents.Agent != want.Agent {
				t.Errorf("%s agent expectation=%q, want %q", owner, cfg.ExpectedComponents.Agent, want.Agent)
			}
		} else if cfg.ExpectedComponents.Agent != "" {
			t.Errorf("server-only %s unexpectedly probes agent version %q", owner, cfg.ExpectedComponents.Agent)
		}
	}
}

func TestWorkloadPredicatesDoNotTreatRolesAsRunningProcesses(t *testing.T) {
	tunnelOnly := &model.Node{Server: &model.ServerRole{}}
	if runsSingBox(tunnelOnly) {
		t.Fatal("server role without inbound_port was treated as a sing-box workload")
	}
	accessWithoutDeclarations := &model.Node{ID: "access", Access: &model.AccessRole{}}
	if runsAgent(&model.SSOT{Nodes: []model.Node{*accessWithoutDeclarations}}, accessWithoutDeclarations) {
		t.Fatal("access role without tunable declarations was treated as a running Agent")
	}
}

// 监听地址必须全是隧道内地址。渲染出一个公网地址不会有任何症状 ——
// 拓扑就那么静静地暴露着。
func TestReporterListensOnlyOnTunnelAddresses(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for owner, c := range reportConfigs(t, res) {
		if len(c.Listen) == 0 {
			t.Errorf("%s 的上报者没有监听地址", owner)
		}
		for _, a := range c.Listen {
			host, _, err := net.SplitHostPort(a)
			if err != nil {
				t.Fatalf("%s:%v", owner, err)
			}
			ip := net.ParseIP(host)
			if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
				t.Errorf("%s 的上报者监听 %s —— 既不是隧道内地址也不是回环", owner, a)
			}
		}
		// 隧道地址一条不少,外加**永远有**的回环 —— ssh 端口转发是隧道
		// 断掉时唯一还能进的路,而那正是最需要看它的时候。
		want := 0
		for i := range s.Tunnels {
			if s.Tunnels[i].From == owner || s.Tunnels[i].To == owner {
				want++
			}
		}
		if len(c.Interfaces) != want {
			t.Errorf("%s 有 %d 条隧道,却列了 %d 个接口", owner, want, len(c.Interfaces))
		}
		if len(c.Listen) != want+1 {
			t.Errorf("%s 有 %d 条隧道,应当监听 %d 个地址(含回环),实际 %d 个:%v",
				owner, want, want+1, len(c.Listen), c.Listen)
		}
		loop := false
		for _, a := range c.Listen {
			if strings.HasPrefix(a, "127.0.0.1:") {
				loop = true
			}
		}
		if !loop {
			t.Errorf("%s 没有绑回环 —— 隧道断掉时就进不去了:%v", owner, c.Listen)
		}
	}
}

// Agent 拉取的必须是**对端**的地址,不是自己那一头。写反了不会报错 ——
// 它会去连自己的地址,然后拿回自己的状态,看起来一切正常。
func TestAgentPeersPointAtTheOtherEnd(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	cfgs := reportConfigs(t, res)

	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "agent/config.json" {
				continue
			}
			var ac agent.Config
			if err := json.Unmarshal([]byte(f.Content), &ac); err != nil {
				t.Fatal(err)
			}
			self := cfgs[b.Owner]
			selfAddrs := map[string]bool{}
			if self != nil {
				for _, a := range self.Listen {
					selfAddrs[a] = true
				}
			}
			for _, p := range ac.Peers {
				if p.Node == b.Owner {
					t.Errorf("%s 把自己列成了对端", b.Owner)
				}
				if selfAddrs[p.Addr] {
					t.Errorf("%s 的对端 %s 指向自己的监听地址 %s —— 地址取反了",
						b.Owner, p.Node, p.Addr)
				}
				peer := cfgs[p.Node]
				if peer == nil {
					t.Errorf("%s 要拉 %s,但 %s 没有上报者", b.Owner, p.Node, p.Node)
					continue
				}
				found := false
				for _, a := range peer.Listen {
					if a == p.Addr {
						found = true
					}
				}
				if !found {
					t.Errorf("%s 要拉 %s 的 %s,但 %s 并不监听这个地址(它监听 %v)",
						b.Owner, p.Node, p.Addr, p.Node, peer.Listen)
				}
			}
			// 有隧道的接入节点必须列出全部隧道对端,不能少。
			want := 0
			for i := range s.Tunnels {
				if s.Tunnels[i].From == b.Owner || s.Tunnels[i].To == b.Owner {
					want++
				}
			}
			if len(ac.Peers) != want {
				t.Errorf("%s 有 %d 条隧道,却只列了 %d 个对端", b.Owner, want, len(ac.Peers))
			}
		}
	}
}

// 每个配置包里的文件都要有约定的安装位置 —— 没有的话它不进自检清单,
// 机器上被人改了也发现不了。
func TestEveryRenderedFileHasAnInstallPath(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if InstallPath(f.Path) == "" {
				t.Errorf("%s/%s 没有约定的安装位置", b.Owner, f.Path)
			}
		}
	}
	if InstallPath("不认识的/东西") != "" {
		t.Error("未知前缀应当返回空,而不是猜一个路径")
	}
}

// 上报接口的端口不能落进对外放行的隧道端口段里 —— 它只绑隧道内地址,
// 但端口撞上会在排障时造成误解。
func TestReportPortIsOutsideTunnelRange(t *testing.T) {
	if ReportPort >= model.TunnelPortMin && ReportPort <= model.TunnelPortMax {
		t.Errorf("上报端口 %d 落在隧道端口段 %d-%d 内",
			ReportPort, model.TunnelPortMin, model.TunnelPortMax)
	}
	if ReportPort == 61800 || ReportPort == 61801 {
		t.Errorf("上报端口 %d 与控制端点或探测入口冲突", ReportPort)
	}
}

func TestReporterUnitRunsTheRightCommand(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "systemd/loom-report.service" {
				continue
			}
			if !strings.Contains(f.Content, "loom report -c /etc/loom/report/config.json -serve") {
				t.Errorf("%s 的上报者 unit 启动命令不对:\n%s", b.Owner, f.Content)
			}
			// 有隧道的节点必须等接口起来,否则没有地址可绑。
			hasTunnel := false
			for i := range s.Tunnels {
				if s.Tunnels[i].From == b.Owner || s.Tunnels[i].To == b.Owner {
					hasTunnel = true
				}
			}
			if hasTunnel != strings.Contains(f.Content, "After=wg-quick@") {
				t.Errorf("%s:有隧道=%v,但 unit 里等隧道=%v", b.Owner, hasTunnel, !hasTunnel)
			}
		}
	}
}

// 过渡窗口里服务器必须**同时**接受两代,而且路由规则要匹配两个用户名。
//
// 只匹配当前代的话,用旧凭据连上来的流量认证过了却没有规则接,落到
// `final: block` —— 客户端看到的是"连上了然后没反应",比认证失败难查得多。
func TestRotationWindowAcceptsBothGenerations(t *testing.T) {
	s := load(t)
	// 挑一份被服务器接受的凭据,把它推进到第二代并开着过渡窗口。
	if len(s.Credentials) == 0 {
		t.Skip("fixture 里没有凭据")
	}
	target := &s.Credentials[0]
	target.Generation = 2
	target.AcceptPrevious = true

	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "sing-box/config.json" {
				continue
			}
			var c struct {
				Inbounds []struct {
					Tag   string `json:"tag"`
					Users []struct {
						Name     string `json:"name"`
						Password string `json:"password"`
					} `json:"users"`
				} `json:"inbounds"`
				Route struct {
					Rules []struct {
						AuthUser []string `json:"auth_user"`
					} `json:"rules"`
				} `json:"route"`
			}
			if err := json.Unmarshal([]byte(f.Content), &c); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, in := range c.Inbounds {
				if in.Tag != "in" {
					continue // 只看服务器的入站,不看探测入口
				}
				for _, u := range in.Users {
					names = append(names, u.Name)
				}
			}
			if len(names) == 0 {
				continue
			}
			checked++
			cur, prev := target.ID, target.PrevUser()
			has := func(x string) bool {
				for _, n := range names {
					if n == x {
						return true
					}
				}
				return false
			}
			if !has(cur) {
				continue // 这台服务器不接受这份凭据
			}
			if !has(prev) {
				t.Errorf("%s 只接受当前代,没有上一代 %s —— 轮换会断连", b.Owner, prev)
			}
			// 规则必须匹配两个名字。
			matched := false
			for _, r := range c.Route.Rules {
				var seenCur, seenPrev bool
				for _, u := range r.AuthUser {
					if u == cur {
						seenCur = true
					}
					if u == prev {
						seenPrev = true
					}
				}
				if seenCur {
					matched = true
					if !seenPrev {
						t.Errorf("%s 有一条规则只匹配当前代 %v —— 旧凭据的流量会落到 final: block",
							b.Owner, r.AuthUser)
					}
				}
			}
			if !matched {
				t.Errorf("%s 接受 %s 但没有任何规则匹配它", b.Owner, cur)
			}
		}
	}
	if checked == 0 {
		t.Fatal("没有检查到任何服务器入站")
	}
}

// 客户端只用当前代 —— 它要是也发旧的,过渡窗口就永远关不掉。
func TestClientUsesCurrentGenerationOnly(t *testing.T) {
	s := load(t)
	if len(s.Credentials) == 0 {
		t.Skip("fixture 里没有凭据")
	}
	target := &s.Credentials[0]
	target.Generation = 2
	target.AcceptPrevious = true
	prevPlaceholder := "${secret:" + target.PrevRef() + "}"

	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		if s.NodeByID()[b.Owner] == nil || !s.NodeByID()[b.Owner].IsAccess() {
			continue
		}
		for _, f := range b.Files {
			if f.Path != "sing-box/config.json" {
				continue
			}
			// 接入节点上出现上一代的引用,就说明客户端也在用旧的。
			// (双角色机器的服务器入站会有,所以只看 outbound 段之外的
			// 精确匹配不可靠 —— 这里用出站里是否出现来判断。)
			var c struct {
				Outbounds []struct {
					Password string `json:"password"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal([]byte(f.Content), &c); err != nil {
				t.Fatal(err)
			}
			for _, o := range c.Outbounds {
				if o.Password == prevPlaceholder {
					t.Errorf("%s 的出站还在用上一代凭据 %s", b.Owner, target.PrevRef())
				}
			}
		}
	}
}
