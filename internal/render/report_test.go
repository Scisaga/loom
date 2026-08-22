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

// 上报者装在**每个**有隧道的节点上,服务器也要 —— DDNS 重解析、隧道断连、
// 有人手工改配置,这些只有节点自己知道。
func TestEveryTunneledNodeGetsAReporter(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	cfgs := reportConfigs(t, res)

	// 每个节点都要有 —— 没有隧道的纯接入节点绑回环,远端拉不到,但
	// 本机的配置自检不能因此消失。
	for i := range s.Nodes {
		if cfgs[s.Nodes[i].ID] == nil {
			t.Errorf("%s 没有上报者配置", s.Nodes[i].ID)
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
		// 有隧道时:监听地址数等于隧道数。没有隧道时:一个回环地址、零个接口。
		want := 0
		for i := range s.Tunnels {
			if s.Tunnels[i].From == owner || s.Tunnels[i].To == owner {
				want++
			}
		}
		if len(c.Interfaces) != want {
			t.Errorf("%s 有 %d 条隧道,却列了 %d 个接口", owner, want, len(c.Interfaces))
		}
		switch {
		case want > 0 && len(c.Listen) != want:
			t.Errorf("%s 有 %d 条隧道,却监听 %d 个地址", owner, want, len(c.Listen))
		case want == 0 && (len(c.Listen) != 1 || !strings.HasPrefix(c.Listen[0], "127.0.0.1:")):
			t.Errorf("%s 没有隧道,监听地址应当只有回环,实际 %v", owner, c.Listen)
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
