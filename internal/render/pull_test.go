package render

import (
	"strings"
	"testing"

	"loom/internal/model"
)

// 没有配置分发点时不能悄悄不渲染 —— 那样节点就只能被 ssh 推,而"为什么
// 我的机器不自己更新"会查很久。
func TestMissingDistributionURLIsReported(t *testing.T) {
	src := []byte(`
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`)
	s, err := model.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, sk := range res.Skipped {
		if strings.Contains(sk.Reason, "distribution_url") {
			n++
		}
	}
	if n != len(s.Nodes) {
		t.Errorf("%d 个节点缺分发点,只报了 %d 条", len(s.Nodes), n)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if strings.HasPrefix(f.Path, "systemd/loom-pull.") {
				t.Errorf("没有分发点却渲染了 %s", f.Path)
			}
		}
	}
}

// pull 必须用**本节点声明的** DNS,不能用机器的全局解析器 —— access-a 上有个
// 与 Loom 无关的接口把所有域名劫到 8.8.8.8,在境内解析不了任何国内域名。
func TestPullUsesDeclaredDNS(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	nodes := s.NodeByID()
	found := 0
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "systemd/loom-pull.service" {
				continue
			}
			found++
			dns := s.DNSFor(nodes[b.Owner])
			if len(dns) == 0 {
				continue
			}
			if !strings.Contains(f.Content, "-dns "+dns[0]) {
				t.Errorf("%s 的 pull unit 没用声明的 DNS %s:\n%s", b.Owner, dns[0], f.Content)
			}
		}
	}
	if found == 0 {
		t.Fatal("没有渲染出任何 pull unit")
	}
}

// 五台机器同时去拉会在分发点上撞一起,也会让全网在同一秒重启同一个服务。
func TestPullTimerIsJittered(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path == "systemd/loom-pull.timer" && !strings.Contains(f.Content, "RandomizedDelaySec") {
				t.Errorf("%s 的 pull timer 没有抖动", b.Owner)
			}
		}
	}
}
