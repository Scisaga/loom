package model

import (
	"strings"
	"testing"
)

const lifecycleSSOT = `
defaults: {dns: [223.5.5.5], distribution_url: "https://x/", components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    server: {direction: bidirectional, wg_public_key: k0}
    access:
      platform: linux-server
      credentials: [c1]
      mixed_ports: [{port: 1080, declaration: d1}]
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
  - {id: b, public_endpoint: 192.0.2.2, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k2}%s}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, max_hops: 2, allowed_servers: [a, b]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
`

func candidatesFor(t *testing.T, extra string) []string {
	t.Helper()
	s, err := Load([]byte(strings.Replace(lifecycleSSOT, "%s", extra, 1)))
	if err != nil {
		t.Fatal(err)
	}
	var acc *Node
	for i := range s.Nodes {
		if s.Nodes[i].ID == "acc" {
			acc = &s.Nodes[i]
		}
	}
	cands, _ := s.EnumerateCandidates(acc, s.DeclarationByID()["d1"])
	var out []string
	for i := range cands {
		out = append(out, cands[i].Tag())
	}
	return out
}

// 排空的机器不进候选。这是迁移能安全做的前提:新旧并存,让实测数据决定
// 什么时候切,而不是"删掉旧的然后祈祷"。
func TestDrainRemovesFromCandidates(t *testing.T) {
	before := candidatesFor(t, "")
	after := candidatesFor(t, ", drain: true")
	if len(after) >= len(before) {
		t.Fatalf("排空之后候选没变少:%d → %d", len(before), len(after))
	}
	for _, c := range after {
		if strings.Contains(c, "b") {
			t.Errorf("被排空的 b 还在候选里:%s", c)
		}
	}
	// a 必须还在 —— 排空一台不该把别的也带走。
	found := false
	for _, c := range after {
		if strings.HasSuffix(c, ":a") {
			found = true
		}
	}
	if !found {
		t.Errorf("排空 b 之后 a 也不见了:%v", after)
	}
}

// 下线比排空更彻底:它连配置都不再渲染。
func TestDecommissionRemovesFromCandidates(t *testing.T) {
	after := candidatesFor(t, ", decommission: true")
	for _, c := range after {
		if strings.HasSuffix(c, ":b") || strings.Contains(c, ">b") {
			t.Errorf("已下线的 b 还在候选里:%s", c)
		}
	}
}

// 两个字段都是运维意图,不是推导值 —— 但也都必须能在 YAML 里写。
// (§D4 说推导值不进结构体;这两个不是推导值。)
func TestDrainAndDecommissionAreDeclarable(t *testing.T) {
	s, err := Load([]byte(strings.Replace(lifecycleSSOT, "%s", ", drain: true, decommission: true", 1)))
	if err != nil {
		t.Fatal(err)
	}
	n := s.NodeByID()["b"]
	if !n.Drain || !n.Decommission {
		t.Errorf("drain=%v decommission=%v,两个都该是 true", n.Drain, n.Decommission)
	}
}
