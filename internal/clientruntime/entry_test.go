package clientruntime

import (
	"encoding/json"
	"net"
	"testing"

	"loom/internal/agent"
)

// §5.1：两个 Service、多个末跳共用一个入口，只产生一个入口地址。
func TestWindowsEntriesFollowActualDetourAndDeduplicate(t *testing.T) {
	cfg := &agent.Config{Declarations: []agent.Decl{
		{Candidates: []agent.Cand{{Tag: "opaque-last-a", Chain: []string{"demo-entry", "demo-exit-a"}}, {Tag: "opaque-last-b", Chain: []string{"demo-entry", "demo-exit-b"}}, {Tag: "direct"}}},
		{Candidates: []agent.Cand{{Tag: "opaque-last-a", Chain: []string{"demo-entry", "demo-exit-a"}}}},
	}}
	sb := singBoxConfig{Outbounds: []singBoxOutbound{
		{Type: "hysteria2", Tag: "opaque-last-a", Server: "192.0.2.2", Detour: "opaque-first"},
		{Type: "hysteria2", Tag: "opaque-last-b", Server: "192.0.2.3", Detour: "opaque-first"},
		{Type: "hysteria2", Tag: "opaque-first", Server: "192.0.2.1"},
		{Type: "direct", Tag: "direct"},
	}}
	body, _ := json.Marshal(sb)
	entries, err := WindowsEntries(body, cfg)
	if err != nil || len(entries) != 1 || entries[0].Node != "demo-entry" || entries[0].Address != "192.0.2.1" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	sb.Outbounds[2].Detour = "opaque-last-a"
	body, _ = json.Marshal(sb)
	if _, err := WindowsEntries(body, cfg); err == nil {
		t.Fatal("recursive detour accepted")
	}
	sb.Outbounds[2].Detour = "missing"
	body, _ = json.Marshal(sb)
	if _, err := WindowsEntries(body, cfg); err == nil {
		t.Fatal("missing entry accepted")
	}
}

func TestWindowsRoutingUsesTheConfiguredHopCarrier(t *testing.T) {
	cfg := &agent.Config{Declarations: []agent.Decl{{Candidates: []agent.Cand{
		{Tag: "demo-chain", Chain: []string{"demo-entry", "demo-exit"}},
		{Tag: "demo-public-exit", Chain: []string{"demo-exit"}},
	}}}}
	sb := singBoxConfig{Outbounds: []singBoxOutbound{
		{Type: "hysteria2", Tag: "demo-chain", Server: "198.51.100.2", Detour: "demo-first"},
		{Type: "hysteria2", Tag: "demo-first", Server: "192.0.2.1"},
		{Type: "hysteria2", Tag: "demo-public-exit", Server: "192.0.2.2"},
	}}
	for _, tc := range []struct{ address, carrier string }{{"198.51.100.2", "neighbor"}, {"192.0.2.2", "public-hysteria2"}} {
		sb.Outbounds[0].Server = tc.address
		body, _ := json.Marshal(sb)
		inputs, err := WindowsRoutingInputs(body, cfg)
		if err != nil || len(inputs.HopCarriers["demo-chain"]) != 1 || inputs.HopCarriers["demo-chain"][0] != tc.carrier {
			t.Fatalf("inputs=%+v err=%v", inputs, err)
		}
	}
	// 合成私有地址覆盖只能经隧道进入、没有公开第一跳候选的出口（§5.6）。
	cfg.Declarations[0].Candidates = cfg.Declarations[0].Candidates[:1]
	sb.Outbounds[0].Server = net.IPv4(10, 0, 0, 2).String()
	body, _ := json.Marshal(sb)
	inputs, err := WindowsRoutingInputs(body, cfg)
	if err != nil || inputs.HopCarriers["demo-chain"][0] != "neighbor" {
		t.Fatalf("reverse-only egress lost neighbor evidence: %+v %v", inputs, err)
	}
}
