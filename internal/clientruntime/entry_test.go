package clientruntime

import (
	"encoding/json"
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
