package main

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/report"
)

// inboundUsers 从渲染出来的 sing-box 配置里读出这台机器实际配了哪些 user。
// 这是 ground truth ——"硬盘上留过哪些凭据明文"就是这个列表。
func inboundUsers(t *testing.T, s *model.SSOT, id string) []string {
	t.Helper()
	res, err := render.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]bool{}
	for i := range s.Credentials {
		creds[s.Credentials[i].ID] = true
	}
	var out []string
	for _, b := range res.Bundles {
		if b.Owner != id {
			continue
		}
		for _, f := range b.Files {
			if !strings.HasSuffix(f.Path, ".json") {
				continue
			}
			var cfg struct {
				Inbounds []struct {
					Users []struct {
						Name string `json:"name"`
					} `json:"users"`
				} `json:"inbounds"`
			}
			if json.Unmarshal([]byte(f.Content), &cfg) != nil {
				continue
			}
			for _, in := range cfg.Inbounds {
				for _, u := range in.Users {
					// 轮换过渡期会多出上一代 user,归到本代凭据名下。
					if creds[u.Name] && !slices.Contains(out, u.Name) {
						out = append(out, u.Name)
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// credentialsHeldBy 必须等于渲染器实际配上去的 user —— 少一张,那张就
// 永远不会在节点移除后被轮换,而且不会有任何症状。
func TestCredentialsHeldByMatchesRenderedUsers(t *testing.T) {
	s, err := model.LoadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.IsServer() {
			continue
		}
		t.Run(n.ID, func(t *testing.T) {
			want := inboundUsers(t, s, n.ID)
			got := credentialsHeldBy(s, n)
			if !slices.Equal(got, want) {
				t.Errorf("凭据清单与渲染结果不一致\n渲染配了: %v\n清单算出: %v", want, got)
			}
		})
	}
}

// 排空/下线之后清单不能变 —— 恰恰是这两个状态才需要问"该轮换什么",
// 而这两个状态下节点已经不进候选了。
func TestCredentialsHeldByIgnoresLifecycle(t *testing.T) {
	s, err := model.LoadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.IsServer() {
			continue
		}
		before := credentialsHeldBy(s, n)
		if len(before) == 0 {
			continue
		}
		t.Run(n.ID, func(t *testing.T) {
			n.Drain, n.Decommission = true, true
			defer func() { n.Drain, n.Decommission = false, false }()
			if got := credentialsHeldBy(s, n); !slices.Equal(got, before) {
				t.Errorf("排空后清单变了:%v -> %v", before, got)
			}
		})
	}
}

// 转述来的节点必须出现在快照分布里 —— 漏掉它们的方式是静默的:
// 落后的那台如果恰好直接够不到,表上就看不见,只会以为全网一致。
func TestSnapshotSpreadIncludesRelayed(t *testing.T) {
	obs := map[string]report.Observation{
		"cn-a":   {Node: "cn-a", Applied: "aaa"},
		"cn-b":   {Node: "cn-b", Applied: "bbb"}, // 落后的那台,只够得到转述
		"edge-a": {Node: "edge-a", Applied: "aaa"},
	}
	direct := map[string]string{"edge-a": "aaa", "access-a": "aaa"}

	got := snapshotSpread(obs, direct)
	want := map[string][]string{"aaa": {"access-a", "cn-a", "edge-a"}, "bbb": {"cn-b"}}
	for k := range want {
		slices.Sort(got[k])
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("快照分布不对\n得到: %v\n期望: %v", got, want)
	}
}

// 直接问到的比转听来的权威 —— 转述可能是几分钟前的。
func TestSnapshotSpreadDirectWins(t *testing.T) {
	obs := map[string]report.Observation{"cn-a": {Node: "cn-a", Applied: "旧"}}
	got := snapshotSpread(obs, map[string]string{"cn-a": "新"})
	if !slices.Equal(got["新"], []string{"cn-a"}) || len(got) != 1 {
		t.Fatalf("直接问到的应当覆盖转述,得到 %v", got)
	}
}
