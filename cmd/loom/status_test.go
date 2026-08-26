package main

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/render"
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

// 转述来的节点必须出现在快照分布里,但只能显示验过签的值。
func TestSnapshotSpreadIncludesVerifiedRelayed(t *testing.T) {
	expected := []string{"access-a", "cn-a", "cn-b", "edge-a"}
	verified := map[string]string{
		"cn-a": "aaa", "cn-b": "bbb", // 已由 foldAttested 验签
		"edge-a": "aaa", "access-a": "aaa", // 直接问到
	}

	got := snapshotSpread(expected, verified)
	want := map[string][]string{"aaa": {"access-a", "cn-a", "edge-a"}, "bbb": {"cn-b"}}
	for k := range want {
		slices.Sort(got[k])
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("快照分布不对\n得到: %v\n期望: %v", got, want)
	}
}

// 未签名的 Applied 可以伪造,只能证明"听说过这台节点"。
func TestSnapshotSpreadRejectsUnsignedApplied(t *testing.T) {
	got := snapshotSpread([]string{"cn-a"}, nil)
	if !slices.Equal(got[snapshotUnverified], []string{"cn-a"}) || len(got) != 1 {
		t.Fatalf("未签名 Applied 不得进入快照分布,得到 %v", got)
	}
	if snapshotKeyVerified(snapshotUnverified) {
		t.Fatal("全部未核验时不得宣称全网快照一致")
	}
}

// 直接拉取超时或转述链也完全静默时，SSOT 节点仍在“全网”分母里。
// 否则其余机器恰好同版时，会产生一条自相矛盾的“全网一致”结论。
func TestSnapshotSpreadIncludesSilentExpectedNodes(t *testing.T) {
	got := snapshotSpread([]string{"jm24", "gz02", "hz01"}, map[string]string{"jm24": "aaa"})
	slices.Sort(got[snapshotUnverified])
	if !slices.Equal(got["aaa"], []string{"jm24"}) ||
		!slices.Equal(got[snapshotUnverified], []string{"gz02", "hz01"}) || len(got) != 2 {
		t.Fatalf("静默/超时节点不得从快照分母消失,得到 %v", got)
	}
}

func TestSnapshotSpreadAllUnknownOrUnrecordedIsNotConsistent(t *testing.T) {
	allSilent := snapshotSpread([]string{"jm24", "gz02"}, nil)
	if len(allSilent) != 1 || snapshotKeyVerified(snapshotUnverified) {
		t.Fatalf("全静默不得宣称快照一致:%v", allSilent)
	}
	allEmpty := snapshotSpread([]string{"jm24", "gz02"}, map[string]string{"jm24": "", "gz02": ""})
	if len(allEmpty) != 1 || snapshotKeyVerified(snapshotUnrecorded) {
		t.Fatalf("全未记录 Applied 不得宣称快照一致:%v", allEmpty)
	}
}
