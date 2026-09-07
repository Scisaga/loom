package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"loom/internal/version"
)

func TestConfiguredChainTreatsTagAsOpaque(t *testing.T) {
	d := &Decl{Candidates: []Cand{
		{Tag: "cand:svc@v1:demo-b@https://api.example/", Chain: []string{"demo-b"}},
		{Tag: "cand:svc@v1:direct@https://api.example/"},
	}}
	if got, ok := configuredChain(d, d.Candidates[0].Tag); !ok || !reflect.DeepEqual(got, []string{"demo-b"}) {
		t.Fatalf("显式链没有按 opaque tag 找到:%v,%v", got, ok)
	}
	if got, ok := configuredChain(d, d.Candidates[1].Tag); !ok || len(got) != 0 {
		t.Fatalf("direct 应是显式空链:%v,%v", got, ok)
	}
}

func TestStateStoreWritesCompleteSortedSnapshot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	s, err := newStateStore(p, "demo-d", []Decl{
		{ID: "z", Candidates: []Cand{{Tag: "opaque-z"}}},
		{ID: "a", Candidates: []Cand{{Tag: "opaque-a"}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.observe(context.Background(), Selection{Declaration: "z", Selector: "svc:z", Candidate: "opaque-z", Chain: []string{"demo-b", "demo-e"}}, now); err != nil {
		t.Fatal(err)
	}
	p50, p95 := 17, 31
	if err := s.observe(context.Background(), Selection{
		Declaration: "a", Selector: "svc:a", Candidate: "opaque-a",
		Health: &CandidateHealth{
			Candidates: 1, RecentSuccess: 1, SelectedState: healthSuccess,
			SelectedSamples: 4, SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &p50,
		},
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	st, err := ReadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Node != "demo-d" || st.TS != "2026-08-26T12:00:01Z" || len(st.Selections) != 2 {
		t.Fatalf("状态不完整:%+v", st)
	}
	if st.ComponentVersion != version.AgentProtocolVersion {
		t.Fatalf("Agent 没有自证 component_version:%q", st.ComponentVersion)
	}
	if st.Selections[0].Declaration != "a" || !reflect.DeepEqual(st.Selections[1].Chain, []string{"demo-b", "demo-e"}) {
		t.Fatalf("声明未稳定排序或路径没解析:%+v", st.Selections)
	}
	if st.Selections[0].DecisionScope != decisionScope("demo-d", &Decl{ID: "a", Candidates: []Cand{{Tag: "opaque-a"}}}) ||
		st.Selections[1].DecisionScope != decisionScope("demo-d", &Decl{ID: "z", Candidates: []Cand{{Tag: "opaque-z"}}}) {
		t.Fatalf("状态没有绑定当前 decision_scope:%+v", st.Selections)
	}
	if st.Selections[0].UpdatedAt != "2026-08-26T12:00:01Z" || st.Selections[1].UpdatedAt != "2026-08-26T12:00:00Z" {
		t.Fatalf("每条选择没有自己的观测时间:%+v", st.Selections)
	}
	if h := st.Selections[0].Health; h == nil || h.Candidates != 1 ||
		intValue(h.SelectedP50MS) != 17 || intValue(h.SelectedP95MS) != 31 {
		t.Fatalf("候选健康没有写入 agent-state:%+v", h)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件未被 rename")
	}
}

func TestStateStorePrunesRemovedDeclarationsAtStartup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	keep := Decl{ID: "keep", Candidates: []Cand{{Tag: "a"}}}
	old := State{Node: "demo-d", TS: "2026-08-26T11:00:00Z", Selections: []Selection{
		{Declaration: "keep", Selector: "svc:keep", Candidate: "a", DecisionScope: decisionScope("demo-d", &keep), UpdatedAt: "2026-08-26T11:00:00Z"},
		{Declaration: "removed", Selector: "svc:removed", Candidate: "b", UpdatedAt: "2026-08-26T11:00:00Z"},
	}}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if _, err := newStateStore(p, "demo-d", []Decl{keep}, now); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Selections) != 1 || got.Selections[0].Declaration != "keep" || got.TS != now.Format(time.RFC3339) {
		t.Fatalf("启动没有原子清理已删除声明:%+v", got)
	}
}

func TestStateStoreDropsLegacyAndChangedDecisionScopesAtStartup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	current := Decl{ID: "d", Targets: []string{"https://new.example/"}, Candidates: []Cand{{Tag: "a"}}}
	old := State{Node: "demo-d", TS: now.Add(-time.Minute).Format(time.RFC3339), Selections: []Selection{
		{Declaration: "d", Selector: "svc:d", Candidate: "a", UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339)},
		{Declaration: "d", Selector: "svc:d", Candidate: "a", DecisionScope: decisionScope("demo-d", &Decl{
			ID: "d", Targets: []string{"https://old.example/"}, Candidates: []Cand{{Tag: "a"}},
		}), UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newStateStore(p, "demo-d", []Decl{current}, now); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Selections) != 0 {
		t.Fatalf("legacy/异 scope 状态在配置变化后仍冒充当前选择:%+v", got.Selections)
	}
}

func TestStateStoreDoesNotWriteAfterCancellation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	d := Decl{ID: "d", Candidates: []Cand{{Tag: "a"}}}
	s, err := newStateStore(p, "demo-d", []Decl{d}, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.observe(ctx, Selection{Declaration: "d", Selector: "svc:d", Candidate: "a"}, now.Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled state write error=%v", err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("cancelled state write changed snapshot:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestReadStateAbsentIsNormal(t *testing.T) {
	st, err := ReadState(filepath.Join(t.TempDir(), "absent"))
	if err != nil || st != nil {
		t.Fatalf("不存在应返回 nil,nil，得到 %+v,%v", st, err)
	}
}
