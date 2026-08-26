package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestConfiguredChainTreatsTagAsOpaque(t *testing.T) {
	d := &Decl{Candidates: []Cand{
		{Tag: "cand:svc@v1:gz02@https://api.example/", Chain: []string{"gz02"}},
		{Tag: "cand:svc@v1:direct@https://api.example/"},
	}}
	if got, ok := configuredChain(d, d.Candidates[0].Tag); !ok || !reflect.DeepEqual(got, []string{"gz02"}) {
		t.Fatalf("显式链没有按 opaque tag 找到:%v,%v", got, ok)
	}
	if got, ok := configuredChain(d, d.Candidates[1].Tag); !ok || len(got) != 0 {
		t.Fatalf("direct 应是显式空链:%v,%v", got, ok)
	}
}

func TestStateStoreWritesCompleteSortedSnapshot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	s, err := newStateStore(p, "jm24", []Decl{
		{ID: "z", Candidates: []Cand{{Tag: "opaque-z"}}},
		{ID: "a", Candidates: []Cand{{Tag: "opaque-a"}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.observe(Selection{Declaration: "z", Selector: "svc:z", Candidate: "opaque-z", Chain: []string{"gz02", "sg02"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.observe(Selection{Declaration: "a", Selector: "svc:a", Candidate: "opaque-a"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	st, err := ReadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Node != "jm24" || st.TS != "2026-08-26T12:00:01Z" || len(st.Selections) != 2 {
		t.Fatalf("状态不完整:%+v", st)
	}
	if st.Selections[0].Declaration != "a" || !reflect.DeepEqual(st.Selections[1].Chain, []string{"gz02", "sg02"}) {
		t.Fatalf("声明未稳定排序或路径没解析:%+v", st.Selections)
	}
	if st.Selections[0].UpdatedAt != "2026-08-26T12:00:01Z" || st.Selections[1].UpdatedAt != "2026-08-26T12:00:00Z" {
		t.Fatalf("每条选择没有自己的观测时间:%+v", st.Selections)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件未被 rename")
	}
}

func TestStateStorePrunesRemovedDeclarationsAtStartup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	old := State{Node: "jm24", TS: "2026-08-26T11:00:00Z", Selections: []Selection{
		{Declaration: "keep", Selector: "svc:keep", Candidate: "a", UpdatedAt: "2026-08-26T11:00:00Z"},
		{Declaration: "removed", Selector: "svc:removed", Candidate: "b", UpdatedAt: "2026-08-26T11:00:00Z"},
	}}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if _, err := newStateStore(p, "jm24", []Decl{{ID: "keep", Candidates: []Cand{{Tag: "a"}}}}, now); err != nil {
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

func TestReadStateAbsentIsNormal(t *testing.T) {
	st, err := ReadState(filepath.Join(t.TempDir(), "absent"))
	if err != nil || st != nil {
		t.Fatalf("不存在应返回 nil,nil，得到 %+v,%v", st, err)
	}
}
