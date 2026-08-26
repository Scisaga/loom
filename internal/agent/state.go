package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// StatePath 是 Agent 对外留下“selector 现在实际选了谁”的地方。
// 度量和事件都回答不了这个问题：前者是候选样本，后者只记发生过的切换。
const StatePath = "/var/lib/loom/agent-state.json"

// State 是一次完整的 Agent 选择快照。整份原子覆盖，读取方不会看到五条声明
// 只写到一半的状态。
type State struct {
	Node       string      `json:"node"`
	TS         string      `json:"ts"`
	Selections []Selection `json:"selections"`
}

// Selection 来自 sing-box selector 的 GET 结果，不是 Agent 根据事件推断的值。
type Selection struct {
	Declaration string   `json:"declaration"`
	Selector    string   `json:"selector"`
	Candidate   string   `json:"candidate"`
	Chain       []string `json:"chain,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	UpdatedAt   string   `json:"updated_at"`
}

// ReadState 读取 Agent 状态；不存在表示这台机器没有 Agent（服务器节点的
// 正常形态），不是错误。
func ReadState(path string) (*State, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

type stateStore struct {
	mu   sync.Mutex
	path string
	node string
	byID map[string]Selection
}

func newStateStore(path, node string, declarations []Decl, now time.Time) (*stateStore, error) {
	s := &stateStore{path: path, node: node, byID: map[string]Selection{}}
	active := make(map[string]map[string]bool, len(declarations))
	for _, d := range declarations {
		active[d.ID] = map[string]bool{}
		for _, c := range d.Candidates {
			active[d.ID][c.Tag] = true
		}
	}
	if old, err := ReadState(path); err == nil && old != nil && old.Node == node {
		for _, v := range old.Selections {
			if active[v.Declaration][v.Candidate] {
				s.byID[v.Declaration] = v
			}
		}
	} else if err != nil {
		return nil, err
	}
	// 启动就写一份过滤后的快照。否则已经从配置删除的 declaration 会在
	// 第一个新观测到来前继续冒充当前 route。
	if err := s.writeLocked(now); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *stateStore) observe(v Selection, now time.Time) error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Chain = append([]string(nil), v.Chain...)
	v.UpdatedAt = now.UTC().Format(time.RFC3339)
	s.byID[v.Declaration] = v
	return s.writeLocked(now)
}

func (s *stateStore) writeLocked(now time.Time) error {
	if s == nil || s.path == "" {
		return nil
	}
	st := State{Node: s.node, TS: now.UTC().Format(time.RFC3339)}
	for _, x := range s.byID {
		st.Selections = append(st.Selections, x)
	}
	sort.Slice(st.Selections, func(i, j int) bool {
		return st.Selections[i].Declaration < st.Selections[j].Declaration
	})
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
