package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/version"
)

// StatePath 是 Agent 对外留下“selector 现在实际选了谁”的地方。
// 度量和事件都回答不了这个问题：前者是候选样本，后者只记发生过的切换。
const StatePath = "/var/lib/loom/agent-state.json"

// State 是一次完整的 Agent 选择快照。整份原子覆盖，读取方不会看到五条声明
// 只写到一半的状态。
type State struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// ComponentVersion 是历史线格式名，值实际表示 agent-state 协议版本；
	// 运行中二进制的构建身份必须另看 node-owned version.Coordinate。
	ComponentVersion string      `json:"component_version,omitempty"`
	Selections       []Selection `json:"selections"`
}

// Selection 来自 sing-box selector 的 GET 结果，不是 Agent 根据事件推断的值。
type Selection struct {
	Declaration string   `json:"declaration"`
	Selector    string   `json:"selector"`
	Candidate   string   `json:"candidate"`
	Chain       []string `json:"chain,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	UpdatedAt   string   `json:"updated_at"`

	// Health 是与本次 selector 实读同一轮得到的候选集摘要。它是可选字段，
	// 让旧版 agent-state.json 在滚动升级期间仍可读取；缺失只表示旧格式或
	// 尚未完成第一轮探测，绝不能被解释成健康。
	Health *CandidateHealth `json:"health,omitempty"`
}

// CandidateHealth 按 declaration 汇总当前窗口内的候选健康。
//
// 五个分类互斥且之和必须等于 Candidates：
//
//   - recent_success：窗口内有成功样本且没有失败；
//   - recent_degraded：窗口内既有成功也有失败；
//   - recent_failed：窗口内只有失败；
//   - stale：以前量过，但当前窗口/新鲜度规则已不再接受；
//   - unknown：在本机保留的度量里从未见过。
//
// 延迟使用指针区分“真实的 0ms”与“没有可用样本”。
type CandidateHealth struct {
	Candidates       int    `json:"candidates"`
	RecentSuccess    int    `json:"recent_success"`
	RecentDegraded   int    `json:"recent_degraded,omitempty"`
	RecentFailed     int    `json:"recent_failed"`
	Stale            int    `json:"stale"`
	Unknown          int    `json:"unknown"`
	SelectedState    string `json:"selected_state"`
	SelectedSamples  int    `json:"selected_samples,omitempty"`
	SelectedFailures int    `json:"selected_failures,omitempty"`
	SelectedP50MS    *int   `json:"selected_p50_ms,omitempty"`
	SelectedP95MS    *int   `json:"selected_p95_ms,omitempty"`
	BestP50MS        *int   `json:"best_p50_ms,omitempty"`
	SelectedKBps     *int   `json:"selected_kbps,omitempty"`
	BestKBps         *int   `json:"best_kbps,omitempty"`
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
	v.Health = cloneCandidateHealth(v.Health)
	v.UpdatedAt = now.UTC().Format(time.RFC3339)
	s.byID[v.Declaration] = v
	return s.writeLocked(now)
}

func cloneCandidateHealth(h *CandidateHealth) *CandidateHealth {
	if h == nil {
		return nil
	}
	cp := *h
	cloneInt := func(v *int) *int {
		if v == nil {
			return nil
		}
		x := *v
		return &x
	}
	cp.SelectedP50MS = cloneInt(h.SelectedP50MS)
	cp.SelectedP95MS = cloneInt(h.SelectedP95MS)
	cp.BestP50MS = cloneInt(h.BestP50MS)
	cp.SelectedKBps = cloneInt(h.SelectedKBps)
	cp.BestKBps = cloneInt(h.BestKBps)
	return &cp
}

func (s *stateStore) writeLocked(now time.Time) error {
	if s == nil || s.path == "" {
		return nil
	}
	// 必须由 Agent 进程自己写。report 与 Agent 虽共用同一二进制，但让 report
	// 用自己的常量代填，会把“report 是新版”冒充成“Agent 正在跑新版”。
	st := State{
		Node: s.node, TS: now.UTC().Format(time.RFC3339),
		ComponentVersion: version.AgentProtocolVersion,
	}
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
