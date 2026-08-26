package report

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"
)

// 与 internal/agent.StatePath 的线格式约定。report 不能 import agent：agent
// 本身要 import report 读取观测，反向依赖会形成环。
func readAgentState(path string) (*AgentState, error) {
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
	var st AgentState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	sort.Slice(st.Selections, func(i, j int) bool {
		a, b := st.Selections[i], st.Selections[j]
		if a.Declaration != b.Declaration {
			return a.Declaration < b.Declaration
		}
		if a.Selector != b.Selector {
			return a.Selector < b.Selector
		}
		return a.Candidate < b.Candidate
	})
	return &st, nil
}

const AgentStateStaleAfter = 30 * time.Minute

func validateAgentState(st *AgentState, node string, now time.Time) []string {
	if st == nil {
		return nil
	}
	var out []string
	if st.Node == "" || st.Node != node {
		out = append(out, "Agent 状态节点与 report 节点不一致")
	}
	checkTime := func(label, raw string) {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			out = append(out, label+"时间无效:"+raw)
			return
		}
		age := now.UTC().Sub(t.UTC())
		if age > AgentStateStaleAfter {
			out = append(out, label+"已过期:"+raw)
		} else if age < -2*time.Minute {
			out = append(out, label+"来自未来:"+raw)
		}
	}
	checkTime("Agent 状态", st.TS)
	for _, s := range st.Selections {
		if s.Declaration == "" || s.Selector == "" || s.Candidate == "" {
			out = append(out, "Agent 选择缺 declaration/selector/candidate")
		}
		checkTime("Agent 选择 "+s.Declaration, s.UpdatedAt)
	}
	return out
}
