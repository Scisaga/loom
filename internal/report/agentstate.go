package report

import (
	"encoding/json"
	"errors"
	"loom/internal/observation"
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
	body, _ := json.Marshal(st)
	var wire observation.AgentState
	if err := json.Unmarshal(body, &wire); err != nil {
		return []string{"Agent 状态无法转换"}
	}
	return observation.ValidateAgentState(&wire, node, now)
}

// validateAgentStateForConfig 在通用线格式检查之外，核对“这份配置要求 Agent
// 管哪些 declaration”。只遍历实际状态会产生一个危险真空：某个 tick 永久
// 失败后，该 declaration 会从状态和界面一起消失，却没人报错。
func validateAgentStateForConfig(st *AgentState, cfg *Config, now time.Time) []string {
	if cfg == nil {
		return validateAgentState(st, "", now)
	}
	out := validateAgentState(st, cfg.Node, now)
	expected := map[string]bool{}
	for _, route := range cfg.ExpectedRoutes {
		if route.Access == cfg.Node && route.Declaration != "" {
			expected[route.Declaration] = true
		}
	}
	// 没有本机 Agent workload 的服务器节点不需要 selections；ExpectedRoutes
	// 同时携带全网其他接入节点的候选，必须按 Access 过滤。
	if len(expected) == 0 && cfg.AgentState == "" && cfg.ExpectedComponents.Agent == "" {
		return out
	}
	if st == nil {
		// §16.4 声明了 Agent 协议组件时，缺失状态由 componentStatuses 唯一
		// 负责；这里再报“缺少全部 declaration”会把同一根因伪装成两项漂移。
		// 没有声明协议组件的配置仍由本校验器 fail closed。
		if cfg.ExpectedComponents.Agent != "" {
			return out
		}
		if len(expected) > 0 || cfg.AgentState != "" {
			out = append(out, "Agent 状态不存在，缺少全部期望 declaration")
		}
		return out
	}
	actual := map[string]bool{}
	for _, selection := range st.Selections {
		id := selection.Declaration
		if actual[id] {
			out = append(out, "Agent 状态重复 declaration:"+id)
		}
		actual[id] = true
		if len(expected) > 0 && !expected[id] {
			out = append(out, "Agent 状态含非期望 declaration:"+id)
		}
		// component_version 非空表示写状态的 Agent 已声明支持新版协议；这时
		// Health=nil 不再是“旧版兼容”，而是探测半途失败留下的假绿窗口。
		if st.ComponentVersion != "" && selection.Health == nil {
			out = append(out, "Agent declaration "+id+" 未上报候选健康")
		}
	}
	for id := range expected {
		if !actual[id] {
			out = append(out, "Agent 状态缺少期望 declaration:"+id)
		}
	}
	sort.Strings(out)
	return out
}

func validateAgentCandidateHealth(h *AgentCandidateHealth) []string {
	return observation.ValidateAgentCandidateHealth(candidateHealthClaim(h))
}
