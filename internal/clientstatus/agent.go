// Package clientstatus 定义客户端本机选路状态，与传输和签名协议无关。
package clientstatus

// AgentState 投影当前 Agent 与 selector 回读，不包含上报端点或身份。
type AgentState struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// ComponentVersion 保留既有 JSON 名称，承载的是 Agent 线协议版本；
	// 它不能替代运行中 Agent 进程的 commit/binary 构建坐标。
	ComponentVersion string           `json:"component_version,omitempty"`
	Selections       []AgentSelection `json:"selections"`
}

type AgentSelection struct {
	Declaration string                `json:"declaration"`
	Selector    string                `json:"selector"`
	Candidate   string                `json:"candidate"`
	Chain       []string              `json:"chain,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	UpdatedAt   string                `json:"updated_at"`
	Health      *AgentCandidateHealth `json:"health,omitempty"`
}

// AgentCandidateHealth 与 internal/agent.CandidateHealth 共用线格式。
// report 不能 import agent（agent 已经依赖 report），因此在边界处显式镜像。
// 缺少观测的指标保持可选，不用零值假冒实测。
type AgentCandidateHealth struct {
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
