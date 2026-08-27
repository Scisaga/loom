package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"

	"loom/internal/attest"
	"loom/internal/version"
)

// AttestationMaxAge 与默认 observation_stale 相同。签名证明来源，新鲜度
// 证明这不是一条无限重放的旧事实。
const AttestationMaxAge = 10 * time.Minute

// AttestedState 是从已验签 Claim 重建出来的可信状态。调用方不得继续使用
// 外层 Observation 里可被 relay 改写的 Version/Rollout/Agent 值。
type AttestedState struct {
	Version    *version.Coordinate
	Rollout    *RolloutState
	Agent      *AgentState
	Components []ComponentStatus
	// Applied is node-owned state covered by every attestation version.  It is
	// kept here so callers never have to fall back to the mutable outer field
	// after verification.
	Applied string
	// MeasurementsVerified means Edges/Targets are covered by the node-owned
	// v3/v4 claim. Legacy v1/v2 claims still authenticate identity state, but their
	// measurements must remain unknown in topology views.
	MeasurementsVerified bool
}

// measurementDigest hashes exactly the relayed measurement payload. A struct
// fixes JSON field order; observation construction sorts both slices, so the
// same node-owned payload has stable bytes without coupling attest to report.
func measurementDigest(o *Observation) string {
	if o == nil {
		return ""
	}
	edges := o.Edges
	targets := o.Targets
	// Observation uses omitempty, so a non-nil empty slice becomes absent on
	// the wire and unmarshals as nil. Normalize the two equivalent forms before
	// hashing or a legitimate empty observation could fail after JSON transit.
	if len(edges) == 0 {
		edges = nil
	}
	if len(targets) == 0 {
		targets = nil
	}
	payload := struct {
		Edges   []Edge  `json:"edges"`
		Targets []Reach `json:"targets"`
	}{Edges: edges, Targets: targets}
	b, err := json.Marshal(payload)
	if err != nil {
		return "" // current concrete fields cannot fail; fail closed if that changes
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyObservation 先验签和检查新鲜度，再把签名 Claim 与外层观测绑定。
// 外层 Node 决定索引、TS 决定去重、Applied 参与版本汇总；三者任意一个不绑，
// relay 都能把一条合法陈述包装成另一台机器或永不过期的新观测。
func VerifyObservation(o *Observation, ca []byte, now time.Time, maxAge time.Duration) (*AttestedState, error) {
	if o == nil || o.Attest == nil {
		return nil, fmt.Errorf("没有签名陈述")
	}
	legacy, err := attest.VerifyFresh(o.Attest, ca, now, maxAge)
	if err != nil {
		return nil, fmt.Errorf("兼容签名:%w", err)
	}
	// 用旧 reader 反序列化后能看见的投影再绑定一次。这样双签不是“多放了
	// 一个没人检查的字段”，而是每个新节点都会持续验证旧节点能消费的 v3。
	if err := bindClaim(legacyObservation(o), legacy); err != nil {
		return nil, fmt.Errorf("兼容签名绑定:%w", err)
	}
	c := legacy
	if o.AttestExtended != nil {
		if o.AttestExtended.CanonicalVersion != 4 && o.AttestExtended.CanonicalVersion != 5 {
			return nil, fmt.Errorf("扩展签名必须使用 canonical_version=4/5")
		}
		c, err = attest.VerifyFresh(o.AttestExtended, ca, now, maxAge)
		if err != nil {
			return nil, fmt.Errorf("扩展签名:%w", err)
		}
	}
	if err := bindClaim(o, c); err != nil {
		return nil, err
	}
	st := stateFromClaim(c)
	if problems := validateAgentState(st.Agent, o.Node, now); len(problems) > 0 {
		return nil, fmt.Errorf("签名 Agent 状态非法:%s", problems[0])
	}
	if problems := validateComponentStatuses(st.Components); len(problems) > 0 {
		return nil, fmt.Errorf("签名组件状态非法:%s", problems[0])
	}
	return st, nil
}

// legacyObservation 模拟旧 Go 结构对新 JSON 的解码结果：未知的 components、
// component_version、health 与 attest_extended 会被忽略，其余字段保持原样。
func legacyObservation(o *Observation) *Observation {
	if o == nil {
		return nil
	}
	legacy := *o
	legacy.Components = nil
	legacy.AttestExtended = nil
	if o.Agent != nil {
		a := *o.Agent
		a.ComponentVersion = ""
		a.Selections = append([]AgentSelection(nil), o.Agent.Selections...)
		for i := range a.Selections {
			a.Selections[i].Health = nil
		}
		legacy.Agent = &a
	}
	return &legacy
}

func bindClaim(o *Observation, c *attest.Claim) error {
	switch {
	case c.Node != o.Node:
		return fmt.Errorf("签名节点 %q 与外层观测节点 %q 不一致", c.Node, o.Node)
	case c.TS != o.TS:
		return fmt.Errorf("签名时间 %q 与外层观测时间 %q 不一致", c.TS, o.TS)
	case c.Applied != o.Applied:
		return fmt.Errorf("签名快照 %q 与外层观测快照 %q 不一致", c.Applied, o.Applied)
	}

	// v1 观测没有这些外层字段，可信值仍从 Claim 取；新格式一旦携带，就必须
	// 与签名完全相同，不能让 relay 改 UI 上显示的版本、rollout 或路径。
	trusted := stateFromClaim(c)
	if trusted.Agent != nil && trusted.Agent.Node != o.Node {
		return fmt.Errorf("Agent 状态节点 %q 与观测节点 %q 不一致", trusted.Agent.Node, o.Node)
	}
	if o.Version != nil && !reflect.DeepEqual(o.Version, trusted.Version) {
		return fmt.Errorf("外层版本坐标与签名陈述不一致")
	}
	if o.Rollout != nil && !reflect.DeepEqual(o.Rollout, trusted.Rollout) {
		return fmt.Errorf("外层 rollout 与签名陈述不一致")
	}
	if o.Agent != nil && !reflect.DeepEqual(o.Agent, trusted.Agent) {
		return fmt.Errorf("外层 Agent 选择与签名陈述不一致")
	}
	if !componentStatusesEqual(o.Components, trusted.Components) {
		return fmt.Errorf("外层组件版本与签名陈述不一致")
	}
	if c.MeasurementsSHA256 != "" && c.MeasurementsSHA256 != measurementDigest(o) {
		return fmt.Errorf("外层链路观测与签名陈述不一致")
	}
	return nil
}

func stateFromClaim(c *attest.Claim) *AttestedState {
	st := &AttestedState{Version: &version.Coordinate{
		Commit: c.Commit, Dirty: c.Dirty, Tag: c.Tag, Binary: c.Binary,
		BinaryErr: c.BinaryErr, Go: c.Go, Platform: c.Platform,
	}, Applied: c.Applied, MeasurementsVerified: c.MeasurementsSHA256 != ""}
	if c.Rollout != nil {
		st.Rollout = &RolloutState{
			Snapshot: c.Rollout.Snapshot, Stage: c.Rollout.Stage,
			EnteredAt: c.Rollout.EnteredAt, LastGood: c.Rollout.LastGood,
			Error: c.Rollout.Error,
		}
	}
	if c.Agent != nil {
		st.Agent = &AgentState{
			Node: c.Agent.Node, TS: c.Agent.TS,
			ComponentVersion: c.Agent.ComponentVersion,
		}
		for _, s := range c.Agent.Selections {
			st.Agent.Selections = append(st.Agent.Selections, AgentSelection{
				Declaration: s.Declaration, Selector: s.Selector,
				Candidate: s.Candidate, Chain: append([]string(nil), s.Chain...),
				Reason: s.Reason, UpdatedAt: s.UpdatedAt,
				Health: agentCandidateHealth(s.Health),
			})
		}
	}
	for _, component := range c.Components {
		st.Components = append(st.Components, ComponentStatus{
			Name: component.Name, Expected: component.Expected,
			Actual: component.Actual, Error: component.Error,
		})
	}
	sortComponentStatuses(st.Components)
	return st
}

func componentStatusesEqual(a, b []ComponentStatus) bool {
	aa := append([]ComponentStatus(nil), a...)
	bb := append([]ComponentStatus(nil), b...)
	sortComponentStatuses(aa)
	sortComponentStatuses(bb)
	return reflect.DeepEqual(aa, bb)
}

func candidateHealthClaim(h *AgentCandidateHealth) *attest.CandidateHealthClaim {
	if h == nil {
		return nil
	}
	return &attest.CandidateHealthClaim{
		Candidates: h.Candidates, RecentSuccess: h.RecentSuccess,
		RecentDegraded: h.RecentDegraded, RecentFailed: h.RecentFailed,
		Stale: h.Stale, Unknown: h.Unknown, SelectedState: h.SelectedState,
		SelectedSamples: h.SelectedSamples, SelectedFailures: h.SelectedFailures,
		SelectedP50MS: cloneInt(h.SelectedP50MS), SelectedP95MS: cloneInt(h.SelectedP95MS),
		BestP50MS: cloneInt(h.BestP50MS), SelectedKBps: cloneInt(h.SelectedKBps),
		BestKBps: cloneInt(h.BestKBps),
	}
}

func agentCandidateHealth(h *attest.CandidateHealthClaim) *AgentCandidateHealth {
	if h == nil {
		return nil
	}
	return &AgentCandidateHealth{
		Candidates: h.Candidates, RecentSuccess: h.RecentSuccess,
		RecentDegraded: h.RecentDegraded, RecentFailed: h.RecentFailed,
		Stale: h.Stale, Unknown: h.Unknown, SelectedState: h.SelectedState,
		SelectedSamples: h.SelectedSamples, SelectedFailures: h.SelectedFailures,
		SelectedP50MS: cloneInt(h.SelectedP50MS), SelectedP95MS: cloneInt(h.SelectedP95MS),
		BestP50MS: cloneInt(h.BestP50MS), SelectedKBps: cloneInt(h.SelectedKBps),
		BestKBps: cloneInt(h.BestKBps),
	}
}

func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}

// AttestationErrors 校验 Status 里所有带签名的观测。没有签名仍按旧节点兼容
// 处理；出现签名却验不过是明确故障，必须进入 Status.Errors/OK。
func AttestationErrors(st *Status, now time.Time, maxAge time.Duration) []string {
	if st == nil {
		return nil
	}
	var signed []*Observation
	if st.Observation != nil && st.Observation.Attest != nil {
		signed = append(signed, st.Observation)
	}
	for i := range st.Learned {
		if st.Learned[i].Attest != nil {
			signed = append(signed, &st.Learned[i])
		}
	}
	if len(signed) == 0 {
		return nil
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return []string{"读签名 CA:" + err.Error()}
	}
	var out []string
	for _, o := range signed {
		if _, err := VerifyObservation(o, ca, now, maxAge); err != nil {
			out = append(out, fmt.Sprintf("观测 %s 的签名陈述无效:%v", o.Node, err))
		}
	}
	return out
}

const caPath = "/etc/loom/tls/ca.crt"
