package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"loom/internal/attest"
	"loom/internal/version"
	"reflect"
	"time"
)

// §16.1.2：从 report 的原校验入口提取；服务器与客户端共同使用，不改变 canonical 字节。
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
	// v3+ claim. Legacy v1/v2 claims still authenticate identity state, but their
	// measurements must remain unknown in topology views.
	MeasurementsVerified bool
}

// measurementDigest hashes exactly the relayed measurement payload. A struct
// fixes JSON field order; observation construction sorts both slices, so the
// same node-owned payload has stable bytes without coupling attest to report.
func MeasurementDigest(o *Observation) string {
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
	return VerifyObservationAtLeast(o, ca, now, maxAge, 0)
}

// VerifyObservationAtLeast 在验签之外执行配置下发的最小 canonical 版本闸门。
// minVersion=0 是滚动兼容阶段；=5 表示全网 reader 已升级，legacy 只能作为
// 旧 reader 的旁路副本，不能再被新版信任为完整状态。
func VerifyObservationAtLeast(o *Observation, ca []byte, now time.Time, maxAge time.Duration,
	minVersion int) (*AttestedState, error) {
	if minVersion != 0 && minVersion != 5 {
		return nil, fmt.Errorf("不支持 attestation 最小版本 %d", minVersion)
	}
	if o == nil || o.Attest == nil {
		return nil, fmt.Errorf("没有签名陈述")
	}
	primary, err := attest.VerifyFresh(o.Attest, ca, now, maxAge)
	if err != nil {
		return nil, fmt.Errorf("签名:%w", err)
	}
	c := primary
	if primary.CanonicalVersion == 0 {
		// 用旧 reader 反序列化后能看见的投影再绑定一次。这样双签不是
		// “多放了一个没人检查的字段”，而是每个新节点都会持续验证旧节点
		// 能消费的 v3。
		if err := BindClaim(legacyObservation(o), primary); err != nil {
			return nil, fmt.Errorf("兼容签名绑定:%w", err)
		}
	} else if o.AttestExtended != nil {
		return nil, fmt.Errorf("主签名已经是 v4/v5，不能再携带第二份扩展签名")
	}
	if o.AttestExtended != nil {
		if o.AttestExtended.CanonicalVersion != 4 && o.AttestExtended.CanonicalVersion != 5 {
			return nil, fmt.Errorf("扩展签名必须使用 canonical_version=4/5")
		}
		c, err = attest.VerifyFresh(o.AttestExtended, ca, now, maxAge)
		if err != nil {
			return nil, fmt.Errorf("扩展签名:%w", err)
		}
	}
	if err := RequireAttestationVersion(c, minVersion); err != nil {
		return nil, err
	}
	if err := BindClaim(o, c); err != nil {
		return nil, err
	}
	st := stateFromClaim(c)
	if problems := ValidateAgentState(st.Agent, o.Node, now); len(problems) > 0 {
		return nil, fmt.Errorf("签名 Agent 状态非法:%s", problems[0])
	}
	if problems := ValidateComponentStatuses(st.Components); len(problems) > 0 {
		return nil, fmt.Errorf("签名组件状态非法:%s", problems[0])
	}
	return st, nil
}

func RequireAttestationVersion(c *attest.Claim, minVersion int) error {
	if minVersion == 0 {
		return nil
	}
	if c == nil || c.CanonicalVersion != 5 {
		got := 0
		if c != nil {
			got = c.CanonicalVersion
		}
		return fmt.Errorf("需要 canonical_version=5，收到 %d（扩展签名可能被剥离）", got)
	}
	return nil
}

// legacyObservation 模拟旧 Go 结构对新 JSON 的解码结果：未知的 components、
// component_version、health 与 attest_extended 会被忽略，其余字段保持原样。
func legacyObservation(o *Observation) *Observation {
	if o == nil {
		return nil
	}
	legacy := *o
	legacy.Components = nil
	legacy.Traffic = nil
	legacy.LinkMetrics = nil
	legacy.SelfCheck = nil
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

func BindClaim(o *Observation, c *attest.Claim) error {
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
	if c.MeasurementsSHA256 != "" && c.MeasurementsSHA256 != MeasurementDigest(o) {
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

func observationNeedsVerification(o *Observation, minVersion int) bool {
	return o != nil && (minVersion > 0 || o.Attest != nil || o.AttestExtended != nil)
}

// VerifyAttachments 校验 §16.1 的独立附件；主签名不能替附件背书。
func VerifyAttachments(o *Observation, ca []byte, now time.Time, maxAge time.Duration) error {
	if _, err := VerifySelfCheckAttachment(o, ca, now, maxAge); err != nil {
		return err
	}
	if _, err := VerifyTrafficAttachment(o, ca, now, maxAge); err != nil {
		return err
	}
	if _, err := VerifyLinkMetricAttachment(o, ca, now, maxAge); err != nil {
		return err
	}
	return nil
}
func VerifySelfCheckAttachment(o *Observation, ca []byte, now time.Time,
	maxAge time.Duration) (*attest.SelfCheckClaim, error) {
	if o == nil || o.SelfCheck == nil {
		return nil, nil
	}
	claim, err := attest.VerifySelfCheckFresh(o.SelfCheck, ca, now, maxAge)
	if err != nil {
		return nil, err
	}
	if claim.Node != o.Node {
		return nil, fmt.Errorf("自检签名节点 %q 与外层观测节点 %q 不一致", claim.Node, o.Node)
	}
	if claim.TS != o.TS {
		return nil, fmt.Errorf("自检签名时间 %q 与外层观测时间 %q 不一致", claim.TS, o.TS)
	}
	return claim, nil
}

func VerifyTrafficAttachment(o *Observation, ca []byte, now time.Time,
	maxAge time.Duration) (*attest.TrafficClaim, error) {
	if o == nil || o.Traffic == nil {
		return nil, nil
	}
	claim, err := attest.VerifyTrafficFresh(o.Traffic, ca, now, maxAge)
	if err != nil {
		return nil, err
	}
	if claim.Node != o.Node {
		return nil, fmt.Errorf("流量签名节点 %q 与外层观测节点 %q 不一致", claim.Node, o.Node)
	}
	if claim.TS != o.TS {
		return nil, fmt.Errorf("流量签名时间 %q 与外层观测时间 %q 不一致", claim.TS, o.TS)
	}
	return claim, nil
}

func VerifyLinkMetricAttachment(o *Observation, ca []byte, now time.Time,
	maxAge time.Duration) (*attest.LinkMetricClaim, error) {
	if o == nil || o.LinkMetrics == nil {
		return nil, nil
	}
	claim, err := attest.VerifyLinkMetricFresh(o.LinkMetrics, ca, now, maxAge)
	if err != nil {
		return nil, err
	}
	if claim.Node != o.Node {
		return nil, fmt.Errorf("链路度量签名节点 %q 与外层观测节点 %q 不一致", claim.Node, o.Node)
	}
	if claim.TS != o.TS {
		return nil, fmt.Errorf("链路度量签名时间 %q 与外层观测时间 %q 不一致", claim.TS, o.TS)
	}
	return claim, nil
}
