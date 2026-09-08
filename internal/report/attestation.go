package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"loom/internal/attest"
	"loom/internal/observation"
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
	// v3+ claim. Legacy v1/v2 claims still authenticate identity state, but their
	// measurements must remain unknown in topology views.
	MeasurementsVerified bool
}

// measurementDigest hashes exactly the relayed measurement payload. A struct
// fixes JSON field order; observation construction sorts both slices, so the
// same node-owned payload has stable bytes without coupling attest to report.
func measurementDigest(o *Observation) string {
	wire, err := observationPayload(o)
	if err != nil {
		return ""
	}
	return observation.MeasurementDigest(wire)
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
func VerifyObservationAtLeast(o *Observation, ca []byte, now time.Time, maxAge time.Duration, minVersion int) (*AttestedState, error) {
	wire, err := observationPayload(o)
	if err != nil {
		return nil, err
	}
	trusted, err := observation.VerifyObservationAtLeast(wire, ca, now, maxAge, minVersion)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(trusted)
	if err != nil {
		return nil, err
	}
	var state AttestedState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, err
	}
	return &state, nil
}
func requireAttestationVersion(c *attest.Claim, minVersion int) error {
	return observation.RequireAttestationVersion(c, minVersion)
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

func bindClaim(o *Observation, c *attest.Claim) error {
	wire, err := observationPayload(o)
	if err != nil {
		return err
	}
	return observation.BindClaim(wire, c)
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

// collectSelfCheckAttestation turns the complete local Status verdict into a
// compact, independently signed attachment. Failure to read signing material
// remains an absent attachment (unknown to remote readers), never an unsigned
// green fallback.
func collectSelfCheckAttestation(st *Status, now time.Time) *attest.SelfCheckAttest {
	if st == nil || st.Node == "" || st.TS == "" {
		return nil
	}
	claim := selfCheckClaimFromStatus(st, now)
	key, err := os.ReadFile(nodeKeyPath)
	if err != nil {
		return nil
	}
	crt, err := os.ReadFile(nodeCertPath)
	if err != nil {
		return nil
	}
	signed, err := attest.SignSelfCheck(claim, key, crt)
	if err != nil {
		return nil
	}
	return signed
}

// selfCheckClaimFromStatus is intentionally based on Status.OKAt rather than
// re-inventing a second health verdict. The problem list explains every field
// family that contributes to that verdict; a generic fail-closed entry covers
// future Status fields until their detailed formatter is added here.
func selfCheckClaimFromStatus(st *Status, now time.Time) attest.SelfCheckClaim {
	claim := attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion,
		Node:    st.Node,
		TS:      st.TS,
	}
	claim.Healthy = st.OKAt(now)
	if claim.Healthy {
		return claim
	}

	problems := append([]string(nil), st.Errors...)
	if r := st.Rollout; r != nil {
		switch {
		case r.Stage == "failed":
			problem := "rollout 失败"
			if r.Error != "" {
				problem += ":" + r.Error
			}
			problems = append(problems, problem)
		case r.InFlight():
			if d, ok := r.StuckFor(now); !ok {
				problems = append(problems, "rollout 阶段时间无效:"+r.Stage)
			} else if d > RolloutStuckAfter {
				problems = append(problems,
					fmt.Sprintf("rollout 卡在 %s:%s", r.Stage, d.Round(time.Second)))
			}
		}
	}
	if st.Publisher != nil && st.Publisher.Unhealthy(now) {
		problem := "发布器状态异常"
		if st.Publisher.LastError != "" {
			problem += ":" + st.Publisher.LastError
		}
		problems = append(problems, problem)
	}
	for _, component := range st.Components {
		if !component.OK() {
			problems = append(problems, componentProblem(component))
		}
	}
	problems = append(problems, agentHealthProblems(st.Agent)...)
	for _, tunnel := range st.Tunnels {
		switch {
		case tunnel.Down:
			problems = append(problems, "隧道不存在:"+tunnel.Interface)
		case tunnel.HandshakeAgeSec < 0:
			problems = append(problems, "隧道从未握手:"+tunnel.Interface)
		case tunnel.Stale:
			problems = append(problems,
				fmt.Sprintf("隧道握手陈旧:%s:%ds", tunnel.Interface, tunnel.HandshakeAgeSec))
		}
		if tunnel.UnitState != "" && tunnel.UnitState != "active" {
			problems = append(problems,
				fmt.Sprintf("隧道单元异常:%s:%s", tunnel.Interface, tunnel.UnitState))
		}
	}
	if d := st.Drift; d != nil {
		for _, path := range d.Modified {
			problems = append(problems, "配置被改过:"+path)
		}
		for _, path := range d.Missing {
			problems = append(problems, "配置缺失:"+path)
		}
		for _, path := range d.Unreadable {
			problems = append(problems, "配置读不到:"+path)
		}
	}
	if st.Observation != nil {
		for _, reach := range st.Observation.Targets {
			if reach.Uplink && !reach.OK() {
				problems = append(problems,
					fmt.Sprintf("直连探测失败:%s:%s", reach.Target, reach.Error))
			}
		}
	}
	claim.Problems = compactSelfCheckProblems(problems)
	if len(claim.Problems) == 0 {
		claim.Problems = []string{"本机自检未通过（暂无结构化原因）"}
	}
	return claim
}

func compactSelfCheckProblems(problems []string) []string {
	// Keep every locally produced claim below the aggregate attestation limit
	// even at the maximum item count. The verifier permits a larger individual
	// diagnostic only so future producers remain wire-compatible.
	const derivedProblemLimit = attest.SelfCheckMaxTotalSize / attest.SelfCheckMaxProblems
	set := make(map[string]struct{}, len(problems))
	for _, problem := range problems {
		problem = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, problem)
		problem = strings.Join(strings.Fields(problem), " ")
		if len(problem) > derivedProblemLimit {
			problem = problem[:derivedProblemLimit]
			for !utf8.ValidString(problem) {
				problem = problem[:len(problem)-1]
			}
			problem = strings.TrimSpace(problem)
		}
		if problem != "" {
			set[problem] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for problem := range set {
		out = append(out, problem)
	}
	sort.Strings(out)
	if len(out) > attest.SelfCheckMaxProblems {
		omitted := len(out) - (attest.SelfCheckMaxProblems - 1)
		out = append(append([]string(nil), out[:attest.SelfCheckMaxProblems-1]...),
			fmt.Sprintf("问题列表已截断:另有 %d 项", omitted))
		sort.Strings(out)
	}
	return out
}

// verifySelfCheckAttachment binds the independently verified verdict back to
// its containing Observation. A relay cannot move a green claim to another
// node or refresh its timestamp through the mutable outer envelope.
func verifySelfCheckAttachment(o *Observation, ca []byte, now time.Time, maxAge time.Duration) (*attest.SelfCheckClaim, error) {
	if o == nil {
		return nil, nil
	}
	return observation.VerifySelfCheckAttachment(&observation.Observation{Node: o.Node, TS: o.TS, SelfCheck: o.SelfCheck}, ca, now, maxAge)
}

// AttestationErrors 校验 Status 里所有带签名的观测。兼容阶段允许完全无签名
// 的旧节点保持 unknown；一旦进入 phase B，缺失签名本身就是明确故障。
func AttestationErrors(st *Status, now time.Time, maxAge time.Duration, minVersion int) []string {
	if st == nil {
		return nil
	}
	var signed []*Observation
	if observationNeedsVerification(st.Observation, minVersion) {
		signed = append(signed, st.Observation)
	}
	for i := range st.Learned {
		if observationNeedsVerification(&st.Learned[i], minVersion) {
			signed = append(signed, &st.Learned[i])
		}
	}
	hasTraffic := st.Observation != nil && st.Observation.Traffic != nil
	hasSelfCheck := st.Observation != nil && st.Observation.SelfCheck != nil
	if !hasTraffic || !hasSelfCheck {
		for i := range st.Learned {
			if st.Learned[i].Traffic != nil {
				hasTraffic = true
			}
			if st.Learned[i].SelfCheck != nil {
				hasSelfCheck = true
			}
		}
	}
	if len(signed) == 0 && !hasTraffic && !hasSelfCheck {
		return nil
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return []string{"读签名 CA:" + err.Error()}
	}
	var out []string
	for _, o := range signed {
		if _, err := VerifyObservationAtLeast(o, ca, now, maxAge, minVersion); err != nil {
			out = append(out, fmt.Sprintf("观测 %s 的签名陈述无效:%v", o.Node, err))
		}
	}
	traffic := func(o *Observation) {
		if o == nil || o.Traffic == nil {
			return
		}
		if _, err := verifyTrafficAttachment(o, ca, now, maxAge); err != nil {
			out = append(out, fmt.Sprintf("观测 %s 的流量签名陈述无效:%v", o.Node, err))
		}
	}
	traffic(st.Observation)
	for i := range st.Learned {
		traffic(&st.Learned[i])
	}
	selfCheck := func(o *Observation) {
		if o == nil || o.SelfCheck == nil {
			return
		}
		if _, err := verifySelfCheckAttachment(o, ca, now, maxAge); err != nil {
			out = append(out, fmt.Sprintf("观测 %s 的自检签名陈述无效:%v", o.Node, err))
		}
	}
	selfCheck(st.Observation)
	for i := range st.Learned {
		selfCheck(&st.Learned[i])
	}
	return out
}

const caPath = "/etc/loom/tls/ca.crt"

// §16.1.2：仅转换既有 DTO，签名与外层字段绑定统一由纯 observation 包执行。
func observationPayload(o *Observation) (*observation.Observation, error) {
	if o == nil {
		return nil, nil
	}
	body, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var wire observation.Observation
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	return &wire, nil
}
