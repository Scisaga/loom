package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	// v3+ claim. Legacy v1/v2 claims still authenticate identity state, but their
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
		if err := bindClaim(legacyObservation(o), primary); err != nil {
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
	if err := requireAttestationVersion(c, minVersion); err != nil {
		return nil, err
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

func requireAttestationVersion(c *attest.Claim, minVersion int) error {
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
func verifySelfCheckAttachment(o *Observation, ca []byte, now time.Time,
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
