// Package attest 让一台机器**关于自己的陈述**在转述之后仍然可信。
//
// # 要解决的是什么
//
// gz02 和 hz01 与中控之间没有隧道(这是拓扑,不是故障),它们的消息只能
// 由 sg02 / ber01 转述过来。观测转述是没问题的 —— 快照 id、RTT 这类
// 数字,B 转述 C 的观测,可信度就是 B 的可信度,而观测本来就是尽力而为。
//
// **但身份不一样。** "C 跑的是 commit X"这句话如果只由 B 说,那么排障时
// 恰恰不能假设 B 可信 —— 出问题的往往就是链路上某一环。所以 D71/D73
// 的结论是"版本核不了转述来的节点",代价是 `loom status` 只能报
// "3/5 台核对过",另外两台永远是空白。
//
// 签名把这条限制取消掉:**转述的是密文,不是信任**。B 转述 C 的签名陈述,
// 篡改会被验签发现,伪造需要 C 的私钥。于是 C 够不够得到就不重要了。
// 同一份陈述也覆盖 Applied、rollout 与 Agent selector 实选；这些同样是
// 节点自己拥有、relay 只能原样转交而不能代写的运行态。
//
// # 为什么用现成的 PKI
//
// 每台机器早就有 `/etc/loom/tls/node.key` 和 `node.crt`(CN 是
// `<节点>.node.internal`,由内部 CA 签发)。不需要引入新的密钥材料,
// 也就不需要新的分发和轮换路径 —— 那是这个系统里最贵的东西。
package attest

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Claim 是一台机器关于**它自己拥有的运行态**的陈述：节点身份、版本坐标、
// 已应用快照、rollout 阶段，以及 Agent 从 selector 实读的当前选择。
//
// RTT、可达性等对外界的观测仍留在 Observation 的外层结构中，但 v3 用
// MeasurementsSHA256 绑定其完整 payload；这里直接携带的是 relay 不能代节点
// 改写的 node-owned state。
type Claim struct {
	// CanonicalVersion is zero for legacy v1/v2/v3 claims. New extension
	// families set an explicit version so future node-owned fields can add a
	// new canonical layout without changing the bytes of already deployed
	// signatures. Version 4 adds per-declaration candidate health; version 5
	// adds node-observed component versions.
	CanonicalVersion int              `json:"canonical_version,omitempty"`
	Node             string           `json:"node"`
	TS               string           `json:"ts"`
	Commit           string           `json:"commit,omitempty"`
	Dirty            bool             `json:"dirty,omitempty"`
	Tag              string           `json:"tag,omitempty"`
	Binary           string           `json:"binary,omitempty"`
	BinaryErr        string           `json:"binary_err,omitempty"`
	Go               string           `json:"go,omitempty"`
	Platform         string           `json:"platform,omitempty"`
	Applied          string           `json:"applied,omitempty"`
	Rollout          *RolloutClaim    `json:"rollout,omitempty"`
	Agent            *AgentClaim      `json:"agent,omitempty"`
	Components       []ComponentClaim `json:"components,omitempty"`

	// MeasurementsSHA256 binds the outer Observation.Edges/Targets payload.
	// Keeping the measurements outside Claim avoids duplicating report's wire
	// types here, while the digest prevents a relay from changing a legitimate
	// node's link measurements and turning an expected WG edge falsely green.
	// Empty means a legacy v1/v2 claim: identity state is still trustworthy,
	// measurements are not.
	MeasurementsSHA256 string `json:"measurements_sha256,omitempty"`
}

// ComponentClaim binds the installed version observation to the node that ran
// the version command. Expected is included so a relay cannot rewrite a
// mismatch into a match; the snapshot coordinate still tells callers whether
// that node's expectation is the current generation.
type ComponentClaim struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
}

// RolloutClaim 是随节点运行态一起签名的 rollout 摘要。它只带跨节点判断需要的
// 字段；逐步耗时仍留在节点本机的 rollout.json 里。
type RolloutClaim struct {
	Snapshot  string `json:"snapshot"`
	Stage     string `json:"stage"`
	EnteredAt string `json:"entered_at"`
	LastGood  string `json:"last_good,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SelectionClaim 是 Agent 从 sing-box selector 读到的实际选择。它跟随节点
// 节点运行态签名，转述方不能把候选或路径换成另一条。
type SelectionClaim struct {
	Declaration string                `json:"declaration"`
	Selector    string                `json:"selector"`
	Candidate   string                `json:"candidate"`
	Chain       []string              `json:"chain,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	UpdatedAt   string                `json:"updated_at"`
	Health      *CandidateHealthClaim `json:"health,omitempty"`
}

// CandidateHealthClaim mirrors the compact Agent state summary. It is kept in
// attest rather than importing agent/report so the trust boundary remains
// acyclic; report performs the explicit mapping in both directions.
type CandidateHealthClaim struct {
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

type AgentClaim struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// ComponentVersion preserves the deployed JSON field name but carries the
	// Agent wire-protocol version, not a binary build coordinate.
	ComponentVersion string           `json:"component_version,omitempty"`
	Selections       []SelectionClaim `json:"selections"`
}

// canonical 是签名覆盖的字节。
//
// **固定顺序、长度前缀,不走 JSON。** JSON 的字段顺序、空白、转义都
// 可能因库版本而变,而签名是针对字节的。任意错误文本、reason 和服务 key
// 都可能含分隔符，所以 v2/v3/v4 的每个字符串和数组元素都必须有无歧义边界。
func (c *Claim) canonical() []byte {
	// 没有扩展字段时仍按 v1 算，让升级期间旧节点已经签出的陈述继续可验。
	// 新版不能简单在旧格式后面追加却沿用版本号：否则空字段与旧格式的
	// 边界含糊。v3 只比 v2 多一个测量摘要字段；v4 再加入显式版本、
	// Agent component_version 与候选健康字段族；v5 再加入组件实际版本。
	if !c.extended() {
		return []byte(strings.Join([]string{
			"loom-attest-v1", c.Node, c.TS, c.Commit, c.Binary, c.Applied,
		}, "\x1f"))
	}
	roll := RolloutClaim{}
	if c.Rollout != nil {
		roll = *c.Rollout
	}
	agent := AgentClaim{}
	if c.Agent != nil {
		agent = *c.Agent
		agent.Selections = append([]SelectionClaim(nil), c.Agent.Selections...)
		sort.Slice(agent.Selections, func(i, j int) bool {
			a, b := agent.Selections[i], agent.Selections[j]
			for _, pair := range [][2]string{
				{a.Declaration, b.Declaration}, {a.Selector, b.Selector},
				{a.Candidate, b.Candidate},
			} {
				if n := cmp.Compare(pair[0], pair[1]); n != 0 {
					return n < 0
				}
			}
			if n := slices.Compare(a.Chain, b.Chain); n != 0 {
				return n < 0
			}
			if n := cmp.Compare(a.Reason, b.Reason); n != 0 {
				return n < 0
			}
			if n := cmp.Compare(a.UpdatedAt, b.UpdatedAt); n != 0 {
				return n < 0
			}
			return slices.Compare(candidateHealthFields(a.Health), candidateHealthFields(b.Health)) < 0
		})
	}
	components := append([]ComponentClaim(nil), c.Components...)
	sort.Slice(components, func(i, j int) bool {
		a, b := components[i], components[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Expected != b.Expected {
			return a.Expected < b.Expected
		}
		if a.Actual != b.Actual {
			return a.Actual < b.Actual
		}
		return a.Error < b.Error
	})
	var b bytes.Buffer
	field := func(s string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		b.Write(size[:])
		b.WriteString(s)
	}
	version := "loom-attest-v2"
	v5 := c.CanonicalVersion == 5 || len(components) > 0
	v4 := v5 || c.CanonicalVersion == 4 || claimNeedsV4(&agent)
	if v5 {
		version = "loom-attest-v5"
	} else if v4 {
		version = "loom-attest-v4"
	} else if c.MeasurementsSHA256 != "" {
		version = "loom-attest-v3"
	}
	fields := []string{version, c.Node, c.TS, c.Commit,
		fmt.Sprint(c.Dirty), c.Tag, c.Binary, c.BinaryErr, c.Go, c.Platform, c.Applied}
	for _, s := range fields {
		field(s)
	}
	field(fmt.Sprint(c.Rollout != nil))
	for _, s := range []string{roll.Snapshot, roll.Stage, roll.EnteredAt, roll.LastGood, roll.Error} {
		field(s)
	}
	field(fmt.Sprint(c.Agent != nil))
	field(agent.Node)
	field(agent.TS)
	if v4 {
		field(agent.ComponentVersion)
	}
	field(fmt.Sprint(len(agent.Selections)))
	for _, s := range agent.Selections {
		field(s.Declaration)
		field(s.Selector)
		field(s.Candidate)
		field(fmt.Sprint(len(s.Chain)))
		for _, node := range s.Chain {
			field(node)
		}
		field(s.Reason)
		field(s.UpdatedAt)
		if v4 {
			for _, v := range candidateHealthFields(s.Health) {
				field(v)
			}
		}
	}
	if v5 {
		field(fmt.Sprint(len(components)))
		for _, component := range components {
			field(component.Name)
			field(component.Expected)
			field(component.Actual)
			field(component.Error)
		}
	}
	if v4 || c.MeasurementsSHA256 != "" {
		field(c.MeasurementsSHA256)
	}
	return b.Bytes()
}

func (c *Claim) extended() bool {
	return c.CanonicalVersion != 0 || c.Dirty || c.Tag != "" || c.BinaryErr != "" || c.Go != "" ||
		c.Platform != "" || c.Rollout != nil || c.Agent != nil || len(c.Components) > 0 ||
		c.MeasurementsSHA256 != ""
}

func claimNeedsV4(a *AgentClaim) bool {
	if a == nil {
		return false
	}
	if a.ComponentVersion != "" {
		return true
	}
	for i := range a.Selections {
		if a.Selections[i].Health != nil {
			return true
		}
	}
	return false
}

// candidateHealthFields returns a fixed-width, length-prefixed field family.
// Keeping presence bits separate from values preserves nil-vs-0 latency and
// leaves the v4 layout straightforward to extend with a later canonical
// version instead of mutating these bytes in place.
func candidateHealthFields(h *CandidateHealthClaim) []string {
	if h == nil {
		return []string{
			"false", "", "", "", "", "", "", "", "", "",
			"false", "", "false", "", "false", "", "false", "", "false", "",
		}
	}
	ptr := func(v *int) (string, string) {
		if v == nil {
			return "false", ""
		}
		return "true", fmt.Sprint(*v)
	}
	p50p, p50 := ptr(h.SelectedP50MS)
	p95p, p95 := ptr(h.SelectedP95MS)
	bestp, best := ptr(h.BestP50MS)
	selKBpsP, selKBps := ptr(h.SelectedKBps)
	bestKBpsP, bestKBps := ptr(h.BestKBps)
	return []string{
		"true", fmt.Sprint(h.Candidates), fmt.Sprint(h.RecentSuccess),
		fmt.Sprint(h.RecentDegraded), fmt.Sprint(h.RecentFailed),
		fmt.Sprint(h.Stale), fmt.Sprint(h.Unknown), h.SelectedState,
		fmt.Sprint(h.SelectedSamples), fmt.Sprint(h.SelectedFailures),
		p50p, p50, p95p, p95, bestp, best,
		selKBpsP, selKBps, bestKBpsP, bestKBps,
	}
}

// Signed 是 Claim 加上"它确实来自那台机器"的证明。
//
// Cert 随签名一起走,所以验证方**不需要事先有对方的证书** —— 只要有 CA。
// 这正是转述场景需要的:中控不必为每台够不到的机器单独准备材料。
type Signed struct {
	Claim `json:",inline"`
	Cert  string `json:"cert"`
	Sig   string `json:"sig"`
}

// Sign 用本机私钥给陈述签名。
func Sign(c Claim, keyPEM, certPEM []byte) (*Signed, error) {
	if c.CanonicalVersion == 0 {
		switch {
		case len(c.Components) > 0:
			c.CanonicalVersion = 5
		case claimNeedsV4(c.Agent):
			c.CanonicalVersion = 4
		}
	}
	if c.CanonicalVersion != 0 && c.CanonicalVersion != 4 && c.CanonicalVersion != 5 {
		return nil, fmt.Errorf("不支持 canonical_version=%d", c.CanonicalVersion)
	}
	if len(c.Components) > 0 && c.CanonicalVersion != 5 {
		return nil, fmt.Errorf("组件陈述必须使用 canonical_version=5")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("签名:%w", err)
	}
	return &Signed{
		Claim: c,
		Cert:  string(certPEM),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify 校验一条陈述,返回其中可信的部分。
//
// 三件事都要查,少一件这个机制就是摆设:
//
//  1. 证书链得到 CA —— 否则谁都能自签一张
//  2. **证书的名字要和 Claim.Node 对上** —— 否则 ber01 可以拿自己的
//     私钥签一条"gz02 跑的是 commit X"
//  3. 签名覆盖 canonical 字节
func Verify(s *Signed, caPEM []byte) (*Claim, error) {
	if s == nil {
		return nil, fmt.Errorf("签名陈述为空")
	}
	if s.CanonicalVersion != 0 && s.CanonicalVersion != 4 && s.CanonicalVersion != 5 {
		return nil, fmt.Errorf("不支持 canonical_version=%d", s.CanonicalVersion)
	}
	if len(s.Components) > 0 && s.CanonicalVersion != 5 {
		return nil, fmt.Errorf("组件陈述没有使用 canonical_version=5")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 证书读不出来")
	}
	blk, _ := pem.Decode([]byte(s.Cert))
	if blk == nil {
		return nil, fmt.Errorf("陈述里的证书不是 PEM")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书:%w", err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("证书链不到 CA:%w", err)
	}
	if !nameMatches(crt, s.Node) {
		// **这一条是整个机制的关键。** 没有它,任何一台有合法证书的机器
		// 都能替别人发言 —— 而"替别人发言"正是转述,正是要根治的东西。
		return nil, fmt.Errorf("证书是 %q 的,却在替 %q 发言", certName(crt), s.Node)
	}
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("证书里不是 ECDSA 公钥")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("签名不是 base64:%w", err)
	}
	sum := sha256.Sum256(s.Claim.canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, fmt.Errorf("签名对不上 —— 内容被改过,或者不是这把钥匙签的")
	}
	c := s.Claim
	return &c, nil
}

// VerifyFresh 在验签之外检查陈述时间。签名只能证明“节点曾经说过”，不能
// 证明这句话现在仍然成立；不做新鲜度检查，任意旧版本陈述都能无限重放。
//
// 允许两分钟的未来偏差，给 NTP 尚未完全收敛的机器留余量；再大的未来时间
// 会让陈述在很长时间内永不过期，必须拒绝。
func VerifyFresh(s *Signed, caPEM []byte, now time.Time, maxAge time.Duration) (*Claim, error) {
	c, err := Verify(s, caPEM)
	if err != nil {
		return nil, err
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("陈述新鲜度上限必须为正")
	}
	ts, err := time.Parse(time.RFC3339, c.TS)
	if err != nil {
		return nil, fmt.Errorf("陈述时间 %q 无法解析:%w", c.TS, err)
	}
	age := now.UTC().Sub(ts.UTC())
	if age < -2*time.Minute {
		return nil, fmt.Errorf("陈述时间在未来 %s", (-age).Round(time.Second))
	}
	if age > maxAge {
		return nil, fmt.Errorf("陈述已过期(%s,上限 %s)", age.Round(time.Second), maxAge)
	}
	return c, nil
}

// nodeSuffix 是节点证书的命名约定(§13.3):`<节点 id>.node.internal`。
const nodeSuffix = ".node.internal"

func nameMatches(crt *x509.Certificate, node string) bool {
	want := node + nodeSuffix
	if crt.Subject.CommonName == want {
		return true
	}
	for _, d := range crt.DNSNames {
		if d == want {
			return true
		}
	}
	return false
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	if len(crt.DNSNames) > 0 {
		return crt.DNSNames[0]
	}
	return "(无名)"
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	// 文件里可能先有一段 EC PARAMETERS,要跳过去找真正的私钥块。
	rest := keyPEM
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			return nil, fmt.Errorf("私钥里没有可用的 PEM 块")
		}
		rest = r
		switch blk.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("私钥不是 ECDSA")
			}
			return ec, nil
		}
	}
}
