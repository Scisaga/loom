package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA 造一套自足的测试材料,不依赖机器上真实的 PKI。
type testCA struct {
	certPEM []byte
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Loom Internal CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(der)
	return &testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key, cert: crt,
	}
}

// issue 给某个节点签一张证书,返回 (keyPEM, certPEM)。
func (ca *testCA) issue(t *testing.T, node string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: node + nodeSuffix},
		DNSNames:     []string{node + nodeSuffix},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func claim(node string) Claim {
	return Claim{Node: node, TS: "2026-08-25T12:00:00Z",
		Commit: "426961f342b0", Binary: "72a1f1abde95", Applied: "2b06535d1dbf"}
}

func TestSignThenVerify(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	s, err := Sign(claim("demo-b"), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(s, ca.certPEM)
	if err != nil {
		t.Fatalf("自己签的自己验不过:%v", err)
	}
	if got.Node != "demo-b" || got.Commit != "426961f342b0" {
		t.Fatalf("验出来的内容不对:%+v", got)
	}
}

func TestExternalPlatformSignerThenAssemble(t *testing.T) {
	ca := newCA(t)
	keyPEM, certPEM := ca.issue(t, "demo-b")
	key, err := parseKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	normalized, message, err := PrepareSignature(claim("demo-b"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := AssembleSignature(normalized, certPEM, signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, ca.certPEM); err != nil {
		t.Fatalf("平台签名组装后无法验证:%v", err)
	}
	signature[len(signature)-1] ^= 1
	if _, err := AssembleSignature(normalized, certPEM, signature); err == nil {
		t.Fatal("损坏的平台签名必须在组装时被拒绝")
	}
}

// **这是本文件存在的主要理由。** 没有这一条,任何一台有合法证书的机器
// 都能替别人发言 —— 而"替别人发言"正是转述,正是签名要根治的东西。
func TestCannotSpeakForAnotherNode(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-a") // demo-a 的合法证书
	c := claim("demo-b")              // 却声称自己是 demo-b
	s, err := Sign(c, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, ca.certPEM); err == nil {
		t.Fatal("demo-a 拿自己的钥匙替 demo-b 发言,必须被拒绝")
	} else if !strings.Contains(err.Error(), "替") {
		t.Errorf("错误要说清楚是冒名,得到:%v", err)
	}
}

// 自签证书链不到 CA —— 否则谁都能造一张。
func TestSelfSignedCertIsRejected(t *testing.T) {
	real := newCA(t)
	rogue := newCA(t)
	key, crt := rogue.issue(t, "demo-b")
	s, _ := Sign(claim("demo-b"), key, crt)
	if _, err := Verify(s, real.certPEM); err == nil {
		t.Fatal("别的 CA 签的证书必须被拒绝")
	}
}

// 内容被改过就验不过 —— 转述路径上任何一环动了手脚都会暴露。
func TestTamperedClaimFailsVerification(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	s, _ := Sign(claim("demo-b"), key, crt)

	for _, tc := range []struct {
		name string
		mut  func(*Signed)
	}{
		{"改 commit", func(s *Signed) { s.Commit = "deadbeefcafe" }},
		{"改 applied", func(s *Signed) { s.Applied = "0000000000ff" }},
		{"改时间", func(s *Signed) { s.TS = "2026-08-25T13:00:00Z" }},
		{"改二进制", func(s *Signed) { s.Binary = "ffffffffffff" }},
		{"改平台", func(s *Signed) { s.Platform = "plan9/amd64" }},
		{"改 rollout", func(s *Signed) {
			s.Rollout = &RolloutClaim{Snapshot: "other", Stage: "failed"}
		}},
		{"改 Agent 选择", func(s *Signed) {
			s.Agent = &AgentClaim{Node: "demo-b", TS: s.TS,
				Selections: []SelectionClaim{{Declaration: "d", Candidate: "cand:d:evil"}}}
		}},
		{"改测量摘要", func(s *Signed) { s.MeasurementsSHA256 = strings.Repeat("0", 64) }},
	} {
		bad := *s
		tc.mut(&bad)
		if _, err := Verify(&bad, ca.certPEM); err == nil {
			t.Errorf("%s 之后仍然验过了", tc.name)
		}
	}
}

func TestVerifyFreshRejectsReplayAndFuture(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	now := time.Date(2026, 8, 25, 12, 10, 0, 0, time.UTC)

	s, err := Sign(claim("demo-b"), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFresh(s, ca.certPEM, now, 15*time.Minute); err != nil {
		t.Fatalf("十分钟前的陈述应仍然新鲜:%v", err)
	}
	if _, err := VerifyFresh(s, ca.certPEM, now, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "过期") {
		t.Fatalf("旧陈述应被当作重放拒绝,得到:%v", err)
	}

	future := claim("demo-b")
	future.TS = now.Add(3 * time.Minute).Format(time.RFC3339)
	fs, err := Sign(future, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFresh(fs, ca.certPEM, now, 15*time.Minute); err == nil || !strings.Contains(err.Error(), "未来") {
		t.Fatalf("过远的未来时间应被拒绝,得到:%v", err)
	}
}

// 升级期间仍会收到旧二进制签的 v1 陈述；没有扩展字段时必须继续可验。
func TestV1ClaimRemainsCompatible(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	c := claim("demo-b")
	if c.extended() {
		t.Fatal("基础陈述应走 v1 canonical")
	}
	s, err := Sign(c, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, ca.certPEM); err != nil {
		t.Fatalf("v1 陈述升级后验不过:%v", err)
	}
}

// v4 只能在新增 node-owned 字段出现时启用；没有健康/Agent 版本的历史
// v2/v3 claim 必须保持逐字节 canonical，才能验证升级前已经签出的陈述。
func TestV2V3CanonicalBytesRemainCompatible(t *testing.T) {
	base := Claim{
		Node: "n", TS: "t", Commit: "c", Dirty: true, Tag: "tag",
		Binary: "b", BinaryErr: "e", Go: "go", Platform: "linux", Applied: "snap",
		Rollout: &RolloutClaim{Snapshot: "snap", Stage: "verified", EnteredAt: "at", LastGood: "old"},
		Agent: &AgentClaim{Node: "n", TS: "t", Selections: []SelectionClaim{{
			Declaration: "d", Selector: "s", Candidate: "cand", Chain: []string{"a", "b"},
			Reason: "why", UpdatedAt: "u",
		}},
		},
	}
	for _, tc := range []struct {
		name, digest, want string
	}{
		{"v2", "", "a881274816058fa687133e1fe4b2043e0085fee3b34e7ad843a01f87d5a05424"},
		{"v3", "abc", "1501dd9510106441a009f46ed0319dacde8f7ae6696607108fbe1995467d3df7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.MeasurementsSHA256 = tc.digest
			sum := sha256.Sum256(c.canonical())
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Fatalf("legacy %s canonical 漂移:%s != %s", tc.name, got, tc.want)
			}
		})
	}
}

func TestV4BindsCandidateHealthAndAgentProtocolVersion(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	p50, p95, best, selectedKBps, bestKBps := 120, 190, 80, 300, 500
	c := claim("demo-b")
	c.MeasurementsSHA256 = strings.Repeat("a", 64)
	c.Agent = &AgentClaim{
		Node: "demo-b", TS: c.TS, ComponentVersion: "0.1.0",
		Selections: []SelectionClaim{{
			Declaration: "d", Selector: "svc:d", Candidate: "cand:d:demo-b", UpdatedAt: c.TS,
			Health: &CandidateHealthClaim{
				Candidates: 3, RecentSuccess: 1, RecentDegraded: 1, RecentFailed: 1,
				SelectedState: "degraded", SelectedSamples: 5, SelectedFailures: 2,
				SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &best,
				SelectedKBps: &selectedKBps, BestKBps: &bestKBps,
			},
		}},
	}
	s, err := Sign(c, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if s.CanonicalVersion != 4 {
		t.Fatalf("新扩展没有显式选择 v4:%d", s.CanonicalVersion)
	}
	if _, err := Verify(s, ca.certPEM); err != nil {
		t.Fatalf("v4 自签名验不过:%v", err)
	}

	mutate := func(change func(*SelectionClaim, *AgentClaim)) *Signed {
		bad := *s
		a := *s.Agent
		a.Selections = append([]SelectionClaim(nil), s.Agent.Selections...)
		sel := a.Selections[0]
		h := *sel.Health
		sel.Health = &h
		a.Selections[0] = sel
		change(&a.Selections[0], &a)
		bad.Agent = &a
		return &bad
	}
	for _, tc := range []struct {
		name string
		mut  func(*SelectionClaim, *AgentClaim)
	}{
		{"候选计数", func(s *SelectionClaim, _ *AgentClaim) { s.Health.RecentFailed++ }},
		{"候选延迟", func(s *SelectionClaim, _ *AgentClaim) { v := 1; s.Health.BestP50MS = &v }},
		{"候选吞吐", func(s *SelectionClaim, _ *AgentClaim) { v := 1; s.Health.BestKBps = &v }},
		{"Agent 组件版本", func(_ *SelectionClaim, a *AgentClaim) { a.ComponentVersion = "forged" }},
	} {
		if _, err := Verify(mutate(tc.mut), ca.certPEM); err == nil {
			t.Errorf("relay 改写%s后仍验签成功", tc.name)
		}
	}
}

func TestV5BindsComponentVersions(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	c := claim("demo-b")
	c.MeasurementsSHA256 = strings.Repeat("b", 64)
	c.Components = []ComponentClaim{
		{Name: "wireguard", Expected: "1.0.20250521", Actual: "1.0.20210914"},
		{Name: "sing-box", Expected: "1.11.4", Actual: "1.11.4"},
	}
	s, err := Sign(c, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if s.CanonicalVersion != 5 {
		t.Fatalf("component claim canonical_version=%d, want 5", s.CanonicalVersion)
	}
	if _, err := Verify(s, ca.certPEM); err != nil {
		t.Fatal(err)
	}
	s.Components[0].Actual = "1.0.20250521"
	if _, err := Verify(s, ca.certPEM); err == nil || !strings.Contains(err.Error(), "签名对不上") {
		t.Fatalf("component tamper still verified: %v", err)
	}
}

// canonical 必须是确定的,而且**字段之间不能互相串位** ——
// 否则把 commit 的一段挪到 binary 里能算出同样的字节。
func TestCanonicalIsUnambiguous(t *testing.T) {
	a := Claim{Node: "n", TS: "t", Commit: "ab", Binary: "cd"}
	b := Claim{Node: "n", TS: "t", Commit: "abcd", Binary: ""}
	if string(a.canonical()) == string(b.canonical()) {
		t.Fatal("相邻字段串位算出了同样的字节 —— 分隔符没起作用")
	}
	if string(a.canonical()) != string(a.canonical()) {
		t.Fatal("同样的输入两次算出不同字节")
	}
}

func TestV2CanonicalCannotCollideOnSeparatorsOrChain(t *testing.T) {
	base := Claim{Node: "n", TS: "t", Commit: "c", Rollout: &RolloutClaim{Stage: "failed"}}
	a, b := base, base
	a.Rollout = &RolloutClaim{Stage: "failed", LastGood: "left\x1fright", Error: "tail"}
	b.Rollout = &RolloutClaim{Stage: "failed", LastGood: "left", Error: "right\x1ftail"}
	if string(a.canonical()) == string(b.canonical()) {
		t.Fatal("错误文本里的 unit separator 造成 v2 canonical 碰撞")
	}

	a = base
	b = base
	a.Agent = &AgentClaim{Node: "n", TS: "t", Selections: []SelectionClaim{{
		Declaration: "d", Selector: "s", Candidate: "c", Chain: []string{"a>b"},
	}}}
	b.Agent = &AgentClaim{Node: "n", TS: "t", Selections: []SelectionClaim{{
		Declaration: "d", Selector: "s", Candidate: "c", Chain: []string{"a", "b"},
	}}}
	if string(a.canonical()) == string(b.canonical()) {
		t.Fatal("包含 > 的节点 ID 与多跳 chain 造成 v2 canonical 碰撞")
	}
}

func TestV2CanonicalSortsSelectionsByAllFields(t *testing.T) {
	a := SelectionClaim{Declaration: "d", Selector: "s", Candidate: "c", Chain: []string{"x"}, Reason: "z"}
	b := SelectionClaim{Declaration: "d", Selector: "s", Candidate: "c", Chain: []string{"y"}, Reason: "a"}
	left := Claim{Node: "n", TS: "t", Agent: &AgentClaim{Node: "n", TS: "t", Selections: []SelectionClaim{a, b}}}
	right := Claim{Node: "n", TS: "t", Agent: &AgentClaim{Node: "n", TS: "t", Selections: []SelectionClaim{b, a}}}
	if string(left.canonical()) != string(right.canonical()) {
		t.Fatal("同内容的 selection 输入排列改变了 canonical")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	s, _ := Sign(claim("demo-b"), key, crt)

	bad := *s
	bad.Sig = "这不是 base64!!!"
	if _, err := Verify(&bad, ca.certPEM); err == nil {
		t.Error("坏签名应报错")
	}
	bad = *s
	bad.Cert = "不是 PEM"
	if _, err := Verify(&bad, ca.certPEM); err == nil {
		t.Error("坏证书应报错")
	}
	if _, err := Verify(s, []byte("不是 CA")); err == nil {
		t.Error("坏 CA 应报错")
	}
}
