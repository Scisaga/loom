package report

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"loom/internal/attest"
)

// TestV5ObservationSurvivesJSONGossipVerificationAndView 钉住完整消费链，避免
// 单包测试各自通过、字段却在 JSON、gossip 或 UI 转换边界上丢失。
func TestV5ObservationSurvivesJSONGossipVerificationAndView(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, keyPEM, certPEM := reportTestIdentity(t, "demo-b")
	p50, p95, best := 41, 73, 41
	o := Observation{
		Node: "demo-b", TS: now.Format(time.RFC3339), Applied: "snapshot-v5",
		Agent: &AgentState{
			Node: "demo-b", TS: now.Format(time.RFC3339), ComponentVersion: "0.1.0",
			Selections: []AgentSelection{{
				Declaration: "best-egress", Selector: "svc:best-egress", Candidate: "cand:demo-b",
				Chain: []string{"demo-b"}, UpdatedAt: now.Format(time.RFC3339),
				Health: &AgentCandidateHealth{
					Candidates: 1, RecentSuccess: 1, SelectedState: "success",
					SelectedSamples: 5, SelectedP50MS: &p50, SelectedP95MS: &p95,
					BestP50MS: &best,
				},
			}},
		},
		Components: []ComponentStatus{{Name: "sing-box", Expected: "1.11.4", Actual: "1.11.4"}},
		Edges:      []Edge{{To: "demo-e", RTTMs: 88, Samples: 5}},
	}
	legacy, current := claimsForObservation(&o, 5)
	var err error
	o.Attest, err = attest.Sign(legacy, keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	o.AttestExtended, err = attest.Sign(current, keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := json.Marshal(&o)
	if err != nil {
		t.Fatal(err)
	}
	var relayed Observation
	if err := json.Unmarshal(wire, &relayed); err != nil {
		t.Fatal(err)
	}
	// 模拟 relay 同时剥掉新签名与旧 reader 看不见的新字段。兼容阶段仍可把
	// 它当作真实 v3 投影；phase B 必须拒绝，不能被悄悄降级。
	downgraded := legacyObservation(&relayed)
	if _, err := VerifyObservationAtLeast(downgraded, caPEM, now, 10*time.Minute, 0); err != nil {
		t.Fatalf("phase A 误拒合法 v3 兼容投影:%v", err)
	}
	if _, err := VerifyObservationAtLeast(downgraded, caPEM, now, 10*time.Minute, 5); err == nil {
		t.Fatal("phase B 接受了被剥掉 v5 的降级投影")
	}

	tbl := newTable(5)
	tbl.verify = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := VerifyObservationAtLeast(got, caPEM, at, maxAge, 5)
		return err
	}
	if err := tbl.put(&relayed, now, 10*time.Minute); err != nil {
		t.Fatalf("v5 观测无法进入 gossip 表:%v", err)
	}
	learned := tbl.snapshot("demo-d", now, 10*time.Minute)
	if len(learned) != 1 {
		t.Fatalf("gossip 快照丢失观测:%+v", learned)
	}
	trusted, err := VerifyObservationAtLeast(&learned[0], caPEM, now, 10*time.Minute, 5)
	if err != nil {
		t.Fatalf("JSON/gossip 后无法重新验签:%v", err)
	}
	node := nodeView("demo-b", false, false, nil, &learned[0], trusted, "", now)
	if node.Source != "签名转述" || node.Applied != "snapshot-v5" || len(node.Edges) != 1 {
		t.Fatalf("签名身份/测量没有进入 UI:%+v", node)
	}
	if len(node.Components) != 1 || !node.Components[0].OK || node.Components[0].Actual != "1.11.4" {
		t.Fatalf("组件状态没有进入 UI:%+v", node.Components)
	}
	if node.Agent == nil || len(node.Agent.Selections) != 1 || node.Agent.Selections[0].Health == nil ||
		node.Agent.Selections[0].Health.SelectedState != "success" {
		t.Fatalf("Agent 候选健康没有进入 UI:%+v", node.Agent)
	}
}

func reportTestIdentity(t *testing.T, node string) (caPEM, keyPEM, certPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loom test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeName := node + ".node.internal"
	nodeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeName}, DNSNames: []string{nodeName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTemplate, caCert, &nodeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nodeDER})
}
