//go:build !windows

package clientreport_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"loom/internal/attest"
	"loom/internal/clientreport"
	"loom/internal/report"
	"math/big"
	"strings"
	"testing"
	"time"
)

func reportIdentityFixture(t *testing.T, node string) (key, cert, ca []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-report-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: node + ".node.internal"},
		DNSNames: []string{node + ".node.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &private.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func reportFixture(t *testing.T, at time.Time) (*clientreport.Observation, []byte, []byte) {
	t.Helper()
	key, cert, ca := reportIdentityFixture(t, "demo-client")
	t.Cleanup(func() { clear(key) })
	o, err := clientreport.Build("demo-client", "0123456789ab", nil, at, key, cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	return o, key, ca
}

func verifyWithServer(o *clientreport.Observation, ca []byte, at time.Time, maxAge time.Duration) error {
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	var wire report.Observation
	if err := json.Unmarshal(body, &wire); err != nil {
		return err
	}
	if _, err := report.VerifyObservationAtLeast(&wire, ca, at, maxAge, 5); err != nil {
		return err
	}
	check, err := attest.VerifySelfCheckFresh(wire.SelfCheck, ca, at, maxAge)
	if err != nil {
		return err
	}
	if check.Node != wire.Node || check.TS != wire.TS || wire.Attest.Cert != wire.SelfCheck.Cert || wire.AttestExtended != nil {
		return errors.New("self-check attachment does not bind the same node/time/identity")
	}
	return nil
}

func TestMinimalTwoSignatureContract(t *testing.T) {
	now := time.Now()
	o, _, ca := reportFixture(t, now)
	if got := clientreport.EmptyMeasurementsDigest(); got != "474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4" {
		t.Fatal(got)
	}
	if o.TS != now.UTC().Format(time.RFC3339Nano) {
		t.Fatal("timestamp lost precision or UTC")
	}
	body, _ := json.Marshal(o)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	if len(fields) != 5 {
		t.Fatalf("unexpected fields: %s", body)
	}
	for _, name := range []string{"node", "ts", "applied", "attest", "self_check"} {
		if _, ok := fields[name]; !ok {
			t.Fatal("missing " + name)
		}
	}
	if err := verifyWithServer(o, ca, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	claim, err := attest.VerifyFresh(o.Attest, ca, now, time.Minute)
	if err != nil || claim.CanonicalVersion != 5 || claim.Components != nil || claim.Commit != "" || claim.Rollout != nil {
		t.Fatalf("not a minimal v5 claim: %v", err)
	}
	check, err := attest.VerifySelfCheckFresh(o.SelfCheck, ca, now, time.Minute)
	if err != nil || check.Version != 1 || check.TS != claim.TS || check.Node != claim.Node || !check.Healthy {
		t.Fatalf("self-check: %v", err)
	}
	for name, mutate := range map[string]func(*clientreport.Observation){
		"node":               func(o *clientreport.Observation) { o.Node = "demo-other" },
		"ts":                 func(o *clientreport.Observation) { o.TS = now.Add(time.Second).UTC().Format(time.RFC3339Nano) },
		"applied":            func(o *clientreport.Observation) { o.Applied = "111111111111" },
		"measurements":       func(o *clientreport.Observation) { o.Attest.MeasurementsSHA256 = "changed" },
		"missing self-check": func(o *clientreport.Observation) { o.SelfCheck = nil },
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(o)
			var altered clientreport.Observation
			_ = json.Unmarshal(body, &altered)
			mutate(&altered)
			if err := verifyWithServer(&altered, ca, now, time.Minute); err == nil {
				t.Fatal("tampered claim accepted")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-2 * time.Minute), now.Add(3 * time.Minute)} {
		old, _, oldCA := reportFixture(t, at)
		if err := verifyWithServer(old, oldCA, now, time.Minute); err == nil {
			t.Fatal("invalid freshness accepted")
		}
	}
	otherKey, otherCert, otherCA := reportIdentityFixture(t, "demo-client")
	defer clear(otherKey)
	o.SelfCheck, err = attest.SignSelfCheck(o.SelfCheck.SelfCheckClaim, otherKey, otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWithServer(o, append(ca, otherCA...), now, time.Minute); err == nil {
		t.Fatal("mixed identities accepted")
	}
}

func TestProblemsAreNormalizedWithoutInventingHealth(t *testing.T) {
	key, cert, ca := reportIdentityFixture(t, "demo-client")
	defer clear(key)
	o, err := clientreport.Build("demo-client", "0123456789ab", []string{"missing probe", "configuration unknown", "missing probe"}, time.Now(), key, cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if o.SelfCheck.Healthy || len(o.SelfCheck.Problems) != 2 || o.SelfCheck.Problems[0] != "configuration unknown" {
		t.Fatal("invalid health or problem ordering")
	}
	if _, err := clientreport.Build("demo-client", "", nil, time.Now(), key, cert, ca); err == nil {
		t.Fatal("unactivated snapshot accepted")
	}
	if _, err := clientreport.Build("demo-client", "0123456789ab", []string{"bad\nproblem"}, time.Now(), key, cert, ca); err == nil {
		t.Fatal("control characters accepted")
	}
}

func TestAgentPathQualityReasonAreBoundToCanonicalV5(t *testing.T) {
	now := time.Now()
	key, cert, ca := reportIdentityFixture(t, "demo-client")
	defer clear(key)
	p50, p95, best, kbps := 12, 24, 12, 100
	state := &clientreport.AgentState{Node: "demo-client", TS: now.UTC().Format(time.RFC3339), ComponentVersion: "demo-agent", Selections: []clientreport.AgentSelection{{
		Declaration: "demo-service", Selector: "opaque:selector", Candidate: "opaque:fast", Chain: []string{"demo-prefix-b", "demo-exit"}, UpdatedAt: now.UTC().Format(time.RFC3339),
		Reason: "完整路径改善超过门槛 [decision_scope=" + strings.Repeat("a", 64) + "]",
		Health: &clientreport.AgentCandidateHealth{Candidates: 2, RecentSuccess: 2, SelectedState: "success", SelectedSamples: 6, SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &best, SelectedKBps: &kbps, BestKBps: &kbps},
	}}}
	o, err := clientreport.BuildWithAgent("demo-client", "0123456789ab", nil, state, now, key, cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWithServer(o, ca, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if o.Attest.CanonicalVersion != 5 || o.Attest.Agent == nil || o.Attest.Agent.Selections[0].Health.SelectedP50MS == nil {
		t.Fatal("not a signed Agent v5 report")
	}
	for name, mutate := range map[string]func(*clientreport.Observation){
		"candidate":        func(o *clientreport.Observation) { o.Agent.Selections[0].Candidate = "opaque:other" },
		"chain":            func(o *clientreport.Observation) { o.Agent.Selections[0].Chain[0] = "demo-forged-prefix" },
		"quality":          func(o *clientreport.Observation) { *o.Agent.Selections[0].Health.SelectedP50MS = 1 },
		"reason and scope": func(o *clientreport.Observation) { o.Agent.Selections[0].Reason = "forged decision_scope" },
		"signed scope":     func(o *clientreport.Observation) { o.Attest.Agent.Selections[0].Reason = "forged decision_scope" },
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(o)
			var changed clientreport.Observation
			_ = json.Unmarshal(body, &changed)
			mutate(&changed)
			if err := verifyWithServer(&changed, ca, now, time.Minute); err == nil {
				t.Fatal("unsigned/tampered Agent evidence accepted")
			}
		})
	}
	state.Selections[0].Health = nil
	state.Selections[0].Reason = "unknown"
	unknown, err := clientreport.BuildWithAgent("demo-client", "0123456789ab", []string{"Agent 尚无测量"}, state, now, key, cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(unknown)
	if bytes.Contains(body, []byte("selected_p50_ms")) || unknown.SelfCheck.Healthy {
		t.Fatal("missing quality became fabricated zero/healthy")
	}
	if err := verifyWithServer(unknown, ca, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}
