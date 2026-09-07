package attest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func selfCheckClaim(node, ts string, healthy bool, problems ...string) SelfCheckClaim {
	return SelfCheckClaim{
		Version: SelfCheckClaimVersion, Node: node, TS: ts,
		Healthy: healthy, Problems: append([]string(nil), problems...),
	}
}

func TestSelfCheckSignVerifyAndTamper(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "demo-b")
	signed, err := SignSelfCheck(selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
		"Agent d 的 2 个候选近期全部失败", "隧道 wg-demo-e 握手陈旧"), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySelfCheckFresh(signed, ca.certPEM, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got.Node != "demo-b" || got.Healthy || len(got.Problems) != 2 {
		t.Fatalf("verified self-check changed: %+v", got)
	}

	for name, mutate := range map[string]func(*SelfCheckAttest){
		"node":     func(s *SelfCheckAttest) { s.Node = "demo-c" },
		"time":     func(s *SelfCheckAttest) { s.TS = now.Add(time.Second).Format(time.RFC3339) },
		"healthy":  func(s *SelfCheckAttest) { s.Healthy = true; s.Problems = nil },
		"problems": func(s *SelfCheckAttest) { s.Problems[0] = "被 relay 改写" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *signed
			bad.Problems = append([]string(nil), signed.Problems...)
			mutate(&bad)
			if _, err := VerifySelfCheck(&bad, ca.certPEM); err == nil {
				t.Fatal("tampered self-check verified")
			}
		})
	}
}

func TestExternalSelfCheckSignerThenAssemble(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	keyPEM, certPEM := ca.issue(t, "demo-b")
	key, err := parseKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	claim := selfCheckClaim("demo-b", now.Format(time.RFC3339), true)
	message, err := PrepareSelfCheckSignature(claim)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := AssembleSelfCheckSignature(claim, certPEM, signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelfCheck(signed, ca.certPEM); err != nil {
		t.Fatalf("平台自检签名组装后无法验证:%v", err)
	}
}

func TestSelfCheckRejectsImpersonationReplayAndInvalidProblemSet(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	peerKey, peerCert := ca.issue(t, "demo-a")
	impersonated, err := SignSelfCheck(
		selfCheckClaim("demo-b", now.Format(time.RFC3339), true), peerKey, peerCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelfCheck(impersonated, ca.certPEM); err == nil || !strings.Contains(err.Error(), "替") {
		t.Fatalf("another node's certificate spoke for demo-b: %v", err)
	}

	key, crt := ca.issue(t, "demo-b")
	old, err := SignSelfCheck(
		selfCheckClaim("demo-b", now.Add(-11*time.Minute).Format(time.RFC3339), true), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelfCheckFresh(old, ca.certPEM, now, 10*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "过期") {
		t.Fatalf("old green verdict was replayable: %v", err)
	}

	for name, claim := range map[string]SelfCheckClaim{
		"healthy with problems": selfCheckClaim("demo-b", now.Format(time.RFC3339), true, "down"),
		"unhealthy empty":       selfCheckClaim("demo-b", now.Format(time.RFC3339), false),
		"unsorted": selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
			"z problem", "a problem"),
		"duplicate": selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
			"same", "same"),
		"control": selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
			"line\nbreak"),
		"oversized": selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
			strings.Repeat("x", SelfCheckMaxProblemSize+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SignSelfCheck(claim, key, crt); err == nil {
				t.Fatal("invalid self-check claim was signed")
			}
		})
	}

	tooMany := make([]string, SelfCheckMaxProblems+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("%03d-problem", i)
	}
	if _, err := SignSelfCheck(selfCheckClaim("demo-b", now.Format(time.RFC3339), false, tooMany...),
		key, crt); err == nil || !strings.Contains(err.Error(), "过多") {
		t.Fatalf("oversized problem count was accepted: %v", err)
	}
	totalTooLarge := make([]string, SelfCheckMaxProblems)
	for i := range totalTooLarge {
		totalTooLarge[i] = fmt.Sprintf("%03d-%s", i, strings.Repeat("x", 300))
	}
	if _, err := SignSelfCheck(selfCheckClaim("demo-b", now.Format(time.RFC3339), false,
		totalTooLarge...), key, crt); err == nil || !strings.Contains(err.Error(), "总长度") {
		t.Fatalf("oversized aggregate problems were accepted: %v", err)
	}
}

func TestSelfCheckCanonicalIsIndependentFromV5(t *testing.T) {
	// Pin an actual v5 layout: the optional self-check must never be appended to
	// these bytes during a later refactor.
	c := Claim{
		CanonicalVersion: 5, Node: "demo-b", TS: "2026-08-28T12:00:00Z",
		Commit: "abc", Binary: "def", Applied: "snap",
		Components:         []ComponentClaim{{Name: "wireguard", Expected: "2", Actual: "2"}},
		MeasurementsSHA256: strings.Repeat("a", 64),
	}
	before := string(c.canonical())
	selfCheck := selfCheckClaim("demo-b", c.TS, true)
	_ = selfCheck.canonical()
	if after := string(c.canonical()); after != before {
		t.Fatal("constructing a self-check changed loom-attest canonical bytes")
	}
	sum := sha256.Sum256(c.canonical())
	if got, want := hex.EncodeToString(sum[:]), "5e15031765c89c20cc6bfbfae1b484036ed585ce871562bba92a90a39802f1f5"; got != want {
		t.Fatalf("loom-attest-v5 canonical drifted: %s != %s", got, want)
	}
}
