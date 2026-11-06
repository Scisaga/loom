package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestReportTargetKeysKeepHistoricalBytesAndNewWriterRequiresNetwork(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := ReleaseDigest([]byte("demo-target-selection"))
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ReportSequence: 1,
		ViewDigest: digest, PolicyID: "demo-policy", NetworkGeneration: "demo-local", ReportedAt: 1,
		Selections:   []ReportSelection{{ServiceID: "demo-service", PolicyID: "demo-policy", CandidateID: digest, Target: "demo.example:443"}},
		Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	// Historical bytes are signed as they were, independently of today's writer.
	message, err := signedContractBytes(reportDomain, report.unsigned())
	if err != nil {
		t.Fatal(err)
	}
	report.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	original, err := CanonicalEncode(report)
	if err != nil || report.Verify(public) != nil {
		t.Fatal("historical report did not verify", err)
	}
	var read DeviceReport
	if err := decodeStoredReport(original, &read); err != nil {
		t.Fatal(err)
	}
	after, _ := CanonicalEncode(read)
	if !bytes.Equal(original, after) || read.Selections[0].Target != "demo.example:443" {
		t.Fatal("historical generic target was rewritten")
	}
	if _, err := SignDeviceReport(report, key); err == nil {
		t.Fatal("new writer issued a historical bare target")
	}
	report.Selections = []ReportSelection{
		{ServiceID: "demo-service", PolicyID: "demo-policy", CandidateID: digest},
		{ServiceID: "demo-service", PolicyID: "demo-policy", CandidateID: digest, Target: "tcp://demo.example:443"},
		{ServiceID: "demo-service", PolicyID: "demo-policy", CandidateID: digest, Target: "udp://demo.example:443"},
	}
	report, err = SignDeviceReport(report, key)
	if err != nil || report.Verify(public) != nil {
		t.Fatal("network-qualified report did not verify", err)
	}
	body, _ := CanonicalEncode(report)
	if err := decodeStoredReport(body, &read); err != nil {
		t.Fatal(err)
	}
	after, _ = CanonicalEncode(read)
	if !bytes.Equal(body, after) {
		t.Fatal("network-qualified report did not round trip")
	}
	for _, invalid := range []string{"http://demo.example:443", "tcp://demo.example:0443", "tcp://demo.example:443/", "tcp://Demo.example:443"} {
		report.Selections[1].Target = invalid
		if _, err := SignDeviceReport(report, key); err == nil {
			t.Fatal("invalid target key signed", invalid)
		}
	}
}
