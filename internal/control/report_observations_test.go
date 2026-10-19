package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestReportObservationValidationKeepsPastAndFutureOriginals(t *testing.T) {
	key := testKey(t)
	digest := "sha256:" + strings.Repeat("0", 64)
	sample := Observation{Level: "service", ServiceID: "demo-service", CandidateID: digest, Target: "https://demo.example/probe", Action: "https_request", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: "unavailable", ObservedAt: 1, ValidUntil: 2}
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: 1, ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: 1000,
		Selections: []ReportSelection{}, Observations: []Observation{sample}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}
	for _, observed := range []int64{1, 2000} {
		report.Observations[0].ObservedAt, report.Observations[0].ValidUntil = observed, observed+1
		signed, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal("producer time policy leaked into the existing signer", err)
		}
		body, err := CanonicalEncode(signed)
		var decoded DeviceReport
		if err != nil || decodeStoredReport(body, &decoded) != nil || decoded.Verify(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))) != nil {
			t.Fatal("valid signed historical observation was rejected", err)
		}
		after, _ := CanonicalEncode(decoded)
		if !bytes.Equal(body, after) {
			t.Fatal("existing report bytes changed")
		}
	}
}
