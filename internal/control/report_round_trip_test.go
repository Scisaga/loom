package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestNativeRoundTripKeepsAbsentBytesAndBindsSuccessfulMeasurements(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	sample := Observation{Level: "link", LinkID: "demo-link", ResourceID: "demo-wg", Target: "[fd00::1]:53", Action: "wireguard_dns", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 2000, DurationMS: new(int64(30))}
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-entry", ReportSequence: 1, ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: 1001, Selections: []ReportSelection{}, Observations: []Observation{sample}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	original, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(original)
	var decoded DeviceReport
	if bytes.Contains(before, []byte("round_trip_ms")) || decodeStoredReport(before, &decoded) != nil || decoded.Verify(public) != nil {
		t.Fatal("absent measurement changed original report")
	}
	after, _ := CanonicalEncode(decoded)
	if !bytes.Equal(before, after) {
		t.Fatal("old report did not round trip")
	}
	for _, value := range []int64{0, 20, 30} {
		report.Observations[0].RoundTripMS = new(value)
		signed, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := CanonicalEncode(signed)
		if decodeStoredReport(body, &decoded) != nil || decoded.Verify(public) != nil || !reflect.DeepEqual(signed, decoded) {
			t.Fatal("measured zero or value lost")
		}
		decoded.Observations[0].RoundTripMS = nil
		if decoded.Verify(public) == nil {
			t.Fatal("measurement was outside signature")
		}
	}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.RoundTripMS = new(int64(-1)) },
		func(v *Observation) { v.RoundTripMS = new(int64(31)) },
		func(v *Observation) { v.DurationMS = nil },
		func(v *Observation) { v.Result = "unavailable" },
		func(v *Observation) { v.Result = "unknown" },
		func(v *Observation) { v.Action = "hysteria2_tls" },
		func(v *Observation) { v.Level, v.LinkID = "resource", "" },
	} {
		value := sample
		value.RoundTripMS = new(int64(10))
		change(&value)
		if value.Validate() == nil {
			t.Fatal("unsupported round trip accepted", value)
		}
	}
	for _, raw := range []string{"null", "-1", "1.5", `"1"`} {
		body := bytes.Replace(before, []byte(`"result":"available"`), []byte(`"result":"available","round_trip_ms":`+raw), 1)
		if decodeStoredReport(body, &decoded) == nil {
			t.Fatal("noncanonical optional value accepted", raw)
		}
	}
}
