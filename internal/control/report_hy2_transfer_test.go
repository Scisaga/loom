package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestHY2TransferPreservesAbsentReportBytesAndSignedScope(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	sample := Observation{Level: "resource", ResourceID: "demo-hy2", Target: "demo.example:443", Action: "hysteria2_tls", SpecDigest: digest,
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 2000, DurationMS: new(int64(30))}
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ReportSequence: 1, ViewDigest: digest,
		NetworkGeneration: sample.NetworkGeneration, ReportedAt: 1001, Selections: []ReportSelection{}, Observations: []Observation{sample},
		Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	original, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(original)
	var decoded DeviceReport
	if bytes.Contains(before, []byte("hy2_transfer")) || decodeStoredReport(before, &decoded) != nil || decoded.Verify(public) != nil {
		t.Fatal("absent transfer altered the original report")
	}
	after, _ := CanonicalEncode(decoded)
	if !bytes.Equal(before, after) {
		t.Fatal("old signed bytes did not round trip")
	}
	measurement := HY2Transfer{DurationNS: 30_000_999, RXBytes: 2048, TXBytes: 1024}
	report.Observations[0].HY2Transfer = &measurement
	report.ReportSequence = 2
	signed, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := CanonicalEncode(signed)
	if decodeStoredReport(body, &decoded) != nil || decoded.Verify(public) != nil || !reflect.DeepEqual(signed, decoded) {
		t.Fatal("measured transfer did not round trip")
	}
	decoded.Observations[0].HY2Transfer.TXBytes++
	if decoded.Verify(public) == nil {
		t.Fatal("actual byte counts were outside the signature")
	}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.HY2Transfer.DurationNS = 0 },
		func(v *Observation) { v.HY2Transfer.DurationNS = -1 },
		func(v *Observation) { v.HY2Transfer.DurationNS = 31_000_000 },
		func(v *Observation) { v.HY2Transfer.RXBytes = 0 },
		func(v *Observation) { v.HY2Transfer.TXBytes = 0 },
		func(v *Observation) { v.DurationMS = nil },
		func(v *Observation) { v.Result = "unavailable" },
		func(v *Observation) { v.Result = "unknown" },
		func(v *Observation) { v.Action = "wireguard_dns" },
		func(v *Observation) { v.Level, v.LinkID = "link", "demo-link" },
		func(v *Observation) {
			v.Level, v.ResourceID, v.ServiceID, v.CandidateID, v.Action, v.Target = "service", "", "demo-service", digest, "https_request", "https://demo.example/"
		},
	} {
		value, transfer := sample, measurement
		value.HY2Transfer = &transfer
		change(&value)
		if value.Validate() == nil {
			t.Fatal("unsupported transfer accepted")
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `{"duration_ns":1,"rx_bytes":"01","tx_bytes":"1"}`,
		`{"duration_ns":1,"rx_bytes":1,"tx_bytes":"1"}`, `{"duration_ns":1.5,"rx_bytes":"1","tx_bytes":"1"}`,
		`{"duration_ns":1,"rx_bytes":"1","tx_bytes":"1","throughput":1}`,
	} {
		bad := bytes.Replace(before, []byte(`"level":"resource"`), []byte(`"hy2_transfer":`+raw+`,"level":"resource"`), 1)
		if decodeStoredReport(bad, &decoded) == nil {
			t.Fatal("noncanonical transfer accepted", raw)
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	var old DeviceReport
	if err := decodeStoredReport(before, &old); err != nil {
		t.Fatal(err)
	}
	for _, value := range []DeviceReport{old, signed} {
		if err := store.Put(value, public); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	history := reopened.History()
	if len(history) != 2 {
		t.Fatal("restart lost original reports")
	}
	for _, value := range history {
		actual, _ := CanonicalEncode(value)
		expected := before
		if value.ReportSequence == 2 {
			expected = body
		}
		if !bytes.Equal(expected, actual) || value.Verify(public) != nil {
			t.Fatal("restart rewrote a signed original or its transfer")
		}
	}
}
