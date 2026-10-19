package clientadapter

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"loom/internal/control"
)

func reportObservationFixture() []control.Observation {
	digest := "sha256:" + strings.Repeat("0", 64)
	service := func(id, result string, observed, until int64) control.Observation {
		return control.Observation{Level: "service", ServiceID: id, CandidateID: digest, Target: "https://demo.example/probe", Action: "https_request", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: result, ObservedAt: observed, ValidUntil: until}
	}
	return []control.Observation{
		{Level: "link", LinkID: "demo-link", ResourceID: "demo-wg", Target: "[fd00::2]:53", Action: "wireguard_dns", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 999, ValidUntil: 1001},
		{Level: "resource", ResourceID: "demo-hy2", Target: "demo.example:443", Action: "hysteria2_tls", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: "unavailable", ObservedAt: 900, ValidUntil: 1000},
		service("demo-a", "available", 1000, 1001),
		service("demo-b", "unavailable", 990, 1010),
		service("demo-c", "unknown", 990, 1010),
		service("demo-d", "available", 1001, 1010),
		service("demo-e", "unavailable", 900, 999),
	}
}

func TestCurrentReportObservationsPreservesInputsAndAllCurrentResults(t *testing.T) {
	input := reportObservationFixture()
	before, err := control.CanonicalEncode(input)
	if err != nil {
		t.Fatal(err)
	}
	current, err := CurrentReportObservations(input, "demo-underlay", 1000)
	want := []control.Observation{input[0], input[2], input[3], input[4]}
	if err != nil || !reflect.DeepEqual(current, want) {
		t.Fatal("report lost a current level/result or retained an expired/future sample", err, current)
	}
	// A later report uses the same original times, while the earlier report stays frozen.
	later, err := CurrentReportObservations(input, "demo-underlay", 1001)
	if err != nil || len(later) != 3 || !reflect.DeepEqual(later[2], input[5]) || !reflect.DeepEqual(current, want) {
		t.Fatal("report time renewed a sample or changed an earlier report", err)
	}
	current[0].Result = "unknown"
	after, _ := control.CanonicalEncode(input)
	if !bytes.Equal(before, after) {
		t.Fatal("report filtering modified the local recovery input")
	}
	empty, err := CurrentReportObservations(input, "demo-underlay", 2000)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty report observations are not an explicit collection", err)
	}
}

func TestCurrentReportObservationsRejectsEntireCollectionBeforeExpiry(t *testing.T) {
	expired := reportObservationFixture()[6]
	for _, test := range []struct {
		name       string
		values     []control.Observation
		generation string
	}{
		{"nil", nil, "demo-underlay"},
		{"generation", []control.Observation{}, ""},
		{"duplicate expired", []control.Observation{expired, expired}, "demo-underlay"},
		{"unordered expired", []control.Observation{expired, reportObservationFixture()[1]}, "demo-underlay"},
		{"wrong generation expired", []control.Observation{expired}, "demo-other-underlay"},
		{"malformed expired", func() []control.Observation {
			value := expired
			value.Result = "invalid"
			return []control.Observation{value}
		}(), "demo-underlay"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CurrentReportObservations(test.values, test.generation, 2000); err == nil {
				t.Fatal("expiry hid invalid report input")
			}
		})
	}
}
