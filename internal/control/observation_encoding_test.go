package control

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestObservationCollectionStreamingPreservesCanonicalContract(t *testing.T) {
	key := testKey(t)
	digest := "sha256:" + strings.Repeat("0", 64)
	state := observationState{Schema: 3, Reports: []DeviceReport{}}
	for sequence := U64(1); sequence <= 2; sequence++ {
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped", AppliedViewDigest: digest}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		state.Reports = append(state.Reports, report)
	}
	for _, value := range []observationState{{Schema: 3, Reports: []DeviceReport{}}, {Schema: 3, Reports: state.Reports[:1]}, state} {
		want, err := CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encodeObservationState(value, len(want))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("streaming encoder changed existing canonical bytes", err)
		}
		decoded, err := decodeObservationState(want)
		if err != nil || !reflect.DeepEqual(decoded, value) {
			t.Fatal("streaming decoder changed the domain value", err)
		}
		decoded, spans, err := decodeObservationStateWithBytes(want)
		if err != nil {
			t.Fatal(err)
		}
		copied, nextSpans, err := encodeOriginalObservationReports(decoded, spans)
		if err != nil || !bytes.Equal(copied, want) {
			t.Fatal("copying original reports changed canonical bytes", err)
		}
		offset := len(observationPrefix)
		for i, span := range nextSpans {
			if i > 0 {
				offset++
			}
			if len(span) != len(spans[i]) || &span[0] != &copied[offset] {
				t.Fatal("new report span retained an old collection buffer")
			}
			offset += len(span)
		}
	}
	body, _ := CanonicalEncode(state)
	first, _ := CanonicalEncode(state.Reports[0])
	second, _ := CanonicalEncode(state.Reports[1])
	wrap := func(members string) string { return observationPrefix + members + observationSuffix }
	for _, invalid := range []string{
		"", "{}", `{"reports":null,"schema":3}`, `{"schema":3,"reports":[]}`,
		`{"reports":[],"schema":4}`, `{"reports":[],"schema":3,"unknown":true}`,
		`{"reports":[],"reports":[],"schema":3}`, `{"reports":[],"schema":3.0}`,
		string(body) + "\n", " " + string(body), string(body) + string(body),
		wrap(" "), wrap("null"), wrap(string(first) + ","), wrap("," + string(first)),
		wrap(" " + string(first)), wrap(string(first) + " "),
		wrap(string(first) + ", " + string(second)), wrap(string(first) + " ," + string(second)),
		wrap(string(second) + "," + string(first)), wrap(string(first) + "," + string(first)),
		strings.Replace(string(body), `"schema":3`, `"schema":3,"schema":3`, 1),
		strings.Replace(string(body), `"report_sequence":"1"`, `"report_sequence":"01"`, 1),
		strings.Replace(string(body), `"network_id":`, `"unknown":`, 1),
	} {
		if _, err := decodeObservationState([]byte(invalid)); err == nil {
			t.Fatal("accepted ambiguous or noncanonical collection")
		}
		var reference observationState
		if err := DecodeCanonical([]byte(invalid), &reference, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 128, MaxItems: len(invalid) + 1}); err == nil {
			t.Fatal("rejected a collection the canonical contract accepts")
		}
	}
}
