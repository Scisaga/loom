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

func TestReportedPreferenceKeepsOriginalBytesAndBindsNewSamples(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ReportSequence: 1,
		ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{},
		Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}
	// The historical signing object is explicit: adding an absent field must
	// not reinterpret any already authenticated original.
	original := map[string]any{"schema": 3, "network_id": report.NetworkID, "device_id": report.DeviceID,
		"report_sequence": report.ReportSequence, "view_digest": digest, "network_generation": report.NetworkGeneration,
		"reported_at": report.ReportedAt, "selections": report.Selections, "observations": report.Observations,
		"runtime": report.Runtime, "components": report.Components}
	message, err := signedContractBytes(reportDomain, original)
	if err != nil {
		t.Fatal(err)
	}
	report.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	before, err := CanonicalEncode(report)
	if err != nil || report.Verify(public) != nil || bytes.Contains(before, []byte("preference")) {
		t.Fatal("original report changed", err)
	}
	var decoded DeviceReport
	if err := decodeStoredReport(before, &decoded); err != nil {
		t.Fatal(err)
	}
	after, _ := CanonicalEncode(decoded)
	if !bytes.Equal(before, after) || decoded.Preference != nil {
		t.Fatal("missing report became an inferred setting")
	}
	for _, preference := range []ReportPreference{{Mode: "auto"}, {Mode: "direct"}, {Mode: "fixed_exit", Exit: "demo-unavailable-exit"}} {
		report.Preference = &preference
		report, err = SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		body, err := CanonicalEncode(report)
		if err != nil || decodeStoredReport(body, &decoded) != nil || !reflect.DeepEqual(decoded, report) || decoded.Verify(public) != nil {
			t.Fatal("new report did not round trip", err)
		}
		tampered := report
		tampered.Preference = nil
		if tampered.Verify(public) == nil {
			t.Fatal("preference was outside the signature")
		}
	}
	for _, invalid := range []string{`null`, `{}`, `{"mode":"unknown"}`, `{"mode":"auto","exit":"demo-exit"}`, `{"mode":"direct","exit":""}`, `{"mode":"fixed_exit"}`, `{"exit":"direct","mode":"fixed_exit"}`, `{"exit":"auto","mode":"fixed_exit"}`, `{"mode":"auto","unknown":true}`} {
		body := bytes.Replace(before, []byte(`"report_sequence"`), []byte(`"preference":`+invalid+`,"report_sequence"`), 1)
		if decodeStoredReport(body, &decoded) == nil {
			t.Fatal("noncanonical or invalid preference accepted", invalid)
		}
	}
}

func TestReportedPreferenceRemainsSeparateFromSelectionAndSurvivesRestart(t *testing.T) {
	fixture, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	report := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1,
		Preference:   &ReportPreference{Mode: "fixed_exit", Exit: "demo-unavailable-exit"},
		Selections:   []ReportSelection{{ServiceID: view.Routes[0].ServiceID, CandidateID: view.Routes[0].ID}},
		Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	report, err = SignDeviceReport(report, fixture.keys[0])
	if err != nil || verifyCurrentReport(report, projection) != nil {
		t.Fatal("intent was confused with actual selection or authorization", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, []DeviceReport{report})
	original := testObservationBytes(t, root)
	for i := 0; i < 2; i++ {
		store, err := OpenObservationStore(root)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := WebSnapshot{Devices: []Device{{ID: view.DeviceID}}, Paths: projectWebPaths(projection)}
		projectWebObservations(&snapshot, store.Verified(projection))
		if snapshot.Devices[0].Evidence == nil || !reflect.DeepEqual(snapshot.Devices[0].Evidence.Preference, report.Preference) || !snapshot.Paths[0].Selected || snapshot.Paths[0].FinalExit != "direct" {
			t.Fatal("readback replaced actual Direct or lost unavailable fixed intent")
		}
		if !bytes.Equal(original, testObservationBytes(t, root)) {
			t.Fatal("restart modified the original signed setting sample")
		}
	}
	view.Responsibilities = []string{"control"}
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("server-only report invented an access setting")
	}
	projection.NetworkIntent.Services[0].Name = "Demo changed service"
	store, _ := OpenObservationStore(root)
	if len(store.Verified(projection)) != 0 {
		t.Fatal("old View preference survived a scope change")
	}
}
