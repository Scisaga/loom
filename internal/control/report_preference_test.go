package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
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
	for _, policy := range []string{"demo-auto-policy", "demo-direct-policy", "demo-fixed-policy"} {
		report.PolicyID = policy
		report, err = SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		body, err := CanonicalEncode(report)
		if err != nil || decodeStoredReport(body, &decoded) != nil || !reflect.DeepEqual(decoded, report) || decoded.Verify(public) != nil {
			t.Fatal("current selected Policy did not round trip", err)
		}
		tampered := report
		tampered.PolicyID = ""
		if tampered.Verify(public) == nil {
			t.Fatal("selected Policy was outside signature")
		}
	}
	legacy := report
	legacy.PolicyID = ""
	legacy.Preference = &ReportPreference{Mode: "auto"}
	if _, err := SignDeviceReport(legacy, key); err == nil {
		t.Fatal("current writer issued a historical routing mode")
	}
	for _, invalid := range []string{`null`, `{}`, `{"mode":"unknown"}`, `{"mode":"auto","exit":"demo-exit"}`, `{"mode":"direct","exit":""}`, `{"mode":"fixed_exit"}`, `{"exit":"direct","mode":"fixed_exit"}`, `{"exit":"auto","mode":"fixed_exit"}`, `{"mode":"auto","unknown":true}`} {
		body := bytes.Replace(before, []byte(`"report_sequence"`), []byte(`"preference":`+invalid+`,"report_sequence"`), 1)
		if decodeStoredReport(body, &decoded) == nil {
			t.Fatal("noncanonical or invalid preference accepted", invalid)
		}
	}
}

func TestCurrentReportSignsIndependentLANSelections(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := ReleaseDigest([]byte("demo-report-view"))
	for _, test := range []struct {
		name   string
		change func(*DeviceReport)
		valid  bool
	}{
		{name: "LAN only", valid: true},
		{name: "Internet and LAN", valid: true, change: func(report *DeviceReport) {
			report.PolicyID = "demo-web-policy"
			report.Selections = append(report.Selections, ReportSelection{ServiceID: "demo-web", PolicyID: report.PolicyID, CandidateID: digest})
		}},
		{name: "Internet confirmed with LAN intent unconfirmed", valid: true, change: func(report *DeviceReport) {
			report.PolicyID = "demo-web-policy"
			report.Selections = []ReportSelection{{ServiceID: "demo-web", PolicyID: report.PolicyID, CandidateID: digest}}
		}},
		{name: "partial Android execution keeps both intents without whole application proof", valid: true, change: func(report *DeviceReport) {
			report.PolicyID = "demo-web-policy"
			report.Selections = []ReportSelection{}
			report.Runtime = RuntimeReadback{State: "unknown", PermissionViewDigest: digest}
		}},
		{name: "unknown without a choice", valid: true, change: func(report *DeviceReport) {
			report.LANPolicyIDs = nil
			report.Selections = []ReportSelection{}
			report.Runtime = RuntimeReadback{State: "unknown"}
		}},
		{name: "unbound selection with unrelated LAN choice", change: func(report *DeviceReport) {
			report.Selections[0].ServiceID = "demo-unbound"
			report.Selections[0].PolicyID = ""
		}},
		{name: "different LAN policy", change: func(report *DeviceReport) {
			report.Selections[0].PolicyID = "demo-other-policy"
		}},
		{name: "historical policy choices", change: func(report *DeviceReport) {
			report.LANPolicyIDs = nil
			report.Selections = []ReportSelection{}
			report.PolicyChoices = &[]PolicyChoice{{ServiceID: "demo-lan", PolicyID: "demo-lan-policy"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ReportSequence: 1,
				ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1,
				LANPolicyIDs: map[string]string{"demo-lan": "demo-lan-policy"},
				Selections:   []ReportSelection{{ServiceID: "demo-lan", PolicyID: "demo-lan-policy", CandidateID: digest}},
				Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
			if test.change != nil {
				test.change(&report)
			}
			before, err := CanonicalEncode(report.unsigned())
			if err != nil {
				t.Fatal(err)
			}
			signed, err := SignDeviceReport(report, key)
			if (err == nil) != test.valid {
				t.Fatal("current report signing accepted or rejected the wrong intent binding", err)
			}
			if !test.valid {
				return
			}
			after, err := CanonicalEncode(signed.unsigned())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("signing changed the report's current intent or actual selection", err)
			}
			body, err := CanonicalEncode(signed)
			var restored DeviceReport
			if err != nil || decodeStoredReport(body, &restored) != nil || !reflect.DeepEqual(restored, signed) || restored.Verify(public) != nil {
				t.Fatal("signed current intent and actual selection did not round trip", err)
			}
			if signed.LANPolicyIDs != nil {
				tampered := signed
				tampered.LANPolicyIDs = map[string]string{}
				for service, policy := range signed.LANPolicyIDs {
					tampered.LANPolicyIDs[service] = policy
				}
				tampered.LANPolicyIDs["demo-extra-lan"] = "demo-extra-lan-policy"
				if tampered.Validate() != nil || tampered.Verify(public) == nil {
					t.Fatal("canonical LAN intent was outside the report signature")
				}
			}
		})
	}
}

func TestReportedPolicyChoiceRemainsSeparateFromSelectionAndSurvivesRestart(t *testing.T) {
	fixture, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	report := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1,
		PolicyID:     "demo-policy",
		Selections:   []ReportSelection{{ServiceID: testDeviceExecution(view).Routes[0].ServiceID, PolicyID: testDeviceExecution(view).Routes[0].PolicyID, CandidateID: testDeviceExecution(view).Routes[0].ID}},
		Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	report, err = SignDeviceReport(report, fixture.keys[0])
	if err != nil || verifyCurrentReport(report, projection) != nil {
		t.Fatal("intent was confused with actual selection or authorization", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, []DeviceReport{report}, view.DevicePublicKey)
	original := testObservationBytes(t, root)
	for i := 0; i < 2; i++ {
		store, err := testOpenObservationStore(t, root)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := WebSnapshot{Devices: []Device{{ID: view.DeviceID}}, Paths: projectWebPathsUsing(projection, func(id string) (DeviceView, error) { return ProjectDeviceView(projection, id) }, report)}
		testProjectWebObservations(&snapshot, store.Verified(projection), time.UnixMilli(report.ReportedAt))
		if snapshot.Devices[0].Evidence == nil || snapshot.Devices[0].Evidence.PolicyID != report.PolicyID || !snapshot.Paths[0].Selected || snapshot.Paths[0].FinalExit != "direct" {
			t.Fatal("readback replaced actual Direct or lost pending policy intent")
		}
		if !bytes.Equal(original, testObservationBytes(t, store)) {
			t.Fatal("restart modified the original signed setting sample")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	view.Responsibilities = []string{"control"}
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("server-only report invented an access setting")
	}
	projection.NetworkIntent.Services[0].Name = "Demo changed service"
	store, _ := testOpenObservationStore(t, root)
	if len(store.Verified(projection)) != 0 {
		t.Fatal("old View preference survived a scope change")
	}
}
