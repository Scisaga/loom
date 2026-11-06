package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebReadbackKeepsSamplesOmittedByLaterSignedReports(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join failed", response.Code)
	}
	projection := server.Runtime.Authority.Snapshot()
	service := projection.NetworkIntent.Services[0]
	service.ProbeURLs = []string{"https://demo-service.example/health"}
	target, _ := projection.CurrentTarget("service", service.ID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-update-probe-urls", Operation: "service.put", TargetKind: "service", TargetID: service.ID, Dependencies: target.MaterialIDs, Payload: service})
	envelope, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(testDeviceExecution(envelope.View).Routes) != 1 {
		t.Fatal("current route unavailable", err)
	}
	route := testDeviceExecution(envelope.View).Routes[0]
	at := server.now()
	sample := Observation{Level: "service", ServiceID: service.ID, CandidateID: route.ID, SpecDigest: route.SpecDigest, Target: service.ProbeURLs[0], Action: "https_request",
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(10 * time.Minute).UnixMilli(), DurationMS: new(int64(5))}
	report := DeviceReport{Schema: 3, NetworkID: envelope.NetworkID, DeviceID: invite.DeviceID, ViewDigest: envelope.ViewDigest, ReportSequence: 1,
		NetworkGeneration: sample.NetworkGeneration, ReportedAt: at.UnixMilli(), PolicyID: route.PolicyID, Selections: []ReportSelection{{ServiceID: service.ID, PolicyID: route.PolicyID, CandidateID: route.ID}},
		Observations: []Observation{sample}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: envelope.ViewDigest}}
	post := func() {
		t.Helper()
		signed, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		if response := enrollmentHTTP(t, server, "/device/report", signed, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
			t.Fatal("formal report rejected", response.Code, response.Body.String())
		}
	}
	post()
	report.ReportSequence++
	report.ReportedAt += 1000
	report.Observations = []Observation{}
	post()
	for _, elapsed := range []time.Duration{2 * time.Second, 4 * time.Minute, 10 * time.Minute} {
		server.Now = func() time.Time { return at.Add(elapsed) }
		snapshot, err := server.snapshotValue(httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, device := range snapshot.Devices {
			if device.ID != invite.DeviceID {
				continue
			}
			found = true
			if device.Evidence == nil || device.Evidence.ReportSequence != 2 {
				t.Fatal("measurement retention restored old runtime metadata")
			}
			if elapsed < 10*time.Minute {
				if len(device.Evidence.Measurements) != 1 || device.Evidence.Measurements[0].ObservedAt != sample.ObservedAt || device.Evidence.Measurements[0].ValidUntil != sample.ValidUntil {
					t.Fatal("metadata-only report erased or renewed a sample")
				}
				if elapsed == 4*time.Minute && (device.RuntimeState != "unknown" || device.Evidence.Freshness != "stale" || device.Evidence.Measurements[0].CurrentUntil > server.now().UnixMilli()) {
					t.Fatal("routing TTL extended the separate Web report display")
				}
			} else if len(device.Evidence.Measurements) != 0 {
				t.Fatal("Web retained an expired sample as current")
			}
		}
		if !found {
			t.Fatal("device disappeared from formal readback")
		}
	}
}
