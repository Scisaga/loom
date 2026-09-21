package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testObservationProjection(t *testing.T) (Projection, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	projection := Projection{Schema: 1,
		EndpointGenerations: []EndpointGeneration{{Schema: 1, EndpointID: "demo-entry", Generation: 1,
			Node: "demo-node", Transport: "tls_tunnel", Listen: "192.0.2.10:443", Address: "192.0.2.10:443",
			ServerName: "demo-entry", TLSCertificateFile: "/demo/cert", TLSPrivateKeyFile: "/demo/key",
			SPKISHA256: strings.Repeat("0", 64), State: "serving"}},
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 1, DeviceID: "demo-device", Name: "demo-device",
			Platform: "linux", Roles: []string{"access"}, DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), Floor: 1}},
	}
	if _, found := projectDeviceView(projection, "demo-device"); !found {
		t.Fatal("test device view is unavailable")
	}
	return projection, private
}

func testSignedObservationReport(t *testing.T, projection Projection, private ed25519.PrivateKey, reportedAt time.Time) DeviceReport {
	t.Helper()
	view, _ := projectDeviceView(projection, "demo-device")
	digest, err := DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 1, DeviceID: "demo-device", ViewDigest: digest,
		ReportedAt: reportedAt.UTC().Format(time.RFC3339), Observations: []Observation{}}, private)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestObservationMergeConvergesAndRetainsSignedHistory(t *testing.T) {
	projection, private := testObservationProjection(t)
	root := t.TempDir()
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	first := testSignedObservationReport(t, projection, private, time.Unix(100, 0))
	second := testSignedObservationReport(t, projection, private, time.Unix(200, 0))
	if merged, err := store.Merge([]DeviceReport{second}, projection); err != nil || merged != 1 {
		t.Fatalf("merge latest: merged=%d err=%v", merged, err)
	}
	if merged, err := store.Merge([]DeviceReport{first}, projection); err != nil || merged != 1 {
		t.Fatalf("merge older signed record: merged=%d err=%v", merged, err)
	}
	if got := store.All(); len(got) != 1 || got[0].ReportedAt != second.ReportedAt {
		t.Fatalf("replay replaced latest report: %+v", got)
	}
	if ids := store.IDs(); len(ids) != 2 || ids[0] >= ids[1] {
		t.Fatalf("signed history was not content-addressed: %+v", ids)
	}
	firstPage, next, err := store.IDPage("", 1)
	if err != nil || len(firstPage) != 1 || next != firstPage[0] {
		t.Fatalf("first content-ID page is invalid: ids=%v next=%q err=%v", firstPage, next, err)
	}
	secondPage, next, err := store.IDPage(next, 1)
	if err != nil || len(secondPage) != 1 || next != "" || secondPage[0] <= firstPage[0] {
		t.Fatalf("second content-ID page is invalid: ids=%v next=%q err=%v", secondPage, next, err)
	}
	records, err := store.MissingRecords(firstPage, projection)
	if err != nil || len(records) != 1 || records[0].ContentID != secondPage[0] {
		t.Fatalf("content-ID delta is invalid: records=%v err=%v", records, err)
	}
	reopened, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.All(); len(got) != 1 || got[0].ReportedAt != second.ReportedAt {
		t.Fatalf("restart lost latest report: reports=%+v", got)
	}
}

func TestObservationProjectionRejectsStaleDeviceView(t *testing.T) {
	projection, private := testObservationProjection(t)
	store, err := OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report := testSignedObservationReport(t, projection, private, time.Unix(100, 0))
	if err := store.Put(report, projection.DeviceAuthorizations[0].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	projection.DeviceAuthorizations[0].Floor++
	if got := store.Verified(projection); len(got) != 0 {
		t.Fatalf("stale device-view report remained visible: %+v", got)
	}
	if merged, err := store.Merge([]DeviceReport{report}, projection); err == nil || merged != 0 {
		t.Fatalf("stale device-view report merged: merged=%d err=%v", merged, err)
	}
}

func TestHistoricalReportContentSyncDoesNotMakeOldViewCurrent(t *testing.T) {
	oldProjection, private := testObservationProjection(t)
	report := testSignedObservationReport(t, oldProjection, private, time.Unix(100, 0))
	source, err := OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Put(report, oldProjection.DeviceAuthorizations[0].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	history := currentReportAuthorities(oldProjection)
	currentProjection := oldProjection
	currentProjection.DeviceAuthorizations[0].Floor++
	for key, value := range currentReportAuthorities(currentProjection) {
		history[key] = value
	}
	records, err := source.missingRecords(nil, history)
	if err != nil || len(records) != 1 {
		t.Fatalf("historical delta=%+v err=%v", records, err)
	}
	receiver, err := OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if merged, err := receiver.mergeRecords(records, history); err != nil || merged != 1 {
		t.Fatalf("historical merge=%d err=%v", merged, err)
	}
	if len(receiver.IDs()) != 1 || len(receiver.Verified(currentProjection)) != 0 {
		t.Fatalf("historical content changed current truth: ids=%v current=%+v", receiver.IDs(), receiver.Verified(currentProjection))
	}
}

func TestTrafficProjectionCountsSenderTXWithoutAddingPeerRX(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	intent := testNetworkIntent(t)
	intent.Nodes = append([]NetworkNode{{ID: "demo-device", Name: "Demo device", Platform: "linux", Roles: []string{"access"}}}, intent.Nodes...)
	intent.Links = []NetworkLink{{ID: "demo-link", From: "demo-device", To: "demo-egress", Transport: "wireguard",
		FromAddress: "10.0.0.1/32", ToAddress: "10.0.0.2/32", ListenPort: 51820,
		ProbeTargets: []NetworkLinkProbeTarget{{Reporter: "demo-device", Target: "10.0.0.2"},
			{Reporter: "demo-egress", Target: "10.0.0.1"}}}}
	runtimeKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		EndpointGenerations: []EndpointGeneration{{Schema: 1, EndpointID: "demo-entry", Generation: 1,
			Node: "demo-egress", Transport: "tls_tunnel", Listen: "192.0.2.10:443", Address: "192.0.2.10:443",
			ServerName: "demo-entry", SPKISHA256: strings.Repeat("0", 64), State: "serving"}},
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "demo-device", DestinationGrants: []string{"demo-policy"},
			DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), RuntimeKey: runtimeKey, Floor: 1}}}
	view, found := projectDeviceView(projection, "demo-device")
	if !found {
		t.Fatal("schema-2 device view was not projected")
	}
	digest, _ := DeviceViewDigest(view)
	makeReport := func(at time.Time, rx, tx uint64) DeviceReport {
		report, err := SignDeviceReport(DeviceReport{Schema: 2, DeviceID: "demo-device", ViewDigest: digest,
			ReportedAt: at.Format(time.RFC3339), Runtime: &RuntimeReadback{State: "running", AppliedViewDigest: digest, Exact: true},
			Selections: []ReportSelection{{Scope: "policy:demo-policy", CandidateID: "route:demo-policy:direct"}},
			Links: []LinkReadback{{LinkID: "demo-link", Peer: "demo-egress", Interface: "wg-demo-egress", Epoch: "boot-a",
				ProbeTarget: "10.0.0.2", Result: "available", RXBytes: rx, TXBytes: tx}}}, private)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	store, err := OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if merged, err := store.Merge([]DeviceReport{makeReport(start, 100, 200)}, projection); err != nil || merged != 1 {
		t.Fatalf("merge first=%d err=%v", merged, err)
	}
	if merged, err := store.Merge([]DeviceReport{makeReport(start.Add(time.Minute), 170, 250)}, projection); err != nil || merged != 1 {
		t.Fatalf("merge second=%d err=%v", merged, err)
	}
	buckets := store.projectTraffic(projection, start.Add(2*time.Minute))
	if len(buckets) != 1 || buckets[0].RXBytes != 70 || buckets[0].TXBytes != 50 || buckets[0].ForwardBytes != 50 {
		t.Fatalf("traffic buckets=%+v", buckets)
	}
}

func TestSchema2PathWaitsForEveryServerToConsumeExactView(t *testing.T) {
	accessPublic, accessPrivate, _ := ed25519.GenerateKey(rand.Reader)
	serverPublic, serverPrivate, _ := ed25519.GenerateKey(rand.Reader)
	intent := testNetworkIntent(t)
	intent.Nodes = append([]NetworkNode{{ID: "d-0123456789", Name: "Demo access", Platform: "linux", Roles: []string{"access"}}}, intent.Nodes...)
	projection := Projection{Schema: 1, NetworkIntent: &intent, Web: WebProjection{Schema: 1},
		Enrollments: []EnrollmentTransaction{{Schema: 2, ID: "demo-transaction", State: "completed",
			Intent: EnrollmentIntent{Schema: 2, DeviceID: "d-0123456789", Name: "Demo access", Platform: "linux",
				Roles: []string{"access"}, DestinationGrants: []string{"demo-policy"}}}},
		EndpointGenerations: []EndpointGeneration{{Schema: 1, EndpointID: "demo-entry", Generation: 1,
			Node: "demo-egress", Transport: "tls_tunnel", Listen: "192.0.2.10:443", Address: "192.0.2.10:443",
			ServerName: "demo-entry", SPKISHA256: strings.Repeat("0", 64), State: "serving"}},
		DeviceAuthorizations: []DeviceAuthorization{
			{Schema: 2, DeviceID: "d-0123456789", DestinationGrants: []string{"demo-policy"}, DevicePublicKey: base64.RawURLEncoding.EncodeToString(accessPublic),
				RuntimeKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Floor: 1},
			{Schema: 2, DeviceID: "demo-egress",
				DevicePublicKey: base64.RawURLEncoding.EncodeToString(serverPublic), RuntimeKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				Floor: 1},
		}}
	projectNetworkWeb(&projection)
	projectEnrollmentWeb(&projection)
	accessView, accessFound := projectDeviceView(projection, "d-0123456789")
	serverView, serverFound := projectDeviceView(projection, "demo-egress")
	if !accessFound || !serverFound {
		t.Fatalf("schema-2 views were not projected: access=%t server=%t", accessFound, serverFound)
	}
	accessDigest, accessDigestErr := DeviceViewDigest(accessView)
	serverDigest, serverDigestErr := DeviceViewDigest(serverView)
	if accessDigestErr != nil || serverDigestErr != nil {
		serverRuntimeErr := error(nil)
		if serverView.ServerRuntime != nil {
			serverRuntimeErr = serverView.ServerRuntime.Validate()
		}
		t.Fatalf("schema-2 view digests failed: access=%v server=%v authorization=%v runtime=%v view=%+v",
			accessDigestErr, serverDigestErr, projection.DeviceAuthorizations[1].Validate(), serverRuntimeErr, serverView)
	}
	now := time.Date(2030, 1, 1, 0, 2, 0, 0, time.UTC)
	accessReport, err := SignDeviceReport(DeviceReport{Schema: 2, DeviceID: "d-0123456789", ViewDigest: accessDigest,
		ReportedAt: now.Add(-time.Minute).Format(time.RFC3339),
		Runtime:    &RuntimeReadback{State: "running", AppliedViewDigest: accessDigest, Exact: true},
		Selections: []ReportSelection{{Scope: "policy:demo-policy", CandidateID: "route:demo-policy:demo-egress"}},
		Observations: []Observation{{CandidateID: "route:demo-policy:demo-egress", NetworkGeneration: "network-a",
			Scope: "policy:demo-policy", Result: "available", Action: "business-probe",
			ObservedAt: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}}, accessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(accessReport, projection.DeviceAuthorizations[0].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	web := projection.Web
	store.Project(&web, projection, now)
	projectEnrollmentReadiness(&web, projection, store.Verified(projection), now)
	if web.Devices[0].Availability != "unknown" {
		t.Fatalf("access became ready before its server consumed the exact view: %+v", web.Devices[0])
	}
	if web.Devices[0].EnrollmentReadiness != "awaiting_deployment" ||
		len(web.Devices[0].WaitingFor) != 1 || web.Devices[0].WaitingFor[0] != "demo-egress" {
		t.Fatalf("enrollment readiness did not name the missing exact server: %+v", web.Devices[0])
	}
	serverReport, err := SignDeviceReport(DeviceReport{Schema: 2, DeviceID: "demo-egress", ViewDigest: serverDigest,
		ReportedAt: now.Add(-30 * time.Second).Format(time.RFC3339),
		Runtime:    &RuntimeReadback{State: "running", AppliedViewDigest: serverDigest, Exact: true}}, serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(serverReport, projection.DeviceAuthorizations[1].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	web = projection.Web
	store.Project(&web, projection, now)
	projectEnrollmentReadiness(&web, projection, store.Verified(projection), now)
	if web.Devices[0].Availability != "available" {
		t.Fatalf("access did not become available after exact server readback: %+v", web.Devices[0])
	}
	if web.Devices[0].EnrollmentReadiness != "ready" || len(web.Devices[0].WaitingFor) != 0 {
		t.Fatalf("enrollment did not become ready after all exact readbacks: %+v", web.Devices[0])
	}
}

func TestInternalReportsRequireMemberSignature(t *testing.T) {
	projection, private := testObservationProjection(t)
	memberPublic, memberPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member := Member{ID: "demo-control", Node: "demo-node", PublicKey: base64.RawURLEncoding.EncodeToString(memberPublic)}
	projection.Config = ControlConfig{Mode: "stable", Members: []Member{member}, Quorum: 1}
	authority := &Authority{projection: projection, certified: CertifiedState{Projection: projection}}
	config := NodeConfig{MemberID: member.ID, IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(memberPrivate)}
	server := &Server{Runtime: &Runtime{Authority: authority, Config: config}, Config: config}
	server.Reports, err = OpenObservationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report := testSignedObservationReport(t, projection, private, time.Unix(100, 0))
	id, _ := deviceReportID(report)
	body, _ := canonical([]reportRecord{{ContentID: id, Report: report}})

	unsigned := httptest.NewRequest(http.MethodPut, "/internal/reports", bytes.NewReader(body))
	unsignedResponse := httptest.NewRecorder()
	server.internalReports(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusForbidden {
		t.Fatalf("unsigned status=%d", unsignedResponse.Code)
	}

	signed := httptest.NewRequest(http.MethodPut, "/internal/reports", bytes.NewReader(body))
	server.Runtime.signRequest(signed, body)
	signedResponse := httptest.NewRecorder()
	server.internalReports(signedResponse, signed)
	if signedResponse.Code != http.StatusOK || len(server.Reports.All()) != 1 {
		t.Fatalf("signed status=%d body=%s reports=%+v", signedResponse.Code, signedResponse.Body.String(), server.Reports.All())
	}
}
