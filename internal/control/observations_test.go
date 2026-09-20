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

func TestObservationMergeConvergesAndIgnoresReplay(t *testing.T) {
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
	if merged, err := store.Merge([]DeviceReport{first}, projection); err != nil || merged != 0 {
		t.Fatalf("merge replay: merged=%d err=%v", merged, err)
	}
	if got := store.All(); len(got) != 1 || got[0].ReportedAt != second.ReportedAt {
		t.Fatalf("replay replaced latest report: %+v", got)
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
	body, _ := canonical([]DeviceReport{report})

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
