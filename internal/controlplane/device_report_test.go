package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/wire"
)

type deviceReportFixture struct {
	service         *PrivateDeviceReportService
	envelope        wire.DeviceReportEnvelopeV2
	leaf            *x509.Certificate
	identity        VerifiedDeviceIdentityV1
	payloadVerified *int
	committed       *int
	sinkError       *error
}

func TestPrivateDeviceReportCommitsOnlyCurrentSignedDeviceReport(t *testing.T) {
	fixture := newDeviceReportFixture(t)
	response := serveDeviceReport(t, fixture, fixture.envelope, "10.50.0.2:7446")
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		*fixture.payloadVerified != 1 || *fixture.committed != 1 {
		t.Fatalf("device_report status=%d body=%q verified=%d commits=%d", response.Code,
			response.Body.String(), *fixture.payloadVerified, *fixture.committed)
	}
}

func TestPrivateDeviceReportRejectsStaleFloorsAndWrongListenerBeforeCommit(t *testing.T) {
	fixture := newDeviceReportFixture(t)
	public := serveDeviceReport(t, fixture, fixture.envelope, "203.0.113.20:7446")
	if public.Code != http.StatusForbidden || *fixture.committed != 0 {
		t.Fatalf("public listener reached sink: status=%d commits=%d", public.Code, *fixture.committed)
	}
	stale := fixture.envelope
	stale.Body.AcceptedFloors.AcceptedControlRevision--
	response := serveDeviceReport(t, fixture, stale, "10.50.0.2:7446")
	if response.Code != http.StatusConflict || *fixture.payloadVerified != 0 || *fixture.committed != 0 {
		t.Fatalf("stale floor reached reader/sink: status=%d verified=%d commits=%d",
			response.Code, *fixture.payloadVerified, *fixture.committed)
	}
}

func TestPrivateDeviceReportMapsAtomicSequenceConflict(t *testing.T) {
	fixture := newDeviceReportFixture(t)
	conflict := error(ErrDeviceReportSequence)
	*fixture.sinkError = conflict
	response := serveDeviceReport(t, fixture, fixture.envelope, "10.50.0.2:7446")
	if response.Code != http.StatusConflict || *fixture.committed != 1 {
		t.Fatalf("sequence conflict status=%d commits=%d", response.Code, *fixture.committed)
	}
}

func TestPrivateDeviceReportAuthenticatesSignatureBeforePayloadReader(t *testing.T) {
	fixture := newDeviceReportFixture(t)
	tampered := fixture.envelope
	tampered.Payload = json.RawMessage(`{"healthy":false,"version":"demo"}`)
	response := serveDeviceReport(t, fixture, tampered, "10.50.0.2:7446")
	if response.Code != http.StatusForbidden || *fixture.payloadVerified != 0 || *fixture.committed != 0 {
		t.Fatalf("未认证 payload 触达 reader/sink: status=%d verified=%d commits=%d",
			response.Code, *fixture.payloadVerified, *fixture.committed)
	}
}

func serveDeviceReport(t *testing.T, fixture deviceReportFixture, envelope wire.DeviceReportEnvelopeV2,
	localAddress string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := wire.MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://10.50.0.2:7446"+PrivateDeviceReportPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, stringAddress(localAddress)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{fixture.leaf}}
	response := httptest.NewRecorder()
	fixture.service.ServeHTTP(response, request)
	return response
}

func newDeviceReportFixture(t *testing.T) deviceReportFixture {
	t.Helper()
	config := newDeviceConfigFixture(t)
	set := config.identitiesSet(t)
	floors, err := wire.VerifyDeviceViewEnvelope(&config.envelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"healthy":true,"version":"demo"}`)
	payloadHash, _ := wire.DeviceReportPayloadHash(payload)
	schemas := wire.DeviceReportSchemaRegistry{"health": 1}
	envelope, err := wire.SignDeviceReport(wire.DeviceReportBodyV2{
		Schema: 2, ClusterID: config.record.ProfileState.ClusterID, DeviceID: config.record.DeviceID,
		ReportID: "report-device-1-1", ReportSequence: 1, GeneratedAt: "2026-09-11T12:01:00Z",
		AcceptedFloors: floors, Kind: "health", PayloadSchema: 1, PayloadHash: payloadHash,
	}, payload, config.identityKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	committed := 0
	payloadVerified := 0
	var sinkError error
	endpoint := wire.PrivateControlServiceV1{
		ServiceID: "device-report-1", Role: "device_report", OverlayIP: "10.50.0.2", Port: 7446,
		CertificateProfileRef:     "internal-service-profile-1",
		SPKIPins:                  []string{wire.HashRaw("device-report-test", []byte("service-pin"))},
		AuthorizedSubjectProfiles: []string{config.record.ProfileState.ProfileID},
	}
	service, err := NewPrivateDeviceReportService(endpoint, config.identities,
		func(kind string, schema int64, payload []byte) error {
			payloadVerified++
			if kind != "health" || schema != 1 {
				return context.Canceled
			}
			var value struct {
				Healthy bool   `json:"healthy"`
				Version string `json:"version"`
			}
			_, err := wire.DecodeStrict(payload, 4096, &value)
			return err
		},
		func(_ context.Context, verified VerifiedDeviceReportV2) error {
			committed++
			if verified.DeviceID() != config.record.DeviceID || verified.Body().ReportSequence != 1 ||
				!bytes.Equal(verified.Payload(), payload) {
				t.Fatal("sink 未收到 exact opaque verified report")
			}
			return sinkError
		}, schemas, func() time.Time { return time.Date(2026, 9, 11, 12, 1, 10, 0, time.UTC) },
		5*time.Minute, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticateDeviceIdentity(context.Background(), config.leaf.Raw,
		time.Date(2026, 9, 11, 12, 1, 10, 0, time.UTC), []string{config.record.ProfileRef.ProfileID}, config.identities)
	if err != nil {
		t.Fatal(err)
	}
	return deviceReportFixture{service: service, envelope: envelope, leaf: config.leaf, identity: identity,
		payloadVerified: &payloadVerified, committed: &committed, sinkError: &sinkError}
}

func (fixture deviceConfigFixture) identitiesSet(t *testing.T) wire.ControlSetV1 {
	t.Helper()
	certificateHash, _ := wire.DeviceCertificateHash(fixture.leaf.Raw)
	authority, err := fixture.identities(context.Background(), certificateHash)
	if err != nil {
		t.Fatal(err)
	}
	return authority.ControlSet
}
