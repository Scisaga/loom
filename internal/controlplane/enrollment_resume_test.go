package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type enrollmentResumeIssuerFunc func(context.Context, enrollmentv2.ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error)

func (function enrollmentResumeIssuerFunc) Issue(ctx context.Context,
	request enrollmentv2.ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error) {
	return function(ctx, request)
}

func TestPrivateEnrollmentResumeRequiresCertifiedAdminOperation(t *testing.T) {
	authorization := wire.EnrollmentResumeAuthorizationV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", RequestID: "enrollment-request",
		DeviceID: "linux-device", ExpectedTransactionStateHash: wire.HashRaw("resume-control-test", []byte("transaction")),
		ExpiresAt: "2026-09-11T12:10:00Z",
	}
	payloadHash, err := wire.EnrollmentResumeAuthorizationHash(&authorization)
	if err != nil {
		t.Fatal(err)
	}
	scope := wire.AdminResourceScopeV1{ScopeKind: "device",
		Device: &wire.AdminScopeIDsV1{DeviceIDs: []string{authorization.DeviceID}}}
	fixture := newPrivateControlFixtureForOperation(t, "issue_enrollment_resume", 1, payloadHash, scope)
	issued := 0
	var captured enrollmentv2.ResumeIssueRequestV1
	service, err := NewPrivateEnrollmentResumeControlService("10.40.0.2", 7444,
		fixture.read, fixture.commit, fixture.schemas,
		enrollmentResumeIssuerFunc(func(_ context.Context, request enrollmentv2.ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error) {
			issued++
			captured = request
			binding := &wire.BootstrapCapabilityResumeBindingV1{
				RequestID:                      request.RequestID,
				ClaimOperationHash:             wire.HashRaw("resume-control-test", []byte("claim-operation")),
				AdmissionQCHash:                wire.HashRaw("resume-control-test", []byte("admission-qc")),
				ClaimCoreHash:                  wire.HashRaw("resume-control-test", []byte("claim-core")),
				EnrollmentTransactionStateHash: request.ExpectedTransactionStateHash,
			}
			return wire.EnrollmentResumeDescriptorV1{
				Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID, RequestID: request.RequestID,
				ExpiresAt: request.ExpiresAt, EnrollmentTransactionStateHash: request.ExpectedTransactionStateHash,
				ClaimCoreHash: binding.ClaimCoreHash, ClaimOperationHash: binding.ClaimOperationHash,
				AdmissionQCHash: binding.AdmissionQCHash,
				ResumeTunnelCapability: wire.BootstrapTunnelCapabilityV1{Body: wire.BootstrapTunnelCapabilityBodyV1{
					Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID, Mode: "resume_committed_claim",
					ResumeBinding: binding, IssuedAt: request.IssuedAt, NotBefore: request.IssuedAt, ExpiresAt: request.ExpiresAt,
				}},
			}, nil
		}), func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	submitted := privateEnrollmentResumeRequestV1{
		Schema: 1, ExpectedHeadHash: fixture.request.ExpectedHeadHash,
		RequestID: fixture.request.RequestID, Operation: fixture.request.Operation, Authorization: authorization,
	}
	response := servePrivateEnrollmentResume(t, service, fixture.peer, submitted, "10.40.0.2:7444", true)
	if response.Code != http.StatusOK || *fixture.committed != 1 || issued != 1 {
		t.Fatalf("resume response=%d body=%s commits=%d issues=%d",
			response.Code, response.Body.String(), *fixture.committed, issued)
	}
	if captured.OperationID != fixture.request.Operation.Body.OperationID || captured.DeviceID != authorization.DeviceID ||
		captured.IssuedAt != "2026-09-11T12:00:01Z" || captured.ExpiresAt != authorization.ExpiresAt ||
		captured.ExpectedTransactionStateHash != authorization.ExpectedTransactionStateHash {
		t.Fatalf("issuer request 未绑定 certified operation/head/payload: %#v", captured)
	}
	canonical, err := wire.CanonicalizeStrict(response.Body.Bytes())
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("resume response 不是 no-store canonical JSON: %v", err)
	}
	var decoded privateEnrollmentResumeResponseV1
	if _, err := wire.DecodeStrict(response.Body.Bytes(), maximumControlRequestBytes, &decoded); err != nil ||
		decoded.Status != "certified" || decoded.OperationLeaf.OperationID != submitted.RequestID ||
		decoded.Descriptor.EnrollmentTransactionStateHash != authorization.ExpectedTransactionStateHash {
		t.Fatalf("resume response 未同时返回 certification 与 descriptor: %#v err=%v", decoded, err)
	}
}

func TestPrivateEnrollmentResumeRejectsPublicStaleTamperedAndOutOfScope(t *testing.T) {
	authorization := wire.EnrollmentResumeAuthorizationV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", RequestID: "enrollment-request",
		DeviceID: "linux-device", ExpectedTransactionStateHash: wire.HashRaw("resume-control-test", []byte("transaction")),
		ExpiresAt: "2026-09-11T12:10:00Z",
	}
	payloadHash, _ := wire.EnrollmentResumeAuthorizationHash(&authorization)
	for _, test := range []struct {
		name          string
		authorizedFor string
		localAddress  string
		withTLS       bool
		mutate        func(*privateEnrollmentResumeRequestV1)
		wantStatus    int
	}{
		{name: "public listener", authorizedFor: "linux-device", localAddress: "203.0.113.9:7444", withTLS: true, wantStatus: http.StatusForbidden},
		{name: "without mTLS", authorizedFor: "linux-device", localAddress: "10.40.0.2:7444", withTLS: false, wantStatus: http.StatusForbidden},
		{name: "stale head", authorizedFor: "linux-device", localAddress: "10.40.0.2:7444", withTLS: true,
			mutate: func(request *privateEnrollmentResumeRequestV1) {
				request.ExpectedHeadHash = wire.HashRaw("resume-control-test", []byte("stale"))
			}, wantStatus: http.StatusConflict},
		{name: "tampered payload", authorizedFor: "linux-device", localAddress: "10.40.0.2:7444", withTLS: true,
			mutate:     func(request *privateEnrollmentResumeRequestV1) { request.Authorization.RequestID = "different-request" },
			wantStatus: http.StatusBadRequest},
		{name: "device scope", authorizedFor: "different-device", localAddress: "10.40.0.2:7444", withTLS: true,
			wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := wire.AdminResourceScopeV1{ScopeKind: "device",
				Device: &wire.AdminScopeIDsV1{DeviceIDs: []string{test.authorizedFor}}}
			fixture := newPrivateControlFixtureForOperation(t, "issue_enrollment_resume", 1, payloadHash, scope)
			issued := 0
			service, err := NewPrivateEnrollmentResumeControlService("10.40.0.2", 7444,
				fixture.read, fixture.commit, fixture.schemas,
				enrollmentResumeIssuerFunc(func(context.Context, enrollmentv2.ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error) {
					issued++
					return wire.EnrollmentResumeDescriptorV1{}, nil
				}), func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			submitted := privateEnrollmentResumeRequestV1{
				Schema: 1, ExpectedHeadHash: fixture.request.ExpectedHeadHash, RequestID: fixture.request.RequestID,
				Operation: fixture.request.Operation, Authorization: authorization,
			}
			if test.mutate != nil {
				test.mutate(&submitted)
			}
			response := servePrivateEnrollmentResume(t, service, fixture.peer, submitted, test.localAddress, test.withTLS)
			if response.Code != test.wantStatus || *fixture.committed != 0 || issued != 0 {
				t.Fatalf("status=%d commits=%d issues=%d body=%s",
					response.Code, *fixture.committed, issued, response.Body.String())
			}
		})
	}
}

func servePrivateEnrollmentResume(t *testing.T, service *PrivateEnrollmentResumeControlService,
	peer *x509.Certificate, submitted privateEnrollmentResumeRequestV1, localAddress string,
	withTLS bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := wire.MarshalCanonical(submitted)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://10.40.0.2:7444"+PrivateEnrollmentResumePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, stringAddress(localAddress)))
	if withTLS {
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{peer}}
	}
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}
