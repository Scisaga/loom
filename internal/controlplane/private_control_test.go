package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/wire"
)

type privateControlFixture struct {
	service       *PrivateControlService
	request       privateControlOperationRequestV1
	peer          *x509.Certificate
	committed     *int
	invalidResult *bool
	read          ControlAuthorityReader
	commit        ControlOperationCommitter
	schemas       wire.OperationSchemaRegistry
	now           time.Time
}

func TestPrivateControlServiceReturnsOnlyCertifiedIncludedOperation(t *testing.T) {
	fixture := newPrivateControlFixture(t)
	response := servePrivateControl(t, fixture, fixture.request, true, "10.40.0.2:7444")
	if response.Code != http.StatusOK || *fixture.committed != 1 {
		t.Fatalf("private control response=%d body=%s commits=%d", response.Code, response.Body.String(), *fixture.committed)
	}
	canonical, err := wire.CanonicalizeStrict(response.Body.Bytes())
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
		t.Fatalf("response 不是 exact canonical JSON: %v", err)
	}
	var result privateControlOperationResponseV1
	if _, err := wire.DecodeStrict(response.Body.Bytes(), 4<<20, &result); err != nil ||
		result.Status != "certified" || result.RequestID != fixture.request.RequestID ||
		result.OperationLeaf.OperationID != fixture.request.Operation.Body.OperationID {
		t.Fatalf("certified response 未绑定 request/operation: %#v err=%v", result, err)
	}
}

func TestPrivateControlServiceRejectsPublicOrStaleRequestsBeforeCommit(t *testing.T) {
	fixture := newPrivateControlFixture(t)
	public := servePrivateControl(t, fixture, fixture.request, true, "203.0.113.9:7444")
	if public.Code != http.StatusForbidden || *fixture.committed != 0 {
		t.Fatalf("public listener reached committer: status=%d commits=%d", public.Code, *fixture.committed)
	}
	stale := fixture.request
	stale.ExpectedHeadHash = wire.HashRaw("private-control-test", []byte("stale"))
	response := servePrivateControl(t, fixture, stale, true, "10.40.0.2:7444")
	if response.Code != http.StatusConflict || *fixture.committed != 0 {
		t.Fatalf("stale request reached committer: status=%d commits=%d", response.Code, *fixture.committed)
	}
	withoutTLS := servePrivateControl(t, fixture, fixture.request, false, "10.40.0.2:7444")
	if withoutTLS.Code != http.StatusForbidden || *fixture.committed != 0 {
		t.Fatalf("non-mTLS request reached committer: status=%d commits=%d", withoutTLS.Code, *fixture.committed)
	}
}

func TestPrivateControlServiceDoesNotReportUncertifiedCommitterResult(t *testing.T) {
	fixture := newPrivateControlFixture(t)
	*fixture.invalidResult = true
	response := servePrivateControl(t, fixture, fixture.request, true, "10.40.0.2:7444")
	if response.Code != http.StatusInternalServerError || *fixture.committed != 1 {
		t.Fatalf("invalid result response=%d commits=%d", response.Code, *fixture.committed)
	}
}

func servePrivateControl(t *testing.T, fixture privateControlFixture, submitted privateControlOperationRequestV1,
	withTLS bool, localAddress string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := wire.MarshalCanonical(submitted)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://10.40.0.2:7444"+PrivateControlOperationPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, stringAddress(localAddress)))
	if withTLS {
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{fixture.peer}}
	}
	response := httptest.NewRecorder()
	fixture.service.ServeHTTP(response, request)
	return response
}

type stringAddress string

func (address stringAddress) Network() string { return "tcp" }
func (address stringAddress) String() string  { return string(address) }

func newPrivateControlFixture(t *testing.T) privateControlFixture {
	t.Helper()
	return newPrivateControlFixtureForOperation(t, "create_invite", 2,
		wire.HashRaw("private-control-test", []byte("invite-payload")),
		wire.AdminResourceScopeV1{ScopeKind: "cluster", Cluster: &struct{}{}})
}

func newPrivateControlFixtureForOperation(t *testing.T, kind string, payloadSchema int64,
	payloadHash string, scope wire.AdminResourceScopeV1) privateControlFixture {
	t.Helper()
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	set, configKeys := testControlSet(t, 1)
	profile, authorization, adminKey, peer := privateAdminFixture(t, now)
	authorization.AllowedOperationKinds = []string{kind}
	authorization.Scopes = []wire.AdminResourceScopeV1{scope}
	profiles := map[string]wire.AdminCertificateProfileV1{profile.ProfileID: profile}
	authorizations := []wire.AdminAuthorizationV1{authorization}
	aclRoot, err := wire.AdminACLRoot(authorizations, profiles)
	if err != nil {
		t.Fatal(err)
	}
	base := testControlHead(t, &set)
	body := base.Body
	body.Payload.AdminACLRoot = aclRoot
	base, err = wire.NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	member := set.Members[0]
	baseSignature, err := wire.SignHeadAttestation(wire.AttestationForHead(&base), member, configKeys[member.MemberID])
	if err != nil {
		t.Fatal(err)
	}
	baseQC, err := wire.MarshalCanonical(wire.StableQC(&base, []wire.ControlConfigSignatureV1{baseSignature}))
	if err != nil {
		t.Fatal(err)
	}
	operationBody := wire.ControlOperationBodyV1{
		Schema: 1, ClusterID: set.ClusterID, OperationID: "operation-private-1", AuthorID: authorization.AdminID,
		AdminCertDigest: authorization.AdminCertificateDigest, CreatedAt: "2026-09-11T11:59:00Z",
		ExpiresAt: "2026-09-11T12:05:00Z", BaseRecoveryEpoch: base.Body.Payload.RecoveryEpoch,
		BaseRecoveryStatementHash: base.Body.Payload.RecoveryStatementHash,
		BaseRecoveryPolicyHash:    base.Body.Payload.RecoveryPolicyHash, BaseControlEpoch: base.Body.Payload.ControlEpoch,
		BaseControlSetHash: base.Body.Payload.ControlSetHash, BaseControlRevision: base.Body.Payload.ControlRevision,
		ParentHeadHash: base.HeadHash, Kind: kind, PayloadSchema: payloadSchema,
		PayloadHash: payloadHash, Reason: "test private control operation",
	}
	schemas := wire.OperationSchemaRegistry{kind: payloadSchema}
	operation, err := wire.NewControlOperation(operationBody, adminKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	committed := 0
	invalidResult := false
	read := func(context.Context) (ControlAuthoritySnapshotV1, error) {
		return ControlAuthoritySnapshotV1{Head: base, ConfigQC: baseQC, ControlSet: set,
			Authorizations: authorizations, Profiles: profiles}, nil
	}
	commit := func(_ context.Context, verified wire.VerifiedAdminOperationV1) (CertifiedControlOperationV1, error) {
		committed++
		if !wire.EqualCanonical(verified.Operation(), operation) || verified.HeadHash() != base.HeadHash {
			t.Fatal("committer 未收到 exact opaque verified operation")
		}
		if invalidResult {
			return CertifiedControlOperationV1{Schema: 1, Status: "certified", Head: base}, nil
		}
		objectID, objectErr := wire.ControlOperationObjectID(&operation, peer.RawSubjectPublicKeyInfo, now, schemas)
		if objectErr != nil {
			t.Fatal(objectErr)
		}
		leaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: operation.Body.OperationID, ObjectID: objectID}
		root, rootErr := wire.ControlOperationRoot([]wire.ControlOperationLeafV1{leaf})
		if rootErr != nil {
			t.Fatal(rootErr)
		}
		nextBody := base.Body
		nextBody.Payload.HeadKind = "ordinary"
		nextBody.Payload.RaftIndex++
		nextBody.Payload.ControlRevision = nextBody.Payload.RaftIndex
		nextBody.Payload.PreviousLogEntryHash = base.EntryHash
		nextBody.Payload.ParentHeadHash = base.HeadHash
		nextBody.Payload.OperationRoot = root
		nextBody.Payload.CommittedLogicalTime = "2026-09-11T12:00:01Z"
		nextBody.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
		nextHead, nextErr := wire.NewHeadEntry(nextBody)
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		signature, signErr := wire.SignHeadAttestation(wire.AttestationForHead(&nextHead), member, configKeys[member.MemberID])
		if signErr != nil {
			t.Fatal(signErr)
		}
		qc, marshalErr := wire.MarshalCanonical(wire.StableQC(&nextHead, []wire.ControlConfigSignatureV1{signature}))
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return CertifiedControlOperationV1{Schema: 1, Status: "certified", Head: nextHead, ConfigQC: qc,
			OperationLeaf: leaf, OperationLeafIndex: 0, OperationTreeSize: 1, OperationAuditPath: []string{}}, nil
	}
	service, err := NewPrivateControlService("10.40.0.2", 7444, read,
		func(_ context.Context, submitted wire.ControlOperationV1) (wire.AdminResourceScopeV1, error) {
			if !wire.EqualCanonical(submitted, operation) {
				return wire.AdminResourceScopeV1{}, context.Canceled
			}
			return scope, nil
		},
		commit, schemas, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return privateControlFixture{
		service: service,
		request: privateControlOperationRequestV1{Schema: 1, ExpectedHeadHash: base.HeadHash,
			RequestID: operation.Body.OperationID, Operation: operation},
		peer: peer, committed: &committed, invalidResult: &invalidResult,
		read: read, commit: commit, schemas: schemas, now: now,
	}
}

func privateAdminFixture(t *testing.T, now time.Time) (wire.AdminCertificateProfileV1,
	wire.AdminAuthorizationV1, ed25519.PrivateKey, *x509.Certificate) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	policy, err := x509.OIDFromASN1OID(policyOID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "admin-1"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []x509.OID{policy},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, adminPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerChain := []string{base64.RawURLEncoding.EncodeToString(rootDER)}
	issuerHash, err := wire.HashObject(wire.DomainAdminIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: issuerChain})
	if err != nil {
		t.Fatal(err)
	}
	profile := wire.AdminCertificateProfileV1{
		Schema: 1, ClusterID: "cluster", ProfileID: "admin-profile-1", Generation: 1,
		IssuerChainDER: issuerChain, AdminIssuerChainHash: issuerHash, SubjectKeyAlgorithm: "ed25519",
		OperationSignatureAlgorithm: "ed25519", RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"},
		RequiredPolicyOIDs: []string{policyOID.String()}, MaximumValiditySeconds: 90000,
	}
	profileHash, err := wire.AdminCertificateProfileHash(&profile)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := wire.AdminCertificateDigest(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := wire.AdminKeyID(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	authorization := wire.AdminAuthorizationV1{
		Schema: 1, ClusterID: "cluster", AuthorizationID: "admin-authorization-1", Generation: 1,
		AdminID: "admin-1", AdminCertificateDER: base64.RawURLEncoding.EncodeToString(leafDER),
		AdminCertificateDigest: digest, AdminKeyID: keyID,
		CertificateProfileRef: wire.AdminCertificateProfileRefV1{ProfileID: profile.ProfileID, Generation: 1,
			AdminCertificateProfileHash: profileHash},
		NotBefore: "2026-09-11T11:59:00Z", NotAfter: "2026-09-12T12:00:00Z", Status: "active",
		AllowedOperationKinds: []string{"create_invite"}, Capabilities: []string{},
		Scopes: []wire.AdminResourceScopeV1{{ScopeKind: "cluster", Cluster: &struct{}{}}},
	}
	return profile, authorization, adminPrivate, leaf
}

var _ net.Addr = stringAddress("")
