package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"loom/internal/wire"
)

type deviceConfigFixture struct {
	service  *PrivateDeviceConfigService
	leaf     *x509.Certificate
	envelope wire.DeviceViewEnvelopeV2
	reads    *int
	record   *DeviceIdentityRecordV1
}

func TestPrivateDeviceConfigReturnsOnlyExactMTLSDeviceView(t *testing.T) {
	fixture := newDeviceConfigFixture(t)
	response := serveDeviceConfig(t, fixture, "10.50.0.2:7445", true)
	want, _ := wire.MarshalCanonical(fixture.envelope)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), want) || *fixture.reads != 1 {
		t.Fatalf("device_config status=%d reads=%d body=%s", response.Code, *fixture.reads, response.Body.String())
	}
}

func TestPrivateDeviceConfigRejectsPublicListenerAndUncertifiedIdentity(t *testing.T) {
	fixture := newDeviceConfigFixture(t)
	public := serveDeviceConfig(t, fixture, "203.0.113.20:7445", true)
	if public.Code != http.StatusForbidden || *fixture.reads != 0 {
		t.Fatalf("public listener reached view reader: status=%d reads=%d", public.Code, *fixture.reads)
	}
	withoutTLS := serveDeviceConfig(t, fixture, "10.50.0.2:7445", false)
	if withoutTLS.Code != http.StatusForbidden || *fixture.reads != 0 {
		t.Fatalf("request without Device mTLS reached reader: status=%d reads=%d", withoutTLS.Code, *fixture.reads)
	}
	fixture.record.IdentitySPKIHash = wire.HashRaw("device-config-test", []byte("wrong-identity"))
	wrongIdentity := serveDeviceConfig(t, fixture, "10.50.0.2:7445", true)
	if wrongIdentity.Code != http.StatusForbidden || *fixture.reads != 0 {
		t.Fatalf("wrong registry SPKI reached reader: status=%d reads=%d", wrongIdentity.Code, *fixture.reads)
	}
}

func TestPrivateDeviceConfigDoesNotServeActiveViewToRevocationPendingIdentity(t *testing.T) {
	fixture := newDeviceConfigFixture(t)
	fixture.record.IdentityStatus = "revocation_pending"
	response := serveDeviceConfig(t, fixture, "10.50.0.2:7445", true)
	if response.Code != http.StatusInternalServerError || *fixture.reads != 1 {
		t.Fatalf("revocation-pending active response=%d reads=%d", response.Code, *fixture.reads)
	}
}

func serveDeviceConfig(t *testing.T, fixture deviceConfigFixture, localAddress string, withTLS bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://10.50.0.2:7445"+PrivateDeviceConfigPath, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, stringAddress(localAddress)))
	if withTLS {
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{fixture.leaf}}
	}
	response := httptest.NewRecorder()
	fixture.service.ServeHTTP(response, request)
	return response
}

func newDeviceConfigFixture(t *testing.T) deviceConfigFixture {
	t.Helper()
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	set, configKeys := testControlSet(t, 1)
	leaf, state, ref, identityHash := controlplaneDeviceCertificate(t, set.ClusterID, now)
	certificateHash, _ := wire.DeviceCertificateHash(leaf.Raw)
	record := &DeviceIdentityRecordV1{
		Schema: 1, CertificateHash: certificateHash, DeviceID: "device-1", IdentitySPKIHash: identityHash,
		Platform: "linux-server", Responsibilities: []string{"use_loom"}, ProfileRef: ref, ProfileState: state,
		Issuance:   wire.IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 2},
		ApprovedAt: "2026-09-11T12:00:00Z", IdentityStatus: "active",
	}
	envelope := controlplaneDeviceEnvelope(t, set, configKeys[set.Members[0].MemberID], *record)
	reads := 0
	endpoint := wire.PrivateControlServiceV1{
		ServiceID: "device-config-1", Role: "device_config", OverlayIP: "10.50.0.2", Port: 7445,
		CertificateProfileRef:     "internal-service-profile-1",
		SPKIPins:                  []string{wire.HashRaw("device-config-test", []byte("service-pin"))},
		AuthorizedSubjectProfiles: []string{state.ProfileID},
	}
	service, err := NewPrivateDeviceConfigService(endpoint,
		func(_ context.Context, requestedHash string) (DeviceIdentityAuthorityV1, error) {
			if requestedHash != certificateHash {
				return DeviceIdentityAuthorityV1{}, context.Canceled
			}
			return DeviceIdentityAuthorityV1{
				Record: *record, Head: envelope.SignedCurrent.Head,
				ConfigQC: envelope.SignedCurrent.QuorumCertificate, ControlSet: set,
				DeviceCertificateProfiles: []wire.DeviceCertificateProfileStateV1{record.ProfileState},
			}, nil
		},
		func(_ context.Context, identity VerifiedDeviceIdentityV1) (DeviceConfigMaterialV1, error) {
			reads++
			if identity.DeviceID() != record.DeviceID || identity.CertificateHash() != certificateHash {
				t.Fatal("view reader 收到未绑定 registry record 的 identity")
			}
			return DeviceConfigMaterialV1{Envelope: envelope}, nil
		}, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	return deviceConfigFixture{service: service, leaf: leaf, envelope: envelope, reads: &reads, record: record}
}

func controlplaneDeviceCertificate(t *testing.T, clusterID string, now time.Time) (*x509.Certificate,
	wire.DeviceCertificateProfileStateV1, wire.DeviceCertificateProfileRefV1, string) {
	t.Helper()
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "device root"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(14 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	issuerPublic, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "device issuer"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(issuerDER)
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}
	policy, _ := x509.OIDFromASN1OID(policyOID)
	deviceURI, _ := url.Parse("spiffe://cluster.example/device/device-1")
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(13), Subject: pkix.Name{}, NotBefore: now, NotAfter: now.Add(6 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Policies: []x509.OID{policy}, URIs: []*url.URL{deviceURI},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &identity.PublicKey, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	chain := []string{base64.RawURLEncoding.EncodeToString(issuerDER), base64.RawURLEncoding.EncodeToString(rootDER)}
	issuerHash, _ := wire.HashBytes(wire.DomainDeviceIssuerCertificateDER, issuerDER)
	chainHash, _ := wire.HashObject(wire.DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: chain})
	extensionOrder := make([]string, len(leaf.Extensions))
	for i, extension := range leaf.Extensions {
		extensionOrder[i] = extension.Id.String()
	}
	intent := wire.DeviceCertificateProfileIntentV1{
		Schema: 1, ClusterID: clusterID, ProfileID: "device-profile-1", Generation: 1, TargetStatus: "staged",
		IssuerID: "issuer-1", IssuerGeneration: 1, IssuerFencingEpoch: 1,
		IssuanceNotBefore: "2026-09-11T00:00:00Z", IssuanceNotAfter: "2026-09-12T00:00:00Z",
		ProfileKind: "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash,
		IssuerChainDER: chain, IssuerChainHash: chainHash,
		IssuerKeyArtifactHash: wire.HashRaw("device-config-test", []byte("issuer-key")),
		AllowedPlatforms:      []string{"android", "linux-server"}, AllowedResponsibilities: []string{"use_loom", "forward"},
		ValiditySeconds: 21600, AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519", SubjectMode: "empty",
		SANURIPrefix: "spiffe://cluster.example/device/", KeyUsageBits: []string{"digital_signature"}, BasicConstraintsCA: false,
		RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{policyOID.String()},
		ExtensionOrderOIDs: extensionOrder,
	}
	set, _ := testControlSet(t, 1)
	if set.ClusterID != clusterID {
		t.Fatal("test ControlSet cluster 不一致")
	}
	stagedHead := testControlHead(t, &set)
	staged, err := wire.ReduceDeviceCertificateProfile(nil, intent, &stagedHead, false)
	if err != nil {
		t.Fatal(err)
	}
	stagedHash, _ := wire.DeviceCertificateProfileStateHash(&staged)
	activeIntent := intent
	activeIntent.Generation, activeIntent.ExpectedPreviousProfileStateHash = 2, stagedHash
	activeIntent.TargetStatus, activeIntent.IssuerFencingEpoch = "active", 2
	activeHead := nextOrdinaryHead(t, stagedHead, 1)
	active, err := wire.ReduceDeviceCertificateProfile(&staged, activeIntent, &activeHead, false)
	if err != nil {
		t.Fatal(err)
	}
	intentHash, _ := wire.DeviceCertificateProfileIntentHash(&activeIntent)
	stateHash, _ := wire.DeviceCertificateProfileStateHash(&active)
	ref := wire.DeviceCertificateProfileRefV1{ProfileID: active.ProfileID, Generation: active.Generation,
		DeviceCertificateProfileIntentHash: intentHash, DeviceCertificateProfileStateHash: stateHash}
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, leaf.RawSubjectPublicKeyInfo)
	return leaf, active, ref, identityHash
}

func controlplaneDeviceEnvelope(t *testing.T, set wire.ControlSetV1, configKey ed25519.PrivateKey,
	record DeviceIdentityRecordV1) wire.DeviceViewEnvelopeV2 {
	t.Helper()
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: append([]string(nil), record.Responsibilities...)}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: record.DeviceID,
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	bundleHash, _ := wire.DeviceEndpointBundleHash(&bundle)
	secretRoot, _ := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	payload := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: set.ClusterID, DeviceID: record.DeviceID,
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: record.IdentitySPKIHash, Membership: membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash, Grants: grants, GrantsHash: grantsHash,
			EndpointBundle: bundle, EndpointBundleHash: bundleHash, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{},
			SecretArtifactRefsRoot: secretRoot,
		}}
	payloadHash, _ := wire.DeviceViewHash(&payload)
	leaf := wire.DeviceViewLeafV2{Schema: 2, ClusterID: set.ClusterID, ViewSchemaVersion: 2, DeviceID: record.DeviceID,
		DeviceGeneration: 1, State: "active", PayloadHash: payloadHash, PreviousViewHash: wire.EmptyHashV1,
		EndpointSetHash: bundleHash, MinReaderVersion: 2}
	leafBytes, _ := wire.MarshalCanonical(leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	head := testControlHead(t, &set)
	headBody := head.Body
	headBody.Payload.DeviceViewsRoot = "sha256:" + fmt.Sprintf("%x", root)
	caProfileRoot, err := wire.CAProfileRoot(nil, []wire.DeviceCertificateProfileStateV1{record.ProfileState})
	if err != nil {
		t.Fatal(err)
	}
	headBody.Payload.CAProfileRoot = caProfileRoot
	head, err = wire.NewHeadEntry(headBody)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := wire.SignHeadAttestation(wire.AttestationForHead(&head), set.Members[0], configKey)
	qc, _ := wire.MarshalCanonical(wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature}))
	return wire.DeviceViewEnvelopeV2{Schema: 2, Payload: payload, Leaf: leaf, LeafIndex: 0, TreeSize: 1,
		AuditPath: []string{}, SignedCurrent: wire.SignedCurrentV2{Schema: 2, Head: head,
			QuorumCertificate: qc, PublishedAt: "2026-09-11T12:00:00Z"}, SecretArtifactRefs: []json.RawMessage{}}
}
