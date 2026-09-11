package wire

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"
)

type deviceCertificateFixture struct {
	intent       DeviceCertificateProfileIntentV1
	leafDER      []byte
	identityHash string
	issuerKey    ed25519.PrivateKey
	now          time.Time
}

func TestDeviceCertificateProfileReducerAndExactLeafVerification(t *testing.T) {
	fixture := newDeviceCertificateFixture(t)
	member, _ := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	stagedHead := testHead(t, &set)
	staged, err := ReduceDeviceCertificateProfile(nil, fixture.intent, &stagedHead, false)
	if err != nil || staged.Status != "staged" || staged.IssuanceCutoff != nil {
		t.Fatalf("staged state=%#v err=%v", staged, err)
	}
	stagedHash, _ := DeviceCertificateProfileStateHash(&staged)
	activeIntent := fixture.intent
	activeIntent.Generation = 2
	activeIntent.ExpectedPreviousProfileStateHash = stagedHash
	activeIntent.TargetStatus = "active"
	activeIntent.IssuerFencingEpoch = 2
	activeHead := nextDeviceProfileHead(t, stagedHead, "2026-09-11T12:01:00Z")
	active, err := ReduceDeviceCertificateProfile(&staged, activeIntent, &activeHead, false)
	if err != nil || active.Status != "active" {
		t.Fatalf("active state=%#v err=%v", active, err)
	}
	intentHash, _ := DeviceCertificateProfileIntentHash(&activeIntent)
	stateHash, _ := DeviceCertificateProfileStateHash(&active)
	ref := DeviceCertificateProfileRefV1{ProfileID: active.ProfileID, Generation: active.Generation,
		DeviceCertificateProfileIntentHash: intentHash, DeviceCertificateProfileStateHash: stateHash}
	if err := ValidateDeviceCertificateProfileRef(&ref, &active); err != nil {
		t.Fatal(err)
	}
	certificate, err := VerifyDeviceCertificateAt(fixture.leafDER, &active, "device-1", fixture.identityHash,
		"linux-server", []string{"use_loom"}, IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 2},
		fixture.now, fixture.now.Add(time.Minute))
	if err != nil || certificate == nil {
		t.Fatalf("合法 Device certificate 被拒绝: cert=%#v err=%v", certificate, err)
	}
	if _, err := VerifyDeviceCertificateAt(fixture.leafDER, &active, "device-2", fixture.identityHash,
		"linux-server", []string{"use_loom"}, IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 2},
		fixture.now, fixture.now.Add(time.Minute)); err == nil {
		t.Fatal("接受了 SAN 中错误的 Device ID")
	}
}

func TestRetiredDeviceProfileOnlyAcceptsPreCutoffIssuanceAndApproval(t *testing.T) {
	fixture := newDeviceCertificateFixture(t)
	member, _ := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	stagedHead := testHead(t, &set)
	staged, _ := ReduceDeviceCertificateProfile(nil, fixture.intent, &stagedHead, false)
	stagedHash, _ := DeviceCertificateProfileStateHash(&staged)
	activeIntent := fixture.intent
	activeIntent.Generation, activeIntent.ExpectedPreviousProfileStateHash = 2, stagedHash
	activeIntent.TargetStatus, activeIntent.IssuerFencingEpoch = "active", 2
	activeHead := nextDeviceProfileHead(t, stagedHead, "2026-09-11T12:01:00Z")
	active, _ := ReduceDeviceCertificateProfile(&staged, activeIntent, &activeHead, false)
	activeHash, _ := DeviceCertificateProfileStateHash(&active)
	retiredIntent := activeIntent
	retiredIntent.Generation, retiredIntent.ExpectedPreviousProfileStateHash = 3, activeHash
	retiredIntent.TargetStatus, retiredIntent.IssuerFencingEpoch = "retired", 3
	retiredHead := nextDeviceProfileHead(t, activeHead, "2026-09-11T12:02:00Z")
	retired, err := ReduceDeviceCertificateProfile(&active, retiredIntent, &retiredHead, false)
	if err != nil || retired.IssuanceCutoff == nil || retired.IssuanceCutoff.RaftIndex != 2 {
		t.Fatalf("retired state=%#v err=%v", retired, err)
	}
	verify := func(coordinate int64, approval time.Time) error {
		_, err := VerifyDeviceCertificateAt(fixture.leafDER, &retired, "device-1", fixture.identityHash,
			"linux-server", []string{"use_loom"}, IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: coordinate},
			approval, fixture.now.Add(time.Minute))
		return err
	}
	if err := verify(2, fixture.now); err != nil {
		t.Fatal("retired profile 拒绝了 cutoff 前已 approval 的证书:", err)
	}
	if err := verify(3, fixture.now); err == nil {
		t.Fatal("retired profile 接受了 cutoff 后 issuance")
	}
	if err := verify(2, time.Date(2026, 9, 11, 12, 2, 0, 0, time.UTC)); err == nil {
		t.Fatal("retired profile 接受了退役时刻才 approval 的证书")
	}
}

func TestDeviceProfileSuccessorCannotMutateFrozenScopeOrReuseFence(t *testing.T) {
	fixture := newDeviceCertificateFixture(t)
	member, _ := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	head := testHead(t, &set)
	staged, _ := ReduceDeviceCertificateProfile(nil, fixture.intent, &head, false)
	stagedHash, _ := DeviceCertificateProfileStateHash(&staged)
	mutated := fixture.intent
	mutated.Generation, mutated.ExpectedPreviousProfileStateHash = 2, stagedHash
	mutated.TargetStatus = "active"
	mutated.AllowedPlatforms = []string{"android"}
	if _, err := ReduceDeviceCertificateProfile(&staged, mutated,
		pointerHead(nextDeviceProfileHead(t, head, "2026-09-11T12:01:00Z")), false); err == nil {
		t.Fatal("successor 改写了冻结的 platform scope")
	}
	mutated = fixture.intent
	mutated.Generation, mutated.ExpectedPreviousProfileStateHash = 2, stagedHash
	mutated.TargetStatus = "active"
	if _, err := ReduceDeviceCertificateProfile(&staged, mutated,
		pointerHead(nextDeviceProfileHead(t, head, "2026-09-11T12:01:00Z")), false); err == nil {
		t.Fatal("successor 重用了 issuer fencing epoch")
	}
}

func TestCAProfileRootIsOrderIndependentAndRejectsDuplicateLatestState(t *testing.T) {
	fixture := newDeviceCertificateFixture(t)
	member, _ := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	head := testHead(t, &set)
	first, err := ReduceDeviceCertificateProfile(nil, fixture.intent, &head, false)
	if err != nil {
		t.Fatal(err)
	}
	secondIntent := fixture.intent
	secondIntent.ProfileID = "device-profile-2"
	second, err := ReduceDeviceCertificateProfile(nil, secondIntent, &head, false)
	if err != nil {
		t.Fatal(err)
	}
	one, err := CAProfileRoot(nil, []DeviceCertificateProfileStateV1{first, second})
	if err != nil {
		t.Fatal(err)
	}
	two, err := CAProfileRoot(nil, []DeviceCertificateProfileStateV1{second, first})
	if err != nil || one != two {
		t.Fatalf("CA profile root 依赖输入顺序: one=%s two=%s err=%v", one, two, err)
	}
	if _, err := CAProfileRoot(nil, []DeviceCertificateProfileStateV1{first, first}); err == nil {
		t.Fatal("CA profile registry 接受了同 profile ID 的两代/重复 current state")
	}
}

func newDeviceCertificateFixture(t *testing.T) deviceCertificateFixture {
	t.Helper()
	now := time.Date(2026, 9, 11, 12, 0, 30, 0, time.UTC)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device root"},
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
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device issuer"},
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
		SerialNumber: big.NewInt(3), Subject: pkix.Name{}, NotBefore: now,
		NotAfter: now.Add(6 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Policies: []x509.OID{policy},
		URIs: []*url.URL{deviceURI},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &identity.PublicKey, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	issuerHash, _ := HashBytes(DomainDeviceIssuerCertificateDER, issuerDER)
	chain := []string{base64.RawURLEncoding.EncodeToString(issuerDER), base64.RawURLEncoding.EncodeToString(rootDER)}
	chainHash, _ := HashObject(DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: chain})
	extensionOrder := make([]string, len(leaf.Extensions))
	for i, extension := range leaf.Extensions {
		extensionOrder[i] = extension.Id.String()
	}
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, leaf.RawSubjectPublicKeyInfo)
	return deviceCertificateFixture{
		now: now, leafDER: leafDER, identityHash: identityHash, issuerKey: issuerPrivate,
		intent: DeviceCertificateProfileIntentV1{
			Schema: 1, ClusterID: "demo-cluster", ProfileID: "device-profile-1", Generation: 1,
			TargetStatus: "staged", IssuerID: "issuer-1", IssuerGeneration: 1, IssuerFencingEpoch: 1,
			IssuanceNotBefore: "2026-09-11T00:00:00Z", IssuanceNotAfter: "2026-09-12T00:00:00Z",
			ProfileKind: "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash,
			IssuerChainDER: chain, IssuerChainHash: chainHash,
			IssuerKeyArtifactHash:   HashRaw("device-profile-test", []byte("issuer-key-artifact")),
			AllowedPlatforms:        []string{"android", "linux-server"},
			AllowedResponsibilities: []string{"use_loom", "forward"}, ValiditySeconds: 21600,
			AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519", SubjectMode: "empty",
			SANURIPrefix: "spiffe://cluster.example/device/", KeyUsageBits: []string{"digital_signature"},
			BasicConstraintsCA: false, RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"},
			RequiredPolicyOIDs: []string{policyOID.String()}, ExtensionOrderOIDs: extensionOrder,
		},
	}
}

func nextDeviceProfileHead(t *testing.T, parent HeadEntryV2, committedAt string) HeadEntryV2 {
	t.Helper()
	body := parent.Body
	body.Payload.HeadKind = "ordinary"
	body.Payload.RaftIndex++
	body.Payload.ControlRevision = body.Payload.RaftIndex
	body.Payload.PreviousLogEntryHash = parent.EntryHash
	body.Payload.ParentHeadHash = parent.HeadHash
	body.Payload.CommittedLogicalTime = committedAt
	body.Payload.OperationRoot = HashRaw("device-profile-test", []byte(committedAt))
	body.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	head, err := NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func pointerHead(head HeadEntryV2) *HeadEntryV2 { return &head }
