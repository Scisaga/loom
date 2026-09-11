package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func adminFixture(t *testing.T, leafUsage x509.ExtKeyUsage) (AdminCertificateProfileV1, AdminAuthorizationV1, ed25519.PrivateKey) {
	t.Helper()
	notBefore := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notBefore.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	adminPublic, adminPrivate, _ := ed25519.GenerateKey(rand.Reader)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	policy, err := x509.OIDFromASN1OID(policyOID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "admin-1"},
		NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{leafUsage}, Policies: []x509.OID{policy},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, adminPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	chain := []string{base64.RawURLEncoding.EncodeToString(rootDER)}
	chainHash, _ := adminIssuerChainHash(chain)
	profile := AdminCertificateProfileV1{
		Schema: 1, ClusterID: "cluster", ProfileID: "admin-profile-1", Generation: 1,
		IssuerChainDER: chain, AdminIssuerChainHash: chainHash,
		SubjectKeyAlgorithm: "ed25519", OperationSignatureAlgorithm: "ed25519",
		RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{policyOID.String()}, MaximumValiditySeconds: 86400,
	}
	profileHash, _ := AdminCertificateProfileHash(&profile)
	digest, _ := AdminCertificateDigest(leafDER)
	keyID, _ := AdminKeyID(leaf.RawSubjectPublicKeyInfo)
	authorization := AdminAuthorizationV1{
		Schema: 1, ClusterID: "cluster", AuthorizationID: "admin-authorization-1", Generation: 1,
		AdminID: "admin-1", AdminCertificateDER: base64.RawURLEncoding.EncodeToString(leafDER),
		AdminCertificateDigest: digest, AdminKeyID: keyID,
		CertificateProfileRef: AdminCertificateProfileRefV1{ProfileID: profile.ProfileID, Generation: 1, AdminCertificateProfileHash: profileHash},
		NotBefore:             "2026-09-11T00:00:00Z", NotAfter: "2026-09-12T00:00:00Z", Status: "active",
		AllowedOperationKinds: []string{"create_invite"}, Capabilities: []string{},
		Scopes: []AdminResourceScopeV1{{ScopeKind: "cluster", Cluster: &struct{}{}}},
	}
	return profile, authorization, adminPrivate
}

func TestAdminACLAuthorizesExactBaseIdentityKindAndScope(t *testing.T) {
	profile, authorization, privateKey := adminFixture(t, x509.ExtKeyUsageClientAuth)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	if err := ValidateAdminAuthorizationAt(&authorization, &profile, now); err != nil {
		t.Fatal(err)
	}
	root, err := AdminACLRoot([]AdminAuthorizationV1{authorization}, map[string]AdminCertificateProfileV1{profile.ProfileID: profile})
	if err != nil || root == "" {
		t.Fatalf("root=%q err=%v", root, err)
	}
	body := testOperationBody()
	body.ClusterID = authorization.ClusterID
	body.AuthorID = authorization.AdminID
	body.AdminCertDigest = authorization.AdminCertificateDigest
	operation, err := NewControlOperation(body, privateKey, OperationSchemaRegistry{"create_invite": 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthorizeControlOperation(&operation, &authorization, &profile, &authorization.Scopes[0], now, OperationSchemaRegistry{"create_invite": 2}); err != nil {
		t.Fatal(err)
	}
	wrongScope := AdminResourceScopeV1{ScopeKind: "device", Device: &AdminScopeIDsV1{DeviceIDs: []string{"other-device"}}}
	if err := AuthorizeControlOperation(&operation, &authorization, &profile, &wrongScope, now, OperationSchemaRegistry{"create_invite": 2}); err == nil {
		t.Fatal("authorized an operation outside the exact resource scope")
	}
	if _, err := AdminAuthorizationHash(&authorization, &profile); err != nil {
		t.Fatal("content hash should remain reproducible independently of current time:", err)
	}
	if err := ValidateAdminAuthorizationAt(&authorization, &profile, now.Add(48*time.Hour)); err == nil {
		t.Fatal("accepted expired active admin authorization")
	}
}

func TestAdminCertificateRejectsWrongRoleEKU(t *testing.T) {
	profile, authorization, _ := adminFixture(t, x509.ExtKeyUsageServerAuth)
	if err := ValidateAdminAuthorizationAt(&authorization, &profile, time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted server-only certificate as an admin client")
	}
}

func TestPrivateControlAuthorizationBindsTLSLeafHeadQCAndACLRoot(t *testing.T) {
	profile, authorization, adminKey := adminFixture(t, x509.ExtKeyUsageClientAuth)
	member, configKey := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	profile.ClusterID = set.ClusterID
	profileHash, err := AdminCertificateProfileHash(&profile)
	if err != nil {
		t.Fatal(err)
	}
	authorization.ClusterID = set.ClusterID
	authorization.CertificateProfileRef.AdminCertificateProfileHash = profileHash
	profiles := map[string]AdminCertificateProfileV1{profile.ProfileID: profile}
	authorizations := []AdminAuthorizationV1{authorization}
	aclRoot, err := AdminACLRoot(authorizations, profiles)
	if err != nil {
		t.Fatal(err)
	}
	head := testHead(t, &set)
	headBody := head.Body
	headBody.Payload.AdminACLRoot = aclRoot
	head, err = NewHeadEntry(headBody)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignHeadAttestation(AttestationForHead(&head), member, configKey)
	if err != nil {
		t.Fatal(err)
	}
	qc := StableQC(&head, []ControlConfigSignatureV1{signature})
	qcRaw, err := MarshalCanonical(qc)
	if err != nil {
		t.Fatal(err)
	}
	body := testOperationBody()
	body.ClusterID = set.ClusterID
	body.AuthorID = authorization.AdminID
	body.AdminCertDigest = authorization.AdminCertificateDigest
	body.BaseRecoveryEpoch = head.Body.Payload.RecoveryEpoch
	body.BaseRecoveryStatementHash = head.Body.Payload.RecoveryStatementHash
	body.BaseRecoveryPolicyHash = head.Body.Payload.RecoveryPolicyHash
	body.BaseControlEpoch = head.Body.Payload.ControlEpoch
	body.BaseControlSetHash = head.Body.Payload.ControlSetHash
	body.BaseControlRevision = head.Body.Payload.ControlRevision
	body.ParentHeadHash = head.HeadHash
	schemas := OperationSchemaRegistry{"create_invite": 2}
	operation, err := NewControlOperation(body, adminKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	peerDER, err := base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := AuthorizeControlOperationAtHead(&operation, peerDER, &authorization.Scopes[0],
		time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC), schemas, &head, qcRaw, &set, nil, authorizations, profiles)
	if err != nil || verified.HeadHash() != head.HeadHash {
		t.Fatalf("private control authorization failed: %#v err=%v", verified, err)
	}
	splicedHead := head
	splicedHead.Body.Payload.AdminACLRoot = HashRaw("test-admin-root-v1", []byte("other"))
	splicedHead, _ = NewHeadEntry(splicedHead.Body)
	if _, err := AuthorizeControlOperationAtHead(&operation, peerDER, &authorization.Scopes[0],
		time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC), schemas, &splicedHead, qcRaw, &set, nil, authorizations, profiles); err == nil {
		t.Fatal("接受了未绑定 QC/ACL root 的 spliced head")
	}
	if _, err := AuthorizeControlOperationAtHead(&operation, []byte("not-an-admin-certificate"), &authorization.Scopes[0],
		time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC), schemas, &head, qcRaw, &set, nil, authorizations, profiles); err == nil {
		t.Fatal("接受了错误角色/未知 TLS leaf")
	}
}
