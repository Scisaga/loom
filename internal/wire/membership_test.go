package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func peerDirectoryFixture(t *testing.T, usages []x509.ExtKeyUsage) (*ControlSetV1, *ControlPeerDirectoryV1) {
	t.Helper()
	member, _ := deterministicMember(t, 1)
	set := &ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "control-peer-1"},
		NotBefore:    notBefore, NotAfter: notBefore.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	spkiHash, _ := HashBytes(DomainControlPeerIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
	certificateHash, _ := HashBytes(DomainControlPeerCertificate, certificateDER)
	directory := &ControlPeerDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, DirectoryGeneration: 1,
		HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Members: []ControlPeerDirectoryMemberV1{{
			Schema: 1, ClusterID: set.ClusterID, MemberID: member.MemberID,
			DeviceID: "control-device-1", PeerIdentitySPKIHash: spkiHash,
			PeerIdentityArtifactHash: HashRaw("test-peer-artifact-v1", []byte("artifact")),
			PeerCertificateDER:       base64.RawURLEncoding.EncodeToString(certificateDER),
			PeerCertificateHash:      certificateHash,
			PeerEndpoints:            []ControlPeerEndpointV1{{EndpointID: "peer-endpoint-1", URL: "https://10.20.0.1:7443"}},
			FaultDomain:              "zone-a",
		}},
	}
	return set, directory
}

func TestControlPeerDirectoryRequiresStrictCertificateProfile(t *testing.T) {
	set, directory := peerDirectoryFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	trustedTime := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	if err := ValidateControlPeerDirectoryAt(set, directory, trustedTime); err != nil {
		t.Fatal(err)
	}
	object := &ControlPeerDirectoryPrivateObjectV1{Schema: 1, ClusterID: set.ClusterID, Directory: *directory}
	object.ControlSetHash, _ = ControlSetHash(set)
	object.ControlPeerDirectoryHash, _ = ControlPeerDirectoryHash(set, directory)
	if hash, err := ControlPeerDirectoryPrivateObjectHash(set, object); err != nil || hash == "" {
		t.Fatalf("private object hash=%q err=%v", hash, err)
	}
	if err := ValidateControlPeerDirectoryAt(set, directory, trustedTime.Add(48*time.Hour)); err == nil {
		t.Fatal("accepted an expired control-peer certificate")
	}
}

func TestControlPeerDirectoryRejectsRoleConfusionAndHashSubstitution(t *testing.T) {
	set, deviceOnly := peerDirectoryFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	trustedTime := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	if err := ValidateControlPeerDirectoryAt(set, deviceOnly, trustedTime); err == nil {
		t.Fatal("accepted a client-only Device certificate as a control peer")
	}

	set, valid := peerDirectoryFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	valid.Members[0].PeerIdentitySPKIHash = valid.Members[0].PeerCertificateHash
	if err := ValidateControlPeerDirectoryAt(set, valid, trustedTime); err == nil {
		t.Fatal("accepted certificate hash in the SPKI hash field")
	}
}
