package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func raftDirectoryFixture(t *testing.T, set wire.ControlSetV1) (wire.ControlPeerDirectoryV1, map[string]tls.Certificate) {
	t.Helper()
	notBefore := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	directory := wire.ControlPeerDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, DirectoryGeneration: 1,
		HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	certificates := make(map[string]tls.Certificate, len(set.Members))
	for i, member := range set.Members {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: member.MemberID},
			NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _ := x509.ParseCertificate(der)
		spkiHash, _ := wire.HashBytes(wire.DomainControlPeerIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
		certificateHash, _ := wire.HashBytes(wire.DomainControlPeerCertificate, der)
		directory.Members = append(directory.Members, wire.ControlPeerDirectoryMemberV1{
			Schema: 1, ClusterID: set.ClusterID, MemberID: member.MemberID,
			DeviceID: fmt.Sprintf("control-device-%d", i+1), PeerIdentitySPKIHash: spkiHash,
			PeerIdentityArtifactHash: wire.HashRaw("transport-test-artifact-v1", []byte(member.MemberID)),
			PeerCertificateDER:       base64.RawURLEncoding.EncodeToString(der), PeerCertificateHash: certificateHash,
			PeerEndpoints: []wire.ControlPeerEndpointV1{{EndpointID: fmt.Sprintf("peer-endpoint-%d", i+1), URL: fmt.Sprintf("https://10.20.0.%d:7443", i+1)}},
			FaultDomain:   fmt.Sprintf("zone-%d", i+1),
		})
		certificates[member.MemberID] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: certificate}
	}
	return directory, certificates
}

func TestRaftHTTPHandlerBindsMessageIdentityToMTLSMember(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	storage, err := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRaftHTTPHandler(storage, set, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	message := VoteRequestV1{Term: 1, CandidateID: set.Members[1].MemberID, LastLogIndex: 0, LastLogTerm: 0}
	body, _ := wire.MarshalCanonical(message)
	request := httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid peer response=%d %s", response.Code, response.Body.String())
	}

	message.CandidateID = set.Members[2].MemberID
	body, _ = wire.MarshalCanonical(message)
	request = httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("spoofed member response=%d %s", response.Code, response.Body.String())
	}
}

func TestControlPeerTLSConfigUsesTLS13AndExactRemoteMember(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	serverConfig, err := NewControlPeerServerTLSConfig(set.Members[0].MemberID, certificates[set.Members[0].MemberID], set, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 || serverConfig.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("unexpected server TLS policy: %#v", serverConfig)
	}
	clientConfig, err := NewControlPeerClientTLSConfig(set.Members[1].MemberID, certificates[set.Members[0].MemberID], set, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificates[set.Members[2].MemberID].Leaf}}); err == nil {
		t.Fatal("accepted a valid directory certificate for the wrong remote member")
	}
}
