package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type admissionPeerFixture struct {
	member wire.ControlMemberV1
	key    ed25519.PrivateKey
	fail   bool
	calls  int
}

func (peer *admissionPeerFixture) VoteAdmission(_ context.Context,
	request enrollmentv2.EnrollmentAdmissionVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	peer.calls++
	if peer.fail {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("peer unavailable")
	}
	return wire.SignEnrollmentAdmission(request.Attestation, peer.member, peer.key)
}

func TestEnrollmentAdmissionCollectorUsesCommittedQuorumAndCanonicalSignerSubset(t *testing.T) {
	set, _ := testControlSet(t, 3)
	attestation := controlplaneAdmissionAttestation(t, &set)
	peers := make(map[string]enrollmentv2.AdmissionVotePeer, len(set.Members))
	fixtures := make([]*admissionPeerFixture, len(set.Members))
	for index, member := range set.Members {
		fixtures[index] = &admissionPeerFixture{member: member, key: enrollmentKeyForOrdinal(index + 1)}
		peers[member.MemberID] = fixtures[index]
	}
	fixtures[0].fail = true
	collector, err := NewEnrollmentAdmissionCollector(set, peers)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollmentv2.EnrollmentAdmissionVoteRequestV1{Schema: 1,
		EnrollmentServiceID: "enrollment-service", Attestation: attestation}
	qc, err := collector.collectAdmissionRequest(context.Background(), request, attestation)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyEnrollmentAdmissionQC(&qc, &set); err != nil {
		t.Fatal(err)
	}
	if len(qc.Signatures) != 2 || qc.Signatures[0].MemberID != set.Members[1].MemberID ||
		qc.Signatures[1].MemberID != set.Members[2].MemberID {
		t.Fatalf("collector 未形成规范 committed quorum: %#v", qc.SignerRefs)
	}
	for index, peer := range fixtures {
		if peer.calls != 1 {
			t.Fatalf("voter %d 收到 %d 次请求", index, peer.calls)
		}
	}
	fixtures[1].fail = true
	if _, err := collector.collectAdmissionRequest(context.Background(), request, attestation); err == nil {
		t.Fatal("少数 voter 被当作 admission quorum")
	}
}

func TestEnrollmentPeerHTTPRequiresExactControlMTLSAndCanonicalBody(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	voter := &admissionPeerFixture{member: set.Members[0], key: enrollmentKeyForOrdinal(1)}
	handler, err := NewEnrollmentPeerHTTPHandler(set, directory, now, voter)
	if err != nil {
		t.Fatal(err)
	}
	attestation := controlplaneAdmissionAttestation(t, &set)
	submitted := enrollmentv2.EnrollmentAdmissionVoteRequestV1{Schema: 1,
		EnrollmentServiceID: "enrollment-service", Attestation: attestation}
	body, _ := wire.MarshalCanonical(submitted)
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+EnrollmentAdmissionVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || voter.calls != 1 {
		t.Fatalf("合法 control peer vote status=%d body=%s calls=%d", response.Code, response.Body.String(), voter.calls)
	}
	var result enrollmentv2.EnrollmentAdmissionVoteResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), 64<<10, &result)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) ||
		wire.VerifyEnrollmentAdmissionSignature(&attestation, &result.Signature, &set) != nil {
		t.Fatalf("peer response 不是可验 canonical signature: %#v err=%v", result, err)
	}

	withoutTLS := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+EnrollmentAdmissionVotePath, bytes.NewReader(body))
	withoutTLS.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, withoutTLS)
	if denied.Code != http.StatusForbidden || voter.calls != 1 {
		t.Fatal("缺 control-peer mTLS 的 admission vote 到达 voter")
	}

	nonCanonical := append(append([]byte(nil), body...), '\n')
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+EnrollmentAdmissionVotePath, bytes.NewReader(nonCanonical))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	denied = httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusBadRequest || voter.calls != 1 {
		t.Fatal("非 canonical peer request 到达 voter")
	}
}

func TestEnrollmentPeerClientRejectsEndpointOutsidePrivateDirectory(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	if _, err := NewEnrollmentPeerClient("https://10.20.0.99:7443", set.Members[1].MemberID,
		certificates[set.Members[0].MemberID], set, directory, now); err == nil {
		t.Fatal("Enrollment peer client 接受了 private directory 外 endpoint")
	}
}

func controlplaneAdmissionAttestation(t *testing.T, set *wire.ControlSetV1) wire.EnrollmentAdmissionAttestationBodyV1 {
	t.Helper()
	setHash, err := wire.ControlSetHash(set)
	if err != nil {
		t.Fatal(err)
	}
	valueHash := wire.HashRaw("enrollment-peer-test", []byte("value"))
	return wire.EnrollmentAdmissionAttestationBodyV1{
		Schema: 1, AttestationType: "enrollment_admission", ClusterID: set.ClusterID,
		InviteID: "invite", RequestID: "request", CertifiedInviteRecordHash: valueHash,
		DeviceEnrollmentIntentCommitmentHash: valueHash, DeviceEnrollmentIntentOpeningHash: valueHash,
		TokenCommitment: valueHash, ClaimCoreHash: valueHash, IdentityKeyHash: valueHash,
		WrappingKeyHash: valueHash, CSRHash: valueHash,
		PoPVerificationProfile: "loom-enrollment-server-nonce-detached-v2",
		BaseRecoveryEpoch:      0, BaseControlEpoch: 0, BaseControlSetHash: setHash, BaseHeadHash: valueHash,
		AdmissionNotAfter: "2026-09-11T12:10:00Z", RetryNotAfter: "2026-09-11T12:20:00Z",
	}
}

func enrollmentKeyForOrdinal(ordinal int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-2], seed[len(seed)-1] = byte(ordinal), 3
	return ed25519.NewKeyFromSeed(seed)
}
