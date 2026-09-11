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

type approvalPeerFixture struct {
	member wire.ControlMemberV1
	key    ed25519.PrivateKey
	fail   bool
	calls  int
}

func (peer *approvalPeerFixture) VoteApproval(_ context.Context,
	request enrollmentv2.EnrollmentApprovalVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	peer.calls++
	if peer.fail {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("peer unavailable")
	}
	return wire.SignEnrollmentApproval(request.Attestation, peer.member, peer.key)
}

func TestEnrollmentApprovalCollectorUsesIssuanceSetQuorumWithoutShrink(t *testing.T) {
	set, _ := testControlSet(t, 3)
	attestation := controlplaneApprovalAttestation()
	peers := make(map[string]enrollmentv2.ApprovalVotePeer, len(set.Members))
	fixtures := make([]*approvalPeerFixture, len(set.Members))
	for index, member := range set.Members {
		fixtures[index] = &approvalPeerFixture{member: member, key: enrollmentKeyForOrdinal(index + 1)}
		peers[member.MemberID] = fixtures[index]
	}
	fixtures[0].fail = true
	collector, err := NewEnrollmentApprovalCollector(set, peers)
	if err != nil {
		t.Fatal(err)
	}
	qc, err := collector.CollectApproval(context.Background(), attestation)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyEnrollmentApprovalQC(&qc, &set); err != nil {
		t.Fatal(err)
	}
	if len(qc.Signatures) != 2 || qc.Signatures[0].MemberID != set.Members[1].MemberID ||
		qc.Signatures[1].MemberID != set.Members[2].MemberID {
		t.Fatalf("approval collector 未固定规范 quorum: %#v", qc.SignerRefs)
	}
	for index, peer := range fixtures {
		if peer.calls != 1 {
			t.Fatalf("approval voter %d 收到 %d 次请求", index, peer.calls)
		}
	}
	fixtures[1].fail = true
	if _, err := collector.CollectApproval(context.Background(), attestation); err == nil {
		t.Fatal("单个在线 voter 被当作 committed approval quorum")
	}
}

func TestEnrollmentApprovalHTTPRequiresExactControlMTLSAndCanonicalBody(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	voter := &approvalPeerFixture{member: set.Members[0], key: enrollmentKeyForOrdinal(1)}
	handler, err := NewEnrollmentApprovalHTTPHandler(set, directory, now, voter)
	if err != nil {
		t.Fatal(err)
	}
	attestation := controlplaneApprovalAttestation()
	submitted := enrollmentv2.EnrollmentApprovalVoteRequestV1{Schema: 1, Attestation: attestation}
	body, _ := wire.MarshalCanonical(submitted)
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+EnrollmentApprovalVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || voter.calls != 1 {
		t.Fatalf("approval HTTP status=%d body=%s calls=%d", response.Code, response.Body.String(), voter.calls)
	}
	var result enrollmentv2.EnrollmentApprovalVoteResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), 64<<10, &result)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) ||
		wire.VerifyEnrollmentApprovalSignature(&attestation, &result.Signature, &set) != nil {
		t.Fatalf("approval response 不是 exact canonical purpose signature: %v", err)
	}

	cleartext := httptest.NewRequest(http.MethodPost,
		"http://10.20.0.1:7443"+EnrollmentApprovalVotePath, bytes.NewReader(body))
	cleartext.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, cleartext)
	if denied.Code != http.StatusForbidden || voter.calls != 1 {
		t.Fatal("approval endpoint 接受了非 control mTLS 请求")
	}

	nonCanonical := append(append([]byte(nil), body...), '\n')
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+EnrollmentApprovalVotePath, bytes.NewReader(nonCanonical))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	denied = httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusBadRequest || voter.calls != 1 {
		t.Fatal("approval endpoint 接受了非 canonical request")
	}
}

func TestEnrollmentApprovalClientRejectsEndpointOutsideDirectory(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	if _, err := NewEnrollmentApprovalPeerClient("https://10.20.0.1:9999", set.Members[0].MemberID,
		certificates[set.Members[1].MemberID], set, directory, now); err == nil {
		t.Fatal("approval client 接受了 directory 外 endpoint")
	}
}

func controlplaneApprovalAttestation() wire.EnrollmentApprovalAttestationBodyV2 {
	hash := wire.HashRaw("approval-peer-test", []byte("value"))
	return wire.EnrollmentApprovalAttestationBodyV2{
		Schema: 2, AttestationType: "enrollment_approval", ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		ClaimOperationHash: hash, ProvisionalIssuanceOperationHash: hash, ProvisionalIssuanceHash: hash,
		IssuanceHeadHash: hash, IssuanceHeadQCHash: hash, ResultingIssuanceRegistryRoot: hash,
		DeviceCertificateHash: hash, InitialDeviceViewHash: hash, SecretArtifactRefsRoot: hash,
		ResultArtifactHash: hash,
	}
}
