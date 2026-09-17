package controlplane

import (
	"bytes"
	"context"
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
	handler, err := NewRaftHTTPHandler(storage, set, directory, now,
		func(context.Context, RaftLogRecordV1, []RaftLogRecordV1) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	message := VoteRequestV1{Term: 1, CandidateID: set.Members[1].MemberID, LastLogIndex: 0, LastLogTerm: 0}
	body, _ := wire.MarshalCanonical(message)
	request := httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid peer response=%d %s", response.Code, response.Body.String())
	}
	wantResponse, err := wire.MarshalCanonical(VoteResultV1{Term: 1, Granted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Body.Bytes(), wantResponse) {
		t.Fatalf("Raft response 不是 exact canonical bytes: got=%q want=%q", response.Body.Bytes(), wantResponse)
	}

	message.CandidateID = set.Members[2].MemberID
	body, _ = wire.MarshalCanonical(message)
	request = httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("spoofed member response=%d %s", response.Code, response.Body.String())
	}
}

func TestRaftHTTPRejectsCandidateBeforeFsyncButPersistsHigherTerm(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	path := filepath.Join(t.TempDir(), "raft.json")
	storage, err := OpenRaftStorage(path, set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	recomputed := 0
	handler, err := NewRaftHTTPHandler(storage, set, directory, now,
		func(_ context.Context, _ RaftLogRecordV1, _ []RaftLogRecordV1) error {
			recomputed++
			return context.Canceled
		})
	if err != nil {
		t.Fatal(err)
	}
	head := retermGenesis(t, testControlHead(t, &set), 2)
	message := AppendEntriesRequestV1{Term: 2, LeaderID: set.Members[1].MemberID,
		PrevLogHash: wire.EmptyHashV1, Entries: []RaftLogRecordV1{recordForEntry(head)}}
	body, _ := wire.MarshalCanonical(message)
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+RaftAppendPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || recomputed != 1 {
		t.Fatalf("invalid candidate response=%d recomputed=%d body=%s", response.Code, recomputed, response.Body.String())
	}
	reopened, err := OpenRaftStorage(path, set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.SnapshotRaft()
	if state.CurrentTerm != 2 || len(state.Log) != 0 {
		t.Fatalf("candidate 拒绝边界未保持 term/log 原子性: %#v", state)
	}
}

func TestRaftElectionHooksRejectPrematurePreVoteAndObserveAppend(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	storage, err := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRaftHTTPHandler(storage, set, directory, now,
		func(context.Context, RaftLogRecordV1, []RaftLogRecordV1) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	if err := handler.SetElectionHooks(func() bool { return false }, func() { observed++ }); err != nil {
		t.Fatal(err)
	}
	peerID := set.Members[1].MemberID
	vote := VoteRequestV1{Term: 1, CandidateID: peerID, PreVote: true}
	body, _ := wire.MarshalCanonical(vote)
	request := httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[peerID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var voteResult VoteResultV1
	if _, err := wire.DecodeStrict(response.Body.Bytes(), 1<<20, &voteResult); err != nil ||
		response.Code != http.StatusOK || voteResult.Granted || storage.SnapshotRaft().CurrentTerm != 0 {
		t.Fatalf("近期 leader contact 后仍批准 pre-vote: status=%d result=%#v err=%v",
			response.Code, voteResult, err)
	}

	head := testControlHead(t, &set)
	appendRequest := AppendEntriesRequestV1{Term: 1, LeaderID: peerID,
		PrevLogHash: wire.EmptyHashV1, Entries: []RaftLogRecordV1{recordForEntry(head)}}
	body, _ = wire.MarshalCanonical(appendRequest)
	request = httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftAppendPath,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[peerID].Leaf}}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || observed != 1 {
		t.Fatalf("合法 AppendEntries 未刷新 election timer: status=%d observed=%d body=%s",
			response.Code, observed, response.Body.String())
	}
}

func TestRaftLearnerHTTPReplicatesButNeverVotes(t *testing.T) {
	oldSet, _ := testControlSet(t, 1)
	newSet, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, oldSet)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	path := filepath.Join(t.TempDir(), "learner.json")
	storage, err := OpenRaftLearnerStorage(path,
		newSet.Members[1].MemberID, oldSet)
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	handler, err := NewRaftLearnerHTTPHandler(storage, oldSet, directory, now,
		func(_ context.Context, record RaftLogRecordV1, prefix []RaftLogRecordV1) error {
			if record.Kind != RaftRecordHead {
				t.Fatal("learner verifier 收到错误 record kind")
			}
			if len(prefix) != 1 || !wire.EqualCanonical(prefix[0], record) {
				t.Fatalf("learner verifier 未收到 candidate 的 exact append prefix: %#v", prefix)
			}
			verified++
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	vote := VoteRequestV1{Term: 1, CandidateID: oldSet.Members[0].MemberID}
	body, _ := wire.MarshalCanonical(vote)
	request := httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftVotePath,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[oldSet.Members[0].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || storage.SnapshotRaft().CurrentTerm != 0 {
		t.Fatalf("learner vote response=%d state=%#v", response.Code, storage.SnapshotRaft())
	}

	head := testControlHead(t, &oldSet)
	appendRequest := AppendEntriesRequestV1{Term: 1, LeaderID: oldSet.Members[0].MemberID,
		PrevLogHash: wire.EmptyHashV1, Entries: []RaftLogRecordV1{recordForEntry(head)}, LeaderCommit: 1}
	body, _ = wire.MarshalCanonical(appendRequest)
	request = httptest.NewRequest(http.MethodPost, "https://10.20.0.1:7443"+RaftAppendPath,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[oldSet.Members[0].MemberID].Leaf}}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	state := storage.SnapshotRaft()
	if response.Code != http.StatusOK || verified != 1 || state.CommitIndex != 1 || len(state.Log) != 1 ||
		!state.VotingDisabled {
		t.Fatalf("learner append response=%d verified=%d state=%#v body=%s",
			response.Code, verified, state, response.Body.String())
	}
	reopened, err := OpenRaftLearnerStorage(path, newSet.Members[1].MemberID, oldSet)
	if err != nil || !wire.EqualCanonical(reopened.SnapshotRaft(), state) {
		t.Fatalf("learner 重启未恢复 exact non-voting prefix: state=%#v err=%v",
			reopened, err)
	}
}

func TestLearnerControlPeerTLSIsAsymmetricBeforeJoint(t *testing.T) {
	oldSet, _ := testControlSet(t, 1)
	newSet, _ := testControlSet(t, 3)
	oldDirectory, oldCertificates := raftDirectoryFixture(t, oldSet)
	newDirectory, newCertificates := raftDirectoryFixture(t, newSet)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	learnerID := newSet.Members[1].MemberID
	serverConfig, err := NewLearnerControlPeerServerTLSConfig(learnerID,
		newCertificates[learnerID], oldSet, newSet, oldDirectory, newDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverConfig.VerifyPeerCertificate([][]byte{
		oldCertificates[oldSet.Members[0].MemberID].Certificate[0],
	}, nil); err != nil {
		t.Fatalf("learner listener 拒绝 old stable voter: %v", err)
	}
	if err := serverConfig.VerifyPeerCertificate([][]byte{
		newCertificates[newSet.Members[2].MemberID].Certificate[0],
	}, nil); err == nil {
		t.Fatal("learner listener 在 Joint 前接受了 new-side peer")
	}
	clientConfig, err := NewLearnerControlPeerClientTLSConfig(learnerID,
		oldCertificates[oldSet.Members[0].MemberID], oldSet, newSet,
		oldDirectory, newDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		newCertificates[learnerID].Leaf,
	}}); err != nil {
		t.Fatalf("old stable voter 拒绝 exact learner server: %v", err)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		newCertificates[newSet.Members[2].MemberID].Leaf,
	}}); err == nil {
		t.Fatal("old stable voter 接受了错误 learner server")
	}
	if _, err := NewRaftLearnerPeerClient(newDirectory.Members[1].PeerEndpoints[0].URL,
		learnerID, oldCertificates[oldSet.Members[0].MemberID], oldSet, newSet,
		oldDirectory, newDirectory, now); err != nil {
		t.Fatalf("不能为 exact new-side endpoint 构造 learner Raft client: %v", err)
	}
}

func TestJointControlPeerTLSAcceptsExactOldNewDirectoryUnion(t *testing.T) {
	oldSet, _ := testControlSet(t, 1)
	newSet, _ := testControlSet(t, 3)
	oldDirectory, oldCertificates := raftDirectoryFixture(t, oldSet)
	newDirectory, newCertificates := raftDirectoryFixture(t, newSet)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	serverConfig, err := NewJointControlPeerServerTLSConfig(oldSet.Members[0].MemberID,
		oldCertificates[oldSet.Members[0].MemberID], oldSet, newSet, oldDirectory, newDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	newOnlyMember := newSet.Members[1].MemberID
	if err := serverConfig.VerifyPeerCertificate([][]byte{
		newCertificates[newOnlyMember].Certificate[0],
	}, nil); err != nil {
		t.Fatalf("server 拒绝 new-side exact peer cert: %v", err)
	}
	clientConfig, err := NewJointControlPeerClientTLSConfig(newOnlyMember,
		oldCertificates[oldSet.Members[0].MemberID], oldSet, newSet, oldDirectory, newDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		newCertificates[newOnlyMember].Leaf,
	}}); err != nil {
		t.Fatalf("client 拒绝 new-side exact remote cert: %v", err)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		newCertificates[newSet.Members[2].MemberID].Leaf,
	}}); err == nil {
		t.Fatal("client 接受了错误 Joint remote member cert")
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
