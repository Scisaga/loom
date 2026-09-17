package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPostCommitHeadAttestationQuorumRecoversAfterExecutorRestart(t *testing.T) {
	set, configKeys := testControlSet(t, 3)
	entry := testControlHead(t, &set)
	peers := make(map[string]HeadAttestationPeer, len(set.Members))
	var commitStorage *RaftStorage
	var commitStorePath string
	followerStores := make([]*Store, 0, len(set.Members)-1)
	var recomputes atomic.Int32
	for memberIndex, member := range set.Members {
		storage, err := OpenRaftStorage(filepath.Join(t.TempDir(), member.MemberID+".json"), member.MemberID, set)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storage.StartElection(); err != nil {
			t.Fatal(err)
		}
		if err := storage.AppendLocal(entry); err != nil {
			t.Fatal(err)
		}
		matches := make(map[string]int64, len(set.Members)-1)
		for _, remote := range set.Members {
			if remote.MemberID != member.MemberID {
				matches[remote.MemberID] = 1
			}
		}
		if committed, err := storage.AdvanceLeaderCommit(matches); err != nil || committed != 1 {
			t.Fatalf("member %s commit=%d err=%v", member.MemberID, committed, err)
		}
		if memberIndex == 0 {
			commitStorage = storage
		}
		storePath := filepath.Join(t.TempDir(), member.MemberID+"-control.json")
		store, err := Open(storePath, set)
		if err != nil {
			t.Fatal(err)
		}
		if memberIndex == 0 {
			commitStorePath = storePath
		} else {
			followerStores = append(followerStores, store)
		}
		voter, err := NewHeadAttestationVoter(storage, store, set, member.MemberID, configKeys[member.MemberID],
			func(_ context.Context, candidate wire.HeadEntryV2) error {
				if !wire.EqualCanonical(candidate, entry) {
					return context.Canceled
				}
				recomputes.Add(1)
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		peers[member.MemberID] = voter
	}
	collector, err := NewHeadAttestationCollector(set, peers)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(commitStorePath, set)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(entry); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitFromRaft(commitStorage, entry.EntryHash); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(commitStorePath, set)
	if err != nil {
		t.Fatal(err)
	}
	localMember := set.Members[0]
	localVoter, err := NewHeadAttestationVoter(commitStorage, reopened, set, localMember.MemberID,
		configKeys[localMember.MemberID], func(_ context.Context, candidate wire.HeadEntryV2) error {
			if !wire.EqualCanonical(candidate, entry) {
				return context.Canceled
			}
			recomputes.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	peers[localMember.MemberID] = localVoter
	collector, err = NewHeadAttestationCollector(set, peers)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.CertifyActive(context.Background(), reopened); err != nil {
		t.Fatal(err)
	}
	state := reopened.Snapshot()
	if state.Active == nil || state.Active.Phase != PhaseCertified || state.Active.QC == nil ||
		len(state.Active.QC.Signatures) != 2 || recomputes.Load() != 3 {
		t.Fatalf("post-commit recovery 未冻结 canonical quorum: state=%#v recomputes=%d", state, recomputes.Load())
	}
	if err := wire.VerifyStableHeadQC(&entry, &set, state.Active.QC); err != nil {
		t.Fatal(err)
	}
	installedCount := 1
	for _, follower := range followerStores {
		followerState := follower.Snapshot()
		if followerState.Active == nil && followerState.CertifiedHead != nil &&
			followerState.CertifiedQC != nil && followerState.CertifiedHead.EntryHash == entry.EntryHash &&
			wire.EqualCanonical(*followerState.CertifiedQC, *state.Active.QC) {
			installedCount++
		}
	}
	quorum, _ := wire.Quorum(len(set.Members))
	if installedCount < quorum {
		t.Fatalf("exact QC 只耐久安装到 %d/%d voters", installedCount, len(set.Members))
	}
}

func TestHeadAttestationCollectorDoesNotShrinkQuorumToCommittedOnlineReplica(t *testing.T) {
	set, configKeys := testControlSet(t, 3)
	entry := testControlHead(t, &set)
	peers := make(map[string]HeadAttestationPeer, len(set.Members))
	for index, member := range set.Members {
		storage, _ := OpenRaftStorage(filepath.Join(t.TempDir(), member.MemberID+".json"), member.MemberID, set)
		store, _ := Open(filepath.Join(t.TempDir(), member.MemberID+"-control.json"), set)
		_, _ = storage.StartElection()
		if err := storage.AppendLocal(entry); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if committed, err := storage.AdvanceLeaderCommit(map[string]int64{set.Members[1].MemberID: 1}); err != nil || committed != 1 {
				t.Fatalf("single committed replica setup failed: commit=%d err=%v", committed, err)
			}
		}
		voter, err := NewHeadAttestationVoter(storage, store, set, member.MemberID, configKeys[member.MemberID],
			func(context.Context, wire.HeadEntryV2) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		peers[member.MemberID] = voter
	}
	collector, _ := NewHeadAttestationCollector(set, peers)
	if _, err := collector.Collect(context.Background(), entry); err == nil {
		t.Fatal("collector 按已 committed/在线单副本缩小了 N=3 quorum")
	}
}

func TestHeadAttestationVoterRejectsUncommittedEntry(t *testing.T) {
	set, configKeys := testControlSet(t, 1)
	entry := testControlHead(t, &set)
	storage, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	store, _ := Open(filepath.Join(t.TempDir(), "control.json"), set)
	_, _ = storage.StartElection()
	if err := storage.AppendLocal(entry); err != nil {
		t.Fatal(err)
	}
	voter, err := NewHeadAttestationVoter(storage, store, set, set.Members[0].MemberID,
		configKeys[set.Members[0].MemberID], func(context.Context, wire.HeadEntryV2) error {
			t.Fatal("uncommitted entry 到达 recompute")
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	request := HeadAttestationVoteRequestV1{Schema: 1, RaftIndex: 1, EntryHash: entry.EntryHash}
	if _, err := voter.VoteHeadAttestation(context.Background(), request); err == nil {
		t.Fatal("未 committed entry 获得 config attestation")
	}
}

func TestHeadAttestationHTTPRequiresControlPeerMTLS(t *testing.T) {
	set, configKeys := testControlSet(t, 1)
	directory, certificates := raftDirectoryFixture(t, set)
	entry := testControlHead(t, &set)
	storage, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	store, _ := Open(filepath.Join(t.TempDir(), "control.json"), set)
	_, _ = storage.StartElection()
	_ = storage.AppendLocal(entry)
	_, _ = storage.AdvanceLeaderCommit(nil)
	voter, _ := NewHeadAttestationVoter(storage, store, set, set.Members[0].MemberID,
		configKeys[set.Members[0].MemberID], func(context.Context, wire.HeadEntryV2) error { return nil })
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	handler, err := NewHeadAttestationHTTPHandler(set, directory, now, voter)
	if err != nil {
		t.Fatal(err)
	}
	submitted := HeadAttestationVoteRequestV1{Schema: 1, RaftIndex: 1, EntryHash: entry.EntryHash}
	body, _ := wire.MarshalCanonical(submitted)
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+HeadAttestationVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[0].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid head attestation status=%d body=%s", response.Code, response.Body.String())
	}
	var result HeadAttestationVoteResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), headPeerMaxBody, &result)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) ||
		wire.VerifyHeadAttestationSignature(&entry, &result.Signature, &set) != nil {
		t.Fatalf("head attestation response 无效: %#v err=%v", result, err)
	}
	certification := HeadCertificationRequestV1{Schema: 1, RaftIndex: 1,
		EntryHash: entry.EntryHash, QC: wire.StableQC(&entry, []wire.ControlConfigSignatureV1{result.Signature})}
	certificationBody, _ := wire.MarshalCanonical(certification)
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+HeadCertificationPath, bytes.NewReader(certificationBody))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[0].MemberID].Leaf}}
	certificationResponse := httptest.NewRecorder()
	handler.ServeHTTP(certificationResponse, request)
	if certificationResponse.Code != http.StatusOK || store.Snapshot().Active != nil ||
		store.Snapshot().CertifiedHead == nil {
		t.Fatalf("valid head certification status=%d state=%#v",
			certificationResponse.Code, store.Snapshot())
	}
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+HeadCertificationPath, bytes.NewReader(certificationBody))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[0].MemberID].Leaf}}
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, request)
	if retryResponse.Code != http.StatusOK {
		t.Fatalf("exact head certification retry status=%d", retryResponse.Code)
	}

	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+HeadAttestationVotePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatal("head attestation endpoint 接受了无 control-peer mTLS 请求")
	}
}
