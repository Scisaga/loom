package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/crdt"
	"loom/internal/wire"
)

func TestCRDTAntiEntropyHandlerAndClientConvergeBothStores(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	receiver, err := crdt.Open(filepath.Join(t.TempDir(), "receiver.json"))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := crdt.Open(filepath.Join(t.TempDir(), "sender.json"))
	if err != nil {
		t.Fatal(err)
	}
	left, _ := crdt.NewObject("object-a", "proposal", []byte(`{"value":1}`))
	right, _ := crdt.NewObject("object-b", "proposal", []byte(`{"value":2}`))
	if err := sender.Add(left); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(right); err != nil {
		t.Fatal(err)
	}
	var verified atomic.Int32
	verify := func(_ context.Context, object crdt.Object) error {
		verified.Add(1)
		if object.Kind != "proposal" {
			return errors.New("unknown kind")
		}
		return nil
	}
	handler, err := NewCRDTAntiEntropyHTTPHandler(set.Members[0].MemberID,
		receiver, set, directory, now, verify)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	})
	client, err := NewCRDTAntiEntropyPeerClient("https://10.20.0.1:7443",
		set.Members[1].MemberID, set.Members[0].MemberID, certificates[set.Members[1].MemberID],
		set, directory, sender, now, verify)
	if err != nil {
		t.Fatal(err)
	}
	client.client = &http.Client{Transport: transport}
	result, err := client.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	senderRoot, _ := sender.Root()
	receiverRoot, _ := receiver.Root()
	if senderRoot != receiverRoot || result.LocalRoot != receiverRoot ||
		len(sender.Snapshot()) != 2 || len(receiver.Snapshot()) != 2 || result.SentObjects != 1 ||
		result.ReceivedObjects != 2 || verified.Load() != 6 {
		t.Fatalf("anti-entropy 未收敛: sender=%s receiver=%s result=%#v verified=%d",
			senderRoot, receiverRoot, result, verified.Load())
	}
}

func TestCRDTAntiEntropyRejectsConflictAtomicallyAndBindsMTLSMember(t *testing.T) {
	set, _ := testControlSet(t, 3)
	directory, certificates := raftDirectoryFixture(t, set)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	store, _ := crdt.Open(filepath.Join(t.TempDir(), "receiver.json"))
	existing, _ := crdt.NewObject("same", "proposal", []byte(`{"value":1}`))
	before, _ := crdt.NewObject("before", "proposal", []byte(`{"value":2}`))
	conflict, _ := crdt.NewObject("same", "proposal", []byte(`{"value":3}`))
	if err := store.Add(existing); err != nil {
		t.Fatal(err)
	}
	handler, err := NewCRDTAntiEntropyHTTPHandler(set.Members[0].MemberID,
		store, set, directory, now, func(_ context.Context, object crdt.Object) error {
			if object.Kind != "proposal" {
				return errors.New("unknown kind")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	objects := []crdt.Object{before, conflict}
	root, _ := crdt.SnapshotRoot(objects)
	submitted := CRDTAntiEntropyRequestV1{Schema: 1,
		SenderMemberID: set.Members[1].MemberID, SenderRoot: root, Objects: objects}
	body, _ := wire.MarshalCanonical(submitted)
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+CRDTAntiEntropyPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || len(store.Snapshot()) != 1 ||
		store.Snapshot()[0].ObjectID != existing.ObjectID {
		t.Fatalf("conflict merge 泄漏部分对象: status=%d state=%#v", response.Code, store.Snapshot())
	}

	wrongMember := submitted
	wrongMember.SenderMemberID = set.Members[2].MemberID
	body, _ = wire.MarshalCanonical(wrongMember)
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+CRDTAntiEntropyPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusBadRequest || len(store.Snapshot()) != 1 {
		t.Fatalf("mTLS/body member mismatch 未被拒绝: status=%d", denied.Code)
	}

	unknown, _ := crdt.NewObject("unknown", "unregistered", []byte(`{"value":4}`))
	unknownObjects := []crdt.Object{unknown}
	unknownRoot, _ := crdt.SnapshotRoot(unknownObjects)
	body, _ = wire.MarshalCanonical(CRDTAntiEntropyRequestV1{Schema: 1,
		SenderMemberID: set.Members[1].MemberID, SenderRoot: unknownRoot, Objects: unknownObjects})
	request = httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+CRDTAntiEntropyPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificates[set.Members[1].MemberID].Leaf}}
	denied = httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusBadRequest || len(store.Snapshot()) != 1 {
		t.Fatalf("unknown typed object 在验证前进入 store: status=%d", denied.Code)
	}
}

func TestJointCRDTAntiEntropyAcceptsNewSideWithoutShrinkingAuthority(t *testing.T) {
	oldSet, _ := testControlSet(t, 1)
	newSet, _ := testControlSet(t, 3)
	oldDirectory, _ := raftDirectoryFixture(t, oldSet)
	newDirectory, newCertificates := raftDirectoryFixture(t, newSet)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	store, _ := crdt.Open(filepath.Join(t.TempDir(), "joint.json"))
	handler, err := NewJointCRDTAntiEntropyHTTPHandler(oldSet.Members[0].MemberID,
		store, oldSet, newSet, oldDirectory, newDirectory, now,
		func(context.Context, crdt.Object) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	newOnly := newSet.Members[1].MemberID
	objects := []crdt.Object{}
	root, _ := crdt.SnapshotRoot(objects)
	body, _ := wire.MarshalCanonical(CRDTAntiEntropyRequestV1{Schema: 1,
		SenderMemberID: newOnly, SenderRoot: root, Objects: objects})
	request := httptest.NewRequest(http.MethodPost,
		"https://10.20.0.1:7443"+CRDTAntiEntropyPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{newCertificates[newOnly].Leaf}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("Joint handler 拒绝 new-side peer: status=%d body=%s", response.Code, response.Body.String())
	}
	// 同步 CRDT material 不会调用 Raft、改变 ControlSet 或缩小 quorum；响应仅含 immutable objects/root。
	var result CRDTAntiEntropyResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), crdtPeerMaxBody, &result)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) || result.ReceiverMemberID != oldSet.Members[0].MemberID {
		t.Fatalf("Joint anti-entropy response 无效: %#v err=%v", result, err)
	}
}

func TestLearnerCRDTAntiEntropyPushesMaterialsFromOldStableVoter(t *testing.T) {
	oldSet, _ := testControlSet(t, 1)
	newSet, _ := testControlSet(t, 3)
	oldDirectory, oldCertificates := raftDirectoryFixture(t, oldSet)
	newDirectory, _ := raftDirectoryFixture(t, newSet)
	now := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	learnerID := newSet.Members[1].MemberID
	receiver, _ := crdt.Open(filepath.Join(t.TempDir(), "learner.json"))
	sender, _ := crdt.Open(filepath.Join(t.TempDir(), "leader.json"))
	object, _ := crdt.NewObject("head-material", "proposal", []byte(`{"value":1}`))
	if err := sender.Add(object); err != nil {
		t.Fatal(err)
	}
	verify := func(_ context.Context, object crdt.Object) error {
		if object.Kind != "proposal" {
			return errors.New("unknown kind")
		}
		return nil
	}
	handler, err := NewLearnerCRDTAntiEntropyHTTPHandler(learnerID, receiver,
		oldSet, newSet, oldDirectory, newDirectory, now, verify)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := newDirectory.Members[1].PeerEndpoints[0].URL
	client, err := NewLearnerCRDTAntiEntropyPeerClient(endpoint,
		oldSet.Members[0].MemberID, learnerID, oldCertificates[oldSet.Members[0].MemberID],
		oldSet, newSet, oldDirectory, newDirectory, sender, now, verify)
	if err != nil {
		t.Fatal(err)
	}
	client.client = &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{oldCertificates[oldSet.Members[0].MemberID].Leaf}}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
	result, err := client.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	senderRoot, _ := sender.Root()
	receiverRoot, _ := receiver.Root()
	if senderRoot != receiverRoot || result.LocalRoot != receiverRoot || len(receiver.Snapshot()) != 1 {
		t.Fatalf("learner material 未收敛: sender=%s receiver=%s result=%#v",
			senderRoot, receiverRoot, result)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
