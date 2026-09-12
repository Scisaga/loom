package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type enrollmentProjectorFixture struct {
	mu         sync.Mutex
	operations map[string]wire.ControlOperationLeafV1
}

type toggledRaftPeer struct {
	mu      sync.Mutex
	enabled bool
	storage *RaftStorage
}

func (peer *toggledRaftPeer) setEnabled(enabled bool) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.enabled = enabled
}

func (peer *toggledRaftPeer) RequestVote(_ context.Context,
	request VoteRequestV1) (VoteResultV1, error) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if !peer.enabled {
		return VoteResultV1{}, errors.New("unavailable")
	}
	return peer.storage.HandleVote(request)
}

func (peer *toggledRaftPeer) AppendEntries(_ context.Context,
	request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if !peer.enabled {
		return AppendEntriesResultV1{}, errors.New("unavailable")
	}
	return peer.storage.HandleAppendEntries(request)
}

func newEnrollmentProjectorFixture() *enrollmentProjectorFixture {
	return &enrollmentProjectorFixture{operations: make(map[string]wire.ControlOperationLeafV1)}
}

func (projector *enrollmentProjectorFixture) Project(_ context.Context, parent wire.HeadEntryV2,
	coordinate enrollmentv2.EnrollmentCommitCoordinateV1,
	mutation enrollmentv2.EnrollmentHeadMutationV1) (EnrollmentHeadProjectionV1, error) {
	projector.mu.Lock()
	defer projector.mu.Unlock()
	if existing, found := projector.operations[mutation.OperationLeaf.OperationID]; found &&
		!wire.EqualCanonical(existing, mutation.OperationLeaf) {
		return EnrollmentHeadProjectionV1{}, errors.New("operation first-result conflict")
	}
	projector.operations[mutation.OperationLeaf.OperationID] = mutation.OperationLeaf
	leaves := make([]wire.ControlOperationLeafV1, 0, len(projector.operations))
	for _, leaf := range projector.operations {
		leaves = append(leaves, leaf)
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].OperationID < leaves[j].OperationID })
	root, err := wire.ControlOperationRoot(leaves)
	if err != nil {
		return EnrollmentHeadProjectionV1{}, err
	}
	leaf, leafIndex, treeSize, auditPath, err := wire.ControlOperationInclusionProof(
		leaves, mutation.OperationLeaf.OperationID)
	if err != nil || !wire.EqualCanonical(leaf, mutation.OperationLeaf) {
		return EnrollmentHeadProjectionV1{}, errors.New("operation proof construction failed")
	}
	payload := parent.Body.Payload
	payload.HeadKind = "ordinary"
	payload.RaftTerm = coordinate.RaftTerm
	payload.RaftIndex = coordinate.RaftIndex
	payload.PreviousLogEntryHash = coordinate.PreviousLogEntryHash
	payload.ControlRevision = coordinate.RaftIndex
	payload.ParentHeadHash = coordinate.ParentHeadHash
	payload.OperationRoot = root
	payload.SnapshotHash = wire.HashRaw("enrollment-sequencer-test", []byte(root))
	payload.CommittedLogicalTime = coordinate.CommittedLogicalTime
	payload.TransitionContext, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	projection := EnrollmentHeadProjectionV1{OperationLeafIndex: leafIndex,
		OperationTreeSize: treeSize, OperationAuditPath: auditPath}
	if mutation.InitialDeviceView != nil {
		viewHash, err := wire.DeviceViewHash(mutation.InitialDeviceView)
		if err != nil {
			return EnrollmentHeadProjectionV1{}, err
		}
		view := mutation.InitialDeviceView
		viewLeaf := wire.DeviceViewLeafV2{Schema: 2, ClusterID: view.ClusterID,
			ViewSchemaVersion: 2, DeviceID: view.DeviceID, DeviceGeneration: view.DeviceGeneration,
			State: view.State, PayloadHash: viewHash, PreviousViewHash: wire.EmptyHashV1,
			EndpointSetHash: view.Active.EndpointBundleHash, MinReaderVersion: 2}
		canonical, _ := wire.MarshalCanonical(viewLeaf)
		payload.DeviceViewsRoot = "sha256:" + hex.EncodeToString(wire.MerkleRoot([][]byte{canonical}))
		projection.DeviceViewLeaf = &viewLeaf
		projection.DeviceViewTreeSize = 1
		projection.DeviceViewAuditPath = []string{}
	}
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: payload,
		TransitionProofHash: parent.Body.TransitionProofHash})
	if err != nil {
		return EnrollmentHeadProjectionV1{}, err
	}
	projection.Head = head
	return projection, nil
}

func TestStableEnrollmentSequencerCommitsJournalsAndReplaysExactResult(t *testing.T) {
	fixture := newStableEnrollmentSequencerFixture(t)
	operationID := "enrollment-operation-1"
	objectID := wire.HashRaw("enrollment-sequencer-test", []byte("operation-1"))
	buildCalls := 0
	result, err := fixture.sequencer.CommitEnrollmentOperation(context.Background(), operationID, nil,
		func(coordinate enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
			buildCalls++
			if coordinate.RaftIndex != 2 || coordinate.ParentHeadHash != fixture.bootstrap.HeadHash {
				return enrollmentv2.EnrollmentHeadMutationV1{}, errors.New("wrong coordinate")
			}
			return enrollmentv2.EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: operationID, ObjectID: objectID}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if buildCalls != 1 || result.Certification.OperationLeaf.ObjectID != objectID ||
		result.DeviceViewEnvelope != nil || fixture.storage.SnapshotRaft().CommitIndex != 2 ||
		fixture.storage.SnapshotRaft().LastApplied != 2 || fixture.store.Snapshot().Active != nil {
		t.Fatalf("sequenced result/state 无效: result=%#v raft=%#v control=%#v",
			result, fixture.storage.SnapshotRaft(), fixture.store.Snapshot())
	}
	replayed, err := fixture.sequencer.CommitEnrollmentOperation(context.Background(), operationID, nil,
		func(enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
			t.Fatal("durable journal replay 不应再次调用 builder")
			return enrollmentv2.EnrollmentHeadMutationV1{}, nil
		})
	if err != nil || !wire.EqualCanonical(replayed, result) {
		t.Fatalf("journal replay changed result: %#v err=%v", replayed, err)
	}
	reopenedJournal, err := OpenEnrollmentCommitJournal(fixture.journal.path, fixture.set)
	if err != nil {
		t.Fatal(err)
	}
	reopenedSequencer, err := NewStableEnrollmentOperationSequencer(fixture.storage, fixture.store,
		fixture.leader, fixture.collector, reopenedJournal, fixture.projector.Project,
		fixture.recompute, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	reopenedResult, err := reopenedSequencer.CommitEnrollmentOperation(context.Background(), operationID, nil,
		func(enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
			t.Fatal("reopened journal replay 不应再次调用 builder")
			return enrollmentv2.EnrollmentHeadMutationV1{}, nil
		})
	if err != nil || !wire.EqualCanonical(reopenedResult, result) {
		t.Fatalf("reopened journal result changed: %#v err=%v", reopenedResult, err)
	}
}

func TestStableEnrollmentSequencerCertifiesDeviceViewOnSameHead(t *testing.T) {
	fixture := newStableEnrollmentSequencerFixture(t)
	first := commitSequencerOperation(t, fixture, "enrollment-operation-1", nil, nil)
	view, refs := enrollmentSequencerDeviceView(t)
	second := commitSequencerOperation(t, fixture, "enrollment-operation-2",
		&first.Certification.Head, func() enrollmentv2.EnrollmentHeadMutationV1 {
			objectID := wire.HashRaw("enrollment-sequencer-test", []byte("operation-2"))
			return enrollmentv2.EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: "enrollment-operation-2", ObjectID: objectID},
				InitialDeviceView: &view, SecretArtifactRefs: refs}
		})
	if second.DeviceViewEnvelope == nil ||
		!wire.EqualCanonical(second.DeviceViewEnvelope.SignedCurrent.Head, second.Certification.Head) ||
		len(second.IntermediateHeads) != 0 {
		t.Fatalf("completion view/head binding 无效: %#v", second)
	}
	if _, err := wire.VerifyDeviceViewEnvelope(second.DeviceViewEnvelope, &fixture.set); err != nil {
		t.Fatalf("same-head Device envelope verification failed: %v", err)
	}
}

func TestStableEnrollmentSequencerRecoversCertifiedHeadBeforeJournalWrite(t *testing.T) {
	fixture := newStableEnrollmentSequencerFixture(t)
	operationID := "enrollment-operation-crash"
	objectID := wire.HashRaw("enrollment-sequencer-test", []byte("crash"))
	raft := fixture.storage.SnapshotRaft()
	coordinate, err := fixture.sequencer.nextCoordinate(&raft, &fixture.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	mutation := enrollmentv2.EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
		Schema: 1, OperationID: operationID, ObjectID: objectID}}
	projection, err := fixture.projector.Project(context.Background(), fixture.bootstrap, coordinate, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.leader.ReplicateHead(context.Background(), fixture.store, projection.Head); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyCommittedPrefix(context.Background(), fixture.storage, fixture.store,
		fixture.recompute); err != nil {
		t.Fatal(err)
	}
	if err := fixture.collector.CertifyActive(context.Background(), fixture.store); err != nil {
		t.Fatal(err)
	}
	if active := fixture.store.Snapshot().Active; active == nil || active.Phase != PhaseCertified {
		t.Fatalf("crash fixture 未停在 certified-before-journal: %#v", active)
	}
	result, err := fixture.sequencer.CommitEnrollmentOperation(context.Background(), operationID, nil,
		func(got enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
			if !wire.EqualCanonical(got, coordinate) {
				return enrollmentv2.EnrollmentHeadMutationV1{}, errors.New("recovery coordinate changed")
			}
			return mutation, nil
		})
	if err != nil || result.Certification.Head.EntryHash != projection.Head.EntryHash ||
		fixture.store.Snapshot().Active != nil {
		t.Fatalf("certified-before-journal recovery failed: result=%#v err=%v", result, err)
	}
}

func TestStableEnrollmentSequencerRetriesExactUncommittedTail(t *testing.T) {
	set, configKeys := testControlSet(t, 3)
	directory := t.TempDir()
	storages := make([]*RaftStorage, len(set.Members))
	for index := range set.Members {
		var err error
		storages[index], err = OpenRaftStorage(filepath.Join(directory, set.Members[index].MemberID+".json"),
			set.Members[index].MemberID, set)
		if err != nil {
			t.Fatal(err)
		}
	}
	toggles := []*toggledRaftPeer{
		{enabled: true, storage: storages[1]},
		{enabled: true, storage: storages[2]},
	}
	leader, err := CampaignStableRaft(context.Background(), storages[0], set, map[string]RaftPeer{
		set.Members[1].MemberID: toggles[0], set.Members[2].MemberID: toggles[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := Open(filepath.Join(directory, "control.json"), set)
	recompute := HeadRecomputer(func(context.Context, wire.HeadEntryV2) error { return nil })
	voters := make(map[string]HeadAttestationPeer, len(set.Members))
	for index, member := range set.Members {
		voter, err := NewHeadAttestationVoter(storages[index], set, member.MemberID,
			configKeys[member.MemberID], recompute)
		if err != nil {
			t.Fatal(err)
		}
		voters[member.MemberID] = voter
	}
	collector, _ := NewHeadAttestationCollector(set, voters)
	bootstrap := testControlHead(t, &set)
	if _, err := leader.ReplicateHead(context.Background(), store, bootstrap); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyCommittedPrefix(context.Background(), storages[0], store, recompute); err != nil {
		t.Fatal(err)
	}
	if err := collector.CertifyActive(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(bootstrap.EntryHash); err != nil {
		t.Fatal(err)
	}
	journal, _ := OpenEnrollmentCommitJournal(filepath.Join(directory, "journal.json"), set)
	projector := newEnrollmentProjectorFixture()
	sequencer, err := NewStableEnrollmentOperationSequencer(storages[0], store, leader, collector,
		journal, projector.Project, recompute,
		func() time.Time { return time.Date(2026, 9, 11, 0, 1, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range toggles {
		peer.setEnabled(false)
	}
	operationID := "enrollment-operation-retry"
	objectID := wire.HashRaw("enrollment-sequencer-test", []byte("retry"))
	coordinates := make([]enrollmentv2.EnrollmentCommitCoordinateV1, 0, 2)
	build := func(coordinate enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
		coordinates = append(coordinates, coordinate)
		return enrollmentv2.EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
			Schema: 1, OperationID: operationID, ObjectID: objectID}}, nil
	}
	if _, err := sequencer.CommitEnrollmentOperation(context.Background(), operationID, nil, build); err == nil {
		t.Fatal("minority unexpectedly committed enrollment Head")
	}
	state := storages[0].SnapshotRaft()
	if len(state.Log) != 2 || state.CommitIndex != 1 || store.Snapshot().Active != nil {
		t.Fatalf("failed attempt did not leave one exact uncommitted tail: %#v", state)
	}
	toggles[0].setEnabled(true)
	result, err := sequencer.CommitEnrollmentOperation(context.Background(), operationID, nil, build)
	if err != nil {
		t.Fatal(err)
	}
	if len(coordinates) != 2 || !wire.EqualCanonical(coordinates[0], coordinates[1]) ||
		result.Certification.Head.Body.Payload.RaftIndex != 2 || len(storages[0].SnapshotRaft().Log) != 2 {
		t.Fatalf("retry did not reuse exact tail coordinate/result: coordinates=%#v result=%#v",
			coordinates, result)
	}
}

type stableEnrollmentSequencerFixture struct {
	set       wire.ControlSetV1
	storage   *RaftStorage
	store     *Store
	leader    *StableRaftLeader
	collector *HeadAttestationCollector
	journal   *EnrollmentCommitJournal
	projector *enrollmentProjectorFixture
	recompute HeadRecomputer
	now       func() time.Time
	bootstrap wire.HeadEntryV2
	sequencer *StableEnrollmentOperationSequencer
}

func newStableEnrollmentSequencerFixture(t *testing.T) stableEnrollmentSequencerFixture {
	t.Helper()
	set, configKeys := testControlSet(t, 1)
	directory := t.TempDir()
	storage, err := OpenRaftStorage(filepath.Join(directory, "raft.json"), set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := CampaignStableRaft(context.Background(), storage, set, map[string]RaftPeer{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(directory, "control.json"), set)
	if err != nil {
		t.Fatal(err)
	}
	recompute := HeadRecomputer(func(context.Context, wire.HeadEntryV2) error { return nil })
	voter, err := NewHeadAttestationVoter(storage, set, set.Members[0].MemberID,
		configKeys[set.Members[0].MemberID], recompute)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewHeadAttestationCollector(set,
		map[string]HeadAttestationPeer{set.Members[0].MemberID: voter})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := testControlHead(t, &set)
	if _, err := leader.ReplicateHead(context.Background(), store, bootstrap); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyCommittedPrefix(context.Background(), storage, store, recompute); err != nil {
		t.Fatal(err)
	}
	if err := collector.CertifyActive(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(bootstrap.EntryHash); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenEnrollmentCommitJournal(filepath.Join(directory, "enrollment-commits.json"), set)
	if err != nil {
		t.Fatal(err)
	}
	projector := newEnrollmentProjectorFixture()
	now := func() time.Time { return time.Date(2026, 9, 11, 0, 1, 0, 0, time.UTC) }
	sequencer, err := NewStableEnrollmentOperationSequencer(storage, store, leader, collector,
		journal, projector.Project, recompute, now)
	if err != nil {
		t.Fatal(err)
	}
	return stableEnrollmentSequencerFixture{set: set, storage: storage, store: store,
		leader: leader, collector: collector, journal: journal, projector: projector,
		recompute: recompute, now: now, bootstrap: bootstrap, sequencer: sequencer}
}

func commitSequencerOperation(t *testing.T, fixture stableEnrollmentSequencerFixture,
	operationID string, lineageFrom *wire.HeadEntryV2,
	mutationFactory func() enrollmentv2.EnrollmentHeadMutationV1) enrollmentv2.EnrollmentOperationCommitResultV1 {
	t.Helper()
	result, err := fixture.sequencer.CommitEnrollmentOperation(context.Background(), operationID, lineageFrom,
		func(enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
			if mutationFactory != nil {
				return mutationFactory(), nil
			}
			return enrollmentv2.EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: operationID,
				ObjectID: wire.HashRaw("enrollment-sequencer-test", []byte(operationID))}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func enrollmentSequencerDeviceView(t *testing.T) (wire.DeviceViewPayloadV2, []json.RawMessage) {
	t.Helper()
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	endpoint := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: "cluster", DeviceID: "demo-device",
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	endpointHash, _ := wire.DeviceEndpointBundleHash(&endpoint)
	refs := []json.RawMessage{}
	refsRoot, err := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	if err != nil {
		t.Fatal(err)
	}
	view := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: "cluster", DeviceID: "demo-device",
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: wire.HashRaw("enrollment-sequencer-test", []byte("identity")),
			Membership:       membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: grants, GrantsHash: grantsHash, EndpointBundle: endpoint,
			EndpointBundleHash: endpointHash, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{},
			SecretArtifactRefsRoot: refsRoot}}
	if _, err := wire.DeviceViewHash(&view); err != nil {
		t.Fatal(err)
	}
	return view, refs
}
