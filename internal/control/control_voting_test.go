package control

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func materialAuthorities(t *testing.T, f materialFixture) ([]*Authority, []NodeConfig) {
	t.Helper()
	authorities := []*Authority{}
	configs := []NodeConfig{}
	genesisID, _ := MaterialID(f.genesis)
	for i, member := range f.members {
		parent := t.TempDir()
		root := filepath.Join(parent, "authority")
		keyPath := filepath.Join(parent, "demo-key.pem")
		der, err := x509.MarshalPKCS8PrivateKey(f.keys[i])
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		config := NodeConfig{Schema: 3, NetworkID: f.genesis.NetworkID, ControlID: member.ControlID, NodeID: member.NodeID, GenesisID: genesisID, SigningKeyFile: keyPath}
		a, err := InitializeAuthority(root, config, f.genesis)
		if err != nil {
			t.Fatal(err)
		}
		authorities = append(authorities, a)
		configs = append(configs, config)
	}
	return authorities, configs
}

func emptyRemoval(f materialFixture, promises []ControlPromise, target int) ControlConfig {
	key, _ := KeyID(f.members[target].PublicKey)
	return ControlConfig{Schema: 3, NetworkID: f.genesis.NetworkID, PreviousConfigID: f.configID, Operation: "revoke", TargetNodeID: f.members[target].NodeID, Members: []Member{f.members[1-target]}, SealedKeys: []ControlSealedKey{{KeyID: key, TipMaterialID: emptyMaterialTip()}}, OriginPromises: promises}
}

func TestControlVotingDurablePromisesHistoryAndInterruptedRound(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	ctx := context.Background()
	first, err := a[0].BeginControlRound(ctx, local[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := a[1].PrepareControl(ctx, f.configID, first.Round, local[1])
	if err != nil {
		t.Fatal(err)
	}
	promises := []ControlPromise{first, second}
	proposal := emptyRemoval(f, promises, 1)
	vote, err := a[0].VoteControl(ctx, proposal, first.Round, promises, local[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a[0], err = OpenAuthority(a[0].root)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := a[0].PrepareControl(ctx, f.configID, first.Round, local[0])
	if err != nil || !reflect.DeepEqual(first, prior) {
		t.Fatalf("retry regenerated the original promise after voting: %v", err)
	}
	if again, err := a[0].VoteControl(ctx, proposal, first.Round, promises, local[0], time.Now()); err != nil || !reflect.DeepEqual(again, vote) {
		t.Fatalf("same-round retry changed original vote: %v", err)
	}
	if _, err := a[0].VoteControl(ctx, emptyRemoval(f, promises, 0), first.Round, promises, local[0], time.Now()); err == nil {
		t.Fatal("member signed two different same-round proposals")
	}
	next, err := a[0].BeginControlRound(ctx, local[0])
	if err != nil {
		t.Fatal(err)
	}
	if next.Round.Counter != 2 || len(next.Votes) != 1 || !reflect.DeepEqual(next.Votes[0].Vote, vote) {
		t.Fatal("restart lost durable round or complete vote history")
	}
	if _, err = a[0].PrepareControl(ctx, f.configID, first.Round, local[0]); !errors.Is(err, errControlRoundSuperseded) {
		t.Fatalf("answered a lower prepare after the higher promise: %v", err)
	}
	other, err := a[1].PrepareControl(ctx, f.configID, next.Round, local[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a[1].VoteControl(ctx, proposal, first.Round, promises, local[1], time.Now()); !errors.Is(err, errControlRoundSuperseded) {
		t.Fatalf("late old vote completed an interrupted round: %v", err)
	}
	secondPromises := []ControlPromise{next, other}
	newProposal := emptyRemoval(f, secondPromises, 0)
	cert := ControlCertificate{Config: newProposal, Round: next.Round, Promises: secondPromises, Votes: []ControlVote{}}
	for i := range a {
		v, err := a[i].VoteControl(ctx, newProposal, next.Round, secondPromises, local[i], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		cert.Votes = append(cert.Votes, v)
	}
	body, err := CanonicalEncode(cert)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if err = a[i].AcceptControlCertificate(ctx, body, local[i]); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenAuthority(a[i].root)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reopened.Snapshot().Config, newProposal) {
			t.Fatal("restart did not recover the certified member table")
		}
	}
	if _, err = a[0].Submit(ctx, authorityService("demo-after-retirement", "demo-request"), local[0]); err == nil {
		t.Fatal("retired member still signed ordinary facts")
	}
	if _, err = a[1].Submit(ctx, authorityService("demo-after-successor", "demo-request"), local[1]); err != nil {
		t.Fatalf("retained member cannot sign under its successor: %v", err)
	}
}

func TestControlCertificatePreservesKnownWithdrawalBeforeActivationAndRetry(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	service := f.sign(t, 1, 1, nil, "demo-service", "service.put", "service", "demo-service", materialTestService("demo-service"))
	withdrawn := f.sign(t, 1, 2, &service, "demo-withdraw", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, materialTestID(t, service))
	for _, m := range []Material{service, withdrawn} {
		body, _, _ := EncodeMaterial(m)
		if _, err := a[0].PutMaterial(body); err != nil {
			t.Fatal(err)
		}
	}
	cert := materialRemovalCertificate(t, f, "revoke", service)
	body, _ := CanonicalEncode(cert)
	// Simulate a failure after the ordinary replacement is durable but before
	// the certificate can be published. Only this test-owned obstruction is removed.
	obstruction := filepath.Join(a[0].root, "control-certificates")
	if err := os.WriteFile(obstruction, []byte("demo-obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	// reload itself must reject malformed certificate storage, before signing.
	if err := a[0].AcceptControlCertificate(context.Background(), body, local[0]); err == nil {
		t.Fatal("accepted a malformed certificate directory")
	}
	if err := os.Remove(obstruction); err != nil {
		t.Fatal(err)
	}
	// Persist the same replacement through the pre-activation function, as a
	// process interrupted immediately before certificate publication would do.
	lock, err := lockAuthority(context.Background(), a[0].root)
	if err != nil {
		t.Fatal(err)
	}
	a[0].mu.Lock()
	if err = a[0].reloadLocked(); err == nil {
		err = a[0].preserveRetiredWithdrawals(context.Background(), cert, []ControlCertificate{cert}, local[0])
	}
	a[0].mu.Unlock()
	lock.Close()
	if err != nil {
		t.Fatal(err)
	}
	before := len(a[0].materials)
	a[0], err = OpenAuthority(a[0].root)
	if err != nil {
		t.Fatal(err)
	}
	if err = a[0].AcceptControlCertificate(context.Background(), body, local[0]); err != nil {
		t.Fatal(err)
	}
	if len(a[0].materials) != before || before != 3 {
		t.Fatal("interrupted activation duplicated or lost the withdrawal replacement")
	}
	state, found := a[0].Snapshot().CurrentTarget("service", "demo-service")
	if !found || !state.Deleted || state.Conflicted {
		t.Fatal("certificate activation restored revoked service")
	}
	original, err := a[0].Material(materialTestID(t, withdrawn))
	if err != nil {
		t.Fatal(err)
	}
	expected, _, _ := EncodeMaterial(withdrawn)
	if string(original) != string(expected) {
		t.Fatal("forward preservation rewrote original authenticated bytes")
	}
	if err = a[0].AcceptControlCertificate(context.Background(), body, local[0]); err != nil || len(a[0].materials) != before {
		t.Fatalf("certificate retry changed original facts: %v", err)
	}
}

func TestControlConflictingCertificatesRemainBlockedAfterRestart(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	base := f.genesis.Payload.(Genesis).ControlConfig
	s := successorFixture{base: base, baseID: f.configID, keys: f.keys}
	promises := []ControlPromise{s.promise(t, 0, 1, []ControlVoteHistoryItem{}), s.promise(t, 1, 1, []ControlVoteHistoryItem{})}
	for i, target := range []int{1, 0} {
		proposal := emptyRemoval(f, promises, target)
		cert := ControlCertificate{Config: proposal, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{s.vote(t, 0, 1, proposal), s.vote(t, 1, 1, proposal)}}
		body, err := CanonicalEncode(cert)
		if err != nil {
			t.Fatal(err)
		}
		err = a[0].AcceptControlCertificate(context.Background(), body, local[0])
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 && !errors.Is(err, errControlCertificatesConflict) {
			t.Fatalf("conflicting majority was not rejected: %v", err)
		}
	}
	if a[0].signingReady(local[0]) {
		t.Fatal("conflicting authority still advertises ordinary signing")
	}
	if _, err := a[0].ControlProof(); !errors.Is(err, errControlCertificatesConflict) {
		t.Fatalf("conflicting authority still delivers a selected member proof: %v", err)
	}
	if _, err := OpenAuthority(a[0].root); !errors.Is(err, errControlCertificatesConflict) {
		t.Fatalf("restart selected a winner for conflicting majorities: %v", err)
	}
	files, err := os.ReadDir(filepath.Join(a[0].root, "control-certificates"))
	if err != nil || len(files) != 2 {
		t.Fatalf("conflicting original evidence was discarded: %v", err)
	}
}

func TestControlConflictingMajorityDoesNotRequireUnknownJoinOriginals(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	s := successorFixture{base: f.genesis.Payload.(Genesis).ControlConfig, baseID: f.configID, keys: f.keys}
	promises := []ControlPromise{s.promise(t, 0, 1, []ControlVoteHistoryItem{}), s.promise(t, 1, 1, []ControlVoteHistoryItem{})}
	for i, proposal := range []ControlConfig{emptyRemoval(f, promises, 1), s.addition(t, 1)} {
		cert := ControlCertificate{Config: proposal, Round: promises[0].Round, Promises: proposal.OriginPromises, Votes: []ControlVote{s.vote(t, 0, 1, proposal), s.vote(t, 1, 1, proposal)}}
		body, _ := CanonicalEncode(cert)
		err := a[0].AcceptControlCertificate(context.Background(), body, local[0])
		if i == 0 && err != nil || i == 1 && !errors.Is(err, errControlCertificatesConflict) {
			t.Fatalf("missing secret originals concealed opposing valid majority: %v", err)
		}
	}
	if _, err := OpenAuthority(a[0].root); !errors.Is(err, errControlCertificatesConflict) {
		t.Fatalf("restart lost conflicting certificate with missing join originals: %v", err)
	}
}

func TestControlVoluntaryRetirementPreservesStopAcrossRestart(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	ctx := context.Background()
	prefix, err := a[0].StopOrdinarySigning(ctx, local[0])
	if err != nil {
		t.Fatal(err)
	}
	a[0], err = OpenAuthority(a[0].root)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := a[0].StopOrdinarySigning(ctx, local[0]); err != nil || again != prefix {
		t.Fatalf("restart rewrote durable final prefix: %v", err)
	}
	if _, err := a[0].Submit(ctx, authorityService("demo-after-stop", "demo-request"), local[0]); err == nil {
		t.Fatal("voluntarily stopped key resumed ordinary signing")
	}
	first, err := a[0].BeginControlRound(ctx, local[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := a[1].PrepareControl(ctx, f.configID, first.Round, local[1])
	if err != nil {
		t.Fatal(err)
	}
	promises := []ControlPromise{first, second}
	proposal := emptyRemoval(f, promises, 0)
	proposal.Operation = "resign"
	for i := range a {
		if _, err = a[i].VoteControl(ctx, proposal, first.Round, promises, local[i], time.Now()); err != nil {
			t.Fatalf("stopped ordinary key could not vote for its own retirement: %v", err)
		}
	}
	wrong := emptyRemoval(f, promises, 1)
	wrong.Operation = "resign"
	verifier, _ := newControlSuccessorVerifier(f.genesis.Payload.(Genesis).ControlConfig)
	if verifier.verifyProposal(wrong) == nil {
		t.Fatal("another member's generic prepare was treated as voluntary stop proof")
	}
}

func TestControlObservedDoubleVotesSurviveRestartWithoutBlockingOrdinaryGovernance(t *testing.T) {
	f := newMaterialFixture(t)
	a, local := materialAuthorities(t, f)
	s := successorFixture{base: f.genesis.Payload.(Genesis).ControlConfig, baseID: f.configID, keys: f.keys}
	initial := []ControlPromise{s.promise(t, 0, 1, []ControlVoteHistoryItem{}), s.promise(t, 1, 1, []ControlVoteHistoryItem{})}
	ctx := context.Background()
	for i, target := range []int{0, 1} {
		proposal := emptyRemoval(f, initial, target)
		promise := s.promise(t, 1, U64(i+2), []ControlVoteHistoryItem{{Proposal: proposal, Vote: s.vote(t, 1, 1, proposal)}})
		err := a[0].ObserveControlPromises(ctx, []ControlPromise{promise})
		if i == 0 && err != nil || i == 1 && !errors.Is(err, errControlDoubleVote) {
			t.Fatalf("observed double vote not preserved and rejected: %v", err)
		}
		var openErr error
		a[0], openErr = OpenAuthority(a[0].root)
		if openErr != nil {
			t.Fatal(openErr)
		}
	}
	if _, err := a[0].BeginControlRound(ctx, local[0]); !errors.Is(err, errControlDoubleVote) {
		t.Fatalf("restart forgot observed double vote: %v", err)
	}
	if _, err := a[0].VoteControl(ctx, emptyRemoval(f, initial, 1), initial[0].Round, initial, local[0], time.Now()); !errors.Is(err, errControlDoubleVote) {
		t.Fatalf("direct voting bypassed original conflict: %v", err)
	}
	files, err := os.ReadDir(filepath.Join(a[0].root, "control-observed-promises", strings.TrimPrefix(f.configID, "sha256:")))
	if err != nil || len(files) < 2 {
		t.Fatal("original conflicting replies lost")
	}
	if _, err = a[0].Submit(ctx, authorityService("demo-independent-service", "demo-independent-write"), local[0]); err != nil {
		t.Fatalf("member vote conflict blocked independent ordinary governance: %v", err)
	}
}

func TestControlStoppedRetainedMemberUsesEffectivePeerWithdrawal(t *testing.T) {
	s := newSuccessorFixture(t, 3)
	keyID, _ := KeyID(s.base.Members[0].PublicKey)
	genesis, err := SignMaterial(Material{Schema: 3, NetworkID: s.base.NetworkID, IssuerControlID: s.base.Members[0].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: s.base, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{}}}, s.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	f := materialFixture{genesis: genesis, keys: s.keys, members: s.base.Members, configID: s.baseID}
	peers := membershipTLSPeers(t, f)
	a, local := []*Authority{}, []NodeConfig{}
	for _, peer := range peers {
		a, local = append(a, peer.server.Runtime.Authority), append(local, peer.server.Config)
	}
	service := f.sign(t, 2, 1, nil, "demo-service", "service.put", "service", "demo-service", materialTestService("demo-service"))
	withdrawal := f.sign(t, 2, 2, &service, "demo-retired-withdraw", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, materialTestID(t, service))
	replacement := f.sign(t, 0, 1, nil, "demo-peer-withdraw", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, materialTestID(t, withdrawal))
	for _, fact := range []Material{service, withdrawal, replacement} {
		body, _, _ := EncodeMaterial(fact)
		if _, err = a[0].PutMaterial(body); err != nil {
			t.Fatal(err)
		}
		if fact.RequestID != replacement.RequestID {
			if _, err = a[1].PutMaterial(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = a[1].StopOrdinarySigning(context.Background(), local[1]); err != nil {
		t.Fatal(err)
	}
	key, _ := KeyID(s.base.Members[2].PublicKey)
	seal := ControlSealedKey{KeyID: key, Sequence: 1, TipMaterialID: materialTestID(t, service)}
	promises := []ControlPromise{}
	for i := 0; i < 2; i++ {
		p := s.promise(t, i, 1, []ControlVoteHistoryItem{})
		for j := range p.Prefixes {
			if p.Prefixes[j].KeyID == key {
				p.Prefixes[j] = seal
			}
		}
		p.Signature, err = signControlValue("loom-control-promise-v3\x00", unsignedControlPromise(p), s.keys[i])
		if err != nil {
			t.Fatal(err)
		}
		promises = append(promises, p)
	}
	config := ControlConfig{Schema: 3, NetworkID: s.base.NetworkID, PreviousConfigID: s.baseID, Operation: "revoke", TargetNodeID: s.base.Members[2].NodeID, Members: s.base.Members[:2], SealedKeys: []ControlSealedKey{seal}, OriginPromises: promises}
	cert := ControlCertificate{Config: config, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{s.vote(t, 0, 1, config), s.vote(t, 1, 1, config)}}
	body, _ := CanonicalEncode(cert)
	if err = a[0].AcceptControlCertificate(context.Background(), body, local[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = a[0].Submit(context.Background(), authorityService("demo-after-change", "demo-after-change"), local[0]); err != nil {
		t.Fatal(err)
	}
	if err = peers[1].server.Runtime.reconcilePeer(context.Background(), f.members[0]); err != nil {
		t.Fatal("stopped retained member cannot fetch the effective peer withdrawal before activation", err)
	}
	reopened, err := OpenAuthority(a[1].root)
	if err != nil {
		t.Fatal(err)
	}
	target, found := reopened.Snapshot().CurrentTarget("service", "demo-service")
	if !found || !target.Deleted || target.Conflicted || len(reopened.materials) != 4 || reopened.signingReady(local[1]) {
		t.Fatal("successor activation lost withdrawal or resumed stopped signing")
	}
}
