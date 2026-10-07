package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

type successorFixture struct {
	base   ControlConfig
	keys   []ed25519.PrivateKey
	baseID string
}

func newSuccessorFixture(t *testing.T, count int) successorFixture {
	t.Helper()
	f := successorFixture{base: ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: []Member{}, SealedKeys: []ControlSealedKey{}}}
	for i := 0; i < count; i++ {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, key)
		f.base.Members = append(f.base.Members, Member{ControlID: fmt.Sprintf("demo-control-%d", i), NodeID: fmt.Sprintf("demo-node-%d", i), PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	}
	id, err := ConfigID(f.base)
	if err != nil {
		t.Fatal(err)
	}
	f.baseID = id
	return f
}

func TestControlSuccessorRejectsDoubleVoteHiddenInInheritedProposal(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	first, contradictory := f.addition(t, 1), f.addition(t, 1)
	second := f.addition(t, 2)
	second.OriginPromises = []ControlPromise{
		f.promise(t, 0, 2, []ControlVoteHistoryItem{}),
		f.promise(t, 1, 2, []ControlVoteHistoryItem{{Proposal: first, Vote: f.vote(t, 1, 1, first)}}),
		f.promise(t, 2, 2, []ControlVoteHistoryItem{}),
	}
	// All three second-round replies prove that the first proposal was not
	// selected. In round three the missing member makes second-round value
	// possible; its original proof also exposes the responder's old double vote.
	promises := []ControlPromise{
		f.promise(t, 0, 3, []ControlVoteHistoryItem{{Proposal: second, Vote: f.vote(t, 0, 2, second)}}),
		f.promise(t, 1, 3, []ControlVoteHistoryItem{{Proposal: contradictory, Vote: f.vote(t, 1, 1, contradictory)}}),
	}
	cert := ControlCertificate{Config: second, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{f.vote(t, 0, 3, second), f.vote(t, 1, 3, second)}}
	verifier, _ := newControlSuccessorVerifier(f.base)
	if err := verifier.verifyCertificate(cert); !errors.Is(err, errControlDoubleVote) {
		t.Fatalf("nested same-round double vote escaped proof verification: %v", err)
	}
}
func (f successorFixture) promise(t *testing.T, who int, round U64, history []ControlVoteHistoryItem) ControlPromise {
	t.Helper()
	p := ControlPromise{Schema: 3, NetworkID: f.base.NetworkID, BaseConfigID: f.baseID, Round: ControlRound{round, f.base.Members[0].ControlID}, ResponderControlID: f.base.Members[who].ControlID, Votes: history, Prefixes: []ControlSealedKey{}}
	for _, member := range f.base.Members {
		key, _ := KeyID(member.PublicKey)
		p.Prefixes = append(p.Prefixes, ControlSealedKey{KeyID: key, TipMaterialID: emptyMaterialTip()})
	}
	sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].KeyID < p.Prefixes[j].KeyID })
	signed, err := signControlValue("loom-control-promise-v3\x00", unsignedControlPromise(p), f.keys[who])
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = signed
	return p
}
func (f successorFixture) vote(t *testing.T, who int, round U64, proposal ControlConfig) ControlVote {
	t.Helper()
	id, err := ConfigID(proposal)
	if err != nil {
		t.Fatal(err)
	}
	v := ControlVote{Schema: 3, NetworkID: f.base.NetworkID, BaseConfigID: f.baseID, Round: ControlRound{round, f.base.Members[0].ControlID}, ProposalID: id, VoterControlID: f.base.Members[who].ControlID}
	signature, err := signControlValue("loom-control-vote-v3\x00", unsignedControlVote(v), f.keys[who])
	if err != nil {
		t.Fatal(err)
	}
	v.Signature = signature
	return v
}
func (f successorFixture) addition(t *testing.T, round U64) ControlConfig {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := ControlJoinBinding{TransactionID: "demo-invite", InviteMaterialID: endpointByteDigest([]byte("demo-invite")), BindingMaterialID: endpointByteDigest([]byte("demo-bind")), DevicePublicKey: base64.RawURLEncoding.EncodeToString(public)}
	proposal := ControlConfig{Schema: 3, NetworkID: f.base.NetworkID, PreviousConfigID: f.baseID, Operation: "add", TargetNodeID: "demo-node-new", Members: append([]Member{}, f.base.Members...), SealedKeys: []ControlSealedKey{}, OriginPromises: []ControlPromise{}, Join: &binding}
	proposal.Members = append(proposal.Members, Member{ControlID: proposal.TargetNodeID, NodeID: proposal.TargetNodeID, PublicKey: binding.DevicePublicKey})
	for i := 0; i < len(f.base.Members)/2+1; i++ {
		proposal.OriginPromises = append(proposal.OriginPromises, f.promise(t, i, round, []ControlVoteHistoryItem{}))
	}
	return proposal
}

func TestControlSuccessorExactMajorityAndOriginalMessages(t *testing.T) {
	for _, count := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newSuccessorFixture(t, count)
			proposal := f.addition(t, 1)
			cert := ControlCertificate{Config: proposal, Round: proposal.OriginPromises[0].Round, Promises: proposal.OriginPromises, Votes: []ControlVote{}}
			for i := 0; i < count/2+1; i++ {
				cert.Votes = append(cert.Votes, f.vote(t, i, 1, proposal))
			}
			verifier, err := newControlSuccessorVerifier(f.base)
			if err != nil {
				t.Fatal(err)
			}
			if err = verifier.verifyCertificate(cert); err != nil {
				t.Fatal(err)
			}
			body, err := CanonicalEncode(cert)
			if err != nil {
				t.Fatal(err)
			}
			var decoded ControlCertificate
			if err = DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 1 << 16}); err != nil || !reflect.DeepEqual(decoded, cert) {
				t.Fatalf("canonical certificate: %v", err)
			}
			fewer := cert
			fewer.Votes = append([]ControlVote{}, cert.Votes[:len(cert.Votes)-1]...)
			if verifier.verifyCertificate(fewer) == nil {
				t.Fatal("accepted missing old-member majority")
			}
			altered := cert
			altered.Votes = append([]ControlVote{}, cert.Votes...)
			altered.Votes[0].ProposalID = endpointByteDigest([]byte("demo-other"))
			if verifier.verifyCertificate(altered) == nil {
				t.Fatal("accepted votes for another complete proposal")
			}
		})
	}
}

func TestControlSuccessorRecoversKnownValueWithoutInventingOldCertificate(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	proposal := f.addition(t, 1)
	first := f.vote(t, 0, 1, proposal)
	secondA, secondB := f.vote(t, 0, 2, proposal), f.vote(t, 1, 2, proposal)
	promises := []ControlPromise{
		f.promise(t, 0, 3, []ControlVoteHistoryItem{{proposal, first}, {proposal, secondA}}),
		f.promise(t, 1, 3, []ControlVoteHistoryItem{{proposal, secondB}}),
	}
	selected, chosen, err := chooseControlProposal(f.base, promises)
	if err != nil || !chosen || !reflect.DeepEqual(selected, &proposal) {
		t.Fatalf("lost certificate changed selected value: %v", err)
	}
	cert := ControlCertificate{Config: proposal, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{f.vote(t, 0, 3, proposal), f.vote(t, 1, 3, proposal)}}
	verifier, _ := newControlSuccessorVerifier(f.base)
	if err = verifier.verifyCertificate(cert); err != nil {
		t.Fatal(err)
	}
	// These real round-2 votes have no matching round-2 promises here. They cannot
	// be put into a certificate with either the origin or current promises.
	forged := cert
	forged.Round = secondA.Round
	forged.Votes = []ControlVote{secondA, secondB}
	if verifier.verifyCertificate(forged) == nil {
		t.Fatal("combined current promises with earlier votes")
	}
	forged.Promises = proposal.OriginPromises
	if verifier.verifyCertificate(forged) == nil {
		t.Fatal("combined original promises with later votes")
	}
}

func TestControlSuccessorExactRoundsAndHighestAmbiguity(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	a, b := f.addition(t, 1), f.addition(t, 1)
	av, bv := f.vote(t, 0, 1, a), f.vote(t, 1, 1, b)
	replies := []ControlPromise{f.promise(t, 0, 2, []ControlVoteHistoryItem{{a, av}}), f.promise(t, 1, 2, []ControlVoteHistoryItem{{b, bv}})}
	if _, _, err := chooseControlProposal(f.base, replies); !errors.Is(err, errControlRoundAmbiguous) {
		t.Fatalf("highest ambiguous round: %v", err)
	}
	all := append(append([]ControlPromise{}, replies...), f.promise(t, 2, 2, []ControlVoteHistoryItem{}))
	if selected, chosen, err := chooseControlProposal(f.base, all); err != nil || selected != nil || chosen {
		t.Fatalf("all replies prove no old majority: %v", err)
	}
	all[2] = f.promise(t, 2, 2, []ControlVoteHistoryItem{{a, f.vote(t, 2, 1, a)}})
	if selected, chosen, err := chooseControlProposal(f.base, all); err != nil || !chosen || !reflect.DeepEqual(selected, &a) {
		t.Fatalf("actual same-round majority: %v", err)
	}
	// A later unique possible value resolves the lower-round fork.
	higherA := f.vote(t, 0, 2, a)
	replies = []ControlPromise{f.promise(t, 0, 3, []ControlVoteHistoryItem{{a, av}, {a, higherA}}), f.promise(t, 1, 3, []ControlVoteHistoryItem{{b, bv}})}
	if selected, chosen, err := chooseControlProposal(f.base, replies); err != nil || chosen || !reflect.DeepEqual(selected, &a) {
		t.Fatalf("lower fork prevented highest unique value: %v", err)
	}
	two := newSuccessorFixture(t, 2)
	old := two.addition(t, 1)
	oldVote := two.vote(t, 0, 1, old)
	round2 := []ControlPromise{two.promise(t, 0, 2, []ControlVoteHistoryItem{{old, oldVote}}), two.promise(t, 1, 2, []ControlVoteHistoryItem{})}
	next := two.addition(t, 2)
	next.OriginPromises = round2
	nextVote := two.vote(t, 1, 2, next)
	round3 := []ControlPromise{two.promise(t, 0, 3, []ControlVoteHistoryItem{{old, oldVote}}), two.promise(t, 1, 3, []ControlVoteHistoryItem{{next, nextVote}})}
	if selected, chosen, err := chooseControlProposal(two.base, round3); err != nil || chosen || selected != nil {
		t.Fatalf("combined votes from different rounds: %v", err)
	}
}

func TestControlSuccessorSealsOnlyOriginalPrefixesAndRetiredKeys(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	proposal := f.addition(t, 1)
	retired := f.base.Members[2]
	keyID, _ := KeyID(retired.PublicKey)
	proposal.Operation = "revoke"
	proposal.Join = nil
	proposal.TargetNodeID = retired.NodeID
	proposal.Members = append([]Member{}, f.base.Members[:2]...)
	proposal.SealedKeys = []ControlSealedKey{{KeyID: keyID, TipMaterialID: emptyMaterialTip()}}
	certificate := func(f successorFixture, config ControlConfig) ControlCertificate {
		c := ControlCertificate{Config: config, Round: config.OriginPromises[0].Round, Promises: config.OriginPromises, Votes: []ControlVote{}}
		for i := 0; i < len(f.base.Members)/2+1; i++ {
			c.Votes = append(c.Votes, f.vote(t, i, c.Round.Counter, config))
		}
		return c
	}
	first := certificate(f, proposal)
	if _, err := verifyControlSuccessors(f.base, []ControlCertificate{first}); err != nil {
		t.Fatal(err)
	}
	inflated := proposal
	inflated.SealedKeys = []ControlSealedKey{{KeyID: keyID, Sequence: 9, TipMaterialID: endpointByteDigest([]byte("demo-fabricated-prefix"))}}
	verifier, _ := newControlSuccessorVerifier(f.base)
	if verifier.verifyCertificate(certificate(f, inflated)) == nil {
		t.Fatal("accepted a seal without its original signed maximum")
	}
	wrong := proposal
	wrong.SealedKeys = append([]ControlSealedKey{}, proposal.SealedKeys...)
	wrong.SealedKeys[0].KeyID, _ = KeyID(f.base.Members[0].PublicKey)
	if verifier.verifyCertificate(certificate(f, wrong)) == nil {
		t.Fatal("sealed a retained member")
	}
	nextFixture := f
	nextFixture.base = proposal
	nextFixture.baseID, _ = ConfigID(proposal)
	next := nextFixture.addition(t, 1)
	next.Join.DevicePublicKey = retired.PublicKey
	next.Members[len(next.Members)-1].PublicKey = retired.PublicKey
	second := certificate(nextFixture, next)
	if _, err := verifyControlSuccessors(f.base, []ControlCertificate{first, second}); err == nil {
		t.Fatal("reopened a permanently sealed key through a later addition")
	}
}
