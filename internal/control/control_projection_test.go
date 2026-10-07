package control

import (
	"reflect"
	"sort"
	"testing"
)

func TestControlDeviceProofAllowsOnlyCertifiedRetiredPrefix(t *testing.T) {
	f, proof, p := deviceContractFixture(t)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	sealedMaterial := f.sign(t, 1, 1, nil, "demo-service", "service.put", "service", "demo-service", materialTestService("demo-service"))
	cert := materialRemovalCertificate(t, f, "revoke", sealedMaterial)
	retained, _ := KeyID(f.members[0].PublicKey)
	retired, _ := KeyID(f.members[1].PublicKey)
	previous := DeviceViewEnvelope{Schema: 3, NetworkID: f.genesis.NetworkID, GenesisDigest: materialTestID(t, f.genesis), IssuerControlID: f.members[0].ControlID, IssuerKeyID: retained, ControlProof: proof, View: view, FactFrontier: []FactFrontier{{KeyID: retained, Sequence: 4, TipMaterialID: endpointByteDigest([]byte("demo-retained"))}, {KeyID: retired, Sequence: 9, TipMaterialID: endpointByteDigest([]byte("demo-original-high-water"))}}}
	sort.Slice(previous.FactFrontier, func(i, j int) bool { return previous.FactFrontier[i].KeyID < previous.FactFrontier[j].KeyID })
	previous, err = SignDeviceViewEnvelope(previous, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	next := previous
	next.ControlProof = ControlProof{Genesis: f.genesis, Successors: []ControlCertificate{cert}}
	next.FactFrontier = append([]FactFrontier{}, previous.FactFrontier...)
	for i := range next.FactFrontier {
		if next.FactFrontier[i].KeyID == retired {
			next.FactFrontier[i] = cert.Config.SealedKeys[0]
		}
	}
	next, err = SignDeviceViewEnvelope(next, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckDeviceViewAdvance(next, previous, previous.FactFrontier); err != nil {
		t.Fatalf("certified retirement rejected preserved original high-water: %v", err)
	}
	if err = CheckDeviceViewAdvance(next, next, previous.FactFrontier); err != nil {
		t.Fatalf("reopened device cannot retain evidence above seal: %v", err)
	}
	bad := next
	bad.FactFrontier = append([]FactFrontier{}, next.FactFrontier...)
	for i := range bad.FactFrontier {
		if bad.FactFrontier[i].KeyID == retained {
			bad.FactFrontier[i].Sequence--
		}
	}
	bad, err = SignDeviceViewEnvelope(bad, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if CheckDeviceViewAdvance(bad, previous, previous.FactFrontier) == nil {
		t.Fatal("retirement exception rolled back an unrelated retained key")
	}
	if CheckDeviceViewAdvance(previous, next, previous.FactFrontier) == nil {
		t.Fatal("device discarded an accepted member successor")
	}
}

func materialRemovalCertificate(t *testing.T, f materialFixture, operation string, prefix Material) ControlCertificate {
	t.Helper()
	base := f.genesis.Payload.(Genesis).ControlConfig
	s := successorFixture{base: base, keys: f.keys, baseID: f.configID}
	key, _ := KeyID(f.members[1].PublicKey)
	seal := ControlSealedKey{KeyID: key, Sequence: prefix.Sequence, TipMaterialID: materialTestID(t, prefix)}
	promises := []ControlPromise{}
	for i := range base.Members {
		p := s.promise(t, i, 1, []ControlVoteHistoryItem{})
		for j := range p.Prefixes {
			if p.Prefixes[j].KeyID == key {
				p.Prefixes[j] = seal
			}
		}
		var err error
		p.Signature, err = signControlValue("loom-control-promise-v3\x00", unsignedControlPromise(p), f.keys[i])
		if err != nil {
			t.Fatal(err)
		}
		promises = append(promises, p)
	}
	c := ControlConfig{Schema: 3, NetworkID: base.NetworkID, PreviousConfigID: f.configID, Operation: operation, TargetNodeID: base.Members[1].NodeID, Members: append([]Member{}, base.Members[:1]...), SealedKeys: []ControlSealedKey{seal}, OriginPromises: promises}
	return ControlCertificate{Config: c, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{s.vote(t, 0, 1, c), s.vote(t, 1, 1, c)}}
}

func TestControlProjectionRetiredEvidenceDoesNotInterruptIndependentWithdrawal(t *testing.T) {
	f := newMaterialFixture(t)
	service := f.sign(t, 1, 1, nil, "demo-service", "service.put", "service", "demo-service", materialTestService("demo-service"))
	sid := materialTestID(t, service)
	withdrawn := f.sign(t, 1, 2, &service, "demo-withdraw", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, sid)
	wid := materialTestID(t, withdrawn)
	independent := f.sign(t, 0, 1, nil, "demo-retained-withdraw", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, wid)
	unrelated := f.sign(t, 0, 2, &independent, "demo-unrelated", "service.put", "service", "demo-unrelated", materialTestService("demo-unrelated"))
	cert := materialRemovalCertificate(t, f, "revoke", service)
	facts := []Material{unrelated, withdrawn, service, independent}
	p, err := Project(f.genesis, []ControlCertificate{cert}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.InvalidMaterials) != 0 || len(p.PendingMaterialIDs) != 0 {
		t.Fatalf("valid evidence invalidated a retained signer: %+v", p.InvalidMaterials)
	}
	state, found := p.CurrentTarget("service", "demo-service")
	if !found || !state.Deleted || state.Conflicted {
		t.Fatal("independent retained withdrawal stopped applying")
	}
	if len(p.NetworkIntent.Services) != 1 || p.NetworkIntent.Services[0].ID != "demo-unrelated" {
		t.Fatal("unrelated retained fact was lost")
	}
	retained, _ := KeyID(f.members[0].PublicKey)
	retired, _ := KeyID(f.members[1].PublicKey)
	if frontierFor(p.Frontier, retained).Sequence != 2 || frontierFor(p.Frontier, retired).Sequence != 1 {
		t.Fatal("retained sequence or certified retirement frontier changed")
	}
	// The certificate does allow a device without the original withdrawal to
	// accept the sealed prefix. Local activation must re-sign known withdrawals.
	without, err := Project(f.genesis, []ControlCertificate{cert}, []Material{service, withdrawn})
	if err != nil || len(without.NetworkIntent.Services) != 1 {
		t.Fatalf("retired evidence became an extra local authority: %v", err)
	}
	for i, j := 0, len(facts)-1; i < j; i, j = i+1, j-1 {
		facts[i], facts[j] = facts[j], facts[i]
	}
	again, err := Project(f.genesis, []ControlCertificate{cert}, facts)
	if err != nil || !reflect.DeepEqual(p, again) {
		t.Fatalf("arrival order changed member projection: %v", err)
	}
	newF := f
	newF.configID, _ = ConfigID(cert.Config)
	next := newF.sign(t, 0, 3, &unrelated, "demo-after-successor", "service.put", "service", "demo-next", materialTestService("demo-next"))
	if err = ValidateAdmission(next, f.genesis, []ControlCertificate{cert}, facts); err != nil {
		t.Fatalf("retained sequence cannot cross member change: %v", err)
	}
}

func TestControlProjectionDoesNotGrantThroughSealedBusinessReference(t *testing.T) {
	f := newMaterialFixture(t)
	base := f.sign(t, 1, 1, nil, "demo-base", "service.put", "service", "demo-base", materialTestService("demo-base"))
	late := f.sign(t, 1, 2, &base, "demo-late", "service.put", "service", "demo-late", materialTestService("demo-late"))
	policy := f.sign(t, 0, 1, nil, "demo-policy", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-late"), materialTestID(t, late))
	independent := f.sign(t, 0, 2, &policy, "demo-independent", "service.put", "service", "demo-independent", materialTestService("demo-independent"))
	facts := []Material{base, late, policy, independent}
	before, err := Project(f.genesis, nil, facts)
	if err != nil || len(before.NetworkIntent.Policies) != 1 {
		t.Fatalf("fixture policy is not an original valid grant: %v", err)
	}
	cert := materialRemovalCertificate(t, f, "revoke", base)
	after, err := Project(f.genesis, []ControlCertificate{cert}, facts)
	if err != nil || len(after.InvalidMaterials) != 0 || len(after.NetworkIntent.Policies) != 0 {
		t.Fatalf("sealed business reference remained effective: %v", err)
	}
	if len(after.NetworkIntent.Services) != 2 {
		t.Fatal("unrelated facts following the suppressed grant did not survive")
	}
	key, _ := KeyID(f.members[0].PublicKey)
	if frontierFor(after.Frontier, key).Sequence != 2 {
		t.Fatal("projection eligibility interrupted a valid original signing chain")
	}
}
