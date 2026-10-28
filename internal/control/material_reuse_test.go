package control

import (
	"reflect"
	"testing"
)

func TestVerifiedCausalReuseMatchesColdAppendPendingForkAndRemoval(t *testing.T) {
	f := newMaterialFixture(t)
	service := f.sign(t, 0, 1, nil, "demo-service-create", "service.put", "service", "demo-service", materialTestService("demo-service"))
	sid := materialTestID(t, service)
	policy := f.sign(t, 1, 1, nil, "demo-policy-create", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-service"), sid)
	fork := f.sign(t, 0, 1, nil, "demo-service-fork", "service.put", "service", "demo-other", materialTestService("demo-other"))
	build := func(values []Material, previous *materialGraph) *materialGraph {
		t.Helper()
		g, e := newMaterialGraph(f.genesis, nil, values)
		if e != nil {
			t.Fatal(e)
		}
		g.reuseValidated(previous)
		actual := g.project()
		cold, e := Project(f.genesis, nil, values)
		if e != nil || !reflect.DeepEqual(actual, cold) {
			t.Fatal("cached causal validation changed effective authority", e)
		}
		return g
	}
	before := build([]Material{service}, nil)
	next, e := newMaterialGraph(f.genesis, nil, []Material{service, policy})
	if e != nil {
		t.Fatal(e)
	}
	next.reuseValidated(before)
	if !next.checked[sid] || next.checked[materialTestID(t, policy)] {
		t.Fatal("did not reuse only verified old input")
	}
	build([]Material{service, policy}, before)
	pending := build([]Material{policy}, nil)
	restored := build([]Material{service, policy}, pending)
	if len(restored.project().PendingMaterialIDs) != 0 {
		t.Fatal("cached a missing-dependency rejection")
	}
	forked := build([]Material{service, policy, fork}, restored)
	if len(forked.project().InvalidMaterials) != 3 {
		t.Fatal("fork did not invalidate its causal descendants")
	}
	missing := build([]Material{policy}, restored)
	if len(missing.project().PendingMaterialIDs) != 1 {
		t.Fatal("removed original remained in cached authority")
	}
	// A changed member table cannot inherit the old admission context even if
	// the old fact's bytes are present. Full proof validation remains upstream.
	changed, e := newMaterialGraph(f.genesis, nil, []Material{service, policy})
	if e != nil {
		t.Fatal(e)
	}
	changed.chain = append([]ControlConfig{}, changed.chain...)
	changed.chain[0].Operation = "delete"
	changed.reuseValidated(restored)
	if len(changed.checked) != 0 {
		t.Fatal("member context change reused causal validation")
	}
}
