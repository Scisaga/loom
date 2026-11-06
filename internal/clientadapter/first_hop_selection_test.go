package clientadapter

import (
	"bytes"
	"context"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func TestActivationRestoresFirstHopCacheWithoutBorrowingAnotherCredential(t *testing.T) {
	lkg, samples := resourceCacheFixture(t)
	body, err := EncodeResourceObservations(lkg, samples, testPolicyIDs(lkg.View))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeResourceObservations(body, lkg, "demo-underlay", testPolicyIDs(lkg.View))
	if err != nil {
		t.Fatal(err)
	}
	routes, _, err := AccessProjection(lkg.View, testPolicyIDs(lkg.View))
	if err != nil {
		t.Fatal(err)
	}
	failed := samples[1]
	var matching, unrelated clientmodel.RouteCandidate
	for _, route := range routes {
		if route.FirstHop != nil && route.FirstHop.SpecDigest == failed.SpecDigest {
			matching = route
		}
	}
	foreign, err := AccessCandidates(lkg.View, []string{lkg.View.PolicyIDs[1]})
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range foreign {
		if route.FirstHop != nil && route.FirstHop.ResourceID == failed.ResourceID && route.FirstHop.SpecDigest != failed.SpecDigest {
			unrelated = route
			break
		}
	}

	if matching.ID == "" || unrelated.ID == "" || matching.Scope == unrelated.Scope {
		t.Fatal("fixture must have distinct credentials on the same public resource")
	}
	var allowed []clientmodel.RouteCandidate
	for _, route := range routes {
		if route.Scope == matching.Scope || route.ID == unrelated.ID {
			allowed = append(allowed, route)
		}
	}
	selector := &fakeSelector{current: map[string]string{"access": matching.ID}}
	preference, err := clientmodel.ChoosePolicy(clientmodel.EmptyPreference(), lkg.View, matching.PolicyID)
	if err != nil {
		t.Fatal(err)
	}
	state := State{Preference: preference, NetworkGeneration: "demo-underlay", ResourceObservations: restored}
	activation, err := Activate(context.Background(), selector, allowed, state, nil, func() time.Time { return time.UnixMilli(failed.ObservedAt) })
	if err != nil || len(activation.Selections) != 1 || selector.current["access"] == matching.ID || activation.Selections[0].PolicyID != matching.PolicyID {
		t.Fatal("cached authentication failure was ignored or crossed credentials", err)
	}
	for _, selected := range activation.Selections {
		if selected.State != "unknown" {
			t.Fatal("first-hop evidence became Service health")
		}
	}
	after, err := EncodeResourceObservations(lkg, activation.State.ResourceObservations, testPolicyIDs(lkg.View))
	if err != nil || !bytes.Equal(body, after) || len(activation.State.Observations) != 0 {
		t.Fatal("selection changed original cache bytes or manufactured business observations", err)
	}
}
