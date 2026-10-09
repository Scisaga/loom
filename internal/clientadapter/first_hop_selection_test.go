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
	body, err := EncodeResourceObservations(lkg, samples)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeResourceObservations(body, lkg, "demo-underlay")
	if err != nil {
		t.Fatal(err)
	}
	routes, _, err := AccessProjection(lkg.View)
	if err != nil {
		t.Fatal(err)
	}
	failed := samples[1]
	var matching, unrelated clientmodel.RouteCandidate
	for _, route := range routes {
		if route.FirstHop != nil && route.FirstHop.ResourceID == failed.ResourceID {
			matching = route
		}
		for _, authorized := range lkg.View.Routes {
			if authorized.ID == route.ID && authorized.FirstResourceID == failed.ResourceID && route.FirstHop == nil {
				unrelated = route
			}
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
	selector := &fakeSelector{current: map[string]string{matching.Scope: matching.ID, unrelated.Scope: unrelated.ID}}
	state := State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}, NetworkGeneration: "demo-underlay", ResourceObservations: restored}
	activation, err := ActivateServices(context.Background(), selector, allowed, state, nil, func() time.Time { return time.UnixMilli(failed.ObservedAt) })
	if err != nil || len(activation.Selections) != 2 || selector.current[matching.Scope] == matching.ID || selector.current[unrelated.Scope] != unrelated.ID {
		t.Fatal("cached authentication failure was ignored or crossed credentials", err)
	}
	for _, selected := range activation.Selections {
		if selected.State != "unknown" {
			t.Fatal("first-hop evidence became Service health")
		}
	}
	after, err := EncodeResourceObservations(lkg, activation.State.ResourceObservations)
	if err != nil || !bytes.Equal(body, after) || len(activation.State.Observations) != 0 {
		t.Fatal("selection changed original cache bytes or manufactured business observations", err)
	}
}
