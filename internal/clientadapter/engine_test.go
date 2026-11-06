package clientadapter

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

type fakeSelector struct {
	snapshots         map[string]clientmodel.Selection
	revision          control.U64
	current           map[string]string
	readAs            string
	targets           map[string]string
	elapsed           int64
	closed            int
	supersede         bool
	advanceAfterApply bool
}

func (s *fakeSelector) Read(_ context.Context, scope string) (string, error) {
	if s.readAs != "" {
		return s.readAs, nil
	}
	v, ok := s.current[scope]
	if !ok {
		return "", errors.New("missing selector")
	}
	return v, nil
}
func (s *fakeSelector) Set(ctx context.Context, scope, id string) error {
	before, err := s.ReadSelection(ctx, scope)
	if err != nil {
		return err
	}
	_, err = s.ApplySelection(ctx, before, clientmodel.Selection{Scope: scope, CandidateID: id, Targets: map[string]string{}})
	return err
}
func (s *fakeSelector) CloseConnections(context.Context, []string) error { s.closed++; return nil }
func (s *fakeSelector) ElapsedMillis() int64                             { return s.elapsed }
func (s *fakeSelector) ReadSelection(ctx context.Context, scope string) (clientmodel.Selection, error) {
	id, err := s.Read(ctx, scope)
	if err != nil {
		return clientmodel.Selection{}, err
	}
	values := map[string]string{}
	maps.Copy(values, s.targets)
	value := s.snapshots[scope]
	value.Scope, value.CandidateID, value.Targets, value.Revision = scope, id, values, strconv.FormatUint(uint64(s.revision), 10)
	return value, nil
}
func (s *fakeSelector) ApplySelection(_ context.Context, expected, desired clientmodel.Selection) (clientmodel.Selection, error) {
	if s.supersede {
		s.current[expected.Scope] = "demo-user-choice"
		return clientmodel.Selection{}, ErrSelectionSuperseded
	}
	if strconv.FormatUint(uint64(s.revision), 10) != expected.Revision || s.current[expected.Scope] != expected.CandidateID || !maps.Equal(s.targets, expected.Targets) {
		return clientmodel.Selection{}, ErrSelectionSuperseded
	}
	if s.snapshots == nil {
		s.snapshots = map[string]clientmodel.Selection{}
	}
	s.snapshots[desired.Scope] = desired
	s.current[desired.Scope] = desired.CandidateID
	s.targets = maps.Clone(desired.Targets)
	s.revision++
	desired.Revision = strconv.FormatUint(uint64(s.revision), 10)
	if s.advanceAfterApply {
		s.revision++ // A later operation reapplied the identical choice.
	}
	return desired, nil
}
func engineEvidence() (time.Time, []clientmodel.RouteCandidate, []control.Observation) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{}
	samples := []control.Observation{}
	for i, id := range []string{"demo-fast", "demo-slow"} {
		spec := control.ReleaseDigest([]byte(id))
		metric := int64(10 + i*30)
		routes = append(routes, clientmodel.RouteCandidate{ID: engineCandidateID(id), EntryNodeID: "demo-exit", FirstResourceID: id, PolicyID: "demo-policy", FixedExit: true, SourceNode: "demo-access", Scope: "service:demo-service", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, FirstHop: &clientmodel.ResourceSampleRef{ResourceID: id, SpecDigest: spec, Target: "192.0.2.1:51820", Action: "wireguard_echo"}})
		samples = append(samples, control.Observation{Level: "resource", ResourceID: id, SpecDigest: spec, Target: "192.0.2.1:51820", Action: "wireguard_echo", NetworkGeneration: "demo-network", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), Result: "available", RoundTripMS: new(metric), DurationMS: new(metric + 1)})
	}
	return at, routes, samples
}
func TestActivationWithoutProbeURLsAppliesAndReadsOnePolicy(t *testing.T) {
	at, routes, _ := engineEvidence()
	s := &fakeSelector{current: map[string]string{"access": "reject"}}
	result, err := Activate(context.Background(), s, routes, State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network"}, nil, func() time.Time { return at })
	if err != nil || len(result.Selections) != 1 || result.Selections[0].PolicyID != "demo-policy" || result.Selections[0].State != "unknown" || len(result.State.Observations) != 0 {
		t.Fatal("no URLs prevented connectivity or selector readback manufactured business health", result, err)
	}
	if s.closed != 0 {
		t.Fatal("initial routing closed unrelated connections")
	}
}
func TestStableOptimizationAffectsNewConnectionsWithoutClosingExistingOnes(t *testing.T) {
	at, routes, samples := engineEvidence()
	s := &fakeSelector{current: map[string]string{"access": engineCandidateID("demo-slow")}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", ResourceObservations: samples}
	first, err := Activate(context.Background(), s, routes, state, nil, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if first.Selections[0].CandidateID != engineCandidateID("demo-slow") {
		t.Fatal("unconfirmed improvement was applied")
	}
	for i := range samples {
		samples[i].ObservedAt += 20_000
		samples[i].ValidUntil += 20_000
	}
	s.elapsed = 35_000
	second, err := Activate(context.Background(), s, routes, first.State, nil, func() time.Time { return at.Add(35 * time.Second) })
	if err != nil || second.Selections[0].CandidateID != engineCandidateID("demo-fast") || s.closed != 0 || len(second.State.Observations) != 0 {
		t.Fatal("sustained update closed flows or manufactured URL samples", second, err, s.closed)
	}
}
func TestSupersededActivationPreservesTheNewUserSelection(t *testing.T) {
	at, routes, samples := engineEvidence()
	s := &fakeSelector{current: map[string]string{"access": "reject"}, supersede: true}
	_, err := Activate(context.Background(), s, routes, State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", ResourceObservations: samples}, nil, func() time.Time { return at })
	if !errors.Is(err, ErrSelectionSuperseded) || s.current["access"] != "demo-user-choice" || s.closed != 0 {
		t.Fatal("stale optimization overwrote or closed the user choice", err)
	}
}

func TestActivationDoesNotConfirmAnIdenticalChoiceAppliedByALaterOperation(t *testing.T) {
	at, routes, samples := engineEvidence()
	s := &fakeSelector{current: map[string]string{"access": "reject"}, advanceAfterApply: true}
	result, err := Activate(context.Background(), s, routes, State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", ResourceObservations: samples}, nil, func() time.Time { return at })
	if !errors.Is(err, ErrSelectionSuperseded) || len(result.State.SelectionMemory[control.AccessSelectorScope].Decisions) != 0 || s.closed != 0 {
		t.Fatal("later identical operation was confirmed as this optimization", err, result.State.SelectionMemory)
	}
}

func engineCandidateID(resource string) string {
	value, _ := protocol.CandidateID("demo-service", "demo-policy", protocol.RouteChoice{EntryNodeID: "demo-exit", FirstResourceID: resource, FinalExit: "demo-exit"})
	return value
}
