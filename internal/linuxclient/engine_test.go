package linuxclient

import (
	"context"
	"maps"
	"strconv"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

type fakeSelector struct {
	snapshots map[string]clientmodel.Selection
	revision  control.U64
	current   map[string]string
	targets   map[string]string
	closed    int
}

func (s *fakeSelector) Read(_ context.Context, scope string) (string, error) {
	return s.current[scope], nil
}
func (s *fakeSelector) Set(ctx context.Context, scope, id string) error {
	expected, _ := s.ReadSelection(ctx, scope)
	_, err := s.ApplySelection(ctx, expected, clientmodel.Selection{Scope: scope, CandidateID: id, Targets: map[string]string{}})
	return err
}
func (s *fakeSelector) CloseConnections(context.Context, []string) error { s.closed++; return nil }
func (s *fakeSelector) ElapsedMillis() int64                             { return 0 }
func (s *fakeSelector) ReadSelection(_ context.Context, scope string) (clientmodel.Selection, error) {
	m := map[string]string{}
	maps.Copy(m, s.targets)
	value := s.snapshots[scope]
	value.Scope, value.CandidateID, value.Targets, value.Revision = scope, s.current[scope], m, strconv.FormatUint(uint64(s.revision), 10)
	return value, nil
}
func (s *fakeSelector) ApplySelection(_ context.Context, expected, desired clientmodel.Selection) (clientmodel.Selection, error) {
	if strconv.FormatUint(uint64(s.revision), 10) != expected.Revision || s.current[expected.Scope] != expected.CandidateID || !maps.Equal(s.targets, expected.Targets) {
		return clientmodel.Selection{}, clientadapter.ErrSelectionSuperseded
	}
	if s.snapshots == nil {
		s.snapshots = map[string]clientmodel.Selection{}
	}
	s.snapshots[desired.Scope] = desired
	s.current[desired.Scope] = desired.CandidateID
	s.targets = maps.Clone(desired.Targets)
	s.revision++
	desired.Revision = strconv.FormatUint(uint64(s.revision), 10)
	return desired, nil
}
func TestLinuxActivationKeepsOnePolicyAndDoesNotRequireProbeURLs(t *testing.T) {
	s := &fakeSelector{current: map[string]string{"access": "reject"}}
	routes := []clientmodel.RouteCandidate{{ID: "demo-direct", PolicyID: "demo-policy", Scope: "service:demo-service", SourceNode: "demo-access", FinalExit: "direct", Chain: []string{}}}
	state := defaultState("demo-network")
	state.Preference = clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	result, err := Activate(context.Background(), s, routes, state, nil, func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil || len(result.Selections) != 1 || result.Selections[0].State != "unknown" || s.closed != 0 || len(result.State.Observations) != 0 || result.State.SelectionMemory[control.AccessSelectorScope].PolicyID != "demo-policy" {
		t.Fatal("Linux did not consume the shared model or invented a business sample", result, err)
	}
}
