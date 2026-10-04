package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var ErrReportEquivocation = errors.New("device signed different reports at one sequence")
var ErrReportReplay = errors.New("device report sequence is below the durable high-water mark")

// This collection preserves the signed observations, including fork evidence.
// Latest values and high-water marks are rebuilt, never separately persisted.
type observationState struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports"`
}

func (state observationState) Validate() error {
	if state.Schema != 3 || state.Reports == nil {
		return errors.New("observation collection schema is invalid")
	}
	var previous []byte
	for index, report := range state.Reports {
		body, err := CanonicalEncode(report)
		if err != nil {
			return err
		}
		if index > 0 && !reportBefore(state.Reports[index-1], previous, report, body) {
			return errors.New("signed observations are not uniquely sorted")
		}
		previous = body
	}
	return nil
}
func reportBefore(left DeviceReport, leftBody []byte, right DeviceReport, rightBody []byte) bool {
	if left.NetworkID != right.NetworkID {
		return left.NetworkID < right.NetworkID
	}
	if left.DeviceID != right.DeviceID {
		return left.DeviceID < right.DeviceID
	}
	if left.ReportSequence != right.ReportSequence {
		return left.ReportSequence < right.ReportSequence
	}
	return bytes.Compare(leftBody, rightBody) < 0
}

type ObservationStore struct {
	path  string
	mu    sync.RWMutex
	state observationState
}

func OpenObservationStore(root string) (*ObservationStore, error) {
	if err := validateControlRoot(root); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(root, ".observations.lock")
	_, previousLockErr := os.Lstat(lockPath)
	_, nodeErr := os.Lstat(filepath.Join(root, "node.json"))
	lock, err := lockProtectedControlPath(context.Background(), lockPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	store := &ObservationStore{path: filepath.Join(root, "observations.json")}
	if err := store.reloadLocked(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if !errors.Is(previousLockErr, os.ErrNotExist) || !errors.Is(nodeErr, os.ErrNotExist) {
			return nil, errors.New("existing observation history is missing; report high-water marks cannot be reinitialized")
		}
		state := observationState{Schema: 3, Reports: []DeviceReport{}}
		body, err := CanonicalEncode(state)
		if err != nil {
			return nil, err
		}
		if err := putControlBytes(store.path, body); err != nil {
			return nil, err
		}
		store.state = state
	}
	return store, nil
}
func (store *ObservationStore) reloadLocked() error {
	body, err := readProtectedControlFile(store.path)
	if err != nil {
		return err
	}
	var state observationState
	if err := DecodeCanonical(body, &state, ContractDecodeLimits{MaxBytes: 64 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	store.state = state
	return nil
}
func cloneReport(report DeviceReport) DeviceReport {
	body, err := CanonicalEncode(report)
	var result DeviceReport
	if err == nil {
		err = DecodeCanonical(body, &result, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
	}
	if err != nil {
		return DeviceReport{}
	}
	return result
}
func (store *ObservationStore) Put(report DeviceReport, publicKey string) error {
	if err := report.Verify(publicKey); err != nil {
		return err
	}
	body, err := CanonicalEncode(report)
	if err != nil {
		return err
	}
	lock, err := lockProtectedControlPath(context.Background(), filepath.Join(filepath.Dir(store.path), ".observations.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.reloadLocked(); err != nil {
		return err
	}
	high := U64(0)
	fork := false
	duplicate := false
	for _, prior := range store.state.Reports {
		if prior.NetworkID != report.NetworkID || prior.DeviceID != report.DeviceID {
			continue
		}
		if err := prior.Verify(publicKey); err != nil {
			return errors.New("stored observation does not verify against the current immutable device key")
		}
		if prior.ReportSequence > high {
			high = prior.ReportSequence
		}
		if prior.ReportSequence == report.ReportSequence {
			old, _ := CanonicalEncode(prior)
			if bytes.Equal(old, body) {
				duplicate = true
				continue
			}
			fork = true
		}
	}
	if duplicate {
		if err := syncControlDirectory(filepath.Dir(store.path)); err != nil {
			return err
		}
		if fork {
			return ErrReportEquivocation
		}
		return nil
	}
	if report.ReportSequence < high {
		return ErrReportReplay
	}
	next := observationState{Schema: 3, Reports: append(append([]DeviceReport{}, store.state.Reports...), cloneReport(report))}
	sort.Slice(next.Reports, func(i, j int) bool {
		a, _ := CanonicalEncode(next.Reports[i])
		b, _ := CanonicalEncode(next.Reports[j])
		return reportBefore(next.Reports[i], a, next.Reports[j], b)
	})
	encoded, err := CanonicalEncode(next)
	if err != nil {
		return err
	}
	if err := atomicWrite(store.path, encoded); err != nil {
		return err
	}
	store.state = next
	if fork {
		return ErrReportEquivocation
	}
	return nil
}

// All is a diagnostic latest-report readback. It never claims freshness or
// applied authorization. A fork at the highest sequence has no chosen winner.
func (store *ObservationStore) All() []DeviceReport {
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []DeviceReport{}
	for index := 0; index < len(store.state.Reports); {
		end := index + 1
		for end < len(store.state.Reports) && store.state.Reports[end].NetworkID == store.state.Reports[index].NetworkID && store.state.Reports[end].DeviceID == store.state.Reports[index].DeviceID {
			end++
		}
		last := store.state.Reports[end-1]
		if end-index == 1 || store.state.Reports[end-2].ReportSequence != last.ReportSequence {
			result = append(result, cloneReport(last))
		}
		index = end
	}
	return result
}
func (store *ObservationStore) History() []DeviceReport {
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]DeviceReport, 0, len(store.state.Reports))
	for _, report := range store.state.Reports {
		result = append(result, cloneReport(report))
	}
	return result
}
func (store *ObservationStore) Verified(projection Projection) []DeviceReport {
	result := []DeviceReport{}
	for _, report := range store.All() {
		if verifyCurrentReport(report, projection) == nil {
			result = append(result, report)
		}
	}
	return result
}
func verifyCurrentReport(report DeviceReport, projection Projection) error {
	if report.NetworkID != projection.NetworkID {
		return errors.New("device report belongs to another network")
	}
	authorization, found := authorizationFor(projection, report.DeviceID)
	if !found || report.Verify(authorization.DevicePublicKey) != nil {
		return errors.New("device report signature or authorization rejected")
	}
	view, err := ProjectDeviceView(projection, report.DeviceID)
	if err != nil {
		return err
	}
	digest, err := DeviceViewDigest(view)
	if err != nil || report.ViewDigest != digest {
		return errors.New("device report view is stale")
	}
	return verifyReportViewFields(report, view)
}
func verifyReportViewFields(report DeviceReport, view DeviceView) error {
	owned := map[string]TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && resource.Kind == "hysteria2" {
			owned[resource.ID] = resource
		}
	}
	if report.Runtime.Resources != nil {
		if report.Runtime.AppliedViewDigest != report.ViewDigest || len(*report.Runtime.Resources) != len(owned) {
			return errors.New("resource readback is not for the complete applied view")
		}
		for _, value := range *report.Runtime.Resources {
			resource, exists := owned[value.ResourceID]
			digest, err := InboundACLDigest(view, value.ResourceID)
			if !exists || resource.ListenerID != value.ListenerID || err != nil || value.ACLDigest != digest {
				return errors.New("resource readback does not match its current listener and ACL")
			}
		}
	} else if len(owned) != 0 && report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest {
		return errors.New("running resource execution has no listener and ACL readback")
	}
	routes := map[string]RouteCandidate{}
	for _, route := range view.Routes {
		routes[route.ID] = route
	}
	for _, selection := range report.Selections {
		route, found := routes[selection.CandidateID]
		if !found || route.ServiceID != selection.ServiceID {
			return errors.New("report selection is outside the current view")
		}
	}
	for _, observation := range report.Observations {
		route, found := routes[observation.CandidateID]
		if !found || observation.Level != "service" || route.ServiceID != observation.ServiceID || route.SpecDigest != observation.SpecDigest {
			return errors.New("report observation specification is outside the current view")
		}
		allowed := false
		for _, set := range view.BusinessProbeTargets {
			if set.ServiceID == observation.ServiceID {
				for _, target := range set.Targets {
					allowed = allowed || target == observation.Target
				}
			}
		}
		if !allowed {
			return errors.New("report observation target is outside the current view")
		}
	}
	return nil
}
