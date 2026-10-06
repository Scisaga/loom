package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
)

var ErrReportEquivocation = errors.New("device signed different reports at one sequence")
var ErrReportReplay = errors.New("device report sequence is below the durable high-water mark")

// The protected file reader applies this same capacity. A history may contain
// more JSON values than any individual report; its bytes already bound them.
const maxObservationStateBytes = maxControlInputBytes

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
	path      string
	mu        sync.RWMutex
	state     observationState
	canonical []byte                      // Rebuildable decode cache, checked against the protected file under its lock.
	index     atomic.Pointer[reportIndex] // Immutable projection of exact committed bytes; never persisted.
	indexRead chan struct{}               // Bounds snapshot buffers/rebuilds independently of the writer lock.
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
	store := &ObservationStore{path: filepath.Join(root, "observations.json"), indexRead: make(chan struct{}, 1)}
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
		store.canonical = body
	}
	return store, nil
}
func (store *ObservationStore) reloadLocked() error {
	body, err := readProtectedControlFileMatching(store.path, store.canonical)
	if err != nil {
		return err
	}
	if len(store.canonical) != 0 && bytes.Equal(body, store.canonical) {
		return nil
	}
	var state observationState
	if err := DecodeCanonical(body, &state, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 128, MaxItems: len(body)}); err != nil {
		return err
	}
	store.state = state
	store.canonical = body
	if cached := store.index.Load(); cached != nil && !bytes.Equal(cached.canonical, body) {
		store.index.CompareAndSwap(cached, nil)
	}
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
	return store.mergeReports(context.Background(), []DeviceReport{report}, map[reportOwner]string{{report.NetworkID, report.DeviceID}: publicKey}, false)
}

type reportOwner struct{ network, device string }
type reportPosition struct {
	owner    reportOwner
	sequence U64
}

// Member history and direct uploads share one writer and the same original
// collection. Only authenticated member exchange may fill an unknown old slot.
func (store *ObservationStore) mergeReportHistory(ctx context.Context, reports []DeviceReport, projection Projection) error {
	keys := map[reportOwner]string{}
	for _, report := range reports {
		authorization, ok := authorizationFor(projection, report.DeviceID)
		if !ok || report.NetworkID != projection.NetworkID {
			return errors.New("peer report is outside current device authorization")
		}
		keys[reportOwner{report.NetworkID, report.DeviceID}] = authorization.DevicePublicKey
	}
	return store.mergeReports(ctx, reports, keys, true)
}

func (store *ObservationStore) mergeReports(ctx context.Context, reports []DeviceReport, keys map[reportOwner]string, historical bool) error {
	if len(reports) == 0 {
		return errors.New("empty report merge")
	}
	bodies := make([][]byte, len(reports))
	positions := map[reportPosition]bool{}
	for i, report := range reports {
		if err := report.Verify(keys[reportOwner{report.NetworkID, report.DeviceID}]); err != nil {
			return err
		}
		body, err := CanonicalEncode(report)
		if err != nil || len(body) > controlHTTPBodyLimit {
			return errors.New("report exceeds its input boundary")
		}
		bodies[i] = body
		positions[reportPosition{reportOwner{report.NetworkID, report.DeviceID}, report.ReportSequence}] = true
	}
	lock, err := lockProtectedControlPath(ctx, filepath.Join(filepath.Dir(store.path), ".observations.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.reloadLocked(); err != nil {
		return err
	}
	high := map[reportOwner]U64{}
	known := map[reportPosition]map[string]bool{}
	for _, prior := range store.state.Reports {
		owner := reportOwner{prior.NetworkID, prior.DeviceID}
		publicKey, concerned := keys[owner]
		if !concerned {
			continue
		}
		if err := prior.Verify(publicKey); err != nil {
			return errors.New("stored observation does not verify against the current immutable device key")
		}
		if prior.ReportSequence > high[owner] {
			high[owner] = prior.ReportSequence
		}
		position := reportPosition{owner, prior.ReportSequence}
		if !positions[position] {
			continue
		}
		if known[position] == nil {
			known[position] = map[string]bool{}
		}
		body, _ := CanonicalEncode(prior)
		known[position][ReleaseDigest(body)] = true
	}
	additions := []DeviceReport{}
	fork := false
	for i, report := range reports {
		owner := reportOwner{report.NetworkID, report.DeviceID}
		position := reportPosition{owner, report.ReportSequence}
		id := ReleaseDigest(bodies[i])
		ids := known[position]
		if ids[id] {
			fork = fork || len(ids) > 1
			continue
		}
		if !historical && report.ReportSequence < high[owner] && len(ids) == 0 {
			return ErrReportReplay
		}
		fork = fork || len(ids) > 0
		if ids == nil {
			ids = map[string]bool{}
			known[position] = ids
		}
		ids[id] = true
		copy := cloneReport(report)
		if copy.Schema != 3 {
			return errors.New("report cannot round trip through its input boundary")
		}
		additions = append(additions, copy)
	}
	if len(additions) == 0 {
		if err := syncControlDirectory(filepath.Dir(store.path)); err != nil {
			return err
		}
		if fork {
			return ErrReportEquivocation
		}
		return nil
	}
	less := func(left, right DeviceReport) bool {
		var leftBody, rightBody []byte
		if left.NetworkID == right.NetworkID && left.DeviceID == right.DeviceID && left.ReportSequence == right.ReportSequence {
			leftBody, _ = CanonicalEncode(left)
			rightBody, _ = CanonicalEncode(right)
		}
		return reportBefore(left, leftBody, right, rightBody)
	}
	sort.Slice(additions, func(i, j int) bool { return less(additions[i], additions[j]) })
	next := observationState{Schema: 3, Reports: make([]DeviceReport, 0, len(store.state.Reports)+len(additions))}
	index := 0
	for _, report := range additions {
		for index < len(store.state.Reports) && less(store.state.Reports[index], report) {
			next.Reports = append(next.Reports, store.state.Reports[index])
			index++
		}
		next.Reports = append(next.Reports, report)
	}
	next.Reports = append(next.Reports, store.state.Reports[index:]...)
	encoded, err := CanonicalEncode(next)
	if err != nil {
		return err
	}
	var nextIndex *reportIndex
	if cached := store.index.Load(); cached != nil && bytes.Equal(cached.canonical, store.canonical) {
		// Prepare the disposable projection before the file becomes visible.
		// Failure only drops the cache; it cannot change persistence semantics.
		nextIndex, _ = cached.withReports(additions)
		if nextIndex != nil {
			nextIndex.canonical = encoded
		}
	}
	if err := writeObservationState(store.path, encoded); err != nil {
		return err
	}
	store.index.Store(nextIndex)
	store.state = next
	store.canonical = encoded
	if fork {
		return ErrReportEquivocation
	}
	return nil
}

func writeObservationState(path string, body []byte) error {
	if len(body) > maxObservationStateBytes {
		return errors.New("observation history exceeds the current reader resource bound")
	}
	return atomicWrite(path, body)
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
func (store *ObservationStore) Verified(projection Projection, releases ...ReleaseSet) []DeviceReport {
	result := []DeviceReport{}
	for _, report := range store.All() {
		if verifyCurrentReport(report, projection, releases...) == nil {
			result = append(result, report)
		}
	}
	return result
}
func verifyCurrentReport(report DeviceReport, projection Projection, releases ...ReleaseSet) error {
	if report.NetworkID != projection.NetworkID {
		return errors.New("device report belongs to another network")
	}
	authorization, found := authorizationFor(projection, report.DeviceID)
	if !found || report.Verify(authorization.DevicePublicKey) != nil {
		return errors.New("device report signature or authorization rejected")
	}
	view, err := ProjectDeviceView(projection, report.DeviceID, releases...)
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
