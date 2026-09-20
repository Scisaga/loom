package control

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type observationState struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports"`
}

type ObservationStore struct {
	path  string
	mu    sync.RWMutex
	state observationState
}

func OpenObservationStore(root string) (*ObservationStore, error) {
	store := &ObservationStore{path: filepath.Join(root, "observations.json"), state: observationState{Schema: 1, Reports: []DeviceReport{}}}
	if err := readStrict(store.path, &store.state); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := atomicJSON(store.path, store.state); err != nil {
			return nil, err
		}
	}
	if store.state.Schema != 1 {
		return nil, errors.New("observation store schema is invalid")
	}
	for index, report := range store.state.Reports {
		if report.validate(false, "") != nil || index > 0 && store.state.Reports[index-1].DeviceID >= report.DeviceID {
			return nil, errors.New("observation store is invalid")
		}
	}
	return store, nil
}

func (store *ObservationStore) Put(report DeviceReport, publicKey string) error {
	if report.Verify(publicKey) != nil {
		return errors.New("device report is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := sort.Search(len(store.state.Reports), func(index int) bool { return store.state.Reports[index].DeviceID >= report.DeviceID })
	if index < len(store.state.Reports) && store.state.Reports[index].DeviceID == report.DeviceID {
		previous, _ := time.Parse(time.RFC3339, store.state.Reports[index].ReportedAt)
		next, _ := time.Parse(time.RFC3339, report.ReportedAt)
		if !next.After(previous) {
			return errors.New("device report does not advance")
		}
		nextState := store.state
		nextState.Reports = append([]DeviceReport(nil), store.state.Reports...)
		nextState.Reports[index] = report
		if err := atomicJSON(store.path, nextState); err != nil {
			return err
		}
		store.state = nextState
		return nil
	}
	nextState := store.state
	nextState.Reports = append([]DeviceReport(nil), store.state.Reports...)
	nextState.Reports = append(nextState.Reports, DeviceReport{})
	copy(nextState.Reports[index+1:], nextState.Reports[index:])
	nextState.Reports[index] = report
	if err := atomicJSON(store.path, nextState); err != nil {
		return err
	}
	store.state = nextState
	return nil
}

// Merge accepts the latest still-current report for each device from another
// control member. Replays are harmless: an equal or older report is ignored.
func (store *ObservationStore) Merge(reports []DeviceReport, projection Projection) (int, error) {
	if store == nil {
		return 0, errors.New("observation store is unavailable")
	}
	for index, report := range reports {
		if index > 0 && reports[index-1].DeviceID >= report.DeviceID {
			return 0, errors.New("device reports are not uniquely sorted")
		}
		if err := verifyCurrentReport(report, projection); err != nil {
			return 0, err
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	nextState := store.state
	nextState.Reports = append([]DeviceReport(nil), store.state.Reports...)
	merged := 0
	for _, report := range reports {
		index := sort.Search(len(nextState.Reports), func(index int) bool {
			return nextState.Reports[index].DeviceID >= report.DeviceID
		})
		if index < len(nextState.Reports) && nextState.Reports[index].DeviceID == report.DeviceID {
			previous, _ := time.Parse(time.RFC3339, nextState.Reports[index].ReportedAt)
			next, _ := time.Parse(time.RFC3339, report.ReportedAt)
			if !next.After(previous) {
				continue
			}
			nextState.Reports[index] = report
			merged++
			continue
		}
		nextState.Reports = append(nextState.Reports, DeviceReport{})
		copy(nextState.Reports[index+1:], nextState.Reports[index:])
		nextState.Reports[index] = report
		merged++
	}
	if merged == 0 {
		return 0, nil
	}
	if err := atomicJSON(store.path, nextState); err != nil {
		return 0, err
	}
	store.state = nextState
	return merged, nil
}

func (store *ObservationStore) All() []DeviceReport {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]DeviceReport(nil), store.state.Reports...)
}

func (store *ObservationStore) Verified(projection Projection) []DeviceReport {
	if store == nil {
		return nil
	}
	verified := []DeviceReport{}
	for _, report := range store.All() {
		if verifyCurrentReport(report, projection) == nil {
			verified = append(verified, report)
		}
	}
	return verified
}

func verifyCurrentReport(report DeviceReport, projection Projection) error {
	authorization, found := authorizationFor(projection, report.DeviceID)
	if !found || report.Verify(authorization.DevicePublicKey) != nil {
		return errors.New("device report signature rejected")
	}
	view, found := projectDeviceView(projection, report.DeviceID)
	if !found {
		return errors.New("device report view is unavailable")
	}
	digest, err := DeviceViewDigest(view)
	if err != nil || report.ViewDigest != digest {
		return errors.New("device report view is stale")
	}
	return nil
}

func (store *ObservationStore) Project(projection *WebProjection, authority Projection, now time.Time) {
	if store == nil || projection == nil {
		return
	}
	for _, report := range store.Verified(authority) {
		available, unavailable, current := false, false, 0
		for _, observation := range report.Observations {
			until, err := time.Parse(time.RFC3339, observation.ValidUntil)
			if err != nil || !now.Before(until) {
				continue
			}
			current++
			available = available || observation.Result == "available"
			unavailable = unavailable || observation.Result == "unavailable"
			for index := range projection.Paths {
				if projection.Paths[index].Device == report.DeviceID && projection.Paths[index].CandidateID == observation.CandidateID {
					projection.Paths[index].Availability = observation.Result
				}
			}
		}
		state := "unknown"
		if available {
			state = "available"
		} else if current > 0 && unavailable {
			state = "unavailable"
		}
		for index := range projection.Devices {
			if projection.Devices[index].ID == report.DeviceID {
				projection.Devices[index].Availability = state
			}
		}
		for index := range projection.Paths {
			if projection.Paths[index].Device == report.DeviceID {
				projection.Paths[index].Selected = projection.Paths[index].CandidateID == report.Selection
			}
		}
	}
}
