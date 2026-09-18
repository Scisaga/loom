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
		authorization, found := authorizationFor(projection, report.DeviceID)
		if found && report.Verify(authorization.DevicePublicKey) == nil {
			verified = append(verified, report)
		}
	}
	return verified
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
