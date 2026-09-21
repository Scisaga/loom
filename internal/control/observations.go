package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type observationState struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports,omitempty"`
	Records []reportRecord `json:"records,omitempty"`
	Latest  []latestReport `json:"latest,omitempty"`
}

type reportRecord struct {
	ContentID string       `json:"content_id"`
	Report    DeviceReport `json:"report"`
}

type reportAuthority struct {
	PublicKey string
	View      DeviceView
}

type latestReport struct {
	DeviceID  string `json:"device_id"`
	ContentID string `json:"content_id"`
}

type ObservationStore struct {
	path  string
	mu    sync.RWMutex
	state observationState
}

func OpenObservationStore(root string) (*ObservationStore, error) {
	store := &ObservationStore{path: filepath.Join(root, "observations.json"), state: observationState{Schema: 2, Records: []reportRecord{}, Latest: []latestReport{}}}
	if err := readStrict(store.path, &store.state); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := atomicJSON(store.path, store.state); err != nil {
			return nil, err
		}
	}
	if store.state.Schema == 1 {
		legacy := append([]DeviceReport(nil), store.state.Reports...)
		store.state = observationState{Schema: 2, Records: []reportRecord{}, Latest: []latestReport{}}
		for index, report := range legacy {
			if report.validate(false, "") != nil || index > 0 && legacy[index-1].DeviceID >= report.DeviceID {
				return nil, errors.New("observation store is invalid")
			}
			id, err := deviceReportID(report)
			if err != nil {
				return nil, err
			}
			store.state.Records = append(store.state.Records, reportRecord{ContentID: id, Report: report})
			store.state.Latest = append(store.state.Latest, latestReport{DeviceID: report.DeviceID, ContentID: id})
		}
		sort.Slice(store.state.Records, func(i, j int) bool { return store.state.Records[i].ContentID < store.state.Records[j].ContentID })
		if err := atomicJSON(store.path, store.state); err != nil {
			return nil, err
		}
	}
	if store.state.Schema != 2 || len(store.state.Reports) != 0 {
		return nil, errors.New("observation store schema is invalid")
	}
	records := map[string]DeviceReport{}
	for index, record := range store.state.Records {
		id, err := deviceReportID(record.Report)
		if err != nil || id != record.ContentID || index > 0 && store.state.Records[index-1].ContentID >= record.ContentID {
			return nil, errors.New("observation store is invalid")
		}
		records[record.ContentID] = record.Report
	}
	for index, latest := range store.state.Latest {
		report, ok := records[latest.ContentID]
		if !ok || report.DeviceID != latest.DeviceID || index > 0 && store.state.Latest[index-1].DeviceID >= latest.DeviceID {
			return nil, errors.New("observation latest index is invalid")
		}
	}
	return store, nil
}

func deviceReportID(report DeviceReport) (string, error) {
	body, err := canonical(report)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("loom-signed-device-report-content-v1\n"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func reportForID(state observationState, id string) (DeviceReport, bool) {
	index := sort.Search(len(state.Records), func(index int) bool { return state.Records[index].ContentID >= id })
	if index == len(state.Records) || state.Records[index].ContentID != id {
		return DeviceReport{}, false
	}
	return state.Records[index].Report, true
}

func putReport(state observationState, report DeviceReport) (observationState, bool, error) {
	id, err := deviceReportID(report)
	if err != nil {
		return state, false, err
	}
	latestIndex := sort.Search(len(state.Latest), func(index int) bool { return state.Latest[index].DeviceID >= report.DeviceID })
	advanceLatest := true
	if latestIndex < len(state.Latest) && state.Latest[latestIndex].DeviceID == report.DeviceID {
		previous, ok := reportForID(state, state.Latest[latestIndex].ContentID)
		if !ok {
			return state, false, errors.New("observation latest index is corrupt")
		}
		previousTime, _ := time.Parse(time.RFC3339, previous.ReportedAt)
		nextTime, _ := time.Parse(time.RFC3339, report.ReportedAt)
		if !nextTime.After(previousTime) {
			advanceLatest = false
		}
	}
	next := observationState{Schema: 2, Records: append([]reportRecord(nil), state.Records...), Latest: append([]latestReport(nil), state.Latest...)}
	recordIndex := sort.Search(len(next.Records), func(index int) bool { return next.Records[index].ContentID >= id })
	inserted := recordIndex == len(next.Records) || next.Records[recordIndex].ContentID != id
	if inserted {
		next.Records = append(next.Records, reportRecord{})
		copy(next.Records[recordIndex+1:], next.Records[recordIndex:])
		next.Records[recordIndex] = reportRecord{ContentID: id, Report: report}
	}
	if advanceLatest && latestIndex < len(next.Latest) && next.Latest[latestIndex].DeviceID == report.DeviceID {
		next.Latest[latestIndex].ContentID = id
	} else if latestIndex == len(next.Latest) || next.Latest[latestIndex].DeviceID != report.DeviceID {
		next.Latest = append(next.Latest, latestReport{})
		copy(next.Latest[latestIndex+1:], next.Latest[latestIndex:])
		next.Latest[latestIndex] = latestReport{DeviceID: report.DeviceID, ContentID: id}
	}
	anchor := time.Time{}
	for _, entry := range next.Latest {
		latest, ok := reportForID(next, entry.ContentID)
		if !ok {
			return state, false, errors.New("observation latest index is corrupt")
		}
		at, _ := time.Parse(time.RFC3339, latest.ReportedAt)
		if at.After(anchor) {
			anchor = at
		}
	}
	cutoff := anchor.Add(-30 * 24 * time.Hour)
	kept := next.Records[:0]
	keptIDs := map[string]bool{}
	for _, record := range next.Records {
		at, parseErr := time.Parse(time.RFC3339, record.Report.ReportedAt)
		if parseErr == nil && !at.Before(cutoff) {
			kept = append(kept, record)
			keptIDs[record.ContentID] = true
		}
	}
	next.Records = kept
	latest := next.Latest[:0]
	for _, entry := range next.Latest {
		if keptIDs[entry.ContentID] {
			latest = append(latest, entry)
		}
	}
	next.Latest = latest
	return next, keptIDs[id] && (inserted || advanceLatest), nil
}

func (store *ObservationStore) IDs() []string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]string, len(store.state.Records))
	for index, record := range store.state.Records {
		result[index] = record.ContentID
	}
	return result
}

func (store *ObservationStore) IDPage(after string, limit int) ([]string, string, error) {
	if after != "" && !validDigest(after) || limit < 1 || limit > 4096 {
		return nil, "", errors.New("report content ID page is invalid")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	start := sort.Search(len(store.state.Records), func(index int) bool {
		return store.state.Records[index].ContentID > after
	})
	end := min(start+limit, len(store.state.Records))
	result := make([]string, 0, end-start)
	for _, record := range store.state.Records[start:end] {
		result = append(result, record.ContentID)
	}
	next := ""
	if end < len(store.state.Records) {
		next = result[len(result)-1]
	}
	return result, next, nil
}

func (store *ObservationStore) MissingRecords(known []string, projection Projection) ([]reportRecord, error) {
	return store.missingRecords(known, currentReportAuthorities(projection))
}

func (store *ObservationStore) missingRecords(known []string, authorities map[string]reportAuthority) ([]reportRecord, error) {
	if !sort.StringsAreSorted(known) {
		return nil, errors.New("report content IDs are not sorted")
	}
	wanted := make(map[string]bool, len(known))
	for index, id := range known {
		if !validDigest(id) || index > 0 && known[index-1] == id {
			return nil, errors.New("report content IDs are invalid")
		}
		wanted[id] = true
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []reportRecord{}
	for _, record := range store.state.Records {
		if !wanted[record.ContentID] && verifyAuthorizedReport(record.Report, authorities) == nil {
			result = append(result, record)
		}
	}
	return result, nil
}

func (store *ObservationStore) MergeRecords(records []reportRecord, projection Projection) (int, error) {
	return store.mergeRecords(records, currentReportAuthorities(projection))
}

func (store *ObservationStore) mergeRecords(records []reportRecord, authorities map[string]reportAuthority) (int, error) {
	reports := make([]DeviceReport, len(records))
	for index, record := range records {
		id, err := deviceReportID(record.Report)
		if err != nil || id != record.ContentID || index > 0 && records[index-1].ContentID >= record.ContentID {
			return 0, errors.New("signed report records are invalid")
		}
		if err := verifyAuthorizedReport(record.Report, authorities); err != nil {
			return 0, err
		}
		reports[index] = record.Report
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	next, merged := store.state, 0
	for _, report := range reports {
		var changed bool
		var err error
		next, changed, err = putReport(next, report)
		if err != nil {
			return 0, err
		}
		if changed {
			merged++
		}
	}
	if merged == 0 {
		return 0, nil
	}
	if err := atomicJSON(store.path, next); err != nil {
		return 0, err
	}
	store.state = next
	return merged, nil
}

func (store *ObservationStore) Put(report DeviceReport, publicKey string) error {
	if report.Verify(publicKey) != nil {
		return errors.New("device report is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	nextState, advanced, err := putReport(store.state, report)
	if err != nil {
		return err
	}
	if !advanced {
		return errors.New("device report does not advance")
	}
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
	merged := 0
	for _, report := range reports {
		var advanced bool
		var err error
		nextState, advanced, err = putReport(nextState, report)
		if err != nil {
			return 0, err
		}
		if advanced {
			merged++
		}
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
	result := make([]DeviceReport, 0, len(store.state.Latest))
	for _, latest := range store.state.Latest {
		if report, ok := reportForID(store.state, latest.ContentID); ok {
			result = append(result, report)
		}
	}
	return result
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

// VerifiedHistory returns authenticated report history in occurrence order.
// Old reports are checked against the certified DeviceView/key that was valid
// for their view digest; returning them here never makes that old view current.
func (store *ObservationStore) VerifiedHistory(authorities map[string]reportAuthority, now time.Time) []DeviceReport {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	records := append([]reportRecord(nil), store.state.Records...)
	store.mu.RUnlock()
	cutoff := now.Add(-30 * 24 * time.Hour)
	verified := make([]DeviceReport, 0, len(records))
	for _, record := range records {
		at, err := time.Parse(time.RFC3339, record.Report.ReportedAt)
		if err != nil || at.Before(cutoff) || at.After(now) || verifyAuthorizedReport(record.Report, authorities) != nil {
			continue
		}
		verified = append(verified, record.Report)
	}
	sort.Slice(verified, func(i, j int) bool {
		left := verified[i].ReportedAt + "\x00" + verified[i].DeviceID + "\x00" + verified[i].ViewDigest
		right := verified[j].ReportedAt + "\x00" + verified[j].DeviceID + "\x00" + verified[j].ViewDigest
		return left < right
	})
	return verified
}

func currentReportAuthorities(projection Projection) map[string]reportAuthority {
	result := map[string]reportAuthority{}
	for _, authorization := range projection.DeviceAuthorizations {
		view, found := projectDeviceView(projection, authorization.DeviceID)
		if !found {
			continue
		}
		digest, err := DeviceViewDigest(view)
		if err == nil {
			result[authorization.DeviceID+"\x00"+digest] = reportAuthority{PublicKey: authorization.DevicePublicKey, View: view}
		}
	}
	return result
}

func verifyAuthorizedReport(report DeviceReport, authorities map[string]reportAuthority) error {
	authority, found := authorities[report.DeviceID+"\x00"+report.ViewDigest]
	if !found || report.Verify(authority.PublicKey) != nil {
		return errors.New("device report signature or certified view rejected")
	}
	return verifyReportViewFields(report, authority.View)
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
	return verifyReportViewFields(report, view)
}

func verifyReportViewFields(report DeviceReport, view DeviceView) error {
	if view.Schema == deviceViewSchemaV2 && report.Schema != enrollmentSchemaV2 {
		return errors.New("schema-2 device view requires a schema-2 report")
	}
	if view.Schema == deviceViewSchema && report.Schema != enrollmentSchema {
		return errors.New("legacy device view requires a schema-1 report")
	}
	if report.Schema == enrollmentSchemaV2 {
		routes := map[string]RouteCandidate{}
		scopes := map[string]bool{}
		for _, route := range view.Routes {
			routes[route.ID] = route
			scopes[route.Scope] = true
		}
		selectedScopes := map[string]bool{}
		for _, selection := range report.Selections {
			route, ok := routes[selection.CandidateID]
			if !ok || route.Scope != selection.Scope || selectedScopes[selection.Scope] {
				return errors.New("device report selection is not authorized")
			}
			selectedScopes[selection.Scope] = true
		}
		if len(selectedScopes) != len(scopes) {
			return errors.New("device report selections do not cover every authorized scope")
		}
		targets := map[string]LinkProbeTarget{}
		for _, target := range view.LinkProbeTargets {
			targets[target.LinkID] = target
		}
		for _, link := range report.Links {
			target, ok := targets[link.LinkID]
			if !ok || target.Peer != link.Peer || target.Target != link.ProbeTarget || link.Interface != "wg-"+target.Peer {
				return errors.New("device report link target is not certified")
			}
		}
		expected := map[string]bool{}
		for _, component := range view.ExpectedComponents {
			expected[component.Name] = true
		}
		for _, component := range report.Components {
			if !expected[component.Name] {
				return errors.New("device report component is not expected")
			}
		}
	}
	return nil
}

func (store *ObservationStore) Project(projection *WebProjection, authority Projection, now time.Time) {
	if store == nil || projection == nil {
		return
	}
	latest := map[string]DeviceReport{}
	for _, report := range store.Verified(authority) {
		reportedAt, _ := time.Parse(time.RFC3339, report.ReportedAt)
		if now.Before(reportedAt) || report.Schema == enrollmentSchemaV2 && now.Sub(reportedAt) > 3*time.Minute {
			continue
		}
		previous, found := latest[report.DeviceID]
		if !found || previous.ReportedAt < report.ReportedAt {
			latest[report.DeviceID] = report
		}
	}
	serverReady := func(deviceID string) bool {
		report, found := latest[deviceID]
		if !found || report.Schema != enrollmentSchemaV2 || report.Runtime == nil || report.Runtime.State != "running" || !report.Runtime.Exact {
			return false
		}
		view, found := projectDeviceView(authority, deviceID)
		if !found {
			return false
		}
		digest, err := DeviceViewDigest(view)
		return err == nil && report.Runtime.AppliedViewDigest == digest
	}
	deviceIDs := make([]string, 0, len(latest))
	for deviceID := range latest {
		deviceIDs = append(deviceIDs, deviceID)
	}
	sort.Strings(deviceIDs)
	for _, deviceID := range deviceIDs {
		report := latest[deviceID]
		available, unavailable, current := false, false, 0
		currentResults := map[string]string{}
		for _, observation := range report.Observations {
			until, err := time.Parse(time.RFC3339, observation.ValidUntil)
			if err != nil || !now.Before(until) {
				continue
			}
			current++
			available = available || observation.Result == "available"
			unavailable = unavailable || observation.Result == "unavailable"
			currentResults[observation.CandidateID] = observation.Result
			for index := range projection.Paths {
				if projection.Paths[index].Device == report.DeviceID && projection.Paths[index].CandidateID == observation.CandidateID {
					projection.Paths[index].Availability = observation.Result
				}
			}
		}
		state := "unknown"
		if report.Schema == enrollmentSchema {
			if available {
				state = "available"
			} else if current > 0 && unavailable {
				state = "unavailable"
			}
		} else if len(report.Selections) > 0 {
			allAvailable, anyUnavailable := true, false
			authorization, authorized := authorizationFor(authority, report.DeviceID)
			routes, _, routeErr := projectAuthorizationRuntime(authority, authorization)
			routeByID := map[string]RouteCandidate{}
			if authorized && routeErr == nil {
				for _, route := range routes {
					routeByID[route.ID] = route
				}
			}
			for _, selection := range report.Selections {
				result, observed := currentResults[selection.CandidateID]
				route, projected := routeByID[selection.CandidateID]
				if !observed || !projected {
					allAvailable = false
					continue
				}
				if result == "unavailable" {
					allAvailable, anyUnavailable = false, true
					continue
				}
				if result != "available" {
					allAvailable = false
					continue
				}
				for _, serverID := range route.Chain {
					if !serverReady(serverID) {
						allAvailable = false
					}
				}
			}
			if anyUnavailable {
				state = "unavailable"
			} else if allAvailable {
				state = "available"
			}
		}
		for index := range projection.Devices {
			if projection.Devices[index].ID == report.DeviceID {
				projection.Devices[index].Availability = state
				projection.Devices[index].Presence = "available"
				projection.Devices[index].LastReportAt = report.ReportedAt
				if report.Runtime != nil {
					projection.Devices[index].RuntimeState = report.Runtime.State
				}
				projection.Devices[index].Components = componentState(report, authority, report.DeviceID)
				projection.Devices[index].Evidence = &DeviceEvidence{ReportedAt: report.ReportedAt, ViewDigest: report.ViewDigest,
					Selections: append([]ReportSelection(nil), report.Selections...), Components: append([]ComponentReadback(nil), report.Components...),
					Links: append([]LinkReadback(nil), report.Links...), Measurements: append([]Observation(nil), report.Observations...),
					Deployment: report.Deployment}
				if report.Runtime != nil {
					runtime := *report.Runtime
					projection.Devices[index].Evidence.Runtime = &runtime
				}
			}
		}
		selections := map[string]string{}
		for _, selection := range report.Selections {
			selections[selection.Scope] = selection.CandidateID
		}
		for index := range projection.Paths {
			if projection.Paths[index].Device == report.DeviceID {
				if report.Schema == enrollmentSchema {
					projection.Paths[index].Selected = projection.Paths[index].CandidateID == report.Selection
				} else {
					candidate := projection.Paths[index]
					routeScope := ""
					if authorization, found := authorizationFor(authority, report.DeviceID); found {
						routes, _, _ := projectAuthorizationRuntime(authority, authorization)
						for _, route := range routes {
							if route.ID == candidate.CandidateID {
								routeScope = route.Scope
							}
						}
					}
					projection.Paths[index].Selected = selections[routeScope] == candidate.CandidateID
				}
			}
		}
		for _, readback := range report.Links {
			for index := range projection.Links {
				if projection.Links[index].ID == readback.LinkID {
					projection.Links[index].Availability = readback.Result
					projection.Links[index].LatencyMS = readback.LatencyMS
				}
			}
		}
	}
	projection.Traffic = store.projectTraffic(authority, now)
}

func componentState(report DeviceReport, authority Projection, deviceID string) string {
	view, found := projectDeviceView(authority, deviceID)
	if !found || len(view.ExpectedComponents) == 0 {
		return "unknown"
	}
	actual := map[string]ComponentReadback{}
	for _, component := range report.Components {
		actual[component.Name] = component
	}
	for _, expected := range view.ExpectedComponents {
		value, ok := actual[expected.Name]
		if !ok {
			return "unknown"
		}
		if value.Version != expected.Version || expected.Digest != "" && value.Digest != expected.Digest {
			return "mismatch"
		}
	}
	return "matching"
}

func (store *ObservationStore) projectTraffic(authority Projection, now time.Time) []TrafficBucket {
	store.mu.RLock()
	records := append([]reportRecord(nil), store.state.Records...)
	store.mu.RUnlock()
	byStream := map[string][]DeviceReport{}
	cutoff := now.Add(-24 * time.Hour)
	for _, record := range records {
		report := record.Report
		at, err := time.Parse(time.RFC3339, report.ReportedAt)
		if err != nil || at.Before(cutoff) || at.After(now) || report.Schema != enrollmentSchemaV2 || verifyCurrentReport(report, authority) != nil {
			continue
		}
		for _, link := range report.Links {
			key := report.DeviceID + "\x00" + link.LinkID + "\x00" + link.Peer + "\x00" + link.Interface + "\x00" + link.Epoch
			copy := report
			copy.Links = []LinkReadback{link}
			byStream[key] = append(byStream[key], copy)
		}
	}
	totals := map[string]TrafficBucket{}
	for _, reports := range byStream {
		sort.Slice(reports, func(i, j int) bool { return reports[i].ReportedAt < reports[j].ReportedAt })
		for index := 1; index < len(reports); index++ {
			previous, current := reports[index-1], reports[index]
			previousAt, _ := time.Parse(time.RFC3339, previous.ReportedAt)
			currentAt, _ := time.Parse(time.RFC3339, current.ReportedAt)
			left, right := previous.Links[0], current.Links[0]
			deltaTime := currentAt.Sub(previousAt)
			if deltaTime <= 0 || deltaTime > 3*time.Minute || right.TXBytes < left.TXBytes || right.RXBytes < left.RXBytes {
				continue
			}
			hour := currentAt.Truncate(time.Hour).Format(time.RFC3339)
			key := current.DeviceID + "\x00" + right.LinkID + "\x00" + hour
			bucket := totals[key]
			bucket.Device, bucket.LinkID, bucket.Hour = current.DeviceID, right.LinkID, hour
			bucket.TXBytes += right.TXBytes - left.TXBytes
			bucket.RXBytes += right.RXBytes - left.RXBytes
			// Count each transmitted byte at its sending endpoint. The peer's RX
			// is the same traffic and must not be added again for link/fleet totals.
			bucket.ForwardBytes += right.TXBytes - left.TXBytes
			totals[key] = bucket
		}
	}
	result := make([]TrafficBucket, 0, len(totals))
	for _, bucket := range totals {
		result = append(result, bucket)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Hour+"\x00"+result[i].Device+"\x00"+result[i].LinkID <
			result[j].Hour+"\x00"+result[j].Device+"\x00"+result[j].LinkID
	})
	return result
}
