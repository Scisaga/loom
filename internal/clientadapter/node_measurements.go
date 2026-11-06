package clientadapter

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// MeasurementTiming keeps repeat opportunities independent of validity and
// performance-switch timing. The budget may delay a due job without renewing it.
type MeasurementTiming struct{ ActivePeriod, IdlePeriod, SuccessValidity, FailureValidity, RoundTimeout time.Duration }

// RecoveryPeriod gives failed measurements a faster repeat opportunity using
// only the measurement period. Expiry changes sample adoption, never cadence.
func (timing MeasurementTiming) RecoveryPeriod() time.Duration {
	return max(time.Millisecond, timing.ActivePeriod/2)
}

var DefaultMeasurementTiming = MeasurementTiming{30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Second, 10 * time.Second}

type nodeMeasurement struct {
	key           string
	due           time.Time
	group         string
	templates     []control.Observation
	template      control.Observation
	active        bool
	observed      int64
	run           func(context.Context) (*int64, *control.HY2Transfer, bool, error)
	localRun      func(context.Context) (clientmodel.Observation, error)
	localProgress func([]clientmodel.Observation) error
}

type nodeMeasurementCompletion struct {
	shared   []control.Observation
	local    []clientmodel.Observation
	progress func([]clientmodel.Observation) error
}

func nodeMeasurementKey(task nodeMeasurement) string {
	if task.key != "" {
		return task.key
	}
	return measurementSampleKey(task.template)
}

func measurementSampleKey(sample control.Observation) string {
	return sample.Level + "\x00" + sample.ResourceID + "\x00" + sample.LinkID + "\x00" + sample.Target + "\x00" + sample.SpecDigest
}

// ObserveNodeMeasurements builds one fair due list across this node's existing
// roles. It never enumerates Service/Policy/full-path products. Unknown and
// oldest due items get a chance; current use and a significant pending
// alternative use a shorter repeat period, without changing the node budget.
func ObserveNodeMeasurements(ctx context.Context, view control.DeviceExecution, selected []string, previous []control.Observation, generation string, now func() time.Time, timing MeasurementTiming, progress func([]control.Observation) error, recovery ...*TCPRecoveryInput) ([]control.Observation, error) {
	if control.ValidateID(generation) != nil || now == nil || timing.ActivePeriod <= 0 || timing.IdlePeriod < timing.ActivePeriod || timing.SuccessValidity <= 0 || timing.FailureValidity <= 0 || timing.RoundTimeout <= 0 {
		return nil, errors.New("invalid node measurement input")
	}
	ctx = WithMeasurementNetwork(ctx, generation)
	activeResources, activeLinks := map[string]bool{}, map[string]bool{}
	for _, id := range selected {
		found := false
		for _, route := range view.Routes {
			if route.ID == id {
				found = true
				activeResources[route.FirstResourceID] = true
				_, linkIDs, err := control.CandidateTopologyEstimate(view, route)
				if err != nil {
					return nil, err
				}
				for _, link := range linkIDs {
					activeLinks[link] = true
				}
			}
		}
		if !found {
			for _, link := range view.Links {
				if link.ID == id && link.FromNodeID == view.DeviceID {
					activeLinks[link.ID], found = true, true
					break
				}
			}
		}
		if !found {
			return nil, errors.New("measurement priority is outside the current View")
		}
	}
	tasks := []nodeMeasurement{}
	resources := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	first, err := control.FirstHopProbes(view)
	if err != nil {
		return nil, err
	}
	for _, probe := range first {
		task := nodeMeasurement{template: control.Observation{Level: "resource", ResourceID: probe.Resource.ID, Target: probe.Target(), Action: probe.Action(), SpecDigest: probe.SpecDigest}, active: activeResources[probe.Resource.ID]}
		task.run = func(ctx context.Context) (*int64, *control.HY2Transfer, bool, error) {
			if probe.Resource.Kind == "wireguard" {
				rtt, err := ProbeWireGuardAdmission(ctx, probe)
				var metric *int64
				if rtt != nil {
					metric = new(rtt.Milliseconds())
				}
				return metric, nil, err == nil, err
			}
			result, err := probeFirstHop(ctx, probe, view.DNSServers, now())
			return result.roundTripMS, result.transfer, err == nil, err
		}
		if probe.Resource.Kind == "wireguard" {
			task.group = "wg-admission:" + probe.Resource.ID + ":" + probe.PolicyID
		}
		tasks = append(tasks, task)
	}
	specs, err := control.LinkSpecifications(view.DeviceView)
	if err != nil {
		return nil, err
	}
	credentials := map[string]string{}
	for _, credential := range view.TransportCredentials {
		if credential.SenderID == view.DeviceID {
			credentials[credential.ResourceID] = credential.Credential
		}
	}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID {
			continue
		}
		spec := specs[link.ID]
		task := nodeMeasurement{template: control.Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, Target: net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)), Action: link.ProbeTarget.Action, SpecDigest: spec}, active: activeLinks[link.ID]}
		task.run = func(ctx context.Context) (*int64, *control.HY2Transfer, bool, error) {
			resource := resources[link.ResourceID]
			if resource.Kind == "hysteria2" {
				result, err := probeFirstHop(ctx, control.ResourceProbe{NetworkID: view.NetworkID, Resource: resource, Credential: credentials[resource.ID], SpecDigest: spec}, view.DNSServers, now())
				return result.roundTripMS, result.transfer, err == nil, err
			}
			rtt, err := measureWireGuardEcho(ctx, view.NetworkID, resource, resource.ID, protocol.TransportEcho, "", spec)
			var metric *int64
			if rtt != nil {
				metric = new(rtt.Milliseconds())
			}
			return metric, nil, err == nil, err
		}
		if resources[link.ResourceID].Kind == "wireguard" {
			task.group = "wg-transport:" + link.ResourceID
		}
		tasks = append(tasks, task)
	}
	egress, err := control.EgressProbes(view.DeviceView)
	if err != nil {
		return nil, err
	}
	for _, probe := range egress {
		task := nodeMeasurement{template: control.Observation{Level: "egress", Target: probe.Target, Action: "https_request", SpecDigest: probe.SpecDigest}}
		task.run = func(ctx context.Context) (*int64, *control.HY2Transfer, bool, error) {
			result := ProbeEgressBusiness(ctx, probe)
			if result.Deferred {
				return nil, nil, false, ErrMeasurementDeferred
			}
			return nil, nil, result.Available, nil
		}
		tasks = append(tasks, task)
	}
	grouped := []nodeMeasurement{}
	byGroup := map[string]int{}
	for _, task := range tasks {
		if task.group == "" {
			task.group = measurementSampleKey(task.template)
		}
		if index, found := byGroup[task.group]; found {
			grouped[index].templates = append(grouped[index].templates, task.template)
			grouped[index].active = grouped[index].active || task.active
		} else {
			task.templates = []control.Observation{task.template}
			byGroup[task.group] = len(grouped)
			grouped = append(grouped, task)
		}
	}
	if len(recovery) > 1 {
		return nil, errors.New("one current TCP recovery input is required")
	}
	if len(recovery) == 1 && recovery[0] != nil {
		local, err := tcpRecoveryJobs(ctx, recovery[0], generation, now)
		if err != nil {
			return nil, err
		}
		grouped = append(grouped, local...)
	}
	return observeNodeJobs(ctx, grouped, previous, generation, now, timing, progress)
}

func observeNodeJobs(ctx context.Context, tasks []nodeMeasurement, previous []control.Observation, generation string, now func() time.Time, timing MeasurementTiming, progress func([]control.Observation) error) ([]control.Observation, error) {
	at := now()
	cached := map[string]control.Observation{}
	known := map[string]bool{}
	for index := range tasks {
		if tasks[index].localRun != nil {
			continue
		}
		if len(tasks[index].templates) == 0 {
			tasks[index].templates = []control.Observation{tasks[index].template}
		}
		for _, template := range tasks[index].templates {
			known[measurementSampleKey(template)] = true
		}
	}
	for _, sample := range previous {
		key := measurementSampleKey(sample)
		if known[key] && sample.NetworkGeneration == generation && sample.Validate() == nil {
			if old, ok := cached[key]; ok && old.ObservedAt == sample.ObservedAt && !reflect.DeepEqual(old, sample) {
				return nil, errors.New("conflicting node measurements have the same source specification and time")
			}
			if old, ok := cached[key]; !ok || old.ObservedAt < sample.ObservedAt {
				cached[key] = sample
			}
		}
	}
	budget := nodeMeasurementBudget(ctx)
	budget.mu.Lock()
	discovered := map[string]time.Time{}
	for _, task := range tasks {
		key := nodeMeasurementKey(task)
		first, found := budget.discovered[key]
		if !found {
			first = at
		}
		discovered[key] = first
	}
	budget.discovered = discovered
	budget.mu.Unlock()
	due := []nodeMeasurement{}
tasksLoop:
	for _, task := range tasks {
		period := timing.IdlePeriod
		if task.active {
			period = timing.ActivePeriod
		}
		needs := false
		task.due = discovered[nodeMeasurementKey(task)]
		if task.localRun != nil {
			if task.observed > 0 {
				task.due = maxTime(task.due, time.UnixMilli(task.observed).Add(period))
			}
			needs = !at.Before(task.due)
		}
		for _, template := range task.templates {
			sample, found := cached[measurementSampleKey(template)]
			if found && sample.ObservedAt > at.UnixMilli() {
				continue tasksLoop
			}
			if !found {
				needs = true
				break
			}
			repeat := period
			if sample.Result == "unavailable" {
				repeat = min(repeat, timing.RecoveryPeriod())
			}
			deadline := time.UnixMilli(sample.ObservedAt).Add(repeat)
			if task.observed == 0 || sample.ObservedAt < task.observed {
				task.observed = sample.ObservedAt
				task.due = deadline
			}
			needs = needs || !at.Before(deadline)
		}
		if needs {
			// Active work gets a bounded head start. An idle item's fixed
			// discovery/due time eventually wins, even under steady load.
			if task.active {
				task.due = task.due.Add(-timing.IdlePeriod)
			}
			due = append(due, task)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].due.Equal(due[j].due) {
			return due[i].due.Before(due[j].due)
		}
		if due[i].active != due[j].active {
			return due[i].active
		}
		return nodeMeasurementKey(due[i]) < nodeMeasurementKey(due[j])
	})
	pending, cancel := context.WithTimeout(ctx, timing.RoundTimeout)
	defer cancel()
	jobs := make(chan nodeMeasurement)
	concurrency := min(budget.limits.Concurrent, len(due))
	completedJobs := make(chan nodeMeasurementCompletion, concurrency)
	var workers sync.WaitGroup
	for index := 0; index < concurrency; index++ {
		workers.Go(func() {
			for task := range jobs {
				if pending.Err() != nil {
					return
				}
				clockStart := time.Now()
				measured, capture := captureMeasurementTime(pending, now)
				if task.localRun != nil {
					value, err := task.localRun(measured)
					if !errors.Is(err, ErrMeasurementDeferred) && !errors.Is(err, ErrSelectionSuperseded) && !errors.Is(err, context.Canceled) {
						budget.mu.Lock()
						budget.discovered[nodeMeasurementKey(task)] = now().Add(timing.ActivePeriod)
						budget.mu.Unlock()
					}
					if err == nil && pending.Err() == nil && value.Validate() == nil {
						select {
						case completedJobs <- nodeMeasurementCompletion{local: []clientmodel.Observation{value}, progress: task.localProgress}:
						case <-pending.Done():
							return
						}
					}
					continue
				}
				rtt, transfer, available, err := task.run(measured)
				if pending.Err() != nil || errors.Is(err, ErrMeasurementDeferred) || errors.Is(err, context.Canceled) {
					continue
				}
				duration := time.Since(clockStart).Milliseconds()
				completed := now()
				if !capture.timing.completed.IsZero() {
					completed, duration = capture.timing.completed, capture.timing.duration.Milliseconds()
				}
				completedSamples := make([]control.Observation, 0, len(task.templates))
				for _, template := range task.templates {
					value := template
					value.NetworkGeneration = generation
					value.Result = "unavailable"
					validity := timing.FailureValidity
					if available {
						value.Result = "available"
						validity = timing.SuccessValidity
						value.RoundTripMS = rtt
						value.HY2Transfer = transfer
					}
					value.ObservedAt, value.ValidUntil = completed.UnixMilli(), completed.Add(validity).UnixMilli()
					value.DurationMS = new(duration)
					if value.Validate() != nil {
						continue
					}
					completedSamples = append(completedSamples, value)
				}
				if len(completedSamples) != 0 {
					select {
					case completedJobs <- nodeMeasurementCompletion{shared: completedSamples}:
					case <-pending.Done():
						return
					}
				}
			}
		})
	}
	workers.Go(func() {
		defer close(jobs)
		for _, task := range due {
			select {
			case <-pending.Done():
				return
			case jobs <- task:
			}
		}
	})
	go func() {
		workers.Wait()
		close(completedJobs)
	}()
	// One reducer owns the cache and invokes the consumer serially. A bounded
	// completion queue lets a fast entry become usable while other work waits;
	// it never copies the complete cache for each finished measurement.
	var progressErr error
	for batch := range completedJobs {
		if ctx.Err() != nil || progressErr != nil {
			continue
		}
		if len(batch.local) > 0 {
			if batch.progress != nil {
				progressErr = batch.progress(batch.local)
				if progressErr != nil {
					cancel()
				}
			}
			continue
		}
		updates := batch.shared[:0]
		for _, value := range batch.shared {
			key := measurementSampleKey(value)
			if old, ok := cached[key]; ok {
				if old.ObservedAt == value.ObservedAt && !reflect.DeepEqual(old, value) {
					progressErr = errors.New("conflicting completed node measurements have the same specification and time")
					cancel()
					break
				}
				if old.ObservedAt >= value.ObservedAt {
					continue
				}
			}
			cached[key] = value
			updates = append(updates, value)
		}
		if progressErr == nil && len(updates) != 0 && progress != nil {
			progressErr = progress(updates)
			if progressErr != nil {
				cancel()
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if progressErr != nil {
		return nil, progressErr
	}
	result := make([]control.Observation, 0, len(cached))
	for _, sample := range cached {
		result = append(result, sample)
	}
	// These are report-ready originals, including unchanged samples with their
	// original deadlines. A later upload cannot turn them into a new measurement.
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Level != right.Level {
			return left.Level < right.Level
		}
		if left.ResourceID != right.ResourceID {
			return left.ResourceID < right.ResourceID
		}
		if left.LinkID != right.LinkID {
			return left.LinkID < right.LinkID
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		return left.SpecDigest < right.SpecDigest
	})
	return result, nil
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// MergeNodeMeasurements consumes a completion delta without changing the
// original sample times. Callers retain only their current execution inputs.
func MergeNodeMeasurements(previous, updates []control.Observation) []control.Observation {
	positions := make(map[string]int, len(previous)+len(updates))
	result := make([]control.Observation, 0, len(previous)+len(updates))
	for _, batch := range [][]control.Observation{previous, updates} {
		for _, value := range batch {
			if len(updates) != 0 && value.NetworkGeneration != updates[0].NetworkGeneration {
				continue
			}
			key := measurementSampleKey(value)
			if i, ok := positions[key]; ok {
				if result[i].ObservedAt < value.ObservedAt {
					result[i] = value
				}
			} else {
				positions[key] = len(result)
				result = append(result, value)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return measurementSampleKey(result[i]) < measurementSampleKey(result[j]) })
	return result
}
