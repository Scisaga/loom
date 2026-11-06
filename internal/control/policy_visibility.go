package control

import (
	"errors"
	"reflect"
	"strings"
	"time"
)

// HiddenInternetPolicies is a deletable UI projection, never an authorization or
// a routing decision. Shared samples must be the complete recipient cache already
// accepted for this View by MergeMeasurementDelivery; no selected Policy filter is
// applied to that delivery. The returned deadlines expire the display evidence
// without another request. An empty currentPolicyID lets a caller protect its
// current choice when applying the result to its own latest UI snapshot.
func HiddenInternetPolicies(view DeviceView, currentPolicyID string, shared []DeviceLinkObservation, local []Observation, generation string, now time.Time) (map[string]int64, error) {
	if ValidateID(view.NetworkID) != nil || ValidateID(view.DeviceID) != nil || currentPolicyID != "" && ValidateID(currentPolicyID) != nil ||
		!validateTime(now.UnixMilli()) || len(local) > 0 && ValidateID(generation) != nil {
		return nil, errors.New("invalid Policy visibility context")
	}
	type item struct {
		sample        Observation
		until         int64
		conflict      bool
		scopeConflict bool
	}
	index := map[string]item{}
	add := func(source string, sample Observation, until int64) {
		key := source + "\x00" + sample.Target
		value := item{sample: sample, until: min(until, sample.ValidUntil)}
		old, found := index[key]
		if !found {
			index[key] = value
			return
		}
		if old.sample.NetworkGeneration != sample.NetworkGeneration || old.sample.SpecDigest != sample.SpecDigest {
			old.conflict = true
			old.scopeConflict = true
		} else if sample.ObservedAt > old.sample.ObservedAt {
			value.conflict, value.scopeConflict = old.scopeConflict, old.scopeConflict
			index[key] = value
			return
		} else if sample.ObservedAt == old.sample.ObservedAt {
			old.conflict = old.conflict || !reflect.DeepEqual(old.sample, sample)
			old.until = min(old.until, value.until)
		}
		index[key] = old
	}
	for _, row := range shared {
		if row.Validate() != nil {
			return nil, errors.New("invalid shared Policy visibility sample")
		}
		if row.Observation.Level == "egress" && row.DeviceID != view.DeviceID {
			add(row.DeviceID, row.Observation, row.CurrentUntil)
		}
	}
	probes, err := EgressProbes(view)
	if err != nil {
		return nil, err
	}
	ownSpecs := map[string]bool{}
	for _, probe := range probes {
		ownSpecs[probe.SpecDigest+"\x00"+probe.Target] = true
	}
	for _, sample := range local {
		if sample.Validate() != nil {
			return nil, errors.New("invalid local Policy visibility sample")
		}
		if sample.Level == "egress" && sample.NetworkGeneration == generation && ownSpecs[sample.SpecDigest+"\x00"+sample.Target] {
			add(view.DeviceID, sample, sample.ValidUntil)
		}
	}
	granted, services := map[string]bool{}, map[string]Service{}
	for _, id := range view.PolicyIDs {
		granted[id] = true
	}
	for _, service := range view.Services {
		services[service.ID] = service
	}
	exitsByScope := map[string][]string{}
	// One summary per Service/source, reused by every Policy that references it.
	// The URL/source index above also reuses samples shared by different Services.
	failedUntil := map[string]int64{}
	hidden := map[string]int64{}
	for _, policy := range view.Policies {
		service, found := services[policy.ServiceID]
		if !granted[policy.ID] || policy.Action != "allow" || !found || service.Kind != "internet" || policy.ID == currentPolicyID || len(service.ProbeURLs) == 0 || policy.permitsDirect() {
			continue
		}
		if policy.ExitScope == nil {
			return nil, errors.New("internet Policy has no exit scope")
		}
		scope := policy.ExitScope.Mode + "\x00" + strings.Join(policy.ExitScope.NodeIDs, "\x00")
		exits, known := exitsByScope[scope]
		if !known {
			exits = stableExits(view, policy, service)
			exitsByScope[scope] = exits
		}
		until, count := int64(0), 0
		for _, exit := range exits {
			if exit == view.DeviceID && !policy.permitsLocalEgress(view.DeviceID) {
				continue
			}
			count++
			key := service.ID + "\x00" + exit
			deadline, known := failedUntil[key]
			if !known {
				for _, target := range service.ProbeURLs {
					value, found := index[exit+"\x00"+target]
					if !found || value.conflict || value.sample.Result != "unavailable" || value.sample.ObservedAt > now.UnixMilli() || value.until <= now.UnixMilli() {
						deadline = 0
						break
					}
					if deadline == 0 || value.until < deadline {
						deadline = value.until
					}
				}
				failedUntil[key] = deadline
			}
			if deadline == 0 {
				until = 0
				break
			}
			if until == 0 || deadline < until {
				until = deadline
			}
		}
		if count > 0 && until > now.UnixMilli() {
			hidden[policy.ID] = until
		}
	}
	return hidden, nil
}
