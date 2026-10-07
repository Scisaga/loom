package deviceclient

import (
	"bytes"
	"sort"
	"strings"

	"loom/internal/control"
)

// These are disposable review values. They never grant permission, acknowledge
// a missing withdrawal, or replace the one protected identity and LKG.
type PermissionChange struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Change string `json:"change"`
}

type MemberReview struct {
	PossiblePermissionRestoration bool               `json:"possible_permission_restoration"`
	Changes                       []PermissionChange `json:"changes"`
}

func PossiblePermissionRestoration(state State) bool {
	if state.LKG == nil {
		return false
	}
	for _, certificate := range state.LKG.ControlProof.Successors {
		for _, seal := range certificate.Config.SealedKeys {
			for _, seen := range state.HighWater {
				if seen.KeyID == seal.KeyID && seen.Sequence > seal.Sequence {
					return true
				}
			}
		}
	}
	return false
}

func (store *Store) PossiblePermissionRestoration() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return PossiblePermissionRestoration(store.state)
}

// Call only with verified identity states, before replacing the previous LKG.
// A persistent warning is rebuilt from original high-water and certificates;
// the transition diff is optional diagnostics and has no durable lifecycle.
func ReviewMemberTransition(next, previous State) MemberReview {
	review := MemberReview{Changes: []PermissionChange{}}
	if !PossiblePermissionRestoration(next) || previous.LKG == nil || len(next.LKG.ControlProof.Successors) <= len(previous.LKG.ControlProof.Successors) {
		return review
	}
	review.PossiblePermissionRestoration = true
	before, after := visiblePermissions(previous.LKG.View), visiblePermissions(next.LKG.View)
	defer func() {
		for _, values := range []map[string][]byte{before, after} {
			for _, body := range values {
				clear(body)
			}
		}
	}()
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		old, existed := before[key]
		current, exists := after[key]
		change := "changed"
		if !existed {
			change = "added"
		} else if !exists {
			change = "removed"
		} else if bytes.Equal(old, current) {
			continue
		}
		kind, id, _ := strings.Cut(key, "\x00")
		review.Changes = append(review.Changes, PermissionChange{Kind: kind, ID: id, Change: change})
	}
	return review
}

func visiblePermissions(view control.DeviceView) map[string][]byte {
	values := map[string][]byte{}
	add := func(kind, id string, value any) {
		body, _ := control.CanonicalEncode(value)
		values[kind+"\x00"+id] = body
	}
	for _, role := range view.Responsibilities {
		add("responsibility", role, role)
	}
	for _, value := range view.Services {
		add("service", value.ID, value)
	}
	for _, value := range view.Policies {
		add("policy", value.ID, value)
	}
	for _, value := range view.Routes {
		add("route", value.ID, value)
	}
	for _, value := range view.Resources {
		add("resource", value.ID, value)
	}
	for _, value := range view.Links {
		add("link", value.ID, value)
	}
	for _, value := range view.DNSRecords {
		add("dns_record", value.ID, value)
	}
	for _, value := range view.InboundCredentials {
		// Credential bytes are not a visible permission and never enter a diff.
		value.Credential = ""
		add("inbound", value.DeviceID+"/"+value.ServiceID+"/"+value.PolicyID+"/"+value.ResourceID+"/"+value.ReceiverNodeID, value)
	}
	return values
}
