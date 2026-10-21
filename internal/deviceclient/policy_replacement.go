package deviceclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sort"

	"loom/internal/clientmodel"
	"loom/internal/clientsecret"
	"loom/internal/control"
)

// ReplacePolicySelectionLKG is explicit and one-way. Historical execution is
// never decoded; unchanged identity bytes are verified by the ordinary decoder
// only after substituting the newly certified View and current preference.
func ReplacePolicySelectionLKG(original []byte, replacement control.DeviceViewEnvelope, externalPreference []byte) (State, clientmodel.Preference, error) {
	if len(original) > maxStateBytes || replacement.Validate() != nil {
		return State{}, clientmodel.Preference{}, errors.New("policy replacement input is invalid")
	}
	type span struct {
		name       string
		start, end int
		raw        []byte
	}
	fields := []span{}
	decoder := json.NewDecoder(bytes.NewReader(original))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return State{}, clientmodel.Preference{}, errors.New("historical identity is not an object")
	}
	seen := map[string]bool{}
	var historicalView, historicalPreference []byte
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return State{}, clientmodel.Preference{}, errors.New("historical identity has duplicated fields")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return State{}, clientmodel.Preference{}, err
		}
		if name == "certified_lkg" || name == "preference" {
			end := int(decoder.InputOffset())
			fields = append(fields, span{name, end - len(raw), end, raw})
		}
		if name == "certified_lkg" {
			historicalView = raw
		}
		if name == "preference" {
			historicalPreference = raw
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(historicalView) == 0 {
		return State{}, clientmodel.Preference{}, errors.New("historical identity has no complete LKG")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return State{}, clientmodel.Preference{}, errors.New("trailing historical identity input")
	}
	if len(externalPreference) > 0 {
		historicalPreference = externalPreference
	}
	preference, err := migratePolicyPreference(historicalView, historicalPreference, replacement.View)
	if err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	viewBody, err := control.CanonicalEncode(replacement)
	if err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	defer clear(viewBody)
	preferenceBody, err := control.CanonicalEncode(preference)
	if err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].start > fields[j].start })
	nextBytes := append([]byte{}, original...)
	defer func() { clear(nextBytes) }()
	for _, field := range fields {
		body := viewBody
		if field.name == "preference" {
			body = preferenceBody
		}
		value := make([]byte, 0, len(nextBytes)+len(body))
		value = append(value, nextBytes[:field.start]...)
		value = append(value, body...)
		value = append(value, nextBytes[field.end:]...)
		clear(nextBytes)
		nextBytes = value
	}
	next, err := DecodeIdentityState(nextBytes)
	if err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	if err := control.CheckPolicySelectionReplacement(historicalView, replacement, next.Invite, next.HighWater); err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	next, err = AcceptLKG(next, replacement)
	return next, preference, err
}

// This finite local value is read only by explicit migration, never startup.
type historicalRoutingPreference struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
	Exit   string `json:"exit,omitempty"`
}

func (value historicalRoutingPreference) Validate() error {
	if value.Schema != 3 {
		return errors.New("historical preference schema is invalid")
	}
	if (value.Mode == "auto" || value.Mode == "direct") && value.Exit == "" {
		return nil
	}
	if value.Mode == "fixed_exit" && control.ValidateID(value.Exit) == nil && value.Exit != "direct" && value.Exit != "auto" {
		return nil
	}
	return errors.New("historical preference is invalid")
}

func migratePolicyPreference(historicalView, previous []byte, next control.DeviceView) (clientmodel.Preference, error) {
	var envelope struct {
		View json.RawMessage `json:"view"`
	}
	if err := json.Unmarshal(historicalView, &envelope); err != nil {
		return clientmodel.Preference{}, err
	}
	var rawView map[string]json.RawMessage
	if err := json.Unmarshal(envelope.View, &rawView); err != nil {
		return clientmodel.Preference{}, err
	}
	var view struct {
		PolicyIDs []string
		Policies  []control.NetworkPolicy
		Services  []control.Service
		DeviceID  string
	}
	for name, target := range map[string]any{"policy_ids": &view.PolicyIDs, "policies": &view.Policies, "services": &view.Services, "device_id": &view.DeviceID} {
		if err := control.DecodeCanonical(rawView[name], target, control.ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 32, MaxItems: 1 << 20}); err != nil {
			return clientmodel.Preference{}, err
		}
	}
	for i, id := range view.PolicyIDs {
		if control.ValidateID(id) != nil || i > 0 && view.PolicyIDs[i-1] >= id {
			return clientmodel.Preference{}, errors.New("historical policy references are not canonical")
		}
	}
	for i, policy := range view.Policies {
		if policy.Validate() != nil || i > 0 && view.Policies[i-1].ID >= policy.ID {
			return clientmodel.Preference{}, errors.New("historical policies are invalid")
		}
	}
	for i, service := range view.Services {
		if service.Validate() != nil || i > 0 && view.Services[i-1].ID >= service.ID {
			return clientmodel.Preference{}, errors.New("historical Services are invalid")
		}
	}
	var legacy historicalRoutingPreference
	if len(previous) > 0 {
		if err := control.DecodeCanonical(previous, &legacy, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}); err != nil {
			return clientmodel.Preference{}, err
		}
	}
	preference := clientmodel.EmptyPreference()
	for _, service := range view.Services {
		var assigned []control.NetworkPolicy
		for _, policy := range view.Policies {
			for _, id := range view.PolicyIDs {
				if id == policy.ID && policy.ServiceID == service.ID {
					assigned = append(assigned, policy)
				}
			}
		}
		if len(assigned) == 0 {
			continue
		}
		choice := clientmodel.ServicePreference{ServiceID: service.ID}
		if len(assigned) == 1 && assigned[0].Action == "allow" {
			policy := assigned[0]
			equivalent := policyMatchesHistoricalPreference(view.DeviceID, service.Kind, policy, legacy)
			currentKind := ""
			sameServiceRules := false
			for _, current := range next.Services {
				if current.ID == service.ID {
					currentKind = current.Kind
					current.Name = service.Name
					sameServiceRules = reflect.DeepEqual(current, service)
				}
			}
			for _, current := range next.Policies {
				if current.ID == policy.ID && current.ServiceID == service.ID {
					equivalent = equivalent && currentKind == service.Kind && policyMatchesHistoricalPreference(next.DeviceID, currentKind, current, legacy)
					current.Name = policy.Name
					if legacy.Mode != "auto" {
						equivalent = equivalent && sameServiceRules && reflect.DeepEqual(current, policy)
					}
				}
			}
			if equivalent {
				choice.PolicyID = policy.ID
			}
		}
		preference.Services = append(preference.Services, choice)
	}
	sort.Slice(preference.Services, func(i, j int) bool { return preference.Services[i].ServiceID < preference.Services[j].ServiceID })
	return clientmodel.ReconcilePreference(preference, next)
}

func policyMatchesHistoricalPreference(deviceID, kind string, policy control.NetworkPolicy, legacy historicalRoutingPreference) bool {
	if policy.Action != "allow" || legacy.Mode == "" {
		return false
	}
	if kind == "local_network" || legacy.Mode == "auto" {
		return true
	}
	if legacy.Mode == "fixed_exit" {
		return policy.AllowDirect != nil && !*policy.AllowDirect && policy.ExitScope != nil && policy.ExitScope.Mode == "only" && len(policy.ExitScope.NodeIDs) == 1 && policy.ExitScope.NodeIDs[0] == legacy.Exit
	}
	if legacy.Mode != "direct" || policy.AllowDirect == nil || !*policy.AllowDirect || policy.EntryScope.Mode != "none" {
		return false
	}
	if policy.LocalEgressDevices != nil {
		for _, id := range *policy.LocalEgressDevices {
			if id == deviceID {
				return false
			}
		}
	}
	return true
}

// MigratePolicySelectionFile never runs from Load, sync or startup. Retrying the
// same completed cutover checks its protected original and monotonic progress.
func MigratePolicySelectionFile(path, evidence string, replacement control.DeviceViewEnvelope, legacyPreference []byte, protector clientsecret.Protector) (clientmodel.Preference, error) {
	var preference clientmodel.Preference
	err := migrateForwardState(path, evidence, replacement, protector, func(original []byte, next control.DeviceViewEnvelope) (State, error) {
		state, choices, err := ReplacePolicySelectionLKG(original, next, legacyPreference)
		preference = choices
		return state, err
	}, true)
	return preference, err
}

// PreviewPolicySelectionFile authenticates the finite original before a host
// adapter prepares its separate protected preference value. No files change.
func PreviewPolicySelectionFile(path, evidence string, replacement control.DeviceViewEnvelope, legacyPreference []byte, protector clientsecret.Protector) (clientmodel.Preference, error) {
	if !validStatePath(path) || !validStatePath(evidence) || path == evidence {
		return clientmodel.Preference{}, errors.New("migration requires distinct canonical paths")
	}
	lock, err := lockStateFile(path)
	if err != nil {
		return clientmodel.Preference{}, err
	}
	defer lock.Close()
	store := &Store{path: evidence, protector: protector}
	original, err := store.readBytesUnlocked()
	if errors.Is(err, os.ErrNotExist) {
		store.path = path
		original, err = store.readBytesUnlocked()
	}
	if err != nil {
		return clientmodel.Preference{}, err
	}
	defer clear(original)
	_, preference, err := ReplacePolicySelectionLKG(original, replacement, legacyPreference)
	return preference, err
}
