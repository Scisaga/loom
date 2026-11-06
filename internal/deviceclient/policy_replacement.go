package deviceclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
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
	decoder := json.NewDecoder(bytes.NewReader(original))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return State{}, clientmodel.Preference{}, errors.New("historical identity is not an object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || fields[name] != nil {
			return State{}, clientmodel.Preference{}, errors.New("historical identity has duplicated fields")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return State{}, clientmodel.Preference{}, err
		}
		fields[name] = raw
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return State{}, clientmodel.Preference{}, errors.New("historical identity is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return State{}, clientmodel.Preference{}, errors.New("trailing historical identity input")
	}
	if !bytes.Equal(original, joinHistoricalIdentityFields(fields)) {
		return State{}, clientmodel.Preference{}, errors.New("historical identity is not canonical")
	}
	historicalView, historicalPreference := fields["certified_lkg"], fields["preference"]
	if len(historicalView) == 0 {
		return State{}, clientmodel.Preference{}, errors.New("historical identity has no LKG")
	}
	if len(externalPreference) > 0 {
		if len(historicalPreference) > 0 && !bytes.Equal(externalPreference, historicalPreference) {
			return State{}, clientmodel.Preference{}, errors.New("conflicting historical preference originals require explicit review")
		}
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
	fields["certified_lkg"], fields["preference"] = viewBody, preferenceBody
	nextBytes := joinHistoricalIdentityFields(fields)
	defer clear(nextBytes)
	next, err := DecodeIdentityState(nextBytes)
	if err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	if err := control.CheckPolicySelectionReplacement(historicalView, replacement, *next.Invite, next.HighWater); err != nil {
		return State{}, clientmodel.Preference{}, err
	}
	next, err = AcceptLKG(next, replacement)
	return next, preference, err
}

// This only reconstructs the canonical outer container during explicit import;
// signed subobjects keep their original bytes and are verified independently.
func joinHistoricalIdentityFields(fields map[string]json.RawMessage) []byte {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	body := []byte{'{'}
	for index, key := range keys {
		if index > 0 {
			body = append(body, ',')
		}
		name, _ := json.Marshal(key)
		body = append(body, name...)
		body = append(body, ':')
		body = append(body, fields[key]...)
	}
	return append(body, '}')
}

// Finite original values for explicit import, never a current preference DTO.
type historicalRoutingPreference struct {
	Schema   int                     `json:"schema"`
	Services *[]control.PolicyChoice `json:"services,omitempty"`
	Mode     string                  `json:"mode,omitempty"`
	Exit     string                  `json:"exit,omitempty"`
}

func (value historicalRoutingPreference) Validate() error {
	if value.Schema != 3 {
		return errors.New("historical preference schema is invalid")
	}
	if value.Services != nil {
		if value.Mode != "" || value.Exit != "" {
			return errors.New("ambiguous historical preference")
		}
		return control.ValidatePolicyChoices(*value.Services)
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
		if err := control.DecodeCanonical(previous, &legacy, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1 << 16}); err != nil {
			return clientmodel.Preference{}, err
		}
	}
	oldPolicies := map[string]control.NetworkPolicy{}
	for _, policy := range view.Policies {
		for _, id := range view.PolicyIDs {
			if id == policy.ID {
				oldPolicies[id] = policy
			}
		}
	}
	intent := map[string]bool{}
	if legacy.Services != nil {
		for _, choice := range *legacy.Services {
			if choice.PolicyID == "" {
				continue
			}
			policy, found := oldPolicies[choice.PolicyID]
			if !found || policy.ServiceID != choice.ServiceID || policy.Action != "allow" {
				return clientmodel.Preference{}, errors.New("historical choice is not an original granted Policy")
			}
			intent[policy.ID] = true
		}
	} else if len(previous) > 0 {
		for _, service := range view.Services {
			for _, policy := range oldPolicies {
				if policy.ServiceID == service.ID && policyMatchesHistoricalPreference(view.DeviceID, service.Kind, policy, legacy) {
					intent[policy.ID] = true
				}
			}
		}
	} else if len(oldPolicies) == 1 {
		for id, policy := range oldPolicies {
			if policy.Action == "allow" {
				intent[id] = true
			}
		}
	}
	_, options := clientmodel.PolicyOptions(next)
	nextKinds := map[string]string{}
	for _, service := range next.Services {
		nextKinds[service.ID] = service.Kind
	}
	choices := []string{}
	lanChoices := map[string]string{}
	for _, policy := range options {
		original, found := oldPolicies[policy.ID]
		if legacy.Services == nil && len(previous) > 0 && !policyMatchesHistoricalPreference(next.DeviceID, nextKinds[policy.ServiceID], policy, legacy) {
			continue
		}
		if found && intent[policy.ID] && original.ServiceID == policy.ServiceID {
			if nextKinds[policy.ServiceID] == "local_network" {
				if previous, exists := lanChoices[policy.ServiceID]; exists && previous != policy.ID {
					lanChoices[policy.ServiceID] = ""
				} else if !exists {
					lanChoices[policy.ServiceID] = policy.ID
				}
			} else {
				choices = append(choices, policy.ID)
			}
		}
	}
	preference := clientmodel.EmptyPreference()
	for service, policy := range lanChoices {
		if policy != "" {
			if preference.LANPolicyIDs == nil {
				preference.LANPolicyIDs = map[string]string{}
			}
			preference.LANPolicyIDs[service] = policy
		}
	}
	if len(choices) == 1 {
		preference.PolicyID = choices[0]
	}
	// Several formerly simultaneous choices cannot identify one user choice.
	// Preserve pending intent and let the normal current Policy UI select it.
	return preference, nil
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

// PreviewPolicySelectionFile authenticates the finite original before the host
// prepares a disposable runtime cache. The choice stays in identity. No files change.
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
