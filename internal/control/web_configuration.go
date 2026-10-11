package control

import (
	"errors"
	"net/http"
	"sort"
	"time"
)

// These public values are disposable views of current originals. They neither
// hold secret payloads nor give an object another lifecycle or write authority.
type WebConfigurationSource struct {
	MaterialID string          `json:"material_id"`
	ControlID  string          `json:"control_id"`
	KeyID      string          `json:"key_id"`
	Sequence   U64             `json:"sequence"`
	Operation  string          `json:"operation"`
	Status     string          `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	Value      MaterialPayload `json:"value,omitempty"`
}

type WebConfigurationReference struct {
	Kind             string   `json:"kind"`
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	State            string   `json:"state"`
	Effect           string   `json:"effect,omitempty"`
	PolicyIDs        []string `json:"policy_ids,omitempty"`
	Responsibilities []string `json:"responsibilities,omitempty"`
	ExpiresAt        int64    `json:"expires_at,omitempty"`
}

type WebConfigurationRow struct {
	Target     TargetState                 `json:"target"`
	Sources    []WebConfigurationSource    `json:"sources"`
	References []WebConfigurationReference `json:"references"`
	Resolvable bool                        `json:"resolvable"`
	Reason     string                      `json:"reason,omitempty"`
}

type WebConfiguration struct {
	Schema          int                   `json:"schema"`
	ControlConfigID string                `json:"control_config_id"`
	LocalControlID  string                `json:"local_control_id"`
	ObservedAt      string                `json:"observed_at"`
	Targets         []TargetState         `json:"targets"`
	Policies        []NetworkPolicy       `json:"policies"`
	Rows            []WebConfigurationRow `json:"rows"`
	ReferencesLocal bool                  `json:"references_local"`
}

func publicConfigurationValue(payload MaterialPayload) MaterialPayload {
	if value, ok := payload.(ConflictResolution); ok {
		return publicConfigurationValue(value.Value)
	}
	if value, ok := payload.(DeviceAuthorization); ok {
		return publicDeviceValue(value)
	}
	// Transaction capabilities and identity bindings have their own redacted
	// normal UI entry; do not expose their original payload in this editor.
	switch payload.(type) {
	case Service, NetworkPolicy, DevicePut, TransportResource, NetworkLink, BusinessProbeTarget, ExpectedComponent, DNSRecord, PublicTrust, AdminCertificate, DeleteTarget:
		return payload
	}
	return nil
}

func genesisConfigurationValue(genesis Genesis, kind, id string) MaterialPayload {
	var values []MaterialPayload
	for _, value := range genesis.NetworkIntent.Services {
		values = append(values, value)
	}
	for _, value := range genesis.NetworkIntent.Policies {
		values = append(values, value)
	}
	for _, value := range genesis.NetworkIntent.BusinessProbeTargets {
		values = append(values, value)
	}
	for _, value := range genesis.NetworkIntent.DNSRecords {
		values = append(values, value)
	}
	for _, value := range genesis.NetworkIntent.PublicTrust {
		values = append(values, value)
	}
	for _, value := range genesis.AdminCertificates {
		values = append(values, value)
	}
	for _, value := range values {
		if validateMaterialPayload(kind+".put", kind, id, value) == nil {
			return value
		}
	}
	return nil
}

func (a *Authority) configurationReview(controlID string, now time.Time) (WebConfiguration, error) {
	a.mu.RLock()
	if a.blocked != nil {
		a.mu.RUnlock()
		return WebConfiguration{}, errors.New("current authority is unavailable")
	}
	projection := cloneAuthorityProjection(a.projection)
	genesis := a.genesis
	materials := append([]Material{}, a.materials...)
	certificates := append([]ControlCertificate{}, a.certificates...)
	a.mu.RUnlock()
	genesisID, err := MaterialID(genesis)
	if err != nil {
		return WebConfiguration{}, err
	}
	result := WebConfiguration{Schema: 3, ControlConfigID: projection.ControlConfigID, LocalControlID: controlID, ObservedAt: now.UTC().Format(time.RFC3339Nano), Targets: projection.Targets, Policies: projection.NetworkIntent.Policies, Rows: []WebConfigurationRow{}, ReferencesLocal: true}
	byID := map[string]Material{}
	for _, material := range materials {
		id, err := MaterialID(material)
		if err != nil {
			return WebConfiguration{}, err
		}
		byID[id] = material
	}
	rejected := map[string]string{}
	for _, value := range projection.InvalidMaterials {
		rejected[value.MaterialID] = value.Reason
	}
	completed := map[string]bool{}
	for _, join := range projection.ControlJoins {
		completed[join.TransactionID] = true
	}
	proof := ControlProof{Genesis: genesis, Successors: certificates}
	for id, original := range byID {
		if original.Operation != "device.join" || rejected[id] != "" || contains(projection.PendingMaterialIDs, id) {
			continue
		}
		value := original.Payload.(DeviceAuthorization)
		inviteMaterial, found := byID[value.InviteMaterialID]
		invite, isInvite := inviteMaterial.Payload.(Invite)
		if !found || !isInvite {
			continue
		}
		memberJoin := containsString(invite.Responsibilities, "control")
		if base, found := proofConfig(proof, inviteMaterial.ControlConfigID); found {
			for _, member := range base.Members {
				if member.NodeID == invite.DeviceID {
					memberJoin = false
				}
			}
		}
		if !memberJoin {
			completed[value.TransactionID] = true
		}
	}
	for _, target := range projection.Targets {
		row := WebConfigurationRow{Target: target, Sources: []WebConfigurationSource{}, References: []WebConfigurationReference{}, Resolvable: target.Conflicted && !target.Deleted && resolvableTarget(target.TargetKind) && len(target.MaterialIDs) >= 2}
		for _, id := range target.MaterialIDs {
			material, found := byID[id]
			if id == genesisID {
				material, found = genesis, true
			}
			source := WebConfigurationSource{MaterialID: id, Status: "unavailable"}
			if found {
				source.ControlID, source.KeyID, source.Sequence, source.Operation, source.Status = material.IssuerControlID, material.IssuerKeyID, material.Sequence, material.Operation, "verified"
				source.Value = publicConfigurationValue(effectiveMaterial(material).Payload)
				if id == genesisID {
					source.Value = genesisConfigurationValue(genesis.Payload.(Genesis), target.TargetKind, target.TargetID)
				}
				if contains(projection.PendingMaterialIDs, id) {
					source.Status, source.Value = "pending", nil
				}
				if reason := rejected[id]; reason != "" {
					source.Status, source.Reason, source.Value = "invalid", reason, nil
				}
			}
			if source.Status != "verified" || source.Value == nil {
				row.Resolvable = false
			}
			row.Sources = append(row.Sources, source)
		}
		if target.Conflicted && !row.Resolvable {
			switch {
			case !resolvableTarget(target.TargetKind):
				row.Reason = "This object retains its issuer or owner lifecycle. Use the original enrollment or endpoint entry; bound control changes require member governance."
			case len(target.MaterialIDs) < 2:
				row.Reason = "Other transactions or identities collide with this object. Review the related invitations and member bindings before editing its ordinary value."
			case target.Deleted:
				row.Reason = "Deletion remains effective; ordinary conflict resolution cannot reopen a device tombstone or choose an invalid signing chain."
			default:
				row.Reason = "Some current originals are pending or invalid. Obtain their declared dependencies or resolve the signing member problem before editing a final value."
			}
		}
		result.Rows = append(result.Rows, row)
	}
	for i := range result.Rows {
		result.Rows[i].References = configurationReferences(result.Rows, projection, completed, result.Rows[i].Target, now)
	}
	return result, nil
}

func configurationReferences(rows []WebConfigurationRow, projection Projection, completed map[string]bool, target TargetState, now time.Time) []WebConfigurationReference {
	policyIDs := map[string]bool{}
	if target.TargetKind == "policy" {
		policyIDs[target.TargetID] = true
	}
	refs := map[string]WebConfigurationReference{}
	for _, row := range rows {
		if row.Target.Deleted {
			continue
		}
		for _, source := range row.Sources {
			if value, ok := source.Value.(NetworkPolicy); ok && target.TargetKind == "service" && value.ServiceID == target.TargetID {
				policyIDs[value.ID] = true
				refs["policy\x00"+value.ID] = WebConfigurationReference{Kind: "policy", ID: value.ID, Name: value.Name, State: configurationState(row.Target)}
			}
		}
	}
	for _, row := range rows {
		if row.Target.Deleted {
			continue
		}
		for _, source := range row.Sources {
			if value, ok := source.Value.(DevicePut); ok {
				match := target.TargetKind == "device" && target.TargetID == value.ID
				for _, id := range value.PolicyIDs {
					match = match || policyIDs[id]
				}
				if match {
					key := "device\x00" + value.ID
					prior := refs[key]
					prior.Kind, prior.ID, prior.Name, prior.State = "device", value.ID, value.Name, configurationState(row.Target)
					prior.PolicyIDs = sortedUniqueStrings(append(prior.PolicyIDs, value.PolicyIDs...))
					prior.Responsibilities = sortedUniqueStrings(append(prior.Responsibilities, value.Responsibilities...))
					refs[key] = prior
				}
			}
		}
	}
	for _, invite := range projection.Invites {
		state, found := projection.CurrentTarget("invite", invite.ID)
		if !found || state.Deleted || !now.Before(time.UnixMilli(invite.ExpiresAt)) {
			continue
		}
		if completed[invite.ID] {
			continue
		}
		match := target.TargetKind == "device" && target.TargetID == invite.DeviceID
		for _, id := range invite.PolicyIDs {
			match = match || policyIDs[id]
		}
		if !match {
			continue
		}
		status := "open"
		for _, binding := range projection.Bindings {
			if binding.TransactionID == invite.ID {
				status = "bound"
			}
		}
		if state.Conflicted {
			status = "conflicted"
		}
		refs["invite\x00"+invite.ID] = WebConfigurationReference{Kind: "invite", ID: invite.ID, Name: invite.DeviceID, State: status, PolicyIDs: invite.PolicyIDs, Responsibilities: invite.Responsibilities, ExpiresAt: invite.ExpiresAt}
	}
	keys := []string{}
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := []WebConfigurationReference{}
	for _, key := range keys {
		value := refs[key]
		if target.Conflicted {
			value.Effect = "Access through the conflicted object is paused."
			if value.Kind == "invite" {
				value.Effect = "Claim requires the referenced authorization to recover; existing bindings remain recorded."
			}
		}
		result = append(result, value)
	}
	return result
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func configurationState(target TargetState) string {
	if target.Conflicted {
		return "conflicted"
	}
	if target.Deleted {
		return "deleted"
	}
	return "effective_here"
}

func (server *Server) configurationReview(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "configuration review accepts no query parameters", http.StatusBadRequest)
		return
	}
	result, err := server.Runtime.Authority.configurationReview(server.Config.ControlID, server.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
