package control

import "sort"

func (graph *materialGraph) memberDeletedNode(configID, nodeID string) bool {
	for _, table := range graph.chain {
		if table.Operation == "delete" && table.TargetNodeID == nodeID {
			return true
		}
		id, _ := ConfigID(table)
		if id == configID {
			break
		}
	}
	return false
}

// A member certificate changes eligibility, never the bytes or causal validity
// of an original fact. Historical admission uses the table named by that fact.
func (graph *materialGraph) projectInConfig(ids []string, suspended map[string][]string, config ControlConfig) Projection {
	configID, _ := ConfigID(config)
	seals := map[string]ControlSealedKey{}
	deleted := map[string]bool{}
	joins := map[string]ControlJoinBinding{}
	invalidated := map[string]bool{}
	for _, table := range graph.chain {
		for _, seal := range table.SealedKeys {
			seals[seal.KeyID] = seal
		}
		if table.Operation == "delete" {
			deleted[table.TargetNodeID] = true
		}
		if table.Join != nil {
			joins[table.Join.TransactionID] = *table.Join
		}
		if table.Invalidation != nil {
			invalidated[table.Invalidation.TransactionID] = true
		}
		id, _ := ConfigID(table)
		if id == configID {
			break
		}
	}
	project := func(values []string, blocked map[string][]string) Projection {
		view := graph.projectValues(values, blocked, config)
		graph.applyMemberProjection(&view, deleted, joins, invalidated)
		return view
	}
	if len(seals) == 0 {
		return project(ids, suspended)
	}
	available := map[string]bool{}
	for _, id := range ids {
		available[id] = true
	}
	checked, effective := map[string]bool{}, map[string]bool{}
	var eligible func(string) bool
	eligible = func(id string) bool {
		if checked[id] {
			return effective[id]
		}
		checked[id] = true
		material := graph.facts[id]
		if seal, found := seals[material.IssuerKeyID]; found && material.Sequence > seal.Sequence {
			return false
		}
		if isWithdrawal(material.Operation) {
			effective[id] = true
			return true
		}
		history := []string{}
		blocked := map[string][]string{}
		for ancestor := range graph.ancestors[id] {
			if !available[ancestor] {
				continue
			}
			if eligible(ancestor) {
				history = append(history, ancestor)
			} else {
				prior := graph.facts[ancestor]
				if seal, found := seals[prior.IssuerKeyID]; !found || prior.Sequence <= seal.Sequence {
					key := prior.TargetKind + "\x00" + prior.TargetID
					blocked[key] = append(blocked[key], ancestor)
				}
			}
		}
		sort.Strings(history)
		effective[id] = graph.effectiveReferences(material, project(history, blocked))
		return effective[id]
	}
	kept := []string{}
	blocked := map[string][]string{}
	for key, values := range suspended {
		blocked[key] = append([]string{}, values...)
	}
	for _, id := range ids {
		if eligible(id) {
			kept = append(kept, id)
			continue
		}
		material := graph.facts[id]
		if seal, found := seals[material.IssuerKeyID]; !found || material.Sequence <= seal.Sequence {
			key := material.TargetKind + "\x00" + material.TargetID
			blocked[key] = append(blocked[key], id)
		}
	}
	return project(kept, blocked)
}

// Only business references are re-evaluated against eligible ancestors. Key
// ownership, identity binding and lifecycle were verified in the original
// member context and cannot be reinterpreted after a later addition.
func (graph *materialGraph) effectiveReferences(material Material, view Projection) bool {
	reference := func(kind, id string, active bool) bool {
		return requireTargetDependency(material, view, kind, id, active) == nil
	}
	switch value := material.Payload.(type) {
	case Service:
		return validateServiceGateway(material, view, value) == nil
	case NetworkPolicy:
		return reference("service", value.ServiceID, true) && validatePolicyNodes(material, view, value) == nil
	case DeviceAuthorization:
		if material.Operation == "device.put" && !reference("device", value.ID, false) {
			return false
		}
		if material.Operation == "device.join" && !reference("invite", value.TransactionID, true) {
			return false
		}
		return validateAssignedPolicies(material, view, value.PolicyIDs) == nil
	case Invite:
		return reference("endpoint", value.Endpoint.ID, true) && validateAssignedPolicies(material, view, value.PolicyIDs) == nil
	case EnrollmentBind:
		invite, ok := graph.facts[value.InviteMaterialID].Payload.(Invite)
		return ok && reference("invite", value.TransactionID, true) && validateAssignedPolicies(material, view, invite.PolicyIDs) == nil
	case ExpectedComponent:
		return reference("device", value.NodeID, true) && validateExpectedNode(value, view) == nil
	case TransportResource:
		return reference("device", value.OwnerNodeID, true)
	case NetworkLink:
		for _, id := range []string{value.FromResourceID, value.ResourceID, value.ProbeTarget.ResourceID} {
			if !reference("resource", id, true) {
				return false
			}
		}
		return reference("device", value.FromNodeID, true) && reference("device", value.ToNodeID, true)
	case EndpointGeneration:
		if value.WebsiteTrustID != "" && (value.State == "prepared" || value.State == "serving") {
			_, err := endpointWebsiteTrust(view, value)
			return err == nil
		}
	}
	return true
}

func (graph *materialGraph) applyMemberProjection(view *Projection, deleted map[string]bool, joins map[string]ControlJoinBinding, invalidated map[string]bool) {
	view.ControlJoins = []ControlJoinBinding{}
	for _, join := range joins {
		view.ControlJoins = append(view.ControlJoins, join)
	}
	sort.Slice(view.ControlJoins, func(i, j int) bool { return view.ControlJoins[i].TransactionID < view.ControlJoins[j].TransactionID })
	devices := view.DeviceAuthorizations[:0]
	for _, device := range view.DeviceAuthorizations {
		if deleted[device.ID] || invalidated[device.TransactionID] {
			continue
		}
		inviteFact := graph.facts[device.InviteMaterialID]
		invite, found := inviteFact.Payload.(Invite)
		if found && containsString(invite.Responsibilities, "control") {
			initial := false
			for _, member := range graph.configs[inviteFact.ControlConfigID].Members {
				if member.NodeID == device.ID {
					initial = true
				}
			}
			if !initial {
				join, completed := joins[device.TransactionID]
				if !completed || join.DevicePublicKey != device.DevicePublicKey || join.BindingMaterialID != device.BindingMaterialID {
					continue
				}
			}
		}
		devices = append(devices, device)
	}
	view.DeviceAuthorizations = devices
	for node := range deleted {
		found := false
		for i := range view.Targets {
			if view.Targets[i].TargetKind == "device" && view.Targets[i].TargetID == node {
				view.Targets[i].Deleted = true
				view.Targets[i].DeviceForReview = nil
				found = true
			}
		}
		if !found {
			view.Targets = append(view.Targets, TargetState{TargetKind: "device", TargetID: node, Deleted: true, MaterialIDs: []string{}})
		}
	}
	for i := range view.Targets {
		if view.Targets[i].TargetKind == "invite" && invalidated[view.Targets[i].TargetID] {
			view.Targets[i].Deleted = true
		}
	}
	closeEnrollmentConflicts(view)
	sort.Slice(view.Targets, func(i, j int) bool {
		a, b := view.Targets[i], view.Targets[j]
		return a.TargetKind < b.TargetKind || a.TargetKind == b.TargetKind && a.TargetID < b.TargetID
	})
	endpoints := view.EndpointGenerations[:0]
	for _, endpoint := range view.EndpointGenerations {
		if _, found := proofMember(view.Config, endpoint.OwnerControlID); found {
			endpoints = append(endpoints, endpoint)
		}
	}
	view.EndpointGenerations = endpoints
	resources := view.NetworkIntent.Resources[:0]
	removed := map[string]bool{}
	for _, resource := range view.NetworkIntent.Resources {
		if deleted[resource.OwnerNodeID] {
			removed[resource.ID] = true
		} else {
			resources = append(resources, resource)
		}
	}
	view.NetworkIntent.Resources = resources
	links := view.NetworkIntent.Links[:0]
	for _, link := range view.NetworkIntent.Links {
		if !deleted[link.FromNodeID] && !deleted[link.ToNodeID] && !removed[link.FromResourceID] && !removed[link.ResourceID] {
			links = append(links, link)
		}
	}
	view.NetworkIntent.Links = links
}

// Only the exact conditional authorization chosen by the majority contributes
// a device value. Other originals remain signed causal evidence, not alternate
// credential roots or concurrent ordinary updates.
func (graph *materialGraph) memberAuthorizationEffective(id, configID string) bool {
	material := graph.facts[id]
	device, ok := material.Payload.(DeviceAuthorization)
	if !ok {
		return true
	}
	inviteFact := graph.facts[device.InviteMaterialID]
	invite, ok := inviteFact.Payload.(Invite)
	if !ok || !containsString(invite.Responsibilities, "control") {
		return true
	}
	for _, member := range graph.configs[inviteFact.ControlConfigID].Members {
		if member.NodeID == device.ID {
			return true
		}
	}
	selected := false
	for _, table := range graph.chain {
		if table.Join != nil && table.Join.TransactionID == device.TransactionID {
			selected = material.Operation != "device.join" || table.Join.AuthorizationMaterialID == id
		}
		if table.Invalidation != nil && table.Invalidation.TransactionID == device.TransactionID {
			return false
		}
		tableID, _ := ConfigID(table)
		if tableID == configID {
			break
		}
	}
	return selected
}
