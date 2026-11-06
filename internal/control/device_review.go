package control

// revokedDeviceForReview projects only the public value known in the causal
// history of the current withdrawals. It cannot authorize a device: active
// authorization continues to come exclusively from DeviceAuthorizations.
func (graph *materialGraph) revokedDeviceForReview(facts, maxima []targetFact) *DevicePut {
	candidates := []targetFact{}
	for _, fact := range facts {
		if fact.operation == "device.delete" {
			return nil
		}
		if _, ok := fact.payload.(DeviceAuthorization); !ok {
			continue
		}
		for _, withdrawal := range maxima {
			if withdrawal.operation == "device.revoke" && graph.ancestors[withdrawal.id][fact.id] {
				candidates = append(candidates, fact)
				break
			}
		}
	}
	var reviewed *DevicePut
	for _, candidate := range candidates {
		superseded := false
		for _, other := range candidates {
			if candidate.id != other.id && graph.ancestors[other.id][candidate.id] {
				superseded = true
				break
			}
		}
		if superseded {
			continue
		}
		if reviewed != nil {
			return nil
		}
		value := candidate.payload.(DeviceAuthorization)
		public := publicDeviceValue(value)
		reviewed = &public
	}
	return reviewed
}
