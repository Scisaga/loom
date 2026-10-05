package linuxclient

import "errors"

func (transaction *wireGuardTransaction) execution() wireGuardExecution {
	result := wireGuardExecution{WireGuard: []wireGuardExecutionLink{}}
	if transaction != nil {
		for _, owned := range transaction.owned {
			if owned.alias != "" {
				result.WireGuard = append(result.WireGuard, owned.link)
			}
		}
	}
	return result
}

// Only a live creation handle may preserve an interface. A matching old View,
// name or crash-cleanup record alone is never sufficient to adopt one.
func (transaction *wireGuardTransaction) sameExecution(profile wireGuardExecution, identity *wireGuardIdentity) bool {
	if transaction == nil || len(transaction.owned) != len(profile.WireGuard) {
		return false
	}
	for index, link := range profile.WireGuard {
		owned := transaction.owned[index]
		if !owned.configured || owned.alias == "" || owned.link != link || identity == nil || owned.publicKey != identity.WGPublicKey {
			return false
		}
	}
	return true
}

func replaceWireGuard(current **wireGuardTransaction, profile wireGuardExecution, identity *wireGuardIdentity, options Options) error {
	if (*current).sameExecution(profile, identity) {
		if len(profile.WireGuard) == 0 {
			return nil
		}
		publicKey, err := privateWireGuardPublicKey(options.WireGuard, options.WireGuardPrivateKey)
		if err != nil || publicKey != identity.WGPublicKey {
			return errors.New("WireGuard private key does not match the certified server identity")
		}
		for _, owned := range (*current).owned {
			actual, exists, err := inspectOwnedWireGuardInterface(options, owned)
			if err != nil || !exists || actual.Name != owned.link.Interface || actual.Index != owned.index ||
				actual.Alias != owned.alias || actual.Info.Kind != "wireguard" {
				return errors.Join(ErrWireGuardOwnership, err)
			}
			if err := verifyOwnedWireGuardLink(options, owned); err != nil {
				return errors.Join(ErrWireGuardOwnership, err)
			}
		}
		return readbackWireGuard(profile, options)
	}
	if err := (*current).Cleanup(); err != nil {
		return err
	}
	*current = nil
	transaction, err := applyWireGuard(&profile, nil, identity, options)
	if err == nil {
		*current = transaction
	}
	return err
}
