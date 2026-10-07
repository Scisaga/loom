package linuxclient

import (
	"errors"
	"reflect"
)

func (transaction *wireGuardTransaction) execution() wireGuardExecution {
	result := wireGuardExecution{WireGuard: []wireGuardExecutionLink{}}
	if transaction != nil {
		for _, owned := range transaction.owned {
			if owned.alias != "" {
				result.WireGuard = append(result.WireGuard, owned.peerLinks()...)
			}
		}
	}
	return result
}

// Only a live creation handle may preserve an interface. A matching old View,
// name or crash-cleanup record alone is never sufficient to adopt one.
func (transaction *wireGuardTransaction) sameExecution(profile wireGuardExecution, identity *wireGuardIdentity) bool {
	groups, err := groupWireGuardLinks(profile.WireGuard)
	if transaction == nil || err != nil || len(transaction.owned) != len(groups) {
		return false
	}
	for index, group := range groups {
		owned := transaction.owned[index]
		if !owned.configured || owned.alias == "" || owned.link != group.link || !reflect.DeepEqual(owned.peers, group.peers) || identity == nil || owned.publicKey != identity.WGPublicKey {
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
		if err := (*current).verifyFilters(); err != nil {
			return err
		}
		return readbackWireGuard(profile, options)
	}
	if handled, err := (*current).reconcileAccessPeers(profile, identity); handled {
		return err
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
