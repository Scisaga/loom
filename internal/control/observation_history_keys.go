package control

import (
	"context"
	"errors"
)

// Offline verification must not create the reception/coverage annotations that
// normal Authority startup initializes. Only its verified original projection
// is needed; retain the same authority lock while reading it.
func loadReportVerificationKeys(ctx context.Context, root string) (map[reportOwner]string, error) {
	lock, err := lockAuthority(ctx, root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	authority := &Authority{root: root}
	if err := authority.reloadLocked(); err != nil {
		return nil, err
	}
	return authority.reportVerificationKeys()
}

// Historical identity only, never permission. Revocation and deletion do not
// erase a previously accepted immutable binding needed to audit signed reports.
func (a *Authority) reportVerificationKeys() (map[reportOwner]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := map[reportOwner]string{}
	remember := func(owner reportOwner, key string) error {
		if ValidateID(owner.network) != nil || ValidateID(owner.device) != nil || ValidatePublicKey(key) != nil {
			return errors.New("invalid accepted report identity binding")
		}
		if previous := keys[owner]; previous != "" && previous != key {
			return errors.New("conflicting immutable report identity bindings")
		}
		keys[owner] = key
		return nil
	}
	excluded := map[string]bool{}
	for _, id := range a.projection.PendingMaterialIDs {
		excluded[id] = true
	}
	for _, invalid := range a.projection.InvalidMaterials {
		excluded[invalid.MaterialID] = true
	}
	for _, material := range a.materials {
		id, err := MaterialID(material)
		if err != nil {
			return nil, err
		}
		if excluded[id] || material.Operation != "device.join" || material.Sequence > frontierFor(a.projection.Frontier, material.IssuerKeyID).Sequence {
			continue
		}
		device, ok := material.Payload.(DeviceAuthorization)
		if !ok {
			return nil, errors.New("accepted report device binding is invalid")
		}
		if err := remember(reportOwner{material.NetworkID, device.ID}, device.DevicePublicKey); err != nil {
			return nil, err
		}
	}
	// A majority-certified Join binds the reporting key for a newly added
	// control-only device, which need not have an ordinary device.join fact.
	// Genesis members can have independent device keys: do not substitute their
	// control signing keys for missing ordinary enrollment bindings.
	for _, certificate := range a.certificates {
		config := certificate.Config
		if config.Join == nil {
			continue
		}
		if err := remember(reportOwner{config.NetworkID, config.TargetNodeID}, config.Join.DevicePublicKey); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
