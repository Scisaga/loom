package deviceclient

import (
	"errors"
	"loom/internal/clientmodel"
	"loom/internal/clientsecret"
	"loom/internal/control"
)

const protectedStatePurpose = "device-profile-v3"

// Both storage adapters encode the same authoritative identity value.
type protectedState = State

type ProtectedStore struct{ *Store }

func OpenProtected(path string, invite control.BootstrapInvite, protector clientsecret.Protector) (*ProtectedStore, error) {
	if protector == nil {
		return nil, errors.New("protected device state requires a protector")
	}
	store, err := openStore(path, invite, "windows", protector)
	if err != nil {
		return nil, err
	}
	return &ProtectedStore{Store: store}, nil
}
func LoadProtected(path string, protector clientsecret.Protector) (*ProtectedStore, error) {
	if protector == nil {
		return nil, errors.New("protected device state requires a protector")
	}
	store, err := loadStore(path, protector)
	if err != nil {
		return nil, err
	}
	return &ProtectedStore{Store: store}, nil
}
func (store *ProtectedStore) Preference() clientmodel.Preference {
	store.mu.Lock()
	defer store.mu.Unlock()
	return *store.state.Preference
}
func (store *ProtectedStore) SetPreference(preference clientmodel.Preference) error {
	if err := preference.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.save(store.state, &preference, false)
}
