package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"loom/internal/clientmodel"
	"loom/internal/clientsecret"
	"loom/internal/control"
)

const (
	protectedStateSchema  = 1
	protectedStatePurpose = "device-profile-v2"
)

type protectedState struct {
	Schema         int                         `json:"schema"`
	V2Latch        bool                        `json:"v2_latch"`
	PrivateKey     string                      `json:"private_key"`
	PublicKey      string                      `json:"public_key"`
	ClaimRequestID string                      `json:"claim_request_id"`
	Capability     control.BootstrapCapability `json:"capability"`
	Floor          uint64                      `json:"floor"`
	LKG            *control.DeviceViewEnvelope `json:"certified_lkg,omitempty"`
	Preference     clientmodel.Preference      `json:"preference"`
}

// ProtectedStore is one Windows profile's authoritative DPAPI envelope. The
// profile index intentionally cannot reconstruct any field in this store.
type ProtectedStore struct {
	mu        sync.Mutex
	path      string
	protector clientsecret.Protector
	state     protectedState
	preflight func(control.DeviceViewEnvelope) error
}

// SetLKGPreflight installs the HostAdapter check that must succeed before a
// newly received certified view may replace the previous protected LKG.
func (store *ProtectedStore) SetLKGPreflight(preflight func(control.DeviceViewEnvelope) error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.preflight = preflight
}

func validateProtectedStorePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("protected device state path is invalid")
	}
	return nil
}

func OpenProtected(path string, invite control.BootstrapInvite, protector clientsecret.Protector) (*ProtectedStore, error) {
	if err := validateProtectedStorePath(path); err != nil || protector == nil || invite.Schema != 1 || invite.Capability.Validate() != nil {
		return nil, errors.New("protected device state path, protector, or invite is invalid")
	}
	store := &ProtectedStore{path: path, protector: protector}
	if err := store.load(); err == nil {
		left, _ := json.Marshal(store.state.Capability)
		right, _ := json.Marshal(invite.Capability)
		if !bytes.Equal(left, right) {
			return nil, errors.New("protected device state is bound to another enrollment capability")
		}
		return store, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	request := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, request); err != nil {
		return nil, err
	}
	store.state = protectedState{Schema: protectedStateSchema, V2Latch: true,
		PrivateKey: base64.RawURLEncoding.EncodeToString(private), PublicKey: base64.RawURLEncoding.EncodeToString(public),
		ClaimRequestID: hex.EncodeToString(request), Capability: invite.Capability,
		Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}}
	if err := store.save(store.state); err != nil {
		return nil, err
	}
	return store, nil
}

func LoadProtected(path string, protector clientsecret.Protector) (*ProtectedStore, error) {
	if err := validateProtectedStorePath(path); err != nil || protector == nil {
		return nil, errors.New("protected device state path or protector is invalid")
	}
	store := &ProtectedStore{path: path, protector: protector}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func validateProtectedState(state protectedState) error {
	private, privateErr := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	public, publicErr := base64.RawURLEncoding.DecodeString(state.PublicKey)
	if state.Schema != protectedStateSchema || !state.V2Latch || privateErr != nil || publicErr != nil ||
		len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize ||
		!ed25519.PrivateKey(private).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(public)) ||
		state.ClaimRequestID == "" || state.Capability.Validate() != nil || state.Preference.Validate() != nil {
		return errors.New("protected device identity state is invalid")
	}
	if state.LKG == nil {
		if state.Floor != 0 {
			return errors.New("protected device state has a floor without LKG")
		}
		return nil
	}
	if err := control.VerifyDeviceViewEnvelope(*state.LKG, state.Capability); err != nil ||
		state.LKG.View.DevicePublicKey != state.PublicKey || state.LKG.View.Platform != "windows" ||
		state.LKG.View.Runtime == nil || state.LKG.View.Runtime.Validate(state.LKG.View.Routes) != nil ||
		state.Floor != state.LKG.Head.Index || state.Floor < state.LKG.View.Floor {
		return errors.New("protected Windows device LKG is invalid")
	}
	return nil
}

func (store *ProtectedStore) load() error {
	var state protectedState
	if err := clientsecret.ReadJSONProtected(store.path, protectedStatePurpose, &state, store.protector); err != nil {
		return err
	}
	if err := validateProtectedState(state); err != nil {
		return err
	}
	store.state = state
	return nil
}

func (store *ProtectedStore) save(next protectedState) error {
	if err := validateProtectedState(next); err != nil {
		return err
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".device-profile-*.dpapi")
	if err != nil {
		return err
	}
	temporary := file.Name()
	if closeErr := file.Close(); closeErr != nil {
		_ = os.Remove(temporary)
		return closeErr
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := clientsecret.WriteJSONProtected(temporary, protectedStatePurpose, next, store.protector); err != nil {
		return err
	}
	var readback protectedState
	if err := clientsecret.ReadJSONProtected(temporary, protectedStatePurpose, &readback, store.protector); err != nil {
		return fmt.Errorf("read back staged protected profile: %w", err)
	}
	if err := validateProtectedState(readback); err != nil {
		return fmt.Errorf("validate staged protected profile: %w", err)
	}
	want, _ := json.Marshal(next)
	got, _ := json.Marshal(readback)
	if !bytes.Equal(want, got) {
		return errors.New("protected profile readback differs from staged authority")
	}
	if err := replaceProtectedFile(temporary, store.path); err != nil {
		return err
	}
	if err := syncProtectedDirectory(directory); err != nil {
		return err
	}
	var committed protectedState
	if err := clientsecret.ReadJSONProtected(store.path, protectedStatePurpose, &committed, store.protector); err != nil {
		return fmt.Errorf("read back committed protected profile: %w", err)
	}
	if err := validateProtectedState(committed); err != nil {
		return fmt.Errorf("validate committed protected profile: %w", err)
	}
	got, _ = json.Marshal(committed)
	if !bytes.Equal(want, got) {
		return errors.New("committed protected profile differs from staged authority")
	}
	store.state = committed
	return nil
}

func (store *ProtectedStore) PrivateKey() ed25519.PrivateKey {
	store.mu.Lock()
	defer store.mu.Unlock()
	key, _ := base64.RawURLEncoding.DecodeString(store.state.PrivateKey)
	return ed25519.PrivateKey(append([]byte(nil), key...))
}

func (store *ProtectedStore) PublicKey() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.PublicKey
}

func (store *ProtectedStore) Capability() control.BootstrapCapability {
	store.mu.Lock()
	defer store.mu.Unlock()
	body, _ := json.Marshal(store.state.Capability)
	var copy control.BootstrapCapability
	_ = json.Unmarshal(body, &copy)
	return copy
}

func (store *ProtectedStore) ClaimRequestID() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.ClaimRequestID
}

func (store *ProtectedStore) LKG() *control.DeviceViewEnvelope {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.LKG == nil {
		return nil
	}
	body, _ := json.Marshal(store.state.LKG)
	var copy control.DeviceViewEnvelope
	_ = json.Unmarshal(body, &copy)
	return &copy
}

func (store *ProtectedStore) Preference() clientmodel.Preference {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.Preference
}

func (store *ProtectedStore) SetPreference(preference clientmodel.Preference) error {
	if err := preference.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	next := store.state
	next.Preference = preference
	return store.save(next)
}

func (store *ProtectedStore) SaveLKG(envelope control.DeviceViewEnvelope) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := control.VerifyDeviceViewEnvelope(envelope, store.state.Capability); err != nil {
		return err
	}
	if envelope.View.DevicePublicKey != store.state.PublicKey || envelope.View.Platform != "windows" ||
		envelope.View.Runtime == nil || envelope.View.Runtime.Validate(envelope.View.Routes) != nil ||
		envelope.Head.Index < store.state.Floor {
		return errors.New("Windows device view is invalid, bound to another identity, or rolls back floor")
	}
	if store.preflight == nil {
		return errors.New("Windows HostAdapter preflight is required before replacing the certified LKG")
	}
	if err := store.preflight(envelope); err != nil {
		return fmt.Errorf("Windows HostAdapter preflight: %w", err)
	}
	next := store.state
	next.Floor = envelope.Head.Index
	next.LKG = &envelope
	return store.save(next)
}
