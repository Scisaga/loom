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
	"runtime"

	"loom/internal/control"
)

const stateSchema = 2

type State struct {
	Schema         int                         `json:"schema"`
	V2Latch        bool                        `json:"v2_latch"`
	PrivateKey     string                      `json:"private_key"`
	PublicKey      string                      `json:"public_key"`
	ClaimRequestID string                      `json:"claim_request_id"`
	Capability     control.BootstrapCapability `json:"capability"`
	Floor          uint64                      `json:"floor"`
	LKG            *control.DeviceViewEnvelope `json:"certified_lkg,omitempty"`
}

type Store struct {
	path  string
	state State
}

func Open(path string, invite control.BootstrapInvite) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || invite.Schema != 1 || invite.Capability.Validate() != nil {
		return nil, errors.New("device state path or invite is invalid")
	}
	store := &Store{path: path}
	if err := store.load(); err == nil {
		left, _ := json.Marshal(store.state.Capability)
		right, _ := json.Marshal(invite.Capability)
		if !bytes.Equal(left, right) {
			return nil, errors.New("device state is bound to another enrollment capability")
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
	store.state = State{Schema: stateSchema, V2Latch: true, PrivateKey: base64.RawURLEncoding.EncodeToString(private),
		PublicKey: base64.RawURLEncoding.EncodeToString(public), ClaimRequestID: hex.EncodeToString(request),
		Capability: invite.Capability}
	if err := store.save(store.state); err != nil {
		return nil, err
	}
	return store, nil
}

func Load(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("device state path is invalid")
	}
	store := &Store{path: path}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *Store) load() error {
	info, err := os.Lstat(store.path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 || info.Size() > 4<<20 {
		return errors.New("device state must be an owner-only bounded regular file")
	}
	body, err := os.ReadFile(store.path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store.state); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("device state has trailing content")
	}
	// Schema 1 was the already-deployed certified LKG store. Migrate it once,
	// after full validation, so identity, rollback floor and exact LKG survive
	// while a stripped latch on schema 2 remains a hard failure.
	if store.state.Schema == 1 && !store.state.V2Latch {
		store.state.Schema = stateSchema
		store.state.V2Latch = true
		if err := store.validate(); err != nil {
			return fmt.Errorf("migrate legacy device state: %w", err)
		}
		return store.save(store.state)
	}
	return store.validate()
}

func (store *Store) validate() error {
	private, err := base64.RawURLEncoding.DecodeString(store.state.PrivateKey)
	public, publicErr := base64.RawURLEncoding.DecodeString(store.state.PublicKey)
	if store.state.Schema != stateSchema || !store.state.V2Latch || err != nil || publicErr != nil || len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize ||
		!ed25519.PrivateKey(private).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(public)) ||
		store.state.ClaimRequestID == "" || store.state.Capability.Validate() != nil {
		return errors.New("device identity state is invalid")
	}
	if store.state.LKG == nil {
		if store.state.Floor != 0 {
			return errors.New("device state has a floor without LKG")
		}
		return nil
	}
	if err := control.VerifyDeviceViewEnvelope(*store.state.LKG, store.state.Capability); err != nil ||
		store.state.LKG.View.DevicePublicKey != store.state.PublicKey || store.state.Floor != store.state.LKG.Head.Index ||
		store.state.Floor < store.state.LKG.View.Floor {
		return errors.New("device LKG is invalid")
	}
	return nil
}

func (store *Store) save(next State) error {
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".device-state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, store.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	store.state = next
	return nil
}

func (store *Store) PrivateKey() ed25519.PrivateKey {
	key, _ := base64.RawURLEncoding.DecodeString(store.state.PrivateKey)
	return ed25519.PrivateKey(append([]byte(nil), key...))
}

func (store *Store) PublicKey() string                       { return store.state.PublicKey }
func (store *Store) Capability() control.BootstrapCapability { return store.state.Capability }
func (store *Store) ClaimRequestID() string                  { return store.state.ClaimRequestID }
func (store *Store) LKG() *control.DeviceViewEnvelope {
	if store.state.LKG == nil {
		return nil
	}
	body, _ := json.Marshal(store.state.LKG)
	var copy control.DeviceViewEnvelope
	_ = json.Unmarshal(body, &copy)
	return &copy
}

func (store *Store) SaveLKG(envelope control.DeviceViewEnvelope) error {
	if err := control.VerifyDeviceViewEnvelope(envelope, store.state.Capability); err != nil {
		return err
	}
	if envelope.View.DevicePublicKey != store.state.PublicKey || envelope.Head.Index < store.state.Floor {
		return errors.New("device view is bound to another identity or rolls back floor")
	}
	next := store.state
	next.Floor = envelope.Head.Index
	next.LKG = &envelope
	if err := (&Store{state: next}).validate(); err != nil {
		return fmt.Errorf("validate next device LKG: %w", err)
	}
	return store.save(next)
}
