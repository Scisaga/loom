package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"loom/internal/clientmodel"
	"loom/internal/clientsecret"
	"loom/internal/control"
)

const stateSchema = 3
const maxStateBytes = 5 << 20

var stateLimits = control.ContractDecodeLimits{MaxBytes: maxStateBytes, MaxDepth: 128, MaxItems: 1 << 20}

// State is the one accepted device identity and authorization. Protection is a
// storage adapter; it does not create a second Windows authorization model.
type State struct {
	Schema             int                         `json:"schema"`
	AuthenticatedLatch bool                        `json:"authenticated_latch"`
	PrivateKey         string                      `json:"private_key"`
	PublicKey          string                      `json:"public_key"`
	Platform           string                      `json:"platform"`
	ClaimRequestID     string                      `json:"claim_request_id"`
	Invite             control.BootstrapInvite     `json:"invite"`
	HighWater          []control.FactFrontier      `json:"high_water"`
	ReportSequence     control.U64                 `json:"report_sequence"`
	LKG                *control.DeviceViewEnvelope `json:"certified_lkg,omitempty"`
	Preference         *clientmodel.Preference     `json:"preference,omitempty"`
}

// NewIdentityState is shared with encrypted mobile storage. The caller creates
// the identity once and durably saves this value before making a claim.
func NewIdentityState(invite control.BootstrapInvite, platform string, private ed25519.PrivateKey, claimRequestID string) (State, error) {
	if len(private) != ed25519.PrivateKeySize {
		return State{}, errors.New("device private key is invalid")
	}
	state := State{Schema: stateSchema, AuthenticatedLatch: true, PrivateKey: base64.RawURLEncoding.EncodeToString(private), PublicKey: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Platform: platform, ClaimRequestID: claimRequestID, Invite: invite, HighWater: []control.FactFrontier{}}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return cloneCanonical(state), nil
}

// AcceptLKG returns the next authoritative value. The caller must commit it
// atomically before applying runtime changes; no runtime outcome is an input.
func AcceptLKG(state State, envelope control.DeviceViewEnvelope) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if err := control.VerifyDeviceViewEnvelope(envelope, state.Invite); err != nil {
		return State{}, err
	}
	if envelope.View.DevicePublicKey != state.PublicKey || envelope.View.Platform != state.Platform {
		return State{}, errors.New("device view is bound to another identity or platform")
	}
	if state.LKG != nil {
		if err := control.CheckDeviceViewAdvance(envelope, *state.LKG, state.HighWater); err != nil {
			return State{}, err
		}
	}
	next := state
	next.LKG = &envelope
	next.HighWater = append([]control.FactFrontier{}, envelope.FactFrontier...)
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return cloneCanonical(next), nil
}

// AdvanceReportSequence reserves a number in the same identity value. Commit
// the returned State before signing/sending; a failed send consumes its number.
func AdvanceReportSequence(state State) (State, control.U64, error) {
	if err := state.Validate(); err != nil {
		return State{}, 0, err
	}
	if state.LKG == nil || state.ReportSequence == control.U64(math.MaxUint64) {
		return State{}, 0, errors.New("report sequence cannot advance")
	}
	state.ReportSequence++
	return cloneCanonical(state), state.ReportSequence, nil
}

func EncodeIdentityState(state State) ([]byte, error) {
	body, err := control.CanonicalEncode(state)
	if err != nil {
		return nil, err
	}
	if len(body) > maxStateBytes {
		return nil, errors.New("device state exceeds protected storage limit")
	}
	return body, nil
}

func DecodeIdentityState(body []byte) (State, error) {
	var state State
	err := control.DecodeCanonical(body, &state, stateLimits)
	return state, err
}

func CheckIdentityStateAdvance(next, previous State) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	return checkStateAdvance(next, previous)
}

func (state State) Validate() error {
	private, err := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	if state.Schema != stateSchema || !state.AuthenticatedLatch || err != nil || len(private) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(private) != state.PrivateKey ||
		!bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || control.ValidatePublicKey(state.PublicKey) != nil ||
		base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(private).Public().(ed25519.PublicKey)) != state.PublicKey || control.ValidateID(state.ClaimRequestID) != nil ||
		state.Invite.Validate() != nil || state.HighWater == nil || state.Platform != "linux" && state.Platform != "windows" && state.Platform != "android" {
		return errors.New("device identity state is invalid")
	}
	if state.Preference != nil && state.Preference.Validate() != nil {
		return errors.New("device preference is invalid")
	}
	for i, prefix := range state.HighWater {
		if prefix.Validate() != nil || i > 0 && state.HighWater[i-1].KeyID >= prefix.KeyID {
			return errors.New("saved fact high-water values are invalid")
		}
	}
	if state.LKG == nil {
		if len(state.HighWater) != 0 || state.ReportSequence != 0 {
			return errors.New("device state has accepted progress without LKG")
		}
		return nil
	}
	if err := control.VerifyDeviceViewEnvelope(*state.LKG, state.Invite); err != nil {
		return err
	}
	if state.LKG.View.DevicePublicKey != state.PublicKey || state.LKG.View.Platform != state.Platform {
		return errors.New("device LKG is bound to another identity or platform")
	}
	if _, err := control.VerifyControlProofExtension(state.LKG.ControlProof, state.Invite.ControlProof, state.Invite.NetworkID, state.Invite.GenesisDigest); err != nil {
		return err
	}
	return control.CheckDeviceViewAdvance(*state.LKG, *state.LKG, state.HighWater)
}

type Store struct {
	mu        sync.Mutex
	path      string
	protector clientsecret.Protector
	state     State
	failed    error
}

func validStatePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}
func Open(path string, invite control.BootstrapInvite) (*Store, error) {
	return OpenForPlatform(path, invite, runtime.GOOS)
}
func OpenForPlatform(path string, invite control.BootstrapInvite, platform string) (*Store, error) {
	return openStore(path, invite, platform, nil)
}
func openStore(path string, invite control.BootstrapInvite, platform string, protector clientsecret.Protector) (*Store, error) {
	if !validStatePath(path) || invite.Validate() != nil || platform != "linux" && platform != "windows" && platform != "android" {
		return nil, errors.New("device state path, platform or invite is invalid")
	}
	store := &Store{path: path, protector: protector}
	if err := store.load(); err == nil {
		left, _ := control.CanonicalEncode(store.state.Invite)
		right, _ := control.CanonicalEncode(invite)
		if !bytes.Equal(left, right) || store.state.Platform != platform {
			return nil, errors.New("device state is bound to another invitation or platform")
		}
		return store, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	request := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, request); err != nil {
		return nil, err
	}
	next, err := NewIdentityState(invite, platform, private, hex.EncodeToString(request))
	if err != nil {
		return nil, err
	}
	if protector != nil {
		next.Preference = &clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}
	}
	if err := store.save(next, nil, false); err != nil {
		return nil, err
	}
	return store, nil
}
func Load(path string) (*Store, error) { return loadStore(path, nil) }
func loadStore(path string, protector clientsecret.Protector) (*Store, error) {
	if !validStatePath(path) {
		return nil, errors.New("device state path is invalid")
	}
	store := &Store{path: path, protector: protector}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}
func (store *Store) validateState(state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if store.protector != nil && (state.Platform != "windows" || state.Preference == nil) {
		return errors.New("protected device state is not a Windows profile")
	}
	if store.protector == nil && state.Preference != nil {
		return errors.New("plain device identity cannot contain a protected profile preference")
	}
	return nil
}
func (store *Store) readUnlocked() (State, error) {
	var state State
	var body []byte
	var err error
	if store.protector != nil {
		body, err = clientsecret.ReadProtected(store.path, protectedStatePurpose, store.protector)
	} else {
		before, statErr := os.Lstat(store.path)
		if statErr != nil {
			return state, statErr
		}
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 || before.Size() > maxStateBytes {
			return state, errors.New("device state must be an owner-only bounded regular file")
		}
		file, openErr := os.Open(store.path)
		if openErr != nil {
			return state, openErr
		}
		defer file.Close()
		after, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
			return state, errors.New("device state changed during open")
		}
		body, err = io.ReadAll(io.LimitReader(file, maxStateBytes+1))
		if err == nil && int64(len(body)) != after.Size() {
			err = errors.New("device state changed during read")
		}
	}
	if err != nil {
		return state, err
	}
	defer clear(body)
	if err := control.DecodeCanonical(body, &state, stateLimits); err != nil {
		return State{}, err
	}
	if err := store.validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}
func (store *Store) load() error {
	lock, err := lockStateFile(store.path)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := store.readUnlocked()
	if err != nil {
		return err
	}
	if err := syncProtectedDirectory(filepath.Dir(store.path)); err != nil {
		return err
	}
	store.state = state
	return nil
}
func fixedIdentityEqual(left, right State) bool {
	a, _ := control.CanonicalEncode(left.Invite)
	b, _ := control.CanonicalEncode(right.Invite)
	return left.PrivateKey == right.PrivateKey && left.PublicKey == right.PublicKey && left.Platform == right.Platform && left.ClaimRequestID == right.ClaimRequestID && left.AuthenticatedLatch && right.AuthenticatedLatch && bytes.Equal(a, b)
}
func checkStateAdvance(next, previous State) error {
	if !fixedIdentityEqual(next, previous) || next.ReportSequence < previous.ReportSequence {
		return errors.New("persistent device identity or report sequence cannot roll back")
	}
	if previous.LKG != nil {
		if next.LKG == nil {
			return errors.New("accepted LKG cannot be removed")
		}
		return control.CheckDeviceViewAdvance(*next.LKG, *previous.LKG, previous.HighWater)
	}
	return nil
}
func (store *Store) fail(err error) error {
	if err != nil {
		store.failed = err
	}
	return err
}
func (store *Store) save(next State, preference *clientmodel.Preference, reserveReport bool) error {
	if store.failed != nil {
		return errors.New("device persistence previously failed; reopen the state before continuing")
	}
	if err := store.validateState(next); err != nil {
		return err
	}
	lock, err := lockStateFile(store.path)
	if err != nil {
		return store.fail(err)
	}
	defer lock.Close()
	current, readErr := store.readUnlocked()
	if readErr == nil {
		if !fixedIdentityEqual(next, current) {
			return errors.New("device write conflicts with current persistent identity")
		}
		if preference != nil || reserveReport {
			// Preference/report updates consume current durable authority, never the
			// stale LKG held by a separate GUI or reporting handle.
			next = current
			if preference != nil {
				copy := *preference
				next.Preference = &copy
			}
			if reserveReport {
				next, _, err = AdvanceReportSequence(current)
				if err != nil {
					return err
				}
			}
		} else {
			next.Preference = current.Preference
			next.ReportSequence = current.ReportSequence
			if err := checkStateAdvance(next, current); err != nil {
				return err
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return store.fail(readErr)
	} else if store.state.Schema != 0 {
		return store.fail(errors.New("accepted identity file disappeared"))
	}
	if err := store.validateState(next); err != nil {
		return err
	}
	body, err := control.CanonicalEncode(next)
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) > maxStateBytes {
		return errors.New("device state exceeds protected storage limit")
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return store.fail(err)
	}
	file, err := os.CreateTemp(directory, ".device-state-*")
	if err != nil {
		return store.fail(err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if store.protector == nil {
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(body)
		}
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	} else {
		err = file.Close()
		if err == nil {
			err = os.Remove(temporary)
		}
		if err == nil {
			err = clientsecret.WriteProtected(temporary, protectedStatePurpose, body, store.protector)
		}
	}
	if err != nil {
		return store.fail(err)
	}
	staged := &Store{path: temporary, protector: store.protector}
	readback, err := staged.readUnlocked()
	if err != nil {
		return store.fail(err)
	}
	got, err := control.CanonicalEncode(readback)
	if err != nil || !bytes.Equal(body, got) {
		return store.fail(errors.New("staged device state readback mismatch"))
	}
	clear(got)
	if err := replaceProtectedFile(temporary, store.path); err != nil {
		return store.fail(err)
	}
	if err := syncProtectedDirectory(directory); err != nil {
		return store.fail(err)
	}
	committed, err := store.readUnlocked()
	if err != nil {
		return store.fail(err)
	}
	got, err = control.CanonicalEncode(committed)
	if err != nil || !bytes.Equal(body, got) {
		return store.fail(errors.New("committed device state readback mismatch"))
	}
	clear(got)
	store.state = committed
	return nil
}
func (store *Store) PrivateKey() ed25519.PrivateKey {
	store.mu.Lock()
	defer store.mu.Unlock()
	key, _ := base64.RawURLEncoding.DecodeString(store.state.PrivateKey)
	return ed25519.PrivateKey(key)
}
func (store *Store) PublicKey() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.PublicKey
}
func (store *Store) Platform() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.Platform
}
func (store *Store) ClaimRequestID() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.ClaimRequestID
}
func cloneCanonical[T any](value T) T {
	body, err := control.CanonicalEncode(value)
	if err != nil {
		panic("invalid in-memory device authority")
	}
	var copy T
	if control.DecodeCanonical(body, &copy, stateLimits) != nil {
		panic("invalid in-memory device authority")
	}
	return copy
}
func (store *Store) Invite() control.BootstrapInvite {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneCanonical(store.state.Invite)
}
func (store *Store) LKG() *control.DeviceViewEnvelope {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.LKG == nil {
		return nil
	}
	copy := cloneCanonical(*store.state.LKG)
	return &copy
}
func (store *Store) Reload() (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failed != nil {
		return false, errors.New("device persistence previously failed; reopen the state before continuing")
	}
	current := &Store{path: store.path, protector: store.protector}
	if err := current.load(); err != nil {
		return false, store.fail(err)
	}
	if err := checkStateAdvance(current.state, store.state); err != nil {
		return false, err
	}
	before, _ := control.CanonicalEncode(store.state.LKG)
	after, _ := control.CanonicalEncode(current.state.LKG)
	changed := !bytes.Equal(before, after)
	clear(before)
	clear(after)
	store.state = current.state
	return changed, nil
}
func (store *Store) SaveLKG(envelope control.DeviceViewEnvelope) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, err := AcceptLKG(store.state, envelope)
	if err != nil {
		return err
	}
	return store.save(next, nil, false)
}
func (store *Store) ReserveReportSequence() (control.U64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.save(store.state, nil, true); err != nil {
		return 0, err
	}
	return store.state.ReportSequence, nil
}
