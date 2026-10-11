package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
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
	return cloneOwnedAuthority(state), nil
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
	highWater := map[string]control.FactFrontier{}
	inviteID, err := control.MaterialID(state.Invite.Material)
	if err != nil {
		return State{}, err
	}
	invitation := state.Invite.Material
	highWater[invitation.IssuerKeyID] = control.FactFrontier{KeyID: invitation.IssuerKeyID, Sequence: invitation.Sequence, TipMaterialID: inviteID}
	for _, prefix := range append(append([]control.FactFrontier{}, state.HighWater...), envelope.FactFrontier...) {
		previous, found := highWater[prefix.KeyID]
		if !found || prefix.Sequence > previous.Sequence {
			highWater[prefix.KeyID] = prefix
		}
	}
	next.HighWater = make([]control.FactFrontier, 0, len(highWater))
	for _, prefix := range highWater {
		next.HighWater = append(next.HighWater, prefix)
	}
	sort.Slice(next.HighWater, func(i, j int) bool { return next.HighWater[i].KeyID < next.HighWater[j].KeyID })
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return cloneOwnedAuthority(next), nil
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
	return cloneOwnedAuthority(state), state.ReportSequence, nil
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
	// Derived only from the exact bytes authenticated into state or committed
	// and read back. Missing or different bytes always require full decoding.
	authenticatedBytes *[sha256.Size]byte
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
	return store.validateProtection(state)
}
func (store *Store) validateProtection(state State) error {
	if store.protector != nil && (state.Platform != "windows" || state.Preference == nil) {
		return errors.New("protected device state is not a Windows profile")
	}
	if store.protector == nil && state.Preference != nil {
		return errors.New("plain device identity cannot contain a protected profile preference")
	}
	return nil
}
func (store *Store) readBytesUnlocked() ([]byte, error) {
	var body []byte
	var err error
	if store.protector != nil {
		body, err = clientsecret.ReadProtected(store.path, protectedStatePurpose, store.protector)
	} else {
		before, statErr := os.Lstat(store.path)
		if statErr != nil {
			return nil, statErr
		}
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 || before.Size() > maxStateBytes {
			return nil, errors.New("device state must be an owner-only bounded regular file")
		}
		file, openErr := os.Open(store.path)
		if openErr != nil {
			return nil, openErr
		}
		defer file.Close()
		after, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
			return nil, errors.New("device state changed during open")
		}
		body, err = io.ReadAll(io.LimitReader(file, maxStateBytes+1))
		if err == nil && int64(len(body)) != after.Size() {
			err = errors.New("device state changed during read")
		}
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}
func (store *Store) readUnlocked() (State, [sha256.Size]byte, error) {
	body, err := store.readBytesUnlocked()
	if err != nil {
		return State{}, [sha256.Size]byte{}, err
	}
	defer clear(body)
	digest := sha256.Sum256(body)
	if store.authenticatedBytes != nil && digest == *store.authenticatedBytes {
		return cloneOwnedAuthority(store.state), digest, nil
	}
	var state State
	if err := control.DecodeCanonical(body, &state, stateLimits); err != nil {
		return State{}, digest, err
	}
	// DecodeCanonical already validates the complete domain value. Only the
	// local protection adapter constraint remains outside that contract.
	if err := store.validateProtection(state); err != nil {
		return State{}, digest, err
	}
	return state, digest, nil
}
func (store *Store) load() error {
	lock, err := lockStateFile(store.path)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, digest, err := store.readUnlocked()
	if err != nil {
		return err
	}
	if err := syncProtectedDirectory(filepath.Dir(store.path)); err != nil {
		return err
	}
	store.state = state
	store.authenticatedBytes = &digest
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
	for _, before := range previous.HighWater {
		found := false
		for _, after := range next.HighWater {
			if after.KeyID != before.KeyID {
				continue
			}
			if after.Sequence < before.Sequence || after.Sequence == before.Sequence && after.TipMaterialID != before.TipMaterialID {
				return errors.New("persistent authenticated high-water cannot roll back or fork")
			}
			found = true
		}
		if !found {
			return errors.New("persistent authenticated high-water cannot be removed")
		}
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
	if !reserveReport {
		if err := store.validateState(next); err != nil {
			return err
		}
	}
	lock, err := lockStateFile(store.path)
	if err != nil {
		return store.fail(err)
	}
	defer lock.Close()
	current, _, readErr := store.readUnlocked()
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
				// current was just fully authenticated under the file lock;
				// this change cannot alter its identity, LKG or floor.
				if next.LKG == nil || next.ReportSequence == control.U64(math.MaxUint64) {
					return errors.New("report sequence cannot advance")
				}
				next.ReportSequence++
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
	if !reserveReport {
		if err := store.validateState(next); err != nil {
			return err
		}
	}
	return store.writeUnlocked(next, current)
}

// Caller holds the state file lock and has checked the forward transition.
func (store *Store) writeUnlocked(next, current State) error {
	review := ReviewMemberTransition(next, current)
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
	readback, err := staged.readBytesUnlocked()
	defer clear(readback)
	if err != nil {
		return store.fail(err)
	}
	if !bytes.Equal(body, readback) {
		return store.fail(errors.New("staged device state readback mismatch"))
	}
	if err := replaceProtectedFile(temporary, store.path); err != nil {
		return store.fail(err)
	}
	if err := syncProtectedDirectory(directory); err != nil {
		return store.fail(err)
	}
	committed, err := store.readBytesUnlocked()
	defer clear(committed)
	if err != nil {
		return store.fail(err)
	}
	if !bytes.Equal(body, committed) {
		return store.fail(errors.New("committed device state readback mismatch"))
	}
	// next is privately owned by the locked caller. Exact readback proves the
	// disk holds the same validated value; no external pointer is retained.
	store.state = next
	store.authenticatedBytes = new(sha256.Sum256(committed))
	if review.PossiblePermissionRestoration {
		body, _ := json.Marshal(review)
		log.Printf("member certificate accepted; permission review is incomplete: %s", body)
	}
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

// Only private, already validated domain values reach this copier. Input and
// persistence boundaries retain canonical decoding and complete authentication.
func cloneOwnedAuthority[T any](value T) T {
	return cloneAuthorityValue(reflect.ValueOf(value)).Interface().(T)
}
func cloneAuthorityValue(value reflect.Value) reflect.Value {
	copy := reflect.New(value.Type()).Elem()
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			if value.Kind() == reflect.Pointer {
				copy.Set(reflect.New(value.Type().Elem()))
				copy.Elem().Set(cloneAuthorityValue(value.Elem()))
			} else {
				copy.Set(cloneAuthorityValue(value.Elem()))
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).PkgPath != "" {
				panic("undefined private field in device authority")
			}
			copy.Field(i).Set(cloneAuthorityValue(value.Field(i)))
		}
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice {
			if value.IsNil() {
				return copy
			}
			copy.Set(reflect.MakeSlice(value.Type(), value.Len(), value.Len()))
		}
		for i := 0; i < value.Len(); i++ {
			copy.Index(i).Set(cloneAuthorityValue(value.Index(i)))
		}
	case reflect.Map:
		if !value.IsNil() {
			copy.Set(reflect.MakeMapWithSize(value.Type(), value.Len()))
			for entries := value.MapRange(); entries.Next(); {
				copy.SetMapIndex(cloneAuthorityValue(entries.Key()), cloneAuthorityValue(entries.Value()))
			}
		}
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		copy.Set(value)
	default:
		panic("undefined kind in device authority")
	}
	return copy
}
func (store *Store) Invite() control.BootstrapInvite {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneOwnedAuthority(store.state.Invite)
}
func (store *Store) LKG() *control.DeviceViewEnvelope {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.LKG == nil {
		return nil
	}
	copy := cloneOwnedAuthority(*store.state.LKG)
	return &copy
}
func (store *Store) Reload() (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failed != nil {
		return false, errors.New("device persistence previously failed; reopen the state before continuing")
	}
	current := &Store{path: store.path, protector: store.protector, state: store.state, authenticatedBytes: store.authenticatedBytes}
	if err := current.load(); err != nil {
		return false, store.fail(err)
	}
	if reflect.DeepEqual(current.state, store.state) {
		store.authenticatedBytes = current.authenticatedBytes
		return false, nil
	}
	if err := checkStateAdvance(current.state, store.state); err != nil {
		return false, err
	}
	changed := !reflect.DeepEqual(store.state.LKG, current.state.LKG)
	store.state = current.state
	store.authenticatedBytes = current.authenticatedBytes
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
