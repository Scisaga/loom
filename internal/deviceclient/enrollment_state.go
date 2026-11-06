package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"

	"loom/internal/clientsecret"
	"loom/internal/control"
)

func NewPendingIdentityState(reference control.InvitationReference, platform string, private ed25519.PrivateKey, requestID string) (State, error) {
	// Reuse the identity constructor's key representation; validation below also
	// proves the reference/complete-proof union is exclusive.
	if len(private) != ed25519.PrivateKeySize {
		return State{}, errors.New("invalid identity key")
	}
	state := State{Schema: stateSchema, AuthenticatedLatch: true, PrivateKey: base64.RawURLEncoding.EncodeToString(private), PublicKey: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Platform: platform, ClaimRequestID: requestID, InvitationReference: &reference, HighWater: []control.FactFrontier{}}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return cloneOwnedAuthority(state), nil
}
func (state State) Reference() (control.InvitationReference, error) {
	if state.InvitationReference != nil {
		return cloneOwnedAuthority(*state.InvitationReference), nil
	}
	if state.Invite == nil {
		return control.InvitationReference{}, errors.New("identity has no invitation")
	}
	return control.ReferenceForInvite(*state.Invite)
}
func (state State) TransactionID() string {
	if state.InvitationReference != nil {
		return state.InvitationReference.TransactionID
	}
	if state.Invite != nil {
		return state.Invite.Material.TargetID
	}
	return ""
}
func AcceptEnrollmentProof(state State, proof control.BootstrapInvite) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	reference, err := state.Reference()
	if err != nil {
		return State{}, err
	}
	if err := reference.MatchesInvite(proof); err != nil {
		return State{}, err
	}
	if state.Invite != nil {
		return cloneOwnedAuthority(state), nil
	}
	next := state
	next.Invite = &proof
	next.InvitationReference = nil
	if err := checkEnrollmentAdvance(next, state); err != nil {
		return State{}, err
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return cloneOwnedAuthority(next), nil
}
func checkEnrollmentAdvance(next, previous State) error {
	if fixedIdentityEqual(next, previous) {
		return nil
	}
	if next.PrivateKey != previous.PrivateKey || next.PublicKey != previous.PublicKey || next.Platform != previous.Platform || next.ClaimRequestID != previous.ClaimRequestID || !next.AuthenticatedLatch || !previous.AuthenticatedLatch || previous.Invite != nil || previous.InvitationReference == nil || next.InvitationReference != nil || next.Invite == nil {
		return errors.New("persistent device identity cannot change")
	}
	return previous.InvitationReference.MatchesInvite(*next.Invite)
}
func OpenReference(path string, reference control.InvitationReference) (*Store, error) {
	return openReferenceStore(path, reference, runtime.GOOS, nil)
}
func OpenProtectedReference(path string, reference control.InvitationReference, protector clientsecret.Protector) (*ProtectedStore, error) {
	if protector == nil {
		return nil, errors.New("protected device state requires a protector")
	}
	store, err := openReferenceStore(path, reference, "windows", protector)
	if err != nil {
		return nil, err
	}
	return &ProtectedStore{Store: store}, nil
}
func openReferenceStore(path string, reference control.InvitationReference, platform string, protector clientsecret.Protector) (*Store, error) {
	if !validStatePath(path) || reference.Validate() != nil {
		return nil, errors.New("invalid device path or invitation")
	}
	store := &Store{path: path, protector: protector}
	if err := store.load(); err == nil {
		saved, err := store.state.Reference()
		left, _ := control.CanonicalEncode(saved)
		right, _ := control.CanonicalEncode(reference)
		if err != nil || !bytes.Equal(left, right) || store.state.Platform != platform {
			return nil, errors.New("device state belongs to another invitation or platform")
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
	state, err := NewPendingIdentityState(reference, platform, private, hex.EncodeToString(request))
	if err != nil {
		return nil, err
	}
	if err := store.save(state, nil, false); err != nil {
		return nil, err
	}
	return store, nil
}
func (store *Store) Reference() (control.InvitationReference, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.Reference()
}
func (store *Store) SaveEnrollmentProof(proof control.BootstrapInvite) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, err := AcceptEnrollmentProof(store.state, proof)
	if err != nil {
		return err
	}
	return store.save(next, nil, false)
}
