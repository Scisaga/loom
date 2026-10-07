package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (a *Authority) stoppedOrdinaryKey(key string) (ControlSealedKey, bool, error) {
	if ValidateDigest(key) != nil {
		return ControlSealedKey{}, false, errors.New("invalid signing key identity")
	}
	dir := filepath.Join(a.root, "control-retired")
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return ControlSealedKey{}, false, nil
	}
	if err := validateControlRoot(dir); err != nil {
		return ControlSealedKey{}, false, err
	}
	body, err := readProtectedControlFile(filepath.Join(dir, strings.TrimPrefix(key, "sha256:")+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return ControlSealedKey{}, false, nil
	}
	if err != nil {
		return ControlSealedKey{}, false, err
	}
	var prefix ControlSealedKey
	if err = DecodeCanonical(body, &prefix, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 16}); err != nil {
		return ControlSealedKey{}, false, err
	}
	if prefix.KeyID != key {
		return ControlSealedKey{}, false, errors.New("stopped signing key marker changed identity")
	}
	return prefix, true, nil
}

func (a *Authority) StopOrdinarySigning(ctx context.Context, local NodeConfig) (ControlSealedKey, error) {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return ControlSealedKey{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return ControlSealedKey{}, err
	}
	member, err := activeLocalMember(local, a.projection.Config)
	if err != nil {
		return ControlSealedKey{}, err
	}
	key, _ := KeyID(member.PublicKey)
	if original, found, err := a.stoppedOrdinaryKey(key); err != nil || found {
		return original, err
	}
	prefix := frontierFor(a.projection.Frontier, key)
	for _, fact := range a.materials {
		if fact.IssuerKeyID == key && fact.Sequence > prefix.Sequence {
			return ControlSealedKey{}, errors.New("unresolved signing history cannot establish a final prefix")
		}
	}
	dir, err := protectedMemberDirectory(a.root, "control-retired")
	if err != nil {
		return ControlSealedKey{}, err
	}
	body, err := CanonicalEncode(prefix)
	if err != nil {
		return ControlSealedKey{}, err
	}
	if err = ctx.Err(); err != nil {
		return ControlSealedKey{}, err
	}
	if err = putControlBytes(filepath.Join(dir, strings.TrimPrefix(key, "sha256:")+".json"), body); err != nil {
		return ControlSealedKey{}, err
	}
	return prefix, nil
}
