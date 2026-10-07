package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func validateRotationInputs(current, next NodeConfig) error {
	if next.Validate() != nil || current.NetworkID != next.NetworkID || current.GenesisID != next.GenesisID || current.ControlID != next.ControlID || current.NodeID != next.NodeID || !reflect.DeepEqual(current.BrowserTLS, next.BrowserTLS) || current.PeerTLS == nil || next.PeerTLS == nil {
		return errors.New("prepared rotation changes fixed identity or lacks the existing private transport")
	}
	oldPublic, err := current.PublicKey()
	if err != nil {
		return err
	}
	newPublic, err := next.PublicKey()
	if err != nil || oldPublic.Equal(newPublic) {
		return errors.New("prepared rotation must own a different signing key")
	}
	oldRoots, err := readControlPublicFile(current.PeerTLS.TrustFile)
	if err != nil {
		return err
	}
	newRoots, err := readControlPublicFile(next.PeerTLS.TrustFile)
	if err != nil || !bytes.Equal(oldRoots, newRoots) {
		return errors.New("rotation cannot replace member transport trust")
	}
	identity, err := peerTLSConfig(next)
	if err != nil {
		return err
	}
	pair := identity.Certificates[0]
	intermediates := x509.NewCertPool()
	for _, body := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err = pair.Leaf.Verify(x509.VerifyOptions{Roots: identity.RootCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return errors.New("prepared member leaf is not signed by the existing transport trust")
		}
	}
	return nil
}

func PrepareControlKey(ctx context.Context, root string, next NodeConfig) error {
	if err := validateControlRoot(root); err != nil {
		return err
	}
	lock, err := lockAuthority(ctx, root)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := LoadNodeConfig(root)
	if err != nil {
		return err
	}
	if err = validateRotationInputs(current, next); err != nil {
		return err
	}
	a := &Authority{root: root}
	if err = a.reloadLocked(); err != nil {
		return err
	}
	if _, err = activeLocalMember(current, a.Snapshot().Config); err != nil {
		return err
	}
	public, _ := next.PublicKey()
	if a.historicalSigningKey(base64.RawURLEncoding.EncodeToString(public)) {
		return errors.New("rotation cannot reuse a member signing key")
	}
	body, err := CanonicalEncode(next)
	if err != nil {
		return err
	}
	return putControlBytes(filepath.Join(root, "node-next.json"), body)
}

func (a *Authority) historicalSigningKey(public string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	tables := []ControlConfig{a.genesis.Payload.(Genesis).ControlConfig}
	for _, cert := range a.certificates {
		tables = append(tables, cert.Config)
	}
	for _, table := range tables {
		for _, member := range table.Members {
			if member.PublicKey == public {
				return true
			}
		}
	}
	return false
}

func (runtime *Runtime) preflightControlRotation(public string) error {
	body, err := readProtectedControlFile(filepath.Join(runtime.Authority.root, "node-next.json"))
	if err != nil {
		return errors.New("prepare the owned signing key and existing-trust member TLS leaf before rotation")
	}
	var next NodeConfig
	if err = DecodeCanonical(body, &next, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}); err != nil {
		return err
	}
	key, err := next.PublicKey()
	if err != nil || public != base64.RawURLEncoding.EncodeToString(key) {
		return errors.New("requested public key differs from prepared private execution inputs")
	}
	if runtime.Authority.historicalSigningKey(public) {
		return errors.New("rotation cannot reuse a member signing key")
	}
	return validateRotationInputs(runtime.Config, next)
}

// This consumes the prepared NodeConfig only after the original member chain
// certifies it. Neither file grants signing qualification on its own.
func ActivatePreparedControlKey(ctx context.Context, root string) error {
	if _, err := os.Lstat(filepath.Join(root, "node-next.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := validateControlRoot(root); err != nil {
		return err
	}
	lock, err := lockAuthority(ctx, root)
	if err != nil {
		return err
	}
	defer lock.Close()
	body, err := readProtectedControlFile(filepath.Join(root, "node-next.json"))
	if err != nil {
		return err
	}
	var next NodeConfig
	if err = DecodeCanonical(body, &next, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}); err != nil {
		return err
	}
	current, err := LoadNodeConfig(root)
	if err != nil {
		return err
	}
	a := &Authority{root: root}
	if err = a.reloadLocked(); err != nil {
		return err
	}
	public, err := next.PublicKey()
	if err != nil {
		return err
	}
	certified := false
	for _, cert := range a.certificates {
		if cert.Config.Operation != "rotate" || cert.Config.TargetNodeID != current.NodeID {
			continue
		}
		if member, ok := proofMember(cert.Config, current.ControlID); ok && member.PublicKey == base64.RawURLEncoding.EncodeToString(public) {
			certified = true
		}
	}
	if !certified {
		return nil
	}
	if _, err = activeLocalMember(next, a.Snapshot().Config); err != nil {
		return err
	}
	if !reflect.DeepEqual(current, next) {
		if err = validateRotationInputs(current, next); err != nil {
			return err
		}
		oldPublic, err := current.PublicKey()
		if err != nil {
			return err
		}
		oldKey, _ := KeyID(base64.RawURLEncoding.EncodeToString(oldPublic))
		original, err := readProtectedControlFile(filepath.Join(root, "node.json"))
		if err != nil {
			return err
		}
		dir, err := protectedMemberDirectory(root, "control-retired")
		if err != nil {
			return err
		}
		if err = putControlBytes(filepath.Join(dir, strings.TrimPrefix(oldKey, "sha256:")+".node.json"), original); err != nil {
			return err
		}
		if err = atomicWrite(filepath.Join(root, "node.json"), body); err != nil {
			return err
		}
	}
	if err = os.Remove(filepath.Join(root, "node-next.json")); err != nil {
		return err
	}
	return syncControlDirectory(root)
}
