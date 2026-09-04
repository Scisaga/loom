// Package clientruntime turns a verified, still-redacted device bundle into a
// DPAPI-protected Windows candidate. It does not activate routes or processes;
// candidate preparation and data-plane activation remain separate commits.
package clientruntime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/secret"
)

const (
	CandidateSchema        = 1
	CandidateConfigPurpose = "candidate-config-v1"
	CandidateStatePurpose  = "candidate-state-v1"
)

type CandidateVersion struct {
	Generation    uint64 `json:"generation"`
	PayloadSHA256 string `json:"payload_sha256"`
	Snapshot      string `json:"snapshot"`
	BundleSHA256  string `json:"bundle_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}

type CandidateState struct {
	Schema   int               `json:"schema"`
	Current  CandidateVersion  `json:"current"`
	Previous *CandidateVersion `json:"previous,omitempty"`
}

type PrepareResult struct {
	Version      CandidateVersion
	Components   clientupdate.ComponentVersions
	Changed      bool
	SecretsUsed  int
	CandidateRef string
}

func PrepareWindowsCandidate(root, node string, publicKey ed25519.PublicKey, vaultPath string,
	protector clientsecret.Protector) (PrepareResult, error) {
	if err := validateRoot(root); err != nil {
		return PrepareResult{}, err
	}
	verified, err := clientupdate.LoadVerifiedBundle(root, node, publicKey)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("load verified bundle: %w", err)
	}
	if len(verified.Files) != 1 {
		return PrepareResult{}, fmt.Errorf("Windows bundle must contain exactly sing-box/config.json, got %d files", len(verified.Files))
	}
	redacted, ok := verified.Files["sing-box/config.json"]
	if !ok {
		return PrepareResult{}, errors.New("Windows bundle does not contain sing-box/config.json")
	}
	secrets, err := clientsecret.ReadVault(vaultPath, protector)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("read protected secret vault: %w", err)
	}
	hydrated, missing := secret.Hydrate(redacted, secrets)
	clear(secrets)
	if len(missing) > 0 {
		return PrepareResult{}, fmt.Errorf("protected secret vault is missing refs: %s", strings.Join(missing, ", "))
	}
	if secret.HasPlaceholder(hydrated) {
		return PrepareResult{}, errors.New("hydrated Windows config still contains a secret placeholder")
	}
	if err := ValidateWindowsSingBox([]byte(hydrated)); err != nil {
		return PrepareResult{}, fmt.Errorf("Windows sing-box structural preflight: %w", err)
	}
	configSum := sha256.Sum256([]byte(hydrated))
	version := CandidateVersion{
		Generation: verified.Version.Generation, PayloadSHA256: verified.Version.PayloadSHA256,
		Snapshot: verified.Version.Snapshot, BundleSHA256: verified.Version.BundleSHA256,
		ConfigSHA256: hex.EncodeToString(configSum[:]),
	}
	if err := version.Validate(); err != nil {
		return PrepareResult{}, err
	}
	candidatePath := candidatePath(root, version)
	if err := clientsecret.WriteProtected(candidatePath, CandidateConfigPurpose, []byte(hydrated), protector); err != nil {
		return PrepareResult{}, fmt.Errorf("protect hydrated candidate: %w", err)
	}

	current, err := ReadCandidateState(root, protector)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return PrepareResult{}, err
	}
	changed := current == nil || current.Current.ConfigSHA256 != version.ConfigSHA256 ||
		current.Current.Snapshot != version.Snapshot || current.Current.BundleSHA256 != version.BundleSHA256
	next := CandidateState{Schema: CandidateSchema, Current: version}
	if current != nil {
		if changed {
			previous := current.Current
			next.Previous = &previous
		} else {
			next.Previous = current.Previous
		}
	}
	if err := next.Validate(); err != nil {
		return PrepareResult{}, err
	}
	if err := clientsecret.WriteJSONProtected(candidateStatePath(root), CandidateStatePurpose, &next, protector); err != nil {
		return PrepareResult{}, fmt.Errorf("commit candidate pointer: %w", err)
	}
	return PrepareResult{
		Version: version, Components: verified.Components, Changed: changed, SecretsUsed: len(secret.Refs(redacted)),
		CandidateRef: filepath.Base(candidatePath),
	}, nil
}

func ReadCandidateState(root string, protector clientsecret.Protector) (*CandidateState, error) {
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	var state CandidateState
	if err := clientsecret.ReadJSONProtected(candidateStatePath(root), CandidateStatePurpose, &state, protector); err != nil {
		return nil, err
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func ReadCandidateConfig(root string, protector clientsecret.Protector) ([]byte, *CandidateState, error) {
	if err := validateRoot(root); err != nil {
		return nil, nil, err
	}
	state, err := ReadCandidateState(root, protector)
	if err != nil {
		return nil, nil, err
	}
	body, err := clientsecret.ReadProtected(candidatePath(root, state.Current), CandidateConfigPurpose, protector)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != state.Current.ConfigSHA256 {
		clear(body)
		return nil, nil, errors.New("protected candidate content does not match candidate pointer")
	}
	if err := ValidateWindowsSingBox(body); err != nil {
		clear(body)
		return nil, nil, err
	}
	return body, state, nil
}

func (s CandidateState) Validate() error {
	if s.Schema != CandidateSchema {
		return fmt.Errorf("candidate schema must be %d", CandidateSchema)
	}
	if err := s.Current.Validate(); err != nil {
		return fmt.Errorf("invalid current candidate: %w", err)
	}
	if s.Previous != nil {
		if err := s.Previous.Validate(); err != nil {
			return fmt.Errorf("invalid previous candidate: %w", err)
		}
		if *s.Previous == s.Current {
			return errors.New("previous candidate must differ from current")
		}
	}
	return nil
}

func (v CandidateVersion) Validate() error {
	if v.Generation == 0 || !validLowerHex(v.PayloadSHA256, 64) || !validLowerHex(v.Snapshot, 12) ||
		!validLowerHex(v.BundleSHA256, 64) || !validLowerHex(v.ConfigSHA256, 64) {
		return errors.New("candidate has invalid generation or content coordinates")
	}
	return nil
}

func candidateStatePath(root string) string {
	return filepath.Join(root, "state", "candidate.json.dpapi")
}

func candidatePath(root string, version CandidateVersion) string {
	name := version.Snapshot + "-" + version.BundleSHA256 + "-" + version.ConfigSHA256 + ".json.dpapi"
	return filepath.Join(root, "candidates", name)
}

func validateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("client state root must be absolute and clean: %q", root)
	}
	return nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
