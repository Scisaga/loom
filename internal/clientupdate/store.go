package clientupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"loom/internal/publish"
	"loom/internal/releasefloor"
)

const (
	StateSchema = 1
	maxState    = 64 << 10
)

type VerifiedVersion struct {
	Generation    uint64 `json:"generation"`
	PayloadSHA256 string `json:"payload_sha256"`
	Snapshot      string `json:"snapshot"`
	BundleSHA256  string `json:"bundle_sha256"`
}

type VerifiedState struct {
	Schema   int              `json:"schema"`
	Current  VerifiedVersion  `json:"current"`
	Previous *VerifiedVersion `json:"previous,omitempty"`
}

type VerifiedBundle struct {
	Version    VerifiedVersion
	Components ComponentVersions
	Files      map[string]string
}

// ComponentVersions is the signed compatibility request for one device. It is
// intentionally version-only: exact executable hashes live in the separately
// platform-signed component package, whose current/previous slots are replayed
// before use.
type ComponentVersions struct {
	SingBox   string
	WireGuard string
	Tailscale string
	Agent     string
}

func ReadVerifiedState(root string) (*VerifiedState, error) {
	if err := requireAbsoluteClean(root); err != nil {
		return nil, err
	}
	body, err := readLimitedFile(statePath(root, "verified.json"), maxState)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state VerifiedState
	if err := decodeStrict(body, maxState, &state); err != nil {
		return nil, err
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

// LoadVerifiedBundle replays the complete local trust chain before returning
// material for secret hydration. A cache pointer alone is never authority: the
// signed current, snapshot signature, device binding, bundle hash, and local
// anti-replay floor must still agree after a restart.
func LoadVerifiedBundle(root, node string, publicKey ed25519.PublicKey) (*VerifiedBundle, error) {
	state, err := ReadVerifiedState(root)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, os.ErrNotExist
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("pinned platform public key has invalid length")
	}
	dir := packagePath(root, state.Current)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("verified package contains non-file entry %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{"bundle.json", "current.json", "snapshot.json", "snapshot.sig"}
	if !slices.Equal(names, wantNames) {
		return nil, fmt.Errorf("verified package file set is %v, want %v", names, wantNames)
	}

	currentBody, err := readLimitedFile(filepath.Join(dir, "current.json"), maxCurrentBody)
	if err != nil {
		return nil, err
	}
	current, err := publish.DecodeDeploymentCurrent(currentBody)
	if err != nil {
		return nil, fmt.Errorf("decode cached signed current: %w", err)
	}
	if err := current.Verify(publicKey); err != nil {
		return nil, fmt.Errorf("verify cached signed current: %w", err)
	}
	selected, err := current.Select(node)
	if err != nil {
		return nil, fmt.Errorf("cached signed current does not bind this device: %w", err)
	}
	digest, err := current.PayloadSHA256()
	if err != nil {
		return nil, err
	}
	version := state.Current
	if current.Generation != version.Generation || digest != version.PayloadSHA256 || selected != version.Snapshot {
		return nil, errors.New("cached signed current does not match verified state coordinates")
	}
	floor, err := releasefloor.Read(statePath(root, "release-floor.json"))
	if err != nil {
		return nil, err
	}
	if floor == nil || floor.Generation < version.Generation ||
		(floor.Generation == version.Generation &&
			(floor.PayloadSHA256 != version.PayloadSHA256 || floor.SelectedSnapshot != version.Snapshot)) {
		return nil, errors.New("verified package is not covered by the durable release floor")
	}

	manifestBody, err := readLimitedFile(filepath.Join(dir, "snapshot.json"), maxManifestBody)
	if err != nil {
		return nil, err
	}
	signature, err := readLimitedFile(filepath.Join(dir, "snapshot.sig"), maxSignature)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifestBody, signature) {
		return nil, errors.New("cached snapshot signature is missing, malformed, or invalid")
	}
	var manifest manifestWire
	if err := decodeStrict(manifestBody, maxManifestBody, &manifest); err != nil {
		return nil, fmt.Errorf("decode cached manifest: %w", err)
	}
	wantHash, err := validateManifest(&manifest, version.Snapshot, node)
	if err != nil {
		return nil, err
	}
	if wantHash != version.BundleSHA256 {
		return nil, errors.New("cached manifest bundle hash does not match verified state")
	}
	components, err := componentVersionsForNode(&manifest, node)
	if err != nil {
		return nil, err
	}
	bundleBody, err := readLimitedFile(filepath.Join(dir, "bundle.json"), maxBundleBody)
	if err != nil {
		return nil, err
	}
	var bundle bundleWire
	if err := decodeStrict(bundleBody, maxBundleBody, &bundle); err != nil {
		return nil, fmt.Errorf("decode cached bundle: %w", err)
	}
	if err := validateBundle(bundle, node); err != nil {
		return nil, err
	}
	if got := bundleHash(bundle.Files); got != wantHash {
		return nil, errors.New("cached bundle content does not match signed manifest")
	}
	files := make(map[string]string, len(bundle.Files))
	for name, content := range bundle.Files {
		files[name] = content
	}
	return &VerifiedBundle{Version: version, Components: components, Files: files}, nil
}

func (s VerifiedState) Validate() error {
	if s.Schema != StateSchema {
		return fmt.Errorf("verified state schema must be %d", StateSchema)
	}
	if err := s.Current.Validate(); err != nil {
		return fmt.Errorf("invalid current version: %w", err)
	}
	if s.Previous != nil {
		if err := s.Previous.Validate(); err != nil {
			return fmt.Errorf("invalid previous version: %w", err)
		}
		if *s.Previous == s.Current {
			return errors.New("previous version must differ from current")
		}
	}
	return nil
}

func (v VerifiedVersion) Validate() error {
	if v.Generation == 0 || !validLowerHex(v.PayloadSHA256, 64) ||
		!validLowerHex(v.Snapshot, 12) || !validLowerHex(v.BundleSHA256, 64) {
		return errors.New("version has invalid generation or content coordinates")
	}
	return nil
}

func commitVerified(root string, next VerifiedVersion, payload verifiedPayload) (bool, error) {
	if err := next.Validate(); err != nil {
		return false, err
	}
	if err := ensurePackage(root, next, payload); err != nil {
		return false, err
	}
	current, err := ReadVerifiedState(root)
	if err != nil {
		return false, err
	}
	changed := current == nil || current.Current.Snapshot != next.Snapshot || current.Current.BundleSHA256 != next.BundleSHA256
	state := VerifiedState{Schema: StateSchema, Current: next}
	if current != nil {
		if changed {
			previous := current.Current
			state.Previous = &previous
		} else {
			state.Previous = current.Previous
		}
	}
	if err := state.Validate(); err != nil {
		return false, err
	}
	body, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		return false, err
	}
	if err := writeAtomic(statePath(root, "verified.json"), append(body, '\n'), 0o600); err != nil {
		return false, err
	}
	return changed, nil
}

func ensurePackage(root string, version VerifiedVersion, payload verifiedPayload) (retErr error) {
	packages := filepath.Join(root, "packages")
	if err := os.MkdirAll(packages, 0o700); err != nil {
		return err
	}
	target := packagePath(root, version)
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("verified package target %s is not a real directory", target)
		}
		return comparePackage(target, payload)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stage, err := os.MkdirTemp(packages, ".stage-*")
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	for _, file := range []struct {
		name string
		body []byte
	}{
		{"current.json", payload.currentBody},
		{"snapshot.json", payload.manifestBody},
		{"snapshot.sig", payload.signature},
		{"bundle.json", payload.bundleBody},
	} {
		if err := writeNewSynced(filepath.Join(stage, file.name), file.body, 0o600); err != nil {
			return err
		}
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, target); err != nil {
		return fmt.Errorf("install immutable verified package: %w", err)
	}
	if err := syncDirectory(packages); err != nil {
		return err
	}
	return nil
}

func comparePackage(dir string, payload verifiedPayload) error {
	for _, file := range []struct {
		name string
		want []byte
	}{
		{"current.json", payload.currentBody},
		{"snapshot.json", payload.manifestBody},
		{"snapshot.sig", payload.signature},
		{"bundle.json", payload.bundleBody},
	} {
		got, err := readLimitedFile(filepath.Join(dir, file.name), maxBundleBody)
		if err != nil {
			return fmt.Errorf("read cached %s: %w", file.name, err)
		}
		if !bytes.Equal(got, file.want) {
			return fmt.Errorf("immutable cached package %s differs from newly verified bytes", file.name)
		}
	}
	return nil
}

func writeNewSynced(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeAtomic(path string, body []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func readLimitedFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() != info.Size() || opened.Size() > maximum {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded file %s: %w", path, err)
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("read bounded file %s: file grew past %d bytes", path, maximum)
	}
	return body, nil
}

func statePath(root, name string) string {
	return filepath.Join(root, "state", name)
}

func packagePath(root string, version VerifiedVersion) string {
	return filepath.Join(root, "packages", version.Snapshot+"-"+version.BundleSHA256[:12])
}
