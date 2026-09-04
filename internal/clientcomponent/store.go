package clientcomponent

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
	"strings"
)

const (
	StateSchema = 1
	maxState    = 64 << 10
)

type AuthenticodeVerifier func(path string) error

type SlotRef struct {
	ID             string `json:"id"`
	Arch           string `json:"arch"`
	SingBoxVersion string `json:"sing_box_version"`
	WintunVersion  string `json:"wintun_version"`
}

type State struct {
	Schema   int      `json:"schema"`
	Current  SlotRef  `json:"current"`
	Previous *SlotRef `json:"previous,omitempty"`
}

type InstallResult struct {
	Slot    SlotRef
	Changed bool
	Paths   RuntimePaths
}

type RuntimePaths struct {
	SlotID      string
	SingBox     string
	Wintun      string
	Manifest    Manifest
	ManifestRaw []byte
}

// Install verifies the platform signature and every payload before committing
// an immutable content-addressed slot. The supplied verifier must perform the
// native Authenticode policy check on the staged Wintun DLL.
func Install(root string, packageBody []byte, publicKey ed25519.PublicKey,
	verifyAuthenticode AuthenticodeVerifier) (InstallResult, error) {
	return installWithPackageVerifier(root, packageBody, publicKey, verifyAuthenticode, Verify)
}

type packageVerifier func([]byte, ed25519.PublicKey) (*Verified, error)

func installWithPackageVerifier(root string, packageBody []byte, publicKey ed25519.PublicKey,
	verifyAuthenticode AuthenticodeVerifier, verifyPackage packageVerifier) (InstallResult, error) {
	if err := validateRoot(root); err != nil {
		return InstallResult{}, err
	}
	if verifyAuthenticode == nil {
		return InstallResult{}, errors.New("Wintun Authenticode verifier is required")
	}
	if verifyPackage == nil {
		return InstallResult{}, errors.New("component package verifier is required")
	}
	verified, err := verifyPackage(packageBody, publicKey)
	if err != nil {
		return InstallResult{}, fmt.Errorf("verify Windows component package: %w", err)
	}
	ref := slotRef(verified)
	components := filepath.Join(root, "components")
	if err := os.MkdirAll(components, 0o700); err != nil {
		return InstallResult{}, err
	}
	target := filepath.Join(components, ref.ID)
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return InstallResult{}, errors.New("component slot target is not a real directory")
		}
		if _, err := verifySlot(target, ref, publicKey, verifyAuthenticode, verifyPackage); err != nil {
			return InstallResult{}, fmt.Errorf("existing immutable component slot is corrupt: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return InstallResult{}, statErr
	} else if err := installSlot(components, target, verified, verifyAuthenticode); err != nil {
		return InstallResult{}, err
	}

	state, err := ReadState(root)
	if err != nil {
		return InstallResult{}, err
	}
	changed := state == nil || state.Current.ID != ref.ID
	next := State{Schema: StateSchema, Current: ref}
	if state != nil {
		if changed {
			previous := state.Current
			next.Previous = &previous
		} else {
			next.Previous = state.Previous
		}
	}
	if err := next.Validate(); err != nil {
		return InstallResult{}, err
	}
	body, err := json.MarshalIndent(&next, "", "  ")
	if err != nil {
		return InstallResult{}, err
	}
	if err := writeAtomic(statePath(root), append(body, '\n'), 0o600); err != nil {
		return InstallResult{}, fmt.Errorf("commit component pointer: %w", err)
	}
	paths, err := verifySlot(target, ref, publicKey, verifyAuthenticode, verifyPackage)
	if err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Slot: ref, Changed: changed, Paths: paths}, nil
}

// Load selects only current or previous, and only when its signed sing-box
// version matches the version requested by the authenticated snapshot.
func Load(root string, publicKey ed25519.PublicKey, arch, singBoxVersion string,
	verifyAuthenticode AuthenticodeVerifier) (RuntimePaths, error) {
	return loadWithPackageVerifier(root, publicKey, arch, singBoxVersion, verifyAuthenticode, Verify)
}

func loadWithPackageVerifier(root string, publicKey ed25519.PublicKey, arch, singBoxVersion string,
	verifyAuthenticode AuthenticodeVerifier, verifyPackage packageVerifier) (RuntimePaths, error) {
	if err := validateRoot(root); err != nil {
		return RuntimePaths{}, err
	}
	if verifyAuthenticode == nil {
		return RuntimePaths{}, errors.New("Wintun Authenticode verifier is required")
	}
	if verifyPackage == nil {
		return RuntimePaths{}, errors.New("component package verifier is required")
	}
	state, err := ReadState(root)
	if err != nil {
		return RuntimePaths{}, err
	}
	if state == nil {
		return RuntimePaths{}, os.ErrNotExist
	}
	wantVersion := strings.TrimPrefix(singBoxVersion, "v")
	if wantVersion == "" {
		return RuntimePaths{}, errors.New("snapshot does not declare a sing-box version")
	}
	var selected *SlotRef
	for _, candidate := range []*SlotRef{&state.Current, state.Previous} {
		if candidate != nil && candidate.Arch == arch && strings.TrimPrefix(candidate.SingBoxVersion, "v") == wantVersion {
			copy := *candidate
			selected = &copy
			break
		}
	}
	if selected == nil {
		return RuntimePaths{}, fmt.Errorf("no current/previous signed component slot matches windows/%s sing-box %s", arch, singBoxVersion)
	}
	return verifySlot(filepath.Join(root, "components", selected.ID), *selected, publicKey, verifyAuthenticode, verifyPackage)
}

func ReadState(root string) (*State, error) {
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	body, err := readRegularBounded(statePath(root), maxState)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := decodeStrict(body, &state); err != nil {
		return nil, err
	}
	canonical, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		return nil, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(body, canonical) {
		return nil, errors.New("component state is not in canonical form")
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func (state State) Validate() error {
	if state.Schema != StateSchema {
		return fmt.Errorf("component state schema must be %d", StateSchema)
	}
	if err := state.Current.Validate(); err != nil {
		return fmt.Errorf("invalid current component slot: %w", err)
	}
	if state.Previous != nil {
		if err := state.Previous.Validate(); err != nil {
			return fmt.Errorf("invalid previous component slot: %w", err)
		}
		if *state.Previous == state.Current {
			return errors.New("previous component slot must differ from current")
		}
	}
	return nil
}

func (ref SlotRef) Validate() error {
	if !validLowerHex(ref.ID, 64) || (ref.Arch != "amd64" && ref.Arch != "arm64") ||
		ref.SingBoxVersion == "" || len(ref.SingBoxVersion) > 64 || ref.WintunVersion == "" || len(ref.WintunVersion) > 64 {
		return errors.New("component slot has invalid content coordinates")
	}
	return nil
}

func installSlot(parent, target string, verified *Verified, verifyAuthenticode AuthenticodeVerifier) (retErr error) {
	stage, err := os.MkdirTemp(parent, ".stage-*")
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	files := cloneFiles(verified.Files)
	files["manifest.json"] = append([]byte(nil), verified.ManifestBody...)
	files["manifest.sig"] = append([]byte(nil), verified.Signature...)
	for _, name := range sortedNames(files) {
		destination := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		if err := writeNewSynced(destination, files[name], 0o600); err != nil {
			return err
		}
	}
	if err := verifyAuthenticode(filepath.Join(stage, filepath.FromSlash(WintunPath))); err != nil {
		return fmt.Errorf("verify staged Wintun Authenticode signature: %w", err)
	}
	if err := os.Rename(stage, target); err != nil {
		return fmt.Errorf("install immutable component slot: %w", err)
	}
	return syncDirectory(parent)
}

func verifySlot(dir string, want SlotRef, publicKey ed25519.PublicKey,
	verifyAuthenticode AuthenticodeVerifier, verifyPackage packageVerifier) (RuntimePaths, error) {
	if err := want.Validate(); err != nil {
		return RuntimePaths{}, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return RuntimePaths{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return RuntimePaths{}, errors.New("component slot is not a real directory")
	}
	var diskNames []string
	err = filepath.WalkDir(dir, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == dir {
			return nil
		}
		relative, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("component slot contains link %q", relative)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("component slot contains non-file %q", relative)
		}
		diskNames = append(diskNames, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return RuntimePaths{}, err
	}
	sort.Strings(diskNames)
	wantNames := []string{SingBoxPath, WintunPath, SingBoxLicense, WintunLicense, "manifest.json", "manifest.sig"}
	sort.Strings(wantNames)
	if !slices.Equal(diskNames, wantNames) {
		return RuntimePaths{}, fmt.Errorf("component slot file set is %v, want %v", diskNames, wantNames)
	}
	files := make(map[string][]byte, len(diskNames))
	for _, name := range diskNames {
		maximum := int64(maxEntryBytes)
		if name == "manifest.json" {
			maximum = maxManifestBytes
		} else if name == "manifest.sig" {
			maximum = ed25519.SignatureSize
		}
		body, err := readRegularBounded(filepath.Join(dir, filepath.FromSlash(name)), maximum)
		if err != nil {
			return RuntimePaths{}, err
		}
		files[name] = body
	}
	packageBody, err := buildZip(files)
	if err != nil {
		return RuntimePaths{}, err
	}
	verified, err := verifyPackage(packageBody, publicKey)
	if err != nil {
		return RuntimePaths{}, err
	}
	got := slotRef(verified)
	if got != want {
		return RuntimePaths{}, errors.New("component slot does not match its state pointer")
	}
	wintun := filepath.Join(dir, filepath.FromSlash(WintunPath))
	if err := verifyAuthenticode(wintun); err != nil {
		return RuntimePaths{}, fmt.Errorf("verify installed Wintun Authenticode signature: %w", err)
	}
	return RuntimePaths{SlotID: got.ID,
		SingBox: filepath.Join(dir, filepath.FromSlash(SingBoxPath)), Wintun: wintun,
		Manifest: verified.Manifest, ManifestRaw: verified.ManifestBody}, nil
}

func slotRef(verified *Verified) SlotRef {
	return SlotRef{ID: verified.ID, Arch: verified.Manifest.Arch,
		SingBoxVersion: verified.Manifest.SingBox.Version, WintunVersion: verified.Manifest.Wintun.Version}
}

func statePath(root string) string { return filepath.Join(root, "state", "components.json") }

func validateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("client state root must be absolute and clean: %q", root)
	}
	return nil
}

func writeNewSynced(name string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
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

func writeAtomic(name string, body []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(name)+".tmp-*")
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
	if err := replaceFile(temporary, name); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func readRegularBounded(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s is not a bounded regular file", name)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || opened.Size() > maximum {
		return nil, fmt.Errorf("%s changed while opening", name)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != opened.Size() {
		return nil, fmt.Errorf("%s changed while reading", name)
	}
	return body, nil
}
