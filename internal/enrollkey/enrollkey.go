// Package enrollkey manages the control plane's shared SSH bootstrap identity.
//
// The private key is the identity. It is generated at most once and is never
// exposed by this package's API. The adjacent public-key file is derived state:
// Ensure repairs it when it is missing or does not match the private key.
package enrollkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const publicComment = "loom-control-bootstrap"

// Manager owns the shared control-plane bootstrap identity at PrivatePath.
// The corresponding authorized_keys-compatible public key is stored at
// PrivatePath + ".pub".
type Manager struct {
	PrivatePath string
}

// Status describes public information about the bootstrap identity. It never
// contains private key material.
type Status struct {
	Ready         bool
	PrivatePath   string
	PublicPath    string
	PublicOpenSSH string
	Fingerprint   string
}

// Status validates the existing private key and reports its public identity.
// It does not create files or repair the public-key file.
func (m Manager) Status() (Status, error) {
	state := Status{PrivatePath: m.PrivatePath, PublicPath: m.publicPath()}
	if err := m.validatePath(); err != nil {
		return state, err
	}
	private, err := readPrivate(m.PrivatePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	return statusForPrivate(m, private), nil
}

// Ensure creates the identity if absent, validates it if present, and repairs
// the public-key file from the private key. Concurrent callers and processes
// converge on the private key that first reaches PrivatePath.
func (m Manager) Ensure() (Status, error) {
	if err := m.validatePath(); err != nil {
		return Status{}, err
	}
	if err := ensureSecureParent(m.PrivatePath); err != nil {
		return Status{}, err
	}

	private, err := readPrivate(m.PrivatePath)
	if errors.Is(err, os.ErrNotExist) {
		if err := m.generateOnce(); err != nil {
			return Status{}, err
		}
		private, err = readPrivate(m.PrivatePath)
	}
	if err != nil {
		return Status{}, err
	}
	publicLine := publicOpenSSH(private.Public().(ed25519.PublicKey))
	if err := m.ensurePublicFile(publicLine + "\n"); err != nil {
		return Status{}, err
	}
	return statusForPrivate(m, private), nil
}

// PublicOpenSSH returns the authorized_keys-compatible public key derived from
// the private key. It never reads or returns private key text.
func (m Manager) PublicOpenSSH() (string, error) {
	if err := m.validatePath(); err != nil {
		return "", err
	}
	private, err := readPrivate(m.PrivatePath)
	if err != nil {
		return "", err
	}
	return publicOpenSSH(private.Public().(ed25519.PublicKey)), nil
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of the public key.
func (m Manager) Fingerprint() (string, error) {
	if err := m.validatePath(); err != nil {
		return "", err
	}
	private, err := readPrivate(m.PrivatePath)
	if err != nil {
		return "", err
	}
	return fingerprint(private.Public().(ed25519.PublicKey)), nil
}

func (m Manager) publicPath() string { return m.PrivatePath + ".pub" }

func (m Manager) validatePath() error {
	if strings.TrimSpace(m.PrivatePath) == "" {
		return errors.New("bootstrap private key path is empty")
	}
	if strings.ContainsAny(m.PrivatePath, "\x00\r\n") {
		return errors.New("bootstrap private key path contains control bytes")
	}
	if !filepath.IsAbs(m.PrivatePath) {
		return errors.New("bootstrap private key path must be absolute")
	}
	if filepath.Clean(m.PrivatePath) != m.PrivatePath {
		return errors.New("bootstrap private key path must be clean")
	}
	return validateSecureParent(m.PrivatePath, false)
}

func statusForPrivate(m Manager, private ed25519.PrivateKey) Status {
	public := private.Public().(ed25519.PublicKey)
	return Status{
		Ready:         true,
		PrivatePath:   m.PrivatePath,
		PublicPath:    m.publicPath(),
		PublicOpenSSH: publicOpenSSH(public),
		Fingerprint:   fingerprint(public),
	}
}

func (m Manager) generateOnce() error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate bootstrap key: %w", err)
	}
	encoded, err := marshalOpenSSHPrivate(private, publicComment)
	if err != nil {
		return fmt.Errorf("encode bootstrap private key: %w", err)
	}

	dir := filepath.Dir(m.PrivatePath)
	tmp, err := os.CreateTemp(dir, ".loom-bootstrap-key-*")
	if err != nil {
		return fmt.Errorf("create bootstrap key temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set bootstrap private key permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		return fmt.Errorf("write bootstrap private key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap private key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close bootstrap private key: %w", err)
	}

	// Linking a complete, synced file makes publishing atomic without ever
	// replacing an identity another process already installed.
	if err := os.Link(tmpPath, m.PrivatePath); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("publish bootstrap private key: %w", err)
		}
	} else if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync bootstrap key directory: %w", err)
	}

	if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove bootstrap key temporary file: %w", err)
	}
	keepTemp = false
	return nil
}

func (m Manager) ensurePublicFile(want string) error {
	path := m.publicPath()
	match, err := publicFileMatches(path, []byte(want))
	if err == nil && match {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read bootstrap public key: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".loom-bootstrap-pub-*")
	if err != nil {
		return fmt.Errorf("create bootstrap public key temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("set bootstrap public key permissions: %w", err)
	}
	if _, err := io.WriteString(tmp, want); err != nil {
		return fmt.Errorf("write bootstrap public key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap public key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close bootstrap public key: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish bootstrap public key: %w", err)
	}
	removeTemp = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync bootstrap key directory: %w", err)
	}
	return nil
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("inspect bootstrap private key: %w", err)
	}
	if err := validatePrivateMetadata(info); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap private key: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open bootstrap private key: %w", err)
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("bootstrap private key changed while opening")
	}
	if err := validatePrivateMetadata(opened); err != nil {
		return nil, err
	}
	encoded, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap private key: %w", err)
	}
	private, err := parseOpenSSHPrivate(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid bootstrap private key: %w", err)
	}
	return private, nil
}

func validatePrivateMetadata(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("bootstrap private key is not a regular file")
	}
	uid, err := fileOwner(info)
	if err != nil {
		return fmt.Errorf("inspect bootstrap private key owner: %w", err)
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("bootstrap private key owner is uid %d, require current euid %d", uid, os.Geteuid())
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("bootstrap private key permissions are %04o, require exactly 0600", info.Mode().Perm())
	}
	return nil
}

type parentDirectory struct {
	path string
	mode os.FileMode
	uid  uint32
}

// validateSecureParent rejects symlinks throughout the path and writable
// parent directories. A sticky shared ancestor (normally /tmp) is accepted
// only when its immediate child is an owner-controlled, non-writable
// directory. This makes /tmp/<0700 tempdir>/key safe while correctly rejecting
// /tmp/key.
func validateSecureParent(path string, create bool) error {
	parent := filepath.Dir(path)
	paths := parentPaths(parent)
	directories := make([]parentDirectory, 0, len(paths))
	missing := false
	for _, current := range paths {
		var info os.FileInfo
		if !missing {
			var err error
			info, err = os.Lstat(current)
			if errors.Is(err, os.ErrNotExist) {
				missing = true
			} else if err != nil {
				return fmt.Errorf("inspect bootstrap key parent %q: %w", current, err)
			}
		}
		if missing {
			if create {
				if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
					return fmt.Errorf("create bootstrap key parent %q: %w", current, err)
				}
				var err error
				info, err = os.Lstat(current)
				if err != nil {
					return fmt.Errorf("inspect created bootstrap key parent %q: %w", current, err)
				}
				missing = false
			} else {
				directories = append(directories, parentDirectory{path: current, mode: 0o700 | os.ModeDir, uid: uint32(os.Geteuid())})
				continue
			}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bootstrap key parent %q must be a directory and not a symlink", current)
		}
		uid, err := fileOwner(info)
		if err != nil {
			return fmt.Errorf("inspect bootstrap key parent owner %q: %w", current, err)
		}
		directories = append(directories, parentDirectory{path: current, mode: info.Mode(), uid: uid})
	}
	for i, directory := range directories {
		if directory.mode.Perm()&0o022 == 0 {
			continue
		}
		if directory.mode&os.ModeSticky == 0 || i+1 >= len(directories) {
			return fmt.Errorf("bootstrap key parent %q is group/world writable", directory.path)
		}
		child := directories[i+1]
		if child.mode.Perm()&0o022 != 0 || (child.uid != uint32(os.Geteuid()) && child.uid != 0) {
			return fmt.Errorf("bootstrap key parent %q is not protected beneath sticky directory %q", child.path, directory.path)
		}
	}
	return nil
}

func ensureSecureParent(path string) error {
	return validateSecureParent(path, true)
}

func parentPaths(parent string) []string {
	if parent == string(filepath.Separator) {
		return []string{parent}
	}
	parts := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	paths := make([]string, 0, len(parts)+1)
	current := string(filepath.Separator)
	paths = append(paths, current)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	return paths
}

func fileOwner(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("filesystem did not expose Unix ownership")
	}
	return stat.Uid, nil
}

func publicFileMatches(path string, want []byte) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !os.SameFile(info, opened) {
		// Another Ensure may have atomically published the same derived key.
		// Treat the stale descriptor as a cache miss and converge by writing.
		return false, nil
	}
	got, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(got, want) {
		return false, nil
	}
	if err := f.Chmod(0o644); err != nil {
		return false, fmt.Errorf("set bootstrap public key permissions: %w", err)
	}
	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("sync bootstrap public key permissions: %w", err)
	}
	return true, nil
}

func publicOpenSSH(public ed25519.PublicKey) string {
	blob := marshalPublicBlob(public)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + publicComment
}

func fingerprint(public ed25519.PublicKey) string {
	sum := sha256.Sum256(marshalPublicBlob(public))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
