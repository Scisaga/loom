package clientcore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ReadPreference reads local non-secret preference state. Missing state is
// reported as os.ErrNotExist so the platform host can choose an explicit safe
// first-run default without conflating absence with corruption.
func ReadPreference(path string) (Preference, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Preference{}, err
	}
	p, err := ParsePreference(body)
	if err != nil {
		return Preference{}, fmt.Errorf("read preference %s: %w", path, err)
	}
	return p, nil
}

// WritePreference replaces preference state atomically in one directory.
// Preference contains no credentials; Windows protects the parent ProgramData
// directory with its service ACL while identity and access secrets use DPAPI.
func WritePreference(path string, preference Preference) (retErr error) {
	body, err := EncodePreference(preference)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create preference directory %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary preference: %w", err)
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary preference: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("write temporary preference: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temporary preference: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary preference: %w", err)
	}
	if err := replaceFile(tmp, path); err != nil {
		return fmt.Errorf("replace preference %s: %w", path, err)
	}
	if err := syncParent(dir); err != nil {
		return fmt.Errorf("sync preference directory %s: %w", dir, err)
	}
	return nil
}

// EnsurePreference creates Auto only when no preference exists. Corrupt state
// is never overwritten: losing a user's FixedExit choice could silently change
// routing semantics.
func EnsurePreference(path string) (Preference, error) {
	p, err := ReadPreference(path)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Preference{}, err
	}
	p = Preference{Schema: PreferenceSchema, Mode: Auto}
	if err := WritePreference(path, p); err != nil {
		return Preference{}, err
	}
	return p, nil
}
