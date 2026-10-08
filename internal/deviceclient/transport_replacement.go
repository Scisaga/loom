package deviceclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"loom/internal/clientsecret"
	"loom/internal/control"
)

// ReplaceTransportLKG is the explicit schema 3 forward migration. The old
// signed View is only an input to signature/progress verification, never a
// decoded executable identity. Mobile storage can atomically persist the result.
func ReplaceTransportLKG(original []byte, replacement control.DeviceViewEnvelope) (State, error) {
	if len(original) > maxStateBytes || replacement.Validate() != nil {
		return State{}, errors.New("transport replacement input is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(original))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return State{}, errors.New("device identity is not an object")
	}
	start, end := -1, -1
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return State{}, errors.New("device identity has invalid or duplicated fields")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return State{}, errors.New("device identity contains invalid JSON")
		}
		if name == "certified_lkg" {
			end = int(decoder.InputOffset())
			start = end - len(raw)
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || start < 0 {
		return State{}, errors.New("device identity has no complete historical LKG")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return State{}, errors.New("device identity has trailing JSON")
	}
	body, err := control.CanonicalEncode(replacement)
	if err != nil {
		return State{}, err
	}
	defer clear(body)
	nextBytes := make([]byte, 0, len(original)+len(body))
	nextBytes = append(nextBytes, original[:start]...)
	nextBytes = append(nextBytes, body...)
	nextBytes = append(nextBytes, original[end:]...)
	defer clear(nextBytes)
	// The ordinary decoder now verifies every unchanged identity field and
	// exact canonical bytes, including keys, latch, floor, sequence, preference.
	next, err := DecodeIdentityState(nextBytes)
	if err != nil {
		return State{}, err
	}
	if err := control.CheckTransportReplacement(original[start:end], replacement, next.Invite, next.HighWater); err != nil {
		return State{}, err
	}
	return AcceptLKG(next, replacement)
}

// MigrateTransportFile is never called by Load, Open, sync or runtime startup.
// The explicit command supplies both a newly certified View and an evidence
// destination. Failed verification leaves the original state untouched.
func MigrateTransportFile(path, evidence string, replacement control.DeviceViewEnvelope, protector clientsecret.Protector) error {
	if !validStatePath(path) || !validStatePath(evidence) || path == evidence {
		return errors.New("migration requires distinct canonical state and evidence paths")
	}
	store := &Store{path: path, protector: protector}
	lock, err := lockStateFile(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	original, err := store.readBytesUnlocked()
	if err != nil {
		return err
	}
	defer clear(original)
	next, err := ReplaceTransportLKG(original, replacement)
	if err != nil {
		return err
	}
	if err := store.validateState(next); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(evidence), 0700); err != nil {
		return err
	}
	backup := &Store{path: evidence, protector: protector}
	if protector != nil {
		if err := clientsecret.PreserveProtected(path, evidence, protectedStatePurpose, original, protector); err != nil {
			return err
		}
		return store.writeUnlocked(next, next)
	}
	saved, err := backup.readBytesUnlocked()
	if err == nil {
		defer clear(saved)
		if !bytes.Equal(saved, original) {
			return errors.New("migration evidence already contains different bytes")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		var file *os.File
		file, err = os.OpenFile(evidence, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = file.Write(original)
			if err == nil {
				err = file.Sync()
			}
			err = errors.Join(err, file.Close())
		}
		if err == nil {
			err = syncProtectedDirectory(filepath.Dir(evidence))
		}
		if err != nil {
			return err
		}
	} else {
		return err
	}
	readback, err := backup.readBytesUnlocked()
	defer clear(readback)
	if err != nil || !bytes.Equal(readback, original) {
		return errors.New("historical evidence did not survive readback")
	}
	return store.writeUnlocked(next, next)
}
