package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func readPolicyMigrationBytes(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	link, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > 1<<20 || !os.SameFile(before, link) {
		return nil, errors.New("policy evidence requires a bounded private regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || len(body) > 1<<20 {
		return nil, errors.New("policy evidence changed during read")
	}
	return body, nil
}

// Historical preference bytes are only exposed to the explicit migration.
// Ordinary state loading never calls this reader or accepts the old shape.
func PolicyMigrationInput(path, evidence string) ([]byte, []byte, error) {
	body, err := readPolicyMigrationBytes(evidence)
	if errors.Is(err, os.ErrNotExist) {
		body, err = readPolicyMigrationBytes(path)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(body) == 0 {
		return nil, nil, nil
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, nil, err
	}
	return body, value["preference"], nil
}

func PreparePolicyMigration(original []byte, preference clientmodel.Preference, generation, digest string) (LocalState, error) {
	if err := preference.Validate(); err != nil {
		return LocalState{}, err
	}
	state := defaultState(generation)
	if len(original) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(original))
		if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
			return LocalState{}, errors.New("historical runtime is not an object")
		}
		fields := map[string]json.RawMessage{}
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok || fields[name] != nil {
				return LocalState{}, errors.New("duplicate historical runtime field")
			}
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return LocalState{}, err
			}
			fields[name] = raw
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return LocalState{}, errors.New("incomplete historical runtime")
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return LocalState{}, errors.New("trailing historical runtime input")
		}
		join := func() []byte {
			keys := make([]string, 0, len(fields))
			for name := range fields {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			body := []byte{'{'}
			for i, name := range keys {
				if i > 0 {
					body = append(body, ',')
				}
				encoded, _ := json.Marshal(name)
				body = append(body, encoded...)
				body = append(body, ':')
				body = append(body, fields[name]...)
			}
			return append(body, '}')
		}
		if !bytes.Equal(original, join()) || fields["preference"] == nil {
			return LocalState{}, errors.New("historical runtime preference is missing or noncanonical")
		}
		delete(fields, "preference")
		if err := control.DecodeCanonical(join(), &state.observationCache, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100000}); err != nil {
			return LocalState{}, err
		}
	}
	state.Preference = preference // transient input; never written to runtime.json
	state.NetworkGeneration = generation
	state.ObservationViewDigest = digest
	state.Observations = []clientmodel.Observation{}
	state.ResourceObservations = nil
	return state, state.validate()
}

func CommitPolicyMigration(path, evidence string, original []byte, next LocalState) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(evidence) || filepath.Clean(evidence) != evidence || path == evidence {
		return errors.New("policy migration requires distinct canonical private paths")
	}
	if err := next.validate(); err != nil {
		return err
	}
	return withLock(path, func() error {
		var current LocalState
		if readStrict(path, 1<<20, &current.observationCache) == nil && current.validate() == nil && current.ObservationViewDigest == next.ObservationViewDigest {
			saved, err := readPolicyMigrationBytes(evidence)
			if err != nil || !bytes.Equal(saved, original) {
				return errors.New("completed migration has no matching original preference evidence")
			}
			return nil
		}
		disk, err := readPolicyMigrationBytes(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !bytes.Equal(disk, original) {
			return errors.New("local preference changed after migration review")
		}
		if err := os.MkdirAll(filepath.Dir(evidence), 0700); err != nil {
			return err
		}
		saved, err := readPolicyMigrationBytes(evidence)
		if errors.Is(err, os.ErrNotExist) {
			var file *os.File
			file, err = os.OpenFile(evidence, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = file.Write(original)
			if err == nil {
				err = file.Sync()
			}
			err = errors.Join(err, file.Close())
			if err != nil {
				return err
			}
			var dir *os.File
			dir, err = os.Open(filepath.Dir(evidence))
			if err != nil {
				return err
			}
			err = dir.Sync()
			err = errors.Join(err, dir.Close())
			if err != nil {
				return err
			}
			saved, err = readPolicyMigrationBytes(evidence)
		}
		if err != nil || !bytes.Equal(saved, original) {
			return errors.New("original policy preference evidence differs")
		}
		return atomicJSON(path, next.observationCache)
	})
}
