// Package linuxclient implements the Linux HostAdapter for the shared client
// runtime model. It persists only the local preference and bounded observations;
// identity and the certified LKG remain in deviceclient.Store.
package linuxclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"loom/internal/clientmodel"
)

const localStateSchema = 1

type LocalState struct {
	Schema            int                       `json:"schema"`
	Preference        clientmodel.Preference    `json:"preference"`
	NetworkGeneration string                    `json:"network_generation"`
	Observations      []clientmodel.Observation `json:"observations"`
}

type SelectionStatus struct {
	Scope       string   `json:"scope"`
	CandidateID string   `json:"candidate_id"`
	Chain       []string `json:"chain,omitempty"`
	State       string   `json:"state"`
}

// Status is a deletable readback projection. It is written under /run by the
// service and never used as authority on the next start.
type Status struct {
	Schema            int                       `json:"schema"`
	DeviceID          string                    `json:"device_id"`
	Head              string                    `json:"head"`
	Floor             uint64                    `json:"floor"`
	Preference        clientmodel.Preference    `json:"preference"`
	NetworkGeneration string                    `json:"network_generation"`
	Selections        []SelectionStatus         `json:"selections"`
	Observations      []clientmodel.Observation `json:"observations"`
	Runtime           string                    `json:"runtime"`
	Reported          bool                      `json:"reported"`
}

func defaultState(generation string) LocalState {
	return LocalState{Schema: localStateSchema,
		Preference:        clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto},
		NetworkGeneration: generation, Observations: []clientmodel.Observation{}}
}

func (state LocalState) validate() error {
	if state.Schema != localStateSchema || state.Preference.Validate() != nil || state.NetworkGeneration == "" ||
		len(state.NetworkGeneration) > 128 || strings.TrimSpace(state.NetworkGeneration) != state.NetworkGeneration {
		return errors.New("Linux client local state is invalid")
	}
	for index, observation := range state.Observations {
		if observation.Validate() != nil || observation.NetworkGeneration != state.NetworkGeneration ||
			index > 0 && state.Observations[index-1].CandidateID >= observation.CandidateID {
			return errors.New("Linux client observations are not current and uniquely sorted")
		}
	}
	return nil
}

func readStrict(path string, maximum int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum ||
		runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("Linux client state must be an owner-only bounded regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Linux client state has trailing content")
	}
	return nil
}

func atomicJSON(path string, value any) (retErr error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".linux-client-*")
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
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func withLock(path string, action func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return action()
}

// LoadLocalState resets observations when the host-provided underlay
// generation changes. It never manufactures an availability result.
func LoadLocalState(path, generation string) (LocalState, error) {
	var result LocalState
	err := withLock(path, func() error {
		var state LocalState
		if err := readStrict(path, 1<<20, &state); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			state = defaultState(generation)
			if err := atomicJSON(path, state); err != nil {
				return err
			}
		} else if err := state.validate(); err != nil {
			return err
		}
		if state.NetworkGeneration != generation {
			state.NetworkGeneration = generation
			state.Observations = []clientmodel.Observation{}
			if err := atomicJSON(path, state); err != nil {
				return err
			}
		}
		result = state
		return nil
	})
	return result, err
}

func SaveLocalState(path string, state LocalState) error {
	if err := state.validate(); err != nil {
		return err
	}
	return withLock(path, func() error { return atomicJSON(path, state) })
}

// SaveObservations preserves a concurrently-written Preference; the runtime
// only owns Observation changes, while the CLI is the sole preference writer.
func SaveObservations(path string, state LocalState) (LocalState, error) {
	if err := state.validate(); err != nil {
		return LocalState{}, err
	}
	var saved LocalState
	err := withLock(path, func() error {
		var current LocalState
		if err := readStrict(path, 1<<20, &current); err != nil {
			return err
		}
		if err := current.validate(); err != nil {
			return err
		}
		if current.NetworkGeneration != state.NetworkGeneration {
			return errors.New("network generation changed while recording observations")
		}
		current.Observations = append([]clientmodel.Observation(nil), state.Observations...)
		if err := atomicJSON(path, current); err != nil {
			return err
		}
		saved = current
		return nil
	})
	return saved, err
}

func SetPreference(path, generation string, preference clientmodel.Preference) error {
	if err := preference.Validate(); err != nil {
		return err
	}
	return withLock(path, func() error {
		var state LocalState
		if err := readStrict(path, 1<<20, &state); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			state = defaultState(generation)
		} else if err := state.validate(); err != nil {
			return err
		}
		if state.NetworkGeneration != generation {
			state.NetworkGeneration = generation
			state.Observations = []clientmodel.Observation{}
		}
		state.Preference = preference
		return atomicJSON(path, state)
	})
}

func WriteStatus(path string, status Status) error {
	if status.Schema != 1 || status.DeviceID == "" || status.Head == "" || status.Floor == 0 ||
		status.Preference.Validate() != nil || status.NetworkGeneration == "" {
		return errors.New("Linux client status is incomplete")
	}
	return atomicJSON(path, status)
}

func ReadStatus(path string) (Status, error) {
	var status Status
	if err := readStrict(path, 1<<20, &status); err != nil {
		return status, err
	}
	if status.Schema != 1 || status.Preference.Validate() != nil || status.DeviceID == "" || status.Head == "" ||
		status.NetworkGeneration == "" || status.Runtime != "running" {
		return Status{}, errors.New("Linux client runtime is not running")
	}
	return status, nil
}

// NetworkGeneration hashes only local underlay identity inputs. A reboot or a
// route/address/DNS change invalidates old observations without a random ID.
func NetworkGeneration() (string, error) {
	var values []string
	for _, path := range []string{"/proc/sys/kernel/random/boot_id", "/proc/net/route", "/proc/net/ipv6_route", "/etc/resolv.conf"} {
		body, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read network generation input %s: %w", path, err)
		}
		values = append(values, path+"\x00"+string(body))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, networkInterface := range interfaces {
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return "", addressErr
		}
		for _, address := range addresses {
			values = append(values, networkInterface.Name+"\x00"+address.String())
		}
	}
	sort.Strings(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "net-" + hex.EncodeToString(digest[:16]), nil
}

func observationState(observations []clientmodel.Observation, candidateID, generation string, now time.Time) string {
	for _, observation := range observations {
		until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
		if observation.CandidateID == candidateID && observation.NetworkGeneration == generation && now.Before(until) {
			return observation.Result
		}
	}
	return "unknown"
}
