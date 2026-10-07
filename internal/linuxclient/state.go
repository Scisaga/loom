// Package linuxclient implements the Linux HostAdapter for the shared client
// runtime model. It persists only the local preference and bounded observations;
// identity and the certified LKG remain in deviceclient.Store.
package linuxclient

import (
	"crypto/sha256"
	"encoding/hex"
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
	"loom/internal/control"
)

const localStateSchema = 3

type LocalState struct {
	Schema                int                       `json:"schema"`
	Preference            clientmodel.Preference    `json:"preference"`
	NetworkGeneration     string                    `json:"network_generation"`
	ObservationViewDigest string                    `json:"observation_view_digest,omitempty"`
	Observations          []clientmodel.Observation `json:"observations"`
	ResourceObservations  []control.Observation     `json:"resource_observations,omitempty"`
}

type SelectionStatus struct {
	Scope       string   `json:"scope"`
	CandidateID string   `json:"candidate_id"`
	FinalExit   string   `json:"final_exit"`
	Chain       []string `json:"chain,omitempty"`
	State       string   `json:"state"`
}

// Status is a deletable readback projection. It is written under /run by the
// service and never used as authority on the next start.
type Status struct {
	PossiblePermissionRestoration bool                       `json:"possible_permission_restoration"`
	Schema                        int                        `json:"schema"`
	DeviceID                      string                     `json:"device_id"`
	ViewDigest                    string                     `json:"view_digest"`
	FactFrontier                  []control.FactFrontier     `json:"fact_frontier"`
	Preference                    clientmodel.Preference     `json:"preference"`
	NetworkGeneration             string                     `json:"network_generation"`
	Selections                    []SelectionStatus          `json:"selections"`
	Observations                  []clientmodel.Observation  `json:"observations"`
	Runtime                       string                     `json:"runtime"`
	Reported                      bool                       `json:"reported"`
	Resources                     []control.ResourceReadback `json:"resources,omitempty"`
	ResourceObservations          []control.Observation      `json:"resource_observations,omitempty"`
}

func defaultState(generation string) LocalState {
	return LocalState{Schema: localStateSchema,
		Preference:        clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto},
		NetworkGeneration: generation, Observations: []clientmodel.Observation{}}
}

func (state LocalState) validate() error {
	if state.Schema != localStateSchema || state.Preference.Validate() != nil || state.NetworkGeneration == "" ||
		len(state.NetworkGeneration) > 128 || strings.TrimSpace(state.NetworkGeneration) != state.NetworkGeneration {
		return errors.New("Linux client local state is invalid")
	}
	if state.ObservationViewDigest != "" {
		digest, err := hex.DecodeString(strings.TrimPrefix(state.ObservationViewDigest, "sha256:"))
		if err != nil || len(digest) != sha256.Size || state.ObservationViewDigest != "sha256:"+hex.EncodeToString(digest) {
			return errors.New("Linux observation view binding is invalid")
		}
	}
	for index, observation := range state.Observations {
		if observation.Validate() != nil || observation.NetworkGeneration != state.NetworkGeneration ||
			index > 0 && state.Observations[index-1].CandidateID >= observation.CandidateID {
			return errors.New("Linux client observations are not current and uniquely sorted")
		}
	}
	if state.ResourceObservations != nil && (len(state.ResourceObservations) == 0 || state.ObservationViewDigest == "") {
		return errors.New("resource observation cache has no view binding or is noncanonical")
	}
	if err := validateResourceObservations(state.ResourceObservations, state.NetworkGeneration); err != nil {
		return err
	}
	return nil
}

func validateResourceObservations(values []control.Observation, generation string) error {
	for i, value := range values {
		if value.Validate() != nil || value.Level != "resource" || value.NetworkGeneration != generation ||
			i > 0 && values[i-1].ResourceID >= value.ResourceID {
			return errors.New("resource observations are not current and uniquely sorted")
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
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("Linux client state changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return err
	}
	return control.DecodeCanonical(body, value, control.ContractDecodeLimits{MaxBytes: int(maximum), MaxDepth: 32, MaxItems: 100000})
}

func atomicJSON(path string, value any) (retErr error) {
	body, err := control.CanonicalEncode(value)
	if err != nil {
		return err
	}
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
	return loadLocalState(path, generation, "")
}

// loadLocalState binds disposable observations to the exact authenticated view.
// A cache without that binding cannot prove that a reused candidate ID still
// describes the same authorization, targets and runtime inputs.
func loadLocalState(path, generation, viewDigest string) (LocalState, error) {
	return loadLocalStateWithEvidence(path, generation, viewDigest, nil)
}

func loadLocalStateWithEvidence(path, generation, viewDigest string, retain func(LocalState) ([]clientmodel.Observation, []control.Observation)) (LocalState, error) {
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
		if state.NetworkGeneration != generation || viewDigest != "" && state.ObservationViewDigest != viewDigest {
			observations := []clientmodel.Observation{}
			var resources []control.Observation
			if state.NetworkGeneration == generation && retain != nil {
				observations, resources = retain(state)
			}
			state.NetworkGeneration = generation
			state.ObservationViewDigest = viewDigest
			state.Observations = observations
			state.ResourceObservations = append([]control.Observation(nil), resources...)
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
		if current.NetworkGeneration != state.NetworkGeneration || current.ObservationViewDigest != state.ObservationViewDigest {
			return errors.New("network generation or certified view changed while recording observations")
		}
		current.Observations = append([]clientmodel.Observation{}, state.Observations...)
		current.ResourceObservations = append([]control.Observation(nil), state.ResourceObservations...)
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
			state.ResourceObservations = nil
		}
		state.Preference = preference
		return atomicJSON(path, state)
	})
}

func WriteStatus(path string, status Status) error {
	if err := status.validate(); err != nil {
		return err
	}
	return atomicJSON(path, status)
}

func (status Status) validate() error {
	if status.Schema != 3 || status.DeviceID == "" || control.ValidateDigest(status.ViewDigest) != nil || status.FactFrontier == nil ||
		status.Preference.Validate() != nil || status.NetworkGeneration == "" ||
		status.Runtime != "running" && status.Runtime != "error" && status.Runtime != "stopped" ||
		status.Runtime != "running" && (len(status.Selections) != 0 || len(status.Observations) != 0) {
		return errors.New("Linux client status is incomplete")
	}
	if err := validateResourceObservations(status.ResourceObservations, status.NetworkGeneration); err != nil ||
		status.Runtime != "running" && len(status.ResourceObservations) > 0 {
		return errors.New("Linux resource observation status is invalid")
	}
	for index, value := range status.Resources {
		if status.Runtime != "running" || value.Validate() != nil || index > 0 && status.Resources[index-1].ResourceID >= value.ResourceID {
			return errors.New("Linux resource status is invalid")
		}
	}
	return nil
}

func ReadStatus(path string) (Status, error) {
	var status Status
	if err := readStrict(path, 1<<20, &status); err != nil {
		return status, err
	}
	if err := status.validate(); err != nil {
		return Status{}, err
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
