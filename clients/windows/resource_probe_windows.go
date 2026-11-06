//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func windowsResourceCachePath(root string) string {
	return filepath.Join(root, "runtime", "resource-observations.json")
}

func readWindowsResourceCache(root string, lkg control.DeviceViewEnvelope, generation string, policies []string) ([]control.Observation, error) {
	path := windowsResourceCachePath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return []control.Observation{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > clientadapter.ResourceObservationCacheLimit {
		return nil, errors.New("resource observation cache is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("resource observation cache changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, clientadapter.ResourceObservationCacheLimit+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || int64(len(body)) != opened.Size() || len(body) > clientadapter.ResourceObservationCacheLimit {
		return nil, errors.New("resource observation cache changed while reading")
	}
	return clientadapter.DecodeResourceObservations(body, lkg, generation, policies)
}

func windowsSelectedCandidates(activation clientadapter.Activation) []string {
	return clientadapter.MeasurementCandidates(activation.Selections, activation.State.SelectionMemory, activation.State.NetworkGeneration)
}

// The process lock owns the running instance; it is not a UI operation lock.
// Completion deltas are consumed serially while other probes continue.
func observeWindowsFirstHops(ctx context.Context, root string, lkg control.DeviceViewEnvelope, activation *clientadapter.Activation, initiallySelected []string, progress func() error, recovery ...*clientadapter.TCPRecoveryInput) error {
	previous := activation.State.ResourceObservations
	if previous == nil {
		var err error
		previous, err = readWindowsResourceCache(root, lkg, activation.State.NetworkGeneration, clientmodel.MeasurementPolicies(activation.State.Preference))
		if err != nil {
			log.Printf("first-hop observation cache unavailable; resource samples remain unknown: %v", err)
			return nil
		}
	}
	selected := append(append([]string{}, initiallySelected...), windowsSelectedCandidates(*activation)...)
	activation.State.ResourceObservations = previous
	execution, err := control.ProjectDeviceCandidates(lkg.View, clientmodel.MeasurementPolicies(activation.State.Preference))
	if err != nil {
		activation.State.ResourceObservations = nil
		return err
	}
	values, err := clientadapter.ObserveFirstHops(ctx, execution, selected, previous, activation.State.NetworkGeneration, time.Now, func(batch []control.Observation) error {
		activation.State.ResourceObservations = clientadapter.MergeNodeMeasurements(activation.State.ResourceObservations, batch)
		return progress()
	}, recovery...)
	if err != nil {
		return err
	}
	activation.State.ResourceObservations = append([]control.Observation{}, values...)
	body, err := clientadapter.EncodeResourceObservations(lkg, values, clientmodel.MeasurementPolicies(activation.State.Preference))
	if err == nil {
		err = writeWindowsJoinFile(windowsResourceCachePath(root), body)
	}
	if err != nil {
		log.Printf("first-hop samples are only reusable in this process; cache write unavailable: %v", err)
	}
	return nil
}
