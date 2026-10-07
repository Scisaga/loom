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
	"loom/internal/control"
)

func windowsResourceCachePath(root string) string {
	return filepath.Join(root, "runtime", "resource-observations.json")
}

func readWindowsResourceCache(root string, lkg control.DeviceViewEnvelope, generation string) ([]control.Observation, error) {
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
	return clientadapter.DecodeResourceObservations(body, lkg, generation)
}

func windowsSelectedCandidates(activation clientadapter.Activation) []string {
	result := make([]string, 0, len(activation.Selections))
	for _, selection := range activation.Selections {
		result = append(result, selection.CandidateID)
	}
	return result
}

// Called under the existing process-wide data-plane lock. A diagnostic cache
// failure cannot grant a route or turn a Service result into resource health.
func observeWindowsFirstHops(ctx context.Context, root string, lkg control.DeviceViewEnvelope, activation *clientadapter.Activation, initiallySelected []string) {
	previous := activation.State.ResourceObservations
	if previous == nil {
		var err error
		previous, err = readWindowsResourceCache(root, lkg, activation.State.NetworkGeneration)
		if err != nil {
			log.Printf("first-hop observation cache unavailable; resource samples remain unknown: %v", err)
			return
		}
	}
	selected := append(append([]string{}, initiallySelected...), windowsSelectedCandidates(*activation)...)
	values, err := clientadapter.ObserveFirstHops(ctx, lkg.View, selected, previous, activation.State.NetworkGeneration, time.Now)
	if err != nil {
		activation.State.ResourceObservations = nil
		if ctx.Err() == nil {
			log.Printf("first-hop observation unavailable; Service selections unchanged: %v", err)
		}
		return
	}
	activation.State.ResourceObservations = append([]control.Observation{}, values...)
	body, err := clientadapter.EncodeResourceObservations(lkg, values)
	if err == nil {
		err = writeWindowsJoinFile(windowsResourceCachePath(root), body)
	}
	if err != nil {
		log.Printf("first-hop samples are only reusable in this process; cache write unavailable: %v", err)
	}
}
