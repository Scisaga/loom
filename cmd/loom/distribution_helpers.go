package main

// This file contains transport and atomic-apply helpers still shared by the
// administrator rollback/pin tools. The retired node-side pull producer is not
// present and these helpers do not select or install a client configuration.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"loom/internal/render"
	"loom/internal/report"
)

func getBytes(client *http.Client, address string) ([]byte, error) {
	response, err := client.Get(address)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", address, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 16<<20))
}

const (
	blobStall        = 45 * time.Second
	blobMinimumRate  = int64(32 << 10)
	blobTotalMinimum = 2 * time.Minute
	blobTotalMaximum = 20 * time.Minute
)

func blobTotalTimeout(size int64) time.Duration {
	if size < 0 {
		size = 0
	}
	seconds := size / blobMinimumRate
	if size%blobMinimumRate != 0 {
		seconds++
	}
	maximumSeconds := int64((blobTotalMaximum - blobStall) / time.Second)
	if seconds >= maximumSeconds {
		return blobTotalMaximum
	}
	total := time.Duration(seconds)*time.Second + blobStall
	if total < blobTotalMinimum {
		return blobTotalMinimum
	}
	if total > blobTotalMaximum {
		return blobTotalMaximum
	}
	return total
}

func getBlob(client *http.Client, address string, maximum int64, stall time.Duration) ([]byte, error) {
	return getBlobWithLimits(client, address, maximum, stall, blobTotalTimeout(maximum))
}

func getBlobWithLimits(client *http.Client, address string, maximum int64, stall, total time.Duration) ([]byte, error) {
	if maximum <= 0 || stall <= 0 || total <= 0 {
		return nil, fmt.Errorf("invalid blob download boundary")
	}
	networkClient := *client
	networkClient.Timeout = 0
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := networkClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", address, response.StatusCode)
	}
	var stalled atomic.Bool
	timer := time.AfterFunc(stall, func() { stalled.Store(true); cancel() })
	defer timer.Stop()
	body, err := io.ReadAll(&stallReader{reader: io.LimitReader(response.Body, maximum), timer: timer, duration: stall})
	if err != nil && stalled.Load() {
		return nil, fmt.Errorf("blob transfer stalled for %s", stall)
	}
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("blob transfer exceeded %s", total)
	}
	return body, err
}

type stallReader struct {
	reader   io.Reader
	timer    *time.Timer
	duration time.Duration
}

func (reader *stallReader) Read(body []byte) (int, error) {
	read, err := reader.reader.Read(body)
	if read > 0 {
		reader.timer.Reset(reader.duration)
	}
	return read, err
}

func short(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

const manifestBundlePath = "report/manifest.json"

func buildManifest(node string, files map[string]string) string {
	manifest := report.Manifest{Node: node, Files: map[string]string{}}
	for bundlePath, content := range files {
		if bundlePath == manifestBundlePath {
			continue
		}
		absolute := render.InstallPath(bundlePath)
		if absolute == "" {
			continue
		}
		digest := sha256.Sum256([]byte(content))
		manifest.Files[absolute] = hex.EncodeToString(digest[:])
	}
	body, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(body) + "\n"
}
