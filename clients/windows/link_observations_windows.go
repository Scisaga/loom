//go:build windows

package main

import (
	"context"
	"log"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func refreshWindowsLinkObservations(ctx context.Context, store deviceclient.IdentityStore, view *control.DeviceViewEnvelope, state *clientadapter.State) {
	attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, err := deviceclient.FetchLinkObservations(attempt, store)
	if err != nil || value.ViewDigest != view.ViewDigest {
		log.Print("current relay observation refresh unavailable; previous samples retain their original expiry")
		return
	}
	state.LinkObservations = value.Observations
}
