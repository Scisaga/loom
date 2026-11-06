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

func refreshWindowsLinkObservations(ctx context.Context, store deviceclient.IdentityStore, view *control.DeviceViewEnvelope, state *clientadapter.State, previous *control.DeviceLinkObservations) *control.DeviceLinkObservations {
	defer func() {
		if ctx.Err() == nil {
			publishWindowsRouteVisibility(ctx, view, state)
		}
	}()
	if previous != nil && previous.ValidateForView(view.View) != nil {
		previous = nil
	}
	state.LinkObservations = nil
	if previous != nil {
		state.LinkObservations = previous.Observations
	}
	attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, err := deviceclient.FetchLinkObservations(attempt, store, previous)
	if err != nil || ctx.Err() != nil || value.ViewDigest != view.ViewDigest {
		log.Print("current relay observation refresh unavailable; previous samples retain their original expiry")
		return previous
	}
	state.LinkObservations = value.Observations
	return &value
}
