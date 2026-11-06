package loomcore

import (
	"context"
	"errors"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// AndroidDeviceRequest owns one cancellable private I/O call, never a profile
// or persistent state. The host rechecks the current record before committing.
type AndroidDeviceRequest struct {
	ctx    context.Context
	cancel context.CancelFunc
	run    func(context.Context) ([]byte, error)
}

func (request *AndroidDeviceRequest) Cancel() { request.cancel() }

func (request *AndroidDeviceRequest) Run() ([]byte, error) {
	defer request.cancel()
	if err := request.ctx.Err(); err != nil {
		return nil, err
	}
	return request.run(request.ctx)
}

// NewAndroidConfigurationRequest fetches the signed envelope only. Accepting it
// against the latest protected record preserves concurrent report reservations.
func NewAndroidConfigurationRequest(body []byte, waitForChange bool, round int64) (*AndroidDeviceRequest, error) {
	if round < 0 {
		return nil, errors.New("configuration request round must be nonnegative")
	}
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("configuration request requires an accepted LKG")
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		var envelope control.DeviceViewEnvelope
		var err error
		if waitForChange {
			envelope, err = deviceclient.AwaitConfiguration(ctx, &androidIdentity{state: state}, uint64(round))
		} else {
			envelope, err = deviceclient.Fetch(ctx, &androidIdentity{state: state})
		}
		if err != nil {
			return nil, err
		}
		return control.CanonicalEncode(envelope)
	}}, nil
}

func NewAndroidEnrollmentRequest(body []byte) (*AndroidDeviceRequest, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		store := &androidIdentity{state: state}
		var callErr error
		if state.LKG == nil {
			_, callErr = deviceclient.Claim(ctx, store)
		} else {
			_, callErr = deviceclient.Resume(ctx, store)
		}
		if callErr != nil {
			return nil, callErr
		}
		return deviceclient.EncodeIdentityState(store.state)
	}}, nil
}
