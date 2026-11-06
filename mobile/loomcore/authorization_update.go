package loomcore

import (
	"context"
	"encoding/json"
	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"time"
)

// ApplyAndroidRuntimeAuthorization confirms accepted permission separately from
// the current resource construction descriptions. Call only after the identity write is durable.
func ApplyAndroidRuntimeAuthorization(beforeSource, afterSource, running string) (string, error) {
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 5*time.Second)
	defer cancel()
	result, err := clientadapter.ApplyRuntimeAuthorization(ctx, beforeSource, afterSource, running)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(result)
	return string(body), err
}

// NewAndroidRuntimeResourcesRequest owns cancellable description installation. It
// runs outside the host configuration lock and never accepts authority itself.
func NewAndroidRuntimeResourcesRequest(source, running string) (*AndroidDeviceRequest, error) {
	selector, err := clientadapter.NewHTTPSelector(running)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 8*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		ready, err := selector.ReconcileRuntimeResources(ctx, source)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Description installation cannot undo the already confirmed permissions.
		// Its failure remains unknown and is retried from the current source.
		current := selector.ConfirmRuntimePermissions(ctx, source) == nil
		result := clientadapter.RuntimeApplication{Supported: true, PermissionCurrent: current, ResourcesReady: err == nil && ready, Config: running}
		return json.Marshal(result)
	}}, nil
}

// AndroidNativeResourceBase is a pure execution projection. The accepted
// profile retains its full description; this value alone starts native objects.
func AndroidNativeResourceBase(config string) (string, error) {
	return clientadapter.NativeResourceBase(config)
}

func NewAndroidSelectionResourcesRequest(source string, body []byte) (*AndroidDeviceRequest, error) {
	var desired clientmodel.Selection
	if err := decodeStrictJSON(body, 1<<20, &desired); err != nil {
		return nil, err
	}
	if err := clientmodel.ValidateAccessSelection(desired); err != nil {
		return nil, err
	}
	selector, err := clientadapter.NewHTTPSelector(source)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 8*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		ready, err := selector.PrepareSelectionResources(ctx, desired)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		current := selector.ConfirmRuntimePermissions(ctx, source) == nil
		return json.Marshal(clientadapter.RuntimeApplication{Supported: true, PermissionCurrent: current, ResourcesReady: err == nil && ready, Config: source})
	}}, nil
}

// NewAndroidRuntimeAuthorizationRequest gives the host real cancellation and
// join for its serialized permission call, without accepting identity itself.
func NewAndroidRuntimeAuthorizationRequest(beforeSource, afterSource, running string) (*AndroidDeviceRequest, error) {
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 5*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		result, err := clientadapter.ApplyRuntimeAuthorization(ctx, beforeSource, afterSource, running)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}}, nil
}
