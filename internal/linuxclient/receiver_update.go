package linuxclient

import (
	"context"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

// rebuildReceivingConfigs only renders from the newly accepted View. Existing
// management interfaces, endpoint DNS answers, secrets and capture ownership
// are inputs; this function never creates or mutates any host network object.
func rebuildReceivingConfigs(view control.DeviceView, options Options, secret string, exclusions []string, executions []resourceExecution, website clientadapter.WebsiteAccess, connected *[]string, localNetworks []control.LocalNetworkPrefix, wg wireGuardExecution, transaction *wireGuardTransaction) (string, string, error) {
	config, server, err := generationConfigs(view, secret, exclusions, options.Capture, executions, website)
	if err != nil {
		return "", "", err
	}
	config, err = clientadapter.WithLocalNetworkBoundary(config, connected, localNetworks...)
	if err != nil {
		return "", "", err
	}
	if server != "" {
		server, err = clientadapter.WithLocalNetworkBoundary(server, connected, localNetworks...)
		if err == nil {
			server, err = appendNativeWireGuard(server, view, wg, transaction, options.WireGuardPrivateKey)
		}
	} else {
		config, err = appendNativeWireGuard(config, view, wg, transaction, options.WireGuardPrivateKey)
	}
	if err != nil {
		return "", "", err
	}
	config, err = withPersistentDNSCache(config, options.DeviceState)
	if err == nil && server != "" {
		server, err = withPersistentDNSCache(server, options.DeviceState)
	}
	return config, server, err
}

func applyReceivingConfigs(ctx context.Context, options Options, before, after, beforeServer, afterServer string) (clientadapter.RuntimeApplication, error) {
	result := clientadapter.RuntimeApplication{Supported: true, PermissionCurrent: true, ResourcesReady: true, Config: after}
	type resourceTarget struct {
		selector *clientadapter.HTTPSelector
		source   string
	}
	targets := []resourceTarget{}
	apply := func(previous, next string, isolated bool) (clientadapter.RuntimeApplication, error) {
		if previous == "" || next == "" {
			return clientadapter.RuntimeApplication{Supported: previous == next, PermissionCurrent: previous == next, ResourcesReady: previous == next, Config: next}, nil
		}
		selector, err := clientadapter.NewHTTPSelector(previous)
		if err != nil {
			return clientadapter.RuntimeApplication{}, err
		}
		if isolated && options.captureNamespace != nil {
			selector.SetDialer(namespaceDialer(options.captureNamespace))
		}
		applied, err := selector.ApplyRuntimeAuthorization(ctx, previous, next, previous)
		if err != nil || !applied.Supported || !applied.PermissionCurrent {
			return applied, err
		}
		targets = append(targets, resourceTarget{selector: selector, source: next})
		return applied, nil
	}
	// Host and capture share one accepted View. Failure never reinstalls old grants.
	for _, pair := range []struct {
		before, after string
		isolated      bool
	}{{beforeServer, afterServer, false}, {before, after, true}} {
		applied, err := apply(pair.before, pair.after, pair.isolated)
		result.Supported = result.Supported && applied.Supported
		result.PermissionCurrent = result.PermissionCurrent && applied.PermissionCurrent
		result.ResourcesReady = result.ResourcesReady && applied.ResourcesReady
		if err != nil || !applied.Supported || !applied.PermissionCurrent {
			result.PermissionCurrent = false
			return result, err
		}
	}
	// Both existing processes now enforce the accepted permission. Resource
	// preparation cannot block the other process's revocation or restore it.
	result.ResourcesReady = true
	for _, target := range targets {
		ready, resourceErr := target.selector.ReconcileRuntimeResources(ctx, target.source)
		result.ResourcesReady = result.ResourcesReady && ready && resourceErr == nil
		if ctx.Err() != nil {
			result.ResourcesReady = false
			break
		}
	}
	if beforeServer != afterServer && afterServer != "" {
		if err := writeNativeResourceConfig(options.Config+".server", afterServer); err != nil {
			return result, err
		}
	}
	if before != after {
		if err := writeNativeResourceConfig(options.Config, after); err != nil {
			return result, err
		}
	}
	return result, nil
}
