//go:build linux

package main

import (
	"time"

	"loom/internal/clientv2"
)

func openBootstrapRuntimeDeviceAccess(statePath, identityPath, deviceID,
	ingressSetHash string, now func() time.Time,
	timeout time.Duration) (bootstrapRuntimeDeviceAccess, error) {
	return clientv2.OpenLinuxBootstrapIngressAccess(statePath, identityPath, deviceID,
		ingressSetHash, now, timeout)
}
