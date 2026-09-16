//go:build !linux

package main

import (
	"errors"
	"time"
)

func openBootstrapRuntimeDeviceAccess(_, _, _, _ string, _ func() time.Time,
	_ time.Duration) (bootstrapRuntimeDeviceAccess, error) {
	return nil, errors.New("bootstrap ingress 仅在原生 Linux server 上运行")
}
