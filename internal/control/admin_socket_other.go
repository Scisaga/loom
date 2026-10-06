//go:build !linux

package control

import (
	"context"
	"net"
	"os"
)

// Preserve the existing non-Linux listener behavior; Linux recovery relies on
// kernel file locks and Unix ownership checks at the deployed control boundary.
func listenControlAdmin(_ context.Context, path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
