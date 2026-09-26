package linuxclient

import (
	"errors"
	"fmt"
	"os"
)

const initialNetworkNamespaceError = "Linux access runtime refuses auto-route TUN in the initial network namespace; configure a dedicated network namespace before activation"

func requireDifferentNetworkNamespace(currentPath, initialPath string) error {
	current, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("read current network namespace: %w", err)
	}
	initial, err := os.Stat(initialPath)
	if err != nil {
		return fmt.Errorf("read initial network namespace: %w", err)
	}
	if os.SameFile(current, initial) {
		return errors.New(initialNetworkNamespaceError)
	}
	return nil
}

func requireIsolatedNetworkNamespace() error {
	return requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net")
}
