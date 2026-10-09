package loomcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"syscall"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func androidConnectedIPv4Prefixes(body []byte, resources ...control.TransportResource) (*[]string, error) {
	var addresses []string
	if len(body) > 1<<20 || json.Unmarshal(body, &addresses) != nil {
		return nil, errors.New("Android interface readback is invalid")
	}
	return clientadapter.InterfaceIPv4Prefixes(addresses, resources...)
}

// AndroidSocketProtector is the platform VpnService boundary, not identity or
// saved runtime state. It is installed before capture and removed after close.
type AndroidSocketProtector interface{ ProtectSocket(fd int64) bool }

var androidUnderlay struct {
	sync.RWMutex
	protector AndroidSocketProtector
}

func SetAndroidSocketProtector(protector AndroidSocketProtector) {
	androidUnderlay.Lock()
	defer androidUnderlay.Unlock()
	androidUnderlay.protector = protector
}

func androidNetworkContext() context.Context {
	dialer := &net.Dialer{Control: func(_, _ string, connection syscall.RawConn) error {
		var protectErr error
		err := connection.Control(func(fd uintptr) {
			androidUnderlay.RLock()
			defer androidUnderlay.RUnlock()
			if androidUnderlay.protector != nil && !androidUnderlay.protector.ProtectSocket(int64(fd)) {
				protectErr = errors.New("Android private underlay socket protection failed")
			}
		})
		return errors.Join(err, protectErr)
	}}
	return control.WithEndpointDialer(context.Background(), dialer.DialContext)
}
