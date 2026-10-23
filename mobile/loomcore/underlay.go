package loomcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
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
type AndroidSocketProtector interface {
	ProtectSocket(fd int64) bool
	ResolveHost(host string) (string, error)
}

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
	return control.WithEndpointDialer(context.Background(), func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		androidUnderlay.RLock()
		protector := androidUnderlay.protector
		androidUnderlay.RUnlock()
		if net.ParseIP(host) != nil || protector == nil {
			return dialer.DialContext(ctx, network, address)
		}
		resolved, err := protector.ResolveHost(host)
		if err != nil || len(resolved) == 0 || len(resolved) > 4096 {
			return nil, errors.New("Android underlay DNS failed")
		}
		addresses := strings.Split(resolved, "\n")
		if len(addresses) > 64 {
			return nil, errors.New("Android underlay DNS exceeds limit")
		}
		for _, address := range addresses {
			if ip := net.ParseIP(address); ip == nil || ip.String() != address {
				return nil, errors.New("Android underlay DNS returned an invalid address")
			}
		}
		var failures []error
		for _, address := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address, port))
			if err == nil {
				return connection, nil
			}
			failures = append(failures, err)
		}
		return nil, errors.Join(failures...)
	})
}
