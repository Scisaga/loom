package control

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"loom/internal/netx"
)

func (channel *PrivateChannel) dialPrivateTCP(ctx context.Context, address string) (net.Conn, error) {
	if channel.underlayDial != nil {
		return channel.underlayDial(ctx, "tcp", address)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

// DNS answers belong only to this connection attempt. The local authority's
// current device authorization supplies resolvers independently of a client.
// connect includes TLS when used for a member, so a reachable wrong identity
// cannot prevent another resolved address from authenticating.
func (channel *PrivateChannel) dialPrivateEndpoint(ctx context.Context, endpoint string, connect func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	if !parsePrivateChannelAddress(endpoint, false) {
		return nil, errors.New("private dial coordinate is invalid")
	}
	channel.transportM.Lock()
	select {
	case <-channel.done:
		channel.transportM.Unlock()
		return nil, net.ErrClosed
	default:
		channel.workers.Add(1)
	}
	channel.transportM.Unlock()
	defer channel.workers.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-channel.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	host, port, _ := net.SplitHostPort(endpoint)
	if _, err := netip.ParseAddr(host); err == nil {
		return connect(ctx, endpoint)
	}
	channel.authorityM.RLock()
	authority := channel.authority
	channel.authorityM.RUnlock()
	if authority == nil {
		return nil, errors.New("private hostname requires current local DNS authorization")
	}
	var servers []string
	matches := 0
	for _, authorization := range authority.Snapshot().DeviceAuthorizations {
		if authorization.ID == channel.config.Node {
			matches++
			servers = append([]string(nil), authorization.DNSServers...)
		}
	}
	if matches != 1 || len(servers) == 0 {
		return nil, errors.New("private hostname requires unambiguous local DNS authorization")
	}
	addresses, err := netx.ResolveCertifiedIPs(ctx, host, servers, channel.underlayDial)
	if err != nil {
		return nil, err
	}
	var candidates []string
	for _, ip := range addresses {
		address := net.JoinHostPort(ip.String(), port)
		if parsePrivateChannelAddress(address, false) {
			candidates = append(candidates, address)
		}
	}
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, 2)
	next, active := 0, 0
	start := func() {
		address := candidates[next]
		next++
		active++
		go func() {
			connection, err := connect(ctx, address)
			results <- result{connection, err}
		}()
	}
	for active < 2 && next < len(candidates) && ctx.Err() == nil {
		start()
	}
	var winner net.Conn
	var failures []error
	for active > 0 {
		result := <-results
		active--
		if result.err == nil && result.connection != nil && winner == nil && ctx.Err() == nil {
			winner = result.connection
			cancel()
		} else {
			if result.connection != nil {
				_ = result.connection.Close()
			}
			if result.err != nil {
				failures = append(failures, result.err)
			}
		}
		if winner == nil && next < len(candidates) && ctx.Err() == nil {
			start()
		}
	}
	if winner != nil {
		return winner, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(failures) == 0 {
		return nil, errors.New("private hostname has no usable dial address")
	}
	return nil, errors.Join(failures...)
}
