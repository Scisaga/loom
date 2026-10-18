package deviceclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"time"

	"loom/internal/control"
)

const deviceRequestTimeout = 5 * time.Second

// A candidate wins only after the caller has validated its complete response.
// Candidate work never commits the LKG or reserves another report sequence.
func requestDevice[T any](ctx context.Context, store IdentityStore, lkg *control.DeviceViewEnvelope, parallel int, timeout time.Duration,
	request func(context.Context, net.Conn) (T, error)) (T, error) {
	var zero T
	if lkg == nil {
		return zero, errors.New("device has no accepted LKG")
	}
	endpoints := servingDeviceEndpoints(lkg)
	if len(endpoints) == 0 {
		return zero, errors.New("device LKG has no serving endpoint")
	}
	return requestDeviceEndpoints(withCertifiedDNS(ctx, lkg.View.DNSServers), endpoints, lkg.View.DeviceID, store.PrivateKey(), parallel, timeout, control.DialEndpoint, request)
}

func servingDeviceEndpoints(lkg *control.DeviceViewEnvelope) []control.EndpointGeneration {
	endpoints := []control.EndpointGeneration{}
	for _, endpoint := range endpointOrder(lkg.View.Endpoints) {
		if endpoint.State == "serving" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

func requestDeviceEndpoints[T any](ctx context.Context, endpoints []control.EndpointGeneration, deviceID string, private ed25519.PrivateKey, parallel int, timeout time.Duration,
	dial func(context.Context, control.EndpointGeneration, control.TunnelHello, ed25519.PrivateKey) (net.Conn, error),
	request func(context.Context, net.Conn) (T, error)) (T, error) {
	return tryDeviceEndpoints(ctx, endpoints, parallel, timeout, func(attempt context.Context, endpoint control.EndpointGeneration) (T, error) {
		var zero T
		hello := control.TunnelHello{Schema: 3, Mode: "device", EndpointID: endpoint.ID, Generation: endpoint.Generation, DeviceID: deviceID}
		authentication, authenticated := context.WithTimeout(attempt, deviceRequestTimeout)
		connection, err := dial(authentication, endpoint, hello, private)
		authenticationErr := authentication.Err()
		authenticated()
		if err == nil {
			err = authenticationErr
		}
		if connection != nil {
			defer connection.Close()
		}
		if err != nil {
			return zero, err
		}
		if connection == nil {
			return zero, errors.New("private endpoint returned no connection")
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(attempt, func() {
			_ = connection.Close()
			close(closed)
		})
		defer func() {
			if !stop() {
				<-closed
			}
		}()
		if err := attempt.Err(); err != nil {
			return zero, err
		}
		return request(attempt, connection)
	})
}

func tryDeviceEndpoints[T any](ctx context.Context, endpoints []control.EndpointGeneration, parallel int, timeout time.Duration,
	request func(context.Context, control.EndpointGeneration) (T, error)) (T, error) {
	var zero T
	if len(endpoints) == 0 || parallel < 1 || parallel > 2 || timeout < 0 {
		return zero, errors.New("invalid private request bounds")
	}
	type result struct {
		index int
		value T
		err   error
	}
	activeContext, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	results := make(chan result, parallel)
	started, active := 0, 0
	failures := make([]error, len(endpoints))
	start := func(index int) {
		started++
		active++
		workers.Add(1)
		go func() {
			defer workers.Done()
			attempt, finish := context.WithCancel(activeContext)
			if timeout > 0 {
				finish()
				attempt, finish = context.WithTimeout(activeContext, timeout)
			}
			defer finish()
			value, err := request(attempt, endpoints[index])
			if err == nil {
				err = attempt.Err()
			}
			results <- result{index, value, err}
		}()
	}
	// Receiving every started result also waits for its connection cleanup.
	drain := func() {
		cancel()
		for active > 0 {
			<-results
			active--
		}
		workers.Wait()
	}
	for started < len(endpoints) && active < parallel && ctx.Err() == nil {
		start(started)
	}
	for active > 0 {
		select {
		case <-ctx.Done():
			drain()
			return zero, ctx.Err()
		case value := <-results:
			active--
			if value.err == nil {
				drain()
				if err := ctx.Err(); err != nil {
					return zero, err
				}
				return value.value, nil
			}
			failures[value.index] = value.err
			if started < len(endpoints) && ctx.Err() == nil {
				start(started)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return zero, errors.Join(failures...)
}
