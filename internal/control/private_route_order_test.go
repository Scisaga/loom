package control

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemberRelayPoolReturnsToRecoveredDirectWithoutRotatingDirect(t *testing.T) {
	f := threeSchedulingMembers(t)
	peers := membershipTLSPeers(t, f)
	runtime, channel := peers[0].server.Runtime, peers[0].channel
	direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
	var available atomic.Bool
	var directDials, relayDials atomic.Int32
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == direct {
			directDials.Add(1)
			if !available.Load() {
				return nil, errors.New("demo temporary direct failure")
			}
		}
		if address == relay {
			relayDials.Add(1)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	clients, err := runtime.memberClients(f.members[1])
	if err != nil {
		t.Fatal(err)
	}
	defer clients.close()
	owned := clients.client.Transport.(*memberHTTPTransport)
	start := time.Now()
	var offset atomic.Int64
	owned.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, memberHTTPAttemptKey{}, clients)
	read := func() ([]byte, net.Conn) {
		t.Helper()
		var got net.Conn
		traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { got = info.Conn }})
		body, err := runtime.peerBody(traced, f.members[1], http.MethodGet, "/internal/frontier", nil)
		if err != nil || got == nil {
			t.Fatal("authenticated frontier read failed", err)
		}
		return body, got
	}
	body, first := read()
	if directDials.Load() != 1 || relayDials.Load() != 1 || owned.relayUntil.Load() == nil {
		t.Fatal("temporary outage did not retain its authenticated relay")
	}
	offset.Store(int64(30 * time.Second))
	again, second := read()
	if second != first || directDials.Load() != 1 || !bytes.Equal(body, again) {
		t.Fatal("relay was rebuilt before its bounded recheck")
	}
	offset.Store(int64(61 * time.Second))
	_, renewed := read()
	if renewed == first || directDials.Load() != 2 || relayDials.Load() != 2 || owned.relayUntil.Load() == nil {
		t.Fatal("unavailable direct member did not renew a bounded relay")
	}
	available.Store(true)
	offset.Store(int64(90 * time.Second))
	_, reused := read()
	if reused != renewed || directDials.Load() != 2 || relayDials.Load() != 2 {
		t.Fatal("renewed relay was rebuilt on every request")
	}
	offset.Store(int64(122 * time.Second))
	again, third := read()
	if third == renewed || directDials.Load() != 3 || relayDials.Load() != 2 || owned.relayUntil.Load() != nil || !bytes.Equal(body, again) {
		t.Fatal("recovered direct member remained behind its old relay")
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	_, err = first.Read(make([]byte, 1))
	var networkErr net.Error
	if err == nil || errors.As(err, &networkErr) && networkErr.Timeout() {
		t.Fatal("expired idle relay connection remained open", err)
	}
	offset.Store(int64(3 * time.Minute))
	_, fourth := read()
	if fourth != third || directDials.Load() != 3 || relayDials.Load() != 2 {
		t.Fatal("healthy direct connection was needlessly rotated")
	}
}

func TestMemberRouteAvoidsRelayWhenDirectAuthenticates(t *testing.T) {
	f := threeSchedulingMembers(t)
	peers := membershipTLSPeers(t, f)
	channel := peers[0].channel
	direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
	var relayDials atomic.Int32
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == relay {
			relayDials.Add(1)
		}
		if address == direct {
			select {
			case <-time.After(40 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	accepted := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-direct-service", "demo-direct-request"))
	if err := peers[0].server.Runtime.reconcilePeerAttempt(context.Background(), f.members[1]); err != nil {
		t.Fatal("available direct member did not converge", err)
	}
	if _, err := peers[0].server.Runtime.Authority.Material(accepted.MaterialID); err != nil {
		t.Fatal("direct transfer lost its original", err)
	}
	if relayDials.Load() != 0 {
		t.Fatal("healthy direct member still opened an unnecessary relay", relayDials.Load())
	}
}

func TestMemberRouteRelayRemainsIndependentOfDirectFailure(t *testing.T) {
	for _, failure := range []string{"immediate", "wrong-identity", "slow", "absent", "cancel", "close"} {
		t.Run(failure, func(t *testing.T) {
			f := threeSchedulingMembers(t)
			peers := membershipTLSPeers(t, f)
			channel := peers[0].channel
			direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
			if failure == "absent" {
				channel.config.Peers = []PrivatePeer{{Node: f.members[2].NodeID, Addresses: []string{relay}}}
			}
			var relayDials atomic.Int32
			directStopped := make(chan struct{}, 1)
			ownerClosed := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == relay {
					relayDials.Add(1)
				}
				if address == direct {
					switch failure {
					case "immediate":
						return nil, errors.New("demo direct unavailable")
					case "wrong-identity":
						address = peers[0].channel.ListenAddresses()[0]
					case "slow", "cancel", "close":
						if failure == "cancel" {
							cancel()
						}
						if failure == "close" {
							go func() { channel.Close(); close(ownerClosed) }()
						}
						<-ctx.Done()
						directStopped <- struct{}{}
						return nil, ctx.Err()
					}
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			start := time.Now()
			connection, err := channel.dialMemberTLS(ctx, f.members[1].NodeID, controlALPN, controlRelayALPN, time.Second)
			if connection != nil {
				connection.Close()
			}
			if failure == "cancel" {
				if !errors.Is(err, context.Canceled) || relayDials.Load() != 0 {
					t.Fatal("cancellation started a delayed relay or lost its cause", err, relayDials.Load())
				}
			} else if failure == "close" {
				if !errors.Is(err, net.ErrClosed) || relayDials.Load() != 0 {
					t.Fatal("owner closure started a delayed relay or lost its cause", err, relayDials.Load())
				}
			} else if err != nil || relayDials.Load() != 1 || time.Since(start) > time.Second {
				t.Fatal("direct failure blocked the independent authenticated relay", err, relayDials.Load(), time.Since(start))
			}
			if failure == "slow" || failure == "cancel" || failure == "close" {
				select {
				case <-directStopped:
				case <-time.After(time.Second):
					t.Fatal("losing direct attempt outlived the call")
				}
			}
			if failure == "close" {
				select {
				case <-ownerClosed:
				case <-time.After(time.Second):
					t.Fatal("member transport owner did not finish closing")
				}
			}
		})
	}
}
