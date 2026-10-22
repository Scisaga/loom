package control

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

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
