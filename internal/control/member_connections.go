package control

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// These resources have exactly the current member's runtime lifetime. Only the
// scheduling goroutine changes them; worker results are read after done closes.
type memberCall struct {
	member    Member
	ctx       context.Context
	stop      context.CancelFunc
	done      chan struct{}
	result    error
	http      memberHTTPAttempt
	direct    *memberDirectCheck
	trial     bool
	nextCheck time.Time
}

type memberDirectCheck struct {
	client *http.Client
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func (runtime *Runtime) memberNow() time.Time {
	if runtime.now != nil {
		return runtime.now()
	}
	return time.Now()
}

func ordinaryMemberTransport(client *http.Client) *memberHTTPTransport {
	return client.Transport.(*memberHTTPTransport)
}

func (runtime *Runtime) retainMemberClient(client *http.Client) {
	owned := ordinaryMemberTransport(client)
	owned.now = runtime.memberNow
	owned.transport.DisableKeepAlives = false
	owned.transport.IdleConnTimeout = 120 * time.Second
}

func (runtime *Runtime) currentMember(member Member) bool {
	config := runtime.Authority.Snapshot().Config
	if _, err := activeLocalMember(runtime.Config, config); err != nil {
		return false
	}
	for _, current := range config.Members {
		if current == member {
			return true
		}
	}
	return false
}

func (active *memberCall) discardDirect() {
	if active.direct != nil {
		active.direct.cancel()
		active.direct.client.CloseIdleConnections()
		active.direct = nil
	}
}

func (active *memberCall) finishAttempt(runtime *Runtime, eligible bool) {
	if active.trial {
		if eligible && active.ctx.Err() == nil && active.result == nil && runtime.currentMember(active.member) {
			active.http.client.CloseIdleConnections()
			active.http.client = active.direct.client
			ordinaryMemberTransport(active.http.client).preference.Store(int32(memberPreferDirect))
			proof := active.http.proof.Transport.(controlProofRoundTripper).transport.(*memberHTTPTransport)
			if proof.relayed.Load() {
				proof.CloseIdleConnections()
			}
			active.direct.cancel()
			active.direct = nil
		} else {
			active.discardDirect()
		}
		active.trial = false
		return
	}
	owned := ordinaryMemberTransport(active.http.client)
	if owned.networkFailure.Swap(false) && !owned.relayed.Load() {
		owned.preference.Store(int32(memberPreferRelay))
		owned.CloseIdleConnections()
	}
}

func (active *memberCall) checkDirect(runtime *Runtime, workers *sync.WaitGroup) {
	if active.ctx.Err() != nil || active.trial {
		return
	}
	if !runtime.currentMember(active.member) {
		if active.direct != nil {
			active.direct.cancel()
			select {
			case <-active.direct.done:
				active.discardDirect()
			default:
			}
		}
		return
	}
	owned := ordinaryMemberTransport(active.http.client)
	if active.direct != nil {
		select {
		case <-active.direct.done:
			if active.direct.err != nil || !owned.relayed.Load() || owned.connectedAt.Load() == nil {
				active.discardDirect()
			}
		default:
		}
		return
	}
	connected := owned.connectedAt.Load()
	now := runtime.memberNow()
	if !owned.relayed.Load() || connected == nil || now.Before(connected.Add(time.Minute)) || now.Before(active.nextCheck) || len(runtime.Channel.endpoints(active.member.NodeID)) == 0 {
		return
	}
	active.nextCheck = now.Add(time.Minute)
	client, err := runtime.Channel.memberClient(active.member.NodeID, false, memberDirectOnly)
	if err != nil {
		return
	}
	runtime.retainMemberClient(client)
	ctx, cancel := context.WithTimeout(active.ctx, 15*time.Second)
	check := &memberDirectCheck{client: client, cancel: cancel, done: make(chan struct{})}
	active.direct = check
	scope := active.http
	scope.client = client
	ctx = context.WithValue(ctx, memberHTTPAttemptKey{}, scope)
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(check.done)
		defer cancel()
		frontier, confirmed, _, err := runtime.peerFrontier(ctx, active.member)
		if err == nil && (!confirmed || frontier == nil) {
			err = errors.New("direct member frontier did not confirm current authority")
		}
		if err == nil {
			err = validateRemoteFrontier(frontier)
		}
		check.err = err
	}()
}

func (active *memberCall) attemptScope() memberHTTPAttempt {
	scope := active.http
	if active.direct != nil {
		select {
		case <-active.direct.done:
			if active.direct.err == nil {
				active.trial = true
				scope.client = active.direct.client
			}
		default:
		}
	}
	return scope
}

func (active *memberCall) close() {
	active.stop()
	active.http.close()
	active.discardDirect()
}
