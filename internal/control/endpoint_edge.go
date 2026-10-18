package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type EndpointEdgeRuntime struct {
	listener net.Listener
	target   string
	website  string
	member   string
	done     chan struct{}
	once     sync.Once
	context  context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	workers  sync.WaitGroup
	closeErr error
}

// OpenEndpointEdge consumes explicit operator-owned TCP coordinates and only
// copies opaque bytes. TLS and every authorization decision remain at control.
func OpenEndpointEdge(listen, target string) (*EndpointEdgeRuntime, error) {
	return OpenSharedEndpointEdge(listen, target, "", "")
}

// OpenSharedEndpointEdge optionally shares an existing public website mapping.
// It reads a bounded ClientHello only to choose an opaque TCP destination. The
// original bytes, TLS handshake and all authorization stay at the destination.
func OpenSharedEndpointEdge(listen, target, website, member string) (*EndpointEdgeRuntime, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || port == "" || !privateAddress(target) ||
		website != "" && !privateAddress(website) || member != "" && (website == "" || !privateAddress(member)) {
		return nil, errors.New("endpoint edge requires an IP listener and private target")
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &EndpointEdgeRuntime{listener: listener, target: target, website: website, member: member, done: make(chan struct{}), context: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	go runtime.accept()
	return runtime, nil
}

func (runtime *EndpointEdgeRuntime) accept() {
	defer close(runtime.done)
	for {
		incoming, err := runtime.listener.Accept()
		if err != nil {
			return
		}
		runtime.mu.Lock()
		if runtime.closed {
			runtime.mu.Unlock()
			_ = incoming.Close()
			return
		}
		runtime.conns[incoming] = struct{}{}
		runtime.workers.Add(1)
		runtime.mu.Unlock()
		go runtime.forward(incoming)
	}
}

func (runtime *EndpointEdgeRuntime) forward(incoming net.Conn) {
	defer runtime.workers.Done()
	defer runtime.release(incoming)
	destination := runtime.target
	var prefix []byte
	if runtime.website != "" {
		_ = incoming.SetReadDeadline(time.Now().Add(5 * time.Second))
		protocols, original, err := readEdgeClientHello(incoming)
		if err != nil {
			return
		}
		prefix = original
		var device, member bool
		for _, protocol := range protocols {
			device = device || protocol == tunnelALPN
			member = member || protocol == controlALPN || protocol == controlRelayALPN
		}
		if device && member {
			return
		}
		switch {
		case device:
			destination = runtime.target
		case member:
			if runtime.member == "" {
				return
			}
			destination = runtime.member
		default:
			destination = runtime.website
		}
		_ = incoming.SetReadDeadline(time.Time{})
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err := dialer.DialContext(runtime.context, "tcp", destination)
	if err != nil {
		return
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		_ = target.Close()
		return
	}
	runtime.conns[target] = struct{}{}
	runtime.mu.Unlock()
	defer runtime.release(target)
	_ = incoming.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	finished := make(chan struct{})
	go func() {
		_, _ = io.Copy(target, io.MultiReader(bytes.NewReader(prefix), incoming))
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(finished)
	}()
	_, _ = io.Copy(incoming, target)
	_ = target.Close()
	_ = incoming.Close()
	<-finished
}

func (runtime *EndpointEdgeRuntime) release(connection net.Conn) {
	_ = connection.Close()
	runtime.mu.Lock()
	delete(runtime.conns, connection)
	runtime.mu.Unlock()
}

func (runtime *EndpointEdgeRuntime) Close() error {
	runtime.once.Do(func() {
		runtime.mu.Lock()
		runtime.closed = true
		connections := make([]net.Conn, 0, len(runtime.conns))
		for connection := range runtime.conns {
			connections = append(connections, connection)
		}
		runtime.mu.Unlock()
		runtime.cancel()
		if err := runtime.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			runtime.closeErr = errors.Join(runtime.closeErr, err)
		}
		for _, connection := range connections {
			if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				runtime.closeErr = errors.Join(runtime.closeErr, err)
			}
		}
		<-runtime.done
		runtime.workers.Wait()
	})
	return runtime.closeErr
}
