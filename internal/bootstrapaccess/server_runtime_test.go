package bootstrapaccess

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestBootstrapIngressRuntimeOwnsCertifiedTrojanSocketLifecycle(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots, tlsConfig, certificate := trojanCertificate(t, "bootstrap.example")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	binding := testListenerBinding(t, "trojan_tls", ingressHash, "bootstrap.example",
		listener.Addr(), certificate)
	var listenCalls atomic.Int64
	runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
		Plan:    BootstrapIngressRuntimePlanV1{bindings: []VerifiedBootstrapListenerV1{binding}},
		Manager: manager, Registry: registry, TLSConfig: tlsConfig,
		Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
		ListenTCP: func(_ context.Context, network, address string) (net.Listener, error) {
			listenCalls.Add(1)
			wantNetwork, wantAddress, _ := runtimeBindAddress(binding)
			if network != wantNetwork || address != wantAddress {
				t.Errorf("runtime 请求 bind=%s/%s want=%s/%s", network, address, wantNetwork, wantAddress)
			}
			return listener, nil
		},
		ListenUDP: func(context.Context, string, string) (net.PacketConn, error) {
			return nil, errors.New("Trojan runtime 不应创建 UDP socket")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx) }()
	connection := tls.Client(mustDialTCP(t, listener.Addr().String()), &tls.Config{
		RootCAs: roots, ServerName: "bootstrap.example", MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := connection.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if listenCalls.Load() != 1 || len(manager.SnapshotUsage()) != 0 ||
		verified.TransportCredential() == "" {
		t.Fatalf("runtime lifecycle/listen/outer-probe accounting 异常 calls=%d usage=%#v",
			listenCalls.Load(), manager.SnapshotUsage())
	}
}

func TestBootstrapIngressRuntimeOwnsCertifiedHysteriaSocketLifecycle(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	_, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, tlsConfig, certificate := trojanCertificate(t, "bootstrap.example")
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	binding := testListenerBinding(t, "hysteria2", ingressHash, "bootstrap.example",
		packetConnection.LocalAddr(), certificate)
	listening := make(chan struct{})
	var listenCalls atomic.Int64
	runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
		Plan:    BootstrapIngressRuntimePlanV1{bindings: []VerifiedBootstrapListenerV1{binding}},
		Manager: manager, Registry: registry, TLSConfig: tlsConfig,
		Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
		ListenTCP: func(context.Context, string, string) (net.Listener, error) {
			return nil, errors.New("Hysteria2 runtime 不应创建 TCP socket")
		},
		ListenUDP: func(_ context.Context, network, address string) (net.PacketConn, error) {
			listenCalls.Add(1)
			wantNetwork, wantAddress, _ := runtimeBindAddress(binding)
			if network != wantNetwork || address != wantAddress {
				t.Errorf("runtime 请求 bind=%s/%s want=%s/%s", network, address, wantNetwork, wantAddress)
			}
			close(listening)
			return packetConnection, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx) }()
	select {
	case <-listening:
	case <-time.After(5 * time.Second):
		t.Fatal("Hysteria2 certified UDP socket 未启动")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Hysteria2 runtime 取消后未退出")
	}
	if listenCalls.Load() != 1 || len(manager.SnapshotUsage()) != 0 {
		t.Fatalf("runtime lifecycle/listen accounting 异常 calls=%d usage=%#v",
			listenCalls.Load(), manager.SnapshotUsage())
	}
}

func TestBootstrapIngressRuntimeClosesPartialBindOnFailure(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	_, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, tlsConfig, certificate := trojanCertificate(t, "bootstrap.example")
	firstListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondProbe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondAddress := secondProbe.Addr()
	_ = secondProbe.Close()
	first := testListenerBinding(t, "trojan_tls", ingressHash, "bootstrap.example",
		firstListener.Addr(), certificate)
	second := testListenerBinding(t, "trojan_tls", ingressHash, "bootstrap.example",
		secondAddress, certificate)
	second.projection.PublicPort = first.projection.PublicPort
	second.projection.PublicTuples[0].Port = first.projection.PublicPort
	second.bindingHash, err = wire.HashObject(domainBootstrapListenerRuntimeBinding, second.projection)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
		Plan:    BootstrapIngressRuntimePlanV1{bindings: []VerifiedBootstrapListenerV1{first, second}},
		Manager: manager, Registry: registry, TLSConfig: tlsConfig,
		Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
		ListenTCP: func(context.Context, string, string) (net.Listener, error) {
			if calls.Add(1) == 1 {
				return firstListener, nil
			}
			return nil, errors.New("injected bind failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Serve(context.Background()); err == nil {
		t.Fatal("partial bind failure 被忽略")
	}
	if _, err := firstListener.Accept(); err == nil {
		t.Fatal("后续 bind 失败后首个 listener 未关闭")
	}
}

func TestBootstrapIngressRuntimeStopsGenerationAfterListenerFailure(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	_, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, tlsConfig, certificate := trojanCertificate(t, "bootstrap.example")
	firstListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first := testListenerBinding(t, "trojan_tls", ingressHash, "bootstrap.example",
		firstListener.Addr(), certificate)
	second := testListenerBinding(t, "trojan_tls", ingressHash, "bootstrap.example",
		secondListener.Addr(), certificate)
	second.projection.PublicPort = first.projection.PublicPort
	second.projection.PublicTuples[0].Port = first.projection.PublicPort
	second.bindingHash, err = wire.HashObject(domainBootstrapListenerRuntimeBinding, second.projection)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
		Plan:    BootstrapIngressRuntimePlanV1{bindings: []VerifiedBootstrapListenerV1{first, second}},
		Manager: manager, Registry: registry, TLSConfig: tlsConfig,
		Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
		ListenTCP: func(context.Context, string, string) (net.Listener, error) {
			if calls.Add(1) == 1 {
				return immediateErrorListener{Listener: firstListener}, nil
			}
			return secondListener, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("listener accept failure 被误报为正常退出")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener failure 后 generation 未停止")
	}
	if _, err := secondListener.Accept(); err == nil {
		t.Fatal("同代另一 listener 未随故障关闭")
	}
}

type immediateErrorListener struct {
	net.Listener
}

func (listener immediateErrorListener) Accept() (net.Conn, error) {
	return nil, errors.New("injected accept failure")
}

func mustDialTCP(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}
