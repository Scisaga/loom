package bootstrapaccess

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type TCPListenFunc func(context.Context, string, string) (net.Listener, error)
type UDPListenFunc func(context.Context, string, string) (net.PacketConn, error)

type BootstrapIngressRuntimeOptions struct {
	Plan                         BootstrapIngressRuntimePlanV1
	Manager                      *Manager
	Registry                     *CredentialRegistry
	TLSConfig                    *tls.Config
	Dial                         DialContext
	HandshakeTimeout             time.Duration
	IdleTimeout                  time.Duration
	MaximumConcurrentConnections int
	MaximumStreamsPerConnection  int64
	ListenTCP                    TCPListenFunc
	ListenUDP                    UDPListenFunc
}

type bootstrapRuntimeServer struct {
	binding  VerifiedBootstrapListenerV1
	trojan   *TrojanTLSServer
	hysteria *Hysteria2Server
}

// BootstrapIngressRuntime 同时拥有 certified socket 的创建与 transport server
// 生命周期。调用方只能提供 I/O 实现，network/address 始终从 opaque plan 推导。
type BootstrapIngressRuntime struct {
	mu        sync.Mutex
	running   bool
	ready     bool
	servers   []bootstrapRuntimeServer
	listenTCP TCPListenFunc
	listenUDP UDPListenFunc
}

func NewBootstrapIngressRuntime(options BootstrapIngressRuntimeOptions) (*BootstrapIngressRuntime, error) {
	bindings := options.Plan.Bindings()
	if len(bindings) == 0 || options.Manager == nil || options.Registry == nil ||
		options.TLSConfig == nil || options.Dial == nil {
		return nil, errors.New("[D127 bootstrap runtime] plan/manager/registry/TLS/dial 缺失")
	}
	first := bindings[0].projection
	seen := make(map[string]struct{}, len(bindings))
	servers := make([]bootstrapRuntimeServer, 0, len(bindings))
	for _, binding := range bindings {
		projection := binding.projection
		if !binding.valid() || projection.ClusterID != first.ClusterID ||
			projection.IngressSetHash != first.IngressSetHash || projection.EndpointSetID != first.EndpointSetID ||
			projection.EndpointID != first.EndpointID || projection.LogicalServerID != first.LogicalServerID ||
			projection.Transport != first.Transport || projection.ListenerGeneration != first.ListenerGeneration ||
			projection.ListenerState != first.ListenerState || projection.ServerName != first.ServerName ||
			projection.PublicPort != first.PublicPort || projection.ValidFrom != first.ValidFrom ||
			projection.ValidUntil != first.ValidUntil || options.Registry.IngressSetHash() != projection.IngressSetHash {
			return nil, errors.New("[D127 bootstrap runtime] listener bindings 不属于同一 certified generation")
		}
		key := projection.BindTuple.Transport + "\x00" + projection.BindTuple.Address + "\x00" +
			strconv.FormatInt(projection.BindTuple.Port, 10)
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("[D127 bootstrap runtime] listener binding tuple 重复")
		}
		seen[key] = struct{}{}
		server := bootstrapRuntimeServer{binding: binding}
		var err error
		switch projection.Transport {
		case "trojan_tls":
			server.trojan, err = NewTrojanTLSServer(options.Manager, options.Registry,
				TrojanTLSServerOptions{Listener: binding, TLSConfig: options.TLSConfig,
					HandshakeTimeout:             options.HandshakeTimeout,
					MaximumConcurrentConnections: options.MaximumConcurrentConnections, Dial: options.Dial})
		case "hysteria2":
			server.hysteria, err = NewHysteria2Server(options.Manager, options.Registry,
				Hysteria2ServerOptions{Listener: binding, TLSConfig: options.TLSConfig,
					HandshakeTimeout: options.HandshakeTimeout, IdleTimeout: options.IdleTimeout,
					MaximumConcurrentConnections: options.MaximumConcurrentConnections,
					MaximumStreamsPerConnection:  options.MaximumStreamsPerConnection, Dial: options.Dial})
		default:
			err = errors.New("[D127 bootstrap runtime] transport 未获授权")
		}
		if err != nil {
			return nil, err
		}
		servers = append(servers, server)
	}
	listenTCP := options.ListenTCP
	if listenTCP == nil {
		listenConfig := &net.ListenConfig{}
		listenTCP = listenConfig.Listen
	}
	listenUDP := options.ListenUDP
	if listenUDP == nil {
		listenConfig := &net.ListenConfig{}
		listenUDP = listenConfig.ListenPacket
	}
	return &BootstrapIngressRuntime{servers: servers, listenTCP: listenTCP, listenUDP: listenUDP}, nil
}

// Serve 先把同一 generation 的全部 socket 建完再启动；任一 bind 失败会关闭已建
// socket，避免双栈/NAT 多 tuple 只启动一半却被当成已安装（D103、D127）。
func (runtime *BootstrapIngressRuntime) Serve(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return errors.New("[D127 bootstrap runtime] runtime/context 缺失")
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	done, err := runtime.Start(ctx)
	if err != nil {
		return err
	}
	return <-done
}

// Start 同步完成同代全部 bind 并启动 transport goroutine 后才返回。调用方因此
// 可以在不猜测 sleep/readiness 的情况下执行 local verify；ctx 取消负责关闭整批（D120、D127）。
func (runtime *BootstrapIngressRuntime) Start(ctx context.Context) (<-chan error, error) {
	if runtime == nil || ctx == nil {
		return nil, errors.New("[D127 bootstrap runtime] runtime/context 缺失")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	if runtime.running {
		runtime.mu.Unlock()
		return nil, errors.New("[D127 bootstrap runtime] runtime 已在运行")
	}
	runtime.running = true
	runtime.ready = false
	runtime.mu.Unlock()
	resetRunning := func() {
		runtime.mu.Lock()
		runtime.running = false
		runtime.ready = false
		runtime.mu.Unlock()
	}

	instances := make([]bootstrapRuntimeInstance, 0, len(runtime.servers))
	closeInstances := func() {
		for _, instance := range instances {
			_ = instance.close()
		}
	}
	for _, server := range runtime.servers {
		network, address, err := runtimeBindAddress(server.binding)
		if err != nil {
			closeInstances()
			resetRunning()
			return nil, err
		}
		if server.trojan != nil {
			listener, err := runtime.listenTCP(ctx, network, address)
			if err != nil {
				closeInstances()
				resetRunning()
				return nil, fmt.Errorf("[D127 bootstrap runtime] certified TCP tuple bind 失败: %w", err)
			}
			if !server.binding.matchesLocalAddr(listener.Addr(), "trojan_tls") {
				_ = listener.Close()
				closeInstances()
				resetRunning()
				return nil, errors.New("[D127 bootstrap runtime] TCP listener 未绑定 requested certified tuple")
			}
			trojanServer := server.trojan
			tcpListener := listener
			instances = append(instances, bootstrapRuntimeInstance{
				serve: func(ctx context.Context) error { return trojanServer.Serve(ctx, tcpListener) },
				close: listener.Close,
			})
			continue
		}
		packetConnection, err := runtime.listenUDP(ctx, network, address)
		if err != nil {
			closeInstances()
			resetRunning()
			return nil, fmt.Errorf("[D127 bootstrap runtime] certified UDP tuple bind 失败: %w", err)
		}
		if !server.binding.matchesLocalAddr(packetConnection.LocalAddr(), "hysteria2") {
			_ = packetConnection.Close()
			closeInstances()
			resetRunning()
			return nil, errors.New("[D127 bootstrap runtime] UDP listener 未绑定 requested certified tuple")
		}
		hysteriaServer := server.hysteria
		udpConnection := packetConnection
		instances = append(instances, bootstrapRuntimeInstance{
			serve: func(ctx context.Context) error { return hysteriaServer.Serve(ctx, udpConnection) },
			close: packetConnection.Close,
		})
	}
	runContext, cancel := context.WithCancel(ctx)
	results := make(chan error, len(instances))
	for _, instance := range instances {
		instance := instance
		go func() { results <- instance.serve(runContext) }()
	}
	runtime.mu.Lock()
	runtime.ready = true
	runtime.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		defer resetRunning()
		defer closeInstances()
		defer cancel()
		var firstError error
		for range instances {
			err := <-results
			if err != nil && firstError == nil {
				firstError = err
				cancel()
				closeInstances()
			} else if err == nil && runContext.Err() == nil && firstError == nil {
				firstError = errors.New("[D127 bootstrap runtime] listener 未经取消提前退出")
				cancel()
				closeInstances()
			}
		}
		if ctx.Err() != nil {
			firstError = nil
		}
		done <- firstError
		close(done)
	}()
	return done, nil
}

func (runtime *BootstrapIngressRuntime) runningPlan() (BootstrapIngressRuntimePlanV1, error) {
	if runtime == nil {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[D120 local verify] runtime 缺失")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.running || !runtime.ready {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[D120 local verify] listener generation 尚未完成全批启动")
	}
	bindings := make([]VerifiedBootstrapListenerV1, 0, len(runtime.servers))
	for _, server := range runtime.servers {
		bindings = append(bindings, server.binding)
	}
	return BootstrapIngressRuntimePlanV1{bindings: bindings}, nil
}

type bootstrapRuntimeInstance struct {
	serve func(context.Context) error
	close func() error
}

func runtimeBindAddress(binding VerifiedBootstrapListenerV1) (string, string, error) {
	if !binding.valid() {
		return "", "", errors.New("[D127 bootstrap runtime] listener binding 无效")
	}
	tuple := binding.Tuple()
	address, err := netip.ParseAddr(tuple.Address)
	if err != nil {
		return "", "", errors.New("[D127 bootstrap runtime] bind address 无效")
	}
	network := tuple.Transport + "6"
	if address.Is4() {
		network = tuple.Transport + "4"
	}
	return network, net.JoinHostPort(address.String(), strconv.FormatInt(tuple.Port, 10)), nil
}
