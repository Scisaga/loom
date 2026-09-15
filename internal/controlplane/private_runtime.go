package controlplane

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"loom/internal/enrollmenttransport"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// PrivateRuntimeOptions 由 certified application state 投影。每个 listener 使用
// 独立 server key/profile；业务 reader 在每次请求重验当前 Head，而不是信任启动快照（D131）。
type PrivateRuntimeOptions struct {
	Services       []wire.PrivateControlServiceV1
	Certificates   map[string]tls.Certificate
	Enrollment     *enrollmentv2.PrivateService
	AuthorizeRelay enrollmenttransport.Authorizer
	Identities     DeviceIdentityReader
	VerifyReport   DeviceReportPayloadVerifier
	CommitReport   DeviceReportCommitter
	Observations   DeviceReportObservationReader
	ReportSchemas  wire.DeviceReportSchemaRegistry
	Now            func() time.Time
	Listen         func(context.Context, string, string) (net.Listener, error)
}

type privateRuntimeServer struct {
	service     wire.PrivateControlServiceV1
	certificate tls.Certificate
	handler     http.Handler
}

type PrivateRuntime struct {
	mu        sync.Mutex
	running   bool
	servers   []privateRuntimeServer
	authorize enrollmenttransport.Authorizer
	listen    func(context.Context, string, string) (net.Listener, error)
}

func NewPrivateRuntime(options PrivateRuntimeOptions) (*PrivateRuntime, error) {
	if options.Now == nil || options.Enrollment == nil || options.AuthorizeRelay == nil ||
		options.Identities == nil || options.VerifyReport == nil || options.CommitReport == nil {
		return nil, errors.New("[D131 runtime] Enrollment/Device 业务依赖不完整")
	}
	runtime := &PrivateRuntime{authorize: options.AuthorizeRelay, listen: options.Listen}
	if runtime.listen == nil {
		runtime.listen = (&net.ListenConfig{}).Listen
	}
	roles, addresses, pins := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, service := range options.Services {
		if service.Role == "control_api" {
			addresses[net.JoinHostPort(service.OverlayIP, strconv.FormatInt(service.Port, 10))] = true
			for _, pin := range service.SPKIPins {
				pins[pin] = true
			}
		}
	}
	for _, service := range options.Services {
		if err := wire.ValidatePrivateControlService(&service); err != nil {
			return nil, err
		}
		if service.Role == "control_api" {
			continue
		}
		address := net.JoinHostPort(service.OverlayIP, strconv.FormatInt(service.Port, 10))
		certificate, found := options.Certificates[service.ServiceID]
		if !found || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || roles[service.Role] || addresses[address] {
			return nil, errors.New("[D131 runtime] 本机私有 role/tuple 重复或缺少专用 TLS identity")
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil || leaf.IsCA || leaf.VerifyHostname(service.OverlayIP) != nil ||
			options.Now().UTC().Before(leaf.NotBefore) || !options.Now().UTC().Before(leaf.NotAfter) {
			return nil, errors.New("[D131 runtime] 本机 TLS leaf 与 certified overlay/有效期不一致")
		}
		// endpoint pins 使用原始 SPKI SHA-256，不能误用 typed identity hash（D131）。
		pin := serviceSPKIPin(leaf)
		if !containsString(service.SPKIPins, pin) || pins[pin] || !certificateHasServerAuth(leaf) {
			return nil, errors.New("[D131 runtime] 本机 TLS key/pin/EKU 未隔离")
		}
		for _, candidatePin := range service.SPKIPins {
			if pins[candidatePin] {
				return nil, errors.New("[D131 runtime] role 之间不能复用 overlap SPKI pin")
			}
		}
		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, errors.New("[D131 runtime] server key 不支持签名")
		}
		public, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil || string(public) != string(leaf.RawSubjectPublicKeyInfo) {
			return nil, errors.New("[D131 runtime] server key 与 leaf 不匹配")
		}
		roles[service.Role], addresses[address], pins[pin] = true, true, true
		for _, candidatePin := range service.SPKIPins {
			pins[candidatePin] = true
		}
		var handler http.Handler
		switch service.Role {
		case "enroll":
			handler = enrollmenttransport.Handler(options.Enrollment.ServeVerifiedHTTP)
		case "device_config":
			handler, err = NewPrivateDeviceConfigService(service, options.Identities, options.Now)
		case "device_report":
			var reports *PrivateDeviceReportService
			reports, err = NewPrivateDeviceReportService(service, options.Identities, options.VerifyReport,
				options.CommitReport, options.ReportSchemas, options.Now, 24*time.Hour, 5*time.Minute)
			if err == nil {
				reports.SetObservationReader(options.Observations)
				handler = reports
			}
		}
		if err != nil || handler == nil {
			return nil, fmt.Errorf("[D131 runtime] private %s 初始化失败: %w", service.Role, err)
		}
		runtime.servers = append(runtime.servers, privateRuntimeServer{service: service, certificate: certificate, handler: handler})
	}
	if len(roles) != 3 {
		return nil, errors.New("[D131 runtime] 必须同时配置 Enrollment/config/report")
	}
	return runtime, nil
}

func serviceSPKIPin(leaf *x509.Certificate) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(leaf.RawSubjectPublicKeyInfo))
}

func certificateHasServerAuth(leaf *x509.Certificate) bool {
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return false
		}
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// Start 在全部 exact private tuple bind 成功后才启动 HTTP 服务。失败不留下部分
// 服务；取消只关闭该 runtime 自己创建的 listeners，不影响既有数据平面（D131）。
func (runtime *PrivateRuntime) Start(ctx context.Context) (<-chan error, error) {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("[D131 runtime] context 无效")
	}
	runtime.mu.Lock()
	if runtime.running {
		runtime.mu.Unlock()
		return nil, errors.New("[D131 runtime] 私有服务已在运行")
	}
	runtime.running = true
	runtime.mu.Unlock()
	reset := func() { runtime.mu.Lock(); runtime.running = false; runtime.mu.Unlock() }
	listeners := make([]net.Listener, 0, len(runtime.servers))
	closeListeners := func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}
	for _, server := range runtime.servers {
		address := net.JoinHostPort(server.service.OverlayIP, strconv.FormatInt(server.service.Port, 10))
		listener, err := runtime.listen(ctx, "tcp", address)
		if err == nil && (listener == nil || listener.Addr().String() != address) {
			err = errors.New("[D131 runtime] listener 未绑定 exact certified tuple")
		}
		if err != nil {
			if listener != nil {
				_ = listener.Close()
			}
			closeListeners()
			reset()
			return nil, fmt.Errorf("[D131 runtime] %s bind 失败: %w", server.service.Role, err)
		}
		if server.service.Role == "enroll" {
			relay, err := enrollmenttransport.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{server.certificate}}, runtime.authorize, 10*time.Second, 64)
			if err != nil {
				_ = listener.Close()
				closeListeners()
				reset()
				return nil, err
			}
			listener = relay
		}
		listeners = append(listeners, listener)
	}
	servers := make([]*http.Server, len(runtime.servers))
	results := make(chan error, len(servers))
	for index, service := range runtime.servers {
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{service.certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
		if service.service.Role != "enroll" {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		}
		server := &http.Server{Handler: service.handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		if service.service.Role == "enroll" {
			server.ConnContext = enrollmenttransport.BindConnection
		}
		servers[index] = server
		listener := tls.NewListener(listeners[index], tlsConfig)
		go func() { results <- server.Serve(listener) }()
	}
	done := make(chan error, 1)
	go func() {
		defer reset()
		defer close(done)
		var first error
		remaining := len(servers)
		select {
		case <-ctx.Done():
		case first = <-results:
			remaining--
		}
		for _, server := range servers {
			_ = server.Close()
		}
		closeListeners()
		for ; remaining > 0; remaining-- {
			<-results
		}
		if errors.Is(first, http.ErrServerClosed) || errors.Is(first, net.ErrClosed) {
			first = nil
		}
		done <- first
	}()
	return done, nil
}
