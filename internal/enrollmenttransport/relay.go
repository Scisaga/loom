// Package enrollmenttransport 将 bootstrap ingress 的已认证会话绑定到私有
// Enrollment 连接。节点间 mTLS 只传 capability ID 与仍然加密的 client inner TLS；
// ingress 不终止 inner TLS，也不能以裸 HTTP header 注入已验证身份（D115、D131）。
package enrollmenttransport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/wire"
)

const relayALPN = "private-enrollment-relay/1"

// Authorizer 必须从当前 certified state 校验 ingress 的 Device certificate、
// forward 职责、入口集合、capability 撤销/有效期以及 exact Enrollment tuple。
// capability ID 自身不能代替这些认证（D131）。
type Authorizer func(context.Context, []byte, string) (wire.VerifiedBootstrapCapabilityV1, error)

type boundConn struct {
	net.Conn
	capability wire.VerifiedBootstrapCapabilityV1
}

type capabilityContextKey struct{}

// BindConnection 在 http.Server.ConnContext 中使用；HTTP server 外层的 tls.Conn
// 是客户端 inner TLS，下面的 boundConn 才是已认证 ingress 的 private relay（D131）。
func BindConnection(ctx context.Context, connection net.Conn) context.Context {
	if inner, ok := connection.(*tls.Conn); ok {
		connection = inner.NetConn()
	}
	if bound, ok := connection.(*boundConn); ok {
		return context.WithValue(ctx, capabilityContextKey{}, bound.capability)
	}
	return ctx
}

func Capability(ctx context.Context) (wire.VerifiedBootstrapCapabilityV1, bool) {
	value, ok := ctx.Value(capabilityContextKey{}).(wire.VerifiedBootstrapCapabilityV1)
	return value, ok && value.CapabilityID() != ""
}

// Dialer 保留被 Manager 验证的 network/address；TLSConfig 回调只从 certified
// service ref 返回 exact trust/pins 和当前 ingress Device client certificate。
func Dialer(configure func(context.Context, string) (*tls.Config, error), dial bootstrapaccess.DialContext) bootstrapaccess.DialContext {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		id := bootstrapaccess.RelayCapabilityID(ctx)
		if _, err := wire.ParseHash(id); err != nil || configure == nil {
			return nil, errors.New("[D131 relay] 缺已认证的 bootstrap session")
		}
		config, err := configure(ctx, address)
		if err != nil || config == nil || config.InsecureSkipVerify && config.VerifyConnection == nil {
			return nil, errors.New("[D131 relay] 私有服务 TLS 验证器不可用")
		}
		config = config.Clone()
		config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		config.NextProtos = []string{relayALPN}
		if len(config.Certificates) == 0 && config.GetClientCertificate == nil {
			return nil, errors.New("[D131 relay] ingress Device certificate 缺失")
		}
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, errors.New("[D131 relay] 私有服务连接失败")
		}
		connection := tls.Client(raw, config)
		fail := func() (net.Conn, error) {
			_ = connection.Close()
			return nil, errors.New("[D131 relay] ingress mTLS/session binding 失败")
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = connection.SetDeadline(deadline)
		}
		if err := connection.HandshakeContext(ctx); err != nil || connection.ConnectionState().NegotiatedProtocol != relayALPN {
			return fail()
		}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(id)))
		if err := writeAll(connection, append(length[:], []byte(id)...)); err != nil {
			return fail()
		}
		var accepted [1]byte
		if _, err := io.ReadFull(connection, accepted[:]); err != nil || accepted[0] != 1 {
			return fail()
		}
		return connection, nil
	}
}

// Listener 只把通过 ingress mTLS 与当前 capability 校验的 stream 交给 inner TLS。
// 同时进行的握手有上限；一个慢连接不会堵住其他 ingress 的入网（D131）。
type Listener struct {
	raw       net.Listener
	config    *tls.Config
	authorize Authorizer
	timeout   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	accepted  chan net.Conn
	closed    chan struct{}
	limit     chan struct{}
	workers   sync.WaitGroup
	closeOnce sync.Once
}

func NewListener(raw net.Listener, config *tls.Config, authorize Authorizer, timeout time.Duration, concurrency int) (*Listener, error) {
	if raw == nil || config == nil || authorize == nil || timeout <= 0 || timeout > time.Minute || concurrency < 1 || concurrency > 256 {
		return nil, errors.New("[D131 relay] 私有 listener 依赖/限制无效")
	}
	config = config.Clone()
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.ClientAuth = tls.RequireAnyClientCert
	config.NextProtos = []string{relayALPN}
	ctx, cancel := context.WithCancel(context.Background())
	listener := &Listener{raw: raw, config: config, authorize: authorize, timeout: timeout,
		ctx: ctx, cancel: cancel, accepted: make(chan net.Conn), closed: make(chan struct{}), limit: make(chan struct{}, concurrency)}
	go listener.run()
	return listener, nil
}

func (listener *Listener) run() {
	defer close(listener.closed)
	defer listener.workers.Wait()
	for {
		raw, err := listener.raw.Accept()
		if err != nil {
			listener.cancel()
			return
		}
		select {
		case listener.limit <- struct{}{}:
		default:
			_ = raw.Close()
			continue
		}
		listener.workers.Add(1)
		go func() {
			defer listener.workers.Done()
			defer func() { <-listener.limit }()
			connection, err := listener.authenticate(raw)
			if err != nil {
				_ = raw.Close()
				return
			}
			select {
			case listener.accepted <- connection:
			case <-listener.ctx.Done():
				_ = connection.Close()
			}
		}()
	}
}

func (listener *Listener) authenticate(raw net.Conn) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(listener.ctx, listener.timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(listener.timeout))
	connection := tls.Server(raw, listener.config)
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := connection.ConnectionState()
	if state.NegotiatedProtocol != relayALPN || len(state.PeerCertificates) == 0 {
		return nil, errors.New("[D131 relay] ingress mTLS profile 无效")
	}
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil || int(binary.BigEndian.Uint16(length[:])) != len(wire.EmptyHashV1) {
		return nil, errors.New("[D131 relay] session binding 长度无效")
	}
	encoded := make([]byte, len(wire.EmptyHashV1))
	if _, err := io.ReadFull(connection, encoded); err != nil {
		return nil, err
	}
	id := string(encoded)
	if _, err := wire.ParseHash(id); err != nil {
		return nil, err
	}
	capability, err := listener.authorize(ctx, state.PeerCertificates[0].Raw, id)
	if err != nil || capability.CapabilityID() != id {
		return nil, errors.New("[D131 relay] ingress/capability 未获当前 authority 授权")
	}
	body := capability.Body()
	if body.AllowedInsideTransport != "tcp" || raw.LocalAddr().String() != net.JoinHostPort(body.AllowedDestinationIP, strconv.FormatInt(body.AllowedDestinationPort, 10)) {
		return nil, errors.New("[D131 relay] capability 不属于 exact Enrollment tuple")
	}
	if err := writeAll(connection, []byte{1}); err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &boundConn{Conn: connection, capability: capability}, nil
}

func (listener *Listener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.accepted:
		return connection, nil
	case <-listener.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (listener *Listener) Addr() net.Addr { return listener.raw.Addr() }

func (listener *Listener) Close() error {
	var err error
	listener.closeOnce.Do(func() {
		listener.cancel()
		err = listener.raw.Close()
	})
	<-listener.closed
	return err
}

func writeAll(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		n, err := writer.Write(body)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		body = body[n:]
	}
	return nil
}

// Handler 不接收调用方伪造的 header/context；连接绑定仅由 Listener 产生。
func Handler(serve func(http.ResponseWriter, *http.Request, wire.VerifiedBootstrapCapabilityV1)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capability, ok := Capability(request.Context())
		if !ok || serve == nil {
			http.Error(writer, "[D131 Enrollment] 缺少已认证的私有 tunnel", http.StatusForbidden)
			return
		}
		serve(writer, request, capability)
	})
}
