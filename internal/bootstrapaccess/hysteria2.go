package bootstrapaccess

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

const (
	hysteria2AuthHost         = "hysteria"
	hysteria2AuthPath         = "/auth"
	hysteria2AuthHeader       = "Hysteria-Auth"
	hysteria2UDPHeader        = "Hysteria-UDP"
	hysteria2ReceiveHeader    = "Hysteria-CC-RX"
	hysteria2PaddingHeader    = "Hysteria-Padding"
	hysteria2AuthStatus       = 233
	hysteria2TCPFrameType     = http3.FrameType(0x401)
	hysteria2MaxAddressLength = 2048
	hysteria2MaxPaddingLength = 4096
)

type Hysteria2ServerOptions struct {
	Listener                     VerifiedBootstrapListenerV1
	TLSConfig                    *tls.Config
	HandshakeTimeout             time.Duration
	IdleTimeout                  time.Duration
	MaximumConcurrentConnections int
	MaximumStreamsPerConnection  int64
	Dial                         DialContext
	Random                       io.Reader
}

// Hysteria2Server 提供 bootstrap 的 UDP 主入口，但只开放 HY2 TCP stream；
// QUIC datagram、隧道内 UDP 和任意目的转发全部禁用。
type Hysteria2Server struct {
	manager          *Manager
	registry         *CredentialRegistry
	listener         VerifiedBootstrapListenerV1
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	maximumStreams   int64
	dial             DialContext
	random           io.Reader
	randomMu         sync.Mutex
	pending          chan struct{}
}

func NewHysteria2Server(manager *Manager, registry *CredentialRegistry,
	options Hysteria2ServerOptions) (*Hysteria2Server, error) {
	if manager == nil || registry == nil || options.TLSConfig == nil || options.Dial == nil ||
		!options.Listener.valid() || options.Listener.Transport() != "hysteria2" ||
		registry.IngressSetHash() != options.Listener.IngressSetHash() ||
		options.HandshakeTimeout < time.Second ||
		options.HandshakeTimeout > 30*time.Second || options.IdleTimeout < time.Second ||
		options.IdleTimeout > 5*time.Minute || options.MaximumConcurrentConnections < 1 ||
		options.MaximumConcurrentConnections > 4096 || options.MaximumStreamsPerConnection < 1 ||
		options.MaximumStreamsPerConnection > 64 {
		return nil, errors.New("[bootstrap ingress] Hysteria2 server 配置无效")
	}
	base, err := certifiedTLSConfig(options.TLSConfig, options.Listener)
	if err != nil {
		return nil, err
	}
	random := options.Random
	if random == nil {
		random = cryptorand.Reader
	}
	return &Hysteria2Server{
		manager: manager, registry: registry, listener: options.Listener,
		tlsConfig:        http3.ConfigureTLSConfig(base),
		handshakeTimeout: options.HandshakeTimeout, idleTimeout: options.IdleTimeout,
		maximumStreams: options.MaximumStreamsPerConnection, dial: options.Dial, random: random,
		pending: make(chan struct{}, options.MaximumConcurrentConnections),
	}, nil
}

// Serve 接管一个已经绑定到 certified HY2/UDP tuple 的 PacketConn。返回时连接已关闭；
// 调用方不得把同一 UDP tuple 同时交给 WG 或另一 listener。
func (server *Hysteria2Server) Serve(ctx context.Context, packetConnection net.PacketConn) error {
	if server == nil || ctx == nil || packetConnection == nil ||
		!server.listener.matchesLocalAddr(packetConnection.LocalAddr(), "hysteria2") {
		return errors.New("[bootstrap ingress] Hysteria2 serve 输入不完整")
	}
	listener, err := quic.Listen(packetConnection, server.tlsConfig, &quic.Config{
		HandshakeIdleTimeout: server.handshakeTimeout,
		MaxIdleTimeout:       server.idleTimeout,
		// HTTP/3 auth 自己占一个 bidirectional stream；额外余量只服务控制帧，
		// 真正的 HY2 TCP stream 总数仍由 streamCount 硬限制。
		MaxIncomingStreams: server.maximumStreams + 2,
		EnableDatagrams:    false,
		Allow0RTT:          false,
	})
	if err != nil {
		_ = packetConnection.Close()
		return fmt.Errorf("[bootstrap ingress] Hysteria2 QUIC listener 启动失败: %w", err)
	}
	stopAccept := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		_ = packetConnection.Close()
	})
	defer stopAccept()
	defer listener.Close()
	defer packetConnection.Close()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("[bootstrap ingress] Hysteria2 accept 失败: %w", err)
		}
		select {
		case server.pending <- struct{}{}:
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-server.pending }()
				server.handleConnection(ctx, connection)
			}()
		default:
			_ = connection.CloseWithError(quic.ApplicationErrorCode(0x100), "")
		}
	}
}

func (server *Hysteria2Server) handleConnection(ctx context.Context, connection quic.Connection) {
	sessionID, err := server.sessionID()
	if err != nil {
		_ = connection.CloseWithError(quic.ApplicationErrorCode(0x101), "")
		return
	}
	session := &hysteria2Connection{
		server: server, connection: connection, sessionID: sessionID,
	}
	httpServer := http3.Server{
		Handler: session, EnableDatagrams: false, MaxHeaderBytes: 8 << 10,
		StreamHijacker: session.hijackStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
	session.streams.Wait()
	session.closeCapabilitySession()
}

func (server *Hysteria2Server) sessionID() (string, error) {
	var random [16]byte
	server.randomMu.Lock()
	_, err := io.ReadFull(server.random, random[:])
	server.randomMu.Unlock()
	if err != nil {
		return "", errors.New("[capability] Hysteria2 session identity 生成失败")
	}
	return "hysteria2-" + fmt.Sprintf("%x", random[:]), nil
}

type hysteria2Connection struct {
	server     *Hysteria2Server
	connection quic.Connection
	sessionID  string

	authMu            sync.Mutex
	capabilitySession *Session
	expiration        *time.Timer
	streamCount       atomic.Int64
	streams           sync.WaitGroup
}

func (session *hysteria2Connection) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.Host != hysteria2AuthHost ||
		request.URL.Path != hysteria2AuthPath || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		writeHysteria2AuthFailure(writer)
		return
	}
	if !session.server.listener.acceptsAt(session.server.manager.now()) {
		writeHysteria2AuthFailure(writer)
		return
	}
	credential := request.Header.Get(hysteria2AuthHeader)
	request.Header.Del(hysteria2AuthHeader)
	session.authMu.Lock()
	if session.capabilitySession != nil {
		session.authMu.Unlock()
		writeHysteria2AuthSuccess(writer)
		return
	}
	verifiedSession, err := session.server.registry.openHysteria2Session(
		request.Context(), session.server.manager, credential, session.sessionID)
	credential = ""
	if err != nil {
		session.authMu.Unlock()
		writeHysteria2AuthFailure(writer)
		return
	}
	remaining, err := verifiedSession.remaining()
	if err != nil {
		verifiedSession.Close()
		session.authMu.Unlock()
		writeHysteria2AuthFailure(writer)
		return
	}
	session.capabilitySession = verifiedSession
	session.expiration = time.AfterFunc(remaining, func() {
		_ = session.connection.CloseWithError(quic.ApplicationErrorCode(0x102), "")
		session.closeCapabilitySession()
	})
	session.authMu.Unlock()
	writeHysteria2AuthSuccess(writer)
}

func (session *hysteria2Connection) hijackStream(frameType http3.FrameType,
	_ quic.ConnectionTracingID, stream quic.Stream, frameErr error) (bool, error) {
	if frameErr != nil || frameType != hysteria2TCPFrameType {
		return false, nil
	}
	session.authMu.Lock()
	capabilitySession := session.capabilitySession
	session.authMu.Unlock()
	if capabilitySession == nil {
		return false, nil
	}
	if session.streamCount.Add(1) > session.server.maximumStreams {
		stream.CancelRead(quic.StreamErrorCode(0x103))
		_ = stream.Close()
		return true, nil
	}
	session.streams.Add(1)
	go func() {
		defer session.streams.Done()
		session.handleStream(capabilitySession, stream)
	}()
	return true, nil
}

func (session *hysteria2Connection) handleStream(capabilitySession *Session, stream quic.Stream) {
	connection := &hysteria2ServerConn{Stream: stream, connection: session.connection}
	defer connection.Close()
	requestedAddress, err := readHysteria2TCPRequest(stream)
	if err != nil {
		_ = connection.HandshakeFailure()
		return
	}
	requestedNetwork := "tcp"
	host, _, splitErr := net.SplitHostPort(requestedAddress)
	if address, parseErr := netip.ParseAddr(host); splitErr == nil && parseErr == nil {
		if address.Is4() {
			requestedNetwork = "tcp4"
		} else {
			requestedNetwork = "tcp6"
		}
	}
	if err := capabilitySession.relayStreamTCP(session.connection.Context(), requestedNetwork,
		requestedAddress, connection, session.server.dial); err != nil {
		return
	}
}

func (session *hysteria2Connection) closeCapabilitySession() {
	session.authMu.Lock()
	capabilitySession := session.capabilitySession
	session.capabilitySession = nil
	if session.expiration != nil {
		session.expiration.Stop()
		session.expiration = nil
	}
	session.authMu.Unlock()
	if capabilitySession != nil {
		capabilitySession.Close()
	}
}

func writeHysteria2AuthSuccess(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set(hysteria2UDPHeader, "false")
	writer.Header().Set(hysteria2ReceiveHeader, "auto")
	writer.Header().Set(hysteria2PaddingHeader, strings.Repeat("0", 256))
	writer.WriteHeader(hysteria2AuthStatus)
}

func writeHysteria2AuthFailure(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusNotFound)
}

func readHysteria2TCPRequest(reader io.Reader) (string, error) {
	variableReader := quicvarint.NewReader(reader)
	addressLength, err := quicvarint.Read(variableReader)
	if err != nil || addressLength == 0 || addressLength > hysteria2MaxAddressLength {
		return "", errors.New("[capability] Hysteria2 destination length 无效")
	}
	address := make([]byte, addressLength)
	if _, err := io.ReadFull(reader, address); err != nil || !utf8.Valid(address) {
		return "", errors.New("[capability] Hysteria2 destination 编码无效")
	}
	paddingLength, err := quicvarint.Read(variableReader)
	if err != nil || paddingLength > hysteria2MaxPaddingLength {
		return "", errors.New("[capability] Hysteria2 padding length 无效")
	}
	if paddingLength > 0 {
		if _, err := io.CopyN(io.Discard, reader, int64(paddingLength)); err != nil {
			return "", errors.New("[capability] Hysteria2 padding 不完整")
		}
	}
	return string(address), nil
}

type hysteria2ServerConn struct {
	quic.Stream
	connection quic.Connection
	responseMu sync.Mutex
	responded  bool
}

func (connection *hysteria2ServerConn) HandshakeSuccess() error {
	return connection.writeResponse(true, nil)
}

func (connection *hysteria2ServerConn) HandshakeFailure() error {
	return connection.writeResponse(false, nil)
}

func (connection *hysteria2ServerConn) Write(payload []byte) (int, error) {
	connection.responseMu.Lock()
	if connection.responded {
		connection.responseMu.Unlock()
		return connection.Stream.Write(payload)
	}
	connection.responded = true
	response := hysteria2TCPResponse(true, payload)
	connection.responseMu.Unlock()
	if err := writeFull(connection.Stream, response); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (connection *hysteria2ServerConn) writeResponse(success bool, payload []byte) error {
	connection.responseMu.Lock()
	defer connection.responseMu.Unlock()
	if connection.responded {
		return nil
	}
	connection.responded = true
	return writeFull(connection.Stream, hysteria2TCPResponse(success, payload))
}

func hysteria2TCPResponse(success bool, payload []byte) []byte {
	const paddingLength = 128
	response := make([]byte, 0, 4+paddingLength+len(payload))
	if success {
		response = append(response, 0)
	} else {
		response = append(response, 1)
	}
	// message 为空，错误细节绝不向公网 transport 暴露；保留协议规定的有界
	// padding，避免把 bootstrap listener 变成显眼的零填充变体。
	response = quicvarint.Append(response, 0)
	response = quicvarint.Append(response, paddingLength)
	response = append(response, make([]byte, paddingLength)...)
	return append(response, payload...)
}

func (connection *hysteria2ServerConn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *hysteria2ServerConn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func (connection *hysteria2ServerConn) CloseWrite() error {
	return connection.Stream.Close()
}

func (connection *hysteria2ServerConn) Close() error {
	connection.Stream.CancelRead(0)
	return connection.Stream.Close()
}

func writeFull(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		count, err := writer.Write(body)
		body = body[count:]
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
