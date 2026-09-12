package bootstrapaccess

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	trojanCommandTCP  = 1
	trojanAddressIPv4 = 1
	trojanAddressFQDN = 3
	trojanAddressIPv6 = 4
)

type TrojanTLSServerOptions struct {
	ServerName                   string
	TLSConfig                    *tls.Config
	HandshakeTimeout             time.Duration
	MaximumConcurrentConnections int
	Dial                         DialContext
	Random                       io.Reader
}

// TrojanTLSServer 是 UDP 完全不可用时的独立 TCP fallback。TLS 只证明 certified
// public FQDN；随后 Trojan credential 才打开 capability session，二者都不承载
// Enrollment token 或终止内层 Enrollment TLS（D115、D131）。
type TrojanTLSServer struct {
	manager          *Manager
	registry         *CredentialRegistry
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
	dial             DialContext
	random           io.Reader
	randomMu         sync.Mutex
	pending          chan struct{}
}

func NewTrojanTLSServer(manager *Manager, registry *CredentialRegistry,
	options TrojanTLSServerOptions) (*TrojanTLSServer, error) {
	if manager == nil || registry == nil || options.TLSConfig == nil || options.Dial == nil ||
		!validCertifiedServerName(options.ServerName) || options.HandshakeTimeout < time.Second ||
		options.HandshakeTimeout > 30*time.Second || options.MaximumConcurrentConnections < 1 ||
		options.MaximumConcurrentConnections > 4096 {
		return nil, errors.New("[D115 bootstrap ingress] Trojan/TLS server 配置无效")
	}
	base := options.TLSConfig.Clone()
	if len(base.Certificates) == 0 && base.GetCertificate == nil && base.GetConfigForClient == nil {
		return nil, errors.New("[D115 bootstrap ingress] Trojan/TLS certificate 缺失")
	}
	if len(base.Certificates) > 0 && base.GetCertificate == nil && base.GetConfigForClient == nil &&
		!fixedTLSConfigServesName(base, options.ServerName) {
		return nil, errors.New("[D115 bootstrap ingress] Trojan/TLS certificate 不覆盖 certified FQDN")
	}
	base.MinVersion = tls.VersionTLS13
	base.MaxVersion = tls.VersionTLS13
	base.ClientAuth = tls.NoClientCert
	expectedServerName := options.ServerName
	originalGetConfig := base.GetConfigForClient
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil || hello.ServerName != expectedServerName {
			return nil, errors.New("[D115 bootstrap ingress] Trojan/TLS SNI 不属于 certified listener")
		}
		if originalGetConfig == nil {
			return nil, nil
		}
		selected, err := originalGetConfig(hello)
		if err != nil || selected == nil {
			return selected, err
		}
		strict := selected.Clone()
		strict.MinVersion = tls.VersionTLS13
		strict.MaxVersion = tls.VersionTLS13
		strict.ClientAuth = tls.NoClientCert
		return strict, nil
	}
	random := options.Random
	if random == nil {
		random = cryptorand.Reader
	}
	return &TrojanTLSServer{
		manager: manager, registry: registry, tlsConfig: base,
		handshakeTimeout: options.HandshakeTimeout, dial: options.Dial, random: random,
		pending: make(chan struct{}, options.MaximumConcurrentConnections),
	}, nil
}

// Serve 接受调用方已经绑定到 certified Trojan/TCP tuple 的 listener。它不会创建
// Nginx route，也不会把失败连接转发到 fake website（D115、D131）。
func (server *TrojanTLSServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || ctx == nil || listener == nil {
		return errors.New("[D115 bootstrap ingress] Trojan/TLS serve 输入不完整")
	}
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopAccept()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("[D115 bootstrap ingress] Trojan/TLS accept 失败: %w", err)
		}
		select {
		case server.pending <- struct{}{}:
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-server.pending }()
				_ = server.handle(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *TrojanTLSServer) handle(ctx context.Context, raw net.Conn) error {
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := raw.SetDeadline(time.Now().Add(server.handshakeTimeout)); err != nil {
		return err
	}
	connection := tls.Server(raw, server.tlsConfig)
	handshakeContext, cancel := context.WithTimeout(ctx, server.handshakeTimeout)
	err := connection.HandshakeContext(handshakeContext)
	cancel()
	if err != nil || connection.ConnectionState().Version != tls.VersionTLS13 {
		return errors.New("[D115 bootstrap ingress] Trojan/TLS outer handshake 失败")
	}
	var key [trojanKeyLength]byte
	if _, err := io.ReadFull(connection, key[:]); err != nil {
		return errors.New("[D131 capability] Trojan credential header 不完整")
	}
	sessionID, err := server.sessionID()
	if err != nil {
		return err
	}
	session, err := server.registry.openTrojanSession(server.manager, key, sessionID)
	if err != nil {
		return err
	}
	defer session.Close()
	network, address, err := readTrojanTCPRequest(connection)
	if err != nil {
		return err
	}
	return session.relayTCP(ctx, network, address, connection, server.dial)
}

func (server *TrojanTLSServer) sessionID() (string, error) {
	var random [16]byte
	server.randomMu.Lock()
	_, err := io.ReadFull(server.random, random[:])
	server.randomMu.Unlock()
	if err != nil {
		return "", errors.New("[D131 capability] Trojan session identity 生成失败")
	}
	return "trojan-" + hex.EncodeToString(random[:]), nil
}

func readTrojanTCPRequest(reader io.Reader) (string, string, error) {
	if err := readTrojanCRLF(reader); err != nil {
		return "", "", err
	}
	var command [1]byte
	if _, err := io.ReadFull(reader, command[:]); err != nil || command[0] != trojanCommandTCP {
		return "", "", errors.New("[D131 capability] Trojan bootstrap 只允许 TCP command")
	}
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return "", "", errors.New("[D131 capability] Trojan destination header 不完整")
	}
	var address netip.Addr
	var network string
	switch addressType[0] {
	case trojanAddressIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", "", errors.New("[D131 capability] Trojan IPv4 destination 不完整")
		}
		address = netip.AddrFrom4(raw)
		network = "tcp4"
	case trojanAddressIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", "", errors.New("[D131 capability] Trojan IPv6 destination 不完整")
		}
		address = netip.AddrFrom16(raw)
		network = "tcp6"
	case trojanAddressFQDN:
		return "", "", errors.New("[D131 capability] Trojan bootstrap 禁止 DNS destination")
	default:
		return "", "", errors.New("[D131 capability] Trojan address type 无效")
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return "", "", errors.New("[D131 capability] Trojan destination port 不完整")
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", "", errors.New("[D131 capability] Trojan destination port 无效")
	}
	if err := readTrojanCRLF(reader); err != nil {
		return "", "", err
	}
	return network, net.JoinHostPort(address.String(), strconv.Itoa(int(port))), nil
}

func readTrojanCRLF(reader io.Reader) error {
	var delimiter [2]byte
	if _, err := io.ReadFull(reader, delimiter[:]); err != nil || delimiter != [2]byte{'\r', '\n'} {
		return errors.New("[D131 capability] Trojan request delimiter 无效")
	}
	return nil
}

func validCertifiedServerName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") || !strings.Contains(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func fixedTLSConfigServesName(config *tls.Config, serverName string) bool {
	for _, certificate := range config.Certificates {
		leaf := certificate.Leaf
		if leaf == nil && len(certificate.Certificate) > 0 {
			parsed, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				continue
			}
			leaf = parsed
		}
		if leaf != nil && leaf.VerifyHostname(serverName) == nil {
			return true
		}
	}
	return false
}
