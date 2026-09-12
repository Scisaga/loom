//go:build linux

package clientv2

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"loom/internal/wire"
)

const (
	linuxBootstrapHysteriaAuthHost   = "hysteria"
	linuxBootstrapHysteriaAuthPath   = "/auth"
	linuxBootstrapHysteriaAuthHeader = "Hysteria-Auth"
	linuxBootstrapHysteriaAuthOK     = 233
	linuxBootstrapHysteriaTCPFrame   = uint64(0x401)
	linuxBootstrapMaximumMessage     = 2048
	linuxBootstrapMaximumPadding     = 4096
)

// LinuxBootstrapSelection 是可公开进入诊断证据的最小选择结果；它不包含 FQDN、
// public IP、pin、capability 或 transport credential（D131、Issue #11）。
type LinuxBootstrapSelection struct {
	EndpointID         string
	Transport          string
	ListenerGeneration int64
}

type linuxBootstrapCandidate struct {
	selection  LinuxBootstrapSelection
	hintRank   int64
	serverName string
	publicPort int64
	spkiPins   []string
	preferred  bool
}

// LinuxBootstrapTunnelDialer 只拨 capability 允许的 exact private Enrollment tuple。
// 每次实际 outer dial 都计入 capability attempt budget；不会扫描 catalog 外端口。
type LinuxBootstrapTunnelDialer struct {
	mu sync.Mutex

	candidates      []linuxBootstrapCandidate
	credential      string
	destination     string
	maximumAttempts int64
	attempts        int64
	selected        *LinuxBootstrapSelection
	roots           *x509.CertPool
	timeout         time.Duration

	tcpDial  func(context.Context, string, string) (net.Conn, error)
	quicDial func(context.Context, string, *tls.Config, *quic.Config) (quic.Connection, error)
}

// NewLinuxBootstrapTunnelDialer 把 Invite lineage、catalog QC 与 capability authorization
// 在同一入口重验，再产生只能送达 Enrollment service ref 的 dialer（D115、D131）。
func NewLinuxBootstrapTunnelDialer(catalog *wire.BootstrapEndpointCatalogV1,
	capability *wire.BootstrapTunnelCapabilityV1,
	issuerProof *wire.BootstrapIssuerAuthorizationProofV1,
	policy *wire.InviteIssuancePolicyV2,
	proof wire.VerifiedInviteProofV2,
	trustedTime time.Time, clientProtocol int64, roots *x509.CertPool,
) (*LinuxBootstrapTunnelDialer, error) {
	if catalog == nil || capability == nil || issuerProof == nil || policy == nil ||
		trustedTime.IsZero() || clientProtocol < 1 {
		return nil, errors.New("[D131 Linux bootstrap] tunnel authority 输入不完整")
	}
	if err := wire.ValidateBootstrapEndpointCatalogAt(catalog, trustedTime.UTC(), clientProtocol); err != nil {
		return nil, err
	}
	head, set, previousSet, ok := proof.AuthorityForHead(catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(catalog.ParentHeadHash,
		catalog.BootstrapIngressSet.ConfigQC, &head, &set, previousSet) != nil {
		return nil, errors.New("[D131 Linux bootstrap] catalog QC authority 未通过 Invite lineage")
	}
	verified, err := wire.VerifyCapabilityAuthorizationEvidence(capability, issuerProof, policy, trustedTime.UTC())
	if err != nil {
		return nil, err
	}
	body := verified.Body()
	if body.AllowedIngressSetHash != catalog.BootstrapIngressSetHash ||
		body.AllowedInsideTransport != "tls_tcp" {
		return nil, errors.New("[D131 Linux bootstrap] capability 未绑定 catalog 或 inner TLS/TCP")
	}
	destination, err := capabilityDestination(body)
	if err != nil {
		return nil, err
	}
	candidates, err := linuxBootstrapCandidates(catalog, trustedTime.UTC())
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 12 * time.Second, KeepAlive: 30 * time.Second}
	return &LinuxBootstrapTunnelDialer{
		candidates: candidates, credential: verified.TransportCredential(), destination: destination,
		maximumAttempts: body.MaximumConnectionAttempts, roots: roots, timeout: 12 * time.Second,
		tcpDial: dialer.DialContext,
		quicDial: func(ctx context.Context, address string, tlsConfig *tls.Config,
			config *quic.Config) (quic.Connection, error) {
			return quic.DialAddr(ctx, address, tlsConfig, config)
		},
	}, nil
}

func capabilityDestination(body wire.BootstrapTunnelCapabilityBodyV1) (string, error) {
	address, err := netip.ParseAddr(body.AllowedDestinationIP)
	if err != nil || address.String() != body.AllowedDestinationIP || !address.IsPrivate() ||
		body.AllowedDestinationPort < 1 || body.AllowedDestinationPort > 65535 {
		return "", errors.New("[D131 Linux bootstrap] capability Enrollment destination 无效")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(body.AllowedDestinationPort))), nil
}

func linuxBootstrapCandidates(catalog *wire.BootstrapEndpointCatalogV1,
	now time.Time) ([]linuxBootstrapCandidate, error) {
	if catalog == nil {
		return nil, errors.New("[D131 Linux bootstrap] catalog 不能为空")
	}
	var candidates []linuxBootstrapCandidate
	for endpointIndex := range catalog.BootstrapIngressSet.Endpoints {
		endpoint := &catalog.BootstrapIngressSet.Endpoints[endpointIndex]
		for generationIndex := range endpoint.ListenerGenerations {
			generation := &endpoint.ListenerGenerations[generationIndex]
			validFrom, _ := wire.ParseTimeZ(generation.ValidFrom)
			validUntil, _ := wire.ParseTimeZ(generation.ValidUntil)
			if generation.PublishedState == "draining" || now.Before(validFrom) || !now.Before(validUntil) {
				continue
			}
			pins, err := linuxBootstrapIdentityPins(generation.TransportIdentityRefs)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, linuxBootstrapCandidate{
				selection: LinuxBootstrapSelection{EndpointID: endpoint.EndpointID,
					Transport: endpoint.Transport, ListenerGeneration: generation.ListenerGeneration},
				hintRank: endpoint.HintRank, serverName: generation.DialTargetFQDN,
				publicPort: generation.PublicPort, spkiPins: pins,
				preferred: generation.PublishedState == "preferred",
			})
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("[D131 Linux bootstrap] catalog 没有当前可拨 generation")
	}
	// UDP 可用时必须优先 HY2。hint 只在同 transport 内排序；每个 endpoint 的
	// preferred 又先于 advertised overlap 代（Issue #11、D120）。
	sort.SliceStable(candidates, func(left, right int) bool {
		l, r := candidates[left], candidates[right]
		if l.selection.Transport != r.selection.Transport {
			return l.selection.Transport == "hysteria2"
		}
		if l.hintRank != r.hintRank {
			return l.hintRank < r.hintRank
		}
		if l.selection.EndpointID != r.selection.EndpointID {
			return l.selection.EndpointID < r.selection.EndpointID
		}
		if l.preferred != r.preferred {
			return l.preferred
		}
		return l.selection.ListenerGeneration > r.selection.ListenerGeneration
	})
	return candidates, nil
}

func linuxBootstrapIdentityPins(refs []string) ([]string, error) {
	profileCount := 0
	pins := make([]string, 0, len(refs))
	for _, ref := range refs {
		if strings.HasPrefix(ref, "profile:") {
			if len(strings.TrimPrefix(ref, "profile:")) == 0 {
				return nil, errors.New("[D122 Linux bootstrap] WebPKI profile ref 无效")
			}
			profileCount++
			continue
		}
		if _, err := wire.ParseHash(ref); err != nil {
			return nil, errors.New("[D122 Linux bootstrap] transport identity ref 不是 SPKI pin")
		}
		pins = append(pins, ref)
	}
	if profileCount != 1 || len(pins) == 0 || len(pins) > 2 {
		return nil, errors.New("[D122 Linux bootstrap] listener 必须有一个 WebPKI profile 与一至两个 SPKI pin")
	}
	return pins, nil
}

// DialContext 满足 PrivateEnrollmentClient 的 TunnelDialContext。network/address 不能
// 改写 capability 允许的 exact tuple；同一时刻只建立一个外层 session。
func (dialer *LinuxBootstrapTunnelDialer) DialContext(ctx context.Context,
	network, address string) (net.Conn, error) {
	if dialer == nil || ctx == nil || network != "tcp" || address != dialer.destination {
		return nil, errors.New("[D131 Linux bootstrap] tunnel 只允许 exact Enrollment TCP tuple")
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	for _, candidate := range dialer.candidates {
		if dialer.attempts >= dialer.maximumAttempts {
			break
		}
		dialer.attempts++
		attemptContext, cancel := context.WithTimeout(ctx, dialer.timeout)
		var connection net.Conn
		var err error
		if candidate.selection.Transport == "hysteria2" {
			connection, err = dialer.dialHysteria2(attemptContext, candidate)
		} else {
			connection, err = dialer.dialTrojan(attemptContext, candidate)
		}
		cancel()
		if err != nil {
			continue
		}
		selected := candidate.selection
		dialer.selected = &selected
		return connection, nil
	}
	return nil, errors.New("[D131 Linux bootstrap] capability 预算内没有可达的授权 HY2/Trojan ingress")
}

func (dialer *LinuxBootstrapTunnelDialer) Selection() (LinuxBootstrapSelection, bool) {
	if dialer == nil {
		return LinuxBootstrapSelection{}, false
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if dialer.selected == nil {
		return LinuxBootstrapSelection{}, false
	}
	return *dialer.selected, true
}

func (dialer *LinuxBootstrapTunnelDialer) dialTrojan(ctx context.Context,
	candidate linuxBootstrapCandidate) (net.Conn, error) {
	address := net.JoinHostPort(candidate.serverName, strconv.Itoa(int(candidate.publicPort)))
	raw, err := dialer.tcpDial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, linuxBootstrapTLSConfig(candidate.serverName, candidate.spkiPins, dialer.roots, false))
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	request, err := trojanBootstrapRequest(dialer.credential, dialer.destination)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := writeLinuxBootstrapFull(connection, request); err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}

func trojanBootstrapRequest(credential, destination string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, errors.New("[D131 Linux bootstrap] Trojan destination 无效")
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || port == 0 {
		return nil, errors.New("[D131 Linux bootstrap] Trojan destination tuple 无效")
	}
	digest := sha256.Sum224([]byte(credential))
	request := make([]byte, hex.EncodedLen(len(digest))+2, 96)
	hex.Encode(request, digest[:])
	request[len(request)-2], request[len(request)-1] = '\r', '\n'
	request = append(request, 1) // CONNECT
	if address.Is4() {
		request = append(request, 1)
		request = append(request, address.AsSlice()...)
	} else {
		request = append(request, 4)
		request = append(request, address.AsSlice()...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return append(request, '\r', '\n'), nil
}

func (dialer *LinuxBootstrapTunnelDialer) dialHysteria2(ctx context.Context,
	candidate linuxBootstrapCandidate) (net.Conn, error) {
	address := net.JoinHostPort(candidate.serverName, strconv.Itoa(int(candidate.publicPort)))
	tlsConfig := linuxBootstrapTLSConfig(candidate.serverName, candidate.spkiPins, dialer.roots, true)
	config := &quic.Config{HandshakeIdleTimeout: dialer.timeout, MaxIdleTimeout: 2 * time.Minute,
		KeepAlivePeriod: 20 * time.Second, EnableDatagrams: false, Allow0RTT: false}
	connection, err := dialer.quicDial(ctx, address, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: config,
		EnableDatagrams: false, DisableCompression: true, MaxResponseHeaderBytes: 8 << 10}
	client := transport.NewClientConn(connection)
	request := &http.Request{Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: linuxBootstrapHysteriaAuthHost, Path: linuxBootstrapHysteriaAuthPath},
		Header: make(http.Header), Body: http.NoBody}
	request.Header.Set(linuxBootstrapHysteriaAuthHeader, dialer.credential)
	response, err := client.RoundTrip(request.WithContext(ctx))
	if err != nil {
		_ = connection.CloseWithError(0, "")
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != linuxBootstrapHysteriaAuthOK ||
		response.Header.Get("Hysteria-UDP") != "false" {
		_ = connection.CloseWithError(0, "")
		return nil, errors.New("[D131 Linux bootstrap] Hysteria2 capability auth 失败")
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		_ = connection.CloseWithError(0, "")
		return nil, err
	}
	return &linuxHysteria2TunnelConn{Stream: stream, connection: connection,
		destination: dialer.destination}, nil
}

func linuxBootstrapTLSConfig(serverName string, pins []string, roots *x509.CertPool,
	http3Protocol bool) *tls.Config {
	config := &tls.Config{ServerName: serverName, RootCAs: roots,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("[D122 Linux bootstrap] WebPKI chain 未验证")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			actual := "sha256:" + hex.EncodeToString(digest[:])
			for _, pin := range pins {
				if pin == actual {
					return nil
				}
			}
			return errors.New("[D122 Linux bootstrap] outer TLS SPKI pin 不匹配")
		},
	}
	if http3Protocol {
		config.NextProtos = []string{http3.NextProtoH3}
	}
	return config
}

type linuxHysteria2TunnelConn struct {
	quic.Stream
	connection     quic.Connection
	destination    string
	writeMu        sync.Mutex
	readMu         sync.Mutex
	requestWritten bool
	responseRead   bool
}

func (connection *linuxHysteria2TunnelConn) Write(payload []byte) (int, error) {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.requestWritten {
		return connection.Stream.Write(payload)
	}
	if len(connection.destination) == 0 || len(connection.destination) > 2048 {
		return 0, errors.New("[D131 Linux bootstrap] Hysteria2 destination 长度无效")
	}
	var request []byte
	request = quicvarint.Append(request, linuxBootstrapHysteriaTCPFrame)
	request = quicvarint.Append(request, uint64(len(connection.destination)))
	request = append(request, connection.destination...)
	request = quicvarint.Append(request, 0) // bootstrap 不发送可识别的随机 padding。
	request = append(request, payload...)
	if err := writeLinuxBootstrapFull(connection.Stream, request); err != nil {
		return 0, err
	}
	connection.requestWritten = true
	return len(payload), nil
}

func (connection *linuxHysteria2TunnelConn) Read(payload []byte) (int, error) {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	if !connection.responseRead {
		if err := readLinuxHysteria2Response(connection.Stream); err != nil {
			return 0, err
		}
		connection.responseRead = true
	}
	return connection.Stream.Read(payload)
}

func readLinuxHysteria2Response(reader io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil || status[0] != 0 {
		return errors.New("[D131 Linux bootstrap] Hysteria2 TCP relay 被拒绝")
	}
	variableReader := quicvarint.NewReader(reader)
	messageLength, err := quicvarint.Read(variableReader)
	if err != nil || messageLength > linuxBootstrapMaximumMessage {
		return errors.New("[D131 Linux bootstrap] Hysteria2 response message 无效")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(messageLength)); err != nil {
		return err
	}
	paddingLength, err := quicvarint.Read(variableReader)
	if err != nil || paddingLength > linuxBootstrapMaximumPadding {
		return errors.New("[D131 Linux bootstrap] Hysteria2 response padding 无效")
	}
	_, err = io.CopyN(io.Discard, reader, int64(paddingLength))
	return err
}

func (connection *linuxHysteria2TunnelConn) Close() error {
	connection.Stream.CancelRead(0)
	streamErr := connection.Stream.Close()
	outerErr := connection.connection.CloseWithError(0, "")
	if streamErr != nil {
		return streamErr
	}
	return outerErr
}

func (connection *linuxHysteria2TunnelConn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *linuxHysteria2TunnelConn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func writeLinuxBootstrapFull(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written < 1 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

var _ net.Conn = (*linuxHysteria2TunnelConn)(nil)
