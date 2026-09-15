package clientv2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"loom/internal/wire"
)

const (
	MaximumPrivateDeviceViewBytes = 32 << 20
)

// VerifyPrivateControlDirectory 要求 directory 的 exact hash pin、parent Head、
// ControlSet 与 config QC 同时成立；directory bytes 不能靠公网 URL 自行授权。
func VerifyPrivateControlDirectory(directory *wire.ControlServiceDirectoryV1,
	pinnedDirectoryHash string, head *wire.HeadEntryV2, set, previousSet *wire.ControlSetV1) error {
	if directory == nil || head == nil || set == nil {
		return errors.New("[client] private directory authority 不完整")
	}
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return err
	}
	directoryHash, err := wire.ControlServiceDirectoryHash(directory)
	if err != nil || directoryHash != pinnedDirectoryHash {
		return errors.New("[client] private directory 与 protected hash pin 不一致")
	}
	setHash, err := wire.ControlSetHash(set)
	if err != nil || directory.ClusterID != head.Body.Payload.ClusterID ||
		directory.ClusterID != set.ClusterID || directory.ParentHeadHash != head.HeadHash ||
		directory.ControlSetHash != setHash || head.Body.Payload.ControlSetHash != setHash {
		return errors.New("[client] private directory 未绑定 certified Head/ControlSet")
	}
	return wire.VerifyConfigQCAuthority(directory.ParentHeadHash, directory.ConfigQC,
		head, set, previousSet)
}

// SelectPrivateControlServices 返回 certified 顺序中的获权副本。指定 serviceID
// 时必须恰好命中一个；未指定时宿主可按顺序故障切换但不得扫描额外地址。
func SelectPrivateControlServices(directory *wire.ControlServiceDirectoryV1, role,
	serviceID, certificateProfileID string) ([]wire.PrivateControlServiceV1, error) {
	if directory == nil || (role != "device_config" && role != "device_report") ||
		certificateProfileID == "" {
		return nil, errors.New("[client] private service selection 输入无效")
	}
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return nil, err
	}
	selected := make([]wire.PrivateControlServiceV1, 0)
	for index := range directory.Services {
		candidate := &directory.Services[index]
		if candidate.Role != role || serviceID != "" && candidate.ServiceID != serviceID ||
			!containsString(candidate.AuthorizedSubjectProfiles, certificateProfileID) {
			continue
		}
		copy := *candidate
		copy.SPKIPins = append([]string(nil), candidate.SPKIPins...)
		copy.AuthorizedSubjectProfiles = append([]string(nil), candidate.AuthorizedSubjectProfiles...)
		selected = append(selected, copy)
	}
	if len(selected) == 0 || serviceID != "" && len(selected) != 1 {
		return nil, errors.New("[client] certified private directory 缺唯一获权目标 service")
	}
	return selected, nil
}

type PrivateDeviceHTTPClient struct {
	client  *http.Client
	baseURL string
}

// NewPrivateDeviceHTTPClient 使用 Device certificate + 平台 crypto.Signer 完成
// mTLS。identity private key 不进入共享客户端；每次 dial 只允许 certified overlay tuple。
func NewPrivateDeviceHTTPClient(service wire.PrivateControlServiceV1, expectedRole,
	certificateProfileID string, certificateChainDER [][]byte, identitySigner crypto.Signer,
	roots *x509.CertPool, dial TunnelDialContext, now func() time.Time,
	timeout time.Duration) (*PrivateDeviceHTTPClient, error) {
	if err := wire.ValidatePrivateControlService(&service); err != nil {
		return nil, err
	}
	publicKey, ok := identitySignerPublicP256(identitySigner)
	if service.Role != expectedRole || (expectedRole != "device_config" && expectedRole != "device_report") ||
		certificateProfileID == "" || !containsString(service.AuthorizedSubjectProfiles, certificateProfileID) ||
		!ok || roots == nil || now == nil || timeout < time.Second || timeout > 5*time.Minute ||
		len(certificateChainDER) == 0 || len(certificateChainDER) > 8 {
		return nil, errors.New("[client] mTLS identity/profile/internal CA/time/timeout 无效")
	}
	leaf, err := x509.ParseCertificate(certificateChainDER[0])
	if err != nil || !bytes.Equal(leaf.Raw, certificateChainDER[0]) || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		len(leaf.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("[client] Device certificate profile 无效")
	}
	instant := now().UTC()
	if instant.IsZero() || instant.Before(leaf.NotBefore) || !instant.Before(leaf.NotAfter) {
		return nil, errors.New("[client] Device certificate 已过期或尚未生效")
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(publicSPKI, leaf.RawSubjectPublicKeyInfo) {
		return nil, errors.New("[client] Device certificate/platform signer 不匹配")
	}
	chain := make([][]byte, len(certificateChainDER))
	for index := range certificateChainDER {
		certificate, parseErr := x509.ParseCertificate(certificateChainDER[index])
		if parseErr != nil || !bytes.Equal(certificate.Raw, certificateChainDER[index]) {
			return nil, errors.New("[client] Device certificate chain DER 无效")
		}
		chain[index] = append([]byte(nil), certificateChainDER[index]...)
	}
	expectedAddress := net.JoinHostPort(service.OverlayIP, strconv.FormatInt(service.Port, 10))
	if dial == nil {
		networkDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		dial = networkDialer.DialContext
	}
	clientCertificate := tls.Certificate{Certificate: chain, PrivateKey: identitySigner, Leaf: leaf}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: service.OverlayIP, NextProtos: []string{"http/1.1"},
		Certificates:       []tls.Certificate{clientCertificate},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPrivateDeviceTLS(state, service, roots, now())
		},
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("[client] private service dial 超出 exact overlay tuple")
			}
			raw, err := dial(ctx, "tcp", expectedAddress)
			if err != nil {
				return nil, err
			}
			connection := tls.Client(raw, tlsConfig.Clone())
			if err := connection.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return connection, nil
		},
	}
	baseURL := (&url.URL{Scheme: "https", Host: expectedAddress}).String()
	return &PrivateDeviceHTTPClient{client: &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("[client] private service 禁止 redirect")
		},
	}, baseURL: baseURL}, nil
}

func identitySignerPublicP256(signer crypto.Signer) (*ecdsa.PublicKey, bool) {
	if signer == nil {
		return nil, false
	}
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	return publicKey, ok && publicKey != nil && publicKey.Curve == elliptic.P256() &&
		publicKey.X != nil && publicKey.Y != nil &&
		publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y)
}

func verifyPrivateDeviceTLS(state tls.ConnectionState, service wire.PrivateControlServiceV1,
	roots *x509.CertPool, trustedTime time.Time) error {
	if trustedTime.IsZero() || roots == nil || state.Version != tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 {
		return errors.New("[client] private service TLS version/certificate/time 无效")
	}
	leaf := state.PeerCertificates[0]
	instant := trustedTime.UTC()
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		instant.Before(leaf.NotBefore) || !instant.Before(leaf.NotAfter) ||
		leaf.VerifyHostname(service.OverlayIP) != nil || len(leaf.UnhandledCriticalExtensions) != 0 ||
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("[client] private service leaf role/validity/overlay IP SAN 无效")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	if !containsString(service.SPKIPins, pin) {
		return errors.New("[client] private service SPKI 不在 certified pin set")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: service.OverlayIP, Roots: roots,
		Intermediates: intermediates, CurrentTime: instant,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("[client] private service leaf 不属于 exact internal CA profile")
	}
	return nil
}

func (client *PrivateDeviceHTTPClient) FetchDeviceConfigDelivery(ctx context.Context) (wire.DeviceConfigDeliveryV1, error) {
	if client == nil || client.client == nil || ctx == nil {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[client] private config client/context 缺失")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.baseURL+"/private/v2/device/config", nil)
	if err != nil {
		return wire.DeviceConfigDeliveryV1{}, err
	}
	request.Header.Set("Accept", wire.DeviceConfigDeliveryMediaTypeV1)
	response, err := client.client.Do(request)
	if err != nil {
		return wire.DeviceConfigDeliveryV1{}, fmt.Errorf("[client] private device_config 请求失败: %w", err)
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil ||
		mediaType != wire.DeviceConfigDeliveryMediaTypeV1 || response.Header.Get("Content-Encoding") != "" ||
		response.ContentLength > MaximumPrivateDeviceViewBytes {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return wire.DeviceConfigDeliveryV1{}, errors.New("[client] private device_config 响应状态/类型/大小无效")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumPrivateDeviceViewBytes+1))
	if err != nil || len(body) == 0 || len(body) > MaximumPrivateDeviceViewBytes {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[client] private device_config 响应读取/大小无效")
	}
	var delivery wire.DeviceConfigDeliveryV1
	canonical, err := wire.DecodeStrict(body, MaximumPrivateDeviceViewBytes, &delivery)
	if err != nil || !bytes.Equal(canonical, body) {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[client] private Device delivery 不是 exact canonical wire")
	}
	return delivery, nil
}

func (client *PrivateDeviceHTTPClient) PostDeviceReport(ctx context.Context,
	envelope *wire.DeviceReportEnvelopeV2) error {
	_, err := client.PostDeviceReportWithObservations(ctx, envelope)
	return err
}

func (client *PrivateDeviceHTTPClient) PostDeviceReportWithObservations(ctx context.Context,
	envelope *wire.DeviceReportEnvelopeV2) ([]json.RawMessage, error) {
	if client == nil || client.client == nil || ctx == nil || envelope == nil {
		return nil, errors.New("[client] private report client/context/envelope 缺失")
	}
	body, err := wire.MarshalCanonical(envelope)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/private/v2/device/report", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", wire.DeviceReportReceiptMediaTypeV1)
	response, err := client.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("[client] private device_report 请求失败: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body,
		wire.MaximumDeviceReportReceiptBytes+1))
	if readErr != nil || len(responseBody) > wire.MaximumDeviceReportReceiptBytes ||
		response.Header.Get("Content-Encoding") != "" {
		return nil, fmt.Errorf("[client] private device_report 响应无效: status=%d", response.StatusCode)
	}
	if response.StatusCode == http.StatusNoContent && len(responseBody) == 0 {
		return nil, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != wire.DeviceReportReceiptMediaTypeV1 {
		return nil, fmt.Errorf("[client] private device_report 未接受: status=%d", response.StatusCode)
	}
	receipt, err := wire.DecodeDeviceReportReceipt(responseBody, envelope)
	if err != nil {
		return nil, err
	}
	return receipt.Observations, nil
}

func (client *PrivateDeviceHTTPClient) CloseIdleConnections() {
	if client != nil && client.client != nil {
		client.client.CloseIdleConnections()
	}
}
