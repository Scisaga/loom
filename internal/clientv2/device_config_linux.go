//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

const maximumPrivateDeviceViewBytes = 32 << 20

type LinuxDeviceViewSyncOptions struct {
	StatePath           string
	IdentityPath        string
	Directory           wire.ControlServiceDirectoryV1
	PinnedDirectoryHash string
	ControlSet          wire.ControlSetV1
	PreviousControlSet  *wire.ControlSetV1
	ServiceID           string
	Roots               *x509.CertPool
	Dial                TunnelDialContext
	Now                 func() time.Time
	Timeout             time.Duration
	MirrorFetcher       MirrorFetcher
}

// SyncLinuxDeviceView 经已安装的正式 Device mTLS identity 访问 certified private
// device_config endpoint，并在返回后重新验证 QC/Merkle/identity/floors 才提交 LKG。
// public Nginx、bootstrap capability 和调用方自报 Device ID 都不能进入这条路径。
func SyncLinuxDeviceView(ctx context.Context,
	options LinuxDeviceViewSyncOptions) (wire.ClientFloorsV2, error) {
	if ctx == nil {
		return wire.ClientFloorsV2{}, errors.New("[Linux config] context 缺失")
	}
	store, err := Open(options.StatePath)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	current := store.Envelope()
	installation := store.Installation()
	if current == nil || installation == nil || current.Payload.Active == nil {
		return store.Floors(), errors.New("[Linux config] 正式 active enrollment/LKG 尚未安装")
	}
	currentSet, currentPreviousSet := store.ControlSets()
	if currentSet == nil {
		// 兼容尚未持久化 authority 的旧 LKG；首次成功 delivery 后即迁入 durable state。
		currentSet, currentPreviousSet = &options.ControlSet, options.PreviousControlSet
	}
	directory, directoryHash, roots := options.Directory, options.PinnedDirectoryHash, options.Roots
	installedContext, foundInstalledContext, err := installedLinuxPrivateControlContext(
		installation, store.Floors(), current.Payload.DeviceID)
	if err != nil {
		return store.Floors(), err
	}
	if foundInstalledContext {
		directory, directoryHash, roots = installedContext.directory,
			installedContext.directoryHash, installedContext.roots
	} else if err := VerifyControlServiceDirectory(&directory, directoryHash,
		&current.SignedCurrent.Head, currentSet, currentPreviousSet); err != nil {
		return store.Floors(), err
	}
	service, err := SelectPrivateControlService(&directory, "device_config", options.ServiceID)
	if err != nil {
		return store.Floors(), err
	}
	identity, err := LoadEnrollmentIdentityForResume(options.IdentityPath)
	if err != nil {
		return store.Floors(), err
	}
	identityKey, wrappingPrivate, err := identity.keys()
	if err != nil {
		return store.Floors(), err
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil || identityHash != installation.IdentityKeyHash ||
		identityHash != current.Payload.Active.IdentitySPKIHash {
		return store.Floors(), errors.New("[Linux config] 本机 identity 与 durable installation/view 不一致")
	}
	certificateDER, err := installation.certificateDER()
	if err != nil {
		return store.Floors(), err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil || certificateHash != installation.DeviceCertificateHash {
		return store.Floors(), errors.New("[Linux config] Device certificate 与 durable installation 不一致")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	client, err := newPrivateDeviceHTTPClient(service, "device_config", certificateDER, identityKey,
		roots, options.Dial, now, options.Timeout)
	if err != nil {
		return store.Floors(), err
	}
	defer client.CloseIdleConnections()
	delivery, err := client.fetchDeviceConfigDelivery(ctx)
	if err != nil {
		return store.Floors(), err
	}
	verified, err := wire.VerifyDeviceConfigDeliveryFromProtected(&delivery, current,
		store.Floors(), currentSet, currentPreviousSet, current.Payload.DeviceID, identityHash)
	if err != nil {
		return store.Floors(), err
	}
	finalEnvelope := verified.Envelope()
	configChanged, secretsChanged := changedInstalledArtifactRefs(current, &finalEnvelope)
	var configs *[]InstalledConfigV1
	var credentials *[]InstalledSecretV1
	if finalEnvelope.Payload.State == "active" {
		if configChanged {
			if installation.DistributionMirrors == nil {
				return store.Floors(), errors.New("[Linux config] durable distribution mirrors 缺失")
			}
			fetcher := options.MirrorFetcher
			if fetcher.Timeout == 0 {
				fetcher.Timeout = options.Timeout
			}
			fetcher, err = installedLinuxMirrorFetcher(installation, fetcher)
			if err != nil {
				return store.Floors(), err
			}
			installed, err := FetchLinuxDeviceConfigArtifacts(ctx,
				installation.DistributionMirrors, finalEnvelope.Payload.Active.ConfigArtifactRefs,
				fetcher)
			if err != nil {
				return store.Floors(), err
			}
			configs = &installed
		}
		if secretsChanged {
			refs, err := decodeLinuxSecretArtifactRefs(finalEnvelope.SecretArtifactRefs)
			if err != nil {
				return store.Floors(), err
			}
			installed, err := installLinuxSecrets(refs, delivery.SecretEnvelopes,
				current.Payload.DeviceID, identity.WrappingPublicKeySPKI, wrappingPrivate)
			if err != nil {
				return store.Floors(), err
			}
			credentials = &installed
		}
	}
	return store.AcceptDeviceConfigDeliveryWithArtifacts(&delivery, &options.ControlSet,
		options.PreviousControlSet, current.Payload.DeviceID, identityHash, configs, credentials)
}

// VerifyControlServiceDirectory 要求 root-owned 配置里的 exact directory hash pin，
// 并另行验证其 parent Head/QC 与 ControlSet。Head QC 本身不承诺
// directory bytes，因此不能省略 pin 或把它与 config_qc 混为一谈。
func VerifyControlServiceDirectory(directory *wire.ControlServiceDirectoryV1,
	pinnedDirectoryHash string, head *wire.HeadEntryV2, set, previousSet *wire.ControlSetV1) error {
	if directory == nil || head == nil || set == nil {
		return errors.New("[Linux config] directory authority 不完整")
	}
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return err
	}
	directoryHash, err := wire.ControlServiceDirectoryHash(directory)
	if err != nil || directoryHash != pinnedDirectoryHash {
		return errors.New("[Linux config] private directory 与 root-owned hash pin 不一致")
	}
	setHash, err := wire.ControlSetHash(set)
	if err != nil || directory.ClusterID != head.Body.Payload.ClusterID ||
		directory.ClusterID != set.ClusterID || directory.ParentHeadHash != head.HeadHash ||
		directory.ControlSetHash != setHash || head.Body.Payload.ControlSetHash != setHash {
		return errors.New("[Linux config] directory 未绑定本机 certified Head/ControlSet")
	}
	if err := wire.VerifyConfigQCAuthority(directory.ParentHeadHash, directory.ConfigQC,
		head, set, previousSet); err != nil {
		return err
	}
	return nil
}

func SelectPrivateControlService(directory *wire.ControlServiceDirectoryV1,
	role, serviceID string) (wire.PrivateControlServiceV1, error) {
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return wire.PrivateControlServiceV1{}, err
	}
	var match *wire.PrivateControlServiceV1
	for index := range directory.Services {
		candidate := &directory.Services[index]
		if candidate.Role != role || serviceID != "" && candidate.ServiceID != serviceID {
			continue
		}
		if match != nil {
			return wire.PrivateControlServiceV1{}, errors.New("[Linux config] private service 选择不唯一")
		}
		copy := *candidate
		copy.SPKIPins = append([]string(nil), candidate.SPKIPins...)
		copy.AuthorizedSubjectProfiles = append([]string(nil), candidate.AuthorizedSubjectProfiles...)
		match = &copy
	}
	if match == nil {
		return wire.PrivateControlServiceV1{}, errors.New("[Linux config] certified directory 缺目标 private service")
	}
	return *match, nil
}

type privateDeviceHTTPClient struct {
	client  *http.Client
	baseURL string
}

func newPrivateDeviceHTTPClient(service wire.PrivateControlServiceV1, expectedRole string,
	certificateDER []byte, identityKey *ecdsa.PrivateKey, roots *x509.CertPool, dial TunnelDialContext,
	now func() time.Time, timeout time.Duration) (*privateDeviceHTTPClient, error) {
	if err := wire.ValidatePrivateControlService(&service); err != nil {
		return nil, err
	}
	if service.Role != expectedRole || !containsString([]string{"device_config", "device_report"}, expectedRole) ||
		identityKey == nil || identityKey.Curve != elliptic.P256() || roots == nil ||
		now == nil || timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("[Linux config] mTLS identity/internal CA/time/timeout 无效")
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(leaf.Raw, certificateDER) || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		len(leaf.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("[Linux config] Device certificate profile 无效")
	}
	instant := now().UTC()
	if instant.IsZero() || instant.Before(leaf.NotBefore) || !instant.Before(leaf.NotAfter) {
		return nil, errors.New("[Linux config] Device certificate 已过期或尚未生效")
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil || !bytes.Equal(publicSPKI, leaf.RawSubjectPublicKeyInfo) {
		return nil, errors.New("[Linux config] Device certificate/private key 不匹配")
	}
	expectedAddress := net.JoinHostPort(service.OverlayIP, strconv.FormatInt(service.Port, 10))
	if dial == nil {
		networkDialer := &net.Dialer{Timeout: timeout}
		dial = networkDialer.DialContext
	}
	clientCertificate := tls.Certificate{Certificate: [][]byte{append([]byte(nil), certificateDER...)},
		PrivateKey: identityKey, Leaf: leaf}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: service.OverlayIP, NextProtos: []string{"http/1.1"},
		Certificates:       []tls.Certificate{clientCertificate},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPrivateDeviceServiceTLS(state, service, roots, now())
		},
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("[Linux config] private service dial 超出 exact overlay tuple")
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
	return &privateDeviceHTTPClient{client: &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("[Linux config] private service 禁止 redirect")
		}}, baseURL: baseURL}, nil
}

func (client *privateDeviceHTTPClient) fetchDeviceConfigDelivery(ctx context.Context) (wire.DeviceConfigDeliveryV1, error) {
	if client == nil || client.client == nil {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[Linux config] private client 缺失")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.baseURL+"/private/v2/device/config", nil)
	if err != nil {
		return wire.DeviceConfigDeliveryV1{}, err
	}
	request.Header.Set("Accept", wire.DeviceConfigDeliveryMediaTypeV1)
	response, err := client.client.Do(request)
	if err != nil {
		return wire.DeviceConfigDeliveryV1{}, fmt.Errorf("[Linux config] private device_config 请求失败: %w", err)
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != wire.DeviceConfigDeliveryMediaTypeV1 ||
		response.Header.Get("Content-Encoding") != "" || response.ContentLength > maximumPrivateDeviceViewBytes {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return wire.DeviceConfigDeliveryV1{}, errors.New("[Linux config] private device_config 响应状态/类型/大小无效")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumPrivateDeviceViewBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPrivateDeviceViewBytes {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[Linux config] private device_config 响应读取/大小无效")
	}
	var delivery wire.DeviceConfigDeliveryV1
	canonical, err := wire.DecodeStrict(body, maximumPrivateDeviceViewBytes, &delivery)
	if err != nil || !bytes.Equal(canonical, body) {
		return wire.DeviceConfigDeliveryV1{}, errors.New("[Linux config] private Device delivery 不是 exact canonical wire")
	}
	return delivery, nil
}

func (client *privateDeviceHTTPClient) CloseIdleConnections() {
	if client != nil && client.client != nil {
		client.client.CloseIdleConnections()
	}
}

func verifyPrivateDeviceServiceTLS(state tls.ConnectionState, service wire.PrivateControlServiceV1,
	roots *x509.CertPool, trustedTime time.Time) error {
	if trustedTime.IsZero() || roots == nil || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return errors.New("[Linux config] private service TLS version/certificate/time 无效")
	}
	leaf := state.PeerCertificates[0]
	instant := trustedTime.UTC()
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		instant.Before(leaf.NotBefore) || !instant.Before(leaf.NotAfter) ||
		leaf.VerifyHostname(service.OverlayIP) != nil || len(leaf.UnhandledCriticalExtensions) != 0 ||
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("[Linux config] private service leaf role/validity/overlay IP SAN 无效")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	if !containsString(service.SPKIPins, pin) {
		return errors.New("[Linux config] private service SPKI 不在 certified pin set")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: service.OverlayIP, Roots: roots,
		Intermediates: intermediates, CurrentTime: instant,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("[Linux config] private service leaf 不属于 exact internal CA profile")
	}
	return nil
}
