//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"time"

	"loom/internal/enrollmenttransport"
	"loom/internal/wire"
)

// LinuxBootstrapIngressAccess 把 bootstrap listener 绑定到本机已经迁移并持久化的
// Device 身份。能力授权逐连接从私有 device_config 服务读取；Enrollment relay
// 则只允许 certified directory 中的 exact overlay tuple。
type LinuxBootstrapIngressAccess struct {
	config     *PrivateDeviceHTTPClient
	dial       TunnelDialContext
	identity   *ecdsa.PrivateKey
	ingressSet string
}

// OpenLinuxBootstrapIngressAccess 不创建身份、不改写 LKG，也不接受操作者提供的
// service 地址。directory、internal CA 与 Device certificate 都来自同一 durable
// installation；任一绑定不成立便保持 listener 关闭。
func OpenLinuxBootstrapIngressAccess(statePath, identityPath, expectedDeviceID,
	expectedIngressSetHash string, now func() time.Time,
	timeout time.Duration) (*LinuxBootstrapIngressAccess, error) {
	if expectedDeviceID == "" || now == nil || timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("[bootstrap ingress] Device/time/timeout 无效")
	}
	if _, err := wire.ParseHash(expectedIngressSetHash); err != nil {
		return nil, errors.New("[bootstrap ingress] ingress set hash 无效")
	}
	store, err := Open(statePath)
	if err != nil {
		return nil, err
	}
	envelope, installation := store.Envelope(), store.Installation()
	if envelope == nil || installation == nil || envelope.Payload.State != "active" ||
		envelope.Payload.Active == nil || envelope.Payload.DeviceID != expectedDeviceID ||
		!containsString(envelope.Payload.Active.Responsibilities.Values, "forward") {
		return nil, errors.New("[bootstrap ingress] 本机不是当前 active forward Device")
	}
	installed, found, err := installedLinuxPrivateControlContext(installation,
		store.Floors(), expectedDeviceID)
	if err != nil {
		return nil, err
	}
	if !found || installed.roots == nil {
		return nil, errors.New("[bootstrap ingress] durable private-control credential 缺失")
	}
	if err := VerifyPrivateControlDirectory(&installed.directory, installed.directoryHash,
		&installed.parentHead, &installed.controlSet, installed.previousSet); err != nil {
		return nil, err
	}
	profileID, configService, enrollmentService, err := selectBootstrapIngressPrivateServices(&installed.directory)
	if err != nil {
		return nil, err
	}
	identity, err := LoadEnrollmentIdentityForResume(identityPath)
	if err != nil {
		return nil, err
	}
	identityKey, _, err := identity.keys()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*LinuxBootstrapIngressAccess, error) {
		clearP256PrivateKey(identityKey)
		return nil, cause
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil || identityHash != installation.IdentityKeyHash ||
		identityHash != envelope.Payload.Active.IdentitySPKIHash {
		return fail(errors.New("[bootstrap ingress] 本机 signer 与 durable Device 身份不一致"))
	}
	certificateDER, err := installation.certificateDER()
	if err != nil {
		return fail(err)
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil || certificateHash != installation.DeviceCertificateHash {
		return fail(errors.New("[bootstrap ingress] Device certificate 与 durable installation 不一致"))
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return fail(errors.New("[bootstrap ingress] Device certificate 无效"))
	}
	identitySPKI, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, identitySPKI) {
		return fail(errors.New("[bootstrap ingress] Device certificate/private key 不匹配"))
	}
	configDial, err := installedLinuxDeviceDial(installation, expectedDeviceID, configService, timeout)
	if err != nil {
		return fail(err)
	}
	configClient, err := NewPrivateDeviceHTTPClient(configService, "device_config", profileID,
		[][]byte{certificateDER}, identityKey, installed.roots, configDial, now, timeout)
	if err != nil {
		return fail(err)
	}
	clientCertificate := tls.Certificate{Certificate: [][]byte{append([]byte(nil), certificateDER...)},
		PrivateKey: identityKey, Leaf: leaf}
	expectedAddress := net.JoinHostPort(enrollmentService.OverlayIP,
		strconv.FormatInt(enrollmentService.TCPPort, 10))
	networkDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	rawDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if !bootstrapEnrollmentTCPNetwork(network) || address != expectedAddress {
			return nil, errors.New("[bootstrap ingress] Enrollment dial 超出 certified overlay tuple")
		}
		return networkDialer.DialContext(ctx, network, address)
	}
	configureTLS := func(_ context.Context, address string) (*tls.Config, error) {
		if address != expectedAddress {
			return nil, errors.New("[bootstrap ingress] Enrollment TLS 超出 certified overlay tuple")
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: enrollmentService.OverlayIP, Certificates: []tls.Certificate{clientCertificate},
			InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
				return verifyPrivateEnrollmentTLS(state, enrollmentService, installed.roots, now().UTC())
			}}, nil
	}
	return &LinuxBootstrapIngressAccess{config: configClient,
		dial: TunnelDialContext(enrollmenttransport.Dialer(configureTLS, rawDial)), identity: identityKey,
		ingressSet: expectedIngressSetHash}, nil
}

func bootstrapEnrollmentTCPNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}

func selectBootstrapIngressPrivateServices(directory *wire.ControlServiceDirectoryV1) (string,
	wire.PrivateControlServiceV1, wire.PrivateEnrollmentServiceRefV1, error) {
	var config, enroll *wire.PrivateControlServiceV1
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{}, err
	}
	for index := range directory.Services {
		service := &directory.Services[index]
		switch service.Role {
		case "device_config":
			if config != nil {
				return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{},
					errors.New("[bootstrap ingress] device_config service 不唯一")
			}
			copy := *service
			config = &copy
		case "enroll":
			if enroll != nil {
				return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{},
					errors.New("[bootstrap ingress] Enrollment service 不唯一")
			}
			copy := *service
			enroll = &copy
		}
	}
	if config == nil || enroll == nil {
		return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{},
			errors.New("[bootstrap ingress] certified directory 缺配置或 Enrollment service")
	}
	profiles := make([]string, 0, 1)
	for _, profile := range config.AuthorizedSubjectProfiles {
		if containsString(enroll.AuthorizedSubjectProfiles, profile) {
			profiles = append(profiles, profile)
		}
	}
	if len(profiles) != 1 {
		return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{},
			errors.New("[bootstrap ingress] Device certificate profile 不能从私有目录唯一确定")
	}
	ref := wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: enroll.ServiceID,
		OverlayIP: enroll.OverlayIP, TCPPort: enroll.Port,
		InternalCAProfileRef:   enroll.CertificateProfileRef,
		ServerIdentitySPKIPins: append([]string(nil), enroll.SPKIPins...),
		ServiceGeneration:      directory.Generation}
	if err := wire.ValidatePrivateEnrollmentServiceRef(&ref); err != nil {
		return "", wire.PrivateControlServiceV1{}, wire.PrivateEnrollmentServiceRefV1{}, err
	}
	return profiles[0], *config, ref, nil
}

func clearP256PrivateKey(key *ecdsa.PrivateKey) {
	if key == nil {
		return
	}
	if key.D != nil {
		key.D.SetInt64(0)
	}
	key.X, key.Y = nil, nil
}

func (access *LinuxBootstrapIngressAccess) Resolve(ctx context.Context,
	lookup wire.BootstrapCapabilityLookupRequestV1) (wire.VerifiedBootstrapCapabilityV1, error) {
	if access == nil || access.config == nil || lookup.IngressSetHash != access.ingressSet {
		return wire.VerifiedBootstrapCapabilityV1{},
			errors.New("[bootstrap ingress] capability lookup 不属于本机 ingress set")
	}
	return access.config.ResolveBootstrapCapability(ctx, lookup)
}

func (access *LinuxBootstrapIngressAccess) DialContext(ctx context.Context,
	network, address string) (net.Conn, error) {
	if access == nil || access.dial == nil {
		return nil, errors.New("[bootstrap ingress] Enrollment relay 尚未配置")
	}
	return access.dial(ctx, network, address)
}

func (access *LinuxBootstrapIngressAccess) Close() {
	if access == nil {
		return
	}
	if access.config != nil {
		access.config.CloseIdleConnections()
	}
	clearP256PrivateKey(access.identity)
	access.config, access.dial, access.identity = nil, nil, nil
}
