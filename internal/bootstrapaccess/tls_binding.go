package bootstrapaccess

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

// certifiedTLSConfig 把实际证书选择也收窄到 listener generation 的 exact
// FQDN/SPKI pin set。仅检查“证书覆盖域名”不足以阻止本机换上一张未发布的新 key。
func certifiedTLSConfig(config *tls.Config,
	binding VerifiedBootstrapListenerV1) (*tls.Config, error) {
	return prepareCertifiedTLSConfig(config, binding, true)
}

func prepareCertifiedTLSConfig(config *tls.Config, binding VerifiedBootstrapListenerV1,
	allowConfigSelection bool) (*tls.Config, error) {
	if config == nil || !binding.valid() {
		return nil, errors.New("[bootstrap ingress] TLS config/listener authority 无效")
	}
	base := config.Clone()
	originalGetCertificate := base.GetCertificate
	originalGetConfig := base.GetConfigForClient
	if len(base.Certificates) == 0 && originalGetCertificate == nil &&
		(!allowConfigSelection || originalGetConfig == nil) {
		return nil, errors.New("[bootstrap ingress] TLS certificate 缺失")
	}
	for index := range base.Certificates {
		if !certificateMatchesListener(&base.Certificates[index], binding) {
			return nil, errors.New("[bootstrap ingress] fixed certificate 不属于 certified listener identity")
		}
	}
	if originalGetCertificate != nil {
		base.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello == nil || hello.ServerName != binding.ServerName() {
				return nil, errors.New("[bootstrap ingress] TLS SNI 不属于 certified listener")
			}
			certificate, err := originalGetCertificate(hello)
			if err != nil || certificate == nil {
				return certificate, err
			}
			if !certificateMatchesListener(certificate, binding) {
				return nil, errors.New("[bootstrap ingress] dynamic certificate 不属于 certified listener identity")
			}
			return certificate, nil
		}
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil || hello.ServerName != binding.ServerName() {
			return nil, errors.New("[bootstrap ingress] TLS SNI 不属于 certified listener")
		}
		if originalGetConfig == nil || !allowConfigSelection {
			return nil, nil
		}
		selected, err := originalGetConfig(hello)
		if err != nil || selected == nil {
			return selected, err
		}
		return prepareCertifiedTLSConfig(selected, binding, false)
	}
	base.MinVersion = tls.VersionTLS13
	base.MaxVersion = tls.VersionTLS13
	base.ClientAuth = tls.NoClientCert
	return base, nil
}

func certificateMatchesListener(certificate *tls.Certificate,
	binding VerifiedBootstrapListenerV1) bool {
	if certificate == nil || certificate.PrivateKey == nil || len(certificate.Certificate) == 0 {
		return false
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return false
		}
	}
	if leaf.VerifyHostname(binding.ServerName()) != nil {
		return false
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	for _, allowed := range binding.projection.SPKIPins {
		if allowed == pin {
			return true
		}
	}
	return false
}
