package report

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

// 所有签名附件必须来自同一个节点身份；调用方先校验原 CA 与签名，
// 再将此公钥用于已有服务器心跳转述，不能由附带证书自行建立信任。
func observationPublicKey(o *Observation) (string, error) {
	if o == nil {
		return "", errors.New("观测为空")
	}
	var certs []string
	if o.Attest != nil {
		certs = append(certs, o.Attest.Cert)
	}
	if o.AttestExtended != nil {
		certs = append(certs, o.AttestExtended.Cert)
	}
	if o.SelfCheck != nil {
		certs = append(certs, o.SelfCheck.Cert)
	}
	if o.Traffic != nil {
		certs = append(certs, o.Traffic.Cert)
	}
	if o.LinkMetrics != nil {
		certs = append(certs, o.LinkMetrics.Cert)
	}
	if len(certs) == 0 {
		return "", errors.New("观测没有证书")
	}
	want := ""
	for _, certPEM := range certs {
		block, rest := pemDecodeCertificate(certPEM)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return "", errors.New("观测证书不是单个 PEM certificate")
		}
		certificate, err := x509.ParseCertificate(block)
		if err != nil {
			return "", errors.New("观测证书格式错误")
		}
		key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return "", errors.New("观测证书必须使用 ECDSA P-256")
		}
		spki, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", errors.New("观测公钥无法编码")
		}
		encoded := base64.RawStdEncoding.EncodeToString(spki)
		if want == "" {
			want = encoded
		} else if encoded != want {
			return "", errors.New("观测附件使用了不同身份")
		}
	}
	return want, nil
}

// 服务器观测身份必须是单个证书，不能把尾随证书当作同一个签名来源。
func pemDecodeCertificate(body string) ([]byte, []byte) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(body)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, rest
	}
	return block.Bytes, rest
}
