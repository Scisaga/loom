// Package loomcore exposes the deliberately small, gomobile-compatible edge
// between the Android platform host and Loom's shared Go trust logic.
package loomcore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const bindingVersion = "android-stage3-v1"

var oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificationRequest struct {
	Info               certificationRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// Version lets the Kotlin host prove that the expected Go binding was loaded.
func Version() string { return bindingVersion }

// VerifySignedConfig reuses the same Ed25519 verification implementation as
// signed current. The stage-1 host uses it for its bundled fixture; enrollment
// and durable generation-floor handling arrive in issue #2.
func VerifySignedConfig(config, signature, publicKey []byte) error {
	if len(signature) == 0 {
		return errors.New("快照没有签名")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥长度不对:%d", len(publicKey))
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), config, signature) {
		return errors.New("签名校验失败 —— 这份快照不是用可信密钥签的,或已被篡改")
	}
	return nil
}

// VerifyP256Signature verifies Android Keystore SHA256withECDSA output without
// ever accepting private key material across the binding.
func VerifyP256Signature(publicKeySPKI, message, signatureDER []byte) error {
	key, err := x509.ParsePKIXPublicKey(publicKeySPKI)
	if err != nil {
		return fmt.Errorf("解析设备公钥:%w", err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("设备公钥必须是 ECDSA P-256")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signatureDER) {
		return errors.New("设备签名校验失败")
	}
	return nil
}

// PrepareCSR returns an RFC 2986 CertificationRequestInfo. Android signs these
// exact bytes with SHA256withECDSA in Keystore, so the identity private key is
// non-exportable from its first use onward.
func PrepareCSR(requestID string, publicKeySPKI []byte) ([]byte, error) {
	if err := validateRequestID(requestID); err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(publicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 设备公钥:%w", err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("[§4.3 设备绑定] CSR 公钥必须是 ECDSA P-256")
	}

	publicKeyRaw, err := rawASN1(publicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR SPKI:%w", err)
	}
	subjectDER, err := asn1.Marshal(pkix.Name{CommonName: requestID}.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("编码 CSR subject:%w", err)
	}
	subjectRaw, err := rawASN1(subjectDER)
	if err != nil {
		return nil, err
	}
	infoDER, err := asn1.Marshal(certificationRequestInfo{
		Version: 0, Subject: subjectRaw, PublicKey: publicKeyRaw,
		RawAttributes: []asn1.RawValue{},
	})
	if err != nil {
		return nil, fmt.Errorf("编码 CSR 待签名信息:%w", err)
	}
	return infoDER, nil
}

// AssembleCSR validates the external signature and returns the sole PEM CSR
// accepted by enrollment. No private key crosses this API.
func AssembleCSR(infoDER, signatureDER []byte) ([]byte, error) {
	info, err := parseCSRInfo(infoDER)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(info.PublicKey.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 公钥:%w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if err := VerifyP256Signature(spki, infoDER, signatureDER); err != nil {
		return nil, fmt.Errorf("CSR %w", err)
	}
	der, err := asn1.Marshal(certificationRequest{
		Info: info,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidECDSAWithSHA256,
		},
		SignatureValue: asn1.BitString{Bytes: signatureDER, BitLength: len(signatureDER) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("组装 CSR:%w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("[§4.3 设备绑定] 组装后的 CSR 签名无效")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func parseCSRInfo(infoDER []byte) (certificationRequestInfo, error) {
	var info certificationRequestInfo
	rest, err := asn1.Unmarshal(infoDER, &info)
	if err != nil || len(rest) != 0 || info.Version != 0 || len(info.RawAttributes) != 0 {
		return info, errors.New("[§4.3 设备绑定] CSR 待签名信息无效")
	}
	var name pkix.RDNSequence
	rest, err = asn1.Unmarshal(info.Subject.FullBytes, &name)
	if err != nil || len(rest) != 0 {
		return info, errors.New("[§4.3 设备绑定] CSR subject 无效")
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&name)
	if err := validateRequestID(subject.CommonName); err != nil || len(subject.Names) != 1 {
		return info, errors.New("[§4.3 设备绑定] CSR subject 必须只有 request_id")
	}
	return info, nil
}

func rawASN1(der []byte) (asn1.RawValue, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil || len(rest) != 0 {
		return value, errors.New("ASN.1 DER 含多余数据")
	}
	return value, nil
}

func validateRequestID(requestID string) error {
	if requestID == "" || len(requestID) > 128 || strings.TrimSpace(requestID) != requestID ||
		strings.IndexFunc(requestID, unicode.IsControl) >= 0 {
		return errors.New("[§4.3 设备绑定] request_id 无效")
	}
	return nil
}
