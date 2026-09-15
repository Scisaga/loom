package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// capability 对 ingress 可见，只授权隧道；intent opening 另需客户端证明。
// 初次请求不传 token/key，恢复请求不依赖已过期 token（D115、D130、D131）。
type EnrollmentPreflightAuthorizationV1 struct {
	Mode              string `json:"mode"`
	TokenMAC          string `json:"token_mac,omitempty"`
	IdentityPublicKey string `json:"identity_public_key,omitempty"`
	ProofSignature    string `json:"proof_signature,omitempty"`
}

func EnrollmentPreflightAuthorizationMessage(request *EnrollmentIntentPreflightRequestV1) ([]byte, error) {
	if request == nil || request.Schema != 1 || !validIdentifier(request.ClusterID, 128) || !validIdentifier(request.InviteID, 128) {
		return nil, errors.New("[D131 Enrollment preflight] request identity 无效")
	}
	for _, hash := range []string{request.CertifiedInviteRecordHash, request.CapabilityID} {
		if _, err := ParseHash(hash); err != nil {
			return nil, err
		}
	}
	auth := request.Authorization
	switch auth.Mode {
	case "token_hmac_sha256":
		if auth.IdentityPublicKey != "" || auth.ProofSignature != "" {
			return nil, errors.New("[D131 Enrollment preflight] initial proof 字段混用")
		}
	case "identity_p256_sha256":
		if auth.TokenMAC != "" {
			return nil, errors.New("[D131 Enrollment preflight] resume 不接受 token proof")
		}
		if _, _, err := preflightIdentity(auth.IdentityPublicKey); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("[D131 Enrollment preflight] 缺少客户端授权证明")
	}
	unsigned := *request
	unsigned.Authorization.TokenMAC, unsigned.Authorization.ProofSignature = "", ""
	body, err := MarshalCanonical(unsigned)
	if err != nil {
		return nil, err
	}
	return Frame("loom-enrollment-preflight-authorization-v1", body)
}

func AuthorizeInitialEnrollmentPreflight(request EnrollmentIntentPreflightRequestV1, token string) (EnrollmentIntentPreflightRequestV1, error) {
	key, err := preflightMACBytes(token)
	if err != nil {
		return EnrollmentIntentPreflightRequestV1{}, err
	}
	request.Authorization = EnrollmentPreflightAuthorizationV1{Mode: "token_hmac_sha256"}
	message, err := EnrollmentPreflightAuthorizationMessage(&request)
	if err != nil {
		return EnrollmentIntentPreflightRequestV1{}, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	request.Authorization.TokenMAC = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return request, nil
}

func VerifyInitialEnrollmentPreflight(request *EnrollmentIntentPreflightRequestV1, token string) error {
	if request == nil || request.Authorization.Mode != "token_hmac_sha256" {
		return errors.New("[D131 Enrollment preflight] initial proof 类型无效")
	}
	if _, err := EnrollmentIntentPreflightRequestHash(request); err != nil {
		return err
	}
	expected, err := AuthorizeInitialEnrollmentPreflight(*request, token)
	if err != nil {
		return err
	}
	want, _ := preflightMACBytes(expected.Authorization.TokenMAC)
	got, err := preflightMACBytes(request.Authorization.TokenMAC)
	if err != nil || !hmac.Equal(got, want) {
		return errors.New("[D131 Enrollment preflight] 客户端未证明持有邀请秘密")
	}
	return nil
}

func AuthorizeResumeEnrollmentPreflight(request EnrollmentIntentPreflightRequestV1, signer crypto.Signer) (EnrollmentIntentPreflightRequestV1, error) {
	public, ok := signerPublicP256(signer)
	if !ok {
		return EnrollmentIntentPreflightRequestV1{}, errors.New("[D130 Enrollment preflight] resume signer 必须是原 P-256 key")
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return EnrollmentIntentPreflightRequestV1{}, err
	}
	request.Authorization = EnrollmentPreflightAuthorizationV1{Mode: "identity_p256_sha256", IdentityPublicKey: base64.RawURLEncoding.EncodeToString(spki)}
	message, err := EnrollmentPreflightAuthorizationMessage(&request)
	if err != nil {
		return EnrollmentIntentPreflightRequestV1{}, err
	}
	request.Authorization.ProofSignature, err = signP256LowSWithSigner(message, signer, public)
	return request, err
}

func VerifyResumeEnrollmentPreflight(request *EnrollmentIntentPreflightRequestV1, identityHash string) error {
	if request == nil || request.Authorization.Mode != "identity_p256_sha256" {
		return errors.New("[D130 Enrollment preflight] resume proof 类型无效")
	}
	message, err := EnrollmentPreflightAuthorizationMessage(request)
	if err != nil {
		return err
	}
	public, spki, err := preflightIdentity(request.Authorization.IdentityPublicKey)
	if err != nil {
		return err
	}
	hash, err := HashBytes(DomainEnrollmentIdentitySPKI, spki)
	if err != nil || hash != identityHash {
		return errors.New("[D130 Enrollment preflight] resume key 未绑定原 reservation")
	}
	return verifyP256LowS(message, public, request.Authorization.ProofSignature)
}

func preflightIdentity(encoded string) (*ecdsa.PublicKey, []byte, error) {
	spki, err := decodeCanonicalBase64URL(encoded)
	if err != nil {
		return nil, nil, err
	}
	public, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, nil, err
	}
	key, ok := public.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, nil, errors.New("[D130 Enrollment preflight] identity 不是 P-256")
	}
	return key, spki, nil
}

func preflightMACBytes(value string) ([]byte, error) {
	raw, err := decodeCanonicalBase64URL(value)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("[D131 Enrollment preflight] token/MAC 必须是 32-byte canonical base64url")
	}
	return raw, nil
}
