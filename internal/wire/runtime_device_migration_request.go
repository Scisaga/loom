package wire

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// RuntimeDeviceMigrationRequestV1 由已有身份签名，只授权原地迁移所需的
// wrapping public key/floor 输入，不是 Enrollment token 或新的 Device。
type RuntimeDeviceMigrationRequestBodyV1 struct {
	Schema             int             `json:"schema"`
	DeviceID           string          `json:"device_id"`
	Platform           string          `json:"platform"`
	PlatformKeyHash    string          `json:"platform_key_hash"`
	IdentitySPKIDER    string          `json:"identity_spki_der"`
	WrappingSPKIDER    string          `json:"wrapping_spki_der"`
	WrappingKeyProfile string          `json:"wrapping_key_profile"`
	LegacyFloor        json.RawMessage `json:"legacy_floor"`
}

type RuntimeDeviceMigrationRequestV1 struct {
	Schema    int                                 `json:"schema"`
	Body      RuntimeDeviceMigrationRequestBodyV1 `json:"body"`
	Signature string                              `json:"signature"`
}

func RuntimeDeviceMigrationRequestMessage(body *RuntimeDeviceMigrationRequestBodyV1) ([]byte, error) {
	if body == nil || body.Schema != 1 || !validIdentifier(body.DeviceID, 128) ||
		!oneOf(body.Platform, "android", "windows-desktop", "linux-server") {
		return nil, errors.New("[设备迁移] 请求设备或平台无效")
	}
	if _, err := ParseHash(body.PlatformKeyHash); err != nil {
		return nil, err
	}
	identityDER, err := decodeCanonicalBase64URL(body.IdentitySPKIDER)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(identityDER)
	identity, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || identity.Curve != elliptic.P256() {
		return nil, errors.New("[设备迁移] 原身份不是 P-256")
	}
	wrappingDER, err := decodeCanonicalBase64URL(body.WrappingSPKIDER)
	if err != nil || bytes.Equal(identityDER, wrappingDER) {
		return nil, errors.New("[设备迁移] wrapping key 必须独立于 identity")
	}
	wrapping, err := x509.ParsePKIXPublicKey(wrappingDER)
	if err != nil {
		return nil, err
	}
	switch body.WrappingKeyProfile {
	case "p256-keystore-ecdh-v1", "p256-root-only-pkcs8-ecdh-v1":
		key, ok := wrapping.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("[设备迁移] wrapping key 不是 P-256")
		}
		if (body.Platform == "linux-server") != (body.WrappingKeyProfile == "p256-root-only-pkcs8-ecdh-v1") {
			return nil, errors.New("[设备迁移] wrapping key 存储契约与平台不匹配")
		}
	case "rsa2048-keystore-decrypt-v1":
		key, ok := wrapping.(*rsa.PublicKey)
		if body.Platform != "android" || !ok || key.N.BitLen() != 2048 || key.E != 65537 {
			return nil, errors.New("[设备迁移] RSA wrapping profile 无效")
		}
	default:
		return nil, errors.New("[设备迁移] wrapping profile 无效")
	}
	canonical, err := CanonicalizeStrict(body.LegacyFloor)
	if err != nil || !bytes.Equal(canonical, body.LegacyFloor) || len(canonical) < 2 || canonical[0] != '{' {
		return nil, errors.New("[设备迁移] 本机 floor 必须是完整规范对象")
	}
	raw, err := MarshalCanonical(body)
	if err != nil {
		return nil, err
	}
	return Frame("loom-runtime-device-migration-request-v1", raw)
}

func SignRuntimeDeviceMigrationRequest(body RuntimeDeviceMigrationRequestBodyV1, signer crypto.Signer) (RuntimeDeviceMigrationRequestV1, error) {
	public, ok := signerPublicP256(signer)
	if !ok {
		return RuntimeDeviceMigrationRequestV1{}, errors.New("[设备迁移] 原身份签名器缺失")
	}
	message, err := RuntimeDeviceMigrationRequestMessage(&body)
	if err != nil {
		return RuntimeDeviceMigrationRequestV1{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || base64.RawURLEncoding.EncodeToString(publicDER) != body.IdentitySPKIDER {
		return RuntimeDeviceMigrationRequestV1{}, errors.New("[设备迁移] 请求使用了不同身份签名")
	}
	signature, err := signP256LowSWithSigner(message, signer, public)
	if err != nil {
		return RuntimeDeviceMigrationRequestV1{}, err
	}
	return RuntimeDeviceMigrationRequestV1{Schema: 1, Body: body, Signature: signature}, nil
}

func VerifyRuntimeDeviceMigrationRequest(request *RuntimeDeviceMigrationRequestV1, identityHash, platformKeyHash string) error {
	if request == nil || request.Schema != 1 || request.Body.PlatformKeyHash != platformKeyHash {
		return errors.New("[设备迁移] 请求不是原网络的迁移输入")
	}
	message, err := RuntimeDeviceMigrationRequestMessage(&request.Body)
	if err != nil {
		return err
	}
	der, _ := decodeCanonicalBase64URL(request.Body.IdentitySPKIDER)
	hash, err := HashBytes(DomainEnrollmentIdentitySPKI, der)
	if err != nil || hash != identityHash {
		return errors.New("[设备迁移] 请求未绑定原 registry 身份")
	}
	public, _ := x509.ParsePKIXPublicKey(der)
	return verifyP256LowS(message, public.(*ecdsa.PublicKey), request.Signature)
}
