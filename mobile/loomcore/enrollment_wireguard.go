package loomcore

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"loom/internal/wire"
)

// 密钥只交给本机 Keystore 加密存储和同宿主 WireGuard，不能进入 claim。
func GenerateLocalWireGuardKey() ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func LocalWireGuardPublicKey(private []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, errors.New("[WireGuard] 本机密钥长度无效")
	}
	return key.PublicKey().Bytes(), nil
}

// 本机公钥进入 stable core，随后由原 identity key 的 detached PoP 认证。
func PrepareAndroidEnrollmentV2ClaimCoreWithWireGuard(descriptorJSON, proofBundleJSON, responseJSON []byte,
	requestID string, identitySPKIDER, csrDER, wrappingSPKIDER []byte,
	wrappingProfile string, clientNonce, wireGuardPublic []byte, trustedTime string) ([]byte, error) {
	body, err := PrepareAndroidEnrollmentV2ClaimCore(descriptorJSON, proofBundleJSON, responseJSON,
		requestID, identitySPKIDER, csrDER, wrappingSPKIDER, wrappingProfile, clientNonce, trustedTime)
	if err != nil {
		return nil, err
	}
	var core wire.EnrollmentClaimCoreV2
	if _, err := wire.DecodeStrict(body, 1<<20, &core); err != nil {
		return nil, err
	}
	core.WireGuardPublicKey = base64.StdEncoding.EncodeToString(wireGuardPublic)
	if _, err := wire.EnrollmentWireGuardPublicKey(&core); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(core)
}
