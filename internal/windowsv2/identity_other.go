//go:build !windows

package windowsv2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"

	"loom/internal/clientsecret"
)

const softwareIdentityProvider = "test-dpapi-software-p256-v1"

// 非 Windows 构建只用于共享 wire/state 单元测试。正式 Windows 二进制没有
// 此可导出私钥 fallback；它必须使用 identity_windows.go 的 CNG KSP。
func createPlatformIdentity(_ clientsecret.Protector, random io.Reader,
) (crypto.Signer, []byte, platformIdentityRecord, error) {
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, nil, platformIdentityRecord{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		zeroPrivateKey(key)
		return nil, nil, platformIdentityRecord{}, err
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		zeroPrivateKey(key)
		return nil, nil, platformIdentityRecord{}, err
	}
	record := platformIdentityRecord{Provider: softwareIdentityProvider,
		PrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(privateDER)}
	return &restrictedP256Signer{key: key}, publicDER, record, nil
}

func loadPlatformIdentity(state protectedIdentityV1,
	_ clientsecret.Protector) (crypto.Signer, []byte, error) {
	if state.IdentityProvider != softwareIdentityProvider || state.IdentityKeyName != "" ||
		state.IdentityMachineScope || state.IdentityPrivateKeyPKCS8 == "" {
		return nil, nil, errors.New("非 Windows 测试 identity provider 无效")
	}
	key, publicDER, err := decodeP256Private(state.IdentityPrivateKeyPKCS8,
		state.IdentityPublicKeySPKI)
	if err != nil {
		return nil, nil, err
	}
	return &restrictedP256Signer{key: key}, publicDER, nil
}

func destroyPlatformIdentity(record platformIdentityRecord) error {
	if record.Provider != softwareIdentityProvider || record.KeyName != "" ||
		record.MachineScope || record.PrivateKeyPKCS8 == "" {
		return errors.New("非 Windows 测试 identity descriptor 无效")
	}
	return nil
}
