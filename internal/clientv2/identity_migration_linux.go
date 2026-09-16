//go:build linux

package clientv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

// ImportLinuxMigrationIdentity 保留原 P-256 身份；新 wrapping key 只生成一次。
// original 必须由宿主先与原设备证书验证，不能在失败时生成替代身份。
func ImportLinuxMigrationIdentity(path string, original *ecdsa.PrivateKey) (*EnrollmentIdentityV1, error) {
	if original == nil || original.Curve != elliptic.P256() || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("[Linux migration] 原身份或保存路径无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	public, err := x509.MarshalPKIXPublicKey(&original.PublicKey)
	if err != nil {
		return nil, err
	}
	if state, err := loadEnrollmentIdentity(path); err == nil {
		stored, err := base64.RawURLEncoding.DecodeString(state.IdentityPublicKeySPKI)
		if err != nil || !bytes.Equal(stored, public) {
			return nil, errors.New("[Linux migration] 现有 v2 key 不属于原身份")
		}
		return state, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(wrapping.D.Bits())
	private, err := x509.MarshalPKCS8PrivateKey(original)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	wrapPrivate, err := x509.MarshalPKCS8PrivateKey(wrapping)
	if err != nil {
		return nil, err
	}
	defer clear(wrapPrivate)
	wrapPublic, err := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	if err != nil {
		return nil, err
	}
	state := &EnrollmentIdentityV1{Schema: 1, ProtectionProfile: LinuxSoftwareKeyProtectionProfile,
		IdentityPrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(private), IdentityPublicKeySPKI: base64.RawURLEncoding.EncodeToString(public),
		WrappingPrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(wrapPrivate), WrappingPublicKeySPKI: base64.RawURLEncoding.EncodeToString(wrapPublic)}
	if err := persistEnrollmentIdentity(path, state); err != nil {
		return nil, err
	}
	return loadEnrollmentIdentity(path)
}

func (state *EnrollmentIdentityV1) SignMigrationRequest(body wire.RuntimeDeviceMigrationRequestBodyV1) (wire.RuntimeDeviceMigrationRequestV1, error) {
	identity, wrapping, err := state.keys()
	if err != nil {
		return wire.RuntimeDeviceMigrationRequestV1{}, err
	}
	defer clear(identity.D.Bits())
	defer clear(wrapping.D.Bits())
	if body.Platform != "linux-server" || body.IdentitySPKIDER != state.IdentityPublicKeySPKI ||
		body.WrappingSPKIDER != state.WrappingPublicKeySPKI || body.WrappingKeyProfile != "p256-root-only-pkcs8-ecdh-v1" {
		return wire.RuntimeDeviceMigrationRequestV1{}, errors.New("[Linux migration] 请求与本机身份或 wrapping key 不匹配")
	}
	return wire.SignRuntimeDeviceMigrationRequest(body, identity)
}
