//go:build linux

package clientv2

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"loom/internal/wire"
)

// linuxInstalledPrivateControlContext 只从 enrollment 时已由 Device view 承诺并
// 解封进 0600 state 的 credential 派生。外部 CLI 文件只保留给旧安装迁移。
type linuxInstalledPrivateControlContext struct {
	directory     wire.ControlServiceDirectoryV1
	directoryHash string
	parentHead    wire.HeadEntryV2
	controlSet    wire.ControlSetV1
	previousSet   *wire.ControlSetV1
	roots         *x509.CertPool
}

func installedLinuxPrivateControlContext(installation *DeviceInstallationV1,
	floors wire.ClientFloorsV2, deviceID string,
) (linuxInstalledPrivateControlContext, bool, error) {
	if installation == nil {
		return linuxInstalledPrivateControlContext{}, false,
			errors.New("[Linux private] enrollment installation 缺失")
	}
	var selected *InstalledSecretV1
	for index := range installation.Credentials {
		candidate := &installation.Credentials[index]
		if candidate.SecretID != wire.DevicePrivateControlCredentialSecretIDV1 ||
			candidate.Purpose != "device_credential" {
			continue
		}
		if selected == nil || candidate.Generation > selected.Generation {
			selected = candidate
		}
	}
	if selected == nil {
		return linuxInstalledPrivateControlContext{}, false, nil
	}
	plaintext, err := base64.RawURLEncoding.DecodeString(selected.SecretBytes)
	if err != nil || len(plaintext) == 0 ||
		base64.RawURLEncoding.EncodeToString(plaintext) != selected.SecretBytes ||
		wire.HashRaw("loom-linux-installed-secret-v1", plaintext) != selected.SecretDigest {
		return linuxInstalledPrivateControlContext{}, true,
			errors.New("[Linux private] installed private-control credential 编码/digest 无效")
	}
	defer clear(plaintext)
	var credential wire.DevicePrivateControlCredentialV1
	canonical, err := wire.DecodeStrict(plaintext, 1<<20, &credential)
	if err != nil || !bytes.Equal(canonical, plaintext) {
		return linuxInstalledPrivateControlContext{}, true,
			errors.New("[Linux private] installed private-control credential wire 无效")
	}
	if credential.DeviceID != deviceID ||
		wire.ValidateDevicePrivateControlCredentialAtFloor(&credential, floors) != nil {
		return linuxInstalledPrivateControlContext{}, true,
			errors.New("[Linux private] installed private-control credential 未绑定 durable authority")
	}
	roots := x509.NewCertPool()
	for _, encoded := range credential.InternalCARootsDER {
		der, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		certificate, parseErr := x509.ParseCertificate(der)
		if decodeErr != nil || parseErr != nil || !bytes.Equal(certificate.Raw, der) {
			return linuxInstalledPrivateControlContext{}, true,
				errors.New("[Linux private] installed internal CA root DER 无效")
		}
		roots.AddCert(certificate)
	}
	return linuxInstalledPrivateControlContext{
		directory:     cloneStoreValue(credential.ControlServiceDirectory),
		directoryHash: credential.ControlServiceDirectoryHash,
		parentHead:    cloneStoreValue(credential.ParentHead),
		controlSet:    cloneStoreValue(credential.ControlSet),
		previousSet:   cloneStoreValue(credential.PreviousControlSet),
		roots:         roots,
	}, true, nil
}
