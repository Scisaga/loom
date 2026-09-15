package enrollmentv2

import (
	"crypto"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"loom/internal/wire"
)

// PrepareMigratedDeviceCertificate 为原设备请求生成待认证的证书材料。期望的
// identity/platform hash 必须来自原网络 registry/平台公钥；不能信任请求自报值。
// 只有之后的原 owner/platform 双签迁移与实际 QC 才允许客户端安装该证书。
func PrepareMigratedDeviceCertificate(request wire.RuntimeDeviceMigrationRequestV1,
	expectedIdentityHash, expectedPlatformHash string, profile wire.DeviceCertificateProfileStateV1,
	responsibilities []string, issuance wire.IssuanceLogCoordinateV1, issuedAt time.Time,
	issuerKey crypto.Signer, random io.Reader) ([]byte, error) {
	if err := wire.VerifyRuntimeDeviceMigrationRequest(&request, expectedIdentityHash, expectedPlatformHash); err != nil {
		return nil, err
	}
	if issuance.RecoveryEpoch != 2 || issuance.RaftIndex < 1 || issuedAt.IsZero() ||
		issuedAt != issuedAt.UTC().Truncate(time.Second) {
		return nil, errors.New("[设备迁移] 签发缺实际迁移坐标与规范时间")
	}
	identity, err := base64.RawURLEncoding.DecodeString(request.Body.IdentitySPKIDER)
	if err != nil {
		return nil, err
	}
	return issueDeviceCertificate(profile, request.Body.DeviceID, request.Body.Platform, responsibilities,
		identity, expectedIdentityHash, issuedAt.Format(time.RFC3339), issuance, issuerKey, random)
}
