package wire

import (
	"bytes"
	"crypto/x509"
	"errors"
)

const DevicePrivateControlCredentialSecretIDV1 = "device-private-control"

// DevicePrivateControlCredentialV1 是 Enrollment 通过 Device-owned sealed secret
// 私下交付的稳态控制入口。它不进入 public mirror；目录 hash pin 与 internal CA roots
// 来自同一份已被 Device view secret refs root 承诺的 plaintext（D124、D131）。
type DevicePrivateControlCredentialV1 struct {
	Schema                      int                       `json:"schema"`
	ClusterID                   string                    `json:"cluster_id"`
	DeviceID                    string                    `json:"device_id"`
	ParentHead                  HeadEntryV2               `json:"parent_head"`
	ControlSet                  ControlSetV1              `json:"control_set"`
	PreviousControlSet          *ControlSetV1             `json:"previous_control_set,omitempty"`
	ControlServiceDirectory     ControlServiceDirectoryV1 `json:"control_service_directory"`
	ControlServiceDirectoryHash string                    `json:"control_service_directory_hash"`
	InternalCARootsDER          []string                  `json:"internal_ca_roots_der"`
}

func ValidateDevicePrivateControlCredential(credential *DevicePrivateControlCredentialV1) error {
	if credential == nil || credential.Schema != 1 || !validIdentifier(credential.ClusterID, 128) ||
		!validIdentifier(credential.DeviceID, 128) || len(credential.InternalCARootsDER) == 0 ||
		len(credential.InternalCARootsDER) > 16 {
		return errors.New("[D131 Device control] private credential header/roots 无效")
	}
	directory := &credential.ControlServiceDirectory
	if err := ValidateControlServiceDirectory(directory); err != nil {
		return err
	}
	directoryHash, err := ControlServiceDirectoryHash(directory)
	if err != nil || directoryHash != credential.ControlServiceDirectoryHash ||
		directory.ClusterID != credential.ClusterID || credential.ParentHead.HeadHash != directory.ParentHeadHash {
		return errors.New("[D131 Device control] private directory 与 exact hash/cluster 不一致")
	}
	setHash, err := ControlSetHash(&credential.ControlSet)
	if err != nil || setHash != directory.ControlSetHash ||
		credential.ControlSet.ClusterID != credential.ClusterID ||
		credential.ParentHead.Body.Payload.ClusterID != credential.ClusterID {
		return errors.New("[D131 Device control] private directory 与 exact ControlSet 不一致")
	}
	if err := VerifyConfigQCAuthority(directory.ParentHeadHash, directory.ConfigQC,
		&credential.ParentHead, &credential.ControlSet, credential.PreviousControlSet); err != nil {
		return err
	}
	totalBytes := 0
	for index, encoded := range credential.InternalCARootsDER {
		if index > 0 && credential.InternalCARootsDER[index-1] >= encoded {
			return errors.New("[D131 Device control] internal CA roots 必须严格排序且不重复")
		}
		der, err := decodeCanonicalBase64URL(encoded)
		if err != nil {
			return errors.New("[D131 Device control] internal CA root 不是 canonical DER")
		}
		totalBytes += len(der)
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) || !certificate.BasicConstraintsValid ||
			!certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			len(certificate.UnhandledCriticalExtensions) != 0 ||
			!bytes.Equal(certificate.RawSubject, certificate.RawIssuer) ||
			certificate.CheckSignature(certificate.SignatureAlgorithm,
				certificate.RawTBSCertificate, certificate.Signature) != nil {
			return errors.New("[D131 Device control] internal CA root profile/self-signature 无效")
		}
	}
	if totalBytes > 128<<10 {
		return errors.New("[D131 Device control] internal CA roots 超过大小预算")
	}
	return nil
}

// ValidateDevicePrivateControlCredentialAtFloor 把已解封的 private-control
// credential 约束在客户端已经持久化的 authority floor 内。credential 的 parent
// 可以是同一 recovery/control epoch 中较早的 ordinary Head（否则目录更新会与引用
// 它的 Device view 形成内容哈希环），但不能跨 recovery/ControlSet 继续使用，也不能
// 指向客户端尚未接受的未来 Head 或同 revision 分叉。
func ValidateDevicePrivateControlCredentialAtFloor(credential *DevicePrivateControlCredentialV1,
	floor ClientFloorsV2,
) error {
	if err := ValidateDevicePrivateControlCredential(credential); err != nil {
		return err
	}
	if err := validateClientFloors(floor); err != nil {
		return errors.New("[D131 Device control] durable authority floor 无效")
	}
	payload := credential.ParentHead.Body.Payload
	if credential.ClusterID != floor.ClusterID ||
		payload.RecoveryEpoch != floor.AcceptedRecoveryEpoch ||
		payload.RecoveryStatementHash != floor.RecoveryStatementHash ||
		payload.RecoveryPolicyHash != floor.RecoveryPolicyHash ||
		payload.ControlEpoch != floor.AcceptedControlEpoch ||
		payload.ControlSetHash != floor.ControlSetHash {
		return errors.New("[D131 Device control] private credential 未绑定 durable recovery/ControlSet authority")
	}
	if payload.ControlRevision > floor.AcceptedControlRevision {
		return errors.New("[D131 Device control] private credential 指向尚未接受的未来 Head")
	}
	if payload.ControlRevision == floor.AcceptedControlRevision &&
		credential.ParentHead.HeadHash != floor.HeadHash {
		return errors.New("[D131 Device control] private credential 与 durable Head 同坐标分叉")
	}
	return nil
}
