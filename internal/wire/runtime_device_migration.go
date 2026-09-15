package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// RuntimeDeviceMigrationLeafV1 随原 owner/platform 双签承诺逐设备迁移输入。
// 它不是 Enrollment completion；已有身份不得伪造一次新 claim 来绕过本机 floor。
type RuntimeDeviceMigrationLeafV1 struct {
	Schema                       int                        `json:"schema"`
	ClusterID                    string                     `json:"cluster_id"`
	DeviceID                     string                     `json:"device_id"`
	Platform                     string                     `json:"platform"`
	LegacyFloor                  BootstrapDeviceFloorLeafV1 `json:"legacy_floor"`
	IdentitySPKIHash             string                     `json:"identity_spki_hash"`
	WrappingKeyHash              string                     `json:"wrapping_key_hash"`
	DeviceCertificateHash        string                     `json:"device_certificate_hash"`
	DeviceCertificateProfileHash string                     `json:"device_certificate_profile_hash"`
	Issuance                     IssuanceLogCoordinateV1    `json:"issuance"`
}

type RuntimeDeviceMigrationProofV1 struct {
	Schema    int                          `json:"schema"`
	Leaf      RuntimeDeviceMigrationLeafV1 `json:"leaf"`
	LeafIndex int64                        `json:"leaf_index"`
	TreeSize  int64                        `json:"tree_size"`
	AuditPath []string                     `json:"audit_path"`
}

// 迁移包只交付给对应设备；私有配置与封装凭据沿真实 certified Head 连续推进。
// 公开 activation bundle 只含根承诺，不公开设备证书、标识、目录或迁移记录。
type RuntimeDeviceMigrationPackageV1 struct {
	Schema                    int                               `json:"schema"`
	LegacySignedCurrent       string                            `json:"legacy_signed_current,omitempty"`
	Activation                RuntimeActivationBundleV1         `json:"activation"`
	Migration                 RuntimeDeviceMigrationProofV1     `json:"migration"`
	DeviceCertificateDER      string                            `json:"device_certificate_der"`
	DeviceProfile             DeviceCertificateProfileStateV1   `json:"device_profile"`
	AdminCertificateProfiles  []AdminCertificateProfileV1       `json:"admin_certificate_profiles"`
	DeviceCertificateProfiles []DeviceCertificateProfileStateV1 `json:"device_certificate_profiles"`
	Configuration             DeviceConfigDeliveryV1            `json:"configuration"`
	DistributionMirrors       []DistributionMirrorRefV1         `json:"distribution_mirrors"`
}

type RuntimeDeviceMigrationExpectedV1 struct {
	DeviceID        string
	Platform        string
	IdentitySPKIDER []byte
	WrappingKeyHash string
	LegacyFloor     BootstrapDeviceFloorLeafV1
}

type VerifiedRuntimeDeviceMigrationV1 struct {
	configuration VerifiedDeviceConfigDeliveryV1
	leaf          RuntimeDeviceMigrationLeafV1
	certificate   []byte
	profile       DeviceCertificateProfileStateV1
	approvedAt    string
}

func (v VerifiedRuntimeDeviceMigrationV1) Configuration() VerifiedDeviceConfigDeliveryV1 {
	return v.configuration
}

func (v VerifiedRuntimeDeviceMigrationV1) Leaf() RuntimeDeviceMigrationLeafV1 {
	return v.leaf
}

func (v VerifiedRuntimeDeviceMigrationV1) CertificateDER() []byte {
	return append([]byte(nil), v.certificate...)
}

func (v VerifiedRuntimeDeviceMigrationV1) Profile() DeviceCertificateProfileStateV1 {
	return cloneDeviceConfigValue(v.profile)
}

func (v VerifiedRuntimeDeviceMigrationV1) ApprovedAt() string { return v.approvedAt }

func ValidateRuntimeDeviceMigrationLeaf(leaf *RuntimeDeviceMigrationLeafV1) error {
	if leaf == nil || leaf.Schema != 1 || !validIdentifier(leaf.ClusterID, 128) ||
		!validIdentifier(leaf.DeviceID, 128) || !oneOf(leaf.Platform, "android", "windows-desktop", "linux-server") ||
		leaf.LegacyFloor.Schema != 1 || leaf.LegacyFloor.DeviceID != leaf.DeviceID || leaf.LegacyFloor.V1Generation < 1 ||
		leaf.Issuance.RecoveryEpoch != 2 || leaf.Issuance.RaftIndex < 1 {
		return errors.New("[设备迁移] identity/floor/issuance 无效")
	}
	return requireCanonicalHashes(leaf.LegacyFloor.V1SignedCurrentHash, leaf.LegacyFloor.V1PayloadHash,
		leaf.IdentitySPKIHash, leaf.WrappingKeyHash, leaf.DeviceCertificateHash, leaf.DeviceCertificateProfileHash)
}

func runtimeDeviceMigrationLeaves(values []RuntimeDeviceMigrationLeafV1) ([][]byte, error) {
	leaves := make([][]byte, len(values))
	for i := range values {
		if err := ValidateRuntimeDeviceMigrationLeaf(&values[i]); err != nil {
			return nil, err
		}
		if i > 0 && (values[i-1].DeviceID >= values[i].DeviceID || values[i-1].ClusterID != values[i].ClusterID) {
			return nil, errors.New("[设备迁移] 记录必须属于同一网络，按 Device ID 严格排序且不重复")
		}
		var err error
		leaves[i], err = MarshalCanonical(values[i])
		if err != nil {
			return nil, err
		}
	}
	return leaves, nil
}

func RuntimeDeviceMigrationRoot(values []RuntimeDeviceMigrationLeafV1) (string, error) {
	leaves, err := runtimeDeviceMigrationLeaves(values)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", MerkleRoot(leaves)), nil
}

func BuildRuntimeDeviceMigrationProof(values []RuntimeDeviceMigrationLeafV1, deviceID string) (RuntimeDeviceMigrationProofV1, error) {
	leaves, err := runtimeDeviceMigrationLeaves(values)
	if err != nil {
		return RuntimeDeviceMigrationProofV1{}, err
	}
	for i, leaf := range values {
		if leaf.DeviceID != deviceID {
			continue
		}
		path, err := MerkleInclusionPath(leaves, int64(i))
		if err != nil {
			return RuntimeDeviceMigrationProofV1{}, err
		}
		proof := RuntimeDeviceMigrationProofV1{Schema: 1, Leaf: leaf, LeafIndex: int64(i),
			TreeSize: int64(len(leaves)), AuditPath: make([]string, len(path))}
		for j := range path {
			proof.AuditPath[j] = fmt.Sprintf("sha256:%x", path[j])
		}
		return proof, nil
	}
	return RuntimeDeviceMigrationProofV1{}, errors.New("[设备迁移] 原迁移承诺中没有该 Device")
}

func VerifyRuntimeDeviceMigrationProof(proof *RuntimeDeviceMigrationProofV1, expected RuntimeDeviceMigrationExpectedV1,
	clusterID, rootHash string) error {
	if proof == nil || proof.Schema != 1 || ValidateRuntimeDeviceMigrationLeaf(&proof.Leaf) != nil ||
		proof.Leaf.ClusterID != clusterID || proof.Leaf.DeviceID != expected.DeviceID ||
		proof.Leaf.Platform != expected.Platform || proof.Leaf.WrappingKeyHash != expected.WrappingKeyHash ||
		!EqualCanonical(proof.Leaf.LegacyFloor, expected.LegacyFloor) {
		return errors.New("[设备迁移] 原身份、平台、wrapping key 或本机 floor 不匹配")
	}
	key, err := x509.ParsePKIXPublicKey(expected.IdentitySPKIDER)
	public, ok := key.(*ecdsa.PublicKey)
	hash, hashErr := HashBytes(DomainEnrollmentIdentitySPKI, expected.IdentitySPKIDER)
	if err != nil || !ok || public.Curve != elliptic.P256() || hashErr != nil || hash != proof.Leaf.IdentitySPKIHash {
		return errors.New("[设备迁移] 迁移替换了本机 P-256 身份")
	}
	root, err := ParseHash(rootHash)
	if err != nil {
		return err
	}
	path := make([][]byte, len(proof.AuditPath))
	for i := range path {
		path[i], err = ParseHash(proof.AuditPath[i])
		if err != nil {
			return err
		}
	}
	canonical, _ := MarshalCanonical(proof.Leaf)
	return VerifyMerkleInclusion(canonical, proof.LeafIndex, proof.TreeSize, path, root)
}

// VerifyRuntimeDeviceMigration 只接续外部已信任的原网络与本机身份/floor。
// first view 必须属于实际 activation Head；后续配置复用正式 device_config verifier。
func VerifyRuntimeDeviceMigration(delivery *RuntimeDeviceMigrationPackageV1, expected RuntimeDeviceMigrationExpectedV1,
	trust InviteProofTrustV2, now time.Time) (VerifiedRuntimeDeviceMigrationV1, error) {
	var empty VerifiedRuntimeDeviceMigrationV1
	if delivery == nil || delivery.Schema != 1 || len(delivery.Configuration.Updates) == 0 || now.IsZero() {
		return empty, errors.New("[设备迁移] 私有迁移包不完整")
	}
	transition, err := VerifyRuntimeActivationBundle(&delivery.Activation, trust, "", "")
	if err != nil {
		return empty, err
	}
	activation := &delivery.Activation
	if err := VerifyRuntimeDeviceMigrationProof(&delivery.Migration, expected, activation.Proof.Statement.ClusterID,
		activation.Proof.Statement.DeviceMigrationRoot); err != nil {
		return empty, err
	}
	leaf := delivery.Migration.Leaf
	if leaf.Issuance.RecoveryEpoch != activation.Head.Body.Payload.RecoveryEpoch ||
		leaf.Issuance.RaftIndex != activation.Head.Body.Payload.RaftIndex {
		return empty, errors.New("[设备迁移] 证书没有绑定实际迁移日志坐标")
	}
	first := &delivery.Configuration.Updates[0]
	if first.Envelope.SignedCurrent.Head.HeadHash != activation.Head.HeadHash ||
		!EqualCanonical(first.ControlSet, activation.ControlSet) || first.PreviousControlSet != nil ||
		first.Envelope.Payload.State != "active" || first.Envelope.Payload.Active == nil ||
		first.Envelope.Payload.Active.IdentitySPKIHash != leaf.IdentitySPKIHash {
		return empty, errors.New("[设备迁移] 配置窗口未从原身份的迁移 Head 开始")
	}
	floors, err := VerifyDeviceViewEnvelope(&first.Envelope, &first.ControlSet)
	if err != nil {
		return empty, err
	}
	floors.BootstrapTransitionHash = transition
	verified, err := VerifyDeviceConfigDeliveryFromProtected(&delivery.Configuration, &first.Envelope, floors,
		&first.ControlSet, nil, expected.DeviceID, leaf.IdentitySPKIHash)
	if err != nil {
		return empty, err
	}
	current := verified.Envelope()
	if current.Payload.State != "active" {
		return empty, errors.New("[设备迁移] 设备已撤权或退役，不能恢复连接")
	}
	profileHash, err := DeviceCertificateProfileStateHash(&delivery.DeviceProfile)
	if err != nil || profileHash != leaf.DeviceCertificateProfileHash || delivery.DeviceProfile.Status != "active" ||
		delivery.DeviceProfile.ClusterID != leaf.ClusterID {
		return empty, errors.New("[设备迁移] 证书 profile 不属于当前认证状态")
	}
	root, err := CAProfileRoot(delivery.AdminCertificateProfiles, delivery.DeviceCertificateProfiles)
	if err != nil || root != current.SignedCurrent.Head.Body.Payload.CAProfileRoot {
		return empty, errors.New("[设备迁移] 当前 CA registry 证明不匹配")
	}
	found := false
	for _, profile := range delivery.DeviceCertificateProfiles {
		if EqualCanonical(profile, delivery.DeviceProfile) {
			found = true
		}
	}
	if !found {
		return empty, errors.New("[设备迁移] 当前 CA registry 没有该 Device profile")
	}
	certificate, err := base64.RawURLEncoding.DecodeString(delivery.DeviceCertificateDER)
	certificateHash, hashErr := DeviceCertificateHash(certificate)
	approvedAt, timeErr := ParseTimeZ(activation.Head.Body.Payload.CommittedLogicalTime)
	if err != nil || hashErr != nil || timeErr != nil || certificateHash != leaf.DeviceCertificateHash ||
		base64.RawURLEncoding.EncodeToString(certificate) != delivery.DeviceCertificateDER {
		return empty, errors.New("[设备迁移] 证书 bytes 或认证时间不匹配")
	}
	changedAt, err := ParseTimeZ(delivery.DeviceProfile.StatusChangedAt)
	if err != nil || changedAt.After(approvedAt) {
		return empty, errors.New("[设备迁移] profile 在迁移提交后才生效")
	}
	parsed, err := VerifyDeviceCertificateAt(certificate, &delivery.DeviceProfile, expected.DeviceID,
		leaf.IdentitySPKIHash, expected.Platform, current.Payload.Active.Responsibilities.Values,
		leaf.Issuance, approvedAt, now)
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(parsed.RawSubjectPublicKeyInfo, expected.IdentitySPKIDER) {
		return empty, errors.New("[设备迁移] 证书替换了本机身份公钥")
	}
	if err := ValidateDistributionMirrorRefs(delivery.DistributionMirrors); err != nil {
		return empty, err
	}
	return VerifiedRuntimeDeviceMigrationV1{configuration: verified, leaf: leaf, certificate: append([]byte(nil), certificate...),
		profile: cloneDeviceConfigValue(delivery.DeviceProfile), approvedAt: activation.Head.Body.Payload.CommittedLogicalTime}, nil
}
