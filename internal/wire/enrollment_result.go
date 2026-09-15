package wire

import "errors"

const DomainEnrollmentResultArtifact = "loom-enrollment-result-artifact-v1"

// EnrollmentResultArtifactV1 是 completion 后才允许释放给 Device 的私有交付
// 容器。它只携证书与不可变 view/artifact refs，不携 Device private key。
type EnrollmentResultArtifactV1 struct {
	Schema               int                   `json:"schema"`
	ClusterID            string                `json:"cluster_id"`
	InviteID             string                `json:"invite_id"`
	RequestID            string                `json:"request_id"`
	DeviceCertificateDER string                `json:"device_certificate_der"`
	InitialDeviceView    DeviceViewPayloadV2   `json:"initial_device_view"`
	SecretArtifactRefs   []SecretArtifactRefV2 `json:"secret_artifact_refs"`
}

func ValidateEnrollmentResultArtifact(artifact *EnrollmentResultArtifactV1) error {
	if artifact == nil || artifact.Schema != 1 || !validIdentifier(artifact.ClusterID, 128) ||
		!validIdentifier(artifact.InviteID, 128) || !validIdentifier(artifact.RequestID, 128) ||
		artifact.SecretArtifactRefs == nil {
		return errors.New("[Enrollment] result artifact header/refs 无效")
	}
	certificateDER, err := decodeCanonicalBase64URL(artifact.DeviceCertificateDER)
	if err != nil {
		return errors.New("[Device identity] result artifact certificate DER 编码无效")
	}
	if _, err := DeviceCertificateHash(certificateDER); err != nil {
		return err
	}
	view := &artifact.InitialDeviceView
	if err := ValidateDeviceViewPayload(view); err != nil {
		return err
	}
	if view.ClusterID != artifact.ClusterID || view.DeviceGeneration != 1 || view.State != "active" || view.Active == nil {
		return errors.New("[Enrollment] result artifact 只允许 exact initial active view")
	}
	if root, err := SecretArtifactRefsRoot(artifact.SecretArtifactRefs); err != nil ||
		root != view.Active.SecretArtifactRefsRoot {
		return errors.New("[secret artifact] result artifact secret refs root 不匹配")
	}
	for i := range artifact.SecretArtifactRefs {
		ref := &artifact.SecretArtifactRefs[i]
		owner := ref.Owner
		if owner.Kind != "device" || owner.Device == nil || owner.Device.DeviceID != view.DeviceID {
			return errors.New("[secret artifact] result artifact 含非目标 Device 所有的 secret ref")
		}
		if !oneOf(ref.Purpose, "device_credential", "data_plane_credential", "tls_private_key") {
			return errors.New("[Enrollment] result artifact 含禁止交付的 secret purpose")
		}
	}
	return nil
}

func EnrollmentResultArtifactHash(artifact *EnrollmentResultArtifactV1) (string, error) {
	if err := ValidateEnrollmentResultArtifact(artifact); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentResultArtifact, artifact)
}

func EnrollmentResultCertificateDER(artifact *EnrollmentResultArtifactV1) ([]byte, error) {
	if err := ValidateEnrollmentResultArtifact(artifact); err != nil {
		return nil, err
	}
	return decodeCanonicalBase64URL(artifact.DeviceCertificateDER)
}
