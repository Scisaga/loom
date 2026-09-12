package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"loom/internal/wire"
)

const androidPrivateControlCredentialSecretID = "device-private-control"

type androidPrivateControlPlanV1 struct {
	Schema                    int      `json:"schema"`
	Role                      string   `json:"role"`
	ServiceID                 string   `json:"service_id"`
	OverlayIP                 string   `json:"overlay_ip"`
	Port                      int64    `json:"port"`
	Path                      string   `json:"path"`
	CertificateProfileRef     string   `json:"certificate_profile_ref"`
	ServerSPKIPins            []string `json:"server_spki_pins"`
	InternalCARootsDER        []string `json:"internal_ca_roots_der"`
	ClientCertificateChainDER []string `json:"client_certificate_chain_der"`
	IdentitySPKIHash          string   `json:"identity_spki_hash"`
	DirectoryGeneration       int64    `json:"directory_generation"`
	DirectoryHash             string   `json:"directory_hash"`
}

// PrepareAndroidV2PrivateControlPlan 只从已认证的 Device-owned sealed credential、
// completion certificate/profile 和 protected LKG 投影一个 exact overlay mTLS 连接。
// Kotlin 只持有 Keystore private-key handle；目录、CA 或 endpoint 都不能从公网 URL 推导（D131）。
func PrepareAndroidV2PrivateControlPlan(stateJSON, identitySPKIDER []byte,
	role, serviceID, trustedTime string,
) ([]byte, error) {
	plans, err := prepareAndroidV2PrivateControlPlans(stateJSON, identitySPKIDER, role, serviceID, trustedTime)
	if err != nil {
		return nil, err
	}
	if len(plans) != 1 {
		return nil, errors.New("[D131 Android control] exact private service 选择不唯一")
	}
	return wire.MarshalCanonical(plans[0])
}

// PrepareAndroidV2PrivateControlPlans 按 certified directory 顺序返回当前 Device
// 获权的全部同 role 副本；宿主可逐个故障切换，但不能扫描或派生额外地址（D131）。
func PrepareAndroidV2PrivateControlPlans(stateJSON, identitySPKIDER []byte,
	role, trustedTime string,
) ([]byte, error) {
	plans, err := prepareAndroidV2PrivateControlPlans(stateJSON, identitySPKIDER, role, "", trustedTime)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(plans)
}

func prepareAndroidV2PrivateControlPlans(stateJSON, identitySPKIDER []byte,
	role, serviceID, trustedTime string,
) ([]androidPrivateControlPlanV1, error) {
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return nil, err
	}
	if state.ControlSet == nil || state.Enrollment == nil || state.Envelope.Payload.State != "active" ||
		state.Envelope.Payload.Active == nil || state.Enrollment.DeviceProfile == nil ||
		state.Enrollment.DeviceIssuance == nil || state.Enrollment.DeviceApprovedAt == "" {
		return nil, errors.New("[D131 Android control] active Device/identity/profile 不完整")
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D131 Android control] trusted time 无效")
	}
	identityPublic, err := x509.ParsePKIXPublicKey(identitySPKIDER)
	identity, ok := identityPublic.(*ecdsa.PublicKey)
	identityHash, hashErr := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKIDER)
	if err != nil || !ok || identity.Curve != elliptic.P256() || hashErr != nil ||
		identityHash != state.Enrollment.IdentityKeyHash ||
		identityHash != state.Envelope.Payload.Active.IdentitySPKIHash {
		return nil, errors.New("[D131 Android control] Keystore identity 与 protected Device 不一致")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&state.Enrollment.ResultArtifact)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	approvedAt, approvedErr := wire.ParseTimeZ(state.Enrollment.DeviceApprovedAt)
	if err != nil || approvedErr != nil || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, identitySPKIDER) {
		return nil, errors.New("[D131 Android control] Device certificate/Keystore identity 不匹配")
	}
	if _, err := wire.VerifyDeviceCertificateAt(certificateDER, state.Enrollment.DeviceProfile,
		state.Envelope.Payload.DeviceID, identityHash, state.Enrollment.ClaimCore.ClientPlatform,
		state.Envelope.Payload.Active.Responsibilities.Values, *state.Enrollment.DeviceIssuance,
		approvedAt, now); err != nil {
		return nil, err
	}
	credential, err := androidPrivateControlCredential(state.Enrollment.Credentials,
		state.Envelope.Payload.ClusterID, state.Envelope.Payload.DeviceID)
	if err != nil {
		return nil, err
	}
	setHash, _ := wire.ControlSetHash(&credential.ControlSet)
	if credential.ParentHead.HeadHash != state.Enrollment.ClaimCore.BaseHeadHash ||
		setHash != state.Enrollment.ClaimCore.BaseControlSetHash {
		return nil, errors.New("[D131 Android control] private credential 未延续 Enrollment base authority")
	}
	services, err := selectAndroidPrivateControlServices(&credential.ControlServiceDirectory, role, serviceID)
	if err != nil {
		return nil, err
	}
	clientChain := make([]string, 0, 1+len(state.Enrollment.DeviceProfile.ProfileIntent.IssuerChainDER))
	clientChain = append(clientChain, base64.RawURLEncoding.EncodeToString(certificateDER))
	clientChain = append(clientChain, state.Enrollment.DeviceProfile.ProfileIntent.IssuerChainDER...)
	path := "/private/v2/device/config"
	if role == "device_report" {
		path = "/private/v2/device/report"
	}
	plans := make([]androidPrivateControlPlanV1, 0, len(services))
	for _, service := range services {
		if !containsAndroidString(service.AuthorizedSubjectProfiles, state.Enrollment.DeviceProfile.ProfileID) {
			if serviceID != "" {
				return nil, errors.New("[D131 Android control] Device certificate profile 未获 service 授权")
			}
			continue
		}
		plans = append(plans, androidPrivateControlPlanV1{
			Schema: 1, Role: role, ServiceID: service.ServiceID,
			OverlayIP: service.OverlayIP, Port: service.Port, Path: path,
			CertificateProfileRef:     service.CertificateProfileRef,
			ServerSPKIPins:            append([]string(nil), service.SPKIPins...),
			InternalCARootsDER:        append([]string(nil), credential.InternalCARootsDER...),
			ClientCertificateChainDER: append([]string(nil), clientChain...), IdentitySPKIHash: identityHash,
			DirectoryGeneration: credential.ControlServiceDirectory.Generation,
			DirectoryHash:       credential.ControlServiceDirectoryHash,
		})
	}
	if len(plans) == 0 {
		return nil, errors.New("[D131 Android control] private directory 缺获权目标 service")
	}
	return plans, nil
}

func androidPrivateControlCredential(credentials []androidInstalledSecretV1,
	clusterID, deviceID string,
) (wire.DevicePrivateControlCredentialV1, error) {
	var selected *androidInstalledSecretV1
	for index := range credentials {
		candidate := &credentials[index]
		if candidate.SecretID != androidPrivateControlCredentialSecretID ||
			candidate.Purpose != "device_credential" {
			continue
		}
		if selected == nil || candidate.Generation > selected.Generation {
			selected = candidate
		}
	}
	if selected == nil {
		return wire.DevicePrivateControlCredentialV1{},
			errors.New("[D131 Android control] 缺 exact Device private-control credential")
	}
	plaintext, err := base64.RawURLEncoding.DecodeString(selected.SecretBytes)
	if err != nil || base64.RawURLEncoding.EncodeToString(plaintext) != selected.SecretBytes {
		return wire.DevicePrivateControlCredentialV1{}, errors.New("[D131 Android control] private credential 编码无效")
	}
	defer clear(plaintext)
	var credential wire.DevicePrivateControlCredentialV1
	if err := decodeExactAndroidV2(plaintext, 1<<20, &credential, "private control credential"); err != nil {
		return wire.DevicePrivateControlCredentialV1{}, err
	}
	if err := wire.ValidateDevicePrivateControlCredential(&credential); err != nil {
		return wire.DevicePrivateControlCredentialV1{}, err
	}
	if credential.ClusterID != clusterID || credential.DeviceID != deviceID {
		return wire.DevicePrivateControlCredentialV1{},
			errors.New("[D131 Android control] private credential Device/cluster 绑定无效")
	}
	return credential, nil
}

func selectAndroidPrivateControlServices(directory *wire.ControlServiceDirectoryV1,
	role, serviceID string,
) ([]wire.PrivateControlServiceV1, error) {
	if role != "device_config" && role != "device_report" {
		return nil, errors.New("[D131 Android control] private service role 无效")
	}
	selected := make([]wire.PrivateControlServiceV1, 0)
	for index := range directory.Services {
		candidate := &directory.Services[index]
		if candidate.Role != role || serviceID != "" && candidate.ServiceID != serviceID {
			continue
		}
		copy := *candidate
		copy.SPKIPins = append([]string(nil), candidate.SPKIPins...)
		copy.AuthorizedSubjectProfiles = append([]string(nil), candidate.AuthorizedSubjectProfiles...)
		selected = append(selected, copy)
	}
	if len(selected) == 0 {
		return nil, errors.New("[D131 Android control] private directory 缺目标 service")
	}
	return selected, nil
}
