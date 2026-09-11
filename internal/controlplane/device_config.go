package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"loom/internal/wire"
)

const PrivateDeviceConfigPath = "/private/v2/device/config"

type DeviceIdentityRecordV1 struct {
	Schema           int                                  `json:"schema"`
	CertificateHash  string                               `json:"certificate_hash"`
	DeviceID         string                               `json:"device_id"`
	IdentitySPKIHash string                               `json:"identity_spki_hash"`
	Platform         string                               `json:"platform"`
	Responsibilities []string                             `json:"responsibilities"`
	ProfileRef       wire.DeviceCertificateProfileRefV1   `json:"profile_ref"`
	ProfileState     wire.DeviceCertificateProfileStateV1 `json:"profile_state"`
	Issuance         wire.IssuanceLogCoordinateV1         `json:"issuance"`
	ApprovedAt       string                               `json:"approved_at"`
	IdentityStatus   string                               `json:"identity_status"`
}

// DeviceIdentityAuthorityV1 必须来自一次线性化读取；完整 CA registry preimage
// 用来证明所用 profile state（包括 revoked tombstone）正是 certified head 的当前值（D102）。
type DeviceIdentityAuthorityV1 struct {
	Record                    DeviceIdentityRecordV1
	Head                      wire.HeadEntryV2
	ConfigQC                  json.RawMessage
	ControlSet                wire.ControlSetV1
	PreviousControlSet        *wire.ControlSetV1
	AdminCertificateProfiles  []wire.AdminCertificateProfileV1
	DeviceCertificateProfiles []wire.DeviceCertificateProfileStateV1
}

type DeviceIdentityReader func(context.Context, string) (DeviceIdentityAuthorityV1, error)

// VerifiedDeviceIdentityV1 只有 exact Device certificate/profile/registry record 全部
// 通过后才能产生；config reader 不接受裸 Device ID 或调用方自报的 active 布尔值（D102、D131）。
type VerifiedDeviceIdentityV1 struct {
	record    DeviceIdentityRecordV1
	authority DeviceIdentityAuthorityV1
}

func (verified VerifiedDeviceIdentityV1) DeviceID() string {
	return verified.record.DeviceID
}

func (verified VerifiedDeviceIdentityV1) IdentitySPKIHash() string {
	return verified.record.IdentitySPKIHash
}

func (verified VerifiedDeviceIdentityV1) IdentityStatus() string {
	return verified.record.IdentityStatus
}

func (verified VerifiedDeviceIdentityV1) CertificateHash() string {
	return verified.record.CertificateHash
}

type DeviceConfigMaterialV1 struct {
	Envelope wire.DeviceViewEnvelopeV2
}

type DeviceConfigReader func(context.Context, VerifiedDeviceIdentityV1) (DeviceConfigMaterialV1, error)

type PrivateDeviceConfigService struct {
	localAddress    string
	allowedProfiles []string
	identities      DeviceIdentityReader
	read            DeviceConfigReader
	now             func() time.Time
}

func NewPrivateDeviceConfigService(endpoint wire.PrivateControlServiceV1, identities DeviceIdentityReader,
	read DeviceConfigReader, now func() time.Time) (*PrivateDeviceConfigService, error) {
	if err := wire.ValidatePrivateControlService(&endpoint); err != nil {
		return nil, err
	}
	if endpoint.Role != "device_config" || identities == nil || read == nil || now == nil {
		return nil, errors.New("[D131 device_config] service role/dependencies 无效")
	}
	return &PrivateDeviceConfigService{
		localAddress:    net.JoinHostPort(endpoint.OverlayIP, strconv.FormatInt(endpoint.Port, 10)),
		allowedProfiles: append([]string(nil), endpoint.AuthorizedSubjectProfiles...),
		identities:      identities, read: read, now: now,
	}, nil
}

func (service *PrivateDeviceConfigService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != PrivateDeviceConfigPath || request.URL.RawQuery != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[D131 device_config] 路由不存在")
		return
	}
	if !matchesExactPrivateListener(request, service.localAddress) || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[D131 device_config] Device mTLS 被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writePrivateControlError(writer, http.StatusBadRequest, "[D131 device_config] 请求格式被拒绝")
		return
	}
	trustedTime := service.now().UTC()
	identity, err := service.authenticate(request.Context(), request.TLS.PeerCertificates[0].Raw, trustedTime)
	if err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[D131 device_config] Device identity 被拒绝")
		return
	}
	material, err := service.read(request.Context(), identity)
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[D131 device_config] certified view 暂不可用")
		return
	}
	authority := &identity.authority
	if !wire.EqualCanonical(material.Envelope.SignedCurrent.Head, authority.Head) ||
		!bytes.Equal(material.Envelope.SignedCurrent.QuorumCertificate, authority.ConfigQC) {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D105 device_config] view current 未绑定认证 authority")
		return
	}
	if _, err := wire.VerifyDeviceViewEnvelopeWithPrevious(&material.Envelope, &authority.ControlSet,
		authority.PreviousControlSet); err != nil || material.Envelope.Payload.DeviceID != identity.DeviceID() ||
		material.Envelope.Payload.ClusterID != identity.record.ProfileState.ClusterID ||
		(material.Envelope.Payload.State == "active" &&
			material.Envelope.Payload.Active.IdentitySPKIHash != identity.IdentitySPKIHash()) ||
		(identity.IdentityStatus() == "revocation_pending" && material.Envelope.Payload.State == "active") {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D105 device_config] view identity/QC/inclusion 校验失败")
		return
	}
	body, err := wire.MarshalCanonical(material.Envelope)
	if err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D105 device_config] view 编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func (service *PrivateDeviceConfigService) authenticate(ctx context.Context, certificateDER []byte,
	trustedTime time.Time) (VerifiedDeviceIdentityV1, error) {
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	authority, err := service.identities(ctx, certificateHash)
	record := &authority.Record
	if err != nil || record.Schema != 1 || record.CertificateHash != certificateHash ||
		!oneOfDeviceStatus(record.IdentityStatus, "active", "revocation_pending") ||
		!containsString(service.allowedProfiles, record.ProfileRef.ProfileID) {
		return VerifiedDeviceIdentityV1{}, errors.New("[D102 Device identity] registry record 不存在或未获 service profile 授权")
	}
	if err := wire.VerifyConfigQCAuthority(authority.Head.HeadHash, authority.ConfigQC, &authority.Head,
		&authority.ControlSet, authority.PreviousControlSet); err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	registryRoot, err := wire.CAProfileRoot(authority.AdminCertificateProfiles, authority.DeviceCertificateProfiles)
	if err != nil || registryRoot != authority.Head.Body.Payload.CAProfileRoot ||
		!containsExactDeviceProfile(authority.DeviceCertificateProfiles, &record.ProfileState) {
		return VerifiedDeviceIdentityV1{}, errors.New("[D102 Device identity] profile state 未绑定 certified CA registry")
	}
	if err := wire.ValidateDeviceCertificateProfileRef(&record.ProfileRef, &record.ProfileState); err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	approvedAt, err := wire.ParseTimeZ(record.ApprovedAt)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	_, err = wire.VerifyDeviceCertificateAt(certificateDER, &record.ProfileState, record.DeviceID,
		record.IdentitySPKIHash, record.Platform, record.Responsibilities, record.Issuance, approvedAt, trustedTime)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	return VerifiedDeviceIdentityV1{record: *record, authority: authority}, nil
}

func containsExactDeviceProfile(profiles []wire.DeviceCertificateProfileStateV1,
	want *wire.DeviceCertificateProfileStateV1) bool {
	matched := 0
	for i := range profiles {
		if profiles[i].ProfileID == want.ProfileID {
			if !wire.EqualCanonical(profiles[i], *want) {
				return false
			}
			matched++
		}
	}
	return matched == 1
}

func matchesExactPrivateListener(request *http.Request, expected string) bool {
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return ok && local != nil && local.String() == expected && request.Host == expected
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func oneOfDeviceStatus(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
