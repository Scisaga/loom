package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
// 用来证明所用 profile state（包括 revoked tombstone）正是 certified head 的当前值。
type DeviceIdentityAuthorityV1 struct {
	Record                    DeviceIdentityRecordV1
	Head                      wire.HeadEntryV2
	ConfigQC                  json.RawMessage
	ControlSet                wire.ControlSetV1
	PreviousControlSet        *wire.ControlSetV1
	AdminCertificateProfiles  []wire.AdminCertificateProfileV1
	DeviceCertificateProfiles []wire.DeviceCertificateProfileStateV1
	CurrentDeviceView         wire.DeviceViewEnvelopeV2
	// RecoveryPolicy 是 current Head 已承诺 hash 的 exact public preimage。
	// recovery delivery 依赖它验证 old threshold；不含任何 recovery private key。
	RecoveryPolicy *wire.RecoveryPolicyV1
	// DeviceConfigUpdates 是从保留窗口锚点到 CurrentDeviceView 的逐 Head
	// certified lineage；为空仅表示当前单步兼容响应。
	DeviceConfigUpdates []wire.DeviceConfigUpdateV1
	// DeviceSecretEnvelopes 可在 final refs 变化时返回只封装给该 Device wrapping key
	// 的 exact immutable envelopes；不得包含明文。
	DeviceSecretEnvelopes []wire.SealedSecretEnvelopeV1
}

type DeviceIdentityReader func(context.Context, string) (DeviceIdentityAuthorityV1, error)

// VerifiedDeviceIdentityV1 只有 exact Device certificate/profile/registry record 全部
// 通过后才能产生；config reader 不接受裸 Device ID 或调用方自报的 active 布尔值。
type VerifiedDeviceIdentityV1 struct {
	record      DeviceIdentityRecordV1
	authority   DeviceIdentityAuthorityV1
	certificate *x509.Certificate
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

type PrivateDeviceConfigService struct {
	localAddress    string
	allowedProfiles []string
	identities      DeviceIdentityReader
	now             func() time.Time
}

func NewPrivateDeviceConfigService(endpoint wire.PrivateControlServiceV1, identities DeviceIdentityReader,
	now func() time.Time) (*PrivateDeviceConfigService, error) {
	if err := wire.ValidatePrivateControlService(&endpoint); err != nil {
		return nil, err
	}
	if endpoint.Role != "device_config" || identities == nil || now == nil {
		return nil, errors.New("[device_config] service role/dependencies 无效")
	}
	return &PrivateDeviceConfigService{
		localAddress:    net.JoinHostPort(endpoint.OverlayIP, strconv.FormatInt(endpoint.Port, 10)),
		allowedProfiles: append([]string(nil), endpoint.AuthorizedSubjectProfiles...),
		identities:      identities, now: now,
	}, nil
}

func (service *PrivateDeviceConfigService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != PrivateDeviceConfigPath || request.URL.RawQuery != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[device_config] 路由不存在")
		return
	}
	if !matchesExactPrivateListener(request, service.localAddress) || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[device_config] Device mTLS 被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_config] 请求格式被拒绝")
		return
	}
	trustedTime := service.now().UTC()
	identity, err := service.authenticate(request.Context(), request.TLS.PeerCertificates[0].Raw, trustedTime)
	if err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[device_config] Device identity 被拒绝")
		return
	}
	var body []byte
	if request.Header.Get("Accept") == wire.DeviceConfigDeliveryMediaTypeV1 {
		body, err = marshalDeviceConfigDelivery(identity)
	} else {
		body, err = wire.MarshalCanonical(identity.authority.CurrentDeviceView)
	}
	if err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[device_config] view 编码失败")
		return
	}
	contentType := "application/json"
	if request.Header.Get("Accept") == wire.DeviceConfigDeliveryMediaTypeV1 {
		contentType = wire.DeviceConfigDeliveryMediaTypeV1
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func marshalDeviceConfigDelivery(identity VerifiedDeviceIdentityV1) ([]byte, error) {
	authority := &identity.authority
	updates := authority.DeviceConfigUpdates
	if len(updates) == 0 {
		updates = []wire.DeviceConfigUpdateV1{{
			Schema: 1, Envelope: authority.CurrentDeviceView,
			ControlSet: authority.ControlSet, PreviousControlSet: authority.PreviousControlSet,
			RecoveryPolicy: authority.RecoveryPolicy,
		}}
	}
	delivery := wire.DeviceConfigDeliveryV1{
		Schema: 1, ClusterID: identity.record.ProfileState.ClusterID,
		DeviceID: identity.record.DeviceID, Updates: updates,
		SecretEnvelopes: authority.DeviceSecretEnvelopes,
	}
	if err := wire.ValidateDeviceConfigDelivery(&delivery); err != nil {
		return nil, err
	}
	last := &delivery.Updates[len(delivery.Updates)-1]
	if !wire.EqualCanonical(last.Envelope, authority.CurrentDeviceView) ||
		!wire.EqualCanonical(last.ControlSet, authority.ControlSet) ||
		!equalOptionalControlSet(last.PreviousControlSet, authority.PreviousControlSet) ||
		!equalOptionalRecoveryPolicy(last.RecoveryPolicy, authority.RecoveryPolicy) {
		return nil, errors.New("[device_config] delivery final authority 与线性化读取不一致")
	}
	return wire.MarshalCanonical(delivery)
}

func equalOptionalRecoveryPolicy(left, right *wire.RecoveryPolicyV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return wire.EqualCanonical(*left, *right)
}

func equalOptionalControlSet(left, right *wire.ControlSetV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return wire.EqualCanonical(*left, *right)
}

func (service *PrivateDeviceConfigService) authenticate(ctx context.Context, certificateDER []byte,
	trustedTime time.Time) (VerifiedDeviceIdentityV1, error) {
	return authenticateDeviceIdentity(ctx, certificateDER, trustedTime, service.allowedProfiles, service.identities)
}

func authenticateDeviceIdentity(ctx context.Context, certificateDER []byte, trustedTime time.Time,
	allowedProfiles []string, identities DeviceIdentityReader) (VerifiedDeviceIdentityV1, error) {
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	authority, err := identities(ctx, certificateHash)
	record := &authority.Record
	if err != nil || record.Schema != 1 || record.CertificateHash != certificateHash ||
		!oneOfDeviceStatus(record.IdentityStatus, "active", "revocation_pending") ||
		!containsString(allowedProfiles, record.ProfileRef.ProfileID) {
		return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] registry record 不存在或未获 service profile 授权")
	}
	if err := wire.VerifyConfigQCAuthority(authority.Head.HeadHash, authority.ConfigQC, &authority.Head,
		&authority.ControlSet, authority.PreviousControlSet); err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	registryRoot, err := wire.CAProfileRoot(authority.AdminCertificateProfiles, authority.DeviceCertificateProfiles)
	if err != nil || registryRoot != authority.Head.Body.Payload.CAProfileRoot ||
		!containsExactDeviceProfile(authority.DeviceCertificateProfiles, &record.ProfileState) {
		return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] profile state 未绑定 certified CA registry")
	}
	if err := wire.ValidateDeviceCertificateProfileRef(&record.ProfileRef, &record.ProfileState); err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	approvedAt, err := wire.ParseTimeZ(record.ApprovedAt)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	certificate, err := wire.VerifyDeviceCertificateAt(certificateDER, &record.ProfileState, record.DeviceID,
		record.IdentitySPKIHash, record.Platform, record.Responsibilities, record.Issuance, approvedAt, trustedTime)
	if err != nil {
		return VerifiedDeviceIdentityV1{}, err
	}
	view := &authority.CurrentDeviceView
	if !wire.EqualCanonical(view.SignedCurrent.Head, authority.Head) ||
		!bytes.Equal(view.SignedCurrent.QuorumCertificate, authority.ConfigQC) {
		return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] current view 未绑定认证 authority")
	}
	if _, err := wire.VerifyDeviceViewEnvelopeWithPrevious(view, &authority.ControlSet,
		authority.PreviousControlSet); err != nil || view.Payload.DeviceID != record.DeviceID ||
		view.Payload.ClusterID != record.ProfileState.ClusterID {
		return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] current view QC/inclusion/Device binding 无效")
	}
	if record.IdentityStatus == "active" {
		if view.Payload.State != "active" || view.Payload.Active.IdentitySPKIHash != record.IdentitySPKIHash ||
			!wire.EqualCanonical(view.Payload.Active.Responsibilities.Values, record.Responsibilities) {
			return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] active registry record 与 current view 不一致")
		}
	} else if view.Payload.State == "active" {
		return VerifiedDeviceIdentityV1{}, errors.New("[Device identity] revocation_pending identity 缺 tombstone view")
	}
	return VerifiedDeviceIdentityV1{record: *record, authority: authority, certificate: certificate}, nil
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
