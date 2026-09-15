package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	PrivateDeviceReportPath  = "/private/v2/device/report"
	maximumDeviceReportBytes = 4 << 20
)

var ErrDeviceReportSequence = errors.New("[device_report] report sequence 回退或同序号内容冲突")

// VerifiedDeviceReportV2 只能由 private Device mTLS、current view/floors 与
// Device identity low-S signature 全部验证后产生。
type VerifiedDeviceReportV2 struct {
	body     wire.DeviceReportBodyV2
	payload  []byte
	identity VerifiedDeviceIdentityV1
}

func (verified VerifiedDeviceReportV2) Body() wire.DeviceReportBodyV2 {
	return verified.body
}

func (verified VerifiedDeviceReportV2) Payload() []byte {
	return append([]byte(nil), verified.payload...)
}

func (verified VerifiedDeviceReportV2) DeviceID() string {
	return verified.identity.DeviceID()
}

// DeviceReportCommitter 必须以 (Device ID, certificate hash) 为 key 原子 CAS
// report_sequence；同序号仅允许 exact report 重试，不能用最后写入覆盖冲突报告。
type DeviceReportCommitter func(context.Context, VerifiedDeviceReportV2) error

// DeviceReportPayloadVerifier 按 kind/schema 严格解码 payload；只有 hash 正确不代表
// reader 理解字段，unknown field 也必须在生成 opaque report 前失败。
type DeviceReportPayloadVerifier func(string, int64, []byte) error

type PrivateDeviceReportService struct {
	localAddress    string
	allowedProfiles []string
	identities      DeviceIdentityReader
	verifyPayload   DeviceReportPayloadVerifier
	commit          DeviceReportCommitter
	schemas         wire.DeviceReportSchemaRegistry
	now             func() time.Time
	maximumAge      time.Duration
	maximumSkew     time.Duration
}

func NewPrivateDeviceReportService(endpoint wire.PrivateControlServiceV1, identities DeviceIdentityReader,
	verifyPayload DeviceReportPayloadVerifier, commit DeviceReportCommitter,
	schemas wire.DeviceReportSchemaRegistry, now func() time.Time,
	maximumAge, maximumSkew time.Duration) (*PrivateDeviceReportService, error) {
	if err := wire.ValidatePrivateControlService(&endpoint); err != nil {
		return nil, err
	}
	if endpoint.Role != "device_report" || identities == nil || verifyPayload == nil || commit == nil || now == nil || len(schemas) == 0 ||
		maximumAge <= 0 || maximumAge > 24*time.Hour || maximumSkew < 0 || maximumSkew > 5*time.Minute {
		return nil, errors.New("[device_report] service role/dependencies/freshness policy 无效")
	}
	copySchemas := make(wire.DeviceReportSchemaRegistry, len(schemas))
	for kind, schema := range schemas {
		if kind == "" || strings.TrimSpace(kind) != kind || schema < 1 {
			return nil, errors.New("[device_report] reader contract 无效")
		}
		copySchemas[kind] = schema
	}
	return &PrivateDeviceReportService{
		localAddress:    net.JoinHostPort(endpoint.OverlayIP, strconv.FormatInt(endpoint.Port, 10)),
		allowedProfiles: append([]string(nil), endpoint.AuthorizedSubjectProfiles...),
		identities:      identities, verifyPayload: verifyPayload, commit: commit, schemas: copySchemas, now: now,
		maximumAge: maximumAge, maximumSkew: maximumSkew,
	}, nil
}

func (service *PrivateDeviceReportService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != PrivateDeviceReportPath || request.URL.RawQuery != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[device_report] 路由不存在")
		return
	}
	if !matchesExactPrivateListener(request, service.localAddress) || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[device_report] Device mTLS 被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_report] 请求格式被拒绝")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumDeviceReportBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumDeviceReportBytes {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_report] 请求正文无效或过大")
		return
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_report] 请求不是 exact canonical JSON")
		return
	}
	var envelope wire.DeviceReportEnvelopeV2
	if _, err := wire.DecodeStrict(body, maximumDeviceReportBytes, &envelope); err != nil {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_report] report wire 无效")
		return
	}
	trustedTime := service.now().UTC()
	identity, err := authenticateDeviceIdentity(request.Context(), request.TLS.PeerCertificates[0].Raw,
		trustedTime, service.allowedProfiles, service.identities)
	if err != nil || identity.IdentityStatus() != "active" {
		writePrivateControlError(writer, http.StatusForbidden, "[device_report] Device identity 被拒绝")
		return
	}
	publicKey, ok := identity.certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		writePrivateControlError(writer, http.StatusForbidden, "[device_report] Device identity key profile 被拒绝")
		return
	}
	view := &identity.authority.CurrentDeviceView
	floors, err := wire.VerifyDeviceViewEnvelopeWithPrevious(view, &identity.authority.ControlSet,
		identity.authority.PreviousControlSet)
	if err != nil || !wire.EqualCanonical(envelope.Body.AcceptedFloors, floors) {
		writePrivateControlError(writer, http.StatusConflict, "[device_report] report floors 不是当前 certified Device view")
		return
	}
	if err := wire.VerifyDeviceReport(&envelope, publicKey, identity.DeviceID(), identity.IdentitySPKIHash(),
		trustedTime, service.maximumAge, service.maximumSkew, service.schemas); err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[device_report] Device report signature/freshness 被拒绝")
		return
	}
	// reader contract 可能包含非平凡解码逻辑；只有身份、current floors 和签名都成立后
	// 才允许攻击者控制的 payload 进入该边界。
	if err := service.verifyPayload(envelope.Body.Kind, envelope.Body.PayloadSchema, envelope.Payload); err != nil {
		writePrivateControlError(writer, http.StatusBadRequest, "[device_report] payload schema/字段被拒绝")
		return
	}
	verified := VerifiedDeviceReportV2{body: envelope.Body, payload: append([]byte(nil), envelope.Payload...), identity: identity}
	if err := service.commit(request.Context(), verified); err != nil {
		if errors.Is(err, ErrDeviceReportSequence) {
			writePrivateControlError(writer, http.StatusConflict, "[device_report] report sequence 冲突")
			return
		}
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[device_report] report sink 暂不可用")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusNoContent)
}
