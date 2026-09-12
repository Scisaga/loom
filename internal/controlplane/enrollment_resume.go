package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const PrivateEnrollmentResumePath = "/private/v2/control/enrollment/resume"

type EnrollmentResumeIssuer interface {
	Issue(context.Context, enrollmentv2.ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error)
}

type privateEnrollmentResumeRequestV1 struct {
	Schema           int                                  `json:"schema"`
	ExpectedHeadHash string                               `json:"expected_head_hash"`
	RequestID        string                               `json:"request_id"`
	Operation        wire.ControlOperationV1              `json:"operation"`
	Authorization    wire.EnrollmentResumeAuthorizationV1 `json:"authorization"`
}

type privateEnrollmentResumeResponseV1 struct {
	Schema             int                               `json:"schema"`
	Status             string                            `json:"status"`
	RequestID          string                            `json:"request_id"`
	Head               wire.HeadEntryV2                  `json:"head"`
	ConfigQC           json.RawMessage                   `json:"config_qc"`
	OperationLeaf      wire.ControlOperationLeafV1       `json:"operation_leaf"`
	OperationLeafIndex int64                             `json:"operation_leaf_index"`
	OperationTreeSize  int64                             `json:"operation_tree_size"`
	OperationAuditPath []string                          `json:"operation_audit_path"`
	Descriptor         wire.EnrollmentResumeDescriptorV1 `json:"descriptor"`
}

// PrivateEnrollmentResumeControlService 把 resume 签发限制为 private control_api 上
// 经 admin mTLS、base ACL 和 certified operation 授权的一次性响应（D104、D130）。
type PrivateEnrollmentResumeControlService struct {
	localAddress string
	read         ControlAuthorityReader
	commit       ControlOperationCommitter
	schemas      wire.OperationSchemaRegistry
	issue        EnrollmentResumeIssuer
	now          func() time.Time
}

func NewPrivateEnrollmentResumeControlService(overlayIP string, port int64,
	read ControlAuthorityReader, commit ControlOperationCommitter,
	schemas wire.OperationSchemaRegistry, issue EnrollmentResumeIssuer,
	now func() time.Time) (*PrivateEnrollmentResumeControlService, error) {
	address, err := netip.ParseAddr(overlayIP)
	if err != nil || address.String() != overlayIP || !address.IsPrivate() || port < 1 || port > 65535 ||
		read == nil || commit == nil || issue == nil || now == nil || len(schemas) == 0 ||
		schemas["issue_enrollment_resume"] != 1 {
		return nil, errors.New("[D130 resume] private control tuple/dependencies/schema 无效")
	}
	copySchemas := make(wire.OperationSchemaRegistry, len(schemas))
	for kind, schema := range schemas {
		if kind == "" || strings.TrimSpace(kind) != kind || schema < 1 {
			return nil, errors.New("[D130 resume] operation reader contract 无效")
		}
		copySchemas[kind] = schema
	}
	return &PrivateEnrollmentResumeControlService{
		localAddress: netip.AddrPortFrom(address, uint16(port)).String(),
		read:         read, commit: commit, schemas: copySchemas, issue: issue, now: now,
	}, nil
}

func (service *PrivateEnrollmentResumeControlService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.URL.Path != PrivateEnrollmentResumePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[D130 resume] 路由不存在")
		return
	}
	if !service.matchesPrivateListener(request) || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) != 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[D130 resume] admin private transport identity 被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writePrivateControlError(writer, http.StatusBadRequest, "[D130 resume] 请求格式被拒绝")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumControlRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumControlRequestBytes {
		writePrivateControlError(writer, http.StatusBadRequest, "[D130 resume] 请求正文无效或过大")
		return
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		writePrivateControlError(writer, http.StatusBadRequest, "[D130 resume] 请求不是 exact canonical JSON")
		return
	}
	var submitted privateEnrollmentResumeRequestV1
	if _, err := wire.DecodeStrict(body, maximumControlRequestBytes, &submitted); err != nil ||
		submitted.Schema != 1 || submitted.RequestID == "" ||
		submitted.RequestID != submitted.Operation.Body.OperationID {
		writePrivateControlError(writer, http.StatusBadRequest, "[D130 resume] 请求 identity 无效")
		return
	}
	authorizationHash, err := wire.EnrollmentResumeAuthorizationHash(&submitted.Authorization)
	operationBody := &submitted.Operation.Body
	if err != nil || operationBody.Kind != "issue_enrollment_resume" || operationBody.PayloadSchema != 1 ||
		operationBody.PayloadHash != authorizationHash || operationBody.ClusterID != submitted.Authorization.ClusterID {
		writePrivateControlError(writer, http.StatusBadRequest, "[D130 resume] operation/payload binding 无效")
		return
	}
	snapshot, err := service.read(request.Context())
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[D130 resume] authority 暂不可用")
		return
	}
	if submitted.ExpectedHeadHash != snapshot.Head.HeadHash || submitted.ExpectedHeadHash != operationBody.ParentHeadHash {
		writePrivateControlError(writer, http.StatusConflict, "[D130 resume] expected head 已过期")
		return
	}
	scope := wire.AdminResourceScopeV1{ScopeKind: "device",
		Device: &wire.AdminScopeIDsV1{DeviceIDs: []string{submitted.Authorization.DeviceID}}}
	trustedTime := service.now().UTC()
	verified, err := wire.AuthorizeControlOperationAtHead(&submitted.Operation,
		request.TLS.PeerCertificates[0].Raw, &scope, trustedTime, service.schemas,
		&snapshot.Head, snapshot.ConfigQC, &snapshot.ControlSet, snapshot.PreviousControlSet,
		snapshot.Authorizations, snapshot.Profiles)
	if err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[D130 resume] 管理员授权被拒绝")
		return
	}
	result, err := service.commit(request.Context(), verified)
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[D130 resume] quorum 暂不可用")
		return
	}
	if err := verifyCertifiedControlOperation(&result, &submitted.Operation, request.TLS.PeerCertificates[0],
		&snapshot.Head, &snapshot.ControlSet, trustedTime, service.schemas); err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D130 resume] certified operation 校验失败")
		return
	}
	descriptor, err := service.issue.Issue(request.Context(), enrollmentv2.ResumeIssueRequestV1{
		Schema: 1, OperationID: operationBody.OperationID,
		ClusterID: submitted.Authorization.ClusterID, InviteID: submitted.Authorization.InviteID,
		RequestID: submitted.Authorization.RequestID, DeviceID: submitted.Authorization.DeviceID,
		ExpectedTransactionStateHash: submitted.Authorization.ExpectedTransactionStateHash,
		IssuedAt:                     result.Head.Body.Payload.CommittedLogicalTime, ExpiresAt: submitted.Authorization.ExpiresAt,
	})
	if err != nil {
		writePrivateControlError(writer, http.StatusConflict, "[D130 resume] transaction/resume issuance 冲突")
		return
	}
	if err := validateResumeControlIssuerResult(&descriptor, &submitted.Authorization,
		result.Head.Body.Payload.CommittedLogicalTime, trustedTime); err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D130 resume] issuer result binding 无效")
		return
	}
	response := privateEnrollmentResumeResponseV1{
		Schema: 1, Status: "certified", RequestID: submitted.RequestID,
		Head: result.Head, ConfigQC: result.ConfigQC, OperationLeaf: result.OperationLeaf,
		OperationLeafIndex: result.OperationLeafIndex, OperationTreeSize: result.OperationTreeSize,
		OperationAuditPath: append([]string(nil), result.OperationAuditPath...), Descriptor: descriptor,
	}
	encoded, err := wire.MarshalCanonical(response)
	if err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D130 resume] response 编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func validateResumeControlIssuerResult(descriptor *wire.EnrollmentResumeDescriptorV1,
	authorization *wire.EnrollmentResumeAuthorizationV1, issuedAt string, trustedTime time.Time) error {
	if descriptor == nil || authorization == nil || trustedTime.IsZero() ||
		descriptor.ClusterID != authorization.ClusterID || descriptor.InviteID != authorization.InviteID ||
		descriptor.RequestID != authorization.RequestID || descriptor.ExpiresAt != authorization.ExpiresAt ||
		descriptor.EnrollmentTransactionStateHash != authorization.ExpectedTransactionStateHash {
		return errors.New("[D130 resume] descriptor 与 admin payload 不匹配")
	}
	body := &descriptor.ResumeTunnelCapability.Body
	binding := body.ResumeBinding
	if body.Mode != "resume_committed_claim" || body.ClusterID != authorization.ClusterID ||
		body.InviteID != authorization.InviteID || body.IssuedAt != issuedAt || body.NotBefore != issuedAt ||
		body.ExpiresAt != authorization.ExpiresAt || binding == nil || binding.RequestID != authorization.RequestID ||
		binding.EnrollmentTransactionStateHash != authorization.ExpectedTransactionStateHash ||
		descriptor.ClaimCoreHash != binding.ClaimCoreHash || descriptor.ClaimOperationHash != binding.ClaimOperationHash ||
		descriptor.AdmissionQCHash != binding.AdmissionQCHash {
		return errors.New("[D130 resume] capability 与 certified operation/descriptor 不匹配")
	}
	committed, err := wire.ParseTimeZ(issuedAt)
	expires, expiresErr := wire.ParseTimeZ(authorization.ExpiresAt)
	effectiveTime := trustedTime.UTC()
	if err == nil && committed.After(effectiveTime) {
		effectiveTime = committed
	}
	if err != nil || expiresErr != nil || !effectiveTime.Before(expires) {
		return errors.New("[D130 resume] certified operation/descriptor time 无效")
	}
	return nil
}

func (service *PrivateEnrollmentResumeControlService) matchesPrivateListener(request *http.Request) bool {
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil || local.String() != service.localAddress {
		return false
	}
	return request.Host == service.localAddress
}
