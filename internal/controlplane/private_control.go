package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	PrivateControlOperationPath = "/private/v2/control/operations"
	maximumControlRequestBytes  = 4 << 20
)

// ControlAuthoritySnapshotV1 是一次请求使用的 immutable base authority。reader 必须
// 从同一次线性化读取返回这些字段，不能把不同 revision 的 head、ACL 与 ControlSet 拼接。
type ControlAuthoritySnapshotV1 struct {
	Head               wire.HeadEntryV2
	ConfigQC           json.RawMessage
	ControlSet         wire.ControlSetV1
	PreviousControlSet *wire.ControlSetV1
	Authorizations     []wire.AdminAuthorizationV1
	Profiles           map[string]wire.AdminCertificateProfileV1
}

type ControlAuthorityReader func(context.Context) (ControlAuthoritySnapshotV1, error)

// ControlScopeResolver 必须从 operation 所承诺的 exact payload preimage 推导 scope；
// handler 不接受客户端另报 scope，以免签名 operation 被搬到更宽资源范围。
type ControlScopeResolver func(context.Context, wire.ControlOperationV1) (wire.AdminResourceScopeV1, error)

type CertifiedControlOperationV1 struct {
	Schema             int                         `json:"schema"`
	Status             string                      `json:"status"`
	Head               wire.HeadEntryV2            `json:"head"`
	ConfigQC           json.RawMessage             `json:"config_qc"`
	OperationLeaf      wire.ControlOperationLeafV1 `json:"operation_leaf"`
	OperationLeafIndex int64                       `json:"operation_leaf_index"`
	OperationTreeSize  int64                       `json:"operation_tree_size"`
	OperationAuditPath []string                    `json:"operation_audit_path"`
}

type ControlOperationCommitter func(context.Context, wire.VerifiedAdminOperationV1) (CertifiedControlOperationV1, error)

type privateControlOperationRequestV1 struct {
	Schema           int                     `json:"schema"`
	ExpectedHeadHash string                  `json:"expected_head_hash"`
	RequestID        string                  `json:"request_id"`
	Operation        wire.ControlOperationV1 `json:"operation"`
}

type privateControlOperationResponseV1 struct {
	Schema             int                         `json:"schema"`
	Status             string                      `json:"status"`
	RequestID          string                      `json:"request_id"`
	Head               wire.HeadEntryV2            `json:"head"`
	ConfigQC           json.RawMessage             `json:"config_qc"`
	OperationLeaf      wire.ControlOperationLeafV1 `json:"operation_leaf"`
	OperationLeafIndex int64                       `json:"operation_leaf_index"`
	OperationTreeSize  int64                       `json:"operation_tree_size"`
	OperationAuditPath []string                    `json:"operation_audit_path"`
}

type privateControlErrorV1 struct {
	Schema int    `json:"schema"`
	Error  string `json:"error"`
}

// PrivateControlService 只能直接挂在 certified directory 指定的 overlay IP/port。
// 公网反代既没有匹配的 LocalAddr，也不能绕过下面的 admin leaf/head/QC/ACL 复验。
type PrivateControlService struct {
	localAddress string
	read         ControlAuthorityReader
	resolveScope ControlScopeResolver
	commit       ControlOperationCommitter
	schemas      wire.OperationSchemaRegistry
	now          func() time.Time
}

func NewPrivateControlService(overlayIP string, port int64, read ControlAuthorityReader,
	resolveScope ControlScopeResolver, commit ControlOperationCommitter,
	schemas wire.OperationSchemaRegistry, now func() time.Time) (*PrivateControlService, error) {
	address, err := netip.ParseAddr(overlayIP)
	if err != nil || address.String() != overlayIP || !address.IsPrivate() || port < 1 || port > 65535 ||
		read == nil || resolveScope == nil || commit == nil || now == nil || len(schemas) == 0 {
		return nil, errors.New("[private control] overlay tuple/dependencies/reader contract 无效")
	}
	copySchemas := make(wire.OperationSchemaRegistry, len(schemas))
	for kind, schema := range schemas {
		if kind == "" || strings.TrimSpace(kind) != kind || schema < 1 {
			return nil, errors.New("[private control] operation reader contract 无效")
		}
		copySchemas[kind] = schema
	}
	return &PrivateControlService{
		localAddress: net.JoinHostPort(overlayIP, strconv.FormatInt(port, 10)),
		read:         read, resolveScope: resolveScope, commit: commit, schemas: copySchemas, now: now,
	}, nil
}

func (service *PrivateControlService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != PrivateControlOperationPath || request.URL.RawQuery != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[private control] 路由不存在")
		return
	}
	if !service.matchesPrivateListener(request) || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) < 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[private control] 私有传输身份被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writePrivateControlError(writer, http.StatusBadRequest, "[private control] 请求被拒绝")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumControlRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumControlRequestBytes {
		writePrivateControlError(writer, http.StatusBadRequest, "[private control] 请求被拒绝")
		return
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		writePrivateControlError(writer, http.StatusBadRequest, "[private control] 请求被拒绝")
		return
	}
	var submitted privateControlOperationRequestV1
	if _, err := wire.DecodeStrict(body, maximumControlRequestBytes, &submitted); err != nil ||
		submitted.Schema != 1 || submitted.RequestID == "" || submitted.RequestID != submitted.Operation.Body.OperationID {
		writePrivateControlError(writer, http.StatusBadRequest, "[private control] 请求被拒绝")
		return
	}
	snapshot, err := service.read(request.Context())
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[private control] authority 暂不可用")
		return
	}
	if submitted.ExpectedHeadHash != snapshot.Head.HeadHash || submitted.ExpectedHeadHash != submitted.Operation.Body.ParentHeadHash {
		writePrivateControlError(writer, http.StatusConflict, "[private control] expected head 已过期")
		return
	}
	scope, err := service.resolveScope(request.Context(), submitted.Operation)
	if err != nil {
		writePrivateControlError(writer, http.StatusBadRequest, "[private control] payload scope 被拒绝")
		return
	}
	trustedTime := service.now().UTC()
	verified, err := wire.AuthorizeControlOperationAtHead(&submitted.Operation,
		request.TLS.PeerCertificates[0].Raw, &scope, trustedTime, service.schemas,
		&snapshot.Head, snapshot.ConfigQC, &snapshot.ControlSet, snapshot.PreviousControlSet,
		snapshot.Authorizations, snapshot.Profiles)
	if err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[private control] 管理员授权被拒绝")
		return
	}
	result, err := service.commit(request.Context(), verified)
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[private control] quorum 暂不可用")
		return
	}
	if err := verifyCertifiedControlOperation(&result, &submitted.Operation, request.TLS.PeerCertificates[0],
		&snapshot.Head, &snapshot.ControlSet, trustedTime, service.schemas); err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[private control] 提交结果校验失败")
		return
	}
	response := privateControlOperationResponseV1{
		Schema: 1, Status: "certified", RequestID: submitted.RequestID,
		Head: result.Head, ConfigQC: result.ConfigQC, OperationLeaf: result.OperationLeaf,
		OperationLeafIndex: result.OperationLeafIndex, OperationTreeSize: result.OperationTreeSize,
		OperationAuditPath: append([]string(nil), result.OperationAuditPath...),
	}
	encoded, err := wire.MarshalCanonical(response)
	if err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[private control] 结果编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func (service *PrivateControlService) matchesPrivateListener(request *http.Request) bool {
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil || local.String() != service.localAddress {
		return false
	}
	host := request.Host
	return host == service.localAddress
}

func verifyCertifiedControlOperation(result *CertifiedControlOperationV1, operation *wire.ControlOperationV1,
	peerCertificate *x509.Certificate, parent *wire.HeadEntryV2, set *wire.ControlSetV1,
	trustedTime time.Time, schemas wire.OperationSchemaRegistry) error {
	if result == nil || operation == nil || peerCertificate == nil || parent == nil || set == nil ||
		result.Schema != 1 || result.Status != "certified" || result.Head.Body.Payload.HeadKind != "ordinary" {
		return errors.New("[private control] certified result header 无效")
	}
	if err := wire.ValidateHeadEntry(&result.Head, parent); err != nil {
		return err
	}
	if err := wire.VerifyConfigQCAuthority(result.Head.HeadHash, result.ConfigQC, &result.Head, set, nil); err != nil {
		return err
	}
	objectID, err := wire.ControlOperationObjectID(operation, peerCertificate.RawSubjectPublicKeyInfo, trustedTime, schemas)
	if err != nil || result.OperationLeaf.OperationID != operation.Body.OperationID || result.OperationLeaf.ObjectID != objectID {
		return errors.New("[private control] result operation leaf 未绑定提交 operation")
	}
	return wire.VerifyControlOperationInclusion(&result.OperationLeaf, result.OperationLeafIndex,
		result.OperationTreeSize, result.OperationAuditPath, &result.Head)
}

func writePrivateControlError(writer http.ResponseWriter, status int, message string) {
	body, _ := wire.MarshalCanonical(privateControlErrorV1{Schema: 1, Error: message})
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
