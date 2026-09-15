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
// 从同一次线性化读取返回这些字段，不能把不同 revision 的 head、ACL 与 ControlSet 拼接（D104）。
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
// handler 不接受客户端另报 scope，以免签名 operation 被搬到更宽资源范围（D104）。
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

// ReplayReader 只查 exact 已提交 operation，不执行新的写入。Parent/ControlSet
// 必须来自已验证的本机历史；结果仍由 handler 重验 QC、签名和 inclusion。
type ControlOperationReplayV1 struct {
	Parent     wire.HeadEntryV2
	ControlSet wire.ControlSetV1
	Result     CertifiedControlOperationV1
}

type ControlOperationReplayReader func(context.Context, wire.ControlOperationV1) (*ControlOperationReplayV1, error)

type privateControlOperationRequestV1 struct {
	Schema           int                     `json:"schema"`
	ExpectedHeadHash string                  `json:"expected_head_hash"`
	RequestID        string                  `json:"request_id"`
	Operation        wire.ControlOperationV1 `json:"operation"`
	Payload          json.RawMessage         `json:"payload,omitempty"`
}

type operationPayloadKey struct{}

// OperationPayload 返回当前私有请求的原文。resolver/committer 必须按 kind
// 严格解码并比较签名中的 typed payload hash，不能把此值当作已获授权（D104）。
func OperationPayload(ctx context.Context) json.RawMessage {
	payload, _ := ctx.Value(operationPayloadKey{}).(json.RawMessage)
	return append(json.RawMessage(nil), payload...)
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
// 公网反代既没有匹配的 LocalAddr，也不能绕过下面的 admin leaf/head/QC/ACL 复验（D104、D131）。
type PrivateControlService struct {
	localAddress string
	read         ControlAuthorityReader
	resolveScope ControlScopeResolver
	commit       ControlOperationCommitter
	replay       ControlOperationReplayReader
	schemas      wire.OperationSchemaRegistry
	now          func() time.Time
}

func NewPrivateControlService(overlayIP string, port int64, read ControlAuthorityReader,
	resolveScope ControlScopeResolver, commit ControlOperationCommitter,
	schemas wire.OperationSchemaRegistry, now func() time.Time, replay ...ControlOperationReplayReader) (*PrivateControlService, error) {
	address, err := netip.ParseAddr(overlayIP)
	if err != nil || address.String() != overlayIP || !address.IsPrivate() || port < 1 || port > 65535 ||
		read == nil || resolveScope == nil || commit == nil || now == nil || len(schemas) == 0 {
		return nil, errors.New("[D104 private control] overlay tuple/dependencies/reader contract 无效")
	}
	copySchemas := make(wire.OperationSchemaRegistry, len(schemas))
	for kind, schema := range schemas {
		if kind == "" || strings.TrimSpace(kind) != kind || schema < 1 {
			return nil, errors.New("[D104 private control] operation reader contract 无效")
		}
		copySchemas[kind] = schema
	}
	if len(replay) > 1 || len(replay) == 1 && replay[0] == nil {
		return nil, errors.New("[D104 private control] replay reader 配置无效")
	}
	service := &PrivateControlService{
		localAddress: net.JoinHostPort(overlayIP, strconv.FormatInt(port, 10)),
		read:         read, resolveScope: resolveScope, commit: commit, schemas: copySchemas, now: now,
	}
	if len(replay) == 1 {
		service.replay = replay[0]
	}
	return service, nil
}

func (service *PrivateControlService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != PrivateControlOperationPath || request.URL.RawQuery != "" {
		writePrivateControlError(writer, http.StatusNotFound, "[D131 private control] 路由不存在")
		return
	}
	if !service.matchesPrivateListener(request) || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) < 1 {
		writePrivateControlError(writer, http.StatusForbidden, "[D104 private control] 私有传输身份被拒绝")
		return
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writePrivateControlError(writer, http.StatusBadRequest, "[D104 private control] 请求被拒绝")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumControlRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumControlRequestBytes {
		writePrivateControlError(writer, http.StatusBadRequest, "[D104 private control] 请求被拒绝")
		return
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		writePrivateControlError(writer, http.StatusBadRequest, "[D104 private control] 请求被拒绝")
		return
	}
	var submitted privateControlOperationRequestV1
	if _, err := wire.DecodeStrict(body, maximumControlRequestBytes, &submitted); err != nil ||
		submitted.Schema != 1 || submitted.RequestID == "" || submitted.RequestID != submitted.Operation.Body.OperationID {
		writePrivateControlError(writer, http.StatusBadRequest, "[D104 private control] 请求被拒绝")
		return
	}
	snapshot, err := service.read(request.Context())
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[D104 private control] authority 暂不可用")
		return
	}
	if submitted.ExpectedHeadHash != submitted.Operation.Body.ParentHeadHash {
		writePrivateControlError(writer, http.StatusConflict, "[D104 private control] expected head 已过期")
		return
	}
	ctx := context.WithValue(request.Context(), operationPayloadKey{}, submitted.Payload)
	scope, err := service.resolveScope(ctx, submitted.Operation)
	if err != nil {
		writePrivateControlError(writer, http.StatusBadRequest, "[D104 private control] payload scope 被拒绝")
		return
	}
	trustedTime := service.now().UTC()
	if submitted.ExpectedHeadHash != snapshot.Head.HeadHash {
		if service.replay == nil {
			writePrivateControlError(writer, http.StatusConflict, "[D104 private control] expected head 已过期")
			return
		}
		if err := authorizeOperationReplay(&submitted.Operation, request.TLS.PeerCertificates[0].Raw, &scope, &snapshot, trustedTime); err != nil {
			writePrivateControlError(writer, http.StatusForbidden, "[D104 private control] 当前管理员无结果读取权限")
			return
		}
		replay, err := service.replay(ctx, submitted.Operation)
		if err != nil || replay == nil {
			writePrivateControlError(writer, http.StatusConflict, "[D104 private control] expected head 已过期，缺同一已提交请求")
			return
		}
		committedAt, err := wire.ParseTimeZ(replay.Result.Head.Body.Payload.CommittedLogicalTime)
		if err != nil || replay.Parent.HeadHash != submitted.ExpectedHeadHash ||
			verifyCertifiedControlOperation(&replay.Result, &submitted.Operation, request.TLS.PeerCertificates[0],
				&replay.Parent, &replay.ControlSet, committedAt, service.schemas) != nil {
			writePrivateControlError(writer, http.StatusInternalServerError, "[D104 private control] 历史提交结果校验失败")
			return
		}
		writeControlOperationResponse(writer, submitted.RequestID, replay.Result)
		return
	}
	verified, err := wire.AuthorizeControlOperationAtHead(&submitted.Operation,
		request.TLS.PeerCertificates[0].Raw, &scope, trustedTime, service.schemas,
		&snapshot.Head, snapshot.ConfigQC, &snapshot.ControlSet, snapshot.PreviousControlSet,
		snapshot.Authorizations, snapshot.Profiles)
	if err != nil {
		writePrivateControlError(writer, http.StatusForbidden, "[D104 private control] 管理员授权被拒绝")
		return
	}
	result, err := service.commit(ctx, verified)
	if err != nil {
		writePrivateControlError(writer, http.StatusServiceUnavailable, "[D104 private control] quorum 暂不可用")
		return
	}
	if err := verifyCertifiedControlOperation(&result, &submitted.Operation, request.TLS.PeerCertificates[0],
		&snapshot.Head, &snapshot.ControlSet, trustedTime, service.schemas); err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D104 private control] 提交结果校验失败")
		return
	}
	writeControlOperationResponse(writer, submitted.RequestID, result)
}

func writeControlOperationResponse(writer http.ResponseWriter, requestID string, result CertifiedControlOperationV1) {
	response := privateControlOperationResponseV1{
		Schema: 1, Status: "certified", RequestID: requestID,
		Head: result.Head, ConfigQC: result.ConfigQC, OperationLeaf: result.OperationLeaf,
		OperationLeafIndex: result.OperationLeafIndex, OperationTreeSize: result.OperationTreeSize,
		OperationAuditPath: append([]string(nil), result.OperationAuditPath...),
	}
	encoded, err := wire.MarshalCanonical(response)
	if err != nil {
		writePrivateControlError(writer, http.StatusInternalServerError, "[D104 private control] 结果编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func authorizeOperationReplay(operation *wire.ControlOperationV1, peer []byte, scope *wire.AdminResourceScopeV1,
	snapshot *ControlAuthoritySnapshotV1, now time.Time) error {
	if err := wire.VerifyConfigQCAuthority(snapshot.Head.HeadHash, snapshot.ConfigQC, &snapshot.Head,
		&snapshot.ControlSet, snapshot.PreviousControlSet); err != nil {
		return err
	}
	root, err := wire.AdminACLRoot(snapshot.Authorizations, snapshot.Profiles)
	if err != nil || root != snapshot.Head.Body.Payload.AdminACLRoot || operation.Body.ClusterID != snapshot.Head.Body.Payload.ClusterID {
		return errors.New("[D104 replay] current ACL/cluster 无效")
	}
	digest, err := wire.AdminCertificateDigest(peer)
	if err != nil || digest != operation.Body.AdminCertDigest {
		return errors.New("[D104 replay] 仅允许原操作者读取 exact request")
	}
	scopeHash, err := wire.AdminResourceScopeHash(scope)
	if err != nil {
		return err
	}
	for _, authorization := range snapshot.Authorizations {
		if authorization.AdminCertificateDigest != digest || authorization.AdminID != operation.Body.AuthorID ||
			authorization.Status != "active" || !containsString(authorization.AllowedOperationKinds, operation.Body.Kind) {
			continue
		}
		profile, found := snapshot.Profiles[authorization.CertificateProfileRef.ProfileID]
		if !found || wire.ValidateAdminAuthorizationAt(&authorization, &profile, now) != nil {
			continue
		}
		for _, allowed := range authorization.Scopes {
			if hash, err := wire.AdminResourceScopeHash(&allowed); err == nil && hash == scopeHash {
				return nil
			}
		}
	}
	return errors.New("[D104 replay] 当前 ACL 未授权该操作的 scope")
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
		return errors.New("[D104 private control] certified result header 无效")
	}
	if err := wire.ValidateHeadEntry(&result.Head, parent); err != nil {
		return err
	}
	if err := wire.VerifyConfigQCAuthority(result.Head.HeadHash, result.ConfigQC, &result.Head, set, nil); err != nil {
		return err
	}
	objectID, err := wire.ControlOperationObjectID(operation, peerCertificate.RawSubjectPublicKeyInfo, trustedTime, schemas)
	if err != nil || result.OperationLeaf.OperationID != operation.Body.OperationID || result.OperationLeaf.ObjectID != objectID {
		return errors.New("[D104 private control] result operation leaf 未绑定提交 operation")
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
