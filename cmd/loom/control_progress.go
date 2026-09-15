package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

const controlOperationsUIPath = "/control-operations"

type controlOperationProgressV1 struct {
	RequestID string               `json:"request_id"`
	Kind      string               `json:"kind"`
	Phase     controlplane.Phase   `json:"phase"`
	Phases    []controlplane.Phase `json:"phases"`
	HeadHash  string               `json:"head_hash"`
	RaftIndex int64                `json:"raft_index"`
	Certified bool                 `json:"certified"`
}

type controlOperationProgressResponseV1 struct {
	Schema     int                          `json:"schema"`
	Writable   bool                         `json:"writable"`
	Operations []controlOperationProgressV1 `json:"operations"`
}

// 写流程持有 runtime.mu 等待 commit/QC 时，读取 immutable snapshot 仍能呈现
// 已耐久化的阶段；不能为了展示 pending 再等待同一把写锁（D104）。
type controlOperationReadState struct {
	authority      controlplane.State
	authorizations []wire.AdminAuthorizationV1
	profiles       map[string]wire.AdminCertificateProfileV1
	response       controlOperationProgressResponseV1
}

var controlOperationPhases = []controlplane.Phase{
	controlplane.PhasePending, controlplane.PhaseCommittedNotCertified,
	controlplane.PhaseCertified, controlplane.PhaseReconciled, controlplane.PhaseApplied,
}

func controlPhaseIndex(phase controlplane.Phase) int {
	for index, candidate := range controlOperationPhases {
		if phase == candidate {
			return index
		}
	}
	return -1
}

func (runtime *controlRuntime) publishOperationProgressLocked() {
	state := runtime.store.Snapshot()
	copy := &controlOperationReadState{authority: state, profiles: cloneAdminProfiles(runtime.config.AdminProfiles),
		response: controlOperationProgressResponseV1{Schema: 1, Writable: state.Active == nil && state.CertifiedHead != nil,
			Operations: make([]controlOperationProgressV1, 0, len(runtime.journal.Records))}}
	encoded, _ := json.Marshal(runtime.config.Authorizations)
	_ = json.Unmarshal(encoded, &copy.authorizations)
	for _, record := range runtime.journal.Records {
		phases := append([]controlplane.Phase(nil), record.Phases...)
		phase := controlplane.PhasePending
		if len(phases) != 0 {
			phase = phases[len(phases)-1]
		} else if record.Result != nil {
			// 旧日志没有阶段历史，只呈现已经存在的 QC；不伪造过去的 reconcile（D104）。
			phase = controlplane.PhaseCertified
			phases = []controlplane.Phase{phase}
		} else {
			phases = []controlplane.Phase{phase}
		}
		kind := record.Operation.Body.Kind
		if record.Enrollment != nil && record.Enrollment.Mutation.Preimage != nil {
			kind = "enrollment_" + record.Enrollment.Mutation.Preimage.Kind
		}
		copy.response.Operations = append(copy.response.Operations, controlOperationProgressV1{
			RequestID: record.Leaf.OperationID, Kind: kind,
			Phase: phase, Phases: phases, HeadHash: record.Candidate.HeadHash,
			RaftIndex: record.Candidate.Body.Payload.RaftIndex, Certified: record.Result != nil,
		})
		if controlPhaseIndex(phase) < controlPhaseIndex(controlplane.PhaseApplied) && record.Result == nil {
			copy.response.Writable = false
		}
	}
	runtime.progress.Store(copy)
}

func (runtime *controlRuntime) recordOperationPhaseLocked(entryHash string, phase controlplane.Phase) error {
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Candidate.EntryHash != entryHash {
			continue
		}
		if controlPhaseIndex(phase) < 0 {
			return errors.New("[D104] 未知 operation phase")
		}
		if len(record.Phases) > 0 {
			previous := record.Phases[len(record.Phases)-1]
			if controlPhaseIndex(previous) >= controlPhaseIndex(phase) {
				return nil
			}
		}
		record.Phases = append(record.Phases, phase)
		if err := runtime.persistJournalLocked(); err != nil {
			record.Phases = record.Phases[:len(record.Phases)-1]
			return err
		}
		if runtime.checkpoint != nil {
			return runtime.checkpoint(phase)
		}
		return nil
	}
	// Genesis 没有普通 operation。它的 Head/QC 仍供进度 API 认证读取（D104）。
	runtime.publishOperationProgressLocked()
	return nil
}

func (runtime *controlRuntime) recoverAppliedProgressLocked() error {
	state := runtime.store.Snapshot()
	if state.Active != nil || state.CertifiedHead == nil {
		return nil
	}
	for _, record := range runtime.journal.Records {
		if record.Candidate.EntryHash == state.CertifiedHead.EntryHash && record.Result != nil &&
			len(record.Phases) > 0 && record.Phases[len(record.Phases)-1] == controlplane.PhaseReconciled {
			return runtime.recordOperationPhaseLocked(record.Candidate.EntryHash, controlplane.PhaseApplied)
		}
	}
	runtime.publishOperationProgressLocked()
	return nil
}

// pending journal 比 Raft append 更早落盘。重启已 campaign 到新 term 时，只能
// 在同一个未改变的 base 上重算尚未提交的坐标；不能生成第二个 operation（D104）。
func (runtime *controlRuntime) recoverPendingOperations() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.recoverPendingOperationsLocked()
}

func (runtime *controlRuntime) recoverPendingOperationsLocked() error {
	if err := runtime.restoreProvisionalResultsLocked(); err != nil {
		return err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return err
	}
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Result != nil {
			continue
		}
		if record.Enrollment != nil {
			// Enrollment candidate 内的签发坐标和时间已经进入证书/操作，不能重定位。
			if err := runtime.verifyEnrollmentRecord(index); err != nil {
				return err
			}
			if _, err := runtime.leader.ReplicateHead(context.Background(), runtime.store, record.Candidate); err != nil {
				return err
			}
			if err := runtime.finishCommittedLocked(); err != nil {
				return err
			}
			continue
		}
		state := runtime.store.Snapshot()
		if state.Active != nil || state.CertifiedHead == nil || state.CertifiedHead.HeadHash != record.Operation.Body.ParentHeadHash {
			return errors.New("[D104] pending operation 的 base 已改变，不能隐式改签或丢弃")
		}
		if record.Activation != nil {
			if err := runtime.verifyActivationRecord(index); err != nil {
				return err
			}
		} else if record.AdminRotation != nil {
			// 本机维护轮换有独立的旧身份签名、新 key PoP 和权限不变验证；
			// 它永远不能注册为网络管理 operation（D104、D132）。
			if err := runtime.verifyAdminRotationRecord(index); err != nil {
				return err
			}
		} else if record.Invite != nil || record.DevicePublication != nil {
			if err := runtime.verifyAdminOperationRecord(index); err != nil {
				return err
			}
		} else {
			certificateDER, err := authorizedAdminCertificate(runtime.config.Authorizations, record.Operation.Body.AdminCertDigest)
			if err != nil {
				return err
			}
			certificate, err := x509.ParseCertificate(certificateDER)
			if err != nil {
				return err
			}
			scope, err := runtime.resolveScope(context.Background(), record.Operation)
			if err != nil {
				return err
			}
			qc, err := wire.MarshalCanonical(state.CertifiedQC)
			if err != nil {
				return err
			}
			if _, err := wire.AuthorizeControlOperationAtHead(&record.Operation, certificate.Raw, &scope,
				runtime.now().UTC(), controlOperationSchemas, state.CertifiedHead, qc, &state.ControlSet, nil,
				runtime.config.Authorizations, runtime.config.AdminProfiles); err != nil {
				return err
			}
		}
		raft := runtime.storage.SnapshotRaft()
		if len(raft.Log) == 0 || raft.LastApplied != raft.CommitIndex || int64(len(raft.Log)) != raft.CommitIndex {
			return errors.New("[D104] pending operation 缺已恢复的稳定 Raft prefix")
		}
		body := record.Candidate.Body
		body.Payload.RaftTerm = raft.CurrentTerm
		body.Payload.RaftIndex = int64(len(raft.Log)) + 1
		body.Payload.ControlRevision = body.Payload.RaftIndex
		body.Payload.PreviousLogEntryHash = raft.Log[len(raft.Log)-1].EntryHash
		logical := runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
		if logical < state.CertifiedHead.Body.Payload.CommittedLogicalTime {
			logical = state.CertifiedHead.Body.Payload.CommittedLogicalTime
		}
		body.Payload.CommittedLogicalTime = logical
		if record.Activation != nil {
			var err error
			body, err = wire.RuntimeActivationHeadBody(&record.Activation.Bundle, raft.CurrentTerm,
				int64(len(raft.Log))+1, raft.Log[len(raft.Log)-1].EntryHash, logical)
			if err != nil {
				return err
			}
		}
		candidate, err := wire.NewHeadEntry(body)
		if err != nil {
			return err
		}
		if err := wire.ValidateHeadEntry(&candidate, state.CertifiedHead); err != nil {
			return err
		}
		record.Candidate = candidate
		if err := runtime.persistJournalLocked(); err != nil {
			return err
		}
		if err := runtime.verifyCommittedHead(context.Background(), candidate); err != nil {
			return err
		}
		if _, err := runtime.leader.ReplicateHead(context.Background(), runtime.store, candidate); err != nil {
			return err
		}
		if err := runtime.finishCommittedLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *controlRuntime) serveOperationProgress(writer http.ResponseWriter, request *http.Request, browser bool) {
	address := net.JoinHostPort(runtime.config.OverlayIP, strconv.FormatInt(runtime.config.ControlPort, 10))
	if browser {
		var exact bool
		address, exact = runtime.controlUIAddress(request)
		if !exact {
			http.NotFound(writer, request)
			return
		}
	}
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		!ok || local == nil || local.String() != address || request.Host != address ||
		request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) != 1 || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Content-Encoding") != "" {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D104] private admin operation progress 被拒绝")
		return
	}
	snapshot := runtime.progress.Load()
	if snapshot == nil || !controlAdminCertificateAuthorized(snapshot.authority, snapshot.authorizations,
		snapshot.profiles, request.TLS.PeerCertificates[0].Raw, runtime.now().UTC()) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D104] admin certificate 未获当前 certified ACL 授权")
		return
	}
	response := snapshot.response
	if !browser && request.URL.Path != controlplane.PrivateControlOperationPath {
		id := strings.TrimPrefix(request.URL.Path, controlplane.PrivateControlOperationPath+"/")
		found := false
		for _, operation := range response.Operations {
			if operation.RequestID == id {
				response.Operations = []controlOperationProgressV1{operation}
				found = true
				break
			}
		}
		if !found {
			http.NotFound(writer, request)
			return
		}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if browser {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = controlOperationsTemplate.Execute(writer, response)
		return
	}
	body, err := wire.MarshalCanonical(response)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[D104] operation progress 编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(body)
}

var controlOperationsTemplate = template.Must(template.New("operations").Parse(`<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>控制操作</title><style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:1100px;background:#131719;color:#e9eded}a{color:#86d8c0}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:1rem;border-bottom:1px solid #394146;overflow-wrap:anywhere}code{font-size:.9em}.muted{color:#adbabb}ol{line-height:1.7}</style>
<a href="/">返回管理页面</a><h1>控制操作</h1>
<p>{{if .Writable}}控制面可接受写请求。{{else}}操作处理中或当前没有可写 authority；仅可读取已确认的进度。{{end}}</p>
<ol><li>pending：请求已保存，尚未形成提交。</li><li>committed_not_certified：Raft 已提交，尚未取得认证 QC。</li><li>certified：Head/QC 已认证，后续执行另行跟踪。</li><li>reconciled：本操作要求的执行工作已完成。</li><li>applied：结果已收口并持久化。</li></ol>
<p class="muted">刷新页面查看最新阶段。阶段完成只针对该操作，不表示整个网络或其他业务已经完成。</p>
<table><thead><tr><th>请求</th><th>操作</th><th>当前阶段</th><th>已记录阶段</th></tr></thead><tbody>
{{range .Operations}}<tr><td><code>{{.RequestID}}</code></td><td>{{.Kind}}</td><td><code>{{.Phase}}</code></td><td>{{range .Phases}}<div><code>{{.}}</code></div>{{end}}</td></tr>{{else}}<tr><td colspan="4">暂无控制操作记录。</td></tr>{{end}}</tbody></table></html>`))
