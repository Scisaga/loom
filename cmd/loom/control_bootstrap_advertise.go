package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/controlplane"
	"loom/internal/rotation"
	"loom/internal/wire"
)

const (
	controlAdvertiseBootstrapKind   = "advertise_bootstrap"
	controlBootstrapAdvertiseDomain = "loom-control-bootstrap-advertisement-v1"
)

// controlBootstrapAdvertisementEntryV1 保存节点真实 local readiness 与外部
// observer 的原签名报告。control 在 commit/replay 时重新生成 external evidence，
// 不接受调用方手填 local/external evidence hash。
type controlBootstrapAdvertisementEntryV1 struct {
	EndpointID   string                                                   `json:"endpoint_id"`
	Local        bootstrapaccess.BootstrapLocalReadinessEvidenceV1        `json:"local_readiness"`
	Observations []bootstrapaccess.SignedBootstrapOuterProbeObservationV1 `json:"outer_observations"`
}

type controlBootstrapAdvertisementPayloadV1 struct {
	Schema           int                                    `json:"schema"`
	PreparedHeadHash string                                 `json:"prepared_head_hash"`
	PreparedAt       string                                 `json:"prepared_at"`
	Entries          []controlBootstrapAdvertisementEntryV1 `json:"entries"`
}

// controlBootstrapAdvertisementV1 记录由签名 payload 与最终 certified Head
// 确定性派生的 rotation transition。transition 自身不作为第二份可写状态。
type controlBootstrapAdvertisementV1 struct {
	Payload     controlBootstrapAdvertisementPayloadV1 `json:"payload"`
	Transitions []rotation.Transition                  `json:"transitions"`
}

type controlBootstrapAdvertisementRequestFileV1 struct {
	Schema  int                       `json:"schema"`
	Base    controlStatusResponseV1   `json:"base"`
	Request controlOperationRequestV1 `json:"request"`
}

func controlBootstrapAdvertisementHash(payload controlBootstrapAdvertisementPayloadV1) (string, error) {
	if payload.Schema != 1 || len(payload.Entries) == 0 {
		return "", errors.New("[bootstrap advertise] payload 缺 prepared authority 或验证证据")
	}
	if _, err := wire.ParseHash(payload.PreparedHeadHash); err != nil {
		return "", err
	}
	if _, err := wire.ParseTimeZ(payload.PreparedAt); err != nil {
		return "", err
	}
	for index, entry := range payload.Entries {
		if entry.EndpointID == "" || entry.Local.EndpointID != entry.EndpointID || len(entry.Observations) == 0 ||
			index > 0 && payload.Entries[index-1].EndpointID >= entry.EndpointID {
			return "", errors.New("[bootstrap advertise] endpoint 证据必须完整、唯一并按 ID 排序")
		}
		for observationIndex := range entry.Observations {
			if observationIndex > 0 && entry.Observations[observationIndex-1].Body.ObserverID >= entry.Observations[observationIndex].Body.ObserverID {
				return "", errors.New("[bootstrap advertise] observer 报告必须按 ID 唯一排序")
			}
		}
	}
	return wire.HashObject(controlBootstrapAdvertiseDomain, payload)
}

func decodeControlBootstrapAdvertisement(raw json.RawMessage, operation wire.ControlOperationV1) (controlBootstrapAdvertisementPayloadV1, error) {
	var payload controlBootstrapAdvertisementPayloadV1
	canonical, err := wire.DecodeStrict(raw, 16<<20, &payload)
	if err != nil || !bytes.Equal(canonical, raw) || operation.Body.Kind != controlAdvertiseBootstrapKind || operation.Body.PayloadSchema != 1 {
		return payload, errors.New("[bootstrap advertise] 缺规范认证 payload")
	}
	hash, err := controlBootstrapAdvertisementHash(payload)
	if err != nil || hash != operation.Body.PayloadHash {
		return payload, errors.New("[bootstrap advertise] 管理员签名未绑定 exact evidence")
	}
	return payload, nil
}

func (runtime *controlRuntime) bootstrapPreparedHeadBefore(limit int, application *controlApplicationV1,
	payload controlBootstrapAdvertisementPayloadV1) (wire.HeadEntryV2, error) {
	if application == nil || application.BootstrapInstallation == nil {
		return wire.HeadEntryV2{}, errors.New("[bootstrap advertise] 当前没有待发布的初始安装")
	}
	for index := 0; index < limit; index++ {
		record := &runtime.journal.Records[index]
		if record.Activation == nil || record.Result == nil ||
			!wire.EqualCanonical(record.Activation.Application.BootstrapInstallation, application.BootstrapInstallation) {
			continue
		}
		head := record.Result.Head
		if payload.PreparedHeadHash != head.HeadHash || payload.PreparedAt != head.Body.Payload.CommittedLogicalTime {
			return wire.HeadEntryV2{}, errors.New("[bootstrap advertise] evidence 未绑定安装计划的 certified prepared Head")
		}
		return head, nil
	}
	return wire.HeadEntryV2{}, errors.New("[bootstrap advertise] 安装计划没有可重放的 certified activation")
}

// reduceBootstrapAdvertisement 只把已经由真实监听器和外部 observer 证明的
// 私有安装计划变成公开 catalog。catalog bytes 不变，避免 advertise 偷换地址。
func (application *controlApplicationV1) reduceBootstrapAdvertisement(payload controlBootstrapAdvertisementPayloadV1,
	operation wire.ControlOperationBodyV1, committedAt string, preparedHead wire.HeadEntryV2,
	certifiedHeadHash string) (*controlApplicationV1, []rotation.Transition, error) {
	if application == nil || application.BootstrapInstallation == nil || operation.Kind != controlAdvertiseBootstrapKind ||
		operation.ClusterID != application.ClusterID || preparedHead.HeadHash != payload.PreparedHeadHash ||
		preparedHead.Body.Payload.CommittedLogicalTime != payload.PreparedAt {
		return nil, nil, errors.New("[bootstrap advertise] operation/prepared authority 与当前安装不一致")
	}
	hash, err := controlBootstrapAdvertisementHash(payload)
	if err != nil || hash != operation.PayloadHash {
		return nil, nil, errors.New("[bootstrap advertise] payload hash 与管理签名不一致")
	}
	commitTime, err := wire.ParseTimeZ(committedAt)
	if err != nil {
		return nil, nil, err
	}
	installation := application.BootstrapInstallation
	if len(payload.Entries) != len(installation.Plans) || len(installation.Plans) != len(installation.Input.Listeners) {
		return nil, nil, errors.New("[bootstrap advertise] 必须一次覆盖完整 ingress set")
	}
	transitions := make([]rotation.Transition, 0, len(installation.Plans))
	for index := range installation.Plans {
		plan, listener, entry := installation.Plans[index], installation.Input.Listeners[index], payload.Entries[index]
		if plan.EndpointID != listener.EndpointID || entry.EndpointID != plan.EndpointID {
			return nil, nil, errors.New("[bootstrap advertise] endpoint 证据与 frozen 安装顺序不一致")
		}
		prepared := rotation.Transition{NextPhase: "prepared", CertifiedHeadHash: preparedHead.HeadHash,
			CertifiedAt: preparedHead.Body.Payload.CommittedLogicalTime}
		verify := func(intent *rotation.IntentV1, current *rotation.StateV1, event *rotation.Transition) error {
			if current != nil || !wire.EqualCanonical(*intent, plan.Intent) || !wire.EqualCanonical(*event, prepared) {
				return errors.New("[bootstrap advertise] prepared runtime 不属于 certified 安装")
			}
			return nil
		}
		authorized, err := rotation.AuthorizeInitialPreparedRuntimePlan(plan.Intent, plan.Execution, prepared, verify)
		if err != nil {
			return nil, nil, err
		}
		runtimePlan, err := bootstrapaccess.BuildBootstrapIngressRuntimePlan(&installation.Catalog,
			&installation.Input.Parent, &installation.Input.ControlSet, nil, authorized,
			&listener.Profile, &listener.Resources, plan.EndpointID, 1, commitTime, 2)
		if err != nil {
			return nil, nil, err
		}
		local, err := bootstrapaccess.VerifyBootstrapLocalReadinessEvidence(authorized, runtimePlan, &entry.Local)
		if err != nil {
			return nil, nil, err
		}
		external, err := bootstrapaccess.VerifyBootstrapOuterReachability(&listener.EvidencePolicy,
			authorized, runtimePlan, entry.Observations, commitTime)
		if err != nil {
			return nil, nil, err
		}
		transition := rotation.Transition{NextPhase: "advertised", CertifiedHeadHash: certifiedHeadHash,
			CertifiedAt: committedAt, LocalVerificationEvidenceHash: local.EvidenceHash(),
			ExternalVerificationEvidenceHash: external.EvidenceHash()}
		if err := bootstrapaccess.ValidateBootstrapAdvertiseTransition(authorized, &transition, local, external); err != nil {
			return nil, nil, err
		}
		if _, err := rotation.Advance(plan.Intent, authorized.State(), transition); err != nil {
			return nil, nil, err
		}
		transitions = append(transitions, transition)
	}
	next := controlClone(*application)
	next.BootstrapInstallation = nil
	if !wire.EqualCanonical(next.BootstrapCatalog, installation.Catalog) {
		return nil, nil, errors.New("[bootstrap advertise] advertise 改写了已认证 catalog")
	}
	if _, err := next.roots(); err != nil {
		return nil, nil, err
	}
	return &next, transitions, nil
}

func (runtime *controlRuntime) commitBootstrapAdvertisementLocked(ctx context.Context,
	verified wire.VerifiedAdminOperationV1) (controlplane.CertifiedControlOperationV1, error) {
	operation := verified.Operation()
	payload, err := decodeControlBootstrapAdvertisement(controlplane.OperationPayload(ctx), operation)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	return runtime.commitBootstrapAdvertisementPayloadLocked(ctx, verified, payload,
		controlplane.OperationPayload(ctx))
}

func (runtime *controlRuntime) commitBootstrapAdvertisementPayloadLocked(ctx context.Context,
	verified wire.VerifiedAdminOperationV1, payload controlBootstrapAdvertisementPayloadV1,
	rawPayload json.RawMessage) (controlplane.CertifiedControlOperationV1, error) {
	operation := verified.Operation()
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Leaf.OperationID != operation.Body.OperationID {
			continue
		}
		if record.BootstrapAdvertisement == nil || !wire.EqualCanonical(record.Operation, operation) ||
			!wire.EqualCanonical(record.BootstrapAdvertisement.Payload, payload) {
			return controlplane.CertifiedControlOperationV1{}, errors.New("[bootstrap advertise] request ID 冲突")
		}
		if err := runtime.finishCommittedLocked(); err != nil {
			return controlplane.CertifiedControlOperationV1{}, err
		}
		if record.Result == nil {
			if err := runtime.recoverPendingOperationsLocked(); err != nil {
				return controlplane.CertifiedControlOperationV1{}, err
			}
		}
		return controlplaneResult(record.Result)
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return controlplane.CertifiedControlOperationV1{}, errors.New("[bootstrap advertise] 先恢复已有 pending operation")
		}
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.Active != nil || state.CertifiedHead == nil || state.CertifiedQC == nil ||
		state.CertifiedHead.HeadHash != verified.HeadHash() || len(raft.Log) == 0 ||
		raft.LastApplied != raft.CommitIndex || raft.CommitIndex != int64(len(raft.Log)) {
		return controlplane.CertifiedControlOperationV1{}, errors.New("[bootstrap advertise] base/quorum 不可写")
	}
	index := len(runtime.journal.Records)
	application, err := runtime.applicationBefore(index)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	preparedHead, err := runtime.bootstrapPreparedHeadBefore(index, application, payload)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	logical := runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if logical < state.CertifiedHead.Body.Payload.CommittedLogicalTime {
		logical = state.CertifiedHead.Body.Payload.CommittedLogicalTime
	}
	next, _, err := application.reduceBootstrapAdvertisement(payload, operation.Body, logical, preparedHead,
		state.CertifiedHead.HeadHash)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	der, err := authorizedAdminCertificate(runtime.config.Authorizations, operation.Body.AdminCertDigest)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	committedTime, _ := wire.ParseTimeZ(logical)
	objectID, err := wire.ControlOperationObjectID(&operation, certificate.RawSubjectPublicKeyInfo,
		committedTime, controlOperationSchemas)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	leaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: operation.Body.OperationID, ObjectID: objectID}
	leaves := append(runtime.operationLeaves(index), leaf)
	root, err := wire.ControlOperationRoot(leaves)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	body := state.CertifiedHead.Body
	body.Payload.HeadKind, body.Payload.ParentHeadHash, body.Payload.OperationRoot = "ordinary", state.CertifiedHead.HeadHash, root
	body.Payload.RaftTerm, body.Payload.RaftIndex = raft.CurrentTerm, int64(len(raft.Log))+1
	body.Payload.PreviousLogEntryHash, body.Payload.ControlRevision = raft.Log[len(raft.Log)-1].EntryHash, body.Payload.RaftIndex
	body.Payload.CommittedLogicalTime, body.Payload.TransitionContext = logical, json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	roots, err := next.roots()
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	controlApplyRoots(&body, roots)
	candidate, err := wire.NewHeadEntry(body)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	_, transitions, err := application.reduceBootstrapAdvertisement(payload, operation.Body, logical,
		preparedHead, candidate.HeadHash)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	advertisement := &controlBootstrapAdvertisementV1{Payload: controlClone(payload), Transitions: transitions}
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1,
		Operation: operation, Payload: append(json.RawMessage(nil), rawPayload...),
		Leaf: leaf, Candidate: candidate, BootstrapAdvertisement: advertisement,
		Phases: []controlplane.Phase{controlplane.PhasePending}})
	if err := runtime.verifyCommittedHead(ctx, candidate); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.persistJournalLocked(); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if runtime.checkpoint != nil {
		if err := runtime.checkpoint(controlplane.PhasePending); err != nil {
			return controlplane.CertifiedControlOperationV1{}, err
		}
	}
	if _, err := runtime.leader.ReplicateHead(ctx, runtime.store, candidate); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	return controlplaneResult(runtime.journal.Records[index].Result)
}

func cmdControlAdvertiseBootstrap(args []string) error {
	fs := flag.NewFlagSet("control advertise-bootstrap", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "管理员证书与 endpoint 目录")
	bundlePath := fs.String("bundle", "", "export-bootstrap 导出的认证安装 bundle")
	out := fs.String("out", "", "保存 exact 请求与认证回执的目录")
	var readinessPaths, observationPaths repeatedFlag
	fs.Var(&readinessPaths, "readiness", "每个 endpoint 的节点 readiness 文件；可重复")
	fs.Var(&observationPaths, "observation", "每个 observer 的签名外部报告；可重复")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || *bundlePath == "" || *out == "" || len(readinessPaths) == 0 || len(observationPaths) == 0 {
		return errors.New("用法: loom control advertise-bootstrap -admin-dir <dir> -bundle <file> -readiness <file>... -observation <file>... -out <dir>")
	}
	payload, err := buildControlBootstrapAdvertisementPayload(*bundlePath, readinessPaths, observationPaths)
	if err != nil {
		return err
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(*out)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[bootstrap advertise] 输出目录必须是 0700 实体目录")
	}
	unlock, err := lockControlState(*out)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	requestPath := filepath.Join(*out, "request.json")
	var retained controlBootstrapAdvertisementRequestFileV1
	err = readCanonicalFile(requestPath, 20<<20, &retained)
	if errors.Is(err, os.ErrNotExist) {
		status, err := fetchControlStatus(ctx, endpoint, client)
		if err != nil {
			return err
		}
		hash, err := controlBootstrapAdvertisementHash(payload)
		if err != nil {
			return err
		}
		requestID := "bootstrap-advertise-" + hash[len("sha256:"):len("sha256:")+24]
		request, err := newControlSignedRequest(*adminDir, endpoint, status, controlAdvertiseBootstrapKind,
			hash, requestID, "certify bootstrap listener readiness and external reachability", time.Now())
		if err != nil {
			return err
		}
		request.Payload, err = wire.MarshalCanonical(payload)
		if err != nil {
			return err
		}
		retained = controlBootstrapAdvertisementRequestFileV1{Schema: 1, Base: status, Request: request}
		if err := writeCanonicalAtomic(requestPath, retained, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	raw, _ := wire.MarshalCanonical(payload)
	if retained.Schema != 1 || retained.Base.ClusterID != endpoint.ClusterID ||
		!wire.EqualCanonical(retained.Base.Service, endpoint.Service) || !bytes.Equal(retained.Request.Payload, raw) {
		return errors.New("[bootstrap advertise] 输出目录已绑定另一请求")
	}
	result, err := submitControlOperation(ctx, *adminDir, endpoint, client, retained.Base, retained.Request)
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, "result.json"), result, 0o600); err != nil {
		return err
	}
	fmt.Printf("✓ Bootstrap catalog 已由控制日志认证发布；回执：%s\n", filepath.Join(*out, "result.json"))
	return nil
}

func buildControlBootstrapAdvertisementPayload(bundlePath string, readinessPaths, observationPaths []string) (controlBootstrapAdvertisementPayloadV1, error) {
	var bundle bootstrapInstallationBundleV1
	if err := readCanonicalFile(bundlePath, 32<<20, &bundle); err != nil {
		return controlBootstrapAdvertisementPayloadV1{}, err
	}
	if bundle.Schema != 1 || bundle.Activation.Head.HeadHash == "" || bundle.Installation.Content == nil {
		return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] 安装 bundle 不完整")
	}
	var installation bootstrapaccess.InitialBootstrapInstallationV1
	if _, err := wire.DecodeStrict(bundle.Installation.Content, 16<<20, &installation); err != nil {
		return controlBootstrapAdvertisementPayloadV1{}, err
	}
	if err := bootstrapaccess.ValidateInitialBootstrapInstallation(&installation); err != nil {
		return controlBootstrapAdvertisementPayloadV1{}, err
	}
	bundleHash, err := wire.HashObject("loom-bootstrap-installation-bundle-v1", bundle)
	if err != nil {
		return controlBootstrapAdvertisementPayloadV1{}, err
	}
	readinessByEndpoint := make(map[string]bootstrapPreparedReadinessV1, len(readinessPaths))
	planEndpoint := make(map[string]string, len(readinessPaths))
	for _, path := range readinessPaths {
		var readiness bootstrapPreparedReadinessV1
		if err := readCanonicalFile(path, 4<<20, &readiness); err != nil {
			return controlBootstrapAdvertisementPayloadV1{}, err
		}
		planHash, err := bootstrapaccess.BootstrapOuterProbePlanHash(&readiness.OuterPlan)
		if err != nil || readiness.Schema != 1 || readiness.BundleHash != bundleHash ||
			readiness.LocalEvidence.EndpointID != readiness.OuterPlan.EndpointID || readiness.LocalEvidenceHash == "" {
			return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] readiness 未绑定 exact bundle/outer plan")
		}
		endpointID := readiness.LocalEvidence.EndpointID
		if _, duplicate := readinessByEndpoint[endpointID]; duplicate {
			return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] readiness endpoint 重复")
		}
		readinessByEndpoint[endpointID], planEndpoint[planHash] = readiness, endpointID
	}
	observationsByEndpoint := make(map[string][]bootstrapaccess.SignedBootstrapOuterProbeObservationV1)
	for _, path := range observationPaths {
		var observation bootstrapaccess.SignedBootstrapOuterProbeObservationV1
		if err := readCanonicalFile(path, 2<<20, &observation); err != nil {
			return controlBootstrapAdvertisementPayloadV1{}, err
		}
		endpointID, found := planEndpoint[observation.Body.ProbePlanHash]
		if !found {
			return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] observer 报告不属于提交的 readiness plan")
		}
		observationsByEndpoint[endpointID] = append(observationsByEndpoint[endpointID], observation)
	}
	payload := controlBootstrapAdvertisementPayloadV1{Schema: 1,
		PreparedHeadHash: bundle.Activation.Head.HeadHash,
		PreparedAt:       bundle.Activation.Head.Body.Payload.CommittedLogicalTime,
		Entries:          make([]controlBootstrapAdvertisementEntryV1, 0, len(installation.Plans))}
	for _, plan := range installation.Plans {
		readiness, found := readinessByEndpoint[plan.EndpointID]
		observations := observationsByEndpoint[plan.EndpointID]
		if !found || len(observations) == 0 {
			return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] 某 endpoint 缺 local 或 external evidence")
		}
		sort.Slice(observations, func(i, j int) bool { return observations[i].Body.ObserverID < observations[j].Body.ObserverID })
		payload.Entries = append(payload.Entries, controlBootstrapAdvertisementEntryV1{
			EndpointID: plan.EndpointID, Local: readiness.LocalEvidence, Observations: observations})
	}
	sort.Slice(payload.Entries, func(i, j int) bool { return payload.Entries[i].EndpointID < payload.Entries[j].EndpointID })
	if len(readinessByEndpoint) != len(payload.Entries) || len(observationsByEndpoint) != len(payload.Entries) {
		return controlBootstrapAdvertisementPayloadV1{}, errors.New("[bootstrap advertise] 提交了安装集合之外的额外证据")
	}
	if _, err := controlBootstrapAdvertisementHash(payload); err != nil {
		return controlBootstrapAdvertisementPayloadV1{}, err
	}
	return payload, nil
}
