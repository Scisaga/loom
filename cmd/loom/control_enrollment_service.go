package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type controlEnrollmentWorkflow struct {
	Service *enrollmentv2.PrivateService
	Peers   http.Handler
}

// 所有事务和 voter reader 使用同一个 daemon 的已认证日志；只读取本成员
// enrollment-purpose key，远端签名必须走认证 peer RPC。
func (runtime *controlRuntime) newEnrollmentWorkflow(provision *enrollmentv2.DurableProvisionalService,
	artifacts *enrollmentv2.SealedArtifactStore) (*controlEnrollmentWorkflow, error) {
	if provision == nil || artifacts == nil || runtime.enrollmentStore == nil {
		return nil, errors.New("[D130 daemon] 缺实际签发与制品存储")
	}
	runtime.mu.Lock()
	application, err := runtime.certifiedApplicationLocked()
	set, directory := runtime.config.ControlSet, runtime.config.PeerDirectory
	runtime.mu.Unlock()
	if err != nil {
		return nil, err
	}
	now := func() time.Time { return runtime.now().UTC() }
	admissionVoter, err := enrollmentv2.NewAdmissionVoter(runtime.config.MemberID, set, runtime.enrollmentKey, now, runtime.readInviteMaterial)
	if err != nil {
		return nil, err
	}
	approvalVoter, err := enrollmentv2.NewApprovalVoter(runtime.config.MemberID, set, runtime.enrollmentKey, now, runtime.readApprovalEvidence)
	if err != nil {
		return nil, err
	}
	admissionPeers := map[string]enrollmentv2.AdmissionVotePeer{runtime.config.MemberID: admissionVoter}
	approvalPeers := map[string]enrollmentv2.ApprovalVotePeer{runtime.config.MemberID: approvalVoter}
	for _, member := range set.Members {
		if member.MemberID == runtime.config.MemberID {
			continue
		}
		endpoint := ""
		for _, peer := range directory.Members {
			if peer.MemberID == member.MemberID && len(peer.PeerEndpoints) > 0 {
				endpoint = peer.PeerEndpoints[0].URL
				break
			}
		}
		peer, err := controlplane.NewEnrollmentPeerClient(endpoint, member.MemberID, runtime.peerTLS, set, directory, now)
		if err != nil {
			return nil, err
		}
		approvalPeer, err := controlplane.NewEnrollmentApprovalPeerClient(endpoint, member.MemberID, runtime.peerTLS, set, directory, now)
		if err != nil {
			return nil, err
		}
		admissionPeers[member.MemberID], approvalPeers[member.MemberID] = peer, approvalPeer
	}
	admission, err := controlplane.NewEnrollmentAdmissionCollector(set, admissionPeers)
	if err != nil {
		return nil, err
	}
	approval, err := controlplane.NewEnrollmentApprovalCollector(set, approvalPeers)
	if err != nil {
		return nil, err
	}
	backend, err := enrollmentv2.NewDistributedWorkflowBackend(admission, runtime, provision, runtime.readApprovalEvidence, approval, now)
	if err != nil {
		return nil, err
	}
	coordinator, err := enrollmentv2.NewCoordinator(runtime.enrollmentStore, backend)
	if err != nil {
		return nil, err
	}
	replay, err := enrollmentv2.OpenChallengeReplayStore(filepath.Join(runtime.dir, "enrollment-challenges.json"))
	if err != nil {
		return nil, err
	}
	released, err := enrollmentv2.NewReleasedEnrollmentArtifactReader(runtime.enrollmentStore, artifacts)
	if err != nil {
		return nil, err
	}
	service, err := enrollmentv2.NewPrivateServiceWithReleasedArtifacts(runtime.config.ClusterID, application.EnrollmentService.ServiceID,
		now, nil, time.Minute, replay, runtime.readInviteMaterial,
		func(ctx context.Context, record wire.CertifiedInviteRecordV2) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			value, err := runtime.readInviteToken(record)
			return value.Token, err
		}, coordinator.ProcessClaim, released)
	if err != nil {
		return nil, err
	}
	admissionHandler, err := controlplane.NewEnrollmentPeerHTTPHandler(set, directory, now, admissionVoter)
	if err != nil {
		return nil, err
	}
	approvalHandler, err := controlplane.NewEnrollmentApprovalHTTPHandler(set, directory, now, approvalVoter)
	if err != nil {
		return nil, err
	}
	peers := http.NewServeMux()
	peers.Handle(controlplane.EnrollmentAdmissionVotePath, admissionHandler)
	peers.Handle(controlplane.EnrollmentApprovalVotePath, approvalHandler)
	return &controlEnrollmentWorkflow{Service: service, Peers: peers}, nil
}
