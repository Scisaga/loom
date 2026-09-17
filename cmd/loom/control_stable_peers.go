package main

import (
	"context"
	"errors"
	"fmt"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

type controlOperationMaterialPeer interface {
	Sync(context.Context) (controlplane.CRDTAntiEntropyResultV1, error)
}

type controlRaftPeerGroup struct {
	memberID string
	clients  []*controlplane.RaftPeerClient
}

func (group *controlRaftPeerGroup) RequestVote(ctx context.Context,
	request controlplane.VoteRequestV1) (controlplane.VoteResultV1, error) {
	var last error
	for _, client := range group.clients {
		result, err := client.RequestVote(ctx, request)
		if err == nil {
			return result, nil
		}
		last = err
	}
	return controlplane.VoteResultV1{}, fmt.Errorf("[control peer] %s 的全部 Raft endpoint 失败: %w",
		group.memberID, last)
}

func (group *controlRaftPeerGroup) AppendEntries(ctx context.Context,
	request controlplane.AppendEntriesRequestV1) (controlplane.AppendEntriesResultV1, error) {
	var last error
	for _, client := range group.clients {
		result, err := client.AppendEntries(ctx, request)
		if err == nil {
			return result, nil
		}
		last = err
	}
	return controlplane.AppendEntriesResultV1{}, fmt.Errorf("[control peer] %s 的全部 Raft endpoint 失败: %w",
		group.memberID, last)
}

type controlHeadPeerGroup struct {
	memberID string
	clients  []*controlplane.HeadAttestationPeerClient
}

func (group *controlHeadPeerGroup) VoteHeadAttestation(ctx context.Context,
	request controlplane.HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error) {
	var last error
	for _, client := range group.clients {
		result, err := client.VoteHeadAttestation(ctx, request)
		if err == nil {
			return result, nil
		}
		last = err
	}
	return wire.ControlConfigSignatureV1{}, fmt.Errorf("[control peer] %s 的全部 Head vote endpoint 失败: %w",
		group.memberID, last)
}

func (group *controlHeadPeerGroup) InstallHeadCertification(ctx context.Context,
	request controlplane.HeadCertificationRequestV1) error {
	var last error
	for _, client := range group.clients {
		if err := client.InstallHeadCertification(ctx, request); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return fmt.Errorf("[control peer] %s 的全部 Head certification endpoint 失败: %w",
		group.memberID, last)
}

type controlOperationPeerGroup struct {
	memberID string
	clients  []*controlplane.CRDTAntiEntropyPeerClient
}

func (group *controlOperationPeerGroup) Sync(ctx context.Context) (controlplane.CRDTAntiEntropyResultV1, error) {
	var last error
	for _, client := range group.clients {
		result, err := client.Sync(ctx)
		if err == nil {
			return result, nil
		}
		last = err
	}
	return controlplane.CRDTAntiEntropyResultV1{}, fmt.Errorf(
		"[control peer] %s 的全部 operation-material endpoint 失败: %w", group.memberID, last)
}

func (runtime *controlRuntime) configureStableControlPeers(local controlplane.HeadAttestationPeer) error {
	if runtime == nil || local == nil || runtime.operationMaterials == nil {
		return errors.New("[control peer] runtime/local voter/material store 未初始化")
	}
	directoryMembers := make(map[string]wire.ControlPeerDirectoryMemberV1,
		len(runtime.config.PeerDirectory.Members))
	for _, member := range runtime.config.PeerDirectory.Members {
		directoryMembers[member.MemberID] = member
	}
	raftPeers := make(map[string]controlplane.RaftPeer, len(runtime.config.ControlSet.Members)-1)
	headPeers := make(map[string]controlplane.HeadAttestationPeer, len(runtime.config.ControlSet.Members))
	operationPeers := make(map[string]controlOperationMaterialPeer, len(runtime.config.ControlSet.Members)-1)
	headPeers[runtime.config.MemberID] = local
	for _, member := range runtime.config.ControlSet.Members {
		if member.MemberID == runtime.config.MemberID {
			continue
		}
		directoryMember, ok := directoryMembers[member.MemberID]
		if !ok || len(directoryMember.PeerEndpoints) == 0 {
			return errors.New("[control peer] committed remote 缺 private endpoint")
		}
		raftGroup := &controlRaftPeerGroup{memberID: member.MemberID}
		headGroup := &controlHeadPeerGroup{memberID: member.MemberID}
		operationGroup := &controlOperationPeerGroup{memberID: member.MemberID}
		for _, endpoint := range directoryMember.PeerEndpoints {
			raftClient, err := controlplane.NewRaftPeerClient(endpoint.URL, member.MemberID,
				runtime.peerTLS, runtime.config.ControlSet, runtime.config.PeerDirectory, runtime.now)
			if err != nil {
				return err
			}
			headClient, err := controlplane.NewHeadAttestationPeerClient(endpoint.URL, member.MemberID,
				runtime.peerTLS, runtime.config.ControlSet, runtime.config.PeerDirectory, runtime.now)
			if err != nil {
				return err
			}
			operationClient, err := controlplane.NewCRDTAntiEntropyPeerClient(endpoint.URL,
				runtime.config.MemberID, member.MemberID, runtime.peerTLS, runtime.config.ControlSet,
				runtime.config.PeerDirectory, runtime.operationMaterials, runtime.now,
				runtime.verifyControlOperationMaterialObject)
			if err != nil {
				return err
			}
			raftGroup.clients = append(raftGroup.clients, raftClient)
			headGroup.clients = append(headGroup.clients, headClient)
			operationGroup.clients = append(operationGroup.clients, operationClient)
		}
		raftPeers[member.MemberID] = raftGroup
		headPeers[member.MemberID] = headGroup
		operationPeers[member.MemberID] = operationGroup
	}
	collector, err := controlplane.NewHeadAttestationCollector(runtime.config.ControlSet, headPeers)
	if err != nil {
		return err
	}
	runtime.raftPeers = raftPeers
	runtime.operationClients = operationPeers
	runtime.headCollector = collector
	return nil
}

// replicateHead 保证 follower 在收到 data-bearing Raft entry 前，至少有 committed
// quorum 已耐久合并 exact reducer preimage。CRDT 同步本身不授权对象；follower 仍会
// 在 Raft fsync 前独立重算，随后在 committed prefix 上再次 apply。
func (runtime *controlRuntime) replicateHead(ctx context.Context,
	head wire.HeadEntryV2) (controlplane.StableRaftCommitResult, error) {
	if runtime == nil || runtime.leader == nil || runtime.store == nil {
		return controlplane.StableRaftCommitResult{}, errors.New("[control peer] 本机当前不是可写 Raft leader")
	}
	if head.Body.Payload.HeadKind != "bootstrap" {
		if err := runtime.syncOperationMaterialsToQuorum(ctx); err != nil {
			return controlplane.StableRaftCommitResult{}, err
		}
	}
	return runtime.leader.ReplicateHead(ctx, runtime.store, head)
}

func (runtime *controlRuntime) syncOperationMaterialsToQuorum(ctx context.Context) error {
	quorum, err := wire.Quorum(len(runtime.config.ControlSet.Members))
	if err != nil {
		return err
	}
	if quorum == 1 {
		return nil
	}
	peerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(runtime.operationClients))
	for _, peer := range runtime.operationClients {
		peer := peer
		go func() {
			_, err := peer.Sync(peerContext)
			results <- err
		}()
	}
	synced := 1
	for received := 0; received < len(runtime.operationClients); received++ {
		select {
		case result := <-results:
			if result == nil {
				synced++
				if synced >= quorum {
					return nil
				}
			}
			if synced+(len(runtime.operationClients)-received-1) < quorum {
				return errors.New("[operation material] 未同步到 committed ControlSet quorum")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.New("[operation material] 未同步到 committed ControlSet quorum")
}
