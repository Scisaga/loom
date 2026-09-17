package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	HeadAttestationVotePath = "/private/v2/raft/head-attestation"
	HeadCertificationPath   = "/private/v2/raft/head-certification"
	headPeerMaxBody         = 1 << 20
)

type HeadAttestationVoteRequestV1 struct {
	Schema    int    `json:"schema"`
	RaftIndex int64  `json:"raft_index"`
	EntryHash string `json:"entry_hash"`
}

type HeadAttestationVoteResponseV1 struct {
	Schema    int                           `json:"schema"`
	Signature wire.ControlConfigSignatureV1 `json:"signature"`
}

type HeadCertificationRequestV1 struct {
	Schema    int                            `json:"schema"`
	RaftIndex int64                          `json:"raft_index"`
	EntryHash string                         `json:"entry_hash"`
	QC        wire.StableHeadReplicationQCV1 `json:"qc"`
}

type HeadCertificationResponseV1 struct {
	Schema int `json:"schema"`
}

type HeadAttestationPeer interface {
	VoteHeadAttestation(context.Context, HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error)
	InstallHeadCertification(context.Context, HeadCertificationRequestV1) error
}

type HeadRecomputer func(context.Context, wire.HeadEntryV2) error

// HeadAttestationVoter 只对本机 Raft committed prefix 中的 exact entry 签名；
// recompute 必须先独立重放确定性 reducer，不能信任 leader 提交的 snapshot hash。
type HeadAttestationVoter struct {
	storage    *RaftStorage
	store      *Store
	set        wire.ControlSetV1
	member     wire.ControlMemberV1
	privateKey ed25519.PrivateKey
	recompute  HeadRecomputer
}

func NewHeadAttestationVoter(storage *RaftStorage, store *Store, set wire.ControlSetV1, memberID string,
	privateKey ed25519.PrivateKey, recompute HeadRecomputer) (*HeadAttestationVoter, error) {
	if storage == nil || store == nil || memberID == "" || len(privateKey) != ed25519.PrivateKeySize || recompute == nil {
		return nil, errors.New("[QC peer] storage/store/member/key/recomputer 配置不完整")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	var member *wire.ControlMemberV1
	for index := range set.Members {
		if set.Members[index].MemberID == memberID {
			member = &set.Members[index]
			break
		}
	}
	keyID, err := wire.ControlKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || member == nil || keyID != member.ConfigKeyID {
		return nil, errors.New("[keys] config attestation key 不属于 committed ControlSet member")
	}
	snapshot := storage.SnapshotRaft()
	setHash, _ := wire.ControlSetHash(&set)
	storageSetHash, _ := wire.ControlSetHash(&storage.set)
	if snapshot.MemberID != memberID || setHash != storageSetHash {
		return nil, errors.New("[QC peer] voter identity/ControlSet 与 Raft storage 不一致")
	}
	storeState := store.Snapshot()
	storeSetHash, _ := wire.ControlSetHash(&storeState.ControlSet)
	if storeSetHash != setHash {
		return nil, errors.New("[QC peer] voter control store 与 committed ControlSet 不一致")
	}
	return &HeadAttestationVoter{storage: storage, store: store, set: set, member: *member,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), recompute: recompute}, nil
}

func (voter *HeadAttestationVoter) VoteHeadAttestation(ctx context.Context,
	request HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error) {
	if voter == nil || request.Schema != 1 || request.RaftIndex < 1 {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] attestation request header 无效")
	}
	if _, err := wire.ParseHash(request.EntryHash); err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	if err := ctx.Err(); err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	snapshot := voter.storage.SnapshotRaft()
	if request.RaftIndex > snapshot.CommitIndex || request.RaftIndex > int64(len(snapshot.Log)) {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] 未 committed entry 禁止 attestation")
	}
	record := snapshot.Log[request.RaftIndex-1]
	setHash, _ := wire.ControlSetHash(&voter.set)
	if record.Kind != RaftRecordHead || record.Head == nil || record.EntryHash != request.EntryHash ||
		record.Head.EntryHash != request.EntryHash || record.Head.Body.Payload.ControlSetHash != setHash {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] committed entry/hash/ControlSet binding 无效")
	}
	if _, err := ApplyCommittedPrefixThrough(ctx, voter.storage, voter.store, voter.recompute,
		request.RaftIndex); err != nil {
		return wire.ControlConfigSignatureV1{}, fmt.Errorf("[QC peer] 本机 committed prefix apply 失败: %w", err)
	}
	state := voter.store.Snapshot()
	if state.Active == nil || state.Active.Entry.EntryHash != request.EntryHash ||
		state.Active.Phase != PhaseCommittedNotCertified {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] 本机 entry 尚未进入 committed_not_certified")
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(record.Head), voter.member, voter.privateKey)
	if err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	if err := voter.store.AddAttestation(request.EntryHash, signature); err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	return signature, nil
}

// InstallHeadCertification 在 follower 本机先重放 committed prefix，再安装由
// committed ControlSet 形成的 exact QC。普通 follower 不执行 leader 的外部
// reconciler；certified state 已耐久后即可清除 active gate 并接收下一条 Head。
func (voter *HeadAttestationVoter) InstallHeadCertification(ctx context.Context,
	request HeadCertificationRequestV1) error {
	if voter == nil || request.Schema != 1 || request.RaftIndex < 1 {
		return errors.New("[QC peer] certification request header 无效")
	}
	if _, err := wire.ParseHash(request.EntryHash); err != nil {
		return err
	}
	snapshot := voter.storage.SnapshotRaft()
	if request.RaftIndex > snapshot.CommitIndex || request.RaftIndex > int64(len(snapshot.Log)) {
		return errors.New("[QC peer] certification entry 不在本机 committed prefix")
	}
	record := snapshot.Log[request.RaftIndex-1]
	if record.Kind != RaftRecordHead || record.Head == nil || record.EntryHash != request.EntryHash ||
		record.Head.EntryHash != request.EntryHash {
		return errors.New("[QC peer] certification entry/hash binding 无效")
	}
	if err := wire.VerifyStableHeadQC(record.Head, &voter.set, &request.QC); err != nil {
		return err
	}
	if _, err := ApplyCommittedPrefixThrough(ctx, voter.storage, voter.store, voter.recompute,
		request.RaftIndex); err != nil {
		return err
	}
	if err := voter.store.InstallCertification(request.EntryHash, request.QC); err != nil {
		return err
	}
	installed := voter.store.Snapshot()
	if installed.Active == nil && installed.CertifiedHead != nil &&
		installed.CertifiedHead.EntryHash == request.EntryHash && installed.CertifiedQC != nil &&
		wire.EqualCanonical(*installed.CertifiedQC, request.QC) {
		return nil
	}
	return voter.store.MarkApplied(request.EntryHash)
}

type HeadAttestationHTTPHandler struct {
	set       wire.ControlSetV1
	directory wire.ControlPeerDirectoryV1
	now       func() time.Time
	voter     HeadAttestationPeer
}

func NewHeadAttestationHTTPHandler(set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1,
	now func() time.Time, voter HeadAttestationPeer) (*HeadAttestationHTTPHandler, error) {
	if now == nil || voter == nil {
		return nil, errors.New("[QC peer] time/voter 不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &HeadAttestationHTTPHandler{set: set, directory: directory, now: now, voter: voter}, nil
}

func (handler *HeadAttestationHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost ||
		(request.URL.Path != HeadAttestationVotePath && request.URL.Path != HeadCertificationPath) ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version < tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) != 1 || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writeHeadPeerError(response, http.StatusForbidden)
		return
	}
	if _, err := wire.ControlPeerMemberForCertificate(&handler.set, &handler.directory,
		request.TLS.PeerCertificates[0].Raw, handler.now()); err != nil {
		writeHeadPeerError(response, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, headPeerMaxBody))
	if err != nil || len(body) == 0 {
		writeHeadPeerError(response, http.StatusBadRequest)
		return
	}
	switch request.URL.Path {
	case HeadAttestationVotePath:
		var submitted HeadAttestationVoteRequestV1
		canonical, err := wire.DecodeStrict(body, headPeerMaxBody, &submitted)
		if err != nil || !bytes.Equal(canonical, body) {
			writeHeadPeerError(response, http.StatusBadRequest)
			return
		}
		signature, err := handler.voter.VoteHeadAttestation(request.Context(), submitted)
		if err != nil {
			writeHeadPeerError(response, http.StatusForbidden)
			return
		}
		writeRaftCanonical(response, HeadAttestationVoteResponseV1{Schema: 1, Signature: signature})
	case HeadCertificationPath:
		var submitted HeadCertificationRequestV1
		canonical, err := wire.DecodeStrict(body, headPeerMaxBody, &submitted)
		if err != nil || !bytes.Equal(canonical, body) ||
			handler.voter.InstallHeadCertification(request.Context(), submitted) != nil {
			writeHeadPeerError(response, http.StatusForbidden)
			return
		}
		writeRaftCanonical(response, HeadCertificationResponseV1{Schema: 1})
	}
}

type HeadAttestationPeerClient struct {
	baseURL string
	client  *http.Client
}

func NewHeadAttestationPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate,
	set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*HeadAttestationPeerClient, error) {
	found := false
	for _, member := range directory.Members {
		if member.MemberID != remoteMemberID {
			continue
		}
		for _, endpoint := range member.PeerEndpoints {
			if endpoint.URL == endpointURL {
				found = true
			}
		}
	}
	parsed, err := url.ParseRequestURI(endpointURL)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || !found {
		return nil, errors.New("[control mTLS] head attestation endpoint 不属于目标 member")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	return &HeadAttestationPeerClient{baseURL: endpointURL, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[control mTLS] head attestation RPC 禁止 redirect")
		},
	}}, nil
}

func (client *HeadAttestationPeerClient) VoteHeadAttestation(ctx context.Context,
	request HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error) {
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+HeadAttestationVotePath, bytes.NewReader(body))
	if err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, headPeerMaxBody+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > headPeerMaxBody {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return wire.ControlConfigSignatureV1{}, fmt.Errorf("[QC peer] peer 返回 HTTP %d", response.StatusCode)
	}
	var result HeadAttestationVoteResponseV1
	canonical, err := wire.DecodeStrict(responseBody, headPeerMaxBody, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 {
		return wire.ControlConfigSignatureV1{}, errors.New("[QC peer] response wire 无效")
	}
	return result.Signature, nil
}

func (client *HeadAttestationPeerClient) InstallHeadCertification(ctx context.Context,
	request HeadCertificationRequestV1) error {
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+HeadCertificationPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, headPeerMaxBody+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > headPeerMaxBody {
		return errors.New("[QC peer] certification response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("[QC peer] certification peer 返回 HTTP %d", response.StatusCode)
	}
	var result HeadCertificationResponseV1
	canonical, err := wire.DecodeStrict(responseBody, headPeerMaxBody, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 {
		return errors.New("[QC peer] certification response wire 无效")
	}
	return nil
}

type HeadAttestationCollector struct {
	set   wire.ControlSetV1
	peers map[string]HeadAttestationPeer
}

func NewHeadAttestationCollector(set wire.ControlSetV1,
	peers map[string]HeadAttestationPeer) (*HeadAttestationCollector, error) {
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	if len(peers) != len(set.Members) {
		return nil, errors.New("[QC peer] collector 必须精确配置 committed ControlSet voters")
	}
	cloned := make(map[string]HeadAttestationPeer, len(peers))
	for _, member := range set.Members {
		peer, ok := peers[member.MemberID]
		if !ok || peer == nil {
			return nil, errors.New("[QC peer] collector 缺 committed voter")
		}
		cloned[member.MemberID] = peer
	}
	return &HeadAttestationCollector{set: set, peers: cloned}, nil
}

func (collector *HeadAttestationCollector) Collect(ctx context.Context,
	entry wire.HeadEntryV2) (wire.StableHeadReplicationQCV1, error) {
	if err := wire.ValidateHeadEntry(&entry, nil); err != nil {
		return wire.StableHeadReplicationQCV1{}, err
	}
	setHash, _ := wire.ControlSetHash(&collector.set)
	if entry.Body.Payload.ControlSetHash != setHash {
		return wire.StableHeadReplicationQCV1{}, errors.New("[QC peer] candidate entry 使用错误 committed ControlSet")
	}
	request := HeadAttestationVoteRequestV1{Schema: 1, RaftIndex: entry.Body.Payload.RaftIndex, EntryHash: entry.EntryHash}
	type result struct {
		memberID string
		value    wire.ControlConfigSignatureV1
		err      error
	}
	results := make(chan result, len(collector.set.Members))
	for _, member := range collector.set.Members {
		memberID := member.MemberID
		peer := collector.peers[memberID]
		go func() {
			value, err := peer.VoteHeadAttestation(ctx, request)
			results <- result{memberID: memberID, value: value, err: err}
		}()
	}
	signatures := make([]wire.ControlConfigSignatureV1, 0, len(collector.set.Members))
	lastError := errors.New("[QC peer] 没有有效 attestation")
	for range collector.set.Members {
		var value result
		select {
		case value = <-results:
		case <-ctx.Done():
			return wire.StableHeadReplicationQCV1{}, ctx.Err()
		}
		if value.err != nil {
			lastError = value.err
			continue
		}
		if value.value.MemberID != value.memberID ||
			wire.VerifyHeadAttestationSignature(&entry, &value.value, &collector.set) != nil {
			lastError = errors.New("[QC peer] attestation signer/binding 无效")
			continue
		}
		signatures = append(signatures, value.value)
	}
	quorum, _ := wire.Quorum(len(collector.set.Members))
	if len(signatures) < quorum {
		return wire.StableHeadReplicationQCV1{}, fmt.Errorf(
			"[QC peer] post-commit attestations 未达到 committed ControlSet quorum: %w", lastError)
	}
	sort.Slice(signatures, func(i, j int) bool {
		if signatures[i].MemberID != signatures[j].MemberID {
			return signatures[i].MemberID < signatures[j].MemberID
		}
		return signatures[i].ConfigKeyID < signatures[j].ConfigKeyID
	})
	qc := wire.StableQC(&entry, signatures[:quorum])
	if err := wire.VerifyStableHeadQC(&entry, &collector.set, &qc); err != nil {
		return wire.StableHeadReplicationQCV1{}, err
	}
	return qc, nil
}

// CertifyActive 可在 leader commit→QC 崩溃后由新 executor 重跑；Store 会冻结
// canonical quorum bytes，已 certified entry 不会产生第二个结果。
func (collector *HeadAttestationCollector) CertifyActive(ctx context.Context, store *Store) error {
	if store == nil {
		return errors.New("[QC peer] control store 不能为空")
	}
	state := store.Snapshot()
	if state.Active == nil {
		return nil
	}
	if state.Active.Phase != PhaseCommittedNotCertified && state.Active.Phase != PhaseCertified &&
		state.Active.Phase != PhaseReconciled && state.Active.Phase != PhaseApplied {
		return errors.New("[QC peer] pending entry 未完成 Raft commit")
	}
	if state.Active.Phase == PhaseCommittedNotCertified {
		qc, err := collector.Collect(ctx, state.Active.Entry)
		if err != nil {
			return err
		}
		for _, signature := range qc.Signatures {
			if err := store.AddAttestation(state.Active.Entry.EntryHash, signature); err != nil {
				return err
			}
		}
	}
	certified := store.Snapshot()
	if certified.Active == nil || certified.Active.QC == nil ||
		(certified.Active.Phase != PhaseCertified && certified.Active.Phase != PhaseReconciled &&
			certified.Active.Phase != PhaseApplied) {
		return errors.New("[QC peer] durable store 未冻结 exact collected QC")
	}
	return collector.distributeCertification(ctx, certified.Active)
}

func (collector *HeadAttestationCollector) distributeCertification(ctx context.Context,
	active *OperationState) error {
	if collector == nil || active == nil || active.QC == nil || active.RaftCommit == nil {
		return errors.New("[QC peer] certification distribution context 不完整")
	}
	request := HeadCertificationRequestV1{Schema: 1,
		RaftIndex: active.Entry.Body.Payload.RaftIndex,
		EntryHash: active.Entry.EntryHash, QC: *cloneStableQC(active.QC)}
	quorum, _ := wire.Quorum(len(collector.set.Members))
	if quorum == 1 {
		return nil
	}
	peerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(collector.peers)-1)
	remoteCount := 0
	for memberID, peer := range collector.peers {
		if memberID == active.RaftCommit.MemberID {
			continue
		}
		remoteCount++
		peer := peer
		go func() {
			results <- peer.InstallHeadCertification(peerContext, request)
		}()
	}
	installed := 1
	for received := 0; received < remoteCount; received++ {
		select {
		case err := <-results:
			if err == nil {
				installed++
				if installed >= quorum {
					return nil
				}
			}
			if installed+(remoteCount-received-1) < quorum {
				return errors.New("[QC peer] certification 未耐久安装到 committed ControlSet quorum")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.New("[QC peer] certification 未耐久安装到 committed ControlSet quorum")
}

func writeHeadPeerError(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"private head attestation request rejected"}`))
}
