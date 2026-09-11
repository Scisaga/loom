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
	headPeerMaxBody         = 64 << 10
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

type HeadAttestationPeer interface {
	VoteHeadAttestation(context.Context, HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error)
}

type HeadRecomputer func(context.Context, wire.HeadEntryV2) error

// HeadAttestationVoter 只对本机 Raft committed prefix 中的 exact entry 签名；
// recompute 必须先独立重放确定性 reducer，不能信任 leader 提交的 snapshot hash。
type HeadAttestationVoter struct {
	storage    *RaftStorage
	set        wire.ControlSetV1
	member     wire.ControlMemberV1
	privateKey ed25519.PrivateKey
	recompute  HeadRecomputer
}

func NewHeadAttestationVoter(storage *RaftStorage, set wire.ControlSetV1, memberID string,
	privateKey ed25519.PrivateKey, recompute HeadRecomputer) (*HeadAttestationVoter, error) {
	if storage == nil || memberID == "" || len(privateKey) != ed25519.PrivateKeySize || recompute == nil {
		return nil, errors.New("[D104 QC peer] storage/member/key/recomputer 配置不完整")
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
		return nil, errors.New("[D102 keys] config attestation key 不属于 committed ControlSet member")
	}
	snapshot := storage.SnapshotRaft()
	setHash, _ := wire.ControlSetHash(&set)
	storageSetHash, _ := wire.ControlSetHash(&storage.set)
	if snapshot.MemberID != memberID || setHash != storageSetHash {
		return nil, errors.New("[D104 QC peer] voter identity/ControlSet 与 Raft storage 不一致")
	}
	return &HeadAttestationVoter{storage: storage, set: set, member: *member,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), recompute: recompute}, nil
}

func (voter *HeadAttestationVoter) VoteHeadAttestation(ctx context.Context,
	request HeadAttestationVoteRequestV1) (wire.ControlConfigSignatureV1, error) {
	if voter == nil || request.Schema != 1 || request.RaftIndex < 1 {
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] attestation request header 无效")
	}
	if _, err := wire.ParseHash(request.EntryHash); err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	if err := ctx.Err(); err != nil {
		return wire.ControlConfigSignatureV1{}, err
	}
	snapshot := voter.storage.SnapshotRaft()
	if request.RaftIndex > snapshot.CommitIndex || request.RaftIndex > int64(len(snapshot.Log)) {
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] 未 committed entry 禁止 attestation")
	}
	record := snapshot.Log[request.RaftIndex-1]
	setHash, _ := wire.ControlSetHash(&voter.set)
	if record.EntryHash != request.EntryHash || record.Entry.EntryHash != request.EntryHash ||
		record.Entry.Body.Payload.ControlSetHash != setHash {
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] committed entry/hash/ControlSet binding 无效")
	}
	if err := voter.recompute(ctx, record.Entry); err != nil {
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] deterministic recompute 拒绝 committed entry")
	}
	return wire.SignHeadAttestation(wire.AttestationForHead(&record.Entry), voter.member, voter.privateKey)
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
		return nil, errors.New("[D104 QC peer] time/voter 不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &HeadAttestationHTTPHandler{set: set, directory: directory, now: now, voter: voter}, nil
}

func (handler *HeadAttestationHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.URL.Path != HeadAttestationVotePath ||
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
		return nil, errors.New("[D124 control mTLS] head attestation endpoint 不属于目标 member")
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
			return errors.New("[D124 control mTLS] head attestation RPC 禁止 redirect")
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
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return wire.ControlConfigSignatureV1{}, fmt.Errorf("[D104 QC peer] peer 返回 HTTP %d", response.StatusCode)
	}
	var result HeadAttestationVoteResponseV1
	canonical, err := wire.DecodeStrict(responseBody, headPeerMaxBody, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 {
		return wire.ControlConfigSignatureV1{}, errors.New("[D104 QC peer] response wire 无效")
	}
	return result.Signature, nil
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
		return nil, errors.New("[D104 QC peer] collector 必须精确配置 committed ControlSet voters")
	}
	cloned := make(map[string]HeadAttestationPeer, len(peers))
	for _, member := range set.Members {
		peer, ok := peers[member.MemberID]
		if !ok || peer == nil {
			return nil, errors.New("[D104 QC peer] collector 缺 committed voter")
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
		return wire.StableHeadReplicationQCV1{}, errors.New("[D104 QC peer] candidate entry 使用错误 committed ControlSet")
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
	for range collector.set.Members {
		var value result
		select {
		case value = <-results:
		case <-ctx.Done():
			return wire.StableHeadReplicationQCV1{}, ctx.Err()
		}
		if value.err != nil || value.value.MemberID != value.memberID ||
			wire.VerifyHeadAttestationSignature(&entry, &value.value, &collector.set) != nil {
			continue
		}
		signatures = append(signatures, value.value)
	}
	quorum, _ := wire.Quorum(len(collector.set.Members))
	if len(signatures) < quorum {
		return wire.StableHeadReplicationQCV1{}, errors.New("[D104 QC peer] post-commit attestations 未达到 committed ControlSet quorum")
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
		return errors.New("[D104 QC peer] control store 不能为空")
	}
	state := store.Snapshot()
	if state.Active == nil {
		return nil
	}
	if state.Active.Phase == PhaseCertified || state.Active.Phase == PhaseReconciled || state.Active.Phase == PhaseApplied {
		return nil
	}
	if state.Active.Phase != PhaseCommittedNotCertified {
		return errors.New("[D104 QC peer] pending entry 未完成 Raft commit")
	}
	qc, err := collector.Collect(ctx, state.Active.Entry)
	if err != nil {
		return err
	}
	for _, signature := range qc.Signatures {
		if err := store.AddAttestation(state.Active.Entry.EntryHash, signature); err != nil {
			return err
		}
	}
	certified := store.Snapshot()
	if certified.Active == nil || certified.Active.Phase != PhaseCertified || certified.Active.QC == nil ||
		!wire.EqualCanonical(*certified.Active.QC, qc) {
		return errors.New("[D104 QC peer] durable store 未冻结 exact collected QC")
	}
	return nil
}

func writeHeadPeerError(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"private head attestation request rejected"}`))
}
