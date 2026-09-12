package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	RaftVotePath   = "/private/v2/raft/request-vote"
	RaftAppendPath = "/private/v2/raft/append-entries"
	raftRPCMaxBody = 64 << 20
)

type raftRPCErrorV1 struct {
	Schema int    `json:"schema"`
	Error  string `json:"error"`
}

// NewControlPeerServerTLSConfig 构造只接受 private directory exact leaf 的 TLS 1.3 配置。
// control peer 是自签 pin profile，因此不会回退到系统 trust store（D124）。
func NewControlPeerServerTLSConfig(localMemberID string, certificate tls.Certificate, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*tls.Config, error) {
	if now == nil || len(certificate.Certificate) != 1 {
		return nil, errors.New("[D124 control mTLS] server certificate/可信时间源无效")
	}
	memberID, err := wire.ControlPeerMemberForCertificate(&set, &directory, certificate.Certificate[0], now())
	if err != nil || memberID != localMemberID {
		return nil, errors.New("[D124 control mTLS] server certificate 不属于本机 member")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("[D124 control mTLS] client 必须只发送 exact 自签 leaf")
			}
			_, err := wire.ControlPeerMemberForCertificate(&set, &directory, rawCerts[0], now())
			return err
		},
	}, nil
}

// NewControlPeerClientTLSConfig 同样按 directory pin 验 server，不接受 WebPKI/DNS 替代身份。
func NewControlPeerClientTLSConfig(remoteMemberID string, certificate tls.Certificate, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*tls.Config, error) {
	if now == nil || len(certificate.Certificate) != 1 || !controlSetContains(&set, remoteMemberID) {
		return nil, errors.New("[D124 control mTLS] client certificate/remote member/时间源无效")
	}
	if _, err := wire.ControlPeerMemberForCertificate(&set, &directory, certificate.Certificate[0], now()); err != nil {
		return nil, errors.New("[D124 control mTLS] client certificate 不在 private directory")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true, // 下面按 exact directory cert/SPKI pin 验证；不走系统 WebPKI。
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("[D124 control mTLS] server 必须只发送 exact 自签 leaf")
			}
			memberID, err := wire.ControlPeerMemberForCertificate(&set, &directory, state.PeerCertificates[0].Raw, now())
			if err != nil {
				return err
			}
			if memberID != remoteMemberID {
				return errors.New("[D124 control mTLS] server certificate 绑定到错误 member")
			}
			return nil
		},
	}, nil
}

// NewJointControlPeerServerTLSConfig 在 Joint 期间接受 old/new private directory
// 并集，但每张证书仍必须唯一映射到同一个 member（D112、D124）。
func NewJointControlPeerServerTLSConfig(localMemberID string, certificate tls.Certificate,
	oldSet, newSet wire.ControlSetV1, oldDirectory, newDirectory wire.ControlPeerDirectoryV1,
	now func() time.Time) (*tls.Config, error) {
	if now == nil || len(certificate.Certificate) != 1 {
		return nil, errors.New("[D124 joint mTLS] server certificate/可信时间源无效")
	}
	if err := validateJointPeerDirectories(&oldSet, &newSet, &oldDirectory, &newDirectory, now()); err != nil {
		return nil, err
	}
	memberID, err := controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
		&newDirectory, certificate.Certificate[0], now())
	if err != nil || memberID != localMemberID {
		return nil, errors.New("[D124 joint mTLS] server certificate 不属于本机 Joint member")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("[D124 joint mTLS] client 必须只发送 exact 自签 leaf")
			}
			_, err := controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
				&newDirectory, rawCerts[0], now())
			return err
		},
	}, nil
}

// NewJointControlPeerClientTLSConfig 对远端身份执行同一 union pin，不读取系统
// trust store，也不允许 old/new directory 把同一证书解释成不同 member。
func NewJointControlPeerClientTLSConfig(remoteMemberID string, certificate tls.Certificate,
	oldSet, newSet wire.ControlSetV1, oldDirectory, newDirectory wire.ControlPeerDirectoryV1,
	now func() time.Time) (*tls.Config, error) {
	if now == nil || len(certificate.Certificate) != 1 {
		return nil, errors.New("[D124 joint mTLS] client certificate/可信时间源无效")
	}
	if err := validateJointPeerDirectories(&oldSet, &newSet, &oldDirectory, &newDirectory, now()); err != nil {
		return nil, err
	}
	if _, err := controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
		&newDirectory, certificate.Certificate[0], now()); err != nil {
		return nil, errors.New("[D124 joint mTLS] client certificate 不在 Joint directory union")
	}
	if !controlSetContains(&oldSet, remoteMemberID) && !controlSetContains(&newSet, remoteMemberID) {
		return nil, errors.New("[D124 joint mTLS] remote member 不在 Joint union")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true, // 下面只接受 committed old/new directory union pin。
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("[D124 joint mTLS] server 必须只发送 exact 自签 leaf")
			}
			memberID, err := controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
				&newDirectory, state.PeerCertificates[0].Raw, now())
			if err != nil {
				return err
			}
			if memberID != remoteMemberID {
				return errors.New("[D124 joint mTLS] server certificate 绑定到错误 member")
			}
			return nil
		},
	}, nil
}

func validateJointPeerDirectories(oldSet, newSet *wire.ControlSetV1, oldDirectory,
	newDirectory *wire.ControlPeerDirectoryV1, at time.Time) error {
	if oldSet == nil || newSet == nil || oldDirectory == nil || newDirectory == nil ||
		oldSet.ClusterID != newSet.ClusterID {
		return errors.New("[D124 joint mTLS] old/new directory authority 无效")
	}
	if err := wire.ValidateControlPeerDirectoryAt(oldSet, oldDirectory, at); err != nil {
		return err
	}
	return wire.ValidateControlPeerDirectoryAt(newSet, newDirectory, at)
}

func controlPeerMemberForJointCertificate(oldSet, newSet *wire.ControlSetV1, oldDirectory,
	newDirectory *wire.ControlPeerDirectoryV1, raw []byte, at time.Time) (string, error) {
	oldMember, oldErr := wire.ControlPeerMemberForCertificate(oldSet, oldDirectory, raw, at)
	newMember, newErr := wire.ControlPeerMemberForCertificate(newSet, newDirectory, raw, at)
	switch {
	case oldErr == nil && newErr == nil && oldMember == newMember:
		return oldMember, nil
	case oldErr == nil && newErr != nil:
		return oldMember, nil
	case oldErr != nil && newErr == nil:
		return newMember, nil
	default:
		return "", errors.New("[D124 joint mTLS] certificate 不属于唯一 Joint member")
	}
}

type RaftHTTPHandler struct {
	storage  *RaftStorage
	now      func() time.Time
	identify func([]byte, time.Time) (string, error)
	learner  bool
	verify   RaftCandidateVerifier
}

// RaftCandidateVerifier 必须对 data-bearing record 重放其完整确定性验证；HTTP
// follower 在调用 RaftStorage fsync 之前执行它，不能只信 leader 的 hash（D104、D112）。
type RaftCandidateVerifier func(context.Context, RaftLogRecordV1) error

func NewRaftHTTPHandler(storage *RaftStorage, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1,
	now func() time.Time, verify RaftCandidateVerifier) (*RaftHTTPHandler, error) {
	if storage == nil || now == nil || verify == nil {
		return nil, errors.New("[D104 Raft RPC] storage/可信时间源/candidate verifier 不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	setHash, _ := wire.ControlSetHash(&set)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	if storage.jointSet != nil || storage.SnapshotRaft().VotingDisabled || setHash != storageHash {
		return nil, errors.New("[D104 Raft RPC] handler 与 stable Raft authority 不一致")
	}
	return newRaftHTTPHandler(storage, now, false, verify,
		func(raw []byte, at time.Time) (string, error) {
			return wire.ControlPeerMemberForCertificate(&set, &directory, raw, at)
		}), nil
}

// NewRaftLearnerHTTPHandler 仅开放从 old stable peers 接收 AppendEntries；RequestVote
// 永远拒绝，因此 learner catch-up 不能提前改变 quorum（D112）。
func NewRaftLearnerHTTPHandler(storage *RaftStorage, oldSet wire.ControlSetV1,
	oldDirectory wire.ControlPeerDirectoryV1, now func() time.Time,
	verify RaftCandidateVerifier) (*RaftHTTPHandler, error) {
	if storage == nil || now == nil || verify == nil || !storage.SnapshotRaft().VotingDisabled ||
		storage.jointSet != nil {
		return nil, errors.New("[D112 learner Raft RPC] storage/time/verifier 或 learner phase 无效")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&oldSet, &oldDirectory, now()); err != nil {
		return nil, err
	}
	oldHash, _ := wire.ControlSetHash(&oldSet)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	if oldHash != storageHash {
		return nil, errors.New("[D112 learner Raft RPC] old ControlSet 与 learner storage 不一致")
	}
	return newRaftHTTPHandler(storage, now, true, verify,
		func(raw []byte, at time.Time) (string, error) {
			return wire.ControlPeerMemberForCertificate(&oldSet, &oldDirectory, raw, at)
		}), nil
}

// NewJointRaftHTTPHandler 只接受 old/new private directory 并集中的 exact peer
// certificate；同一证书若映射到不同 member 会按歧义身份拒绝（D112、D124）。
func NewJointRaftHTTPHandler(storage *RaftStorage, oldSet, newSet wire.ControlSetV1,
	oldDirectory, newDirectory wire.ControlPeerDirectoryV1, now func() time.Time,
	verify RaftCandidateVerifier) (*RaftHTTPHandler, error) {
	if storage == nil || now == nil || verify == nil || storage.jointSet == nil ||
		storage.SnapshotRaft().VotingDisabled {
		return nil, errors.New("[D112 joint Raft RPC] storage/time/verifier 或 joint phase 无效")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&oldSet, &oldDirectory, now()); err != nil {
		return nil, err
	}
	if err := wire.ValidateControlPeerDirectoryAt(&newSet, &newDirectory, now()); err != nil {
		return nil, err
	}
	oldHash, _ := wire.ControlSetHash(&oldSet)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	newHash, _ := wire.ControlSetHash(&newSet)
	activeHash, _ := wire.ControlSetHash(storage.jointSet)
	if oldHash != storageHash || newHash != activeHash {
		return nil, errors.New("[D112 joint Raft RPC] old/new 与 active Joint 不一致")
	}
	identify := func(raw []byte, at time.Time) (string, error) {
		return controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
			&newDirectory, raw, at)
	}
	return newRaftHTTPHandler(storage, now, false, verify, identify), nil
}

func newRaftHTTPHandler(storage *RaftStorage, now func() time.Time, learner bool,
	verify RaftCandidateVerifier,
	identify func([]byte, time.Time) (string, error)) *RaftHTTPHandler {
	return &RaftHTTPHandler{storage: storage, now: now, identify: identify,
		learner: learner, verify: verify}
}

func (handler *RaftHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.Method != http.MethodPost || request.TLS == nil || !request.TLS.HandshakeComplete ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" ||
		(request.URL.Path != RaftVotePath && request.URL.Path != RaftAppendPath) {
		http.NotFound(response, request)
		return
	}
	contentType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/json" {
		writeRaftError(response, http.StatusUnsupportedMediaType, "只接受 application/json")
		return
	}
	peerMemberID, err := handler.identify(request.TLS.PeerCertificates[0].Raw, handler.now())
	if err != nil {
		writeRaftError(response, http.StatusForbidden, "control-peer identity 未获当前 directory 授权")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, raftRPCMaxBody))
	if err != nil {
		writeRaftError(response, http.StatusRequestEntityTooLarge, "Raft RPC body 过大")
		return
	}
	switch request.URL.Path {
	case RaftVotePath:
		if handler.learner {
			writeRaftError(response, http.StatusForbidden, "learner 不参与 RequestVote")
			return
		}
		var message VoteRequestV1
		canonical, err := wire.DecodeStrict(body, raftRPCMaxBody, &message)
		if err != nil || !bytes.Equal(canonical, body) || message.CandidateID != peerMemberID {
			writeRaftError(response, http.StatusBadRequest, "vote body 或 mTLS member binding 无效")
			return
		}
		result, err := handler.storage.HandleVote(message)
		if err != nil {
			writeRaftError(response, http.StatusBadRequest, err.Error())
			return
		}
		writeRaftCanonical(response, result)
	case RaftAppendPath:
		var message AppendEntriesRequestV1
		canonical, err := wire.DecodeStrict(body, raftRPCMaxBody, &message)
		if err != nil || !bytes.Equal(canonical, body) || message.LeaderID != peerMemberID {
			writeRaftError(response, http.StatusBadRequest, "append body 或 mTLS member binding 无效")
			return
		}
		if err := handler.validateAppendCandidates(request.Context(), message); err != nil {
			writeRaftError(response, http.StatusBadRequest, err.Error())
			return
		}
		var result AppendEntriesResultV1
		if handler.learner {
			result, err = handler.storage.HandleLearnerAppendEntries(message)
		} else {
			result, err = handler.storage.HandleAppendEntries(message)
		}
		if err != nil {
			writeRaftError(response, http.StatusBadRequest, err.Error())
			return
		}
		writeRaftCanonical(response, result)
	}
}

// validateAppendCandidates 在任何新 Head fsync 前独立重算。更高 term 仍先落盘，
// 避免因为应用 candidate 无效而在崩溃后回到旧 term 再投票（D104）。
func (handler *RaftHTTPHandler) validateAppendCandidates(ctx context.Context,
	message AppendEntriesRequestV1) error {
	if message.Term < 1 || message.PrevLogIndex < 0 || message.PrevLogTerm < 0 || message.LeaderCommit < 0 {
		return errors.New("[D104 Raft RPC] AppendEntries header 无效")
	}
	state := handler.storage.SnapshotRaft()
	if message.Term > state.CurrentTerm {
		if _, err := handler.storage.ObserveTerm(message.Term); err != nil {
			return err
		}
	}
	if message.Term < state.CurrentTerm {
		return nil
	}
	for index := range message.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		record := &message.Entries[index]
		if record.Index >= 1 && record.Index <= int64(len(state.Log)) &&
			wire.EqualCanonical(state.Log[record.Index-1], *record) {
			continue
		}
		switch record.Kind {
		case RaftRecordHead:
			if record.Head == nil {
				return errors.New("[D104 Raft RPC] Head candidate 缺 payload")
			}
		case RaftRecordJointControlSet:
			if record.JointControlSet == nil {
				return errors.New("[D112 joint Raft] Joint candidate 缺 payload")
			}
		case RaftRecordNoOp:
			// no-op 没有应用 payload，exact hash/lineage 由 RaftStorage 重算。
			continue
		default:
			return errors.New("[D104 Raft RPC] 未知 Raft record kind")
		}
		if err := handler.verify(ctx, cloneRaftRecord(*record)); err != nil {
			return errors.New("[D104 Raft RPC] deterministic candidate recompute 失败")
		}
	}
	return nil
}

type RaftPeerClient struct {
	baseURL string
	client  *http.Client
}

func NewRaftPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*RaftPeerClient, error) {
	found := controlPeerDirectoryHasEndpoint(&directory, remoteMemberID, endpointURL)
	parsed, err := url.ParseRequestURI(endpointURL)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Path != "" || parsed.RawQuery != "" || !found {
		return nil, errors.New("[D124 control mTLS] endpoint 不属于目标 member 的 private directory")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
	return newRaftPeerClient(endpointURL, tlsConfig), nil
}

// NewJointRaftPeerClient 只允许目标 member 在 old/new directory 中明确声明的
// exact endpoint，并使用 Joint union TLS pin（D112、D124）。
func NewJointRaftPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate,
	oldSet, newSet wire.ControlSetV1, oldDirectory, newDirectory wire.ControlPeerDirectoryV1,
	now func() time.Time) (*RaftPeerClient, error) {
	found := controlPeerDirectoryHasEndpoint(&oldDirectory, remoteMemberID, endpointURL) ||
		controlPeerDirectoryHasEndpoint(&newDirectory, remoteMemberID, endpointURL)
	parsed, err := url.ParseRequestURI(endpointURL)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Path != "" ||
		parsed.RawQuery != "" || !found {
		return nil, errors.New("[D124 joint mTLS] endpoint 不属于目标 Joint member")
	}
	tlsConfig, err := NewJointControlPeerClientTLSConfig(remoteMemberID, certificate, oldSet,
		newSet, oldDirectory, newDirectory, now)
	if err != nil {
		return nil, err
	}
	return newRaftPeerClient(endpointURL, tlsConfig), nil
}

func newRaftPeerClient(endpointURL string, tlsConfig *tls.Config) *RaftPeerClient {
	transport := &http.Transport{
		Proxy:              nil,
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	return &RaftPeerClient{baseURL: endpointURL, client: &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[D124 control mTLS] Raft RPC 禁止 redirect")
		},
	}}
}

func controlPeerDirectoryHasEndpoint(directory *wire.ControlPeerDirectoryV1, memberID,
	endpointURL string) bool {
	if directory == nil {
		return false
	}
	for _, member := range directory.Members {
		if member.MemberID != memberID {
			continue
		}
		for _, endpoint := range member.PeerEndpoints {
			if endpoint.URL == endpointURL {
				return true
			}
		}
	}
	return false
}

func (client *RaftPeerClient) RequestVote(ctx context.Context, request VoteRequestV1) (VoteResultV1, error) {
	var result VoteResultV1
	err := client.post(ctx, RaftVotePath, request, &result)
	return result, err
}

func (client *RaftPeerClient) AppendEntries(ctx context.Context, request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	var result AppendEntriesResultV1
	err := client.post(ctx, RaftAppendPath, request, &result)
	return result, err
}

func (client *RaftPeerClient) post(ctx context.Context, path string, value, target any) error {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(responseBody) > 1<<20 {
		return errors.New("[D104 Raft RPC] response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("[D104 Raft RPC] peer 返回 HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" ||
		len(response.Cookies()) != 0 || response.Request.URL.String() != client.baseURL+path {
		return errors.New("[D104 Raft RPC] response metadata 无效")
	}
	canonical, err := wire.DecodeStrict(responseBody, 1<<20, target)
	if err != nil || !bytes.Equal(canonical, responseBody) {
		return errors.New("[D104 Raft RPC] response 不是 exact canonical wire")
	}
	return nil
}

func writeRaftCanonical(response http.ResponseWriter, value any) {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		writeRaftError(response, http.StatusInternalServerError, "response canonicalize 失败")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

func writeRaftError(response http.ResponseWriter, status int, message string) {
	body, _ := wire.MarshalCanonical(raftRPCErrorV1{Schema: 1, Error: message})
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write(body)
}
