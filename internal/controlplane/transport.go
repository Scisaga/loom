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

type RaftHTTPHandler struct {
	storage   *RaftStorage
	set       wire.ControlSetV1
	directory wire.ControlPeerDirectoryV1
	now       func() time.Time
}

func NewRaftHTTPHandler(storage *RaftStorage, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*RaftHTTPHandler, error) {
	if storage == nil || now == nil {
		return nil, errors.New("[D104 Raft RPC] storage/可信时间源不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &RaftHTTPHandler{storage: storage, set: set, directory: directory, now: now}, nil
}

func (handler *RaftHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.Method != http.MethodPost ||
		(request.URL.Path != RaftVotePath && request.URL.Path != RaftAppendPath) {
		http.NotFound(response, request)
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		writeRaftError(response, http.StatusForbidden, "需要 control-peer mTLS exact leaf")
		return
	}
	contentType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/json" {
		writeRaftError(response, http.StatusUnsupportedMediaType, "只接受 application/json")
		return
	}
	peerMemberID, err := wire.ControlPeerMemberForCertificate(&handler.set, &handler.directory, request.TLS.PeerCertificates[0].Raw, handler.now())
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
		var message VoteRequestV1
		if _, err := wire.DecodeStrict(body, raftRPCMaxBody, &message); err != nil || message.CandidateID != peerMemberID {
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
		if _, err := wire.DecodeStrict(body, raftRPCMaxBody, &message); err != nil || message.LeaderID != peerMemberID {
			writeRaftError(response, http.StatusBadRequest, "append body 或 mTLS member binding 无效")
			return
		}
		result, err := handler.storage.HandleAppendEntries(message)
		if err != nil {
			writeRaftError(response, http.StatusBadRequest, err.Error())
			return
		}
		writeRaftCanonical(response, result)
	}
}

type RaftPeerClient struct {
	baseURL string
	client  *http.Client
}

func NewRaftPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*RaftPeerClient, error) {
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
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Path != "" || parsed.RawQuery != "" || !found {
		return nil, errors.New("[D124 control mTLS] endpoint 不属于目标 member 的 private directory")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
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
	}}, nil
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
	_, err = wire.DecodeStrict(responseBody, 1<<20, target)
	return err
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
	_, _ = response.Write(append(body, '\n'))
}

func writeRaftError(response http.ResponseWriter, status int, message string) {
	body, _ := wire.MarshalCanonical(raftRPCErrorV1{Schema: 1, Error: message})
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write(append(body, '\n'))
}
