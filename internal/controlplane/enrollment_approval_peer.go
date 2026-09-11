package controlplane

import (
	"bytes"
	"context"
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

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const EnrollmentApprovalVotePath = "/private/v2/enrollment-peer/approval-vote"

type EnrollmentApprovalHTTPHandler struct {
	set       wire.ControlSetV1
	directory wire.ControlPeerDirectoryV1
	now       func() time.Time
	voter     enrollmentv2.ApprovalVotePeer
}

func NewEnrollmentApprovalHTTPHandler(set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1,
	now func() time.Time, voter enrollmentv2.ApprovalVotePeer) (*EnrollmentApprovalHTTPHandler, error) {
	if now == nil || voter == nil {
		return nil, errors.New("[D130 Enrollment peer] approval time/voter 不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &EnrollmentApprovalHTTPHandler{set: set, directory: directory, now: now, voter: voter}, nil
}

func (handler *EnrollmentApprovalHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.URL.Path != EnrollmentApprovalVotePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version < tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) != 1 || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Content-Encoding") != "" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writeEnrollmentPeerError(response, http.StatusForbidden)
		return
	}
	if _, err := wire.ControlPeerMemberForCertificate(&handler.set, &handler.directory,
		request.TLS.PeerCertificates[0].Raw, handler.now()); err != nil {
		writeEnrollmentPeerError(response, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, enrollmentPeerMaxBody))
	if err != nil || len(body) == 0 {
		writeEnrollmentPeerError(response, http.StatusBadRequest)
		return
	}
	var submitted enrollmentv2.EnrollmentApprovalVoteRequestV1
	canonical, err := wire.DecodeStrict(body, enrollmentPeerMaxBody, &submitted)
	if err != nil || !bytes.Equal(canonical, body) {
		writeEnrollmentPeerError(response, http.StatusBadRequest)
		return
	}
	signature, err := handler.voter.VoteApproval(request.Context(), submitted)
	if err != nil {
		writeEnrollmentPeerError(response, http.StatusForbidden)
		return
	}
	writeRaftCanonical(response, enrollmentv2.EnrollmentApprovalVoteResponseV1{Schema: 1, Signature: signature})
}

type EnrollmentApprovalPeerClient struct {
	baseURL string
	client  *http.Client
}

func NewEnrollmentApprovalPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate,
	set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*EnrollmentApprovalPeerClient, error) {
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
		return nil, errors.New("[D124 control mTLS] Enrollment approval endpoint 不属于目标 member")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	return &EnrollmentApprovalPeerClient{baseURL: endpointURL, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[D124 control mTLS] Enrollment approval RPC 禁止 redirect")
		},
	}}, nil
}

func (client *EnrollmentApprovalPeerClient) VoteApproval(ctx context.Context,
	request enrollmentv2.EnrollmentApprovalVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+EnrollmentApprovalVotePath, bytes.NewReader(body))
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > 64<<10 {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D130 Enrollment peer] approval response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return wire.ControlEnrollmentSignatureV1{}, fmt.Errorf("[D130 Enrollment peer] approval peer 返回 HTTP %d", response.StatusCode)
	}
	var result enrollmentv2.EnrollmentApprovalVoteResponseV1
	canonical, err := wire.DecodeStrict(responseBody, 64<<10, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D130 Enrollment peer] approval response wire 无效")
	}
	return result.Signature, nil
}

// EnrollmentApprovalCollector 与 admission 一样请求 committed issuance ControlSet
// 的每个 voter，并固定 member ID 最小的 q(N) signer subset（D129、D130）。
type EnrollmentApprovalCollector struct {
	set   wire.ControlSetV1
	peers map[string]enrollmentv2.ApprovalVotePeer
}

func NewEnrollmentApprovalCollector(set wire.ControlSetV1,
	peers map[string]enrollmentv2.ApprovalVotePeer) (*EnrollmentApprovalCollector, error) {
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	if len(peers) != len(set.Members) {
		return nil, errors.New("[D130 Enrollment peer] approval collector 必须精确配置 committed ControlSet voters")
	}
	cloned := make(map[string]enrollmentv2.ApprovalVotePeer, len(peers))
	for _, member := range set.Members {
		peer, ok := peers[member.MemberID]
		if !ok || peer == nil {
			return nil, errors.New("[D130 Enrollment peer] approval collector 缺 committed voter")
		}
		cloned[member.MemberID] = peer
	}
	return &EnrollmentApprovalCollector{set: set, peers: cloned}, nil
}

func (collector *EnrollmentApprovalCollector) CollectApproval(ctx context.Context,
	attestation wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error) {
	if err := wire.ValidateEnrollmentApproval(&attestation); err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, err
	}
	request := enrollmentv2.EnrollmentApprovalVoteRequestV1{Schema: 1, Attestation: attestation}
	requestBody, err := wire.MarshalCanonical(request)
	if err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, err
	}
	type voteResult struct {
		memberID string
		value    wire.ControlEnrollmentSignatureV1
		err      error
	}
	results := make(chan voteResult, len(collector.set.Members))
	for _, member := range collector.set.Members {
		memberID := member.MemberID
		peer := collector.peers[memberID]
		go func() {
			var peerRequest enrollmentv2.EnrollmentApprovalVoteRequestV1
			if _, err := wire.DecodeStrict(requestBody, enrollmentPeerMaxBody, &peerRequest); err != nil {
				results <- voteResult{memberID: memberID, err: err}
				return
			}
			value, err := peer.VoteApproval(ctx, peerRequest)
			results <- voteResult{memberID: memberID, value: value, err: err}
		}()
	}
	signatures := make([]wire.ControlEnrollmentSignatureV1, 0, len(collector.set.Members))
	for range collector.set.Members {
		var result voteResult
		select {
		case result = <-results:
		case <-ctx.Done():
			return wire.StableEnrollmentApprovalQCV2{}, ctx.Err()
		}
		if result.err != nil || result.value.MemberID != result.memberID ||
			wire.VerifyEnrollmentApprovalSignature(&attestation, &result.value, &collector.set) != nil {
			continue
		}
		signatures = append(signatures, result.value)
	}
	quorum, _ := wire.Quorum(len(collector.set.Members))
	if len(signatures) < quorum {
		return wire.StableEnrollmentApprovalQCV2{}, errors.New("[D130 Enrollment peer] approval signatures 未达到 committed ControlSet quorum")
	}
	sort.Slice(signatures, func(i, j int) bool {
		if signatures[i].MemberID != signatures[j].MemberID {
			return signatures[i].MemberID < signatures[j].MemberID
		}
		return signatures[i].EnrollmentKeyID < signatures[j].EnrollmentKeyID
	})
	qc := wire.StableEnrollmentApprovalQC(attestation, signatures[:quorum])
	if err := wire.VerifyEnrollmentApprovalQC(&qc, &collector.set); err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, err
	}
	return qc, nil
}
