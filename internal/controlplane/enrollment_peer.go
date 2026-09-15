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

const (
	EnrollmentAdmissionVotePath = "/private/v2/enrollment-peer/admission-vote"
	enrollmentPeerMaxBody       = 4 << 20
)

type EnrollmentPeerHTTPHandler struct {
	set       wire.ControlSetV1
	directory wire.ControlPeerDirectoryV1
	now       func() time.Time
	voter     enrollmentv2.AdmissionVotePeer
}

func NewEnrollmentPeerHTTPHandler(set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1,
	now func() time.Time, voter enrollmentv2.AdmissionVotePeer) (*EnrollmentPeerHTTPHandler, error) {
	if now == nil || voter == nil {
		return nil, errors.New("[Enrollment peer] time/voter 不能为空")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &EnrollmentPeerHTTPHandler{set: set, directory: directory, now: now, voter: voter}, nil
}

func (handler *EnrollmentPeerHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.URL.Path != EnrollmentAdmissionVotePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version < tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Content-Encoding") != "" ||
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
	var submitted enrollmentv2.EnrollmentAdmissionVoteRequestV1
	canonical, err := wire.DecodeStrict(body, enrollmentPeerMaxBody, &submitted)
	if err != nil || !bytes.Equal(canonical, body) {
		writeEnrollmentPeerError(response, http.StatusBadRequest)
		return
	}
	signature, err := handler.voter.VoteAdmission(request.Context(), submitted)
	if err != nil {
		writeEnrollmentPeerError(response, http.StatusForbidden)
		return
	}
	writeRaftCanonical(response, enrollmentv2.EnrollmentAdmissionVoteResponseV1{Schema: 1, Signature: signature})
}

type EnrollmentPeerClient struct {
	baseURL string
	client  *http.Client
}

func NewEnrollmentPeerClient(endpointURL, remoteMemberID string, certificate tls.Certificate,
	set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time) (*EnrollmentPeerClient, error) {
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
		return nil, errors.New("[control mTLS] Enrollment peer endpoint 不属于目标 member")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	return &EnrollmentPeerClient{baseURL: endpointURL, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[control mTLS] Enrollment peer RPC 禁止 redirect")
		},
	}}, nil
}

func (client *EnrollmentPeerClient) VoteAdmission(ctx context.Context,
	request enrollmentv2.EnrollmentAdmissionVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+EnrollmentAdmissionVotePath, bytes.NewReader(body))
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
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[Enrollment peer] response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return wire.ControlEnrollmentSignatureV1{}, fmt.Errorf("[Enrollment peer] peer 返回 HTTP %d", response.StatusCode)
	}
	var result enrollmentv2.EnrollmentAdmissionVoteResponseV1
	canonical, err := wire.DecodeStrict(responseBody, 64<<10, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[Enrollment peer] response wire 无效")
	}
	return result.Signature, nil
}

// EnrollmentAdmissionCollector 并行请求 committed ControlSet 的每个 voter，独立
// 验每个 purpose signature，最后只取 member ID 最小的规范 quorum，避免响应顺序影响 QC。
type EnrollmentAdmissionCollector struct {
	set   wire.ControlSetV1
	peers map[string]enrollmentv2.AdmissionVotePeer
}

func NewEnrollmentAdmissionCollector(set wire.ControlSetV1,
	peers map[string]enrollmentv2.AdmissionVotePeer) (*EnrollmentAdmissionCollector, error) {
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	if len(peers) != len(set.Members) {
		return nil, errors.New("[Enrollment peer] collector 必须精确配置 committed ControlSet voters")
	}
	cloned := make(map[string]enrollmentv2.AdmissionVotePeer, len(peers))
	for _, member := range set.Members {
		peer, ok := peers[member.MemberID]
		if !ok || peer == nil {
			return nil, errors.New("[Enrollment peer] collector 缺 committed voter")
		}
		cloned[member.MemberID] = peer
	}
	return &EnrollmentAdmissionCollector{set: set, peers: cloned}, nil
}

func (collector *EnrollmentAdmissionCollector) CollectAdmission(ctx context.Context,
	attempt enrollmentv2.VerifiedClaimAttemptV2,
	attestation wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	submission := attempt.Submission()
	request := enrollmentv2.EnrollmentAdmissionVoteRequestV1{Schema: 1,
		EnrollmentServiceID: submission.Challenge.EnrollmentServiceID,
		Submission:          submission, Attestation: attestation}
	return collector.collectAdmissionRequest(ctx, request, attestation)
}

func (collector *EnrollmentAdmissionCollector) collectAdmissionRequest(ctx context.Context,
	request enrollmentv2.EnrollmentAdmissionVoteRequestV1,
	attestation wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	if err := wire.ValidateEnrollmentAdmission(&attestation); err != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, err
	}
	requestBody, err := wire.MarshalCanonical(request)
	if err != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, err
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
			var peerRequest enrollmentv2.EnrollmentAdmissionVoteRequestV1
			if _, err := wire.DecodeStrict(requestBody, enrollmentPeerMaxBody, &peerRequest); err != nil {
				results <- voteResult{memberID: memberID, err: err}
				return
			}
			value, err := peer.VoteAdmission(ctx, peerRequest)
			results <- voteResult{memberID: memberID, value: value, err: err}
		}()
	}
	signatures := make([]wire.ControlEnrollmentSignatureV1, 0, len(collector.set.Members))
	for range collector.set.Members {
		var result voteResult
		select {
		case result = <-results:
		case <-ctx.Done():
			return wire.StableEnrollmentAdmissionQCV1{}, ctx.Err()
		}
		if result.err != nil || result.value.MemberID != result.memberID ||
			wire.VerifyEnrollmentAdmissionSignature(&attestation, &result.value, &collector.set) != nil {
			continue
		}
		signatures = append(signatures, result.value)
	}
	quorum, _ := wire.Quorum(len(collector.set.Members))
	if len(signatures) < quorum {
		return wire.StableEnrollmentAdmissionQCV1{}, errors.New("[Enrollment peer] admission signatures 未达到 committed ControlSet quorum")
	}
	sort.Slice(signatures, func(i, j int) bool {
		if signatures[i].MemberID != signatures[j].MemberID {
			return signatures[i].MemberID < signatures[j].MemberID
		}
		return signatures[i].EnrollmentKeyID < signatures[j].EnrollmentKeyID
	})
	qc := wire.StableEnrollmentAdmissionQC(attestation, signatures[:quorum])
	if err := wire.VerifyEnrollmentAdmissionQC(&qc, &collector.set); err != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, err
	}
	return qc, nil
}

func writeEnrollmentPeerError(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"private enrollment peer request rejected"}`))
}
