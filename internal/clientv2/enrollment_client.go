package clientv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"loom/internal/wire"
)

const maximumPrivateEnrollmentResponse = 4 << 20

type TunnelDialContext func(context.Context, string, string) (net.Conn, error)

// PrivateEnrollmentClient 只在已经由 capability 限制到 exact Enrollment tuple 的
// tunnel dialer 上运行。非 nil RootCAs 必须来自已验 internal CA profile；即使提供 CA，exact
// certified SPKI pin 和 overlay IP SAN 也仍是强制条件（D129、D131）。
type PrivateEnrollmentClient struct {
	client  *http.Client
	baseURL string
	ref     wire.PrivateEnrollmentServiceRefV1
	now     func() time.Time
}

func NewPrivateEnrollmentClient(ref wire.PrivateEnrollmentServiceRefV1, roots *x509.CertPool,
	dial TunnelDialContext, now func() time.Time, timeout time.Duration) (*PrivateEnrollmentClient, error) {
	if err := wire.ValidatePrivateEnrollmentServiceRef(&ref); err != nil {
		return nil, err
	}
	if dial == nil || now == nil || timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("[D131 client] private Enrollment dialer/可信时间/timeout 无效")
	}
	expectedAddress := net.JoinHostPort(ref.OverlayIP, strconv.FormatInt(ref.TCPPort, 10))
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: ref.OverlayIP,
		NextProtos: []string{"http/1.1"},
		// 私有 CA 不进入系统 WebPKI；下面同时执行 exact roots（若提供）、IP SAN 与 SPKI pin 验证。
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPrivateEnrollmentTLS(state, ref, roots, now())
		},
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("[D131 client] private Enrollment dial 超出 exact overlay tuple")
			}
			raw, err := dial(ctx, "tcp", expectedAddress)
			if err != nil {
				return nil, err
			}
			connection := tls.Client(raw, tlsConfig.Clone())
			if err := connection.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return connection, nil
		},
	}
	base := (&url.URL{Scheme: "https", Host: expectedAddress}).String()
	return &PrivateEnrollmentClient{
		client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[D131 client] private Enrollment 禁止 redirect")
		}},
		baseURL: base, ref: ref, now: now,
	}, nil
}

func verifyPrivateEnrollmentTLS(state tls.ConnectionState, ref wire.PrivateEnrollmentServiceRefV1,
	roots *x509.CertPool, trustedTime time.Time) error {
	if trustedTime.IsZero() || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return errors.New("[D131 client] private Enrollment TLS version/certificate/可信时间无效")
	}
	leaf := state.PeerCertificates[0]
	instant := trustedTime.UTC()
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || instant.Before(leaf.NotBefore) || !instant.Before(leaf.NotAfter) ||
		leaf.VerifyHostname(ref.OverlayIP) != nil || len(leaf.UnhandledCriticalExtensions) != 0 ||
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("[D131 client] Enrollment leaf role/validity/overlay IP SAN 无效")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	if !containsString(ref.ServerIdentitySPKIPins, pin) {
		return errors.New("[D131 client] Enrollment leaf SPKI 不在 certified pin set")
	}
	if roots == nil {
		return nil
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: ref.OverlayIP, Roots: roots, Intermediates: intermediates, CurrentTime: instant,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return errors.New("[D131 client] Enrollment leaf 不属于 exact internal CA profile")
	}
	return nil
}

func (client *PrivateEnrollmentClient) CloseIdleConnections() {
	if client == nil || client.client == nil {
		return
	}
	client.client.CloseIdleConnections()
}

func (client *PrivateEnrollmentClient) Preflight(ctx context.Context,
	request wire.EnrollmentIntentPreflightRequestV1, expectedCommitmentHash string) (wire.EnrollmentIntentPreflightResponseV1, error) {
	if _, err := wire.EnrollmentIntentPreflightRequestHash(&request); err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	if _, err := wire.ParseHash(expectedCommitmentHash); err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	var response wire.EnrollmentIntentPreflightResponseV1
	if err := client.postCanonical(ctx, "/v2/enrollment/preflight", request, http.StatusOK, &response); err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&response, &request, expectedCommitmentHash); err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	return response, nil
}

// Challenge 请求体只有 stable core；token 直到 challenge 被验证后才进入 SubmitClaim。
func (client *PrivateEnrollmentClient) Challenge(ctx context.Context,
	core wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error) {
	coreHash, err := wire.EnrollmentClaimCoreHash(&core)
	if err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	var response wire.EnrollmentPoPChallengeV1
	if err := client.postCanonical(ctx, "/v2/enrollment/challenge", core, http.StatusOK, &response); err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	if response.ClusterID != core.ClusterID || response.InviteID != core.InviteID || response.RequestID != core.RequestID ||
		response.EnrollmentServiceID != client.ref.ServiceID {
		return wire.EnrollmentPoPChallengeV1{}, errors.New("[D129 client] challenge 与 core/private service 不匹配")
	}
	if _, err := wire.EnrollmentChallengeHash(&response, coreHash, client.now().UTC()); err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	return response, nil
}

func (client *PrivateEnrollmentClient) SubmitClaim(ctx context.Context,
	submission wire.EnrollmentClaimSubmissionV2) (wire.EnrollmentClaimResultV2, error) {
	var result wire.EnrollmentClaimResultV2
	if err := client.postCanonicalAnyStatus(ctx, "/v2/enrollment/claim", submission,
		[]int{http.StatusOK, http.StatusAccepted}, &result); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	return result, nil
}

func (client *PrivateEnrollmentClient) postCanonical(ctx context.Context, path string, value any,
	expectedStatus int, target any) error {
	return client.postCanonicalAnyStatus(ctx, path, value, []int{expectedStatus}, target)
}

func (client *PrivateEnrollmentClient) postCanonicalAnyStatus(ctx context.Context, path string, value any,
	expectedStatuses []int, target any) error {
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
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maximumPrivateEnrollmentResponse+1))
	if readErr != nil || len(responseBody) == 0 || len(responseBody) > maximumPrivateEnrollmentResponse {
		return errors.New("[D129 client] private Enrollment response 读取失败或过大")
	}
	if !containsInt(expectedStatuses, response.StatusCode) {
		return fmt.Errorf("[D129 client] private Enrollment 返回 HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" ||
		len(response.Cookies()) != 0 || response.Request.URL.String() != client.baseURL+path {
		return errors.New("[D129 client] private Enrollment response metadata 无效")
	}
	canonical, err := wire.DecodeStrict(responseBody, maximumPrivateEnrollmentResponse, target)
	if err != nil || !bytes.Equal(canonical, responseBody) {
		return errors.New("[D129 client] private Enrollment response 不是 exact canonical wire")
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsExtKeyUsage(values []x509.ExtKeyUsage, value x509.ExtKeyUsage) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
