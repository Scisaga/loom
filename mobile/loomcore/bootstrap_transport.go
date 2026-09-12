package loomcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const (
	androidBootstrapHysteriaAuthHost   = "hysteria"
	androidBootstrapHysteriaAuthPath   = "/auth"
	androidBootstrapHysteriaAuthHeader = "Hysteria-Auth"
	androidBootstrapHysteriaAuthOK     = 233
	androidBootstrapHysteriaTCPFrame   = uint64(0x401)
	androidBootstrapMaximumMessage     = 2048
	androidBootstrapMaximumPadding     = 4096
	androidBootstrapHTTPMaximum        = 4 << 20
	androidBootstrapClientProtocol     = 2
)

// AndroidBootstrapNetwork 由同一个 LoomVpnService 实现。每个 outer socket
// 必须先 protect 再绑定到冻结的 Android Network；解析也必须走该 underlay，
// 不能被正式 TUN/FakeIP 接管（Issue #14、D131）。
type AndroidBootstrapNetwork interface {
	ProtectAndBindSocket(fd int64) error
	ResolveHost(host string) (string, error)
	RecordConnectionAttempt(capabilityID string, attempt int64) error
	UnderlayIdentity() string
}

type androidBootstrapSelection struct {
	Schema             int    `json:"schema"`
	EndpointID         string `json:"endpoint_id"`
	Transport          string `json:"transport"`
	ListenerGeneration int64  `json:"listener_generation"`
	ProbeRTTMillis     int64  `json:"probe_rtt_millis"`
}

type androidBootstrapProbePlan struct {
	Schema   int                         `json:"schema"`
	Selected androidBootstrapSelection   `json:"selected"`
	Viable   []androidBootstrapSelection `json:"viable"`
}

type androidBootstrapCandidate struct {
	endpointID         string
	transport          string
	listenerGeneration int64
	hintRank           int64
	serverName         string
	publicPort         int64
	addressFamilies    []string
	spkiPins           []string
	preferred          bool
}

type androidBootstrapProbeTarget struct {
	candidate androidBootstrapCandidate
	address   netip.Addr
}

type androidBootstrapProbeResult struct {
	androidBootstrapProbeTarget
	rtt time.Duration
}

// AndroidV2BootstrapSession 把 public transport probe、capability tunnel、
// inner TLS 与 preflight/challenge/claim 顺序收进同一个不可并发状态机。
// exported 方法只交换 canonical bytes，Kotlin 不复制 wire 验证逻辑。
type AndroidV2BootstrapSession struct {
	flowMu sync.Mutex

	inputs     androidEnrollmentInputsV2
	network    AndroidBootstrapNetwork
	dialer     *androidBootstrapDialer
	client     *http.Client
	transport  *http.Transport
	baseURL    string
	trustedNow atomic.Int64
	closed     atomic.Bool
	context    context.Context
	cancel     context.CancelFunc

	preflight *wire.EnrollmentIntentPreflightResponseV1
	core      *wire.EnrollmentClaimCoreV2
	challenge *wire.EnrollmentPoPChallengeV1
	resume    *androidEnrollmentResumeInputsV1
	// completedResult 只有完整 completion receipt 与 installation context 已由
	// 共享 verifier 通过后才设置；artifact fetch 不接受宿主传入的 result/ref。
	completedResult   []byte
	completedEvidence *enrollmentv2.VerifiedEnrollmentCompletionV1
}

type androidReleasedArtifactsV1 struct {
	Schema    int                           `json:"schema"`
	Envelopes []wire.SealedSecretEnvelopeV1 `json:"envelopes"`
}

// NewAndroidV2BootstrapSession 只接受完整通过 Invite/catalog/capability authority
// 的输入。priorAttempts 来自加密 pending journal，防止进程重启重置客户端预算；
// ingress 仍会在服务端耐久执行同一上限（D115、D131）。
func NewAndroidV2BootstrapSession(descriptorJSON, proofBundleJSON, catalogJSON []byte,
	trustedTime string, priorAttempts int64, network AndroidBootstrapNetwork,
) (*AndroidV2BootstrapSession, error) {
	return newAndroidV2BootstrapSession(descriptorJSON, proofBundleJSON, catalogJSON,
		trustedTime, priorAttempts, network, nil)
}

func newAndroidV2BootstrapSession(descriptorJSON, proofBundleJSON, catalogJSON []byte,
	trustedTime string, priorAttempts int64, network AndroidBootstrapNetwork,
	outerRoots *x509.CertPool,
) (*AndroidV2BootstrapSession, error) {
	if network == nil {
		return nil, errors.New("[D131 Android] bootstrap Network controller 不能为空")
	}
	underlayIdentity := network.UnderlayIdentity()
	if underlayIdentity == "" || len(underlayIdentity) > 256 || strings.TrimSpace(underlayIdentity) != underlayIdentity {
		return nil, errors.New("[D131 Android] frozen underlay identity 无效")
	}
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	verifiedCatalog, err := VerifyAndroidV2BootstrapCatalog(descriptorJSON, proofBundleJSON,
		catalogJSON, trustedTime, androidBootstrapClientProtocol)
	if err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	if err := decodeExactAndroidV2(verifiedCatalog, 16<<20, &catalog, "bootstrap catalog"); err != nil {
		return nil, err
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	verifiedCapability, err := wire.VerifyCapabilityAuthorizationEvidence(
		&inputs.descriptor.BootstrapTunnelCapability,
		&inputs.bundle.BootstrapIssuerAuthorizationProof,
		&inputs.bundle.InviteIssuancePolicy,
		now,
	)
	if err != nil {
		return nil, err
	}
	body := verifiedCapability.Body()
	if err := validateAndroidBootstrapCapabilityMode(body, "initial_claim",
		catalog.BootstrapIngressSetHash); err != nil {
		return nil, errors.New("[D131 Android] initial capability 未绑定 catalog/inner TLS TCP")
	}
	destination, err := androidBootstrapDestination(body)
	if err != nil {
		return nil, err
	}
	candidates, err := androidBootstrapCandidates(&catalog, now)
	if err != nil {
		return nil, err
	}
	if priorAttempts < 0 || priorAttempts > body.MaximumConnectionAttempts {
		return nil, errors.New("[D131 Android] bootstrap 已用 connection attempt 数无效")
	}
	rootContext, cancel := context.WithCancel(context.Background())
	dialer := &androidBootstrapDialer{
		network: network, candidates: candidates, credential: verifiedCapability.TransportCredential(),
		capabilityID: verifiedCapability.CapabilityID(), destination: destination,
		maximumAttempts: body.MaximumConnectionAttempts, attempts: priorAttempts,
		maximumSession:    time.Duration(body.MaximumSessionSeconds) * time.Second,
		maximumTotalBytes: body.MaximumTotalBytes, roots: outerRoots, timeout: 12 * time.Second,
		notBefore: mustAndroidBootstrapTime(body.NotBefore), expiresAt: mustAndroidBootstrapTime(body.ExpiresAt),
	}
	ref := inputs.descriptor.EnrollmentServiceRef
	transport, client, baseURL, err := newAndroidPrivateEnrollmentHTTP(dialer, ref, func() time.Time {
		return time.Unix(0, dialer.trustedNow.Load()).UTC()
	})
	if err != nil {
		cancel()
		return nil, err
	}
	session := &AndroidV2BootstrapSession{
		inputs: inputs, network: network, dialer: dialer, client: client, transport: transport,
		baseURL: baseURL, context: rootContext, cancel: cancel,
	}
	session.setTrustedTime(now)
	return session, nil
}

// NewAndroidV2ResumeSession 只恢复本机已经耐久保存的 stable core/progress。
// descriptor 不含 token，且必须由 APK platform root、Invite lineage、当前 catalog
// 与本机 expected transaction 一起验证后才建立 tunnel（D115、D130、D131）。
func NewAndroidV2ResumeSession(descriptorJSON, proofBundleJSON, catalogJSON,
	claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey []byte, progressStatus, trustedTime string,
	priorAttempts int64, network AndroidBootstrapNetwork,
) (*AndroidV2BootstrapSession, error) {
	return newAndroidV2ResumeSession(descriptorJSON, proofBundleJSON, catalogJSON,
		claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey, progressStatus, trustedTime,
		priorAttempts, network, nil)
}

func newAndroidV2ResumeSession(descriptorJSON, proofBundleJSON, catalogJSON,
	claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey []byte, progressStatus, trustedTime string,
	priorAttempts int64, network AndroidBootstrapNetwork, outerRoots *x509.CertPool,
) (*AndroidV2BootstrapSession, error) {
	if network == nil {
		return nil, errors.New("[D131 Android resume] bootstrap Network controller 不能为空")
	}
	underlayIdentity := network.UnderlayIdentity()
	if underlayIdentity == "" || len(underlayIdentity) > 256 || strings.TrimSpace(underlayIdentity) != underlayIdentity {
		return nil, errors.New("[D131 Android resume] frozen underlay identity 无效")
	}
	inputs, err := loadAndroidEnrollmentResumeInputsV1(descriptorJSON, proofBundleJSON, catalogJSON,
		claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey, progressStatus, trustedTime)
	if err != nil {
		return nil, err
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	verifiedCapability, err := wire.VerifyCapabilityAuthorizationEvidence(
		&inputs.descriptor.ResumeTunnelCapability,
		&inputs.bundle.BootstrapIssuerAuthorizationProof,
		&inputs.bundle.InviteIssuancePolicy,
		now,
	)
	if err != nil {
		return nil, err
	}
	body := verifiedCapability.Body()
	if err := validateAndroidBootstrapCapabilityMode(body, "resume_committed_claim",
		inputs.catalog.BootstrapIngressSetHash); err != nil {
		return nil, errors.New("[D131 Android resume] capability 未绑定 catalog/inner TLS TCP")
	}
	destination, err := androidBootstrapDestination(body)
	if err != nil {
		return nil, err
	}
	candidates, err := androidBootstrapCandidates(&inputs.catalog, now)
	if err != nil {
		return nil, err
	}
	if priorAttempts < 0 || priorAttempts > body.MaximumConnectionAttempts {
		return nil, errors.New("[D131 Android resume] 已用 connection attempt 数无效")
	}
	rootContext, cancel := context.WithCancel(context.Background())
	dialer := &androidBootstrapDialer{
		network: network, candidates: candidates, credential: verifiedCapability.TransportCredential(),
		capabilityID: verifiedCapability.CapabilityID(), destination: destination,
		maximumAttempts: body.MaximumConnectionAttempts, attempts: priorAttempts,
		maximumSession:    time.Duration(body.MaximumSessionSeconds) * time.Second,
		maximumTotalBytes: body.MaximumTotalBytes, roots: outerRoots, timeout: 12 * time.Second,
		notBefore: mustAndroidBootstrapTime(body.NotBefore), expiresAt: mustAndroidBootstrapTime(body.ExpiresAt),
	}
	transport, client, baseURL, err := newAndroidPrivateEnrollmentHTTP(
		dialer, inputs.descriptor.EnrollmentServiceRef,
		func() time.Time { return time.Unix(0, dialer.trustedNow.Load()).UTC() },
	)
	if err != nil {
		cancel()
		return nil, err
	}
	core := inputs.core
	session := &AndroidV2BootstrapSession{
		network: network, dialer: dialer, client: client, transport: transport, baseURL: baseURL,
		context: rootContext, cancel: cancel, resume: &inputs, core: &core,
	}
	session.setTrustedTime(now)
	return session, nil
}

func validateAndroidBootstrapCapabilityMode(body wire.BootstrapTunnelCapabilityBodyV1,
	mode, ingressSetHash string,
) error {
	if body.Mode != mode || body.AllowedIngressSetHash != ingressSetHash ||
		body.AllowedInsideTransport != "tcp" {
		return errors.New("[D131 Android] capability mode/ingress/inside transport 无效")
	}
	return nil
}

// Probe 对每个已验 listener/address 最多做一次无 bearer TLS/QUIC handshake；
// HY2 只要任一可达就优先，Trojan 仅作为 UDP 阻断 fallback。
func (session *AndroidV2BootstrapSession) Probe(trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	plan, err := session.dialer.probe(session.context, now)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(plan)
}

// RestoreProbe 只允许同一 Android Network generation 重放先前的认证结果。
// 宿主负责比较 UnderlayIdentity；Go 再把 listener identity 绑定回当前已验 catalog。
func (session *AndroidV2BootstrapSession) RestoreProbe(canonicalPlan []byte, trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	var plan androidBootstrapProbePlan
	if err := decodeExactAndroidV2(canonicalPlan, 1<<20, &plan, "bootstrap probe plan"); err != nil {
		return nil, err
	}
	if err := session.dialer.restoreProbe(plan, now); err != nil {
		return nil, err
	}
	return append([]byte(nil), canonicalPlan...), nil
}

// Preflight 是整个 session 中唯一允许的首个 inner request；其 canonical body
// 必须等于共享 verifier 从 proof 投影出的 token-free request。
func (session *AndroidV2BootstrapSession) Preflight(canonicalRequest []byte, trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	if _, err := session.readyAt(trustedTime); err != nil {
		return nil, err
	}
	var request wire.EnrollmentIntentPreflightRequestV1
	if err := decodeExactAndroidV2(canonicalRequest, 1<<20, &request, "Enrollment preflight request"); err != nil {
		return nil, err
	}
	var expected wire.EnrollmentIntentPreflightRequestV1
	if session.resume != nil {
		expected = androidEnrollmentResumePreflightRequest(*session.resume)
	} else {
		expected = androidEnrollmentPreflightRequestV2(session.inputs)
	}
	if !wire.EqualCanonical(request, expected) {
		return nil, errors.New("[D129 Android] preflight request 不是已验 Invite 的 exact 投影")
	}
	body, err := session.postCanonical("/v2/enrollment/preflight", canonicalRequest, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var verified wire.EnrollmentIntentPreflightResponseV1
	if session.resume != nil {
		verified, err = verifyAndroidEnrollmentResumePreflight(*session.resume, body)
	} else {
		verified, err = verifyAndroidEnrollmentPreflightV2(session.inputs, body)
	}
	if err != nil {
		return nil, err
	}
	session.preflight = &verified
	return body, nil
}

// Challenge 固定 stable core；网络重试可以取得新 nonce，但不能替换
// request/body/key/core（D129、D130）。
func (session *AndroidV2BootstrapSession) Challenge(canonicalCore []byte, trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	if session.preflight == nil {
		return nil, errors.New("[D129 Android] challenge 前尚未完成 token-free preflight")
	}
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(canonicalCore, 4<<20, &core, "Enrollment claim core"); err != nil {
		return nil, err
	}
	if session.resume != nil {
		if !wire.EqualCanonical(core, session.resume.core) {
			return nil, errors.New("[D130 Android resume] challenge 未复用 protected stable core")
		}
	} else {
		if err := validateAndroidEnrollmentClaimCoreV2(session.inputs, *session.preflight, &core); err != nil {
			return nil, err
		}
	}
	if session.core != nil && !wire.EqualCanonical(*session.core, core) {
		return nil, errors.New("[D130 Android] 同一 pending transaction 禁止替换 stable core")
	}
	body, err := session.postCanonical("/v2/enrollment/challenge", canonicalCore, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var challenge wire.EnrollmentPoPChallengeV1
	if err := decodeExactAndroidV2(body, 1<<20, &challenge, "Enrollment challenge"); err != nil {
		return nil, err
	}
	coreHash, _ := wire.EnrollmentClaimCoreHash(&core)
	serviceID := session.enrollmentServiceID()
	if challenge.ClusterID != core.ClusterID || challenge.InviteID != core.InviteID ||
		challenge.RequestID != core.RequestID ||
		challenge.EnrollmentServiceID != serviceID {
		return nil, errors.New("[D129 Android] challenge 与 stable core/private service 不匹配")
	}
	if _, err := wire.EnrollmentChallengeHash(&challenge, coreHash, now); err != nil {
		return nil, err
	}
	coreCopy, challengeCopy := core, challenge
	session.core, session.challenge = &coreCopy, &challengeCopy
	return body, nil
}

func (session *AndroidV2BootstrapSession) enrollmentServiceID() string {
	if session.resume != nil {
		return session.resume.descriptor.EnrollmentServiceRef.ServiceID
	}
	return session.inputs.descriptor.EnrollmentServiceRef.ServiceID
}

// SubmitClaim 是 initial flow 中唯一会把 Invite token 送入 inner TLS 的方法。
// 在写 socket 前再次执行与 server voter 同义的完整校验。
func (session *AndroidV2BootstrapSession) SubmitClaim(canonicalSubmission []byte, trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	if session.preflight == nil || session.core == nil || session.challenge == nil {
		return nil, errors.New("[D129 Android] claim 顺序无效")
	}
	if session.resume != nil {
		return nil, errors.New("[D130 Android resume] resume session 禁止提交含 token 的 initial claim")
	}
	var submission wire.EnrollmentClaimSubmissionV2
	if err := decodeExactAndroidV2(canonicalSubmission, 4<<20, &submission, "Enrollment claim submission"); err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(submission.ClaimCore, *session.core) ||
		!wire.EqualCanonical(submission.Challenge, *session.challenge) {
		return nil, errors.New("[D130 Android] claim 未复用已固定 core/challenge")
	}
	if _, err := wire.VerifyEnrollmentClaimSubmission(&submission,
		&session.inputs.bundle.CertifiedInviteRecord, &session.inputs.bundle.InviteIssuancePolicy,
		&session.preflight.DeviceEnrollmentIntentOpening,
		session.inputs.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return nil, err
	}
	body, err := session.postCanonical("/v2/enrollment/claim", canonicalSubmission,
		[]int{http.StatusOK, http.StatusAccepted})
	if err != nil {
		return nil, err
	}
	_, result, completion, err := verifyAndroidEnrollmentV2ClaimResult(
		session.inputs, *session.preflight, *session.core, body, now,
	)
	if err != nil {
		return nil, err
	}
	if err := session.acceptVerifiedEnrollmentResult(body, result, completion); err != nil {
		return nil, err
	}
	return body, nil
}

func (session *AndroidV2BootstrapSession) ResumePreflightRequest(trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	if session.resume == nil {
		return nil, errors.New("[D130 Android resume] initial session 没有 resume preflight")
	}
	if err := session.verifyResumeDescriptorAt(now); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(androidEnrollmentResumePreflightRequest(*session.resume))
}

// PrepareResumePoPBody/AssembleResumeSubmission 把 fresh challenge 的签名边界
// 留在 Keystore；返回的 submission schema 没有 token 字段（D129、D130）。
func (session *AndroidV2BootstrapSession) PrepareResumePoPBody(trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	body, err := session.resumePoPBodyAt(now)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(body)
}

func (session *AndroidV2BootstrapSession) AssembleResumeSubmission(canonicalPoPBody []byte,
	proofSignature, trustedTime string,
) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	var supplied wire.EnrollmentPoPBodyV2
	if err := decodeExactAndroidV2(canonicalPoPBody, 1<<20, &supplied,
		"resume Enrollment PoP body"); err != nil {
		return nil, err
	}
	expected, err := session.resumePoPBodyAt(now)
	if err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(supplied, expected) {
		return nil, errors.New("[D130 Android resume] PoP body 未绑定当前 fresh challenge")
	}
	submission := wire.EnrollmentResumeSubmissionV1{
		Schema: 1, ClaimCore: *session.core, Challenge: *session.challenge,
		PoPBody: supplied, ProofSignature: proofSignature,
	}
	if _, err := wire.VerifyEnrollmentResumeSubmission(&submission,
		session.resume.descriptor.ResumeTunnelCapability.Body.ResumeBinding,
		&session.resume.bundle.CertifiedInviteRecord, &session.resume.bundle.InviteIssuancePolicy,
		&session.preflight.DeviceEnrollmentIntentOpening,
		session.resume.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(submission)
}

// SubmitResume 只接受无 token schema，并在返回给 Kotlin 前验证 progress/completion
// receipt 必须包含 descriptor 所绑定的 transaction state（D130）。
func (session *AndroidV2BootstrapSession) SubmitResume(canonicalSubmission []byte,
	trustedTime string,
) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	now, err := session.readyAt(trustedTime)
	if err != nil {
		return nil, err
	}
	if session.resume == nil || session.preflight == nil || session.core == nil || session.challenge == nil {
		return nil, errors.New("[D130 Android resume] submission 顺序无效")
	}
	if err := session.verifyResumeDescriptorAt(now); err != nil {
		return nil, err
	}
	var submission wire.EnrollmentResumeSubmissionV1
	if err := decodeExactAndroidV2(canonicalSubmission, 4<<20, &submission,
		"Enrollment resume submission"); err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(submission.ClaimCore, *session.core) ||
		!wire.EqualCanonical(submission.Challenge, *session.challenge) {
		return nil, errors.New("[D130 Android resume] submission 未复用 protected core/fresh challenge")
	}
	if _, err := wire.VerifyEnrollmentResumeSubmission(&submission,
		session.resume.descriptor.ResumeTunnelCapability.Body.ResumeBinding,
		&session.resume.bundle.CertifiedInviteRecord, &session.resume.bundle.InviteIssuancePolicy,
		&session.preflight.DeviceEnrollmentIntentOpening,
		session.resume.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return nil, err
	}
	body, err := session.postCanonical("/v2/enrollment/claim", canonicalSubmission,
		[]int{http.StatusOK, http.StatusAccepted})
	if err != nil {
		return nil, err
	}
	projection, result, completion, err := verifyAndroidEnrollmentResultExpected(
		androidResumeProgressExpected(*session.resume, *session.preflight),
		session.resume.verified, body, now,
		[]string{
			session.resume.expected.EnrollmentTransactionStateHash,
			session.resume.descriptor.EnrollmentTransactionStateHash,
		},
	)
	if err != nil {
		return nil, err
	}
	if err := session.acceptVerifiedEnrollmentResult(body, result, completion); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(projection)
}

// PrepareResumeInstallationStateWithConfigs 与首次 completion 共用同一原子
// 安装语义，resume 不得把 config 留成独立、可部分提交的状态（Issue #14、D130）。
func (session *AndroidV2BootstrapSession) PrepareResumeInstallationStateWithConfigs(
	installedSecretsJSON, installedConfigsJSON []byte,
) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	if session == nil || session.closed.Load() || session.resume == nil ||
		len(session.completedResult) == 0 || session.completedEvidence == nil {
		return nil, errors.New("[D130 Android resume] 尚无可安装的 verified completion")
	}
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(session.completedResult, 32<<20, &result,
		"verified resume completion"); err != nil {
		return nil, err
	}
	var credentials []androidInstalledSecretV1
	if err := decodeExactAndroidV2(installedSecretsJSON, 16<<20, &credentials,
		"installed credentials"); err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, errors.New("[D124 Android resume] installed credentials 必须是 canonical array")
	}
	var configs []androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedConfigsJSON, androidMaximumConfigTotalBytes+(4<<20),
		&configs, "installed configs"); err != nil {
		return nil, err
	}
	if configs == nil {
		return nil, errors.New("[D124 Android resume] installed configs 必须是 canonical array")
	}
	if err := session.completedEvidence.VerifyInstallationContext(
		&result, session.core, session.resume.verified,
	); err != nil {
		return nil, err
	}
	return prepareAndroidEnrollmentInstallationState(*session.core, result,
		*session.completedEvidence, session.resume.verified,
		session.resume.descriptor.DistributionMirrors, credentials, configs)
}

func (session *AndroidV2BootstrapSession) resumePoPBodyAt(now time.Time) (wire.EnrollmentPoPBodyV2, error) {
	if session.resume == nil || session.preflight == nil || session.core == nil || session.challenge == nil {
		return wire.EnrollmentPoPBodyV2{}, errors.New("[D130 Android resume] PoP 顺序无效")
	}
	if err := session.verifyResumeDescriptorAt(now); err != nil {
		return wire.EnrollmentPoPBodyV2{}, err
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(session.core)
	if err != nil {
		return wire.EnrollmentPoPBodyV2{}, err
	}
	challengeHash, err := wire.EnrollmentChallengeHash(session.challenge, coreHash, now)
	if err != nil {
		return wire.EnrollmentPoPBodyV2{}, err
	}
	body := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: session.core.ClusterID, InviteID: session.core.InviteID,
		RequestID: session.core.RequestID, ClaimCoreHash: coreHash,
		TokenCommitment: session.resume.bundle.CertifiedInviteRecord.TokenCommitment,
		ChallengeHash:   challengeHash,
	}
	if _, err := wire.EnrollmentPoPMessage(&body); err != nil {
		return wire.EnrollmentPoPBodyV2{}, err
	}
	return body, nil
}

func (session *AndroidV2BootstrapSession) verifyResumeDescriptorAt(now time.Time) error {
	if session.resume == nil {
		return errors.New("[D130 Android resume] session mode 无效")
	}
	return wire.VerifyEnrollmentResumeDescriptorBindings(
		&session.resume.descriptor, session.resume.expected, &session.resume.catalog,
		&session.resume.bundle.BootstrapIssuerAuthorizationProof,
		&session.resume.bundle.InviteIssuancePolicy, now, androidBootstrapClientProtocol,
	)
}

func (session *AndroidV2BootstrapSession) acceptVerifiedEnrollmentResult(body []byte,
	result wire.EnrollmentClaimResultV2, completion *enrollmentv2.VerifiedEnrollmentCompletionV1,
) error {
	if result.Status == "completed" {
		if completion == nil {
			return errors.New("[D130 Android] completed claim 缺 verified completion evidence")
		}
		if len(session.completedResult) != 0 && !bytes.Equal(session.completedResult, body) {
			return errors.New("[D130 Android] completed result 的 exact replay 发生冲突")
		}
		session.completedResult = append(session.completedResult[:0], body...)
		evidence := *completion
		session.completedEvidence = &evidence
	} else if len(session.completedResult) != 0 {
		return errors.New("[D130 Android] completed transaction 禁止回退为 pending")
	}
	return nil
}

// FetchReleasedArtifacts 只使用同一 session 内已经完整验证的 completed result，
// 并按其中 exact canonical refs 的顺序读取 immutable ciphertext。宿主不能注入
// 路径、digest 或 result 来扩张 capability tunnel 的读取范围（D124、D130、D131）。
func (session *AndroidV2BootstrapSession) FetchReleasedArtifacts(trustedTime string) ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	if _, err := session.readyAt(trustedTime); err != nil {
		return nil, err
	}
	if len(session.completedResult) == 0 {
		return nil, errors.New("[D124 Android] released artifact fetch 前尚无 verified completed result")
	}
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(session.completedResult, 32<<20, &result, "verified completed result"); err != nil {
		return nil, err
	}
	if result.Status != "completed" || result.ResultArtifact == nil {
		return nil, errors.New("[D124 Android] verified completed result/artifact 不完整")
	}
	refs := result.ResultArtifact.SecretArtifactRefs
	envelopes := make([]wire.SealedSecretEnvelopeV1, len(refs))
	totalBytes := 0
	for index := range refs {
		ref := &refs[index]
		if ref.BackendKind != "sealed_blob" || ref.SealedBlob == nil {
			return nil, errors.New("[D124 Android] Enrollment result 含不可由 Device 拉取的 secret backend")
		}
		digest, err := wire.ParseHash(ref.SealedBlob.CiphertextDigest)
		if err != nil {
			return nil, err
		}
		path := "/v2/enrollment/artifacts/sha256/" + hex.EncodeToString(digest)
		body, err := session.getCanonical(path)
		if err != nil {
			return nil, fmt.Errorf("[D124 Android] sealed artifact[%d] 获取失败: %w", index, err)
		}
		totalBytes += len(body)
		if totalBytes > 8<<20 {
			return nil, errors.New("[D124 Android] released artifacts 超过 bootstrap 总预算")
		}
		var envelope wire.SealedSecretEnvelopeV1
		if err := decodeExactAndroidV2(body, androidBootstrapHTTPMaximum, &envelope,
			"sealed secret envelope"); err != nil {
			return nil, err
		}
		if err := wire.ValidateSealedSecretEnvelope(&envelope); err != nil {
			return nil, err
		}
		if err := wire.VerifySealedSecretBinding(ref, &envelope); err != nil {
			return nil, err
		}
		envelopes[index] = envelope
	}
	return wire.MarshalCanonical(androidReleasedArtifactsV1{Schema: 1, Envelopes: envelopes})
}

func (session *AndroidV2BootstrapSession) ConnectionAttempts() int64 {
	if session == nil || session.dialer == nil {
		return 0
	}
	return session.dialer.connectionAttempts()
}

func (session *AndroidV2BootstrapSession) Close() {
	if session == nil || !session.closed.CompareAndSwap(false, true) {
		return
	}
	session.cancel()
	session.transport.CloseIdleConnections()
	session.dialer.closeActive()
}

func (session *AndroidV2BootstrapSession) readyAt(raw string) (time.Time, error) {
	if session == nil || session.closed.Load() {
		return time.Time{}, errors.New("[D131 Android] bootstrap session 已关闭")
	}
	now, err := wire.ParseTimeZ(raw)
	if err != nil {
		return time.Time{}, errors.New("[D131 Android] bootstrap trusted time 无效")
	}
	session.setTrustedTime(now)
	if err := session.dialer.validAt(now); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

func (session *AndroidV2BootstrapSession) setTrustedTime(now time.Time) {
	session.trustedNow.Store(now.UTC().UnixNano())
	session.dialer.trustedNow.Store(now.UTC().UnixNano())
}

func (session *AndroidV2BootstrapSession) postCanonical(path string, body []byte, statuses []int) ([]byte, error) {
	requestContext, cancel := context.WithTimeout(session.context, 45*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost,
		session.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Loom-Android/0.3")
	response, err := session.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, androidBootstrapHTTPMaximum+1))
	if readErr != nil || len(responseBody) == 0 || len(responseBody) > androidBootstrapHTTPMaximum {
		return nil, errors.New("[D129 Android] private Enrollment response 读取失败或过大")
	}
	if !androidContainsInt(statuses, response.StatusCode) {
		return nil, fmt.Errorf("[D129 Android] private Enrollment 返回 HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" ||
		len(response.Cookies()) != 0 || response.Request.URL.String() != session.baseURL+path {
		return nil, errors.New("[D129 Android] private Enrollment response metadata 无效")
	}
	return responseBody, nil
}

func (session *AndroidV2BootstrapSession) getCanonical(path string) ([]byte, error) {
	requestContext, cancel := context.WithTimeout(session.context, 45*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, session.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Loom-Android/0.3")
	response, err := session.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, androidBootstrapHTTPMaximum+1))
	if readErr != nil || len(responseBody) == 0 || len(responseBody) > androidBootstrapHTTPMaximum {
		return nil, errors.New("[D124 Android] sealed artifact response 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[D124 Android] sealed artifact 返回 HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" ||
		len(response.Cookies()) != 0 || response.Request.URL.String() != session.baseURL+path {
		return nil, errors.New("[D124 Android] sealed artifact response metadata 无效")
	}
	return responseBody, nil
}

type androidBootstrapDialer struct {
	mu sync.Mutex

	network           AndroidBootstrapNetwork
	candidates        []androidBootstrapCandidate
	credential        string
	capabilityID      string
	destination       string
	maximumAttempts   int64
	attempts          int64
	maximumSession    time.Duration
	maximumTotalBytes int64
	totalBytes        atomic.Int64
	roots             *x509.CertPool
	timeout           time.Duration
	notBefore         time.Time
	expiresAt         time.Time
	trustedNow        atomic.Int64
	probed            bool
	viable            []androidBootstrapProbeResult
	active            net.Conn
}

func (dialer *androidBootstrapDialer) probe(ctx context.Context, now time.Time) (androidBootstrapProbePlan, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if err := dialer.validAt(now); err != nil {
		return androidBootstrapProbePlan{}, err
	}
	if dialer.probed {
		if len(dialer.viable) == 0 {
			return androidBootstrapProbePlan{}, errors.New("[D131 Android] 已冻结的 bootstrap probe 无可达 transport")
		}
		return androidBootstrapPlan(dialer.viable), nil
	}
	targets, err := dialer.resolveTargets()
	if err != nil {
		dialer.probed = true
		return androidBootstrapProbePlan{}, err
	}
	type outcome struct {
		result androidBootstrapProbeResult
		err    error
	}
	outcomes := make(chan outcome, len(targets))
	for _, target := range targets {
		target := target
		go func() {
			attemptContext, cancel := context.WithTimeout(ctx, dialer.timeout)
			defer cancel()
			started := time.Now()
			err := dialer.probeTarget(attemptContext, target, now)
			outcomes <- outcome{result: androidBootstrapProbeResult{
				androidBootstrapProbeTarget: target, rtt: time.Since(started),
			}, err: err}
		}()
	}
	var viable []androidBootstrapProbeResult
	for range targets {
		outcome := <-outcomes
		if outcome.err == nil {
			viable = append(viable, outcome.result)
		}
	}
	sort.SliceStable(viable, func(left, right int) bool {
		l, r := viable[left], viable[right]
		if l.candidate.transport != r.candidate.transport {
			return l.candidate.transport == "hysteria2"
		}
		if l.rtt != r.rtt {
			return l.rtt < r.rtt
		}
		if l.candidate.hintRank != r.candidate.hintRank {
			return l.candidate.hintRank < r.candidate.hintRank
		}
		if l.candidate.endpointID != r.candidate.endpointID {
			return l.candidate.endpointID < r.candidate.endpointID
		}
		if l.candidate.preferred != r.candidate.preferred {
			return l.candidate.preferred
		}
		if l.candidate.listenerGeneration != r.candidate.listenerGeneration {
			return l.candidate.listenerGeneration > r.candidate.listenerGeneration
		}
		return l.address.String() < r.address.String()
	})
	dialer.probed, dialer.viable = true, viable
	if len(viable) == 0 {
		return androidBootstrapProbePlan{}, errors.New("[D131 Android] 当前 underlay 没有通过身份验证的 HY2/Trojan transport")
	}
	return androidBootstrapPlan(viable), nil
}

func androidBootstrapPlan(viable []androidBootstrapProbeResult) androidBootstrapProbePlan {
	plan := androidBootstrapProbePlan{Schema: 1}
	seen := make(map[string]struct{}, len(viable))
	for _, result := range viable {
		selection := result.selection()
		key := selection.EndpointID + "\x00" + selection.Transport + "\x00" + strconv.FormatInt(selection.ListenerGeneration, 10)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		plan.Viable = append(plan.Viable, selection)
	}
	if len(plan.Viable) > 0 {
		plan.Selected = plan.Viable[0]
	}
	return plan
}

func (dialer *androidBootstrapDialer) restoreProbe(plan androidBootstrapProbePlan, now time.Time) error {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if err := dialer.validAt(now); err != nil {
		return err
	}
	if plan.Schema != 1 || len(plan.Viable) == 0 || plan.Selected != plan.Viable[0] {
		return errors.New("[D131 Android] persisted bootstrap probe plan header 无效")
	}
	if dialer.probed {
		if wire.EqualCanonical(plan, androidBootstrapPlan(dialer.viable)) {
			return nil
		}
		return errors.New("[D131 Android] 同一 session 禁止替换 bootstrap probe plan")
	}
	byIdentity := make(map[string]androidBootstrapCandidate, len(dialer.candidates))
	for _, candidate := range dialer.candidates {
		key := candidate.endpointID + "\x00" + candidate.transport + "\x00" + strconv.FormatInt(candidate.listenerGeneration, 10)
		if _, duplicate := byIdentity[key]; duplicate {
			return errors.New("[D131 Android] catalog listener identity 重复")
		}
		byIdentity[key] = candidate
	}
	seen := make(map[string]struct{}, len(plan.Viable))
	var viable []androidBootstrapProbeResult
	for _, selection := range plan.Viable {
		if selection.Schema != 1 || selection.ProbeRTTMillis < 1 {
			return errors.New("[D131 Android] persisted bootstrap selection 无效")
		}
		key := selection.EndpointID + "\x00" + selection.Transport + "\x00" + strconv.FormatInt(selection.ListenerGeneration, 10)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("[D131 Android] persisted bootstrap selection 重复")
		}
		seen[key] = struct{}{}
		candidate, ok := byIdentity[key]
		if !ok {
			return errors.New("[D131 Android] persisted selection 不属于当前已验 catalog")
		}
		raw, err := dialer.network.ResolveHost(candidate.serverName)
		if err != nil {
			return err
		}
		addresses, err := androidBootstrapResolvedAddresses(raw, candidate.addressFamilies)
		if err != nil {
			return err
		}
		for _, address := range addresses {
			viable = append(viable, androidBootstrapProbeResult{
				androidBootstrapProbeTarget: androidBootstrapProbeTarget{candidate: candidate, address: address},
				rtt:                         time.Duration(selection.ProbeRTTMillis) * time.Millisecond,
			})
		}
	}
	dialer.probed, dialer.viable = true, viable
	return nil
}

func (result androidBootstrapProbeResult) selection() androidBootstrapSelection {
	millis := result.rtt.Milliseconds()
	if millis < 1 {
		millis = 1
	}
	return androidBootstrapSelection{
		Schema: 1, EndpointID: result.candidate.endpointID, Transport: result.candidate.transport,
		ListenerGeneration: result.candidate.listenerGeneration, ProbeRTTMillis: millis,
	}
}

func (dialer *androidBootstrapDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != dialer.destination {
		return nil, errors.New("[D131 Android] bootstrap tunnel 只允许 exact Enrollment TCP tuple")
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	now := time.Unix(0, dialer.trustedNow.Load()).UTC()
	if err := dialer.validAt(now); err != nil {
		return nil, err
	}
	if !dialer.probed || len(dialer.viable) == 0 {
		return nil, errors.New("[D131 Android] capability 出示前尚未完成 transport probe")
	}
	if dialer.active != nil {
		return nil, errors.New("[D131 Android] bootstrap capability 只允许一个并发 session")
	}
	for _, target := range dialer.viable {
		if dialer.attempts >= dialer.maximumAttempts {
			break
		}
		dialer.attempts++
		if err := dialer.network.RecordConnectionAttempt(dialer.capabilityID, dialer.attempts); err != nil {
			return nil, fmt.Errorf("[D131 Android] bootstrap attempt journal 拒绝拨号: %w", err)
		}
		attemptContext, cancel := context.WithTimeout(ctx, dialer.timeout)
		var connection net.Conn
		var err error
		if target.candidate.transport == "hysteria2" {
			connection, err = dialer.dialHysteria2(attemptContext, target, now)
		} else {
			connection, err = dialer.dialTrojan(attemptContext, target, now)
		}
		cancel()
		if err != nil {
			continue
		}
		limited := &androidBootstrapLimitedConn{
			Conn: connection, deadline: time.Now().Add(dialer.maximumSession),
			maximumTotal: dialer.maximumTotalBytes, total: &dialer.totalBytes,
			onClose: func() {
				dialer.mu.Lock()
				dialer.active = nil
				dialer.mu.Unlock()
			},
		}
		if err := limited.SetDeadline(limited.deadline); err != nil {
			_ = connection.Close()
			return nil, err
		}
		dialer.active = limited
		return limited, nil
	}
	return nil, errors.New("[D131 Android] capability attempt 预算内没有可用 HY2/Trojan ingress")
}

func (dialer *androidBootstrapDialer) connectionAttempts() int64 {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return dialer.attempts
}

func (dialer *androidBootstrapDialer) closeActive() {
	dialer.mu.Lock()
	active := dialer.active
	dialer.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
}

func (dialer *androidBootstrapDialer) validAt(now time.Time) error {
	if now.IsZero() || now.Before(dialer.notBefore) || !now.Before(dialer.expiresAt) {
		return errors.New("[D131 Android] bootstrap capability 已过期或尚未生效")
	}
	return nil
}

func (dialer *androidBootstrapDialer) resolveTargets() ([]androidBootstrapProbeTarget, error) {
	var targets []androidBootstrapProbeTarget
	seen := make(map[string]struct{})
	for _, candidate := range dialer.candidates {
		raw, err := dialer.network.ResolveHost(candidate.serverName)
		if err != nil {
			continue
		}
		addresses, err := androidBootstrapResolvedAddresses(raw, candidate.addressFamilies)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			key := candidate.endpointID + "\x00" + strconv.FormatInt(candidate.listenerGeneration, 10) + "\x00" + address.String()
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, androidBootstrapProbeTarget{candidate: candidate, address: address})
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("[D131 Android] bootstrap FQDN 没有经冻结 underlay 得到授权地址")
	}
	return targets, nil
}

func (dialer *androidBootstrapDialer) probeTarget(ctx context.Context,
	target androidBootstrapProbeTarget, now time.Time,
) error {
	if target.candidate.transport == "hysteria2" {
		connection, packet, err := dialer.openQUIC(ctx, target, now)
		if err != nil {
			return err
		}
		_ = connection.CloseWithError(0, "")
		return packet.Close()
	}
	raw, err := dialer.openTCP(ctx, target)
	if err != nil {
		return err
	}
	defer raw.Close()
	connection := tls.Client(raw, androidBootstrapOuterTLS(target.candidate, dialer.roots, now, false))
	return connection.HandshakeContext(ctx)
}

func (dialer *androidBootstrapDialer) dialTrojan(ctx context.Context,
	target androidBootstrapProbeResult, now time.Time,
) (net.Conn, error) {
	raw, err := dialer.openTCP(ctx, target.androidBootstrapProbeTarget)
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, androidBootstrapOuterTLS(target.candidate, dialer.roots, now, false))
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	request, err := androidTrojanBootstrapRequest(dialer.credential, dialer.destination)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := androidBootstrapWriteFull(connection, request); err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}

func (dialer *androidBootstrapDialer) dialHysteria2(ctx context.Context,
	target androidBootstrapProbeResult, now time.Time,
) (net.Conn, error) {
	connection, packet, err := dialer.openQUIC(ctx, target.androidBootstrapProbeTarget, now)
	if err != nil {
		return nil, err
	}
	tlsConfig := androidBootstrapOuterTLS(target.candidate, dialer.roots, now, true)
	config := androidBootstrapQUICConfig(dialer.timeout)
	transport := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: config,
		EnableDatagrams: false, DisableCompression: true, MaxResponseHeaderBytes: 8 << 10}
	client := transport.NewClientConn(connection)
	request := &http.Request{Method: http.MethodPost,
		URL: &url.URL{Scheme: "https", Host: androidBootstrapHysteriaAuthHost,
			Path: androidBootstrapHysteriaAuthPath}, Header: make(http.Header), Body: http.NoBody}
	request.Header.Set(androidBootstrapHysteriaAuthHeader, dialer.credential)
	response, err := client.RoundTrip(request.WithContext(ctx))
	if err != nil {
		_ = connection.CloseWithError(0, "")
		_ = packet.Close()
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != androidBootstrapHysteriaAuthOK || response.Header.Get("Hysteria-UDP") != "false" {
		_ = connection.CloseWithError(0, "")
		_ = packet.Close()
		return nil, errors.New("[D131 Android] Hysteria2 capability auth 失败")
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		_ = connection.CloseWithError(0, "")
		_ = packet.Close()
		return nil, err
	}
	return &androidHysteria2TunnelConn{Stream: stream, connection: connection,
		packet: packet, destination: dialer.destination}, nil
}

func (dialer *androidBootstrapDialer) openTCP(ctx context.Context,
	target androidBootstrapProbeTarget,
) (net.Conn, error) {
	network := "tcp6"
	if target.address.Is4() {
		network = "tcp4"
	}
	address := net.JoinHostPort(target.address.String(), strconv.Itoa(int(target.candidate.publicPort)))
	netDialer := &net.Dialer{Timeout: dialer.timeout, KeepAlive: 30 * time.Second,
		Control: dialer.socketControl}
	return netDialer.DialContext(ctx, network, address)
}

func (dialer *androidBootstrapDialer) openQUIC(ctx context.Context,
	target androidBootstrapProbeTarget, now time.Time,
) (quic.Connection, net.PacketConn, error) {
	network, local := "udp6", "[::]:0"
	if target.address.Is4() {
		network, local = "udp4", "0.0.0.0:0"
	}
	packet, err := (&net.ListenConfig{Control: dialer.socketControl}).ListenPacket(ctx, network, local)
	if err != nil {
		return nil, nil, err
	}
	remote := &net.UDPAddr{IP: net.IP(target.address.AsSlice()), Port: int(target.candidate.publicPort)}
	connection, err := quic.Dial(ctx, packet, remote,
		androidBootstrapOuterTLS(target.candidate, dialer.roots, now, true),
		androidBootstrapQUICConfig(dialer.timeout))
	if err != nil {
		_ = packet.Close()
		return nil, nil, err
	}
	return connection, packet, nil
}

func (dialer *androidBootstrapDialer) socketControl(_, _ string, raw syscall.RawConn) error {
	var callbackErr error
	if err := raw.Control(func(fd uintptr) {
		callbackErr = dialer.network.ProtectAndBindSocket(int64(fd))
	}); err != nil {
		return err
	}
	return callbackErr
}

func androidBootstrapOuterTLS(candidate androidBootstrapCandidate, roots *x509.CertPool,
	now time.Time, h3 bool,
) *tls.Config {
	config := &tls.Config{ServerName: candidate.serverName, RootCAs: roots,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Time: func() time.Time { return now },
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("[D122 Android bootstrap] WebPKI chain 未验证")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			pin := "sha256:" + hex.EncodeToString(digest[:])
			if !androidContainsString(candidate.spkiPins, pin) {
				return errors.New("[D122 Android bootstrap] outer TLS SPKI pin 不匹配")
			}
			return nil
		},
	}
	if h3 {
		config.NextProtos = []string{http3.NextProtoH3}
	}
	return config
}

func androidBootstrapQUICConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: 2 * time.Minute,
		KeepAlivePeriod: 20 * time.Second, EnableDatagrams: false, Allow0RTT: false}
}

func androidBootstrapCandidates(catalog *wire.BootstrapEndpointCatalogV1,
	now time.Time,
) ([]androidBootstrapCandidate, error) {
	if catalog == nil {
		return nil, errors.New("[D131 Android] bootstrap catalog 不能为空")
	}
	var candidates []androidBootstrapCandidate
	for endpointIndex := range catalog.BootstrapIngressSet.Endpoints {
		endpoint := &catalog.BootstrapIngressSet.Endpoints[endpointIndex]
		for generationIndex := range endpoint.ListenerGenerations {
			generation := &endpoint.ListenerGenerations[generationIndex]
			validFrom, _ := wire.ParseTimeZ(generation.ValidFrom)
			validUntil, _ := wire.ParseTimeZ(generation.ValidUntil)
			if generation.PublishedState == "draining" || now.Before(validFrom) || !now.Before(validUntil) {
				continue
			}
			pins, err := androidBootstrapIdentityPins(generation.TransportIdentityRefs)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, androidBootstrapCandidate{
				endpointID: endpoint.EndpointID, transport: endpoint.Transport,
				listenerGeneration: generation.ListenerGeneration, hintRank: endpoint.HintRank,
				serverName: generation.DialTargetFQDN, publicPort: generation.PublicPort,
				addressFamilies: append([]string(nil), generation.AddressFamilies...),
				spkiPins:        append([]string(nil), pins...), preferred: generation.PublishedState == "preferred",
			})
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("[D131 Android] catalog 没有当前可拨 generation")
	}
	return candidates, nil
}

func androidBootstrapIdentityPins(refs []string) ([]string, error) {
	profileCount := 0
	pins := make([]string, 0, len(refs))
	for _, ref := range refs {
		if strings.HasPrefix(ref, "profile:") {
			if len(strings.TrimPrefix(ref, "profile:")) == 0 {
				return nil, errors.New("[D122 Android bootstrap] WebPKI profile ref 无效")
			}
			profileCount++
			continue
		}
		if _, err := wire.ParseHash(ref); err != nil {
			return nil, errors.New("[D122 Android bootstrap] transport identity ref 不是 SPKI pin")
		}
		pins = append(pins, ref)
	}
	if profileCount != 1 || len(pins) == 0 || len(pins) > 2 {
		return nil, errors.New("[D122 Android bootstrap] listener 必须有一个 WebPKI profile 与一至两个 SPKI pin")
	}
	return pins, nil
}

func androidBootstrapResolvedAddresses(raw string, families []string) ([]netip.Addr, error) {
	if raw == "" || len(raw) > 4096 {
		return nil, errors.New("[D131 Android] underlay resolver 返回为空或过大")
	}
	allowed := make(map[string]bool, len(families))
	for _, family := range families {
		allowed[family] = true
	}
	seen := make(map[netip.Addr]struct{})
	var addresses []netip.Addr
	for _, value := range strings.Split(raw, "\n") {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value || address.IsUnspecified() || address.IsMulticast() {
			return nil, errors.New("[D131 Android] underlay resolver 返回非规范 unicast IP")
		}
		family := "ipv6"
		if address.Is4() {
			family = "ipv4"
		}
		if !allowed[family] {
			return nil, errors.New("[D131 Android] resolved address family 未经 listener 授权")
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errors.New("[D131 Android] underlay resolver 没有可用地址")
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left].String() < addresses[right].String() })
	return addresses, nil
}

func androidBootstrapDestination(body wire.BootstrapTunnelCapabilityBodyV1) (string, error) {
	address, err := netip.ParseAddr(body.AllowedDestinationIP)
	if err != nil || address.String() != body.AllowedDestinationIP || !address.IsPrivate() ||
		body.AllowedDestinationPort < 1 || body.AllowedDestinationPort > 65535 {
		return "", errors.New("[D131 Android] capability Enrollment destination 无效")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(body.AllowedDestinationPort))), nil
}

func androidTrojanBootstrapRequest(credential, destination string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, errors.New("[D131 Android] Trojan destination 无效")
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || port == 0 {
		return nil, errors.New("[D131 Android] Trojan destination tuple 无效")
	}
	digest := sha256.Sum224([]byte(credential))
	request := make([]byte, hex.EncodedLen(len(digest))+2, 96)
	hex.Encode(request, digest[:])
	request[len(request)-2], request[len(request)-1] = '\r', '\n'
	request = append(request, 1)
	if address.Is4() {
		request = append(request, 1)
		request = append(request, address.AsSlice()...)
	} else {
		request = append(request, 4)
		request = append(request, address.AsSlice()...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return append(request, '\r', '\n'), nil
}

type androidHysteria2TunnelConn struct {
	quic.Stream
	connection     quic.Connection
	packet         net.PacketConn
	destination    string
	writeMu        sync.Mutex
	readMu         sync.Mutex
	requestWritten bool
	responseRead   bool
}

func (connection *androidHysteria2TunnelConn) Write(payload []byte) (int, error) {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.requestWritten {
		return connection.Stream.Write(payload)
	}
	if len(connection.destination) == 0 || len(connection.destination) > 2048 {
		return 0, errors.New("[D131 Android] Hysteria2 destination 长度无效")
	}
	var request []byte
	request = quicvarint.Append(request, androidBootstrapHysteriaTCPFrame)
	request = quicvarint.Append(request, uint64(len(connection.destination)))
	request = append(request, connection.destination...)
	request = quicvarint.Append(request, 0)
	request = append(request, payload...)
	if err := androidBootstrapWriteFull(connection.Stream, request); err != nil {
		return 0, err
	}
	connection.requestWritten = true
	return len(payload), nil
}

func (connection *androidHysteria2TunnelConn) Read(payload []byte) (int, error) {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	if !connection.responseRead {
		if err := androidReadHysteria2Response(connection.Stream); err != nil {
			return 0, err
		}
		connection.responseRead = true
	}
	return connection.Stream.Read(payload)
}

func (connection *androidHysteria2TunnelConn) Close() error {
	connection.Stream.CancelRead(0)
	streamErr := connection.Stream.Close()
	outerErr := connection.connection.CloseWithError(0, "")
	packetErr := connection.packet.Close()
	if streamErr != nil {
		return streamErr
	}
	if outerErr != nil {
		return outerErr
	}
	return packetErr
}

func (connection *androidHysteria2TunnelConn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *androidHysteria2TunnelConn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func androidReadHysteria2Response(reader io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil || status[0] != 0 {
		return errors.New("[D131 Android] Hysteria2 TCP relay 被拒绝")
	}
	variableReader := quicvarint.NewReader(reader)
	messageLength, err := quicvarint.Read(variableReader)
	if err != nil || messageLength > androidBootstrapMaximumMessage {
		return errors.New("[D131 Android] Hysteria2 response message 无效")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(messageLength)); err != nil {
		return err
	}
	paddingLength, err := quicvarint.Read(variableReader)
	if err != nil || paddingLength > androidBootstrapMaximumPadding {
		return errors.New("[D131 Android] Hysteria2 response padding 无效")
	}
	_, err = io.CopyN(io.Discard, reader, int64(paddingLength))
	return err
}

func androidBootstrapWriteFull(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written < 1 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

type androidBootstrapLimitedConn struct {
	net.Conn
	deadline     time.Time
	maximumTotal int64
	total        *atomic.Int64
	onClose      func()
	closeOnce    sync.Once
}

func (connection *androidBootstrapLimitedConn) Read(body []byte) (int, error) {
	count, err := connection.Conn.Read(body)
	if count > 0 && connection.total.Add(int64(count)) > connection.maximumTotal {
		_ = connection.Close()
		return 0, errors.New("[D131 Android] bootstrap capability total byte budget 已耗尽")
	}
	return count, err
}

func (connection *androidBootstrapLimitedConn) Write(body []byte) (int, error) {
	if int64(len(body))+connection.total.Load() > connection.maximumTotal {
		_ = connection.Close()
		return 0, errors.New("[D131 Android] bootstrap capability total byte budget 已耗尽")
	}
	count, err := connection.Conn.Write(body)
	if count > 0 {
		connection.total.Add(int64(count))
	}
	return count, err
}

func (connection *androidBootstrapLimitedConn) Close() error {
	err := connection.Conn.Close()
	connection.closeOnce.Do(connection.onClose)
	return err
}

func newAndroidPrivateEnrollmentHTTP(dialer *androidBootstrapDialer,
	ref wire.PrivateEnrollmentServiceRefV1, now func() time.Time,
) (*http.Transport, *http.Client, string, error) {
	if err := wire.ValidatePrivateEnrollmentServiceRef(&ref); err != nil {
		return nil, nil, "", err
	}
	expectedAddress := net.JoinHostPort(ref.OverlayIP, strconv.FormatInt(ref.TCPPort, 10))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: ref.OverlayIP, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyAndroidPrivateEnrollmentTLS(state, ref, now())
		},
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		MaxIdleConns: 1, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("[D131 Android] private Enrollment dial 超出 exact overlay tuple")
			}
			raw, err := dialer.DialContext(ctx, "tcp", expectedAddress)
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
	baseURL := (&url.URL{Scheme: "https", Host: expectedAddress}).String()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[D131 Android] private Enrollment 禁止 redirect")
		}}
	return transport, client, baseURL, nil
}

func verifyAndroidPrivateEnrollmentTLS(state tls.ConnectionState,
	ref wire.PrivateEnrollmentServiceRefV1, trustedTime time.Time,
) error {
	if trustedTime.IsZero() || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return errors.New("[D131 Android] private Enrollment TLS version/certificate/可信时间无效")
	}
	leaf := state.PeerCertificates[0]
	instant := trustedTime.UTC()
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || instant.Before(leaf.NotBefore) ||
		!instant.Before(leaf.NotAfter) || leaf.VerifyHostname(ref.OverlayIP) != nil ||
		len(leaf.UnhandledCriticalExtensions) != 0 ||
		!androidContainsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("[D131 Android] Enrollment leaf role/validity/overlay IP SAN 无效")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	if !androidContainsString(ref.ServerIdentitySPKIPins, pin) {
		return errors.New("[D131 Android] Enrollment leaf SPKI 不在 certified pin set")
	}
	return nil
}

func mustAndroidBootstrapTime(raw string) time.Time {
	parsed, _ := wire.ParseTimeZ(raw)
	return parsed
}

func androidContainsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func androidContainsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func androidContainsExtKeyUsage(values []x509.ExtKeyUsage, value x509.ExtKeyUsage) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

var _ net.Conn = (*androidHysteria2TunnelConn)(nil)
var _ net.Conn = (*androidBootstrapLimitedConn)(nil)
