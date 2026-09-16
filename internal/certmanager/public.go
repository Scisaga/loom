package certmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"loom/internal/wire"
)

const (
	domainPublicCertificateChain = "loom-public-certificate-chain-pem-v1"
	domainPublicCertificateLeaf  = "loom-public-certificate-leaf-der-v1"
)

type ChallengePresentationV1 struct {
	Schema           int    `json:"schema"`
	AuthorizationURL string `json:"authorization_url"`
	ChallengeURL     string `json:"challenge_url"`
	FQDN             string `json:"fqdn"`
	Value            string `json:"value"`
}

type PendingACMEOrderV1 struct {
	Schema            int                       `json:"schema"`
	Intent            wire.CertificateIntentV1  `json:"intent"`
	IntentHash        string                    `json:"intent_hash"`
	PrivateKeyPath    string                    `json:"private_key_path"`
	CSRPath           string                    `json:"csr_path"`
	OrderURL          string                    `json:"order_url"`
	OrderExpires      string                    `json:"order_expires,omitempty"`
	AuthorizationURLs []string                  `json:"authorization_urls"`
	FinalizeURL       string                    `json:"finalize_url"`
	CertificateURL    string                    `json:"certificate_url,omitempty"`
	Presentations     []ChallengePresentationV1 `json:"presentations"`
}

type CertificateGenerationV1 struct {
	Schema               int                      `json:"schema"`
	Intent               wire.CertificateIntentV1 `json:"intent"`
	IntentHash           string                   `json:"intent_hash"`
	PrivateKeyPath       string                   `json:"private_key_path"`
	CSRPath              string                   `json:"csr_path"`
	CertificatePath      string                   `json:"certificate_path"`
	CertificateChainHash string                   `json:"certificate_chain_hash"`
	LeafCertificateHash  string                   `json:"leaf_certificate_hash"`
	SPKIHash             string                   `json:"spki_hash"`
	CertificateURL       string                   `json:"certificate_url"`
	NotBefore            string                   `json:"not_before"`
	NotAfter             string                   `json:"not_after"`
	InstalledAt          string                   `json:"installed_at"`
}

// PublicCertificateStateV1 是节点本地 LKG。Previous 与两个 pin 只会由获认证的
// retirement 显式收缩，时间经过本身不会提前删掉旧 key/cert。
type PublicCertificateStateV1 struct {
	Schema                  int                      `json:"schema"`
	Active                  *CertificateGenerationV1 `json:"active,omitempty"`
	Previous                *CertificateGenerationV1 `json:"previous,omitempty"`
	PreviousRetireNotBefore string                   `json:"previous_retire_not_before,omitempty"`
	SPKIPins                []string                 `json:"spki_pins"`
	Pending                 *PendingACMEOrderV1      `json:"pending,omitempty"`
}

type CertificateRetirementAuthorizationV1 struct {
	Schema                        int    `json:"schema"`
	ClusterID                     string `json:"cluster_id"`
	ActiveCertificateIntentHash   string `json:"active_certificate_intent_hash"`
	PreviousCertificateIntentHash string `json:"previous_certificate_intent_hash"`
	CertifiedHeadHash             string `json:"certified_head_hash"`
	RetirementGuardHash           string `json:"retirement_guard_hash"`
	ReaderFloor                   int64  `json:"reader_floor"`
	RetiredAt                     string `json:"retired_at"`
}

type CertificateIntentVerifier func(*wire.CertificateIntentV1) error
type CertificateRetirementVerifier func(*CertificateRetirementAuthorizationV1) error

type PublicCertificateManagerConfig struct {
	StatePath         string
	ArtifactDirectory string
	Client            ACMEClient
	DNS01             DNS01
	Roots             *x509.CertPool
	Now               func() time.Time
	VerifyIntent      CertificateIntentVerifier
	VerifyRetirement  CertificateRetirementVerifier
}

type PublicCertificateManager struct {
	mu                sync.Mutex
	path              string
	artifactDirectory string
	client            ACMEClient
	dns01             DNS01
	roots             *x509.CertPool
	now               func() time.Time
	verifyIntent      CertificateIntentVerifier
	verifyRetirement  CertificateRetirementVerifier
	state             PublicCertificateStateV1
}

type RuntimeCertificate struct {
	TLSCertificate                 tls.Certificate
	IdentityProjectionHash         string
	CertificateIntentHash          string
	ExistingCertificateBindingHash string
	SPKIPins                       []string
}

func OpenPublicCertificateManager(config PublicCertificateManagerConfig) (*PublicCertificateManager, error) {
	if config.StatePath == "" || config.ArtifactDirectory == "" || config.Client == nil ||
		config.DNS01.Provider == nil || config.VerifyIntent == nil || config.VerifyRetirement == nil {
		return nil, errors.New("[TLS] certificate manager path/provider/authority verifier 缺失")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	statePath, err := filepath.Abs(config.StatePath)
	if err != nil {
		return nil, err
	}
	artifactDirectory, err := filepath.Abs(config.ArtifactDirectory)
	if err != nil {
		return nil, err
	}
	manager := &PublicCertificateManager{
		path: filepath.Clean(statePath), artifactDirectory: filepath.Clean(artifactDirectory), client: config.Client,
		dns01: config.DNS01, roots: config.Roots, now: config.Now,
		verifyIntent: config.VerifyIntent, verifyRetirement: config.VerifyRetirement,
		state: PublicCertificateStateV1{Schema: 1, SPKIPins: []string{}},
	}
	body, err := readRegularFile(manager.path, 4<<20, true)
	if errors.Is(err, os.ErrNotExist) {
		return manager, nil
	}
	if err != nil {
		return nil, err
	}
	var state PublicCertificateStateV1
	if _, err := wire.DecodeStrict(body, 4<<20, &state); err != nil {
		return nil, fmt.Errorf("[TLS] certificate state 损坏: %w", err)
	}
	if err := manager.validateState(&state, true); err != nil {
		return nil, err
	}
	manager.state = state
	return manager, nil
}

func (manager *PublicCertificateManager) Snapshot() PublicCertificateStateV1 {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return clonePublicCertificateState(manager.state)
}

// LoadActiveRuntimeCertificate 从已核验 LKG 读取 listener 可用的 key pair 与
// exact projection/pins；pending certificate 永远不会进入运行时。
func (manager *PublicCertificateManager) LoadActiveRuntimeCertificate() (RuntimeCertificate, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.state.Active == nil {
		return RuntimeCertificate{}, errors.New("[TLS] 尚无 active public certificate")
	}
	if err := manager.validateState(&manager.state, true); err != nil {
		return RuntimeCertificate{}, err
	}
	certificatePEM, err := readRegularFile(manager.state.Active.CertificatePath, 1<<20, false)
	if err != nil {
		return RuntimeCertificate{}, err
	}
	privateKeyPEM, err := readRegularFile(manager.state.Active.PrivateKeyPath, 64<<10, true)
	if err != nil {
		return RuntimeCertificate{}, err
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return RuntimeCertificate{}, fmt.Errorf("[TLS] active certificate/key pair 无法加载: %w", err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return RuntimeCertificate{}, err
	}
	return RuntimeCertificate{
		TLSCertificate: pair, IdentityProjectionHash: manager.state.Active.Intent.IdentityProjectionHash,
		CertificateIntentHash: manager.state.Active.IntentHash,
		SPKIPins:              append([]string(nil), manager.state.SPKIPins...),
	}, nil
}

// Reconcile 只执行调用方已经验证为 certified 的 exact intent。任何 provider、
// challenge、签发或本地写入失败都保留 Active/Previous LKG。
func (manager *PublicCertificateManager) Reconcile(ctx context.Context, intent wire.CertificateIntentV1,
	privateKeyPath string) (PublicCertificateStateV1, error) {
	if err := wire.ValidateCertificateIntent(&intent); err != nil {
		return PublicCertificateStateV1{}, err
	}
	if err := manager.verifyIntent(&intent); err != nil {
		return PublicCertificateStateV1{}, fmt.Errorf("[TLS] certificate intent 未获 certified authority: %w", err)
	}
	intentHash, _ := wire.CertificateIntentHash(&intent)
	privateKeyPath, err := filepath.Abs(privateKeyPath)
	if err != nil {
		return PublicCertificateStateV1{}, err
	}
	privateKeyPath = filepath.Clean(privateKeyPath)
	identity, err := loadExistingIdentity(privateKeyPath, intent.IdentityProjection.DNSNames)
	if err != nil {
		return PublicCertificateStateV1{}, err
	}
	if err := validateIdentityIntent(identity, &intent); err != nil {
		return PublicCertificateStateV1{}, err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.validateTransition(&intent, intentHash, identity); err != nil {
		return PublicCertificateStateV1{}, err
	}
	if manager.state.Pending == nil && manager.state.Active != nil && manager.state.Active.IntentHash == intentHash {
		return clonePublicCertificateState(manager.state), nil
	}

	var order *acme.Order
	if manager.state.Pending == nil {
		if err := manager.client.EnsureAccount(ctx); err != nil {
			return PublicCertificateStateV1{}, err
		}
		order, err = manager.client.AuthorizeOrder(ctx, intent.IdentityProjection.DNSNames)
		if err != nil {
			return PublicCertificateStateV1{}, fmt.Errorf("[ACME] 创建 order 失败: %w", err)
		}
		pending, err := newPendingOrder(intent, intentHash, identity, order)
		if err != nil {
			return PublicCertificateStateV1{}, err
		}
		candidate := clonePublicCertificateState(manager.state)
		candidate.Pending = pending
		if err := manager.persistLocked(candidate); err != nil {
			return PublicCertificateStateV1{}, err
		}
		manager.state = candidate
	} else {
		if err := manager.client.EnsureAccount(ctx); err != nil {
			return PublicCertificateStateV1{}, err
		}
		order, err = manager.client.GetOrder(ctx, manager.state.Pending.OrderURL)
		if err != nil {
			return PublicCertificateStateV1{}, fmt.Errorf("[ACME] 恢复 order 失败: %w", err)
		}
	}
	if err := manager.refreshPendingLocked(order); err != nil {
		return PublicCertificateStateV1{}, err
	}
	certificates, certificateURL, err := manager.completeOrderLocked(ctx, order)
	if err != nil {
		return PublicCertificateStateV1{}, err
	}
	return manager.installLocked(intent, intentHash, identity, certificates, certificateURL)
}

// RetirePrevious 只消费已绑定 reader floor/rotation guard 的认证结果；达到时间
// 但没有认证不能收缩 old/new pins，磁盘 artifact 仍留给 backup retention。
func (manager *PublicCertificateManager) RetirePrevious(authorization CertificateRetirementAuthorizationV1) (PublicCertificateStateV1, error) {
	if err := validateRetirementAuthorization(&authorization); err != nil {
		return PublicCertificateStateV1{}, err
	}
	if err := manager.verifyRetirement(&authorization); err != nil {
		return PublicCertificateStateV1{}, fmt.Errorf("[TLS] certificate retirement 未获 reader-floor authority: %w", err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.state.Active == nil || manager.state.Previous == nil || manager.state.Pending != nil {
		return PublicCertificateStateV1{}, errors.New("[TLS] 当前没有可退役的稳定 certificate overlap")
	}
	if authorization.ClusterID != manager.state.Active.Intent.IdentityProjection.ClusterID ||
		authorization.ActiveCertificateIntentHash != manager.state.Active.IntentHash ||
		authorization.PreviousCertificateIntentHash != manager.state.Previous.IntentHash {
		return PublicCertificateStateV1{}, errors.New("[TLS] retirement 未绑定 exact active/previous certificate")
	}
	retiredAt, _ := wire.ParseTimeZ(authorization.RetiredAt)
	notBefore, _ := wire.ParseTimeZ(manager.state.PreviousRetireNotBefore)
	if retiredAt.Before(notBefore) || retiredAt.After(manager.now().UTC()) {
		return PublicCertificateStateV1{}, errors.New("[TLS] certificate overlap 最短窗口尚未结束")
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Previous = nil
	candidate.PreviousRetireNotBefore = ""
	candidate.SPKIPins = []string{candidate.Active.SPKIHash}
	if err := manager.persistLocked(candidate); err != nil {
		return PublicCertificateStateV1{}, err
	}
	manager.state = candidate
	return clonePublicCertificateState(candidate), nil
}

func (manager *PublicCertificateManager) validateTransition(intent *wire.CertificateIntentV1, intentHash string, identity LocalIdentity) error {
	if manager.state.Pending != nil {
		if manager.state.Pending.IntentHash != intentHash || manager.state.Pending.PrivateKeyPath != identity.PrivateKeyPath ||
			manager.state.Pending.CSRPath != identity.CSRPath {
			return errors.New("[ACME] 必须先续跑 exact pending order，禁止并发改写签发 identity")
		}
		return nil
	}
	if manager.state.Active == nil {
		return nil
	}
	active := manager.state.Active
	if active.IntentHash == intentHash {
		return nil
	}
	if manager.state.Previous != nil {
		return errors.New("[TLS] 上一代 certificate 尚未通过 reader floor 退役，禁止引入第三个 identity")
	}
	activeProjection := active.Intent.IdentityProjection
	nextProjection := intent.IdentityProjection
	if activeProjection.ClusterID != nextProjection.ClusterID || activeProjection.IntentID != nextProjection.IntentID {
		return errors.New("[TLS] certificate intent 不能接管其他 logical identity")
	}
	if intent.IdentityProjectionHash == active.Intent.IdentityProjectionHash {
		if intent.IssuanceGeneration <= active.Intent.IssuanceGeneration {
			return errors.New("[TLS] 同一 identity 的 issuance generation 必须递增")
		}
		notAfter, _ := wire.ParseTimeZ(active.NotAfter)
		renewAt := notAfter.Add(-time.Duration(active.Intent.RenewBeforeSeconds) * time.Second)
		if manager.now().UTC().Before(renewAt) {
			return errors.New("[TLS] certificate 尚未进入 certified renew window")
		}
		return nil
	}
	if nextProjection.IdentityGeneration != activeProjection.IdentityGeneration+1 ||
		!sameLogicalProjection(activeProjection, nextProjection) {
		return errors.New("[TLS] key rotation 必须只递增 identity generation 并保持 logical binding")
	}
	return nil
}

func (manager *PublicCertificateManager) completeOrderLocked(ctx context.Context, order *acme.Order) ([][]byte, string, error) {
	if order == nil {
		return nil, "", errors.New("[ACME] order 为空")
	}
	if order.Status == acme.StatusInvalid {
		return nil, "", manager.abandonPendingLocked(ctx, errors.New("[ACME] order 已 invalid"))
	}
	if order.Status == acme.StatusPending {
		for _, authorizationURL := range manager.state.Pending.AuthorizationURLs {
			authorization, err := manager.client.GetAuthorization(ctx, authorizationURL)
			if err != nil {
				return nil, "", fmt.Errorf("[ACME] 读取 authorization 失败: %w", err)
			}
			if err := manager.completeAuthorizationLocked(ctx, authorizationURL, authorization); err != nil {
				return nil, "", err
			}
		}
		var err error
		order, err = manager.client.WaitOrder(ctx, manager.state.Pending.OrderURL)
		if err != nil {
			return nil, "", fmt.Errorf("[ACME] 等待 order ready 失败: %w", err)
		}
		if err := manager.refreshPendingLocked(order); err != nil {
			return nil, "", err
		}
	}
	if order.Status == acme.StatusProcessing {
		var err error
		order, err = manager.client.WaitOrder(ctx, manager.state.Pending.OrderURL)
		if err != nil {
			return nil, "", fmt.Errorf("[ACME] 等待 order issuance 失败: %w", err)
		}
		if err := manager.refreshPendingLocked(order); err != nil {
			return nil, "", err
		}
	}
	if order.Status == acme.StatusReady {
		csrDER, _ := base64.RawURLEncoding.DecodeString(manager.state.Pending.Intent.CSRDER)
		certificates, certificateURL, err := manager.client.CreateOrderCert(ctx, manager.state.Pending.FinalizeURL, csrDER, true)
		if err != nil {
			return nil, "", fmt.Errorf("[ACME] finalize order 失败: %w", err)
		}
		if !validHTTPSResourceURL(certificateURL) {
			return nil, "", errors.New("[ACME] certificate URL 无效")
		}
		return certificates, certificateURL, nil
	}
	if order.Status == acme.StatusValid {
		certificateURL := order.CertURL
		if certificateURL == "" {
			certificateURL = manager.state.Pending.CertificateURL
		}
		if !validHTTPSResourceURL(certificateURL) {
			return nil, "", errors.New("[ACME] valid order 缺 certificate URL")
		}
		certificates, err := manager.client.FetchCert(ctx, certificateURL, true)
		if err != nil {
			return nil, "", fmt.Errorf("[ACME] 获取已签发 certificate 失败: %w", err)
		}
		return certificates, certificateURL, nil
	}
	return nil, "", fmt.Errorf("[ACME] order 状态 %q 不能签发", order.Status)
}

func (manager *PublicCertificateManager) completeAuthorizationLocked(ctx context.Context, authorizationURL string,
	authorization *acme.Authorization) error {
	if err := validateAuthorizationForIntent(authorizationURL, authorization, &manager.state.Pending.Intent); err != nil {
		return err
	}
	if authorization.Status == acme.StatusValid {
		return manager.cleanupPresentationLocked(ctx, authorizationURL)
	}
	if authorization.Status != acme.StatusPending {
		if err := manager.cleanupPresentationLocked(ctx, authorizationURL); err != nil {
			return err
		}
		return manager.abandonPendingLocked(ctx, fmt.Errorf("[ACME] authorization 状态 %q 不能继续", authorization.Status))
	}
	challenge, err := exactDNS01Challenge(authorization)
	if err != nil {
		return err
	}
	value, err := manager.client.DNS01ChallengeRecord(challenge.Token)
	if err != nil || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("[ACME] DNS-01 challenge record 无效")
	}
	presentation := ChallengePresentationV1{
		Schema: 1, AuthorizationURL: authorizationURL, ChallengeURL: challenge.URI,
		FQDN: authorization.Identifier.Value, Value: value,
	}
	if err := manager.rememberPresentationLocked(presentation); err != nil {
		return err
	}
	if err := manager.dns01.Present(ctx, presentation.FQDN, presentation.Value); err != nil {
		return fmt.Errorf("[ACME] 发布 DNS-01 TXT 失败: %w", err)
	}
	if challenge.Status == "" || challenge.Status == acme.StatusPending {
		if _, err := manager.client.Accept(ctx, challenge); err != nil {
			return fmt.Errorf("[ACME] 接受 DNS-01 challenge 失败: %w", err)
		}
	} else if challenge.Status != acme.StatusProcessing && challenge.Status != acme.StatusValid {
		return fmt.Errorf("[ACME] DNS-01 challenge 状态 %q 不能继续", challenge.Status)
	}
	completed, err := manager.client.WaitAuthorization(ctx, authorizationURL)
	if err != nil {
		return fmt.Errorf("[ACME] 等待 DNS-01 authorization 失败: %w", err)
	}
	if err := validateAuthorizationForIntent(authorizationURL, completed, &manager.state.Pending.Intent); err != nil || completed.Status != acme.StatusValid {
		return errors.New("[ACME] DNS-01 authorization 未达到 valid")
	}
	return manager.cleanupPresentationLocked(ctx, authorizationURL)
}

func (manager *PublicCertificateManager) rememberPresentationLocked(presentation ChallengePresentationV1) error {
	for _, existing := range manager.state.Pending.Presentations {
		if existing.AuthorizationURL == presentation.AuthorizationURL {
			if existing != presentation {
				return errors.New("[ACME] 同一 authorization 的 challenge bytes 发生变化")
			}
			return nil
		}
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Pending.Presentations = append(candidate.Pending.Presentations, presentation)
	sort.Slice(candidate.Pending.Presentations, func(left, right int) bool {
		return candidate.Pending.Presentations[left].AuthorizationURL < candidate.Pending.Presentations[right].AuthorizationURL
	})
	if err := manager.persistLocked(candidate); err != nil {
		return err
	}
	manager.state = candidate
	return nil
}

func (manager *PublicCertificateManager) cleanupPresentationLocked(ctx context.Context, authorizationURL string) error {
	index := -1
	for candidate, presentation := range manager.state.Pending.Presentations {
		if presentation.AuthorizationURL == authorizationURL {
			index = candidate
			if err := manager.dns01.Cleanup(ctx, presentation.FQDN, presentation.Value); err != nil {
				return fmt.Errorf("[ACME] 清理 DNS-01 TXT 失败: %w", err)
			}
			break
		}
	}
	if index < 0 {
		return nil
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Pending.Presentations = append(candidate.Pending.Presentations[:index], candidate.Pending.Presentations[index+1:]...)
	if err := manager.persistLocked(candidate); err != nil {
		return err
	}
	manager.state = candidate
	return nil
}

func (manager *PublicCertificateManager) abandonPendingLocked(ctx context.Context, reason error) error {
	for len(manager.state.Pending.Presentations) > 0 {
		if err := manager.cleanupPresentationLocked(ctx, manager.state.Pending.Presentations[0].AuthorizationURL); err != nil {
			return errors.Join(reason, err)
		}
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Pending = nil
	if err := manager.persistLocked(candidate); err != nil {
		return errors.Join(reason, err)
	}
	manager.state = candidate
	return reason
}

func (manager *PublicCertificateManager) refreshPendingLocked(order *acme.Order) error {
	if manager.state.Pending == nil {
		return errors.New("[ACME] pending order 缺失")
	}
	if err := validateOrderForPending(order, manager.state.Pending); err != nil {
		return err
	}
	if order.CertURL == "" || order.CertURL == manager.state.Pending.CertificateURL {
		return nil
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Pending.CertificateURL = order.CertURL
	if err := manager.persistLocked(candidate); err != nil {
		return err
	}
	manager.state = candidate
	return nil
}

func (manager *PublicCertificateManager) installLocked(intent wire.CertificateIntentV1, intentHash string,
	identity LocalIdentity, certificates [][]byte, certificateURL string) (PublicCertificateStateV1, error) {
	now := manager.now().UTC().Truncate(time.Second)
	certificatePEM, leaf, err := validateIssuedChain(certificates, &intent, manager.roots, now)
	if err != nil {
		return PublicCertificateStateV1{}, err
	}
	chainHash, _ := wire.HashBytes(domainPublicCertificateChain, certificatePEM)
	leafHash, _ := wire.HashBytes(domainPublicCertificateLeaf, leaf.Raw)
	certificatePath := filepath.Join(manager.artifactDirectory, "certificate-"+strings.TrimPrefix(intentHash, "sha256:")+".pem")
	if err := saveAtomic(certificatePath, certificatePEM, 0o644); err != nil {
		return PublicCertificateStateV1{}, err
	}
	generation := &CertificateGenerationV1{
		Schema: 1, Intent: intent, IntentHash: intentHash,
		PrivateKeyPath: identity.PrivateKeyPath, CSRPath: identity.CSRPath, CertificatePath: certificatePath,
		CertificateChainHash: chainHash, LeafCertificateHash: leafHash,
		SPKIHash: intent.IdentityProjection.SPKIHash, CertificateURL: certificateURL,
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339), NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		InstalledAt: now.Format(time.RFC3339),
	}
	candidate := clonePublicCertificateState(manager.state)
	candidate.Pending = nil
	if candidate.Active != nil {
		candidate.Previous = candidate.Active
		candidate.PreviousRetireNotBefore = now.Add(time.Duration(intent.SPKIOverlapSeconds) * time.Second).Format(time.RFC3339)
	}
	candidate.Active = generation
	candidate.SPKIPins = certificatePins(candidate.Active, candidate.Previous)
	if err := manager.persistLocked(candidate); err != nil {
		return PublicCertificateStateV1{}, err
	}
	manager.state = candidate
	return clonePublicCertificateState(candidate), nil
}

func (manager *PublicCertificateManager) persistLocked(state PublicCertificateStateV1) error {
	if err := manager.validateState(&state, false); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	return saveAtomic(manager.path, body, 0o600)
}

func (manager *PublicCertificateManager) validateState(state *PublicCertificateStateV1, inspectArtifacts bool) error {
	if state == nil || state.Schema != 1 || state.SPKIPins == nil || state.Active == nil && state.Previous != nil ||
		(state.Previous == nil) != (state.PreviousRetireNotBefore == "") {
		return errors.New("[TLS] certificate state shape 无效")
	}
	if state.Active == nil && len(state.SPKIPins) != 0 || state.Active != nil && !equalStringSlices(state.SPKIPins, certificatePins(state.Active, state.Previous)) {
		return errors.New("[TLS] certificate state SPKI pins 不是 active/previous 的 exact projection")
	}
	for _, generation := range []*CertificateGenerationV1{state.Active, state.Previous} {
		if generation == nil {
			continue
		}
		if err := validateCertificateGeneration(generation); err != nil {
			return err
		}
		if !pathWithinDirectory(manager.artifactDirectory, generation.CertificatePath) {
			return errors.New("[TLS] certificate artifact path 离开受控目录")
		}
		if inspectArtifacts {
			if err := manager.inspectGenerationArtifacts(generation); err != nil {
				return err
			}
		}
	}
	if state.Previous != nil {
		deadline, err := wire.ParseTimeZ(state.PreviousRetireNotBefore)
		if err != nil {
			return err
		}
		installedAt, _ := wire.ParseTimeZ(state.Active.InstalledAt)
		wantDeadline := installedAt.Add(time.Duration(state.Active.Intent.SPKIOverlapSeconds) * time.Second)
		if !deadline.Equal(wantDeadline) {
			return errors.New("[TLS] certificate overlap deadline 与 active intent 不匹配")
		}
		if state.Active.IntentHash == state.Previous.IntentHash ||
			!validIntentSuccessor(&state.Previous.Intent, &state.Active.Intent) {
			return errors.New("[TLS] certificate overlap generations 无效")
		}
	}
	if state.Pending != nil {
		if err := validatePendingOrder(state.Pending); err != nil {
			return err
		}
		if state.Previous != nil || state.Active != nil && !validIntentSuccessor(&state.Active.Intent, &state.Pending.Intent) {
			return errors.New("[TLS] pending order 不是 active certificate 的唯一 successor")
		}
		if inspectArtifacts {
			identity, err := loadExistingIdentity(state.Pending.PrivateKeyPath, state.Pending.Intent.IdentityProjection.DNSNames)
			if err != nil {
				return err
			}
			if err := validateIdentityIntent(identity, &state.Pending.Intent); err != nil {
				return err
			}
		}
	}
	return nil
}

func (manager *PublicCertificateManager) inspectGenerationArtifacts(generation *CertificateGenerationV1) error {
	identity, err := loadExistingIdentity(generation.PrivateKeyPath, generation.Intent.IdentityProjection.DNSNames)
	if err != nil {
		return err
	}
	if err := validateIdentityIntent(identity, &generation.Intent); err != nil {
		return err
	}
	body, err := readRegularFile(generation.CertificatePath, 1<<20, false)
	if err != nil {
		return err
	}
	chainHash, _ := wire.HashBytes(domainPublicCertificateChain, body)
	if chainHash != generation.CertificateChainHash {
		return errors.New("[TLS] certificate artifact hash 与 state 不匹配")
	}
	certificates, err := decodeCertificatePEM(body)
	if err != nil {
		return err
	}
	installedAt, _ := wire.ParseTimeZ(generation.InstalledAt)
	_, leaf, err := validateIssuedChain(certificates, &generation.Intent, manager.roots, installedAt)
	if err != nil {
		return err
	}
	leafHash, _ := wire.HashBytes(domainPublicCertificateLeaf, leaf.Raw)
	if leafHash != generation.LeafCertificateHash || leaf.NotBefore.UTC().Format(time.RFC3339) != generation.NotBefore ||
		leaf.NotAfter.UTC().Format(time.RFC3339) != generation.NotAfter {
		return errors.New("[TLS] certificate artifact metadata 与 state 不匹配")
	}
	return nil
}

func newPendingOrder(intent wire.CertificateIntentV1, intentHash string, identity LocalIdentity,
	order *acme.Order) (*PendingACMEOrderV1, error) {
	if err := validateNewOrder(order, intent.IdentityProjection.DNSNames); err != nil {
		return nil, err
	}
	authorizationURLs := append([]string(nil), order.AuthzURLs...)
	sort.Strings(authorizationURLs)
	expires := ""
	if !order.Expires.IsZero() {
		expires = order.Expires.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	return &PendingACMEOrderV1{
		Schema: 1, Intent: intent, IntentHash: intentHash,
		PrivateKeyPath: identity.PrivateKeyPath, CSRPath: identity.CSRPath,
		OrderURL: order.URI, OrderExpires: expires, AuthorizationURLs: authorizationURLs,
		FinalizeURL: order.FinalizeURL, CertificateURL: order.CertURL,
		Presentations: []ChallengePresentationV1{},
	}, nil
}

func validatePendingOrder(pending *PendingACMEOrderV1) error {
	if pending == nil || pending.Schema != 1 || pending.AuthorizationURLs == nil || pending.Presentations == nil ||
		pending.PrivateKeyPath == "" || pending.CSRPath != pending.PrivateKeyPath+".csr" ||
		!validHTTPSResourceURL(pending.OrderURL) || !validHTTPSResourceURL(pending.FinalizeURL) ||
		len(pending.AuthorizationURLs) == 0 || !sortedUniqueStrings(pending.AuthorizationURLs) {
		return errors.New("[ACME] pending order shape 无效")
	}
	if err := wire.ValidateCertificateIntent(&pending.Intent); err != nil {
		return err
	}
	hash, _ := wire.CertificateIntentHash(&pending.Intent)
	if hash != pending.IntentHash {
		return errors.New("[ACME] pending order intent hash 不匹配")
	}
	if pending.OrderExpires != "" {
		if _, err := wire.ParseTimeZ(pending.OrderExpires); err != nil {
			return err
		}
	}
	if pending.CertificateURL != "" && !validHTTPSResourceURL(pending.CertificateURL) {
		return errors.New("[ACME] pending certificate URL 无效")
	}
	for index, presentation := range pending.Presentations {
		if presentation.Schema != 1 || !wire.ValidFQDN(presentation.FQDN) || strings.TrimSpace(presentation.Value) == "" ||
			strings.ContainsAny(presentation.Value, "\r\n") || !validHTTPSResourceURL(presentation.AuthorizationURL) ||
			!validHTTPSResourceURL(presentation.ChallengeURL) ||
			!containsString(pending.AuthorizationURLs, presentation.AuthorizationURL) ||
			index > 0 && pending.Presentations[index-1].AuthorizationURL >= presentation.AuthorizationURL {
			return errors.New("[ACME] pending DNS-01 presentation 无效/未排序")
		}
	}
	return nil
}

func validateNewOrder(order *acme.Order, names []string) error {
	if order == nil || !validHTTPSResourceURL(order.URI) || !validHTTPSResourceURL(order.FinalizeURL) ||
		len(order.AuthzURLs) == 0 || !oneOfStatus(order.Status, acme.StatusPending, acme.StatusReady, acme.StatusProcessing, acme.StatusValid, acme.StatusInvalid) {
		return errors.New("[ACME] CA 返回的 order shape/status 无效")
	}
	if order.CertURL != "" && !validHTTPSResourceURL(order.CertURL) {
		return errors.New("[ACME] CA 返回的 certificate URL 无效")
	}
	if len(order.Identifiers) != len(names) {
		return errors.New("[ACME] order identifiers 与 certificate intent 不一致")
	}
	for index, identifier := range order.Identifiers {
		if identifier.Type != "dns" || identifier.Value != names[index] {
			return errors.New("[ACME] order identifiers 与 certificate intent 不一致")
		}
	}
	for _, resourceURL := range order.AuthzURLs {
		if !validHTTPSResourceURL(resourceURL) {
			return errors.New("[ACME] order authorization URL 无效")
		}
	}
	return nil
}

func validateOrderForPending(order *acme.Order, pending *PendingACMEOrderV1) error {
	if err := validateNewOrder(order, pending.Intent.IdentityProjection.DNSNames); err != nil {
		return err
	}
	authorizationURLs := append([]string(nil), order.AuthzURLs...)
	sort.Strings(authorizationURLs)
	if order.URI != pending.OrderURL || order.FinalizeURL != pending.FinalizeURL ||
		!equalStringSlices(authorizationURLs, pending.AuthorizationURLs) ||
		pending.CertificateURL != "" && order.CertURL != "" && pending.CertificateURL != order.CertURL {
		return errors.New("[ACME] provider 改写了 pending order immutable bytes")
	}
	return nil
}

func validateAuthorizationForIntent(resourceURL string, authorization *acme.Authorization,
	intent *wire.CertificateIntentV1) error {
	if authorization == nil || authorization.URI != resourceURL || authorization.Identifier.Type != "dns" ||
		!containsString(intent.IdentityProjection.DNSNames, authorization.Identifier.Value) || authorization.Wildcard ||
		!oneOfStatus(authorization.Status, acme.StatusPending, acme.StatusValid, acme.StatusInvalid,
			acme.StatusDeactivated, acme.StatusExpired, acme.StatusRevoked) {
		return errors.New("[ACME] authorization 与 exact certificate identity 不匹配")
	}
	return nil
}

func exactDNS01Challenge(authorization *acme.Authorization) (*acme.Challenge, error) {
	var selected *acme.Challenge
	for _, challenge := range authorization.Challenges {
		if challenge == nil || challenge.Type != "dns-01" {
			continue
		}
		if selected != nil || challenge.Token == "" || !validHTTPSResourceURL(challenge.URI) {
			return nil, errors.New("[ACME] authorization 必须恰有一个有效 DNS-01 challenge")
		}
		copyChallenge := *challenge
		selected = &copyChallenge
	}
	if selected == nil {
		return nil, errors.New("[ACME] authorization 缺 DNS-01 challenge")
	}
	return selected, nil
}

func validateIssuedChain(certificates [][]byte, intent *wire.CertificateIntentV1, roots *x509.CertPool,
	now time.Time) ([]byte, *x509.Certificate, error) {
	if len(certificates) == 0 || len(certificates) > 16 {
		return nil, nil, errors.New("[TLS] ACME certificate chain 数量无效")
	}
	parsed := make([]*x509.Certificate, len(certificates))
	total := 0
	seen := make(map[string]struct{}, len(certificates))
	for index, der := range certificates {
		total += len(der)
		if len(der) == 0 || total > 1<<20 {
			return nil, nil, errors.New("[TLS] ACME certificate chain 为空或过大")
		}
		digest := sha256.Sum256(der)
		key := string(digest[:])
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, errors.New("[TLS] ACME certificate chain 含重复 DER")
		}
		seen[key] = struct{}{}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) {
			return nil, nil, errors.New("[TLS] ACME certificate DER 无效")
		}
		parsed[index] = certificate
	}
	leaf := parsed[0]
	csrDER, _ := base64.RawURLEncoding.DecodeString(intent.CSRDER)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	if csr == nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.URIs) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 || !equalSortedDNSNames(leaf.DNSNames, intent.IdentityProjection.DNSNames) {
		return nil, nil, errors.New("[TLS] issued leaf 未绑定 exact CSR/SPKI/DNS server identity")
	}
	if !leaf.NotAfter.After(now.Add(time.Duration(intent.RenewBeforeSeconds) * time.Second)) {
		return nil, nil, errors.New("[TLS] issued leaf 有效期不足以越过 renew window")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range parsed[1:] {
		intermediates.AddCert(certificate)
	}
	for _, name := range intent.IdentityProjection.DNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: name, Roots: roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return nil, nil, fmt.Errorf("[TLS] issued chain/WebPKI hostname 验证失败: %w", err)
		}
	}
	var body bytes.Buffer
	for _, certificate := range parsed {
		if err := pem.Encode(&body, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, nil, err
		}
	}
	return body.Bytes(), leaf, nil
}

func validateCertificateGeneration(generation *CertificateGenerationV1) error {
	if generation == nil || generation.Schema != 1 || generation.PrivateKeyPath == "" ||
		generation.CSRPath != generation.PrivateKeyPath+".csr" || generation.CertificatePath == "" ||
		generation.SPKIHash != generation.Intent.IdentityProjection.SPKIHash ||
		!validHTTPSResourceURL(generation.CertificateURL) {
		return errors.New("[TLS] certificate generation shape 无效")
	}
	if err := wire.ValidateCertificateIntent(&generation.Intent); err != nil {
		return err
	}
	intentHash, _ := wire.CertificateIntentHash(&generation.Intent)
	if intentHash != generation.IntentHash {
		return errors.New("[TLS] certificate generation intent hash 不匹配")
	}
	for _, hash := range []string{generation.CertificateChainHash, generation.LeafCertificateHash, generation.SPKIHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	notBefore, err := wire.ParseTimeZ(generation.NotBefore)
	if err != nil {
		return err
	}
	notAfter, err := wire.ParseTimeZ(generation.NotAfter)
	if err != nil || !notBefore.Before(notAfter) {
		return errors.New("[TLS] certificate generation validity 无效")
	}
	if _, err := wire.ParseTimeZ(generation.InstalledAt); err != nil {
		return err
	}
	installedAt, _ := wire.ParseTimeZ(generation.InstalledAt)
	if installedAt.Before(notBefore) || !installedAt.Before(notAfter) {
		return errors.New("[TLS] certificate installed_at 不在 leaf validity 内")
	}
	return nil
}

func validateRetirementAuthorization(authorization *CertificateRetirementAuthorizationV1) error {
	if authorization == nil || authorization.Schema != 1 || authorization.ClusterID == "" || authorization.ReaderFloor < 1 {
		return errors.New("[TLS] certificate retirement header/floor 无效")
	}
	for _, hash := range []string{authorization.ActiveCertificateIntentHash, authorization.PreviousCertificateIntentHash,
		authorization.CertifiedHeadHash, authorization.RetirementGuardHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return errors.New("[TLS] certificate retirement hash 无效")
		}
	}
	_, err := wire.ParseTimeZ(authorization.RetiredAt)
	return err
}

func loadExistingIdentity(privateKeyPath string, dnsNames []string) (LocalIdentity, error) {
	if privateKeyPath == "" || len(dnsNames) == 0 {
		return LocalIdentity{}, errors.New("[TLS] local identity path/DNS names 缺失")
	}
	privateKey, err := loadP256(privateKeyPath)
	if err != nil {
		return LocalIdentity{}, err
	}
	csrPath := privateKeyPath + ".csr"
	csrDER, err := readRegularFile(csrPath, 256<<10, false)
	if err != nil {
		return LocalIdentity{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	spki, marshalErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || marshalErr != nil || !bytes.Equal(csr.Raw, csrDER) || csr.CheckSignature() != nil ||
		!bytes.Equal(csr.RawSubjectPublicKeyInfo, spki) || !equalStringSlices(csr.DNSNames, dnsNames) {
		return LocalIdentity{}, errors.New("[TLS] 本地 key/CSR 与 certificate identity 不匹配")
	}
	digest := sha256.Sum256(spki)
	return LocalIdentity{
		PrivateKeyPath: privateKeyPath, CSRPath: csrPath, CSRDER: csrDER,
		SPKIHash: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func validateIdentityIntent(identity LocalIdentity, intent *wire.CertificateIntentV1) error {
	csrDER, err := base64.RawURLEncoding.DecodeString(intent.CSRDER)
	if err != nil || !bytes.Equal(csrDER, identity.CSRDER) || identity.SPKIHash != intent.IdentityProjection.SPKIHash {
		return errors.New("[TLS] 本地 private key/CSR 不属于 certified certificate intent")
	}
	return nil
}

func readRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || private && before.Mode().Perm()&0o077 != 0 || !private && before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("[TLS] certificate artifact 不是安全 regular file 或权限过宽")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("[TLS] certificate artifact 在打开期间被替换")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("[TLS] certificate artifact 读取失败或过大")
	}
	return body, nil
}

func decodeCertificatePEM(body []byte) ([][]byte, error) {
	var certificates [][]byte
	rest := body
	for len(rest) > 0 {
		block, trailing := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("[TLS] certificate PEM 无效")
		}
		certificates = append(certificates, append([]byte(nil), block.Bytes...))
		rest = trailing
	}
	if len(certificates) == 0 {
		return nil, errors.New("[TLS] certificate PEM 为空")
	}
	return certificates, nil
}

func sameLogicalProjection(left, right wire.CertificateIdentityProjectionV1) bool {
	return left.ClusterID == right.ClusterID && left.IntentID == right.IntentID &&
		equalStringSlices(left.EndpointIDs, right.EndpointIDs) && equalStringSlices(left.DNSNames, right.DNSNames) &&
		left.IssuerProfileRef == right.IssuerProfileRef && left.KeyOwnerDeviceID == right.KeyOwnerDeviceID
}

func validIntentSuccessor(previous, next *wire.CertificateIntentV1) bool {
	if previous == nil || next == nil || !sameLogicalProjection(previous.IdentityProjection, next.IdentityProjection) {
		return false
	}
	if previous.IdentityProjectionHash == next.IdentityProjectionHash {
		return next.IssuanceGeneration > previous.IssuanceGeneration
	}
	return next.IdentityProjection.IdentityGeneration == previous.IdentityProjection.IdentityGeneration+1
}

func certificatePins(active, previous *CertificateGenerationV1) []string {
	if active == nil {
		return []string{}
	}
	pins := []string{active.SPKIHash}
	if previous != nil && previous.SPKIHash != active.SPKIHash {
		pins = append(pins, previous.SPKIHash)
	}
	sort.Strings(pins)
	return pins
}

func clonePublicCertificateState(state PublicCertificateStateV1) PublicCertificateStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone PublicCertificateStateV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}

func validHTTPSResourceURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.RawQuery == "" && parsed.Path != ""
}

func pathWithinDirectory(directory, path string) bool {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(directory, filepath.Clean(absolutePath))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func sortedUniqueStrings(values []string) bool {
	for index, value := range values {
		if !validHTTPSResourceURL(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalSortedDNSNames(left, right []string) bool {
	copyLeft := append([]string(nil), left...)
	copyRight := append([]string(nil), right...)
	sort.Strings(copyLeft)
	sort.Strings(copyRight)
	return equalStringSlices(copyLeft, copyRight)
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func oneOfStatus(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
