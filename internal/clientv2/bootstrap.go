package clientv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	InviteURIPrefix            = "loom://enroll/v2#d="
	MaximumCompactInviteBytes  = 1800
	MaximumBootstrapObjectSize = 16 << 20
	DomainInviteProofBundle    = wire.DomainInviteProofBundle
)

// DecodeInviteURI 只做 carrier 与 strict wire 解码；authority/signature 必须在 proof 下载后验证。
func DecodeInviteURI(raw string) (wire.InviteBootstrapDescriptorV2, error) {
	if len(raw) <= len(InviteURIPrefix) || len(raw) > MaximumCompactInviteBytes || !strings.HasPrefix(raw, InviteURIPrefix) {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[Linux] v2 Invite URI 形状或长度无效")
	}
	for i := range raw {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return wire.InviteBootstrapDescriptorV2{}, errors.New("[Linux] Invite URI 必须是无空白 ASCII")
		}
	}
	encoded := strings.TrimPrefix(raw, InviteURIPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[Linux] descriptor 必须是规范无 padding base64url")
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	canonical, err := wire.DecodeStrict(body, 1<<20, &descriptor)
	if err != nil || !bytes.Equal(canonical, body) {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[Linux] descriptor 必须是 exact canonical JSON")
	}
	return descriptor, nil
}

func EncodeInviteURI(descriptor *wire.InviteBootstrapDescriptorV2) (string, error) {
	if descriptor == nil {
		return "", errors.New("[Linux] descriptor 不能为空")
	}
	body, err := wire.MarshalCanonical(descriptor)
	if err != nil {
		return "", err
	}
	result := InviteURIPrefix + base64.RawURLEncoding.EncodeToString(body)
	if len(result) > MaximumCompactInviteBytes {
		return "", errors.New("[Linux] descriptor 超过 1800-byte QR 上限，应使用 .loom-invite")
	}
	return result, nil
}

type MirrorFetcher struct {
	RootCAs *x509.CertPool
	Timeout time.Duration
	// DialContext 供 Linux 调用方把 socket 绑定当前底层接口；TLS SNI、WebPKI 与
	// exact SPKI pin 仍来自 certified mirror ref，不能由 dialer 降级。
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// FetchCanonicalObject 只向 descriptor 的 2–3 个镜像发送无 token GET，并拒绝 redirect、cookie、
// proxy 与非 canonical 响应。expectedHash 是 typed object hash，也是 URL 中的 digest。
func (fetcher MirrorFetcher) FetchCanonicalObject(ctx context.Context, mirrors []wire.DistributionMirrorRefV1, expectedHash, domain string, maximum int64) ([]byte, error) {
	if len(mirrors) < 2 || len(mirrors) > 3 || maximum < 1 || maximum > MaximumBootstrapObjectSize {
		return nil, errors.New("[Linux bootstrap] mirror count/object limit 无效")
	}
	if err := wire.ValidateDistributionMirrorRefs(mirrors); err != nil {
		return nil, err
	}
	rawHash, err := wire.ParseHash(expectedHash)
	if err != nil || domain == "" {
		return nil, errors.New("[Linux bootstrap] expected typed hash/domain 无效")
	}
	ordered := append([]wire.DistributionMirrorRefV1(nil), mirrors...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].HintRank != ordered[j].HintRank {
			return ordered[i].HintRank < ordered[j].HintRank
		}
		return ordered[i].EndpointID < ordered[j].EndpointID
	})
	timeout := fetcher.Timeout
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 15 * time.Second
	}
	for _, mirror := range ordered {
		body, fetchErr := fetchMirrorObject(ctx, mirror, hex.EncodeToString(rawHash), maximum, fetcher.RootCAs, timeout, fetcher.DialContext)
		if fetchErr != nil {
			continue
		}
		canonical, canonicalErr := wire.CanonicalizeStrict(body)
		if canonicalErr != nil || !bytes.Equal(canonical, body) {
			continue
		}
		actualHash, hashErr := wire.HashCanonical(domain, canonical)
		if hashErr == nil && actualHash == expectedHash {
			return canonical, nil
		}
	}
	return nil, errors.New("[Linux bootstrap] 所有认证 mirror 均未返回 exact canonical/hash object")
}

func (fetcher MirrorFetcher) FetchBootstrapCatalog(ctx context.Context, descriptor *wire.InviteBootstrapDescriptorV2, now time.Time, clientProtocol int64, head *wire.HeadEntryV2, currentSet, previousSet *wire.ControlSetV1) (*wire.BootstrapEndpointCatalogV1, error) {
	if descriptor == nil {
		return nil, errors.New("[Linux bootstrap] descriptor 不能为空")
	}
	body, err := fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors, descriptor.BootstrapCatalogHash, wire.DomainBootstrapEndpointCatalog, MaximumBootstrapObjectSize)
	if err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	if _, err := wire.DecodeStrict(body, MaximumBootstrapObjectSize, &catalog); err != nil {
		return nil, err
	}
	if err := wire.ValidateBootstrapEndpointCatalogAt(&catalog, now, clientProtocol); err != nil {
		return nil, err
	}
	if descriptor.ClusterID != catalog.ClusterID || descriptor.BootstrapTunnelCapability.Body.AllowedIngressSetHash != catalog.BootstrapIngressSetHash {
		return nil, errors.New("[Linux bootstrap] descriptor/capability/catalog ingress binding 不匹配")
	}
	if err := wire.VerifyConfigQCAuthority(catalog.ParentHeadHash, catalog.BootstrapIngressSet.ConfigQC, head, currentSet, previousSet); err != nil {
		return nil, err
	}
	return &catalog, nil
}

// FetchBootstrapCatalogFromInviteProof 使用刚验证出的 Invite lineage 选择 catalog
// 的 exact parent authority；调用方无需猜测 catalog 与 record 是否共享同一个 Head。
func (fetcher MirrorFetcher) FetchBootstrapCatalogFromInviteProof(ctx context.Context,
	descriptor *wire.InviteBootstrapDescriptorV2, now time.Time, clientProtocol int64,
	proof wire.VerifiedInviteProofV2) (*wire.BootstrapEndpointCatalogV1, error) {
	if descriptor == nil {
		return nil, errors.New("[Linux bootstrap] descriptor 不能为空")
	}
	body, err := fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors,
		descriptor.BootstrapCatalogHash, wire.DomainBootstrapEndpointCatalog, MaximumBootstrapObjectSize)
	if err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	canonical, err := wire.DecodeStrict(body, MaximumBootstrapObjectSize, &catalog)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[Linux bootstrap] bootstrap catalog 必须是 exact canonical wire")
	}
	if err := wire.ValidateBootstrapEndpointCatalogAt(&catalog, now, clientProtocol); err != nil {
		return nil, err
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		catalog.ClusterID != descriptor.ClusterID ||
		catalog.BootstrapIngressSetHash != descriptor.BootstrapTunnelCapability.Body.AllowedIngressSetHash {
		return nil, errors.New("[Linux bootstrap] descriptor/capability/catalog binding 不匹配")
	}
	head, current, previous, ok := proof.AuthorityForHead(catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(catalog.ParentHeadHash,
		catalog.BootstrapIngressSet.ConfigQC, &head, &current, previous) != nil {
		return nil, errors.New("[Linux bootstrap] catalog parent Head/QC 不在已验 Invite lineage")
	}
	return &catalog, nil
}

func (fetcher MirrorFetcher) FetchInviteProofBytes(ctx context.Context, descriptor *wire.InviteBootstrapDescriptorV2) ([]byte, error) {
	if descriptor == nil {
		return nil, errors.New("[Linux] descriptor 不能为空")
	}
	return fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors, descriptor.ProofBundleHash, DomainInviteProofBundle, MaximumBootstrapObjectSize)
}

// FetchAndVerifyInviteProof 在任何 token/CSR/key 离开进程前完成 public proof 的 strict
// decode、typed hash、authority lineage、operation inclusion 与 issuer/capability 验证。
func (fetcher MirrorFetcher) FetchAndVerifyInviteProof(ctx context.Context, descriptor *wire.InviteBootstrapDescriptorV2, now time.Time, trust wire.InviteProofTrustV2) (*wire.InviteProofBundleV2, wire.VerifiedInviteProofV2, error) {
	body, err := fetcher.FetchInviteProofBytes(ctx, descriptor)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	var bundle wire.InviteProofBundleV2
	canonical, err := wire.DecodeStrict(body, MaximumBootstrapObjectSize, &bundle)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, wire.VerifiedInviteProofV2{}, errors.New("[Linux bootstrap] Invite proof 必须是 exact canonical wire")
	}
	verified, err := wire.VerifyInviteProofBundle(&bundle, descriptor, now, trust)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	return &bundle, verified, nil
}

// FetchAndVerifyResumeInviteProof 从 descriptor 指定的公共镜像取 exact proof bundle，
// 但只把本机 v1 migration root 当作 trust root；`.loom-resume` 自报的 hash 不能自行授权。
func (fetcher MirrorFetcher) FetchAndVerifyResumeInviteProof(ctx context.Context,
	descriptor *wire.EnrollmentResumeDescriptorV1, now time.Time,
	trust wire.InviteProofTrustV2) (*wire.InviteProofBundleV2, wire.VerifiedInviteProofV2, error) {
	if descriptor == nil {
		return nil, wire.VerifiedInviteProofV2{}, errors.New("[Linux resume] descriptor 不能为空")
	}
	body, err := fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors,
		descriptor.ProofBundleHash, DomainInviteProofBundle, MaximumBootstrapObjectSize)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	var bundle wire.InviteProofBundleV2
	canonical, err := wire.DecodeStrict(body, MaximumBootstrapObjectSize, &bundle)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, wire.VerifiedInviteProofV2{}, errors.New("[Linux resume] Invite proof 必须是 exact canonical wire")
	}
	verified, err := wire.VerifyResumeInviteProofBundle(&bundle, descriptor, now, trust)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	return &bundle, verified, nil
}

// FetchResumeBootstrapCatalog 验证 resume 指向的 catalog 及其 config QC。QC 的
// exact parent Head/ControlSet 必须来自刚刚重放的 Invite proof lineage。
func (fetcher MirrorFetcher) FetchResumeBootstrapCatalog(ctx context.Context,
	descriptor *wire.EnrollmentResumeDescriptorV1, now time.Time, clientProtocol int64,
	proof wire.VerifiedInviteProofV2) (*wire.BootstrapEndpointCatalogV1, error) {
	if descriptor == nil {
		return nil, errors.New("[Linux resume] descriptor 不能为空")
	}
	body, err := fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors,
		descriptor.BootstrapCatalogHash, wire.DomainBootstrapEndpointCatalog, MaximumBootstrapObjectSize)
	if err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	canonical, err := wire.DecodeStrict(body, MaximumBootstrapObjectSize, &catalog)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[Linux resume] bootstrap catalog 必须是 exact canonical wire")
	}
	if err := wire.ValidateBootstrapEndpointCatalogAt(&catalog, now, clientProtocol); err != nil {
		return nil, err
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		catalog.ClusterID != descriptor.ClusterID ||
		catalog.BootstrapIngressSetHash != descriptor.ResumeTunnelCapability.Body.AllowedIngressSetHash {
		return nil, errors.New("[Linux resume] descriptor/capability/catalog binding 不匹配")
	}
	head, current, previous, ok := proof.AuthorityForHead(catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(catalog.ParentHeadHash,
		catalog.BootstrapIngressSet.ConfigQC, &head, &current, previous) != nil {
		return nil, errors.New("[Linux resume] catalog parent Head/QC 不在已验 Invite lineage")
	}
	return &catalog, nil
}

func fetchMirrorObject(ctx context.Context, mirror wire.DistributionMirrorRefV1, digest string, maximum int64, roots *x509.CertPool, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	base, err := url.ParseRequestURI(mirror.BaseURL)
	if err != nil || base == nil || base.String() != mirror.BaseURL || base.Scheme != "https" || base.RawQuery != "" ||
		base.Fragment != "" || base.Hostname() != mirror.ServerName || base.Port() == "" || base.Path != "/distribution/sha256/" {
		return nil, errors.New("[Linux bootstrap] mirror URL 无效")
	}
	pins := make(map[string]struct{}, len(mirror.SPKIPins))
	for _, pin := range mirror.SPKIPins {
		if _, err := wire.ParseHash(pin); err != nil {
			return nil, errors.New("[Linux bootstrap] mirror SPKI pin 无效")
		}
		pins[pin] = struct{}{}
	}
	if len(pins) == 0 {
		return nil, errors.New("[Linux bootstrap] mirror 缺 SPKI pin")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: mirror.ServerName,
		RootCAs:    roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
				return errors.New("[Linux bootstrap] mirror WebPKI chain 未验证")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			pin := "sha256:" + hex.EncodeToString(digest[:])
			if _, ok := pins[pin]; !ok {
				return errors.New("[Linux bootstrap] mirror SPKI pin 不匹配")
			}
			return nil
		},
	}
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext: dialContext,
	}
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("[Linux bootstrap] immutable mirror 禁止 redirect")
		},
	}
	defer transport.CloseIdleConnections()
	requestURL := mirror.BaseURL + digest
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Cookies()) != 0 || response.Request.URL.String() != requestURL {
		return nil, fmt.Errorf("[Linux bootstrap] mirror response 状态/秘密隔离无效: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, errors.New("[Linux bootstrap] mirror object 超过大小上限")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("[Linux bootstrap] mirror object 读取失败或过大")
	}
	return body, nil
}
