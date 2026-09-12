package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"loom/internal/dnsprovider"
	"loom/internal/wire"
)

type fakeACMEClient struct {
	now                    func() time.Time
	issuer                 *x509.Certificate
	issuerKey              *ecdsa.PrivateKey
	order                  *acme.Order
	authorization          *acme.Authorization
	certificates           [][]byte
	authorizeCalls         int
	ensureAccountCalls     int
	acceptCalls            int
	waitAuthorizationCalls int
	failWaitAuthorization  error
	wrongDNSName           string
	wrongLeafKey           *ecdsa.PrivateKey
	untrustedIssuerKey     *ecdsa.PrivateKey
}

func newFakeACMEClient(t *testing.T, now func() time.Time) (*fakeACMEClient, *x509.CertPool) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instant := now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo ACME Root"},
		NotBefore: instant.Add(-24 * time.Hour), NotAfter: instant.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	return &fakeACMEClient{now: now, issuer: issuer, issuerKey: issuerKey}, roots
}

func (client *fakeACMEClient) EnsureAccount(context.Context) error {
	client.ensureAccountCalls++
	return nil
}

func (client *fakeACMEClient) AuthorizeOrder(_ context.Context, names []string) (*acme.Order, error) {
	client.authorizeCalls++
	index := client.authorizeCalls
	base := "https://acme.example"
	client.order = &acme.Order{
		URI: base + "/order/" + big.NewInt(int64(index)).String(), Status: acme.StatusPending,
		Expires: client.now().Add(24 * time.Hour), Identifiers: acme.DomainIDs(names...),
		AuthzURLs:   []string{base + "/authz/" + big.NewInt(int64(index)).String()},
		FinalizeURL: base + "/finalize/" + big.NewInt(int64(index)).String(),
	}
	client.authorization = &acme.Authorization{
		URI: client.order.AuthzURLs[0], Status: acme.StatusPending,
		Identifier: acme.AuthzID{Type: "dns", Value: names[0]},
		Challenges: []*acme.Challenge{{
			Type: "dns-01", URI: base + "/challenge/" + big.NewInt(int64(index)).String(),
			Token: "token-" + big.NewInt(int64(index)).String(), Status: acme.StatusPending,
		}},
	}
	return cloneACMEOrder(client.order), nil
}

func (client *fakeACMEClient) GetOrder(context.Context, string) (*acme.Order, error) {
	return cloneACMEOrder(client.order), nil
}

func (client *fakeACMEClient) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return cloneACMEAuthorization(client.authorization), nil
}

func (client *fakeACMEClient) DNS01ChallengeRecord(token string) (string, error) {
	return "proof-" + token, nil
}

func (client *fakeACMEClient) Accept(_ context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	client.acceptCalls++
	copyChallenge := *challenge
	copyChallenge.Status = acme.StatusProcessing
	client.authorization.Challenges[0].Status = acme.StatusProcessing
	return &copyChallenge, nil
}

func (client *fakeACMEClient) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	client.waitAuthorizationCalls++
	if client.failWaitAuthorization != nil {
		err := client.failWaitAuthorization
		client.failWaitAuthorization = nil
		return nil, err
	}
	client.authorization.Status = acme.StatusValid
	client.authorization.Challenges[0].Status = acme.StatusValid
	client.order.Status = acme.StatusReady
	return cloneACMEAuthorization(client.authorization), nil
}

func (client *fakeACMEClient) WaitOrder(context.Context, string) (*acme.Order, error) {
	if client.order.Status == acme.StatusPending && client.authorization.Status == acme.StatusValid {
		client.order.Status = acme.StatusReady
	}
	return cloneACMEOrder(client.order), nil
}

func (client *fakeACMEClient) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	certificates, err := client.issue(csrDER)
	if err != nil {
		return nil, "", err
	}
	client.certificates = certificates
	client.order.Status = acme.StatusValid
	client.order.CertURL = client.order.URI + "/certificate"
	return cloneDERChain(certificates), client.order.CertURL, nil
}

func (client *fakeACMEClient) FetchCert(context.Context, string, bool) ([][]byte, error) {
	return cloneDERChain(client.certificates), nil
}

func (client *fakeACMEClient) issue(csrDER []byte) ([][]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	names := append([]string(nil), csr.DNSNames...)
	if client.wrongDNSName != "" {
		names = append(names, client.wrongDNSName)
		sort.Strings(names)
	}
	publicKey := csr.PublicKey
	if client.wrongLeafKey != nil {
		publicKey = &client.wrongLeafKey.PublicKey
	}
	instant := client.now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(100 + client.authorizeCalls)),
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName}, DNSNames: names,
		NotBefore: instant.Add(-time.Hour), NotAfter: instant.Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issuer := client.issuer
	issuerKey := client.issuerKey
	if client.untrustedIssuerKey != nil {
		wrongRoot := &x509.Certificate{
			SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Wrong Root"},
			NotBefore: instant.Add(-time.Hour), NotAfter: instant.Add(365 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, wrongRoot, wrongRoot, &client.untrustedIssuerKey.PublicKey, client.untrustedIssuerKey)
		if err != nil {
			return nil, err
		}
		issuer, err = x509.ParseCertificate(rootDER)
		if err != nil {
			return nil, err
		}
		issuerKey = client.untrustedIssuerKey
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{leafDER, issuer.Raw}, nil
}

func TestCertificateReconcileResumesExactOrderAndCleansOwnedTXT(t *testing.T) {
	instant := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return instant }
	client, roots := newFakeACMEClient(t, now)
	client.failWaitAuthorization = errors.New("simulated process interruption")
	provider := dnsprovider.NewMemory()
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "certificate.json")
	artifactDirectory := filepath.Join(root, "certificates")
	identity, intent := testCertificateIntent(t, filepath.Join(root, "keys", "tls-1.pem"), 1, 1, "key-1")
	config := testCertificateManagerConfig(statePath, artifactDirectory, client, provider, roots, now)
	manager, err := OpenPublicCertificateManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), intent, identity.PrivateKeyPath); err == nil {
		t.Fatal("模拟中断没有使第一次 reconcile 失败")
	}
	pending := manager.Snapshot()
	if pending.Active != nil || pending.Pending == nil || len(pending.Pending.Presentations) != 1 {
		t.Fatalf("中断后 pending ownership 未持久化: %#v", pending)
	}
	readback, err := provider.Read(context.Background(), "example.test", "_acme-challenge.demo-edge", "TXT")
	if err != nil || len(readback.RRSet.Values) != 1 || readback.RRSet.Values[0] != "proof-token-1" {
		t.Fatalf("DNS-01 TXT 未保留供恢复: %#v err=%v", readback, err)
	}

	manager, err = OpenPublicCertificateManager(config)
	if err != nil {
		t.Fatal(err)
	}
	active, err := manager.Reconcile(context.Background(), intent, identity.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if client.authorizeCalls != 1 || active.Pending != nil || active.Active == nil || active.Previous != nil || len(active.SPKIPins) != 1 {
		t.Fatalf("恢复创建了重复 order 或未安装 active LKG: calls=%d state=%#v", client.authorizeCalls, active)
	}
	if _, err := provider.Read(context.Background(), "example.test", "_acme-challenge.demo-edge", "TXT"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal("成功签发后 owned DNS-01 TXT 未清理")
	}
	assertFileMode(t, statePath, 0o600)
	assertFileMode(t, active.Active.CertificatePath, 0o644)
	runtimeCertificate, err := manager.LoadActiveRuntimeCertificate()
	if err != nil || runtimeCertificate.TLSCertificate.PrivateKey == nil ||
		runtimeCertificate.IdentityProjectionHash != active.Active.Intent.IdentityProjectionHash ||
		!equalStringSlices(runtimeCertificate.SPKIPins, active.SPKIPins) {
		t.Fatalf("active LKG 无法作为 exact listener identity 加载: %v", err)
	}
	if _, err := OpenPublicCertificateManager(config); err != nil {
		t.Fatalf("已安装 LKG 无法从严格状态恢复: %v", err)
	}
}

func TestCertificateKeyRotationPublishesTwoPinsUntilCertifiedRetirement(t *testing.T) {
	instant := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return instant }
	client, roots := newFakeACMEClient(t, now)
	provider := dnsprovider.NewMemory()
	root := t.TempDir()
	config := testCertificateManagerConfig(filepath.Join(root, "state.json"), filepath.Join(root, "certs"), client, provider, roots, now)
	retirementAllowed := false
	config.VerifyRetirement = func(*CertificateRetirementAuthorizationV1) error {
		if !retirementAllowed {
			return errors.New("reader floor missing")
		}
		return nil
	}
	manager, err := OpenPublicCertificateManager(config)
	if err != nil {
		t.Fatal(err)
	}
	identityOne, intentOne := testCertificateIntent(t, filepath.Join(root, "keys", "tls-1.pem"), 1, 1, "key-1")
	first, err := manager.Reconcile(context.Background(), intentOne, identityOne.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	identityTwo, intentTwo := testCertificateIntent(t, filepath.Join(root, "keys", "tls-2.pem"), 2, 1, "key-2")
	second, err := manager.Reconcile(context.Background(), intentTwo, identityTwo.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if second.Previous == nil || len(second.SPKIPins) != 2 || second.SPKIPins[0] >= second.SPKIPins[1] ||
		second.Active.SPKIHash == second.Previous.SPKIHash {
		t.Fatalf("key rotation 未建立严格排序 old/new SPKI overlap: %#v", second)
	}
	authorization := CertificateRetirementAuthorizationV1{
		Schema: 1, ClusterID: "demo-cluster", ActiveCertificateIntentHash: second.Active.IntentHash,
		PreviousCertificateIntentHash: second.Previous.IntentHash,
		CertifiedHeadHash:             wire.HashRaw("test-head-v1", []byte("retire")),
		RetirementGuardHash:           wire.HashRaw("test-guard-v1", []byte("retire")), ReaderFloor: 9,
		RetiredAt: instant.Add(7*24*time.Hour - time.Second).Format(time.RFC3339),
	}
	if _, err := manager.RetirePrevious(authorization); err == nil {
		t.Fatal("retirement 在 overlap deadline 前通过")
	}
	instant = instant.Add(7 * 24 * time.Hour)
	authorization.RetiredAt = instant.Format(time.RFC3339)
	if _, err := manager.RetirePrevious(authorization); err == nil {
		t.Fatal("没有 reader-floor authority 却退役旧 pin")
	}
	retirementAllowed = true
	retired, err := manager.RetirePrevious(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Previous != nil || len(retired.SPKIPins) != 1 || retired.SPKIPins[0] != retired.Active.SPKIHash {
		t.Fatalf("certified retirement 未收缩旧 pin: %#v", retired)
	}
	for _, path := range []string{first.Active.CertificatePath, identityOne.PrivateKeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retirement 绕过 backup retention 删除了 artifact %s: %v", path, err)
		}
	}
}

func TestCertificateRejectsPrematureRenewalAndInvalidIssuedIdentity(t *testing.T) {
	instant := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return instant }
	client, roots := newFakeACMEClient(t, now)
	provider := dnsprovider.NewMemory()
	root := t.TempDir()
	manager, err := OpenPublicCertificateManager(testCertificateManagerConfig(
		filepath.Join(root, "state.json"), filepath.Join(root, "certs"), client, provider, roots, now))
	if err != nil {
		t.Fatal(err)
	}
	identity, firstIntent := testCertificateIntent(t, filepath.Join(root, "keys", "tls.pem"), 1, 1, "key-1")
	first, err := manager.Reconcile(context.Background(), firstIntent, identity.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	secondIntent, err := wire.NewCertificateIntentV1(firstIntent.IdentityProjection, 2, identity.CSRDER, 30*24*60*60, 7*24*60*60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), secondIntent, identity.PrivateKeyPath); err == nil {
		t.Fatal("尚未进入 renew window 却创建新 order")
	}
	if client.authorizeCalls != 1 || manager.Snapshot().Active.IntentHash != first.Active.IntentHash {
		t.Fatal("premature renewal 改写了 LKG")
	}

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client.wrongLeafKey = wrongKey
	rotatedIdentity, rotatedIntent := testCertificateIntent(t, filepath.Join(root, "keys", "rotated.pem"), 2, 1, "key-2")
	if _, err := manager.Reconcile(context.Background(), rotatedIntent, rotatedIdentity.PrivateKeyPath); err == nil {
		t.Fatal("错误 leaf key/不受信 chain 被安装")
	}
	after := manager.Snapshot()
	if after.Active.IntentHash != first.Active.IntentHash || after.Pending == nil {
		t.Fatalf("错误签发覆盖 LKG 或丢失可恢复 pending: %#v", after)
	}
}

func TestIssuedCertificateMustMatchKeyNamesAndTrustedChain(t *testing.T) {
	instant := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*fakeACMEClient)
	}{
		{name: "extra DNS SAN", mutate: func(client *fakeACMEClient) { client.wrongDNSName = "unexpected.example.test" }},
		{name: "wrong leaf key", mutate: func(client *fakeACMEClient) {
			client.wrongLeafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}},
		{name: "untrusted issuer", mutate: func(client *fakeACMEClient) {
			client.untrustedIssuerKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := func() time.Time { return instant }
			client, roots := newFakeACMEClient(t, now)
			identity, intent := testCertificateIntent(t, filepath.Join(t.TempDir(), "tls.pem"), 1, 1, "key")
			test.mutate(client)
			certificates, err := client.issue(identity.CSRDER)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := validateIssuedChain(certificates, &intent, roots, instant); err == nil {
				t.Fatal("不匹配的 ACME certificate artifact 被接受")
			}
		})
	}
}

func TestCertificateAuthorityRejectionPrecedesACMESideEffects(t *testing.T) {
	instant := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return instant }
	client, roots := newFakeACMEClient(t, now)
	provider := dnsprovider.NewMemory()
	root := t.TempDir()
	config := testCertificateManagerConfig(filepath.Join(root, "state.json"), filepath.Join(root, "certs"), client, provider, roots, now)
	config.VerifyIntent = func(*wire.CertificateIntentV1) error { return errors.New("not certified") }
	manager, err := OpenPublicCertificateManager(config)
	if err != nil {
		t.Fatal(err)
	}
	identity, intent := testCertificateIntent(t, filepath.Join(root, "tls.pem"), 1, 1, "key")
	if _, err := manager.Reconcile(context.Background(), intent, identity.PrivateKeyPath); err == nil {
		t.Fatal("未获 certified authority 的 certificate intent 被执行")
	}
	if client.ensureAccountCalls != 0 || client.authorizeCalls != 0 || manager.Snapshot().Pending != nil {
		t.Fatal("authority 拒绝后仍发生 ACME side effect")
	}
}

func testCertificateManagerConfig(statePath, artifactDirectory string, client ACMEClient,
	provider dnsprovider.Provider, roots *x509.CertPool, now func() time.Time) PublicCertificateManagerConfig {
	return PublicCertificateManagerConfig{
		StatePath: statePath, ArtifactDirectory: artifactDirectory, Client: client,
		DNS01: DNS01{Provider: provider, Zone: "example.test", TTL: 60}, Roots: roots, Now: now,
		VerifyIntent:     func(*wire.CertificateIntentV1) error { return nil },
		VerifyRetirement: func(*CertificateRetirementAuthorizationV1) error { return nil },
	}
}

func testCertificateIntent(t *testing.T, keyPath string, identityGeneration, issuanceGeneration int64,
	artifactMarker string) (LocalIdentity, wire.CertificateIntentV1) {
	t.Helper()
	identity, err := EnsureLocalIdentity(keyPath, "demo-edge.example.test")
	if err != nil {
		t.Fatal(err)
	}
	projection := wire.CertificateIdentityProjectionV1{
		Schema: 1, ClusterID: "demo-cluster", IntentID: "public-edge", IdentityGeneration: identityGeneration,
		EndpointIDs: []string{"bootstrap-edge", "distribution-edge"}, DNSNames: []string{"demo-edge.example.test"},
		IssuerProfileRef: "public-webpki", KeyOwnerDeviceID: "demo-edge",
		KeyArtifactHash: wire.HashRaw("test-key-artifact-v1", []byte(artifactMarker)), SPKIHash: identity.SPKIHash,
	}
	intent, err := wire.NewCertificateIntentV1(projection, issuanceGeneration, identity.CSRDER, 30*24*60*60, 7*24*60*60)
	if err != nil {
		t.Fatal(err)
	}
	return identity, intent
}

func assertFileMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("%s mode=%v, want regular %o", path, info.Mode(), mode)
	}
}

func cloneACMEOrder(order *acme.Order) *acme.Order {
	if order == nil {
		return nil
	}
	copyOrder := *order
	copyOrder.Identifiers = append([]acme.AuthzID(nil), order.Identifiers...)
	copyOrder.AuthzURLs = append([]string(nil), order.AuthzURLs...)
	return &copyOrder
}

func cloneACMEAuthorization(authorization *acme.Authorization) *acme.Authorization {
	if authorization == nil {
		return nil
	}
	copyAuthorization := *authorization
	copyAuthorization.Challenges = make([]*acme.Challenge, len(authorization.Challenges))
	for index, challenge := range authorization.Challenges {
		if challenge != nil {
			copyChallenge := *challenge
			copyAuthorization.Challenges[index] = &copyChallenge
		}
	}
	return &copyAuthorization
}

func cloneDERChain(certificates [][]byte) [][]byte {
	result := make([][]byte, len(certificates))
	for index := range certificates {
		result[index] = append([]byte(nil), certificates[index]...)
	}
	return result
}
