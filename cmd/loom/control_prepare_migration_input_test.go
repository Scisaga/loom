package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/certmanager"
	"loom/internal/model"
	"loom/internal/wire"
)

func TestPrepareMigrationInputUsesRealKeysAndOriginalRequests(t *testing.T) {
	runtime, admin, original, platform := preparedMigrationInputFixture(t)
	// 原 fixture 的 issuer 是人工构造的测试输入；本测试通过正式生产器生成它。
	if err := os.RemoveAll(filepath.Join(runtime.dir, "bootstrap-issuers")); err != nil {
		t.Fatal(err)
	}
	now := runtime.now().UTC().Truncate(time.Second)
	source, err := os.ReadFile(original.Source)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(source)
	if err != nil {
		t.Fatal(err)
	}
	var owners []string
	for _, node := range ssot.Nodes {
		if node.Server != nil {
			owners = append(owners, node.ID)
		}
	}
	roots := x509.NewCertPool()
	first := migrationMirrorCertificateFixture(t, runtime.config.ClusterID, owners[0], "demo-a.example.test", []string{"demo-bootstrap-hy2", "demo-bootstrap-tcp", "demo-mirror-a"}, roots, now)
	second := migrationMirrorCertificateFixture(t, runtime.config.ClusterID, owners[1], "demo-b.example.test", []string{"demo-mirror-b"}, roots, now)
	state := runtime.store.Snapshot()
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	status := controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID, Service: runtime.config.ControlService,
		Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet}
	bootstrapRequest := testBootstrapPreparationFromCertificate(t, first, roots, now)
	installation, err := prepareInitialBootstrapPlan(bootstrapRequest, status, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	inputs := t.TempDir()
	request := controlPrepareMigrationInputV1{Schema: 1, RequestID: "demo-materials", Source: original.Source, Registry: original.Registry,
		MaterialsPath: filepath.Join(inputs, "materials.json"), RecoveryPath: filepath.Join(inputs, "recovery.json"),
		BootstrapPath: filepath.Join(inputs, "bootstrap.json"), DeviceInputsPath: filepath.Join(inputs, "devices.json"),
		InvitePolicy: original.Prepared.InvitePolicy, DeferredMigrations: original.Prepared.DeferredMigrations,
		Mirrors: []controlExistingMirrorInputV1{
			{EndpointID: "demo-mirror-a", ServerID: owners[0], ServerName: first.Identity.DNSNames[0], Port: 8443, AddressFamilies: []string{"ipv4"}, Certificate: first},
			{EndpointID: "demo-mirror-b", ServerID: owners[1], ServerName: second.Identity.DNSNames[0], Port: 443, AddressFamilies: []string{"ipv4"}, Certificate: second}}}
	for path, data := range map[string]any{request.MaterialsPath: original.Prepared.Materials, request.RecoveryPath: original.Prepared.Recovery,
		request.BootstrapPath: installation, request.DeviceInputsPath: original.DeviceInputs} {
		if err := writeCanonicalAtomic(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := prepareMigrationInput(runtime.dir, request, status, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := prepareMigrationInput(runtime.dir, request, status, roots, now.Add(time.Minute))
	if err != nil || !wire.EqualCanonical(prepared, again) {
		t.Fatal("重复准备更换了 issuer、原请求或材料", err)
	}
	if !wire.EqualCanonical(runtime.store.Snapshot(), state) || len(runtime.journal.Records) != 0 {
		t.Fatal("准备输入提前修改了原日志")
	}
	if !wire.EqualCanonical(*prepared.DeviceInputs, *original.DeviceInputs) || len(prepared.Prepared.DistributionSets) != 2 {
		t.Fatal("未保留原身份请求或完整 distribution preimage")
	}
	issuer := prepared.Prepared.BootstrapIssuers[0]
	key, err := runtime.bootstrapIssuerKey(issuer)
	if err != nil || len(key) == 0 {
		t.Fatal("正式 daemon 无法回读实际 issuer", err)
	}
	clear(key)
	inputPath := filepath.Join(inputs, "migration.json")
	if err := writeCanonicalAtomic(inputPath, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.migrateControlApplication(inputPath, admin, platform, filepath.Join(inputs, "receipt"), "demo-cutover"); err != nil {
		t.Fatal(err)
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil || application.Schema != 2 || len(application.Devices) != len(original.DeviceInputs.Entries) {
		t.Fatal("生产输入未完成原日志认证迁移", err)
	}
	for name, change := range map[string]func(*controlPrepareMigrationInputV1){
		"wrong-owner":    func(r *controlPrepareMigrationInputV1) { r.Mirrors[0].ServerID = "demo-unrelated" },
		"wrong-name":     func(r *controlPrepareMigrationInputV1) { r.Mirrors[0].ServerName = "demo-unrelated.example.test" },
		"wrong-endpoint": func(r *controlPrepareMigrationInputV1) { r.Mirrors[0].EndpointID = "demo-mirror-0" },
		"wrong-port":     func(r *controlPrepareMigrationInputV1) { r.Mirrors[0].Port = 0 },
		"missing-mirror": func(r *controlPrepareMigrationInputV1) { r.Mirrors = r.Mirrors[:1] },
		"wrong-policy":   func(r *controlPrepareMigrationInputV1) { r.InvitePolicy.ClusterID = "demo-unrelated" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := controlClone(request)
			change(&changed)
			if _, err := prepareMigrationInput(runtime.dir, changed, status, roots, now); err == nil {
				t.Fatal("不匹配的迁移材料被接受")
			}
		})
	}
	if _, err := prepareMigrationInput(runtime.dir, request, status, x509.NewCertPool(), now); err == nil {
		t.Fatal("未经 WebPKI 验证的证书被接受")
	}
	if _, err := prepareBootstrapIssuer(runtime.dir, "demo-new-request", runtime.config.ClusterID, issuer.Active.InviteIssuancePolicyHash,
		request.InvitePolicy, installation.Catalog, issuer.Active.PermittedServiceIDs[0]); err == nil {
		t.Fatal("新请求静默重新生成 issuer")
	}
}

func migrationMirrorCertificateFixture(t *testing.T, cluster, owner, name string, endpoints []string, roots *x509.CertPool, now time.Time) certmanager.ExistingCertificateBindingV1 {
	t.Helper()
	_, root, rootKey, err := makeCertificateAuthority("Demo mirror CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Demo mirror"}, DNSNames: []string{name},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certificatePath, keyPath := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem")
	for path, body := range map[string][]byte{certificatePath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	binding, err := certmanager.PrepareExistingCertificate(filepath.Join(dir, "materials"), certmanager.ExistingCertificateRequestV1{
		Schema: 1, RequestID: "demo-prepare", ClusterID: cluster, DeviceID: owner, IdentityID: "demo-public-tls", IdentityGeneration: 1,
		CertificateGeneration: 1, EndpointIDs: endpoints, DNSNames: []string{name}, IssuerProfileRef: "webpki-v1", CertificatePath: certificatePath, PrivateKeyPath: keyPath}, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
