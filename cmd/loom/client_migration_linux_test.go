//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientregistry"
	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/publish"
	"loom/internal/wire"
)

func TestLinuxMigrationExportUsesOriginalIdentityAndPreservesInputs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, issuer, issuerKey, err := makeCertificateAuthority("demo-original-ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "demo-server"}, DNSNames: []string{"demo-server.node.internal"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	platform, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := wire.MarshalCanonical(clientmigration.Floor{Schema: 1, Generation: 5,
		PayloadSHA256: strings.Repeat("a", 64), SelectedSnapshot: strings.Repeat("b", 12)})
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"original.key": append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: parameters}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})...),
		"original.crt":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
		"original-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}),
		"platform.pub":    []byte(base64.StdEncoding.EncodeToString(platform)), "floor.json": floor,
	}
	for name, body := range inputs {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "request.json")
	stateDir := filepath.Join(dir, "client-v2")
	args := []string{"export-migration-request", "-device", "demo-server", "-state-dir", stateDir,
		"-identity-key", filepath.Join(dir, "original.key"), "-identity-cert", filepath.Join(dir, "original.crt"),
		"-identity-ca", filepath.Join(dir, "original-ca.crt"), "-platform-pubkey", filepath.Join(dir, "platform.pub"),
		"-floor", filepath.Join(dir, "floor.json"), "-out", output}
	if err := cmdClient(args); err != nil {
		t.Fatal(err)
	}
	var first wire.RuntimeDeviceMigrationRequestV1
	if err := readCanonicalFile(output, 1<<20, &first); err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(key.Public())
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, public)
	if err := wire.VerifyRuntimeDeviceMigrationRequest(&first, identityHash, fmt.Sprintf("sha256:%x", sha256.Sum256(platform))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Body.LegacyFloor, floor) || first.Body.Platform != "linux-server" ||
		first.Body.IdentitySPKIDER != base64.RawURLEncoding.EncodeToString(public) {
		t.Fatal("正常 CLI 未保留原身份和 floor")
	}
	identity, err := clientv2.LoadEnrollmentIdentityForResume(filepath.Join(stateDir, "identity.json"))
	if err != nil || identity.WrappingPublicKeySPKI != first.Body.WrappingSPKIDER {
		t.Fatal("封装密钥未保存供迁移导入复用", err)
	}
	if err := cmdClient(args); err != nil {
		t.Fatal(err)
	}
	var second wire.RuntimeDeviceMigrationRequestV1
	if err := readCanonicalFile(output, 1<<20, &second); err != nil || !wire.EqualCanonical(first.Body, second.Body) {
		t.Fatal("重试改变了原身份迁移请求", err)
	}
	for name, body := range inputs {
		actual, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(body, actual) {
			t.Fatal("迁移导出改写了原始材料", name, err)
		}
	}
	args[2] = "demo-other-server"
	if err := cmdClient(args); err == nil {
		t.Fatal("原证书被用于另一个 Device 的迁移请求")
	}
	args[2] = "demo-server"
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning} {
		template, err := x509.ParseCertificate(certificate)
		if err != nil {
			t.Fatal(err)
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "original.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		err = cmdClient(args)
		if (usage == x509.ExtKeyUsageServerAuth) != (err == nil) {
			t.Fatalf("原证书用途验证错误: usage=%v err=%v", usage, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	for _, usage := range []x509.KeyUsage{0, x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment} {
		template, err := x509.ParseCertificate(certificate)
		if err != nil {
			t.Fatal(err)
		}
		template.KeyUsage = usage
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, "original.crt"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		want := usage != x509.KeyUsageKeyEncipherment
		if err := cmdClient(args); (err == nil) != want {
			t.Fatalf("原身份导出错误解释 Key Usage: usage=%v err=%v", usage, err)
		}
		if _, err := originalMigrationDeviceIdentity("demo-server", "linux-server", clientregistry.Client{}, string(encoded), roots); (err == nil) != want {
			t.Fatalf("控制迁移错误解释 Key Usage: usage=%v err=%v", usage, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "original.crt"), inputs["original.crt"], 0600); err != nil {
		t.Fatal(err)
	}
	wrongParameters, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: wrongParameters}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})...)
	if err := os.WriteFile(filepath.Join(dir, "original.key"), wrongKey, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdClient(args); err == nil {
		t.Fatal("EC PARAMETERS 与实际 P-256 身份不匹配仍被接受")
	}
}

func TestLinuxMigrationInstallationReplaysRealCertifiedMigrationWithoutEnrollment(t *testing.T) {
	const deviceID = "demo-existing-device"
	platform, platformKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	originalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(dir, "identity.json")
	identity, err := clientv2.ImportLinuxMigrationIdentity(identityPath, originalKey)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, _ := identity.IdentitySPKIHash()
	public, _ := x509.MarshalPKIXPublicKey(originalKey.Public())
	wrapping, _ := base64.RawURLEncoding.DecodeString(identity.WrappingPublicKeySPKI)
	wrappingHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrapping)
	current := publish.DeploymentCurrent{Schema: 1, Generation: 9, Snapshot: "aabbccddeeff", PublishedAt: "2026-09-01T00:00:00Z"}
	if err := current.Sign(platformKey); err != nil {
		t.Fatal(err)
	}
	currentRaw, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := current.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	floor := clientmigration.Floor{Schema: 1, Generation: 9, PayloadSHA256: digest, SelectedSnapshot: current.Snapshot}
	legacy, err := clientmigration.VerifyFloor(currentRaw, platform, deviceID, floor)
	if err != nil {
		t.Fatal(err)
	}
	floorRaw, _ := wire.MarshalCanonical(floor)
	platformHash := fmt.Sprintf("sha256:%x", sha256.Sum256(platform))
	request, err := identity.SignMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: deviceID,
		Platform: "linux-server", IdentitySPKIDER: identity.IdentityPublicKeySPKI, WrappingSPKIDER: identity.WrappingPublicKeySPKI,
		WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1", PlatformKeyHash: platformHash, LegacyFloor: floorRaw})
	if err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	runtime, _, _, _ := controlMigratedDeviceRuntime(t, func(application *controlApplicationV1, runtime *controlRuntime) {
		now := runtime.now().UTC().Truncate(time.Second).Add(time.Second)
		runtime.now = func() time.Time { return now }
		material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
		if err != nil {
			t.Fatal(err)
		}
		defer material.Close()
		profile, err := material.prepareDeviceCA(application.ClusterID, "demo-migration", now)
		if err != nil {
			t.Fatal(err)
		}
		application.CARegistry.DeviceProfiles = []wire.DeviceCertificateProfileStateV1{profile}
		issuer, err := runtime.loadDeviceIssuer(profile)
		if err != nil {
			t.Fatal(err)
		}
		defer clearControlSigner(issuer)
		migration := &application.DeviceMigrations[0]
		migration.Platform, migration.IdentitySPKIHash, migration.WrappingKeyHash, migration.LegacyFloor = "linux-server", identityHash, wrappingHash, legacy
		certificate, err = enrollmentv2.PrepareMigratedDeviceCertificate(request, identityHash, platformHash, profile,
			[]string{"use_loom"}, migration.Issuance, now, issuer, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		migration.DeviceCertificateHash, _ = wire.DeviceCertificateHash(certificate)
		migration.DeviceCertificateProfileHash, _ = wire.DeviceCertificateProfileStateHash(&profile)
		application.Devices[0].View.Active.IdentitySPKIHash = identityHash
	}, platformKey)
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	leaf := application.DeviceMigrations[0]
	for path, raw := range map[string][]byte{
		filepath.Join(runtime.dir, "migration-certificates", strings.TrimPrefix(leaf.DeviceCertificateHash, "sha256:")+".der"): certificate,
		filepath.Join(runtime.dir, "migration-currents", strings.TrimPrefix(legacy.V1SignedCurrentHash, "sha256:")+".json"):    currentRaw,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	delivery, err := runtime.migrationDeliveryLocked(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	trust, err := clientmigration.RuntimeActivationTrust(platform)
	if err != nil {
		t.Fatal(err)
	}
	input := clientv2.LinuxMigrationInstall{StatePath: statePath, IdentityPath: identityPath, Package: delivery,
		Expected:    wire.RuntimeDeviceMigrationExpectedV1{DeviceID: deviceID, Platform: "linux-server", IdentitySPKIDER: public, WrappingKeyHash: wrappingHash},
		LegacyFloor: floor, Trust: trust,
		Now: runtime.now(), Configs: []clientv2.InstalledConfigV1{}, ValidateCandidate: func(state *clientv2.State) error {
			if state.Enrollment != nil || state.Migration == nil || state.Migration.IdentityKeyHash != identityHash {
				t.Fatal("迁移伪造 Enrollment 或替换原身份")
			}
			return nil
		}}
	floors, err := clientv2.InstallLinuxMigration(input)
	if err != nil {
		t.Fatal(err)
	}
	store, err := clientv2.Open(statePath)
	if err != nil || store.Enrollment() != nil || store.Installation() == nil || !wire.EqualCanonical(store.Floors(), floors) {
		t.Fatal("迁移安装不能从持久存储恢复", err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil || bytes.Contains(raw, []byte(`"claim_core"`)) || bytes.Contains(raw, []byte(`"result_artifact"`)) {
		t.Fatal("持久迁移伪造了空 Enrollment 字段", err)
	}
	if _, err := clientv2.InstallLinuxMigration(input); err != nil {
		t.Fatal("exact retry 不能恢复原安装", err)
	}
	input.LegacyFloor.Generation++
	if _, err := clientv2.InstallLinuxMigration(input); err == nil {
		t.Fatal("迁移降低了原设备 floor")
	}
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(raw, after) {
		t.Fatal("失败导入改写了已保存的 v2 身份")
	}
}
