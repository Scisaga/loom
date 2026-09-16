package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/publish"
	"loom/internal/wire"
)

func TestMigrationGeneratesOriginalDeviceIdentitiesAtActualCommitAndRetriesExactly(t *testing.T) {
	runtime, admin, input, platformPath := migrationDeviceInputFixture(t)
	root := t.TempDir()
	inputPath, output := filepath.Join(root, "input.json"), filepath.Join(root, "result")
	if err := writeCanonicalAtomic(inputPath, input, 0600); err != nil {
		t.Fatal(err)
	}
	beforeSource, _ := os.ReadFile(input.Source)
	beforeRegistry, _ := os.ReadFile(input.Registry)
	if err := runtime.migrateControlApplication(inputPath, admin, platformPath, output, "demo migrate original devices"); err != nil {
		t.Fatal(err)
	}
	var request controlMigrationRequestV1
	requestPath := filepath.Join(output, "migration-request.json")
	if err := readCanonicalFile(requestPath, 64<<20, &request); err != nil {
		t.Fatal(err)
	}
	application := request.Activation.Application
	if len(application.Devices) != len(input.DeviceInputs.Entries) || len(application.DeviceMigrations) != len(input.DeviceInputs.Entries) ||
		len(application.Transactions) != 0 || len(application.IssuanceRegistry) != 0 || len(application.DeferredMigrations) != 1 {
		t.Fatal("迁移丢失原 Device 或伪造了 Enrollment")
	}
	for i, leaf := range application.DeviceMigrations {
		identity, err := runtime.readDeviceIdentityLocked(leaf.DeviceCertificateHash)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.Issuance.RaftIndex != identity.Head.Body.Payload.RaftIndex || leaf.Issuance.RecoveryEpoch != identity.Head.Body.Payload.RecoveryEpoch {
			t.Fatal("证书坐标不是实际迁移日志")
		}
		der, err := readOwnerOnlyFile(filepath.Join(runtime.dir, "migration-certificates", strings.TrimPrefix(leaf.DeviceCertificateHash, "sha256:")+".der"), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || base64.RawURLEncoding.EncodeToString(certificate.RawSubjectPublicKeyInfo) != input.DeviceInputs.Entries[i].Request.Body.IdentitySPKIDER {
			t.Fatal("迁移替换了原身份 key", err)
		}
		if len(application.Devices[i].View.Active.ConfigArtifactRefs) != 0 {
			t.Fatal("身份迁移不能凭空捏造可用运行配置")
		}
	}
	firstRequest, _ := os.ReadFile(requestPath)
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.migrateControlApplication(inputPath, admin, platformPath, output, "demo migrate original devices"); err != nil {
		t.Fatal("重启后不能续接第一次认证结果", err)
	}
	secondRequest, _ := os.ReadFile(requestPath)
	afterSource, _ := os.ReadFile(input.Source)
	afterRegistry, _ := os.ReadFile(input.Registry)
	if !bytes.Equal(firstRequest, secondRequest) || !bytes.Equal(beforeSource, afterSource) || !bytes.Equal(beforeRegistry, afterRegistry) {
		t.Fatal("重试替换了原结果、源网络或 registry")
	}
}

func TestMigrationRefusesReplacedRequestsBeforeAuthorityCommit(t *testing.T) {
	runtime, admin, input, platformPath := migrationDeviceInputFixture(t)
	before, _ := os.ReadFile(filepath.Join(runtime.dir, controlJournalName))
	for name, mutate := range map[string]func(*controlMigrationInputV1){
		"wrong-original-key": func(p *controlMigrationInputV1) {
			p.DeviceInputs.Entries[0].Request.Body.IdentitySPKIDER = p.DeviceInputs.Entries[0].Request.Body.WrappingSPKIDER
		},
		"wrong-original-signature": func(p *controlMigrationInputV1) {
			p.DeviceInputs.Entries[0].Request.Signature = strings.Repeat("A", 86)
		},
		"wrong-server-certificate": func(p *controlMigrationInputV1) {
			p.DeviceInputs.Entries[0].ServerCertificatePEM = p.DeviceInputs.Entries[1].ServerCertificatePEM
		},
		"rollback-current": func(p *controlMigrationInputV1) {
			p.DeviceInputs.Entries[0].LegacySignedCurrent = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		},
		"missing-active-device": func(p *controlMigrationInputV1) {
			p.DeviceInputs.Entries = p.DeviceInputs.Entries[:len(p.DeviceInputs.Entries)-1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := controlClone(input)
			mutate(&bad)
			root := t.TempDir()
			inputPath := filepath.Join(root, "input.json")
			if err := writeCanonicalAtomic(inputPath, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if err := runtime.migrateControlApplication(inputPath, admin, platformPath, filepath.Join(root, "out"), "demo reject altered device"); err == nil {
				t.Fatal("篡改或缺失原身份仍被认证")
			}
			after, _ := os.ReadFile(filepath.Join(runtime.dir, controlJournalName))
			if !bytes.Equal(before, after) {
				t.Fatal("被拒绝的输入改变了原 authority")
			}
		})
	}
}

func TestMigrationPreservesRevokedRegistryIdentityOutsideCurrentNetwork(t *testing.T) {
	runtime, admin, input, platformPath := migrationDeviceInputFixture(t)
	var registry controlLegacyRegistryV1
	if err := readCanonicalFile(input.Registry, 4<<20, &registry); err != nil {
		t.Fatal(err)
	}
	original := registry.Clients[0]
	original.ID, original.Status = "demo-revoked-history", "revoked"
	registry.Clients = append(registry.Clients, original)
	raw, err := wire.MarshalCanonical(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.Registry, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input.Application.LegacyRegistryHash = wire.HashRaw("loom-legacy-registry-migration-v1", raw)
	dir := t.TempDir()
	path, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "migration")
	if err := writeCanonicalAtomic(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.migrateControlApplication(path, admin, platformPath, output, "demo preserve original revocation"); err != nil {
		t.Fatal(err)
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, device := range application.Devices {
		if device.View.DeviceID != original.ID {
			continue
		}
		found = true
		if device.View.State != "revoked" || device.View.Active != nil || device.View.Tombstone == nil ||
			device.View.Tombstone.Reason != "revoked" || len(device.SecretArtifactRefs) != 0 || device.EnrollmentInviteID != "" {
			t.Fatal("原撤权身份被恢复或获得凭据")
		}
	}
	if !found || len(application.DeviceMigrations) != len(input.DeviceInputs.Entries) {
		t.Fatal("丢失原撤权身份或伪造了其迁移证书")
	}
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.migrateControlApplication(path, admin, platformPath, output, "demo preserve original revocation"); err != nil {
		t.Fatal("重启不能接续含原撤权记录的迁移", err)
	}
}

func migrationDeviceInputFixture(t *testing.T) (*controlRuntime, string, controlMigrationInputV1, string) {
	t.Helper()
	dir, admin := newAdminRotationFixture(t, true)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	app, recoveryProofs := controlInviteApplication(t, runtime)
	materials, err := prepareControlMigrationMaterials(dir, "demo-migration", map[string]int64{"enroll": 18301, "device_config": 18302, "device_report": 18303}, runtime.now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	app.CARegistry.DeviceProfiles = []wire.DeviceCertificateProfileStateV1{materials.DeviceProfile}
	app.Services = []wire.PrivateControlServiceV1{runtime.config.ControlService}
	for _, entry := range materials.PrivateServices.Services {
		app.Services = append(app.Services, entry.Service)
		if entry.Service.Role == "enroll" {
			app.EnrollmentService = wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: entry.Service.ServiceID,
				OverlayIP: entry.Service.OverlayIP, TCPPort: entry.Service.Port, InternalCAProfileRef: entry.Service.CertificateProfileRef,
				ServerIdentitySPKIPins: entry.Service.SPKIPins, ServiceGeneration: 1}
		}
	}
	ssot, err := model.Load([]byte(app.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	public, platform, _ := ed25519.GenerateKey(rand.Reader)
	platformHash := fmt.Sprintf("sha256:%x", sha256.Sum256(public))
	now := runtime.now().UTC().Truncate(time.Second)
	_, issuer, issuerKey, err := makeCertificateAuthority("demo-original-ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	spec := controlMigrationDeviceInputsV1{Schema: 1, ServerCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})), Entries: []controlMigrationDeviceInputV1{}}
	registry := controlLegacyRegistryV1{Schema: clientregistry.Schema, Clients: []clientregistry.Client{}, Invites: nil}
	current := publish.DeploymentCurrent{Schema: 1, Generation: 9, Snapshot: "aabbccddeeff", PublishedAt: now.Format(time.RFC3339)}
	if err := current.Sign(platform); err != nil {
		t.Fatal(err)
	}
	currentRaw, _ := current.Bytes()
	digest, _ := current.PayloadSHA256()
	floorRaw, _ := wire.MarshalCanonical(clientmigration.Floor{Schema: 1, Generation: 9, PayloadSHA256: digest, SelectedSnapshot: current.Snapshot})
	for i := range ssot.Nodes {
		node := &ssot.Nodes[i]
		name, _, _, err := migrationDeviceAuthorization(ssot, node)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		identityDER, _ := x509.MarshalPKIXPublicKey(key.Public())
		wrappingDER, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
		identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identityDER)
		registry.Clients = append(registry.Clients, clientregistry.Client{ID: node.ID, Platform: name, Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(identityDER)})
		if name == "windows-desktop" {
			app.DeferredMigrations = append(app.DeferredMigrations, controlDeferredDeviceMigrationV1{DeviceID: node.ID, Platform: name, IdentitySPKIHash: identityHash})
			continue
		}
		entry := controlMigrationDeviceInputV1{LegacySignedCurrent: base64.RawURLEncoding.EncodeToString(currentRaw)}
		profile := "p256-keystore-ecdh-v1"
		if name == "linux-server" {
			profile = "p256-root-only-pkcs8-ecdh-v1"
			der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), DNSNames: []string{node.ID + ".node.internal"},
				NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer, key.Public(), issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			entry.ServerCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
		entry.Request, err = wire.SignRuntimeDeviceMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: node.ID, Platform: name,
			PlatformKeyHash: platformHash, IdentitySPKIDER: base64.RawURLEncoding.EncodeToString(identityDER), WrappingSPKIDER: base64.RawURLEncoding.EncodeToString(wrappingDER),
			WrappingKeyProfile: profile, LegacyFloor: floorRaw}, key)
		if err != nil {
			t.Fatal(err)
		}
		spec.Entries = append(spec.Entries, entry)
	}
	sort.Slice(spec.Entries, func(i, j int) bool {
		return spec.Entries[i].Request.Body.DeviceID < spec.Entries[j].Request.Body.DeviceID
	})
	root := t.TempDir()
	input := controlMigrationInputV1{Schema: 1, Source: filepath.Join(root, "source.yaml"), Registry: filepath.Join(root, "registry.json"), Application: app, RecoveryProofs: recoveryProofs, DeviceInputs: &spec}
	if err := os.WriteFile(input.Source, []byte(app.LegacySSOT), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := wire.MarshalCanonical(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.Registry, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input.Application.LegacyRegistryHash = wire.HashRaw("loom-legacy-registry-migration-v1", raw)
	platformPath := filepath.Join(root, "platform.key")
	if err := os.WriteFile(platformPath, []byte(base64.StdEncoding.EncodeToString(platform)), 0600); err != nil {
		t.Fatal(err)
	}
	return runtime, admin, input, platformPath
}

func TestMigrationGrantProjectionDoesNotGrantUnrelatedResources(t *testing.T) {
	node := model.Node{ID: "demo-client", Access: &model.AccessRole{Platform: model.Android, Credentials: []string{"demo-credential"}}}
	ssot := model.SSOT{Nodes: []model.Node{node, {ID: "demo-exit", Drain: true, Server: &model.ServerRole{EgressCapable: true}}, {ID: "demo-other", Server: &model.ServerRole{EgressCapable: true}}},
		Credentials:  []model.Credential{{ID: "demo-credential", Declaration: "demo-declaration"}},
		Declarations: []model.AccessDeclaration{{ID: "demo-declaration", AddressAxis: model.FromRequest, EgressAxis: "pinned:demo-exit", AllowedServers: []string{"demo-exit", "demo-other"}}},
		Services:     []model.Service{{ID: "demo-service", Declaration: "demo-declaration"}, {ID: "demo-unrelated", Declaration: "demo-other-declaration"}}}
	_, roles, grants, err := migrationDeviceAuthorization(&ssot, &node)
	want := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{{Kind: "egress", TargetID: "demo-exit"}, {Kind: "service", TargetID: "demo-service"}}}
	if err != nil || !wire.EqualCanonical(grants, want) || !wire.EqualCanonical(roles.Values, []string{"use_loom"}) {
		t.Fatal("权限迁移丢失 drain 节点授权或扩大原资源授权", err)
	}
}
