package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/wire"
)

func TestControlMigrationRetainsOfflineIdentityWithoutInventingWrappingOrEnrollment(t *testing.T) {
	runtime, _, migration, _, _ := controlRenderedClientFixture(t, model.WindowsDesktop)
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	// 为本测试的其他 source 节点构造已迁移 view；待迁移 Windows 始终没有
	// v2 view、certificate、wrapping key 或伪造的 Enrollment 事务。
	active := controlClone(application.Devices[0])
	application.Devices, application.DeviceMigrations = nil, nil
	for _, node := range ssot.Nodes {
		if node.ID == migration.DeviceID {
			continue
		}
		device := controlClone(active)
		device.View.DeviceID = node.ID
		device.View.Active.EndpointBundle.DeviceID = node.ID
		device.View.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&device.View.Active.EndpointBundle)
		leaf := migration
		leaf.DeviceID, leaf.LegacyFloor.DeviceID = node.ID, node.ID
		application.Devices = append(application.Devices, device)
		application.DeviceMigrations = append(application.DeviceMigrations, leaf)
	}
	sort.Slice(application.Devices, func(i, j int) bool {
		return application.Devices[i].View.DeviceID < application.Devices[j].View.DeviceID
	})
	sort.Slice(application.DeviceMigrations, func(i, j int) bool {
		return application.DeviceMigrations[i].DeviceID < application.DeviceMigrations[j].DeviceID
	})
	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(original.Public())
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
	application.DeferredMigrations = []controlDeferredDeviceMigrationV1{{DeviceID: migration.DeviceID, Platform: "windows-desktop", IdentitySPKIHash: identityHash}}
	root := t.TempDir()
	input := controlMigrationInputV1{Schema: 1, Source: filepath.Join(root, "source.yaml"), Registry: filepath.Join(root, "registry.json"), Application: *application}
	if err := os.WriteFile(input.Source, []byte(application.LegacySSOT), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := struct {
		Schema  int                     `json:"schema"`
		Clients []clientregistry.Client `json:"clients"`
		Invites []json.RawMessage       `json:"invites"`
	}{Schema: clientregistry.Schema, Clients: []clientregistry.Client{{ID: migration.DeviceID, Name: "demo offline client",
		Platform: "windows-desktop", Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(spki)}}, Invites: []json.RawMessage{}}
	raw, err := wire.MarshalCanonical(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.Registry, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input.Application.LegacyRegistryHash = wire.HashRaw("loom-legacy-registry-migration-v1", raw)
	if err := validateControlMigrationSource(&input); err != nil {
		t.Fatal("原身份保留不应依赖不存在的 Windows 宿主", err)
	}
	for _, test := range []struct {
		name   string
		change func(*controlMigrationInputV1)
	}{
		{"dropped-identity", func(p *controlMigrationInputV1) { p.Application.DeferredMigrations = nil }},
		{"replaced-key", func(p *controlMigrationInputV1) {
			p.Application.DeferredMigrations[0].IdentitySPKIHash = wire.EmptyHashV1
		}},
		{"changed-platform", func(p *controlMigrationInputV1) { p.Application.DeferredMigrations[0].Platform = "android" }},
		{"invented-identity", func(p *controlMigrationInputV1) { p.Application.DeferredMigrations[0].DeviceID = "demo-invented" }},
		{"active-and-pending", func(p *controlMigrationInputV1) {
			p.Application.Devices = append(p.Application.Devices, active)
			sort.Slice(p.Application.Devices, func(i, j int) bool {
				return p.Application.Devices[i].View.DeviceID < p.Application.Devices[j].View.DeviceID
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := controlClone(input)
			test.change(&changed)
			if err := validateControlMigrationSource(&changed); err == nil {
				t.Fatal("允许丢失、替换或伪造原身份")
			}
		})
	}
}
