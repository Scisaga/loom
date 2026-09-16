package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"loom/internal/wire"
)

func preparedMigrationInputFixture(t *testing.T) (*controlRuntime, string, controlMigrationInputV1, string) {
	t.Helper()
	runtime, admin, input, platform := migrationDeviceInputFixture(t)
	app := input.Application
	materials, err := prepareControlMigrationMaterials(runtime.dir, "demo-migration",
		map[string]int64{"enroll": 18301, "device_config": 18302, "device_report": 18303}, runtime.now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	prepared := controlMigrationPreparedV1{Schema: 1, ClusterID: app.ClusterID, Materials: materials,
		Recovery:     controlRecoveryMaterialV1{Schema: 1, Policy: app.RecoveryPolicy, Custody: app.RecoveryCustody, Proofs: input.RecoveryProofs},
		InvitePolicy: app.InvitePolicy, BootstrapCatalog: app.BootstrapCatalog, BootstrapIssuers: app.BootstrapIssuers,
		Mirrors: app.Mirrors, DeferredMigrations: app.DeferredMigrations, DistributionSets: []wire.DistributionEndpointSetV1{}}
	for i, mirror := range prepared.Mirrors {
		listener := controlClone(app.BootstrapCatalog.BootstrapIngressSet.Endpoints[0].ListenerGenerations[0])
		listener.DialTargetFQDN = mirror.ServerName
		listener.TransportIdentityRefs = append([]string{mirror.WebPKIProfileRef}, mirror.SPKIPins...)
		sort.Strings(listener.TransportIdentityRefs)
		set := wire.DistributionEndpointSetV1{Schema: 1, ClusterID: app.ClusterID, EndpointSetID: mirror.EndpointID, Generation: 1,
			ValidFrom: app.BootstrapCatalog.ValidFrom, ValidUntil: app.BootstrapCatalog.ValidUntil,
			ParentHeadHash: app.BootstrapCatalog.ParentHeadHash, ConfigQC: app.BootstrapCatalog.BootstrapIngressSet.ConfigQC,
			Endpoints: []wire.DistributionEndpointV1{{EndpointID: mirror.EndpointID, LogicalServerID: mirror.EndpointID, Transport: "https",
				DistributionPathPrefix: "/distribution/sha256/", ListenerGenerations: []wire.ListenerGenerationV2{listener}, ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}}}}
		hash, err := wire.DistributionEndpointSetHash(&set)
		if err != nil {
			t.Fatal(err)
		}
		prepared.Mirrors[i].DistributionEndpointSetHash = hash
		prepared.DistributionSets = append(prepared.DistributionSets, set)
	}
	for i := range prepared.BootstrapIssuers {
		prepared.BootstrapIssuers[i].Active.PermittedServiceIDs = []string{app.EnrollmentService.ServiceID}
	}
	input.Prepared, input.Application, input.RecoveryProofs = &prepared, controlApplicationV1{}, nil
	return runtime, admin, input, platform
}

func TestMigrationPreparedMaterialsBuildActualApplicationAndRetainExactResult(t *testing.T) {
	runtime, admin, input, platform := preparedMigrationInputFixture(t)
	before := runtime.store.Snapshot()
	preview := controlClone(input)
	if err := runtime.prepareMigrationApplication(&preview); err != nil {
		t.Fatal(err)
	}
	if !wire.EqualCanonical(before, runtime.store.Snapshot()) || len(runtime.journal.Records) != 0 {
		t.Fatal("组装迁移输入提前改写认证日志")
	}
	if len(preview.Application.Devices) != 0 || len(preview.Application.DeviceMigrations) != 0 {
		t.Fatal("材料生成器伪造已迁移 Device")
	}
	if preview.Application.Authorizations[0].AdminID != runtime.config.Authorizations[0].AdminID ||
		preview.Application.Authorizations[0].Generation != runtime.config.Authorizations[0].Generation+1 {
		t.Fatal("未保留原管理员")
	}
	key, err := readKey(platform, ed25519.PrivateKeySize)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	clear(key)
	if err := runtime.prepareMigrationDevices(&preview, public); err != nil {
		t.Fatal(err)
	}
	if err := validateControlMigrationSource(&preview); err != nil {
		t.Fatal(err)
	}
	inputPath, output := filepath.Join(t.TempDir(), "input.json"), filepath.Join(t.TempDir(), "migration")
	if err := writeCanonicalAtomic(inputPath, input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.migrateControlApplication(inputPath, admin, platform, output, "demo-certified-cutover"); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(output, "migration-request.json")
	request, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.migrateControlApplication(inputPath, admin, platform, output, "demo-certified-cutover"); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(requestPath)
	if err != nil || string(again) != string(request) {
		t.Fatal("重启重新生成迁移结果", err)
	}
	application, err := reopened.certifiedApplicationLocked()
	if err != nil || len(application.Devices) != len(input.DeviceInputs.Entries) || len(application.DistributionSets) != len(input.Prepared.DistributionSets) {
		t.Fatal("认证结果缺 Device 或完整分发 preimage", err)
	}
}

func TestMigrationPreparedMaterialsRejectSplicedPublicAndPrivateInputs(t *testing.T) {
	for name, change := range map[string]func(*controlMigrationInputV1){
		"foreign-material":        func(input *controlMigrationInputV1) { input.Prepared.Materials.DeviceID = "demo-other" },
		"hand-filled-application": func(input *controlMigrationInputV1) { input.Application.Schema = 1 },
		"missing-device-requests": func(input *controlMigrationInputV1) { input.DeviceInputs = nil },
		"unbound-mirror":          func(input *controlMigrationInputV1) { input.Prepared.DistributionSets = nil },
		"changed-mirror-pin":      func(input *controlMigrationInputV1) { input.Prepared.Mirrors[0].SPKIPins[0] = wire.EmptyHashV1 },
		"changed-service-pin": func(input *controlMigrationInputV1) {
			input.Prepared.Materials.PrivateServices.Services[0].Service.SPKIPins[0] = wire.EmptyHashV1
		},
		"foreign-issuer": func(input *controlMigrationInputV1) {
			input.Prepared.BootstrapIssuers[0].Active.PermittedServiceIDs = []string{"demo-other"}
		},
		"missing-issuer": func(input *controlMigrationInputV1) {
			input.Prepared.BootstrapIssuers = []wire.BootstrapIssuerAuthorizationV1{}
		},
		"unavailable-ca": func(input *controlMigrationInputV1) {
			input.Prepared.Materials.DeviceProfile.ProfileIntent.IssuerKeyArtifactHash = wire.EmptyHashV1
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtime, _, input, _ := preparedMigrationInputFixture(t)
			before := runtime.store.Snapshot()
			change(&input)
			if err := runtime.prepareMigrationApplication(&input); err == nil {
				t.Fatal("拼接迁移材料被接受")
			}
			if !wire.EqualCanonical(before, runtime.store.Snapshot()) || len(runtime.journal.Records) != 0 {
				t.Fatal("失败准备改写原日志")
			}
		})
	}
}
