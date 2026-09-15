package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestControlMigrationKeepsOriginalOwnerAfterAdminRotation(t *testing.T) {
	dir, admin := newAdminRotationFixture(t, true)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := runtime.legacyRuntimePolicy()
	if err != nil {
		t.Fatal(err)
	}
	root := readAdminTestCertificate(t, filepath.Join(admin, controlAdminRootName))
	if original.AdminRoot != base64.RawURLEncoding.EncodeToString(root.Raw) {
		t.Fatal("wrong original owner")
	}
	next := filepath.Join(t.TempDir(), "admin")
	if err := runtime.rotateAdminCertificate(admin, next, "demo migration preparation"); err != nil {
		t.Fatal(err)
	}
	restored, err := runtime.legacyRuntimePolicy()
	if err != nil || !wire.EqualCanonical(original, restored) {
		t.Fatal("rotation replaced migration owner", err)
	}
	application, proofs := controlInviteApplication(t, runtime)
	input := controlMigrationInputV1{Schema: 1, Application: application, RecoveryProofs: proofs}
	inputHash, _ := wire.HashObject("loom-control-migration-input-v1", input)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	platform := filepath.Join(t.TempDir(), "platform.key")
	if err := os.WriteFile(platform, []byte(base64.StdEncoding.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, controlJournalName))
	request, err := runtime.prepareControlMigration(input, inputHash, next, platform, "demo preserve original journal")
	if err != nil {
		t.Fatal(err)
	}
	if request.Activation.Bundle.Parent.HeadHash != runtime.store.Snapshot().CertifiedHead.HeadHash ||
		request.Activation.Bundle.Proof.LegacyPolicy != original {
		t.Fatal("migration was not bound to current parent and original owner")
	}
	after, _ := os.ReadFile(filepath.Join(dir, controlJournalName))
	if !bytes.Equal(before, after) {
		t.Fatal("preparation changed original journal")
	}
	first, err := runtime.activateRuntime(request.Activation, request.Operation)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := runtime.activateRuntime(request.Activation, request.Operation)
	if err != nil || !wire.EqualCanonical(first, replay) {
		t.Fatal("exact migration retry changed receipt", err)
	}
}

func TestControlMigrationRefusesDroppingSourceDevices(t *testing.T) {
	dir, _ := newAdminRotationFixture(t, true)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	application, proofs := controlInviteApplication(t, runtime)
	source, registry := filepath.Join(t.TempDir(), "source.yaml"), filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(source, []byte(application.LegacySSOT), 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema":2,"clients":[],"invites":[]}`)
	if err := os.WriteFile(registry, raw, 0600); err != nil {
		t.Fatal(err)
	}
	application.LegacyRegistryHash = wire.HashRaw("loom-legacy-registry-migration-v1", raw)
	input := controlMigrationInputV1{Schema: 1, Source: source, Registry: registry, Application: application, RecoveryProofs: proofs}
	if err := validateControlMigrationSource(&input); err == nil || !strings.Contains(err.Error(), "缺少原 SSOT") {
		t.Fatal("empty application replaced existing network", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "migration-receipt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed preparation wrote a receipt", err)
	}
}

func controlMigratedDeviceRuntime(t *testing.T, change func(*controlApplicationV1, *controlRuntime)) (*controlRuntime, string, wire.RuntimeDeviceMigrationLeafV1, controlCertifiedOperationResultV1) {
	t.Helper()
	dir, admin := newAdminRotationFixture(t, true)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	application, proofs := controlInviteApplication(t, runtime)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
	const deviceID = "demo-existing-device"
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	endpoint := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: application.ClusterID, DeviceID: deviceID,
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	active := wire.DeviceActiveViewV1{IdentitySPKIHash: identityHash, Membership: membership, Responsibilities: responsibilities,
		Grants: grants, EndpointBundle: endpoint, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}}
	active.MembershipHash, _ = wire.HashObject("loom-enrollment-membership-v1", membership)
	active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&endpoint)
	active.SecretArtifactRefsRoot, _ = wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	application.Devices = []controlDeviceStateV1{{View: wire.DeviceViewPayloadV2{Schema: 2,
		ClusterID: application.ClusterID, DeviceID: deviceID, DeviceGeneration: 1, State: "active", Active: &active},
		PreviousViewHash: wire.EmptyHashV1, SecretArtifactRefs: []wire.SecretArtifactRefV2{}}}
	hash := func(value string) string { return wire.HashRaw("demo-migration-test", []byte(value)) }
	profileHash, _ := wire.DeviceCertificateProfileStateHash(&application.CARegistry.DeviceProfiles[0])
	coordinate := wire.IssuanceLogCoordinateV1{RecoveryEpoch: 2, RaftIndex: runtime.storage.SnapshotRaft().CommitIndex + 1}
	migration := wire.RuntimeDeviceMigrationLeafV1{Schema: 1, ClusterID: application.ClusterID, DeviceID: deviceID,
		Platform: "android", IdentitySPKIHash: identityHash, WrappingKeyHash: hash("wrapping-key"),
		DeviceCertificateHash: hash("certificate"), DeviceCertificateProfileHash: profileHash, Issuance: coordinate,
		LegacyFloor: wire.BootstrapDeviceFloorLeafV1{Schema: 1, DeviceID: deviceID, V1Generation: 9,
			V1SignedCurrentHash: hash("signed-current"), V1PayloadHash: hash("payload")}}
	application.DeviceMigrations = []wire.RuntimeDeviceMigrationLeafV1{migration}
	if change != nil {
		change(&application, runtime)
	}
	input := controlMigrationInputV1{Schema: 1, Application: application, RecoveryProofs: proofs}
	inputHash, _ := wire.HashObject("loom-control-migration-input-v1", input)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	platform := filepath.Join(t.TempDir(), "platform.key")
	if err := os.WriteFile(platform, []byte(base64.StdEncoding.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	request, err := runtime.prepareControlMigration(input, inputHash, admin, platform, "demo retain identity")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash); err == nil {
		t.Fatal("尚未提交的迁移输入被当成 active identity")
	}
	result, err := runtime.activateRuntime(request.Activation, request.Operation)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, admin, migration, *result
}

func TestControlMigrationIdentityReaderUsesOriginalCertifiedJournal(t *testing.T) {
	runtime, _, migration, result := controlMigratedDeviceRuntime(t, nil)
	deviceID, identityHash, coordinate := migration.DeviceID, migration.IdentitySPKIHash, migration.Issuance
	identity, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil || identity.Record.DeviceID != deviceID || identity.Record.IdentitySPKIHash != identityHash ||
		identity.Record.Issuance != coordinate || len(identity.DeviceConfigUpdates) != 1 || identity.Head.HeadHash != result.Head.HeadHash {
		t.Fatal("身份 reader 没有使用原认证迁移日志", err)
	}
	if _, found := runtime.enrollmentStore.SnapshotRecord(deviceID); found {
		t.Fatal("迁移伪造了 Enrollment 记录")
	}
	replayed, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := replayed.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil || !wire.EqualCanonical(identity, restored) {
		t.Fatal("重启未重放同一迁移身份", err)
	}
}
