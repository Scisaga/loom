package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
