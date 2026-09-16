package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrepareMigrationMaterialsRetainsOriginalJournalAndExactKeys(t *testing.T) {
	dir, _ := newAdminRotationFixture(t, true)
	now := time.Now().UTC().Truncate(time.Second)
	before := map[string][]byte{}
	for _, name := range []string{controlConfigName, controlSecretsName, controlJournalName, controlRaftName, controlStateName} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = raw
	}
	ports := map[string]int64{"enroll": 18301, "device_config": 18302, "device_report": 18303}
	first, err := prepareControlMigrationMaterials(dir, "demo-cutover", ports, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := prepareControlMigrationMaterials(dir, "demo-cutover", ports, now.Add(time.Hour))
	if err != nil || !wire.EqualCanonical(first, again) {
		t.Fatal("重试替换了材料", err)
	}
	for name, original := range before {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(raw, original) {
			t.Fatal("材料准备改写了原控制状态", name, err)
		}
	}
	if _, err := prepareControlMigrationMaterials(dir, "demo-other-cutover", ports, now); err == nil {
		t.Fatal("替换固定迁移请求仍成功")
	}
}
