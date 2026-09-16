package wire

import (
	"bytes"
	"testing"
)

func TestApplicationSnapshotProofRevealsOnlyRequestedSection(t *testing.T) {
	application, err := MarshalCanonical(map[string]any{"schema": 2, "cluster_id": "demo-cluster", "bootstrap_installation": map[string]any{"schema": 1, "endpoint": "demo-edge"},
		"legacy_ssot": "demo-private-source", "invites": []string{"demo-private-opening"}, "recovery_custody": "demo-private-custody"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ControlApplicationSnapshotHashV2(application)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildControlApplicationSectionProofV2(application, "bootstrap_installation")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyControlApplicationSectionProofV2(&proof, hash, "demo-cluster", "bootstrap_installation"); err != nil {
		t.Fatal(err)
	}
	encoded, _ := MarshalCanonical(proof)
	for _, private := range []string{"demo-private-source", "demo-private-opening", "demo-private-custody"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("部分证明泄露其他私有内容")
		}
	}
	for _, change := range []func(*ControlApplicationSectionProofV2){
		func(p *ControlApplicationSectionProofV2) { p.Content = []byte(`{"schema":1,"endpoint":"demo-other"}`) },
		func(p *ControlApplicationSectionProofV2) { p.Leaf.Name = "invites" },
		func(p *ControlApplicationSectionProofV2) { p.Leaf.ClusterID = "demo-other" },
		func(p *ControlApplicationSectionProofV2) { p.Snapshot.SectionCount++ },
		func(p *ControlApplicationSectionProofV2) { p.AuditPath = append(p.AuditPath, EmptyHashV1) },
	} {
		var modified ControlApplicationSectionProofV2
		if _, err := DecodeStrict(encoded, 1<<20, &modified); err != nil {
			t.Fatal(err)
		}
		change(&modified)
		if err := VerifyControlApplicationSectionProofV2(&modified, hash, "demo-cluster", "bootstrap_installation"); err == nil {
			t.Fatal("接受篡改部分证明")
		}
	}
	changed := bytes.Replace(application, []byte("demo-private-source"), []byte("demo-changed-source"), 1)
	otherHash, err := ControlApplicationSnapshotHashV2(changed)
	if err != nil || otherHash == hash {
		t.Fatal("其他私有字段未进入 snapshot 承诺")
	}
	if err := VerifyControlApplicationSectionProofV2(&proof, otherHash, "demo-cluster", "bootstrap_installation"); err == nil {
		t.Fatal("接受其他 snapshot 的部分证明")
	}
}
