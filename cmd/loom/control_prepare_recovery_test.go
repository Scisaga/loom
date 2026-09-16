package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestRecoveryPreparationReadsOriginalKeyAndRejectsLostCustody(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "recovery")
	now := time.Now().UTC().Truncate(time.Second)
	first, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-first", now)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(dir, "recovery-key-artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-first", now.Add(time.Hour))
	if err != nil || !wire.EqualCanonical(first, again) {
		t.Fatal("相同请求更换了材料", err)
	}
	if wire.VerifyRecoveryPrivateCustody(&again.Policy, &again.Custody, now.Add(time.Hour), 0) == nil {
		t.Fatal("旧回执被当成当前可用性")
	}
	fresh, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-refresh", now.Add(time.Hour))
	if err != nil || !wire.EqualCanonical(first.Policy.Keys, fresh.Policy.Keys) || first.Custody.PrivateKeyCustodyRoot == fresh.Custody.PrivateKeyCustodyRoot {
		t.Fatal("刷新回执改变了原 recovery key 或没有产生新证据", err)
	}
	current, err := os.ReadFile(filepath.Join(dir, "recovery-key-artifact.json"))
	if err != nil || !bytes.Equal(keyBytes, current) {
		t.Fatal("刷新改变了原封装", err)
	}
	if _, err := prepareControlRecovery(dir, "demo-other-cluster", "demo-policy", "demo-custodian", "demo-other", now); err == nil {
		t.Fatal("旧保管目录被重新绑定到其他网络")
	}
	path := filepath.Join(dir, "software-material", "custody.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-after-loss", now); err == nil {
		t.Fatal("丢失保管 key 后仍出具可用性证明")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("丢失的保管 key 被自动替换", err)
	}
}

func TestRecoveryCustodyVerifiesKeysReceiptsAndFreshness(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := filepath.Join(t.TempDir(), "recovery")
	original, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-first", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.RecoveryKeyPossessionRoot(&original.Policy, original.Proofs); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*controlRecoveryMaterialV1){
		"missing":      func(p *controlRecoveryMaterialV1) { p.Custody.Bindings = nil },
		"wrong-policy": func(p *controlRecoveryMaterialV1) { p.Custody.PolicyID = "demo-other-policy" },
		"wrong-key": func(p *controlRecoveryMaterialV1) {
			p.Custody.Bindings[0].Artifact.PublicKey = p.Custody.Bindings[0].Artifact.Custodians[0].ReceiptPublicKey
		},
		"wrong-ciphertext": func(p *controlRecoveryMaterialV1) {
			p.Custody.Bindings[0].AvailabilityReceipts[0].Body.ArtifactOrVersionDigest = wire.EmptyHashV1
		},
		"wrong-unseal-signature": func(p *controlRecoveryMaterialV1) {
			p.Custody.Bindings[0].AvailabilityReceipts[0].Body.RecoveryKeyTestSignature = strings.Repeat("A", 86)
		},
		"wrong-receipt-signature": func(p *controlRecoveryMaterialV1) {
			p.Custody.Bindings[0].AvailabilityReceipts[0].ReceiptSignature = strings.Repeat("A", 86)
		},
		"wrong-recipient": func(p *controlRecoveryMaterialV1) {
			p.Custody.Bindings[0].AvailabilityReceipts[0].Body.RecipientKey.RecipientKeyGeneration++
		},
		"missing-recipient": func(p *controlRecoveryMaterialV1) { p.Custody.Bindings[0].Artifact.Custodians[0].RecipientKey = nil },
		"duplicate-receipt": func(p *controlRecoveryMaterialV1) {
			b := &p.Custody.Bindings[0]
			b.AvailabilityReceipts = append(b.AvailabilityReceipts, b.AvailabilityReceipts[0])
		},
		"made-up-root": func(p *controlRecoveryMaterialV1) {
			p.Policy.PrivateKeyCustodyRoot = wire.EmptyHashV1
			p.Custody.PrivateKeyCustodyRoot = wire.EmptyHashV1
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := controlClone(original)
			mutate(&value)
			if wire.VerifyRecoveryPrivateCustody(&value.Policy, &value.Custody, now, 0) == nil {
				t.Fatal("篡改的恢复材料仍被接受")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(901 * time.Second)} {
		if wire.VerifyRecoveryPrivateCustody(&original.Policy, &original.Custody, at, 0) == nil {
			t.Fatal("未来或过期回执仍被接受")
		}
	}
	ref := original.Custody.Bindings[0].Artifact.KeyArtifactRef
	path := filepath.Join(dir, "sealed-artifacts", strings.TrimPrefix(ref.SealedBlob.CiphertextDigest, "sha256:")+".json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareControlRecovery(dir, "demo-cluster", "demo-policy", "demo-custodian", "demo-tampered-store", now); err == nil {
		t.Fatal("没有真正解封损坏介质就签发了新回执")
	}
}

func TestActivationRejectsExpiredRecoveryCustodyBeforeCommit(t *testing.T) {
	runtime, _ := controlInviteRuntime(t)
	activation := runtime.journal.Records[0].Activation
	if activation == nil {
		t.Fatal("缺真实迁移记录")
	}
	// 在不改变 policy、密文和任何签名的情况下，提交时间越过回执有效期仍必须拒绝。
	original := runtime.journal.Records[0].Candidate.Body.Payload.CommittedLogicalTime
	at, err := wire.ParseTimeZ(original)
	if err != nil {
		t.Fatal(err)
	}
	runtime.journal.Records[0].Candidate.Body.Payload.CommittedLogicalTime = at.Add(time.Hour).Format(time.RFC3339)
	if err := runtime.verifyActivationRecord(0); err == nil || !strings.Contains(err.Error(), "回执过期") {
		t.Fatal("实际日志验证未拒绝过期保管回执", err)
	}
}
