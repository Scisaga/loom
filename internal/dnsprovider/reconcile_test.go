package dnsprovider

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type fixedResolver struct {
	id      string
	set     RRSet
	instant time.Time
	err     error
}

func (r fixedResolver) ID() string { return r.id }

func (r fixedResolver) Resolve(context.Context, string, string, string) (Readback, error) {
	return Readback{RRSet: r.set, ObservedAt: r.instant}, r.err
}

func dnsIntent(t *testing.T, operation string, set RRSet) CertifiedRRSetIntentV1 {
	t.Helper()
	hash, err := RRSetHash(set)
	if err != nil {
		t.Fatal(err)
	}
	return CertifiedRRSetIntentV1{
		Schema: 1, ClusterID: "demo-cluster", OperationID: operation,
		CertifiedHeadHash:       wire.HashRaw("test-dns-head-v1", []byte(operation)),
		PublicAccessProfileHash: wire.HashRaw("test-public-profile-v1", []byte("profile")),
		RRSet:                   set, RRSetHash: hash,
	}
}

func TestReconcileRequiresAuthorityAndTwoExactExternalResolvers(t *testing.T) {
	instant := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	set := RRSet{Zone: "example.test", Name: "demo-edge", Type: "A", TTL: 300, Values: []string{"203.0.113.10"}}
	provider := NewMemory()
	provider.now = func() time.Time { return instant }
	resolvers := []Resolver{
		fixedResolver{id: "resolver-a", set: set, instant: instant},
		fixedResolver{id: "resolver-b", set: set, instant: instant},
	}
	path := filepath.Join(t.TempDir(), "dns.json")
	reconciler, err := OpenReconciler(path, provider, resolvers, func(intent *CertifiedRRSetIntentV1) error {
		if intent.OperationID != "allowed" {
			return errors.New("not certified")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), dnsIntent(t, "denied", set)); err == nil {
		t.Fatal("未获 authority 的 DNS desired state 被执行")
	}
	if _, err := provider.Read(context.Background(), set.Zone, set.Name, set.Type); !errors.Is(err, ErrNotFound) {
		t.Fatal("authority 拒绝后 provider 被修改")
	}
	state, err := reconciler.Reconcile(context.Background(), dnsIntent(t, "allowed", set))
	if err != nil {
		t.Fatal(err)
	}
	if state.EvidenceHash == "" || len(state.Evidence.ExternalResolvers) != 2 {
		t.Fatalf("reconcile evidence 不完整: %#v", state)
	}
	reopened, err := OpenReconciler(path, provider, resolvers, func(*CertifiedRRSetIntentV1) error { return nil })
	if err != nil || reopened.Snapshot().EvidenceHash != state.EvidenceHash {
		t.Fatalf("reconcile LKG 未耐久恢复: %#v err=%v", reopened, err)
	}
}

func TestFailedExternalVerificationKeepsPreviousLKG(t *testing.T) {
	instant := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	one := RRSet{Zone: "example.test", Name: "demo-edge", Type: "A", TTL: 300, Values: []string{"203.0.113.10"}}
	two := RRSet{Zone: "example.test", Name: "demo-edge", Type: "A", TTL: 300, Values: []string{"203.0.113.11"}}
	provider := NewMemory()
	provider.now = func() time.Time { return instant }
	resolvers := []Resolver{
		fixedResolver{id: "resolver-a", set: one, instant: instant},
		fixedResolver{id: "resolver-b", set: one, instant: instant},
	}
	reconciler, err := OpenReconciler(filepath.Join(t.TempDir(), "dns.json"), provider, resolvers, func(*CertifiedRRSetIntentV1) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	first, err := reconciler.Reconcile(context.Background(), dnsIntent(t, "operation-1", one))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), dnsIntent(t, "operation-2", two)); err == nil {
		t.Fatal("external resolvers 未收敛时错误激活了新 DNS")
	}
	after := reconciler.Snapshot()
	if after.EvidenceHash != first.EvidenceHash || after.ActiveIntent.OperationID != "operation-1" {
		t.Fatalf("失败 reconcile 覆盖了旧 LKG: %#v", after)
	}
}

func TestReconcileRejectsDuplicateResolverIdentity(t *testing.T) {
	set := RRSet{Zone: "example.test", Name: "demo-edge", Type: "A", TTL: 300, Values: []string{"203.0.113.10"}}
	resolvers := []Resolver{fixedResolver{id: "same", set: set}, fixedResolver{id: "same", set: set}}
	if _, err := OpenReconciler(filepath.Join(t.TempDir(), "dns.json"), NewMemory(), resolvers, func(*CertifiedRRSetIntentV1) error { return nil }); err == nil {
		t.Fatal("重复 resolver identity 被计为两个外部观察点")
	}
}

func TestReconcileRejectsNilResolverWithoutPanic(t *testing.T) {
	if _, err := OpenReconciler(filepath.Join(t.TempDir(), "dns.json"), NewMemory(), []Resolver{nil, fixedResolver{id: "resolver-b"}}, func(*CertifiedRRSetIntentV1) error { return nil }); err == nil {
		t.Fatal("nil resolver 被接受")
	}
}
