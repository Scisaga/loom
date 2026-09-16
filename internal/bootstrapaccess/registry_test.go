package bootstrapaccess

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestCredentialRegistryAcceptsOnlyVerifierEvidenceForExactIngress(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	if verified.TransportCredential() == "" || verified.TransportCredential() == verified.CapabilityID() {
		t.Fatal("transport credential 未从完整已签 capability 独立派生")
	}
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	authenticated, ok := registry.authenticate(verified.TransportCredential())
	if !ok || authenticated.CapabilityID() != verified.CapabilityID() {
		t.Fatalf("认证结果未保留 verified evidence:ok=%v", ok)
	}
	if _, ok := registry.authenticate(verified.CapabilityID()); ok {
		t.Fatal("public capability ID 被当作 transport bearer")
	}
	if _, err := NewCredentialRegistry(wire.HashRaw("test-ingress", []byte("other")),
		[]wire.VerifiedBootstrapCapabilityV1{verified}); err == nil {
		t.Fatal("跨 ingress capability 被注册")
	}
	if _, err := NewCredentialRegistry(ingressHash,
		[]wire.VerifiedBootstrapCapabilityV1{{}}); err == nil {
		t.Fatal("zero/调用方自称已验证的 capability 被注册")
	}
	// 保证本测试也走到 durable runtime，而不是只测一个字符串 map。
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.OpenSession(authenticated, "session-1", registry.IngressSetHash())
	if err != nil {
		t.Fatal(err)
	}
	session.Close()
}

func TestCredentialRegistryResolverUsesCurrentAuthorityForEverySession(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	for _, transport := range []string{"hysteria2", "trojan_tls"} {
		t.Run(transport, func(t *testing.T) {
			allowed, calls := true, 0
			registry, err := NewCredentialRegistryWithResolver(ingressHash, nil,
				func(_ context.Context, request wire.BootstrapCapabilityLookupRequestV1) (wire.VerifiedBootstrapCapabilityV1, error) {
					calls++
					if request.Transport != transport || request.IngressSetHash != ingressHash || !allowed {
						return wire.VerifiedBootstrapCapabilityV1{}, errors.New("revoked")
					}
					return verified, nil
				})
			if err != nil {
				t.Fatal(err)
			}
			manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
			if err != nil {
				t.Fatal(err)
			}
			var first *Session
			if transport == "hysteria2" {
				first, err = registry.openHysteria2Session(context.Background(), manager,
					verified.TransportCredential(), "session-1")
			} else {
				first, err = registry.openTrojanSession(context.Background(), manager,
					trojanCredentialKey(verified.TransportCredential()), "session-1")
			}
			if err != nil {
				t.Fatal(err)
			}
			first.Close()
			allowed = false
			if transport == "hysteria2" {
				_, err = registry.openHysteria2Session(context.Background(), manager,
					verified.TransportCredential(), "session-2")
			} else {
				_, err = registry.openTrojanSession(context.Background(), manager,
					trojanCredentialKey(verified.TransportCredential()), "session-2")
			}
			if err == nil || calls != 2 || len(registry.snapshot()) != 0 {
				t.Fatalf("动态 resolver 缓存或绕过当前撤权: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestCredentialRegistryReplaceIsAtomicAndSorted(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := wire.HashRaw("test-ingress", []byte("wrong"))
	if err := registry.Replace(wrongHash, []wire.VerifiedBootstrapCapabilityV1{verified}); err == nil {
		t.Fatal("无效 replace 被接受")
	}
	if _, ok := registry.authenticate(verified.TransportCredential()); !ok || registry.IngressSetHash() != ingressHash {
		t.Fatal("失败 replace 改坏旧认证表")
	}
	if err := registry.Replace(ingressHash, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.authenticate(verified.TransportCredential()); ok || len(registry.snapshot()) != 0 {
		t.Fatal("空 certified set 未原子撤销旧 credential")
	}
}
