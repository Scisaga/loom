package bootstrapaccess

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/rotation"
)

func TestBootstrapLocalReadinessProbesStartedCertifiedGeneration(t *testing.T) {
	observerA, privateA := outerObserver(t, "observer-a", "region-a", 0x61)
	observerB, privateB := outerObserver(t, "observer-b", "region-b", 0x62)
	policy := BootstrapOuterEvidencePolicyV1{
		Schema: 1, ClusterID: "demo-cluster", PolicyID: "bootstrap-external-v1",
		MinimumExternalObservers: 2, MinimumExternalFailureDomains: 2,
		MaximumObservationAgeSeconds: 300,
		Observers:                    []BootstrapOuterObserverV1{observerA, observerB},
	}
	policyHash, err := BootstrapOuterEvidencePolicyHash(&policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"trojan_tls", "hysteria2"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newRuntimePlanFixtureWithEvidencePolicy(t, transport, "direct_standard", policyHash)
			runtimePlan, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
				&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
				fixture.endpointID, fixture.generation, fixture.now, 2)
			if err != nil {
				t.Fatal(err)
			}
			manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewCredentialRegistry(fixture.catalog.BootstrapIngressSetHash, nil)
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
				Plan: runtimePlan, Manager: manager, Registry: registry, TLSConfig: fixture.tlsConfig,
				Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
				HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
				MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done, err := runtime.Start(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			if _, err := runtime.Start(ctx); err == nil {
				cancel()
				t.Fatal("同一 runtime 获准并发启动第二批 listener")
			}
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("runtime shutdown: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("runtime cancel 后未退出")
				}
			}()
			roots := x509.NewCertPool()
			certificate, err := x509.ParseCertificate(fixture.tlsConfig.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots.AddCert(certificate)
			local, err := VerifyBootstrapLocalReadiness(ctx, runtime, fixture.authorized,
				BootstrapLocalReadinessOptions{TLSConfig: &tls.Config{RootCAs: roots},
					Now: func() time.Time { return fixture.now }, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			evidence := local.Evidence()
			if local.EvidenceHash() == "" || len(evidence.Results) != 1 ||
				evidence.Results[0].BindTuple != runtimePlan.Bindings()[0].Tuple() ||
				evidence.Results[0].TLSVersion != int64(tls.VersionTLS13) ||
				transport == "hysteria2" && evidence.Results[0].NegotiatedProtocol != "h3" ||
				transport == "trojan_tls" && evidence.Results[0].NegotiatedProtocol != "" ||
				len(manager.SnapshotUsage()) != 0 {
				t.Fatalf("local readiness/accounting 异常 evidence=%#v usage=%#v",
					evidence, manager.SnapshotUsage())
			}

			outerPlan, err := BuildBootstrapOuterProbePlan(runtimePlan, fixture.authorized)
			if err != nil {
				t.Fatal(err)
			}
			observations := []SignedBootstrapOuterProbeObservationV1{
				signOuterObservation(t, &outerPlan, observerA.ObserverID, privateA, fixture.now),
				signOuterObservation(t, &outerPlan, observerB.ObserverID, privateB, fixture.now),
			}
			external, err := VerifyBootstrapOuterReachability(&policy, fixture.authorized,
				runtimePlan, observations, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			transition := rotation.Transition{
				NextPhase: "advertised", CertifiedHeadHash: runtimePlanHash("advertised-head"),
				CertifiedAt:                      fixture.now.Format(time.RFC3339),
				LocalVerificationEvidenceHash:    local.EvidenceHash(),
				ExternalVerificationEvidenceHash: external.EvidenceHash(),
			}
			if err := ValidateBootstrapAdvertiseTransition(fixture.authorized, &transition, local, external); err != nil {
				t.Fatal(err)
			}
			wrong := transition
			wrong.LocalVerificationEvidenceHash = runtimePlanHash("forged-local")
			if err := ValidateBootstrapAdvertiseTransition(fixture.authorized, &wrong, local, external); err == nil {
				t.Fatal("任意 local evidence hash 被 advertise 接受")
			}
			expired := transition
			expired.CertifiedAt = fixture.now.Add(bootstrapLocalReadinessAge).Format(time.RFC3339)
			if err := local.validateAdvertiseTransition(fixture.authorized, &expired); err == nil {
				t.Fatal("过期 local readiness 被 advertise 重放")
			}
		})
	}
}

func TestBootstrapLocalReadinessRequiresStartedSocket(t *testing.T) {
	fixture := newRuntimePlanFixture(t, "trojan_tls", "direct_standard")
	runtimePlan, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
		&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
		fixture.endpointID, fixture.generation, fixture.now, 2)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(fixture.tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(fixture.catalog.BootstrapIngressSetHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
		Plan: runtimePlan, Manager: manager, Registry: registry, TLSConfig: fixture.tlsConfig,
		Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = VerifyBootstrapLocalReadiness(ctx, runtime, fixture.authorized,
		BootstrapLocalReadinessOptions{TLSConfig: &tls.Config{RootCAs: roots},
			Now: func() time.Time { return fixture.now }, Timeout: time.Second})
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("未启动 socket 的 local readiness 结果=%v", err)
	}
}
