package bootstrapaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/rotation"
	"loom/internal/wire"
)

func TestRunBootstrapOuterProbePerformsBearerFreeTransportHandshake(t *testing.T) {
	for _, transport := range []string{"hysteria2", "trojan_tls"} {
		t.Run(transport, func(t *testing.T) {
			instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
			_, ingressHash := verifiedCapability(t, instant)
			manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewCredentialRegistry(ingressHash, nil)
			if err != nil {
				t.Fatal(err)
			}
			roots, serverTLS, certificate := trojanCertificate(t, "bootstrap.example")
			var address net.Addr
			var tcpListener net.Listener
			var udpConnection net.PacketConn
			if transport == "trojan_tls" {
				tcpListener, err = net.Listen("tcp4", "127.0.0.1:0")
				if err == nil {
					address = tcpListener.Addr()
				}
			} else {
				udpConnection, err = net.ListenPacket("udp4", "127.0.0.1:0")
				if err == nil {
					address = udpConnection.LocalAddr()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			binding := testListenerBinding(t, transport, ingressHash, "bootstrap.example", address, certificate)
			listening := make(chan struct{})
			runtime, err := NewBootstrapIngressRuntime(BootstrapIngressRuntimeOptions{
				Plan:    BootstrapIngressRuntimePlanV1{bindings: []VerifiedBootstrapListenerV1{binding}},
				Manager: manager, Registry: registry, TLSConfig: serverTLS,
				Dial:             func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
				HandshakeTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
				MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
				ListenTCP: func(context.Context, string, string) (net.Listener, error) {
					if tcpListener == nil {
						return nil, errors.New("HY2 probe 不应创建 TCP listener")
					}
					close(listening)
					return tcpListener, nil
				},
				ListenUDP: func(context.Context, string, string) (net.PacketConn, error) {
					if udpConnection == nil {
						return nil, errors.New("Trojan probe 不应创建 UDP listener")
					}
					close(listening)
					return udpConnection, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- runtime.Serve(ctx) }()
			select {
			case <-listening:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("bootstrap runtime 未进入 listen")
			}
			plan := outerProbePlanForBinding(t, binding)
			privateKey := outerObserverPrivateKey(0x31)
			report, probeErr := RunBootstrapOuterProbe(context.Background(), &plan, BootstrapOuterProbeOptions{
				ObserverID: "observer-a", PrivateKey: privateKey, TLSConfig: &tls.Config{RootCAs: roots},
				Now: func() time.Time { return instant }, Timeout: 5 * time.Second,
			})
			wrongPinPlan := plan
			wrongPinPlan.SPKIPins = []string{runtimePlanHash("wrong-spki")}
			_, wrongPinErr := RunBootstrapOuterProbe(context.Background(), &wrongPinPlan, BootstrapOuterProbeOptions{
				ObserverID: "observer-a", PrivateKey: privateKey, TLSConfig: &tls.Config{RootCAs: roots},
				Now: func() time.Time { return instant }, Timeout: 5 * time.Second,
			})
			cancel()
			select {
			case serveErr := <-done:
				if serveErr != nil {
					t.Fatal(serveErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("bootstrap runtime 取消后未退出")
			}
			if probeErr != nil {
				t.Fatal(probeErr)
			}
			if wrongPinErr == nil {
				t.Fatal("合法 WebPKI handshake 绕过了 certified SPKI pin")
			}
			if len(report.Body.Results) != 1 || report.Body.Results[0].Target != plan.Targets[0] ||
				report.Body.Results[0].TLSVersion != int64(tls.VersionTLS13) ||
				report.Signature.Signature == "" || len(manager.SnapshotUsage()) != 0 {
				t.Fatalf("outer probe/report/accounting 异常 report=%#v usage=%#v",
					report, manager.SnapshotUsage())
			}
		})
	}
}

func TestBootstrapOuterReachabilityRequiresFrozenMultiDomainEvidence(t *testing.T) {
	observerA, privateA := outerObserver(t, "observer-a", "region-a", 0x41)
	observerB, privateB := outerObserver(t, "observer-b", "region-b", 0x42)
	policy := BootstrapOuterEvidencePolicyV1{
		Schema: 1, ClusterID: "demo-cluster", PolicyID: "bootstrap-external-v1",
		MinimumExternalObservers: 2, MinimumExternalFailureDomains: 2,
		MaximumObservationAgeSeconds: 60,
		Observers:                    []BootstrapOuterObserverV1{observerA, observerB},
	}
	policyHash, err := BootstrapOuterEvidencePolicyHash(&policy)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newRuntimePlanFixtureWithEvidencePolicy(t, "hysteria2", "nat_mapped", policyHash)
	runtimePlan, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
		&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
		fixture.endpointID, fixture.generation, fixture.now, 2)
	if err != nil {
		t.Fatal(err)
	}
	probePlan, err := BuildBootstrapOuterProbePlan(runtimePlan, fixture.authorized)
	if err != nil {
		t.Fatal(err)
	}
	if len(probePlan.Targets) != 1 || probePlan.Targets[0] != (rotation.Tuple{
		Transport: "udp", Address: "203.0.113.10", Port: 30443,
	}) || runtimePlan.Bindings()[0].Tuple() != (rotation.Tuple{
		Transport: "udp", Address: "10.0.0.10", Port: 24443,
	}) {
		t.Fatalf("NAT public/local probe binding 错误 public=%#v local=%#v",
			probePlan.Targets, runtimePlan.Bindings()[0].Tuple())
	}
	reports := []SignedBootstrapOuterProbeObservationV1{
		signOuterObservation(t, &probePlan, observerA.ObserverID, privateA, fixture.now),
		signOuterObservation(t, &probePlan, observerB.ObserverID, privateB, fixture.now),
	}
	verifiedAt := fixture.now.Add(10 * time.Second)
	verified, err := VerifyBootstrapOuterReachability(&policy, fixture.authorized, runtimePlan,
		reports, verifiedAt)
	if err != nil || verified.EvidenceHash() == "" {
		t.Fatalf("multi-domain evidence verify=%#v err=%v", verified, err)
	}
	stored := verified.Evidence()
	reopened, err := VerifyBootstrapOuterReachabilityEvidence(&policy, fixture.authorized,
		runtimePlan, &stored)
	if err != nil || reopened.EvidenceHash() != verified.EvidenceHash() {
		t.Fatalf("stored evidence 未确定性重验 hash=%q want=%q err=%v",
			reopened.EvidenceHash(), verified.EvidenceHash(), err)
	}
	transition := rotation.Transition{
		NextPhase: "advertised", CertifiedHeadHash: runtimePlanHash("advertise-head"),
		CertifiedAt:                      verifiedAt.Add(time.Second).Format(time.RFC3339),
		LocalVerificationEvidenceHash:    runtimePlanHash("local-verification"),
		ExternalVerificationEvidenceHash: verified.EvidenceHash(),
	}
	if err := verified.validateAdvertiseTransition(fixture.authorized, &transition); err != nil {
		t.Fatal(err)
	}
	if _, err := rotation.Advance(fixture.authorized.Intent(), fixture.authorized.State(), transition); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyBootstrapOuterReachability(&policy, fixture.authorized, runtimePlan,
		reports[:1], verifiedAt); err == nil {
		t.Fatal("单 observer 绕过 multi-observer threshold")
	}
	tampered := append([]SignedBootstrapOuterProbeObservationV1(nil), reports...)
	tampered[1] = cloneSignedBootstrapOuterObservation(tampered[1])
	tampered[1].Body.Results[0].Target.Port++
	if _, err := VerifyBootstrapOuterReachability(&policy, fixture.authorized, runtimePlan,
		tampered, verifiedAt); err == nil {
		t.Fatal("被篡改或不完整的 public tuple observation 被接受")
	}
	if _, err := VerifyBootstrapOuterReachability(&policy, fixture.authorized, runtimePlan,
		reports, fixture.now.Add(61*time.Second)); err == nil {
		t.Fatal("过期 external observations 被接受")
	}
	late := transition
	late.CertifiedAt = stored.ValidUntil
	if err := verified.validateAdvertiseTransition(fixture.authorized, &late); err == nil {
		t.Fatal("evidence expiry 时仍允许 advertise")
	}
}

func outerProbePlanForBinding(t *testing.T, binding VerifiedBootstrapListenerV1) BootstrapOuterProbePlanV1 {
	t.Helper()
	projection := binding.projection
	plan := BootstrapOuterProbePlanV1{
		Schema: 1, ClusterID: projection.ClusterID, RotationID: "demo-rotation",
		FrozenDependenciesHash: runtimePlanHash("frozen"), EndpointSetHash: projection.IngressSetHash,
		EndpointID: projection.EndpointID, LogicalServerID: projection.LogicalServerID,
		Transport: projection.Transport, ListenerGeneration: projection.ListenerGeneration,
		ServerName: projection.ServerName, SPKIPins: append([]string(nil), projection.SPKIPins...),
		Targets: binding.PublicTuples(), ValidFrom: projection.ValidFrom, ValidUntil: projection.ValidUntil,
	}
	if _, err := BootstrapOuterProbePlanHash(&plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func outerObserver(t *testing.T, observerID, failureDomain string,
	seed byte) (BootstrapOuterObserverV1, ed25519.PrivateKey) {
	t.Helper()
	privateKey := outerObserverPrivateKey(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := bootstrapOuterObserverKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return BootstrapOuterObserverV1{ObserverID: observerID, FailureDomain: failureDomain,
		ObserverKeyID: keyID, ObserverPublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}, privateKey
}

func outerObserverPrivateKey(seed byte) ed25519.PrivateKey {
	raw := make([]byte, ed25519.SeedSize)
	raw[len(raw)-1] = seed
	return ed25519.NewKeyFromSeed(raw)
}

func signOuterObservation(t *testing.T, plan *BootstrapOuterProbePlanV1, observerID string,
	privateKey ed25519.PrivateKey, observedAt time.Time) SignedBootstrapOuterProbeObservationV1 {
	t.Helper()
	planHash, err := BootstrapOuterProbePlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]BootstrapOuterProbeResultV1, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		protocol := ""
		if plan.Transport == "hysteria2" {
			protocol = "h3"
		}
		results = append(results, BootstrapOuterProbeResultV1{Target: target,
			TLSVersion: int64(tls.VersionTLS13), NegotiatedProtocol: protocol,
			LeafSPKIHash: plan.SPKIPins[0]})
	}
	body := BootstrapOuterProbeObservationV1{Schema: 1, ClusterID: plan.ClusterID,
		ObserverID: observerID, ProbePlanHash: planHash,
		ObservedAt: observedAt.UTC().Truncate(time.Second).Format(time.RFC3339), Results: results}
	canonical, err := wire.MarshalCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	message, err := wire.Frame(domainBootstrapOuterProbeSignature, canonical)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := bootstrapOuterObserverKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return SignedBootstrapOuterProbeObservationV1{Body: body, Signature: BootstrapOuterProbeSignatureV1{
		Algorithm: "ed25519", ObserverKeyID: keyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
	}}
}
