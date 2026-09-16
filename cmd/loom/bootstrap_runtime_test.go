package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/wire"
)

func testCertifiedBootstrapRuntime(t *testing.T, request controlPrepareBootstrapInputV1, roots *x509.CertPool, materials string) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpPort := int64(udp.LocalAddr().(*net.UDPAddr).Port)
	_ = udp.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := int64(tcp.Addr().(*net.TCPAddr).Port)
	_ = tcp.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device := request.Listeners[0].Profile.ServerID
	runtime, adminDir, _, _ := controlMigratedDeviceRuntime(t, func(app *controlApplicationV1, runtime *controlRuntime) {
		app.Schema = 2
		app.Authorizations[0].AllowedOperationKinds = append(app.Authorizations[0].AllowedOperationKinds,
			controlAdvertiseBootstrapKind)
		sort.Strings(app.Authorizations[0].AllowedOperationKinds)
		bindBootstrapFixtureSource(t, app, device)
		input := controlClone(request)
		for i := range input.Listeners {
			listener := &input.Listeners[i]
			listener.Resources.HY2LocalUDPPortPool = []int64{udpPort}
			listener.Resources.TrojanLocalTCPPortPool = []int64{tcpPort}
			listener.Profile.ForwardListenerResourcesHash, _ = wire.ForwardServerListenerResourcesHash(&listener.Resources)
			listener.PublicPort = udpPort
			if listener.Transport == "trojan_tls" {
				listener.PublicPort = tcpPort
			}
		}
		state := runtime.store.Snapshot()
		qc, _ := wire.MarshalCanonical(state.CertifiedQC)
		plan, err := prepareInitialBootstrapPlan(input, controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID, Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet}, roots, runtime.now())
		if err != nil {
			t.Fatal(err)
		}
		app.BootstrapInstallation = &plan
		app.BootstrapCatalog = plan.Catalog
		app.BootstrapIssuers[0].Active.PermittedIngressSetHashes = []string{plan.Catalog.BootstrapIngressSetHash}
	}, private)
	bundle, err := runtime.bootstrapInstallationDeliveryLocked(device)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wire.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"legacy_ssot"`, `"opening"`, `"recovery_custody"`} {
		if bytes.Contains(body, []byte(field)) {
			t.Fatalf("公开安装部分泄露 %s", field)
		}
	}
	if _, err := verifyBootstrapInstallationBundle(bundle, public, device); err != nil {
		t.Fatal(err)
	}
	staticRoot := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(staticRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticRoot, "index.html"), []byte("<!doctype html><title>Welcome</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	publicConfig := filepath.Join(t.TempDir(), "bootstrap-public.conf")
	if err := renderBootstrapPublicNginx(bundle, public, device, materials, staticRoot,
		publicConfig, roots, runtime.now().UTC()); err != nil {
		t.Fatal(err)
	}
	configBody, err := os.ReadFile(publicConfig)
	if err != nil {
		t.Fatal(err)
	}
	wantListen := "listen " + strconv.FormatInt(request.Listeners[0].Resources.NginxLocalTCPPort, 10) + " ssl;"
	if !strings.Contains(string(configBody), wantListen) || strings.Contains(string(configBody), "proxy_pass") ||
		strings.Contains(string(configBody), "/enroll") {
		t.Fatalf("公网 Nginx 未使用认证 local port 或泄露动态入口:\n%s", configBody)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := filepath.Join(t.TempDir(), "runtime")
	running, err := startPreparedBootstrapRuntime(ctx, bundle, public, device, state, materials, roots, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(running.generations) != 2 {
		running.Close()
		t.Fatal("未启动 HY2 与独立 TCP")
	}
	files, err := filepath.Glob(filepath.Join(state, "*-readiness.json"))
	if err != nil || len(files) != 2 {
		running.Close()
		t.Fatal("缺实际 local verify 回执")
	}
	readiness := make([]bootstrapPreparedReadinessV1, 0, len(files))
	for _, file := range files {
		var ready bootstrapPreparedReadinessV1
		if err := readCanonicalFile(file, 1<<20, &ready); err != nil {
			running.Close()
			t.Fatal(err)
		}
		if len(ready.LocalEvidence.Results) != 1 || ready.LocalEvidenceHash == "" || ready.LocalEvidence.Results[0].TLSVersion == 0 {
			running.Close()
			t.Fatal("local evidence 不来自真实握手")
		}
		readiness = append(readiness, ready)
	}
	observerKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	payload := controlBootstrapAdvertisementPayloadV1{Schema: 1,
		PreparedHeadHash: bundle.Activation.Head.HeadHash,
		PreparedAt:       bundle.Activation.Head.Body.Payload.CommittedLogicalTime}
	for _, ready := range readiness {
		planHash, err := bootstrapaccess.BootstrapOuterProbePlanHash(&ready.OuterPlan)
		if err != nil {
			running.Close()
			t.Fatal(err)
		}
		results := make([]bootstrapaccess.BootstrapOuterProbeResultV1, 0, len(ready.OuterPlan.Targets))
		for _, target := range ready.OuterPlan.Targets {
			protocol := ""
			if ready.OuterPlan.Transport == "hysteria2" {
				protocol = "h3"
			}
			results = append(results, bootstrapaccess.BootstrapOuterProbeResultV1{Target: target,
				TLSVersion: int64(tls.VersionTLS13), NegotiatedProtocol: protocol,
				LeafSPKIHash: ready.OuterPlan.SPKIPins[0]})
		}
		observation := bootstrapaccess.SignedBootstrapOuterProbeObservationV1{Body: bootstrapaccess.BootstrapOuterProbeObservationV1{
			Schema: 1, ClusterID: ready.OuterPlan.ClusterID, ObserverID: "demo-observer",
			ProbePlanHash: planHash, ObservedAt: runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339), Results: results}}
		canonical, _ := wire.MarshalCanonical(observation.Body)
		message, _ := wire.Frame("loom-bootstrap-outer-probe-signature-v1", canonical)
		keyID := installationObserverKeyID(request, ready.OuterPlan.EndpointID)
		observation.Signature = bootstrapaccess.BootstrapOuterProbeSignatureV1{Algorithm: "ed25519", ObserverKeyID: keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(observerKey, message))}
		payload.Entries = append(payload.Entries, controlBootstrapAdvertisementEntryV1{EndpointID: ready.OuterPlan.EndpointID,
			Local: ready.LocalEvidence, Observations: []bootstrapaccess.SignedBootstrapOuterProbeObservationV1{observation}})
	}
	sort.Slice(payload.Entries, func(i, j int) bool { return payload.Entries[i].EndpointID < payload.Entries[j].EndpointID })
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	status := serveRuntimeStatus(t, runtime, peer)
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		running.Close()
		t.Fatal(err)
	}
	payloadHash, err := controlBootstrapAdvertisementHash(payload)
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	advertise, err := newControlSignedRequest(adminDir, endpoint, status, controlAdvertiseBootstrapKind,
		payloadHash, "demo-bootstrap-advertise", "demo external readiness", runtime.now())
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	advertise.Payload, _ = wire.MarshalCanonical(payload)
	currentApplication, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	preparedHead, err := runtime.bootstrapPreparedHeadBefore(len(runtime.journal.Records), currentApplication, payload)
	if err == nil {
		_, _, err = currentApplication.reduceBootstrapAdvertisement(payload, advertise.Operation.Body,
			runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339), preparedHead, status.Head.HeadHash)
	}
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	scope := wire.AdminResourceScopeV1{ScopeKind: "cluster", Cluster: &struct{}{}}
	verified, err := wire.AuthorizeControlOperationAtHead(&advertise.Operation, peer.Raw, &scope,
		runtime.now().UTC(), controlOperationSchemas, &status.Head, status.ConfigQC, &status.ControlSet, nil,
		currentApplication.Authorizations, currentApplication.adminProfiles())
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	runtime.mu.Lock()
	committed, err := runtime.commitBootstrapAdvertisementPayloadLocked(context.Background(), verified, payload, advertise.Payload)
	runtime.mu.Unlock()
	if err != nil {
		running.Close()
		t.Fatal(err)
	}
	result := serveRuntimeOperation(t, runtime, peer, advertise, http.StatusOK)
	if !wire.EqualCanonical(committed.Head, result.Head) {
		running.Close()
		t.Fatal("advertise 响应丢失重试没有回读首次 certified 结果")
	}
	after, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil || after.BootstrapInstallation != nil || result.Head.Body.Payload.SnapshotHash == status.Head.Body.Payload.SnapshotHash {
		running.Close()
		t.Fatalf("认证 advertise 未公开 catalog/解除私有安装: %v", err)
	}
	invite, _ := controlInviteRequest(t, runtime, adminDir, "demo-after-bootstrap-advertise")
	serveRuntimeOperation(t, runtime, peer, invite, http.StatusOK)
	running.Close()
	restarted, err := startPreparedBootstrapRuntime(ctx, bundle, public, device, state, materials, roots, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Close()
	bad := controlClone(bundle)
	bad.Installation.Leaf.ContentHash = wire.EmptyHashV1
	invalidPath := filepath.Join(t.TempDir(), "invalid")
	if runtime, err := startPreparedBootstrapRuntime(ctx, bad, public, device, invalidPath, materials, roots, time.Now); err == nil {
		runtime.Close()
		t.Fatal("接受未认证安装")
	}
	if _, err := os.Lstat(invalidPath); !os.IsNotExist(err) {
		t.Fatal("验证失败仍创建了运行状态")
	}
	if _, err := runtime.bootstrapInstallationDeliveryLocked("demo-other"); err == nil {
		t.Fatal("向其他节点交付安装授权")
	}
}

func installationObserverKeyID(request controlPrepareBootstrapInputV1, endpointID string) string {
	for _, listener := range request.Listeners {
		if listener.EndpointID == endpointID && len(listener.EvidencePolicy.Observers) > 0 {
			return listener.EvidencePolicy.Observers[0].ObserverKeyID
		}
	}
	return ""
}
