package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	runtime, _, _, _ := controlMigratedDeviceRuntime(t, func(app *controlApplicationV1, runtime *controlRuntime) {
		app.Schema = 2
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
	}
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
