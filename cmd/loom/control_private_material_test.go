package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestControlPrivateServicesRetainOriginalCAAndDedicatedSealedKeys(t *testing.T) {
	dir, _ := newAdminRotationFixture(t, true)
	now := time.Now().UTC().Truncate(time.Second)
	runtime, err := openControlRuntime(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ports := map[string]int64{"device_config": runtime.config.ControlPort + 20, "device_report": runtime.config.ControlPort + 21, "enroll": runtime.config.ControlPort + 22}
	prepared, err := runtime.preparePrivateServiceMaterials("demo-migration", "demo-device-profile", ports, now)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := openControlRuntime(dir, func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	again, err := reopened.preparePrivateServiceMaterials("demo-migration", "demo-device-profile", ports, now.Add(time.Hour))
	if err != nil || !wire.EqualCanonical(prepared, again) {
		t.Fatal("重启替换了原 private listener 材料", err)
	}
	application := &controlApplicationV1{}
	for _, entry := range prepared.Services {
		application.Services = append(application.Services, entry.Service)
	}
	certificates, err := reopened.loadPrivateServiceCertificates(application)
	if err != nil || len(certificates) != 3 {
		t.Fatal("无法从真实封装恢复私有 listener", err)
	}
	root, err := x509.ParseCertificate(runtime.controlTLS.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	pins := map[string]bool{runtime.config.ControlService.SPKIPins[0]: true}
	for _, entry := range prepared.Services {
		pin := entry.Service.SPKIPins[0]
		if pins[pin] {
			t.Fatal("不同私有 role 复用了原 control 或其他 role 的密钥")
		}
		pins[pin] = true
		certificate := certificates[entry.Service.ServiceID]
		left, right := net.Pipe()
		server := tls.Server(left, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, Time: reopened.now})
		client := tls.Client(right, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: entry.Service.OverlayIP, Time: reopened.now})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := make(chan error, 1)
		go func() { result <- server.HandshakeContext(ctx) }()
		clientErr := client.HandshakeContext(ctx)
		serverErr := <-result
		cancel()
		_ = left.Close()
		_ = right.Close()
		if clientErr != nil || serverErr != nil {
			t.Fatalf("恢复后的真实密钥不能完成 TLS: client=%v server=%v", clientErr, serverErr)
		}
	}
	application.Services[0].SPKIPins = []string{wire.EmptyHashV1}
	if _, err := reopened.loadPrivateServiceCertificates(application); err == nil {
		t.Fatal("允许本地材料覆盖当前认证目录")
	}
	ports["enroll"]++
	if _, err := reopened.preparePrivateServiceMaterials("demo-migration", "demo-device-profile", ports, now.Add(time.Hour)); err == nil {
		t.Fatal("重试改变了原端口")
	}
}
