package bootstrapaccess

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/wire"
)

// TestOfficialSingBoxHysteria2BootstrapInterop 验证真实 sing-box 的 HY2/TCP
// stream 与 Loom capability auth、exact ACL 和 durable usage 的完整互操作。
func TestOfficialSingBoxHysteria2BootstrapInterop(t *testing.T) {
	executable := os.Getenv("LOOM_HYSTERIA2_BOOTSTRAP_EXECUTABLE")
	if executable == "" {
		t.Skip("未指定官方 sing-box HY2 验收二进制")
	}
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		t.Fatal("sing-box 验收路径必须是规范绝对路径")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("sing-box 验收路径不是可执行普通文件")
	}
	version, err := exec.Command(executable, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "sing-box version 1.11.4") {
		t.Fatal("sing-box 验收二进制不是审核版本 1.11.4")
	}

	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	serverName := "bootstrap.example"
	_, tlsConfig, certificate := trojanCertificate(t, serverName)
	var targetDialed sync.Once
	var targetDialCalls atomic.Int64
	outgoing, enrollment := net.Pipe()
	server, err := NewHysteria2Server(manager, registry, Hysteria2ServerOptions{
		ServerName: serverName, TLSConfig: tlsConfig, HandshakeTimeout: 5 * time.Second,
		IdleTimeout: 2 * time.Second, MaximumConcurrentConnections: 8, MaximumStreamsPerConnection: 4,
		Dial: func(_ context.Context, network, address string) (net.Conn, error) {
			targetDialCalls.Add(1)
			if network != "tcp4" || address != "10.30.0.1:7444" {
				return nil, errors.New("官方 HY2 client 请求了非 Enrollment tuple")
			}
			called := false
			targetDialed.Do(func() { called = true })
			if !called {
				return nil, errors.New("官方 HY2 client 重复拨号")
			}
			return outgoing, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := packetConnection.LocalAddr().(*net.UDPAddr).Port
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext, packetConnection) }()
	var stopServer sync.Once
	stopHY2Server := func() {
		stopServer.Do(func() {
			cancelServer()
			<-serverDone
		})
	}
	t.Cleanup(stopHY2Server)

	root := t.TempDir()
	certificatePath := filepath.Join(root, "bootstrap-ca.pem")
	if err := os.WriteFile(certificatePath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	proxyPort := reserveLocalTCPPort(t)
	config := map[string]any{
		"log": map[string]any{"level": "error", "disabled": false},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "bootstrap-mixed", "listen": "127.0.0.1", "listen_port": proxyPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "hysteria2", "tag": "bootstrap-hy2", "server": "127.0.0.1", "server_port": serverPort,
			"password": verified.TransportCredential(), "network": "tcp",
			"tls": map[string]any{"enabled": true, "server_name": serverName,
				"min_version": "1.3", "max_version": "1.3", "certificate_path": certificatePath},
		}},
		"route": map[string]any{"final": "bootstrap-hy2"},
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sing-box.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(body)
	if output, err := exec.Command(executable, "check", "-c", configPath).CombinedOutput(); err != nil {
		t.Fatalf("官方 sing-box 拒绝 HY2 bootstrap 配置（诊断已抑制，%d bytes）", len(output))
	}
	processContext, cancelProcess := context.WithCancel(context.Background())
	command := exec.CommandContext(processContext, executable, "run", "-c", configPath)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		cancelProcess()
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	var stopProcess sync.Once
	stop := func() {
		stopProcess.Do(func() {
			_ = command.Process.Signal(os.Interrupt)
			select {
			case <-processDone:
			case <-time.After(2 * time.Second):
				cancelProcess()
				<-processDone
			}
			cancelProcess()
		})
	}
	t.Cleanup(stop)
	proxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	waitLocalTCP(t, proxyAddress, 5*time.Second)

	client := socks5ConnectIPv4(t, proxyAddress, [4]byte{10, 30, 0, 1}, 7444)
	request := []byte("ping")
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	gotRequest := make([]byte, len(request))
	if count, err := io.ReadFull(enrollment, gotRequest); err != nil || string(gotRequest) != string(request) {
		t.Fatalf("官方 HY2 请求未到 Enrollment，bytes=%d err=%v", count, err)
	}
	response := []byte("pong")
	writeDone := make(chan error, 1)
	go func() {
		_, err := enrollment.Write(response)
		writeDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if count, err := io.ReadFull(client, gotResponse); err != nil || string(gotResponse) != string(response) {
		t.Fatalf("官方 HY2 响应未回客户端，bytes=%d err=%v", count, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = enrollment.Close()
	badConnection, reply, err := socks5ConnectIPv4Result(proxyAddress, [4]byte{10, 30, 0, 1}, 22)
	if badConnection != nil {
		_, _ = badConnection.Write([]byte("x"))
		_ = badConnection.SetReadDeadline(time.Now().Add(2 * time.Second))
		var unexpected [1]byte
		if _, readErr := badConnection.Read(unexpected[:]); readErr == nil {
			_ = badConnection.Close()
			t.Fatal("HY2 越权目标传输了 payload")
		}
		_ = badConnection.Close()
	} else if err != nil || reply == 0 {
		t.Fatalf("HY2 越权目标没有得到显式 SOCKS 拒绝:reply=%d err=%v", reply, err)
	}
	if targetDialCalls.Load() != 1 {
		t.Fatalf("HY2 exact ACL 后 dial calls=%d", targetDialCalls.Load())
	}
	stop()
	stopHY2Server()
	usage := manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 ||
		usage[0].TransferredBytes != int64(len(request)+len(response)) {
		t.Fatalf("官方 HY2 durable usage=%#v", usage)
	}
}
