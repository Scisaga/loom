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
	"testing"
	"time"
)

// TestOfficialSingBoxTrojanBootstrapInterop 验证真实 sing-box SOCKS→Trojan/TLS
// client 与本包 server/ACL/usage 的兼容性。默认单测不依赖宿主二进制；Linux
// 验收以 LOOM_TROJAN_BOOTSTRAP_EXECUTABLE=/abs/sing-box 显式启用（D131）。
func TestOfficialSingBoxTrojanBootstrapInterop(t *testing.T) {
	executable := os.Getenv("LOOM_TROJAN_BOOTSTRAP_EXECUTABLE")
	if executable == "" {
		t.Skip("未指定官方 sing-box 验收二进制")
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

	var targetDialed sync.Once
	outgoing, enrollment := net.Pipe()
	fixture := newTrojanServerFixture(t, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "10.30.0.1:7444" {
			return nil, errors.New("官方 Trojan client 请求了非 Enrollment tuple")
		}
		called := false
		targetDialed.Do(func() { called = true })
		if !called {
			return nil, errors.New("官方 Trojan client 重复拨号")
		}
		return outgoing, nil
	})
	fixture.start(t)
	defer fixture.stop(t)

	root := t.TempDir()
	certificatePath := filepath.Join(root, "bootstrap-ca.pem")
	if err := os.WriteFile(certificatePath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	proxyPort := reserveLocalTCPPort(t)
	serverPort := fixture.listener.Addr().(*net.TCPAddr).Port
	config := map[string]any{
		"log": map[string]any{"level": "error", "disabled": false},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "bootstrap-mixed", "listen": "127.0.0.1", "listen_port": proxyPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "trojan", "tag": "bootstrap-trojan", "server": "127.0.0.1", "server_port": serverPort,
			"password": fixture.credential, "network": "tcp",
			"tls": map[string]any{"enabled": true, "server_name": fixture.serverName,
				"min_version": "1.3", "max_version": "1.3", "certificate_path": certificatePath},
		}},
		"route": map[string]any{"final": "bootstrap-trojan"},
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
	check := exec.Command(executable, "check", "-c", configPath)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("官方 sing-box 拒绝 Trojan bootstrap 配置（诊断已抑制，%d bytes）", len(output))
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
			cancelProcess()
			<-processDone
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
		t.Fatalf("官方 Trojan 请求未到 Enrollment，bytes=%d err=%v", count, err)
	}
	response := []byte("pong")
	writeDone := make(chan error, 1)
	go func() {
		_, err := enrollment.Write(response)
		writeDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if count, err := io.ReadFull(client, gotResponse); err != nil || string(gotResponse) != string(response) {
		t.Fatalf("官方 Trojan 响应未回客户端，bytes=%d err=%v", count, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = enrollment.Close()
	stop()
	usage := fixture.manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 ||
		usage[0].TransferredBytes != int64(len(request)+len(response)) {
		t.Fatalf("官方 Trojan durable usage=%#v", usage)
	}
}

func reserveLocalTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitLocalTCP(t *testing.T, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		connection, err := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("官方 sing-box mixed listener 未启动")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func socks5ConnectIPv4(t *testing.T, proxyAddress string, address [4]byte, port uint16) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		_ = connection.Close()
		t.Fatalf("sing-box SOCKS greeting 失败:%v", err)
	}
	request := []byte{5, 1, 0, 1, address[0], address[1], address[2], address[3], byte(port >> 8), byte(port)}
	if _, err := connection.Write(request); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil || response[0] != 5 || response[1] != 0 {
		_ = connection.Close()
		t.Fatalf("sing-box SOCKS CONNECT 失败:reply=%d err=%v", response[1], err)
	}
	var addressBytes int
	switch response[3] {
	case 1:
		addressBytes = 4
	case 4:
		addressBytes = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		addressBytes = int(length[0])
	default:
		_ = connection.Close()
		t.Fatal("sing-box SOCKS reply address type 无效")
	}
	if _, err := io.CopyN(io.Discard, connection, int64(addressBytes+2)); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Time{})
	return connection
}
