//go:build linux

package clientv2

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"loom/internal/wire"
)

// 显式提供已安装的真实 sing-box 时执行本机 transport 集成验证；不更改主机
// 路由、已有 listener 或真实 Device。私有 API 的 mTLS/认证另由 daemon 测试覆盖。
func TestDeviceControlWireGuardNativeTransport(t *testing.T) {
	testDeviceControlNativeTransport(t, false)
}

func TestDeviceControlCarrierNativeTransport(t *testing.T) {
	testDeviceControlNativeTransport(t, true)
}

func testDeviceControlNativeTransport(t *testing.T, carrier bool) {
	binary := os.Getenv("LOOM_TEST_SING_BOX")
	if binary == "" {
		t.Skip("需要显式的本机 sing-box 二进制")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var host netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() {
			host = prefix.Addr()
			break
		}
	}
	if !host.IsValid() {
		t.Skip("本机缺可绑定的私网 IPv4 地址")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var received atomic.Int64
	listeners := make([]net.Listener, 3)
	services := make([]wire.PrivateControlServiceV1, 0, 2)
	for i := range listeners {
		listener, err := net.Listen("tcp", net.JoinHostPort(host.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = listener
		index := i
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if index == 2 {
				received.Add(1)
			}
			_, _ = io.WriteString(w, "demo-private-response")
		}), ReadHeaderTimeout: time.Second}
		go server.Serve(listener)
		defer server.Close()
		if i < 2 {
			role := []string{"device_config", "device_report"}[i]
			services = append(services, wire.PrivateControlServiceV1{ServiceID: "private-" + role, Role: role, OverlayIP: host.String(), Port: int64(listener.Addr().(*net.TCPAddr).Port), CertificateProfileRef: "demo-private-tls", SPKIPins: []string{wire.HashRaw("demo-pin", []byte(role))}, AuthorizedSubjectProfiles: []string{"demo-device"}})
		}
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", net.JoinHostPort(host.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	wgPort := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksAddress := socksListener.Addr().String()
	socksPort := socksListener.Addr().(*net.TCPAddr).Port
	_ = socksListener.Close()
	link := wire.DeviceControlLinkV1{Resource: wire.LinuxWireGuardResourceV1{ResourceID: "device-control-demo", LinkID: "device-control-demo", ListenerDeviceID: "demo-server", DialerDeviceID: "demo-client", ListenerGeneration: 1, EndpointAddress: host.String(), EndpointPort: int64(wgPort), ListenerPublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), DialerPublicKey: base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()), ListenerTunnelPrefix: "10.253.254.1/32", DialerTunnelPrefix: "10.253.254.2/32"}, Services: services}
	if err := wire.ValidateDeviceControlLink(&link); err != nil {
		t.Fatal(err)
	}
	serverConfig := map[string]any{"log": map[string]any{"level": "info", "disabled": false}, "endpoints": []wire.DeviceControlEndpointV1{wire.DeviceControlEndpoint(link, base64.StdEncoding.EncodeToString(serverKey.Bytes()))}, "outbounds": []any{map[string]string{"type": "direct", "tag": wire.DeviceControlDirectTag}, map[string]string{"type": "block", "tag": wire.DeviceControlBlockTag}}, "route": map[string]any{"rules": wire.DeviceControlRoutes([]wire.DeviceControlLinkV1{link}), "final": wire.DeviceControlBlockTag}}
	clientConfig := map[string]any{"log": map[string]string{"level": "info"}, "inbounds": []any{map[string]any{"type": "mixed", "tag": "demo-socks", "listen": "127.0.0.1", "listen_port": socksPort}}, "endpoints": []any{map[string]any{"type": "wireguard", "tag": "demo-wg", "system": false, "mtu": 1280, "address": []string{link.Resource.DialerTunnelPrefix}, "private_key": base64.StdEncoding.EncodeToString(clientKey.Bytes()), "peers": []any{map[string]any{"address": host.String(), "port": wgPort, "public_key": link.Resource.ListenerPublicKey, "allowed_ips": []string{netip.PrefixFrom(host, 32).String()}}}}}, "outbounds": []any{}, "route": map[string]string{"final": "demo-wg"}}
	var auth *proxy.Auth
	var outerOnlyAddress string
	if carrier {
		udp, err := net.ListenPacket("udp", net.JoinHostPort(host.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		_ = udp.Close()
		link.Carrier = &wire.DeviceControlCarrierV1{Address: host.String(), Port: int64(port), TLSServerName: "demo-control.example.test", CredentialRef: wire.DeviceControlCarrierCredentialRef(link)}
		if err := wire.ValidateDeviceControlLink(&link); err != nil {
			t.Fatal(err)
		}
		certificate, _, _ := privateEnrollmentCertificate(t, time.Now(), host.String(), link.Carrier.TLSServerName)
		dir := t.TempDir()
		var chain []byte
		for _, der := range certificate.Certificate {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{"certificate.pem": chain, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[1]})} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		const password = "demo-control-carrier-password"
		serverConfig["inbounds"] = []any{map[string]any{"type": "hysteria2", "tag": "in", "listen": host.String(), "listen_port": port,
			"users": []any{map[string]string{"name": link.Resource.ResourceID, "password": password}}, "tls": map[string]any{"enabled": true, "certificate_path": filepath.Join(dir, "certificate.pem"), "key_path": filepath.Join(dir, "key.pem"), "alpn": []string{"h3"}}}}
		serverConfig["route"] = map[string]any{"rules": wire.DeviceControlRoutesForDevice([]wire.DeviceControlLinkV1{link}, link.Resource.ListenerDeviceID), "final": wire.DeviceControlBlockTag}
		clientConfig["endpoints"] = []any{wire.DeviceControlEndpointForDevice(link, link.Resource.DialerDeviceID, base64.StdEncoding.EncodeToString(clientKey.Bytes()))}
		clientConfig["outbounds"] = []any{map[string]any{"type": "hysteria2", "tag": wire.DeviceControlCarrierTag(link), "server": host.String(), "server_port": port, "password": password,
			"tls": map[string]any{"enabled": true, "server_name": link.Carrier.TLSServerName, "certificate_path": filepath.Join(dir, "ca.pem"), "alpn": []string{"h3"}}}}
		outerOnly, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		outerOnlyAddress = outerOnly.Addr().String()
		outerPort := outerOnly.Addr().(*net.TCPAddr).Port
		_ = outerOnly.Close()
		users := []any{map[string]string{"username": link.Resource.ResourceID, "password": password}}
		clientConfig["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "demo-socks", "listen": "127.0.0.1", "listen_port": socksPort, "users": users},
			map[string]any{"type": "mixed", "tag": "demo-outer-only", "listen": "127.0.0.1", "listen_port": outerPort, "users": users}}
		clientConfig["route"] = map[string]any{"rules": []any{map[string]any{"inbound": []string{"demo-outer-only"}, "outbound": wire.DeviceControlCarrierTag(link)}}, "final": wire.DeviceControlEndpointTag(link)}
		auth = &proxy.Auth{User: link.Resource.ResourceID, Password: password}
	}
	startNativeControlBox(t, ctx, binary, serverConfig)
	startNativeControlBox(t, ctx, binary, clientConfig)
	dialer, err := proxy.SOCKS5("tcp", socksAddress, auth, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}, DisableKeepAlives: true}}
	for i, listener := range listeners {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listener.Addr().String()+"/demo", nil)
		response, err := client.Do(request)
		if i == 2 {
			if err == nil {
				response.Body.Close()
				t.Fatal("未授权端口穿过了私有控制链路")
			}
			continue
		}
		if err != nil {
			t.Fatalf("私有服务 %d 的真实 WireGuard 请求失败", i)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || string(body) != "demo-private-response" {
			t.Fatal("私有服务未收到原请求")
		}
	}
	if received.Load() != 0 {
		t.Fatal("未授权服务收到了请求")
	}
	if carrier {
		dialer, err := proxy.SOCKS5("tcp", outerOnlyAddress, auth, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		client.Transport = &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listeners[0].Addr().String()+"/demo", nil)
		if response, err := client.Do(request); err == nil {
			response.Body.Close()
			t.Fatal("仅持有承载凭据绕过 WireGuard 访问了私有服务")
		}
	}
}

func startNativeControlBox(t *testing.T, ctx context.Context, binary string, config any) {
	t.Helper()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	output, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	closed := make(chan error, 1)
	var diagnostic strings.Builder
	var diagnosticMu sync.Mutex
	go func() {
		scan := bufio.NewScanner(output)
		for scan.Scan() {
			diagnosticMu.Lock()
			diagnostic.WriteString(scan.Text() + "\n")
			diagnosticMu.Unlock()
			if strings.Contains(scan.Text(), "sing-box started") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		closed <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("本机测试进程未结束")
		}
		if t.Failed() {
			diagnosticMu.Lock()
			defer diagnosticMu.Unlock()
			t.Log(regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`).ReplaceAllString(diagnostic.String(), "demo-address"))
		}
	})
	select {
	case <-ready:
	case err := <-closed:
		closed <- err
		t.Fatal(fmt.Sprintf("本机测试运行器启动失败: %v", err))
	case <-ctx.Done():
		t.Fatal("本机测试运行器启动超时")
	}
}
