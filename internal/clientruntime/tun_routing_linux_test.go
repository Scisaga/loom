//go:build linux

package clientruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// §7.2.1：真实 TUN 验证使用隔离网络命名空间；测试只替换操作系统接管范围，
// Service、默认策略和本机派生 action 仍由正式配置校验与派生函数生成。
// 运行：LOOM_TUN_ROUTING_EXECUTABLE=/abs/sing-box unshare -Urn <test-binary> -test.run TestOfficialTUNServiceRouting
func TestOfficialTUNServiceRouting(t *testing.T) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("[§7.2.1] 设置 LOOM_TUN_ROUTING_EXECUTABLE 并在独立网络命名空间运行真实 TUN 测试")
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	interfaces, interfaceErr := net.Interfaces()
	if err != nil || len(fields) != 3 || fields[0] != "0" || fields[1] == "0" || fields[2] != "1" ||
		interfaceErr != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("[§7.2.1] 测试要求无宿主权限、仅有回环接口的独立用户/网络命名空间")
	}
	if body, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("[§7.2.1] 无法启用隔离回环接口：%v %s", err, body)
	}
	version, err := exec.Command(executable, "version").Output()
	if err != nil || !strings.Contains(string(version), "sing-box version 1.11.4") {
		t.Fatalf("[§7.2.1] 测试必须使用既有正式数据面 1.11.4：%v %s", err, version)
	}
	dnsAddress := routingDNSServer(t)
	httpPort := routingTargetPair(t, false)
	tlsPort := routingTargetPair(t, true)

	for _, fixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("domain_capture_%t", fixed), func(t *testing.T) {
			body := routingTUNConfig(t, dnsAddress)
			var config map[string]any
			if err := json.Unmarshal(body, &config); err != nil {
				t.Fatal(err)
			}
			if !fixed {
				// §7.2.1：复现修复前仅 DNS 接管、没有域名映射/识别的原样行为。
				config["dns"].(map[string]any)["reverse_mapping"] = false
				route := config["route"].(map[string]any)
				rules := route["rules"].([]any)
				route["rules"] = append(rules[:1], rules[2:]...)
			}
			// §7.2.1：只将测试地址送入隔离 TUN；回环上的目标和 DNS 不进入接管。
			config["inbounds"].([]any)[0].(map[string]any)["route_address"] = []string{"192.0.2.0/24"}
			body, _ = json.Marshal(config)
			stop := runRoutingSingBox(t, executable, body)
			defer stop()
			want := "default"
			if fixed {
				want = "service"
			}
			for _, probe := range []struct {
				name, scheme, host string
				port               string
				mixed              bool
				want               string
			}{
				{"mixed_domain", "http", "demo-service.example", httpPort, true, "service"},
				{"tun_http_host", "http", "demo-service.example", httpPort, false, want},
				{"tun_tls_sni", "https", "demo-service.example", tlsPort, false, want},
				{"tun_without_domain_evidence", "https", "192.0.2.17", tlsPort, false, "default"},
			} {
				t.Run(probe.name, func(t *testing.T) {
					if got := routingRequest(t, probe.scheme, probe.host, probe.port, probe.mixed); got != probe.want {
						t.Fatalf("[§7.2.1] 实际请求进入 %q，预期 %q", got, probe.want)
					}
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "172.19.0.2:53")
			}}
			addresses, err := resolver.LookupIP(ctx, "ip4", "demo-service.example")
			if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.17" {
				t.Fatalf("[§7.2.1] 受管 TUN DNS 查询失败：%v %v", addresses, err)
			}
			// §7.2.1：TLS ClientHello 没有 SNI；唯有此前经过 TUN 的 DNS 证据可恢复域名。
			if got := routingRequest(t, "https", "192.0.2.17", tlsPort, false); got != want {
				t.Fatalf("[§7.2.1] DNS 映射后的无 SNI 连接进入 %q，预期 %q", got, want)
			}
		})
	}
}

func routingTUNConfig(t *testing.T, dnsAddress string) []byte {
	t.Helper()
	var config singBoxConfig
	if err := json.Unmarshal([]byte(validWindowsConfig("debug")), &config); err != nil {
		t.Fatal(err)
	}
	config.DNS.Servers[0].Address = "udp://" + dnsAddress
	config.Outbounds = []singBoxOutbound{
		{Type: "direct", Tag: "dns-out"},
		{Type: "direct", Tag: "demo-service", OverrideAddress: "127.0.0.2"},
		{Type: "direct", Tag: "demo-default", OverrideAddress: "127.0.0.3"},
		{Type: "selector", Tag: "svc:demo-service", Outbounds: []string{"demo-service"}, Default: "demo-service"},
		{Type: "selector", Tag: "decl:demo-default", Outbounds: []string{"demo-default"}, Default: "demo-default"},
		{Type: "block", Tag: "block"},
	}
	config.Route.Rules = []singBoxRule{
		{Inbound: []string{"tun-in", "in-1080"}, Domain: []string{"demo-service.example"}, Outbound: "svc:demo-service"},
		{Inbound: []string{"tun-in", "in-1080"}, Outbound: "decl:demo-default"},
	}
	config.Experimental.ClashAPI.Secret = "demo-api-secret"
	source, _ := json.Marshal(config)
	body, err := DeriveWindowsRuntimeConfig(source, WindowsPortableTUNProfile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func routingTargetPair(t *testing.T, encrypted bool) string {
	t.Helper()
	port := "0"
	for _, target := range []struct{ address, marker string }{{"127.0.0.2", "service"}, {"127.0.0.3", "default"}} {
		listener, err := net.Listen("tcp", net.JoinHostPort(target.address, port))
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ = net.SplitHostPort(listener.Addr().String())
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, target.marker)
		}))
		_ = server.Listener.Close()
		server.Listener = listener
		if encrypted {
			server.StartTLS()
		} else {
			server.Start()
		}
		t.Cleanup(server.Close)
	}
	return port
}

func routingRequest(t *testing.T, scheme, host, port string, mixed bool) string {
	t.Helper()
	transport := &http.Transport{
		DisableKeepAlives: true,
		// §7.2.1：本测试只判定隔离目标的实际选路；自签名测试站点不验证公网证书。
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if mixed {
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1080"})
	} else {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("192.0.2.17", port))
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func runRoutingSingBox(t *testing.T, executable string, body []byte) func() {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "run", "-c", path)
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = command.Process.Signal(os.Interrupt)
		_ = command.Wait()
		cancel()
		if t.Failed() {
			t.Log(log.String())
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return stop
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	t.Fatal("[§7.2.1] 隔离数据面未能启动")
	return stop
}

func routingDNSServer(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		packet := make([]byte, 512)
		for {
			n, peer, err := listener.ReadFrom(packet)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end := 12
			for end < n && packet[end] != 0 {
				end += int(packet[end]) + 1
			}
			end += 5
			if end > n || binary.BigEndian.Uint16(packet[end-4:end-2]) != 1 {
				continue
			}
			response := append([]byte(nil), packet[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[6:8], 1)
			binary.BigEndian.PutUint16(response[8:10], 0)
			binary.BigEndian.PutUint16(response[10:12], 0)
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 17)
			_, _ = listener.WriteTo(response, peer)
		}
	}()
	return listener.LocalAddr().String()
}
