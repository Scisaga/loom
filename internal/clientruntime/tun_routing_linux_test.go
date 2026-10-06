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
	self, err := os.Stat("/proc/self/ns/net")
	host, hostErr := os.Stat("/proc/1/ns/net")
	interfaces, interfaceErr := net.Interfaces()
	if err != nil || hostErr != nil || os.SameFile(self, host) ||
		interfaceErr != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("测试要求仅有回环接口的独立网络命名空间")
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
				delete(config["dns"].(map[string]any), "fakeip")
				delete(config["dns"].(map[string]any), "rules")
				delete(config["dns"].(map[string]any), "independent_cache")
				config["dns"].(map[string]any)["servers"] = config["dns"].(map[string]any)["servers"].([]any)[:1]
				delete(config["experimental"].(map[string]any), "cache_file")
				route := config["route"].(map[string]any)
				rules := route["rules"].([]any)
				route["rules"] = append(rules[:1], rules[2:]...)
			}
			// §7.2.1：只将测试地址送入隔离 TUN；回环上的目标和 DNS 不进入接管。
			config["inbounds"].([]any)[1].(map[string]any)["route_address"] = []string{"192.0.2.0/24", "198.18.0.0/15", "2001:db8:8000::/49"}
			body, _ = json.Marshal(config)
			stop := runRoutingSingBox(t, executable, body)
			defer stop()
			want := "blocked"
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
				{"tun_without_domain_evidence", "https", "192.0.2.17", tlsPort, false, "blocked"},
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
			if err != nil || len(addresses) != 1 || (!fixed && addresses[0].String() != "192.0.2.17") || (fixed && !strings.HasPrefix(addresses[0].String(), "198.18.")) {
				t.Fatalf("[§7.2.1] 受管 TUN DNS 查询失败：%v %v", addresses, err)
			}
			// §7.2.1：TLS ClientHello 没有 SNI；唯有此前经过 TUN 的 DNS 证据可恢复域名。
			if got := routingRequestTo(t, "https", addresses[0].String(), tlsPort, addresses[0].String(), false); got != want {
				t.Fatalf("[§7.2.1] DNS 映射后的无 SNI 连接进入 %q，预期 %q", got, want)
			}
		})
	}
}

func routingTUNConfig(t *testing.T, dnsAddress string) []byte {
	t.Helper()
	source := []byte(validWindowsConfig(""))
	body, err := DeriveWindowsRuntimeConfig(source, WindowsPortableTUNProfile, []string{"192.0.2.53"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var config singBoxConfig
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	// Isolated harness substitutes loopback servers after the formal adapter;
	// the production config never receives destination override facilities.
	config.DNS.Servers[0].Address = "udp://" + dnsAddress
	for i := range config.Outbounds {
		if config.Outbounds[i].Tag == "demo-candidate" {
			config.Outbounds[i].OverrideAddress = "127.0.0.2"
		}
	}
	body, err = json.Marshal(config)
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
	return routingRequestTo(t, scheme, host, port, "192.0.2.17", mixed)
}

func routingRequestTo(t *testing.T, scheme, host, port, address string, mixed bool) string {
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
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address, port))
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		return "blocked"
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func runRoutingSingBox(t *testing.T, executable string, body []byte) func() {
	return runRoutingSingBoxAt(t, executable, body, "127.0.0.1:1080")
}

func runRoutingSingBoxAt(t *testing.T, executable string, body []byte, ready string) func() {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "run", "-c", path)
	command.Dir = filepath.Dir(path)
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
	var capture struct {
		Inbounds []struct {
			Type string `json:"type"`
		} `json:"inbounds"`
	}
	_ = json.Unmarshal(body, &capture)
	hasTUN := false
	for _, inbound := range capture.Inbounds {
		hasTUN = hasTUN || inbound.Type == "tun"
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", ready, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			if !hasTUN {
				return stop
			}
			// Mixed starts before the TUN routes. This is startup readiness only;
			// the callers separately assert real DNS and application outcomes.
			dns, err := net.DialTimeout("udp", "172.19.0.2:53", 100*time.Millisecond)
			if err == nil {
				_ = dns.Close()
				return stop
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	t.Fatal("[§7.2.1] 隔离数据面未能启动")
	return stop
}

func routingDNSServer(t *testing.T) string {
	return routingDNSServerAddress(t, net.IPv4(192, 0, 2, 17))
}

func routingDNSServerAddress(t *testing.T, address net.IP) string {
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
			if end > n {
				continue
			}
			response := append([]byte(nil), packet[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[6:8], 0)
			binary.BigEndian.PutUint16(response[8:10], 0)
			binary.BigEndian.PutUint16(response[10:12], 0)
			if binary.BigEndian.Uint16(packet[end-4:end-2]) == 1 {
				binary.BigEndian.PutUint16(response[6:8], 1)
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				response = append(response, address.To4()...)
			}
			_, _ = listener.WriteTo(response, peer)
		}
	}()
	return listener.LocalAddr().String()
}
