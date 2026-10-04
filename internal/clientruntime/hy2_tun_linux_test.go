//go:build linux

package clientruntime

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This uses only a private network namespace, a local HTTPS target and the
// actual Hy2 receiver ACL. No router, host route or external target is used.
func TestTUNDNSHy2TargetIdentity(t *testing.T) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the exact data plane in a dedicated network namespace")
	}
	self, err := os.Stat("/proc/self/ns/net")
	host, hostErr := os.Stat("/proc/1/ns/net")
	interfaces, interfaceErr := net.Interfaces()
	if err != nil || hostErr != nil || os.SameFile(self, host) || interfaceErr != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires an isolated loopback-only network namespace")
	}
	if body, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v %s", err, body)
	}
	tlsPort := routingTargetPair(t, true)
	// The receiver has real TLS trust; only the separate local HTTPS fixture
	// omits name verification in routingRequestTo.
	certServer := httptest.NewTLSServer(nil)
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()
	root := t.TempDir()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"certificate.pem": certPEM, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	password := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	receiver := map[string]any{
		"log": map[string]any{"level": "debug"},
		"inbounds": []any{map[string]any{"type": "hysteria2", "tag": "demo-resource", "listen": "127.0.0.1", "listen_port": port,
			"users": []any{map[string]any{"name": "demo-user", "password": password}},
			"tls":   map[string]any{"enabled": true, "certificate_path": filepath.Join(root, "certificate.pem"), "key_path": filepath.Join(root, "key.pem")}}},
		"outbounds": []any{map[string]any{"type": "block", "tag": "reject"}, map[string]any{"type": "direct", "tag": "demo-target", "override_address": "127.0.0.2"}},
		"route": map[string]any{"final": "reject", "rules": []any{
			map[string]any{"inbound": []string{"demo-resource"}, "auth_user": []string{"demo-user"}, "domain": []string{"demo-service.example"}, "outbound": "demo-target"},
			map[string]any{"inbound": []string{"demo-resource"}, "auth_user": []string{"demo-user"}, "ip_cidr": []string{"192.0.2.77/32"}, "outbound": "demo-target"},
		}},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:61801", "secret": "demo-api"}},
	}
	body, _ := json.Marshal(receiver)
	stopReceiver := runRoutingSingBoxAt(t, executable, body, "127.0.0.1:61801")
	defer stopReceiver()
	source, _ := decodeWindowsConfig([]byte(validWindowsConfig("")))
	// The same name is queried by both the TUN application and the underlay.
	// A leaked synthetic answer here would make the Hy2 connection recurse.
	source.Outbounds[1] = singBoxOutbound{Type: "hysteria2", Tag: "demo-candidate", Server: "demo-service.example", ServerPort: port, Password: password,
		TLS: &singBoxTLS{Enabled: true, ServerName: "example.com", Certificate: []string{string(certPEM)}}}
	source.Route.Rules[0].Rules = append(source.Route.Rules[0].Rules, singBoxRule{IPCIDR: []string{"192.0.2.77/32"}})
	body, _ = json.Marshal(source)
	body, err = DeriveWindowsRuntimeConfig(body, WindowsPortableTUNProfile, []string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireTUNDNSExecutor(context.Background(), executable, body); err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	_ = json.Unmarshal(body, &config)
	// Substitute only fixture coordinates and the namespace's capture boundary.
	config["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["address"] = "udp://" + routingDNSServerAddress(t, net.IPv4(127, 0, 0, 1))
	config["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"] = filepath.Join(root, "tun-dns.db")
	config["inbounds"].([]any)[1].(map[string]any)["route_address"] = []string{"192.0.2.0/24", "198.18.0.0/15", "2001:db8:8000::/49"}
	body, _ = json.Marshal(config)
	stop := runRoutingSingBox(t, executable, body)
	defer func() { stop() }()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "172.19.0.2:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lookup := func(family string) ([]net.IP, error) {
		for {
			addresses, err := resolver.LookupIP(ctx, family, "demo-service.example")
			if err == nil || ctx.Err() != nil {
				return addresses, err
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	addresses, err := lookup("ip4")
	if err != nil || len(addresses) != 1 || !strings.HasPrefix(addresses[0].String(), "198.18.") {
		t.Fatalf("TUN service DNS failed: %v %v", addresses, err)
	}
	address := addresses[0].String()
	addresses6, err := lookup("ip6")
	if err != nil || len(addresses6) != 1 || addresses6[0].To4() != nil {
		t.Fatalf("TUN IPv6 service DNS failed: %v %v", addresses6, err)
	}
	for _, probe := range []struct{ name, host, address, want string }{
		{"domain_via_dns", "demo-service.example", address, "service"},
		{"domain_without_sni", address, address, "service"},
		{"ipv6_domain_without_sni", addresses6[0].String(), addresses6[0].String(), "service"},
		{"literal_ip", "192.0.2.77", "192.0.2.77", "service"},
		{"forged_sni", "demo-service.example", "192.0.2.88", "blocked"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			if got := routingRequestTo(t, "https", probe.host, tlsPort, probe.address, false); got != probe.want {
				t.Fatalf("actual Hy2 target: got %s, want %s", got, probe.want)
			}
		})
	}
	stop()
	stop = runRoutingSingBox(t, executable, body)
	if got := routingRequestTo(t, "https", address, tlsPort, address, false); got != "service" {
		t.Fatalf("cached DNS destination did not survive restart: %s (port %s)", got, strconv.Itoa(port))
	}
}
