package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Only loopback listeners and one disposable Mixed process; no host network changes.
func TestManagedDoHRuntimePreservesBusinessDomainAndDoesNotGrantResolverAccess(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		name := "specified destinations"
		if ordinary {
			name = "ordinary internet rejects a private DNS answer"
		}
		t.Run(name, func(t *testing.T) { testManagedDoHRuntime(t, ordinary) })
	}
}

func testManagedDoHRuntime(t *testing.T, ordinary bool) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed data-plane executable")
	}
	var queries atomic.Int32
	dns := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("runtime did not use DoH")
			w.WriteHeader(400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			t.Error(err)
			return
		}
		var q dnsmessage.Message
		if q.Unpack(body) != nil || len(q.Questions) != 1 {
			t.Error("invalid query")
			return
		}
		if q.Questions[0].Name.String() != "example.com." {
			t.Error("unexpected runtime lookup")
			return
		}
		queries.Add(1)
		q.Response, q.RecursionAvailable = true, true
		if q.Questions[0].Type == dnsmessage.TypeA {
			q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
		}
		body, err = q.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer dns.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" {
			t.Error("lost original TLS name")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	rule := map[string]any{"domain": []string{"example.com"}, "outbound": "demo-direct"}
	if ordinary {
		rule = map[string]any{"public_internet": true, "outbound": "demo-direct"}
	}
	source, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "mixed", "tag": "demo-mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "demo-direct", "public_internet": ordinary}, map[string]any{"type": "block", "tag": "reject"}}, "route": map[string]any{"final": "reject", "rules": []any{rule}}})
	badTLS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer badTLS.Close()
	config, err := WithManagedDNS(string(source), []string{strings.Replace(badTLS.URL, "http://", "https://", 1) + "/dns-query", dns.URL + "/dns-query"}, false)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	file := filepath.Join(root, "config.json")
	cert := filepath.Join(root, "roots.pem")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dns.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "run", "-c", file)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "SSL_CERT_FILE=") && !strings.HasPrefix(value, "SSL_CERT_DIR=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "SSL_CERT_FILE="+cert, "SSL_CERT_DIR="+root)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Mixed runtime did not start")
	}
	_, targetPort, _ := net.SplitHostPort(target.Listener.Addr().String())
	probe, err := httpsBusinessProbe(address, "https://example.com:"+targetPort+"/demo-probe", target.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if result := probe(ctx); result.Available == ordinary || queries.Load() == 0 {
		t.Fatal("runtime DoH business failed", result)
	}
	for _, url := range []string{dns.URL + "/dns-query", target.URL + "/demo-probe"} {
		probe, err := httpsBusinessProbe(address, url, target.Client().Transport.(*http.Transport).TLSClientConfig)
		if err != nil {
			t.Fatal(err)
		}
		if result := probe(ctx); result.Available {
			t.Fatal("resolver infrastructure granted ordinary IP access")
		}
	}
}
