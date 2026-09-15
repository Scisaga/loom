package dnsprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGandiHTTPSProxyOnlySeesConnect(t *testing.T) {
	var received, connects atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Error("原站未收到 PAT")
		}
		received.Add(1)
		_ = json.NewEncoder(w).Encode(gandiRRSet{RRSetTTL: 300, RRSetValues: []string{"203.0.113.8"}})
	}))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != origin.Listener.Addr().String() || r.Header.Get("Authorization") != "" {
			t.Error("代理收到非 CONNECT 请求或 API bearer")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		connects.Add(1)
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close() }()
		_, _ = io.Copy(client, upstream)
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	client := origin.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	client.Transport = transport
	provider, err := newGandi(origin.URL, "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, client)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.client.CloseIdleConnections()
	if _, err := provider.Read(context.Background(), "example.test", "edge", "A"); err != nil {
		t.Fatal(err)
	}
	if received.Load() != 1 || connects.Load() != 1 {
		t.Fatal("HTTPS 请求没有经过配置的 CONNECT 代理")
	}
}

func TestGandiRejectsTLSBypass(t *testing.T) {
	for _, config := range []*tls.Config{
		{InsecureSkipVerify: true},
		{ServerName: "other.example"},
	} {
		_, err := NewGandi("secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}},
			&http.Client{Transport: &http.Transport{TLSClientConfig: config}})
		if err == nil || strings.Contains(err.Error(), "secret-token") {
			t.Fatal("TLS 校验绕过未拒绝或错误包含凭据")
		}
	}
}

func TestGandiReplaceUsesBearerAndReadback(t *testing.T) {
	t.Helper()
	desired := RRSet{Zone: "example.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/domains/example.test/records/edge/A" || r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Fatalf("unexpected request: %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodPut {
			var body gandiRRSet
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RRSetTTL != 300 || len(body.RRSetValues) != 1 {
				t.Fatalf("unexpected PUT body: %#v err=%v", body, err)
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		_ = json.NewEncoder(w).Encode(gandiRRSet{RRSetTTL: 300, RRSetValues: []string{"203.0.113.8"}})
	}))
	defer server.Close()

	provider, err := newGandi(server.URL, "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Replace(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || !Equal(got.RRSet, desired) {
		t.Fatalf("replace/readback mismatch: requests=%d got=%#v", requests, got.RRSet)
	}
}

func TestGandiRejectsScopeEscapeBeforeNetwork(t *testing.T) {
	provider, err := newGandi("http://127.0.0.1:1", "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []RRSet{
		{Zone: "other.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}},
		{Zone: "example.test", Name: "control", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}},
	} {
		if _, err := provider.Replace(context.Background(), input); err == nil {
			t.Fatalf("scope escape accepted: %#v", input)
		}
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	got, err := Normalize(RRSet{Zone: "EXAMPLE.TEST.", Name: "Edge.", Type: "a", TTL: 300, Values: []string{"203.0.113.9", "203.0.113.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != "example.test" || got.Name != "edge" || got.Type != "A" || got.Values[0] != "203.0.113.8" {
		t.Fatalf("not canonical: %#v", got)
	}
}

func TestGandiRejectsRedirectWithoutForwardingCredential(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		redirected++
		if request.Header.Get("Authorization") != "" {
			t.Fatal("Gandi credential 被带到 redirect target")
		}
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	provider, err := newGandi(origin.URL, "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Replace(context.Background(), RRSet{Zone: "example.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}})
	if err == nil || redirected != 0 {
		t.Fatalf("redirect 未失败关闭: err=%v redirected=%d", err, redirected)
	}
}
