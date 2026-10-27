package clientadapter

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPSBusinessProbeRetainsDomainAndTLSIdentityWithoutClientDNS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:8443" || r.TLS.ServerName != "example.com" {
			t.Error("lost certified HTTPS identity")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targets := make(chan string, 2)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				hello := make([]byte, 3)
				if _, err := io.ReadFull(c, hello); err != nil || !bytes.Equal(hello, []byte{5, 1, 0}) {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				header := make([]byte, 3)
				if _, err := io.ReadFull(c, header); err != nil || header[1] != 1 {
					return
				}
				target, err := readSOCKSAddress(c)
				if err != nil {
					return
				}
				targets <- target
				upstream, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "https://"))
				if err != nil {
					return
				}
				defer upstream.Close()
				bound, _ := socksAddress(listener.Addr().String())
				_, _ = c.Write(append([]byte{5, 0, 0}, bound...))
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, c); close(done) }()
				_, _ = io.Copy(c, upstream)
				_ = c.Close()
				<-done
			}()
		}
	}()
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	probe, err := httpsBusinessProbe(listener.Addr().String(), "https://example.com:8443/demo-probe", trust)
	if err != nil {
		t.Fatal(err)
	}
	if result := probe(t.Context()); !result.Available {
		t.Fatal(result)
	}
	if got := <-targets; got != "example.com:8443" {
		t.Fatal("resolved target on client", got)
	}
	probe, err = httpsBusinessProbe(listener.Addr().String(), "https://demo-invalid.example:8443/demo-probe", trust)
	if err != nil {
		t.Fatal(err)
	}
	if result := probe(t.Context()); result.Available {
		t.Fatal("proxy replaced TLS identity")
	}
	if got := <-targets; got != "demo-invalid.example:8443" {
		t.Fatal(got)
	}
}

func TestHTTPSBusinessProbeRejectsNonlocalProxyAndInvalidTargets(t *testing.T) {
	credentialed := (&url.URL{Scheme: "https", Host: "demo.example", User: url.UserPassword("demo-user", "demo-password")}).String()
	for _, target := range []string{"", "http://demo.example/", credentialed, "https://demo.example/#fragment"} {
		if _, err := HTTPSBusinessProbe("127.0.0.1:1080", target); err == nil {
			t.Fatal("accepted invalid target")
		}
	}
	if _, err := HTTPSBusinessProbe("192.0.2.1:1080", "https://demo.example/"); err == nil {
		t.Fatal("nonlocal proxy accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	probe, err := HTTPSBusinessProbe("127.0.0.1:1080", "https://demo.example/")
	if err != nil {
		t.Fatal(err)
	}
	if result := probe(ctx); result.Available {
		t.Fatal("cancelled request used direct fallback")
	}
}
