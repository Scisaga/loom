//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"loom/internal/wire"
)

func TestLinuxConfigMirrorsUseInstalledResolverAndKeepTLSPins(t *testing.T) {
	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	var queries atomic.Int64
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, address, err := resolver.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			queries.Add(1)
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, question := range query.Questions {
				if question.Type == dnsmessage.TypeA {
					answer.Answers = append(answer.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
						Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					})
				}
			}
			raw, err := answer.Pack()
			if err == nil {
				_, _ = resolver.WriteTo(raw, address)
			}
		}
	}()
	body := []byte(`{"schema":1,"value":"verified-content"}`)
	server, roots, pin := mirrorTLSTestFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("公开镜像收到凭据")
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	contentHash, _ := wire.DeviceConfigArtifactContentHash(body)
	mirrors := []wire.DistributionMirrorRefV1{}
	for i, id := range []string{"demo-mirror-a", "demo-mirror-b"} {
		name := []string{"a.example.test", "b.example.test"}[i]
		mirrors = append(mirrors, wire.DistributionMirrorRefV1{Schema: 1, EndpointID: id,
			DistributionEndpointSetHash: wire.HashRaw("demo-set", []byte(id)), ListenerGeneration: 1,
			BaseURL: "https://" + name + ":" + parsed.Port() + "/distribution/sha256/", ServerName: name,
			WebPKIProfileRef: "webpki-v1", SPKIPins: []string{pin}})
	}
	cfg, _ := json.Marshal(map[string]any{"dns": []string{resolver.LocalAddr().String()}})
	runtime, _ := wire.MarshalCanonical(wire.LinuxRuntimeArtifactV1{Files: []wire.LinuxRuntimeFileV1{{Path: "report/v2/config.json", Content: string(cfg)}}})
	installation := &DeviceInstallationV1{Configs: []InstalledConfigV1{{ArtifactID: wire.LinuxRuntimeArtifactID, Config: runtime}}}
	fetcher, err := installedLinuxMirrorFetcher(installation, MirrorFetcher{RootCAs: roots, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	got, err := fetcher.FetchCanonicalObject(context.Background(), mirrors, contentHash, wire.DomainDeviceConfigArtifact, int64(len(body)))
	if err != nil || !bytes.Equal(got, body) || queries.Load() == 0 {
		t.Fatalf("认证配置中的解析器未用于镜像下载: %v", err)
	}
	for i := range mirrors {
		mirrors[i].SPKIPins = []string{wire.HashRaw("demo-wrong-pin", nil)}
	}
	if _, err := fetcher.FetchCanonicalObject(context.Background(), mirrors, contentHash, wire.DomainDeviceConfigArtifact, int64(len(body))); err == nil {
		t.Fatal("显式解析器绕过了 TLS pin")
	}
}

func TestFetchLinuxDeviceConfigArtifactsUsesPinnedContentAddressedMirrors(t *testing.T) {
	body := []byte(`{"schema":1,"value":"linux-config"}`)
	contentHash, _ := wire.DeviceConfigArtifactContentHash(body)
	digest := strings.TrimPrefix(contentHash, "sha256:")
	requests := 0
	server, roots, pin := mirrorTLSTestFixture(t, http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			requests++
			if request.URL.Path != "/distribution/sha256/"+digest ||
				request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
				http.Error(response, "bad request", http.StatusBadRequest)
				return
			}
			_, _ = response.Write(body)
		}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	hash := func(value string) string { return wire.HashRaw("linux-config-fetch-test", []byte(value)) }
	mirrors := []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"),
			ListenerGeneration: 1, BaseURL: "https://a.example.test:" + parsed.Port() + "/distribution/sha256/",
			ServerName: "a.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{pin}, HintRank: 0},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"),
			ListenerGeneration: 1, BaseURL: "https://b.example.test:" + parsed.Port() + "/distribution/sha256/",
			ServerName: "b.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{pin}, HintRank: 1},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	fetcher := MirrorFetcher{RootCAs: roots, Timeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, parsed.Host)
		}}
	ref := wire.DeviceConfigArtifactRefV1{
		ArtifactID: LinuxLinkIntentArtifactID, Generation: 2, Platform: "linux-server",
		MediaType: "application/vnd.loom.config+json", RenderContractID: wire.LinuxLinkIntentRenderContract,
		SizeBytes: int64(len(body)), ContentHash: contentHash,
	}
	configs, err := FetchLinuxDeviceConfigArtifacts(context.Background(), mirrors,
		[]wire.DeviceConfigArtifactRefV1{ref}, fetcher)
	if err != nil || len(configs) != 1 || !bytes.Equal(configs[0].Config, body) || requests != 1 {
		t.Fatalf("config mirror fetch 无效: configs=%#v requests=%d err=%v", configs, requests, err)
	}
	got, err := LinuxInstalledConfigArtifact(&DeviceInstallationV1{Configs: configs},
		LinuxLinkIntentArtifactID)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("durable config projection 无效: got=%q err=%v", got, err)
	}
	wrongPlatform := ref
	wrongPlatform.Platform = "android"
	if _, err := FetchLinuxDeviceConfigArtifacts(context.Background(), mirrors,
		[]wire.DeviceConfigArtifactRefV1{wrongPlatform}, fetcher); err == nil || requests != 1 {
		t.Fatalf("非 Linux ref 未在请求前拒绝: requests=%d err=%v", requests, err)
	}
}
